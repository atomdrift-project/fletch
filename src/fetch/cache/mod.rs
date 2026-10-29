//! The on-disk blob cache: fetched artifacts and registry metadata with their
//! provenance, the metadata TTL policy, and the sweep that bounds its size.
//!
//! The directory layout and the trust every cache directory must earn before
//! it is read, written or swept live in [`disk`]. On Unix the cache is
//! owner-only (`0o700` directories, `0o600` files) and a directory owned by
//! another user, or writable by one, is refused; other platforms rely on the
//! per-user location of their OS cache directory instead.

use serde::{Deserialize, Serialize};
use std::cell::Cell;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, SystemTime};

use crate::fetch::transport::{DEFAULT_MAX_FETCH_BYTES, Fetch, FetchError, Fetched, Request};
use crate::fetch::{Served, now, sha256_hex};

mod disk;
pub(crate) mod sweep;

use disk::Trusted;
pub(crate) use disk::{Counted, create_private};
use sweep::Limits;

/// Cache lifetime for a pinned reference — immutable, so a stale hit is
/// still correct (and re-verified).
pub(crate) const TTL_PINNED: Duration = Duration::from_secs(7 * 24 * 3600);

/// Cache lifetime for an unpinned reference — `@latest`/mutable tags can
/// move, so staleness is bounded.
pub(crate) const TTL_UNPINNED: Duration = Duration::from_secs(12 * 3600);

/// Registry-*metadata* cache lifetimes, distinct from the artifact TTLs above.
/// Keyed on the *resource's* mutability, not whether the PURL named a version:
///
/// - **Immutable** — a published version's file list (URLs, hashes, upload time)
///   and content-addressed data never change, so cache them forever. This is the
///   version-specific endpoint a download-URL resolution reads.
/// - **Pinned** — the package-level *packument* behind a versioned lookup. No
///   registry we support lets different bytes appear at an already-published
///   coordinate: crates.io and Maven Central refuse to overwrite a release, the
///   Go proxy is content-addressed against the checksum database, and npm and
///   PyPI both block reuse of a version number even after an unpublish or
///   delete. So the attack a short TTL would defend against — publish a benign
///   `1.0.0`, let it be cached and vouched, then swap malware in at that same
///   coordinate — cannot happen, while revalidating hundreds of lockfile
///   coordinates per scan only re-confirms what they already said. 90 days
///   rather than forever so a record still refreshes on a human timescale: the
///   schema we parse can change, and a cache that never expires can never
///   self-heal from a bad parse. The one thing a cached copy can't know is a
///   version published after it was fetched, so a lookup whose copy doesn't
///   list the requested version re-reads it under the unpinned TTL (see
///   [`crate::registry::registry`]).
/// - **Unpinned** — a `latest`/versionless lookup resolves through dist-tags,
///   which are repointable at will. That is where the real mutability lives, so
///   it keeps a tight bound.
///
/// Keyed on version-ness alone rather than a per-registry allowlist: the
/// property is universal, and a table would have to be kept correct for every
/// ecosystem added later, failing open if it were not.
///
/// Accepted cost: a release withdrawn after it was cached — often *because*
/// it was found malicious — is noticed up to the pinned TTL late by a lookup
/// served from the cache.
///
/// The two mutable tiers are overridable per cache via
/// [`BlobCache::with_registry_ttl`]; the immutable tier is never re-checked.
pub(crate) const META_TTL_IMMUTABLE: Duration = Duration::MAX;

const META_TTL_PINNED_DEFAULT: Duration = Duration::from_secs(90 * 86_400);

const META_TTL_UNPINNED_DEFAULT: Duration = Duration::from_secs(3600);

/// The largest sidecar read back. Ours hold a status, a few URLs, and the
/// response headers (which the HTTP client already bounds), so this is ample;
/// it stops a sidecar swapped for `/dev/zero` from exhausting memory.
const MAX_SIDECAR_BYTES: u64 = 4 << 20;

/// The largest body any entry may decompress to, whatever its sidecar
/// claims. A fetch path that stores more than the per-fetch cap (a flattened
/// container image) must stay under it.
pub(crate) const MAX_ENTRY_BYTES: u64 = 4 << 30;

/// Cached provenance stored next to the bytes, so a cache hit reconstructs
/// the full [`FetchRecord`](crate::fetch::FetchRecord) (headers, timestamp, redirects) without a fetch.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct CachedMeta {
    pub(crate) fetched_at: u64,
    pub(crate) status: u16,
    pub(crate) final_url: String,
    pub(crate) redirects: Vec<String>,
    pub(crate) headers: Vec<(String, String)>,
    /// Decompressed length of the blob. Recorded by [`BlobCache::put`], so
    /// callers leave it `None`; absent from entries written before it existed.
    #[serde(default)]
    pub(crate) size: Option<u64>,
}

impl CachedMeta {
    /// The decompression ceiling for this entry's blob: the size recorded when
    /// it was stored. An entry admitted under a larger cap than the per-fetch
    /// `max_bytes` (a container image) is still served, and a blob planted in
    /// its place can expand no further than the entry it replaced. The sidecar
    /// is as writable as the blob, so the recorded size is itself bounded by
    /// [`MAX_ENTRY_BYTES`]. An entry without one falls back to the per-fetch
    /// cap.
    pub(crate) fn read_limit(&self, max_bytes: u64) -> u64 {
        let ceiling = max_bytes.max(MAX_ENTRY_BYTES);
        self.size.map_or(max_bytes, |size| size.min(ceiling))
    }
}

/// One raw provider document a registry lookup read, captured by a recording
/// [`BlobCache`] — the verbatim bytes plus the transport facts (`status`,
/// `content_type`) observed when they were first fetched. The re-parsing backup a
/// consumer archives alongside the normalized record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedSource {
    /// The URL the document was fetched from.
    pub url: String,
    /// HTTP status observed at fetch time (carried through the cache sidecar).
    pub status: u16,
    /// `Content-Type` header at fetch time, when present.
    pub content_type: Option<String>,
    /// The document's size in bytes.
    pub size: u64,
    /// The document bytes, verbatim — `None` when the document is larger than
    /// the cache's [`with_source_limit`](BlobCache::with_source_limit).
    pub bytes: Option<Vec<u8>>,
}

/// Shared sink of [`RecordedSource`]s, populated by a recording [`BlobCache`].
/// See [`BlobCache::recording`].
pub type RawSink = Arc<Mutex<Vec<RecordedSource>>>;

/// Content-addressed cache of fetched responses — bytes (`<key>.zst`) plus a
/// provenance sidecar (`<key>.json`), keyed by `sha256(locator)`. Two
/// manifests naming the same package share one entry. TTL is the caller's
/// policy (passed to `BlobCache::fresh`).
///
/// The directory is used only once it passes the trust check described in
/// the module docs; one that fails it is logged and the cache acts as
/// [`disabled`](Self::disabled).
#[derive(Debug, Clone)]
pub struct BlobCache {
    dir: PathBuf,
    /// When false, every read misses and every write is a no-op — the cache is
    /// inert. Used to force always-fresh fetches and to keep tests hermetic.
    enabled: bool,
    /// Whether `dir` passed the trust check, decided on first use and shared
    /// by every clone.
    trust: Arc<OnceLock<Option<Trusted>>>,
    /// Staleness tolerance for registry-*metadata* reads
    /// ([`cached_metadata`], [`cached_metadata_status`], [`cached_post`]).
    /// [`registry`](crate::registry::registry) overrides it per PURL via
    /// [`with_meta_ttl`](Self::with_meta_ttl); artifact fetches ignore it.
    pub(crate) meta_ttl: Duration,
    /// When set, every metadata document this cache serves — from a hit or a
    /// fresh fetch — is appended to the sink as `(url, bytes)`, so a caller can
    /// recover the raw provider documents a registry lookup consumed without
    /// re-deriving fletch's per-ecosystem fetch recipe. `None` = no recording.
    recorder: Option<RawSink>,
    /// Replaces both mutable registry-metadata TTLs when set (see
    /// [`with_registry_ttl`](Self::with_registry_ttl)).
    registry_ttl: Option<Duration>,
    /// The per-fetch byte cap the stored entries were fetched under, which
    /// bounds how far a stored blob may decompress.
    max_bytes: u64,
    /// The largest document whose bytes a recording keeps (see
    /// [`with_source_limit`](Self::with_source_limit)).
    source_limit: usize,
    /// The size the sweep holds this cache to; a process that writes
    /// `max_entries` entries triggers one.
    limits: Limits,
}

/// The blob cache root (`…/fletch/refs`), or `None` when no OS cache directory
/// can be determined. This is the directory [`crate::cache_sweep`] reclaims.
#[must_use]
pub fn refs_dir() -> Option<PathBuf> {
    Some(dirs::cache_dir()?.join("fletch").join("refs"))
}

impl BlobCache {
    /// Open the cache under the OS cache directory (`…/fletch/refs`).
    pub fn open() -> std::io::Result<Self> {
        let dir = refs_dir().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "no OS cache directory")
        })?;
        Ok(Self::with_dir(dir))
    }

    /// Open a cache rooted at an explicit directory (created on first use).
    /// Its sweep limits come from the `FLETCH_CACHE_*` environment, read once
    /// per process.
    #[must_use]
    pub fn with_dir(dir: impl Into<PathBuf>) -> Self {
        Self::new(dir.into(), true)
    }

    /// A cache that never touches disk: every lookup misses and every store is a
    /// no-op. The caller always falls through to the network (or its test
    /// fixture), so there is no cross-run or cross-test state — the hermetic
    /// choice for tests, and the way to force an uncached fetch.
    #[must_use]
    pub fn disabled() -> Self {
        Self::new(PathBuf::new(), false)
    }

    fn new(dir: PathBuf, enabled: bool) -> Self {
        Self {
            dir,
            enabled,
            trust: Arc::default(),
            meta_ttl: TTL_PINNED,
            recorder: None,
            registry_ttl: None,
            max_bytes: DEFAULT_MAX_FETCH_BYTES,
            source_limit: usize::MAX,
            limits: Limits::from_env(),
        }
    }

    /// This cache, recording only the documents of at most `limit` bytes in
    /// full (see [`recording`](Self::recording)); a larger one is recorded by
    /// its URL, status, type, and size, without its bytes. A distro package
    /// lookup reads a multi-megabyte index, so a consumer that archives
    /// sources only up to some size sets that size here rather than copying
    /// the index into every lookup's sources to discard it.
    #[must_use]
    pub fn with_source_limit(self, limit: usize) -> Self {
        Self {
            source_limit: limit,
            ..self
        }
    }

    /// This cache, with both mutable registry-metadata TTLs replaced by `ttl`:
    /// a long one effectively caches indefinitely (offline, air-gapped), a short
    /// one revalidates aggressively. `None` keeps the 90-day pinned / 1-hour
    /// unpinned defaults. The immutable tier is unaffected — a released
    /// version's file list is never re-fetched regardless.
    #[must_use]
    pub fn with_registry_ttl(self, ttl: Option<Duration>) -> Self {
        Self {
            registry_ttl: ttl,
            ..self
        }
    }

    /// This cache, for entries fetched under a per-fetch cap of `limit` bytes
    /// (the [`HttpFetch::with_max_bytes`](crate::fetch::HttpFetch::with_max_bytes)
    /// of the fetcher that fills it) instead of the default.
    #[must_use]
    pub fn with_max_bytes(self, limit: u64) -> Self {
        Self {
            max_bytes: limit,
            ..self
        }
    }

    /// Metadata TTL for a pinned (versioned) lookup's mutable packument.
    #[must_use]
    pub(crate) fn meta_ttl_pinned(&self) -> Duration {
        self.registry_ttl.unwrap_or(META_TTL_PINNED_DEFAULT)
    }

    /// Metadata TTL for an unpinned (`latest`/versionless) lookup.
    #[must_use]
    pub(crate) fn meta_ttl_unpinned(&self) -> Duration {
        self.registry_ttl.unwrap_or(META_TTL_UNPINNED_DEFAULT)
    }

    /// A clone that records every metadata document it serves (cache hit or fresh
    /// fetch), returning it alongside the shared sink to read them back. Powers
    /// [`lookup_recorded`](crate::registry::lookup_recorded): the raw
    /// provider responses a lookup consumed, captured from the warm cache with no
    /// extra fetch.
    #[must_use]
    pub fn recording(&self) -> (Self, RawSink) {
        let sink: RawSink = Arc::new(Mutex::new(Vec::new()));
        let cache = Self {
            recorder: Some(Arc::clone(&sink)),
            ..self.clone()
        };
        (cache, sink)
    }

    /// A clone whose reads are recorded into a fresh sink held back from this
    /// cache's recorder, when it has one: they reach it only once
    /// [`commit`](Self::commit)ted, so a read the caller then discards (a
    /// superseded attempt) never shows up among its sources.
    pub(crate) fn staged(&self) -> (Self, Option<RawSink>) {
        if self.recorder.is_some() {
            let (cache, sink) = self.recording();
            (cache, Some(sink))
        } else {
            (self.clone(), None)
        }
    }

    /// Forward what a [`staged`](Self::staged) clone recorded to this cache's
    /// recorder. A sink poisoned by a panicking reader still holds whole
    /// records, so its contents are kept.
    pub(crate) fn commit(&self, staged: Option<RawSink>) {
        if let (Some(sink), Some(staged)) = (&self.recorder, staged) {
            let mut read =
                std::mem::take(&mut *staged.lock().unwrap_or_else(PoisonError::into_inner));
            sink.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .append(&mut read);
        }
    }

    /// Append a served metadata document to the recorder, if one is installed.
    fn record(&self, url: &str, status: u16, content_type: Option<&str>, bytes: &[u8]) {
        if let Some(sink) = &self.recorder {
            sink.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(RecordedSource {
                    url: url.to_string(),
                    status,
                    content_type: content_type.map(str::to_string),
                    size: bytes.len() as u64,
                    bytes: (bytes.len() <= self.source_limit).then(|| bytes.to_vec()),
                });
        }
    }

    /// A clone whose registry-*metadata* reads tolerate up to `ttl` of staleness
    /// — [`Duration::MAX`] caches indefinitely. Only [`cached_metadata`],
    /// [`cached_metadata_status`], and [`cached_post`] consult it; artifact fetches
    /// keep their own pinned/unpinned TTLs.
    #[must_use]
    pub(crate) fn with_meta_ttl(&self, ttl: Duration) -> Self {
        Self {
            meta_ttl: ttl,
            ..self.clone()
        }
    }

    /// The cache root, once it has passed the trust check; decided on first
    /// use, creating the root if need be.
    fn trusted_root(&self) -> Option<Trusted> {
        if !self.enabled {
            return None;
        }
        *self.trust.get_or_init(|| {
            let root = self.dir.display();
            if let Err(error) = disk::create_private_dir(&self.dir) {
                tracing::warn!(target: "cache", %root, %error, "cannot create the blob cache; not using it");
                return None;
            }
            disk::trust_root(&self.dir)
                .map_err(|why| {
                    tracing::warn!(target: "cache", %root, %why, "not using the blob cache");
                })
                .ok()
        })
    }

    /// The shard holding `key`, when it exists and is trusted.
    fn readable_shard(&self, key: &str) -> Option<PathBuf> {
        let trusted = self.trusted_root()?;
        let shard = self.dir.join(disk::shard_name(key));
        if !shard.exists() {
            return None;
        }
        self.admit(trusted, shard)
    }

    /// The shard to hold `key`, created if need be, when it is trusted.
    fn writable_shard(&self, key: &str) -> Option<PathBuf> {
        let trusted = self.trusted_root()?;
        let shard = self.dir.join(disk::shard_name(key));
        if let Err(error) = disk::create_private_dir(&shard) {
            tracing::warn!(target: "cache", shard = %shard.display(), %error, "cannot create cache shard");
            return None;
        }
        self.admit(trusted, shard)
    }

    fn admit(&self, trusted: Trusted, shard: PathBuf) -> Option<PathBuf> {
        match trusted.admit(&shard) {
            Ok(()) => Some(shard),
            Err(why) => {
                tracing::warn!(target: "cache", shard = %shard.display(), %why, "not using cache shard");
                None
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn blob_path(&self, key: &str) -> PathBuf {
        self.dir
            .join(disk::shard_name(key))
            .join(disk::blob_name(key))
    }

    #[cfg(test)]
    pub(crate) fn meta_path(&self, key: &str) -> PathBuf {
        self.dir
            .join(disk::shard_name(key))
            .join(disk::meta_name(key))
    }

    /// Stream `key`'s entry through `read`, when it is present and — given a
    /// `max_age` — no older than that; `read` must read the body to its end.
    /// Both the blob and its `.json` sidecar must be present and valid; a
    /// missing or unreadable sidecar is a cache miss rather than fabricated
    /// default provenance (a blob can outlive its sidecar — e.g. a partial
    /// write, or the cache sweep evicting one of the pair — and serving
    /// `status: 0`, `final_url: ""` provenance would silently falsify a
    /// `FetchRecord`).
    ///
    /// The body is decompressed under [`CachedMeta::read_limit`]. Bounded even
    /// though we wrote the file ourselves: a planted or damaged entry could be
    /// a zstd bomb. One byte past the ceiling is read, so an oversized entry is
    /// refused outright — serving a truncated prefix would hash to something
    /// that was never fetched. The pair is written as two renames, so a
    /// concurrent writer can leave one file from each fetch; a length
    /// disagreement is a miss.
    ///
    /// Freshness is measured from the recorded `fetched_at`, not the file
    /// mtime. That leaves the mtime free to record *last access* — bumped on
    /// each hit by [`mark_accessed`] — so the eviction
    /// sweep retains an entry that is still in use rather than one merely
    /// fetched recently.
    pub(crate) fn read_with<T>(
        &self,
        key: &str,
        max_age: Option<Duration>,
        read: impl FnOnce(&mut dyn Read) -> std::io::Result<T>,
    ) -> Option<(T, CachedMeta)> {
        let shard = self.readable_shard(key)?;
        let blob_path = shard.join(disk::blob_name(key));
        let blob = std::fs::File::open(&blob_path).ok()?;
        let blob_mtime = blob.metadata().and_then(|m| m.modified()).ok()?;
        let meta: CachedMeta = match std::fs::File::open(shard.join(disk::meta_name(key))) {
            Ok(sidecar) => match serde_json::from_reader(sidecar.take(MAX_SIDECAR_BYTES)) {
                Ok(meta) => meta,
                Err(error) => return rejected(key, "corrupt sidecar", &error),
            },
            Err(error) => return rejected(key, "blob without a sidecar", &error),
        };
        let age = Duration::from_secs(now().saturating_sub(meta.fetched_at));
        if max_age.is_some_and(|max_age| age > max_age) {
            return None;
        }
        let limit = meta.read_limit(self.max_bytes);
        let decoder = match zstd::stream::read::Decoder::new(blob) {
            Ok(decoder) => decoder,
            Err(error) => return rejected(key, "corrupt blob", &error),
        };
        let count = Cell::new(0);
        let value = match read(&mut Counted::new(
            decoder.take(limit.saturating_add(1)),
            &count,
        )) {
            Ok(value) => value,
            Err(error) => return rejected(key, "unreadable blob", &error),
        };
        if count.get() > limit {
            return rejected(key, "oversized blob", &limit);
        }
        if let Some(size) = meta.size
            && size != count.get()
        {
            return rejected(key, "size does not match its sidecar", &size);
        }
        mark_accessed(&[blob_path, shard.join(disk::meta_name(key))], blob_mtime);
        Some((value, meta))
    }

    /// `key`'s entry unpacked into a spool, for a reader that must seek (a Go
    /// module zip's tree hash) — when present and, given a `max_age`, no
    /// older than that.
    pub(crate) fn unpack(
        &self,
        key: &str,
        max_age: Option<Duration>,
    ) -> Option<(Spool, CachedMeta)> {
        let spool = self.spool(key);
        let ((), meta) = self.read_with(key, max_age, |body| {
            std::io::copy(body, &mut create_private(spool.path())?).map(drop)
        })?;
        Some((spool, meta))
    }

    /// A spool for `key`'s body: a file not yet created, removed when the
    /// spool is dropped. It sits beside the entry it will become, on the
    /// cache's own disk — a system temp directory is often memory-backed,
    /// which is what spooling exists to avoid. A disabled cache, or one whose
    /// directory is unusable, spools to the system temp directory instead.
    ///
    /// The name ends in an unguessable tag ([`disk::unique_suffix`]), so no
    /// one sharing the temp directory can plant the path first.
    pub(crate) fn spool(&self, key: &str) -> Spool {
        let name = format!("{key}.part.{}", disk::unique_suffix());
        if self.enabled {
            if let Some(shard) = self.writable_shard(key) {
                return Spool(shard.join(name));
            }
            tracing::debug!(target: "cache", key, "cache unusable; spooling to the temp directory");
        }
        Spool(std::env::temp_dir().join(name))
    }

    /// Cached bytes + provenance for `key`, if present and younger than
    /// `max_age`.
    pub(crate) fn fresh(&self, key: &str, max_age: Duration) -> Option<(Vec<u8>, CachedMeta)> {
        self.read_with(key, Some(max_age), read_all)
    }

    /// Cached bytes + provenance for `key` at any age — the fallback when a
    /// fresh fetch can't be made (the source is unreachable).
    pub(crate) fn any(&self, key: &str) -> Option<(Vec<u8>, CachedMeta)> {
        self.read_with(key, None, read_all)
    }

    /// The cached bytes for a locator, at any age — for re-analysing a
    /// fetched stage. `None` if it was never fetched.
    ///
    /// These are the fetched bytes as they arrived, for analysis only. A
    /// container image's entry in particular is a flattened rootfs tar whose
    /// symlinks point where the image's do (`/etc/…`, `../../…`) and which
    /// keeps device nodes and setuid bits: it must never be extracted to disk.
    #[must_use]
    pub fn load(&self, locator: &str) -> Option<Vec<u8>> {
        self.any(&sha256_hex(locator.as_bytes()))
            .map(|(bytes, _)| bytes)
    }

    /// Store `bytes` and `meta` for `key`. Best-effort — a write failure is
    /// logged and otherwise non-fatal (the next run re-fetches).
    pub(crate) fn put(&self, key: &str, bytes: &[u8], meta: &CachedMeta) {
        self.store(key, bytes, bytes.len() as u64, meta);
    }

    /// Store the `size`-byte `body` and `meta` for `key`, compressing it as it
    /// streams. Best-effort, as [`put`](Self::put).
    pub(crate) fn store(&self, key: &str, body: impl Read, size: u64, meta: &CachedMeta) {
        let Some(shard) = self.writable_shard(key) else {
            return;
        };
        let stored = disk::write_replacing(&shard.join(disk::blob_name(key)), |out| {
            zstd::stream::copy_encode(body, out, 3)
        })
        .and_then(|()| {
            let meta = CachedMeta {
                size: Some(size),
                ..meta.clone()
            };
            let json = serde_json::to_vec(&meta)?;
            disk::write_replacing(&shard.join(disk::meta_name(key)), |out| {
                out.write_all(&json)
            })
        });
        if let Err(error) = stored {
            tracing::warn!(target: "cache", key, %error, "cannot write cache entry");
            return;
        }
        // A bulk fetch can outgrow the cache ceiling inside one process, long
        // before the next daily sweep would notice.
        sweep::note_write(&self.dir, self.limits);
    }
}

/// Log why `key`'s entry is not served, and miss.
fn rejected<T>(key: &str, reason: &'static str, detail: &dyn std::fmt::Display) -> Option<T> {
    tracing::debug!(target: "cache", key, reason, %detail, "cache entry rejected");
    None
}

/// Bump the mtime of an entry's `paths` to now, recording the access for the
/// sweep — at most once a day, judged by the blob's `mtime`.
fn mark_accessed(paths: &[PathBuf], mtime: SystemTime) {
    const TOUCH_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
    if mtime.elapsed().is_ok_and(|age| age < TOUCH_INTERVAL) {
        return;
    }
    let now = SystemTime::now();
    for path in paths {
        let touched = std::fs::File::options()
            .write(true)
            .open(path)
            .and_then(|file| file.set_modified(now));
        if let Err(error) = touched {
            tracing::debug!(target: "cache", path = %path.display(), %error, "cannot mark cache entry used");
        }
    }
}

/// A temporary file a fetched body is written to, removed when dropped.
#[derive(Debug)]
pub(crate) struct Spool(PathBuf);

impl Spool {
    pub(crate) fn path(&self) -> &Path {
        &self.0
    }

    /// Another spool beside this one, its name this one's plus `.{tag}`: on the
    /// same disk, as unguessable, and likewise removed when dropped.
    pub(crate) fn beside(&self, tag: &str) -> Self {
        let mut name = self.0.clone().into_os_string();
        name.push(".");
        name.push(tag);
        Self(name.into())
    }
}

impl Drop for Spool {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Read a body to its end.
fn read_all(body: &mut dyn Read) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    body.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Whether `error` is the source's answer about the document at `url` rather
/// than a failure to get one. A 403 means that only from proxy.golang.org; from
/// anywhere else it is as likely a rate limit (GitHub's) as a refusal.
fn is_verdict(url: &str, error: &FetchError) -> bool {
    match error {
        FetchError::Status(404 | 410 | 451) => true,
        FetchError::Status(403) => url.starts_with("https://proxy.golang.org/"),
        _ => false,
    }
}

/// The `Content-Type` header value (case-insensitive), if any.
fn content_type_of(headers: &[(String, String)]) -> Option<&str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.as_str())
}

/// Fetch a registry *metadata* document through the blob cache. Used by
/// provenance so a package's facts (publish date, author,
/// downloads) cost one round-trip per cache window and are free on a hit.
///
/// Metadata is small and a release's facts are effectively immutable, so the
/// pinned TTL bounds staleness for the few moving fields (dist-tags, download
/// counts) without re-fetching every scan. A network failure with no cached
/// copy yields `None`; the caller treats that as "unknown".
pub(crate) fn cached_metadata(url: &str, net: &dyn Fetch, cache: &BlobCache) -> Option<Vec<u8>> {
    cached_metadata_status(url, &[], net, cache).ok()
}

/// The unhashed key of a `kind` request to `url` sent with `headers`, each
/// part length-prefixed so no URL can spell another request's headers: with a
/// plain `{url}:{k}:{v}` join, a header-less read of `…/x:k:v` would key the
/// same entry as `…/x` sent with `k: v`.
fn request_key(kind: &str, url: &str, headers: &[(&str, &str)]) -> String {
    let mut key = format!("{kind}:{}:{url}", url.len());
    for (k, v) in headers {
        let _ = write!(key, "|{}:{k}{}:{v}", k.len(), v.len());
    }
    key
}

/// The cache key for a read of `url` sent with `headers`:
/// [`metadata_cache_key`] without any, else [`request_key`]'s.
fn headed_cache_key(url: &str, headers: &[(&str, &str)]) -> String {
    if headers.is_empty() {
        return metadata_cache_key(url);
    }
    sha256_hex(request_key("meta", url, headers).as_bytes())
}

/// The cache key [`cached_metadata`] files a header-less read of `url` under.
pub(crate) fn metadata_cache_key(url: &str) -> String {
    sha256_hex(format!("meta:{url}").as_bytes())
}

/// File a response under [`cached_metadata`]'s key for `url`, so a later
/// header-less read of the same document is a cache hit. For a caller that
/// already has the bytes in hand for another reason and would otherwise make
/// the registry answer twice.
pub(crate) fn store_metadata(url: &str, fetched: &Fetched, cache: &BlobCache) {
    let meta = CachedMeta {
        fetched_at: now(),
        status: fetched.status,
        final_url: fetched.final_url.clone(),
        redirects: fetched.redirects.clone(),
        headers: fetched.headers.clone(),
        size: None,
    };
    cache.put(&metadata_cache_key(url), &fetched.bytes, &meta);
}

/// [`cached_metadata`], keeping the status of a refusal, and attaching request
/// `headers` for a registry that mandates one (the Snap Store's
/// `Snap-Device-Series`). The headers fold into the cache key so a different
/// header set is a distinct entry; an empty set reuses [`cached_metadata`]'s
/// key exactly.
///
/// A registry that answers a metadata request with a status instead of a
/// document is sometimes *saying* something about the package rather than
/// failing to answer: proxy.golang.org replies 403 to a release it has taken
/// down for malware, which is a fact worth recording and not a lookup that
/// went wrong. [`cached_metadata`] cannot express the difference — every
/// unhappy path is the same `None`.
///
/// `Err(FetchError::Status(_))` is a server that answered and refused; any
/// other error is one that could not be reached, with nothing cached to fall
/// back on.
pub(crate) fn cached_metadata_status(
    url: &str,
    headers: &[(&str, &str)],
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Vec<u8>, FetchError> {
    cached_document(&headed_cache_key(url, headers), url, cache, || {
        net.send(&Request::get(url).with_headers(headers))
    })
}

/// [`cached_metadata_status`] for a GitHub API URL fletch named itself, sent
/// with the backend's GitHub token where the transport allows it (see
/// [`Request::github_auth`]). Filed under a key of its own: a document read
/// with the token may describe what an anonymous read must not see, so it is
/// never served to [`cached_metadata`].
pub(crate) fn cached_github_api(
    url: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Vec<u8>, FetchError> {
    let key = sha256_hex(request_key("github", url, &[]).as_bytes());
    cached_document(&key, url, cache, || {
        net.send(&Request::get(url).github_auth())
    })
}

/// Like [`cached_metadata`] but for a JSON-RPC `POST` query — the VS Code
/// Marketplace's `extensionquery` has no GET form. Keyed on the URL, the
/// headers and the body, so a distinct query is a distinct entry.
pub(crate) fn cached_post(
    url: &str,
    body: &[u8],
    headers: &[(&str, &str)],
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Vec<u8>, FetchError> {
    let mut key = request_key("post", url, headers);
    let _ = write!(key, "|body:{}", sha256_hex(body));
    cached_document(&sha256_hex(key.as_bytes()), url, cache, || {
        net.send(&Request::post(url, body).with_headers(headers))
    })
}

/// The metadata cache flow every registry read shares: serve a fresh entry,
/// else `send` the request and store what comes back, else fall back to any
/// cached copy however old — an unreachable source still beats no answer, but
/// a source that answered "gone" ([`is_verdict`]) is never overruled by one.
/// Whatever is served is handed to the cache's recorder, so a caller archiving
/// provenance sees the document exactly once per read.
///
/// `Err` is why the request failed, so a caller that can read meaning into a
/// refusal — see [`cached_metadata_status`] — is not forced to re-issue the
/// request to find out.
fn cached_document(
    key: &str,
    url: &str,
    cache: &BlobCache,
    send: impl FnOnce() -> Result<Fetched, FetchError>,
) -> Result<Vec<u8>, FetchError> {
    if let Some((bytes, meta)) = cache.fresh(key, cache.meta_ttl) {
        crate::metrics::metadata(url, Some(Served::Cache), Some(bytes.len()));
        cache.record(url, meta.status, content_type_of(&meta.headers), &bytes);
        return Ok(bytes);
    }
    let f = match send() {
        Ok(f) => f,
        Err(e) => {
            // A stale copy stands in for a source that could not be reached,
            // never for one that answered: a package removed (404, 410 — how
            // registries pull malware) or withheld (451, the Go proxy's 403
            // takedown) is the news, and an old copy would hide it.
            if !is_verdict(url, &e)
                && let Some((bytes, meta)) = cache.any(key)
            {
                crate::metrics::metadata(url, Some(Served::StaleCache), Some(bytes.len()));
                cache.record(url, meta.status, content_type_of(&meta.headers), &bytes);
                return Ok(bytes);
            }
            crate::metrics::metadata(url, None, None);
            return Err(e);
        }
    };
    crate::metrics::metadata(url, Some(Served::Network), Some(f.bytes.len()));
    let meta = CachedMeta {
        fetched_at: now(),
        status: f.status,
        final_url: f.final_url,
        redirects: f.redirects,
        headers: f.headers,
        size: None,
    };
    cache.put(key, &f.bytes, &meta);
    cache.record(url, meta.status, content_type_of(&meta.headers), &f.bytes);
    Ok(f.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fetch::Fixtures;
    use filefacts::RefLocator;

    #[test]
    fn cache_hit_refreshes_last_access_mtime() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = BlobCache::with_dir(dir.path().to_path_buf());
        let key = "abc123";
        cache.put(
            key,
            b"payload",
            &CachedMeta {
                fetched_at: now(),
                ..Default::default()
            },
        );

        // Backdate both files so the entry looks two days idle to the sweep.
        let old = SystemTime::now() - Duration::from_secs(2 * 24 * 3600);
        for p in [cache.blob_path(key), cache.meta_path(key)] {
            std::fs::File::options()
                .write(true)
                .open(&p)
                .expect("open")
                .set_modified(old)
                .expect("mtime");
        }

        // A cache hit marks the entry accessed, so the eviction sweep (which ages
        // by mtime) treats it as recently used rather than two days old.
        assert!(cache.any(key).is_some(), "entry is served");
        let mtime = std::fs::metadata(cache.blob_path(key))
            .unwrap()
            .modified()
            .unwrap();
        assert!(
            mtime.elapsed().unwrap() < Duration::from_secs(120),
            "the cache hit refreshed the last-access mtime"
        );
    }

    /// Plant `blob` as `key`'s body with a size-less sidecar.
    fn plant(cache: &BlobCache, key: &str, blob: &[u8]) {
        std::fs::create_dir_all(cache.blob_path(key).parent().expect("shard")).expect("mkdir");
        std::fs::write(cache.blob_path(key), blob).expect("plant blob");
        let meta = serde_json::to_vec(&CachedMeta::default()).expect("meta");
        std::fs::write(cache.meta_path(key), meta).expect("plant meta");
    }

    #[test]
    fn a_cache_entry_that_expands_past_the_cap_is_a_miss() {
        // A zstd bomb planted in the cache directory: a few hundred bytes on
        // disk that expand without bound. It must read as a miss, not be
        // decompressed into memory. The cap is a parameter so this costs
        // kilobytes instead of the 256 MiB production ceiling.
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = |cap| BlobCache::with_dir(dir.path().to_path_buf()).with_max_bytes(cap);
        // An entry from before sizes were recorded: read under the cap alone.
        let bomb = zstd::encode_all(&vec![0u8; 1 << 20][..], 3).expect("compress");
        assert!(bomb.len() < 4096, "1 MiB of zeros should compress tiny");
        plant(&cache(0), "bomb", &bomb);

        assert!(
            cache(1024).any("bomb").is_none(),
            "an entry expanding past the cap must not be served"
        );
        // The same entry is served whole when it fits.
        assert_eq!(
            cache(1 << 20).any("bomb").map(|(b, _)| b.len()),
            Some(1 << 20)
        );
        // A blob exactly at the ceiling is still valid — the `+1` read must not
        // reject the boundary case.
        plant(
            &cache(0),
            "exact",
            &zstd::encode_all(&b"12345"[..], 3).expect("compress"),
        );
        assert_eq!(cache(5).any("exact").map(|(b, _)| b.len()), Some(5));
        assert!(cache(4).any("exact").is_none());
        // An unbounded ceiling must not wrap the `+1` read to zero bytes.
        assert_eq!(cache(u64::MAX).any("exact").map(|(b, _)| b.len()), Some(5));
    }

    #[test]
    fn spools_sit_beside_the_entry_or_in_the_temp_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = BlobCache::with_dir(dir.path());
        let spool = cache.spool("abcd");
        assert_eq!(spool.path().parent(), Some(dir.path().join("ab").as_path()));
        let beside = spool.beside("0");
        assert_eq!(beside.path().parent(), spool.path().parent());
        assert_ne!(beside.path(), spool.path());

        let disabled = BlobCache::disabled();
        let (a, b) = (disabled.spool("k"), disabled.spool("k"));
        assert_eq!(a.path().parent(), Some(std::env::temp_dir().as_path()));
        assert_ne!(a.path(), b.path());
    }

    #[cfg(unix)]
    #[test]
    fn a_planted_symlink_cache_entry_is_replaced_not_followed() {
        // Pre-create the entry a fetch is about to write as a symlink pointing
        // at a file outside the cache. The store must unlink the symlink, not
        // write through it.
        let dir = tempfile::tempdir().expect("tempdir");
        let outside = dir.path().join("precious");
        std::fs::write(&outside, b"do not clobber").expect("seed");

        let cache = BlobCache::with_dir(dir.path().join("refs"));
        let key = sha256_hex(b"some-locator");
        let blob = cache.blob_path(&key);
        std::fs::create_dir_all(blob.parent().expect("shard")).expect("mkdir");
        std::os::unix::fs::symlink(&outside, &blob).expect("plant symlink");

        cache.put(&key, b"fetched bytes", &CachedMeta::default());

        assert_eq!(
            std::fs::read(&outside).expect("target still readable"),
            b"do not clobber",
            "the symlink target must be untouched"
        );
        assert!(
            !std::fs::symlink_metadata(&blob)
                .expect("entry exists")
                .is_symlink(),
            "the planted symlink must have been replaced by a real file"
        );
        assert_eq!(
            cache.load("some-locator").as_deref(),
            Some(&b"fetched bytes"[..])
        );
    }

    /// A root or shard someone else can write may hold entries they planted:
    /// it is neither read nor written. One others can only read is made
    /// owner-only and used.
    #[cfg(unix)]
    #[test]
    fn a_cache_directory_others_can_write_is_not_trusted() {
        use std::os::unix::fs::PermissionsExt;
        let set =
            |p: &Path, m| std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("refs");
        let key = "ab".repeat(32);
        plant(
            &BlobCache::with_dir(&root),
            &key,
            &zstd::encode_all(&b"planted"[..], 3).unwrap(),
        );

        set(&root, 0o777);
        assert!(
            BlobCache::with_dir(&root).any(&key).is_none(),
            "loose root: not read"
        );
        BlobCache::with_dir(&root).put("cd00", b"x", &CachedMeta::default());
        assert!(!root.join("cd").exists(), "loose root: not written");

        set(&root, 0o755);
        set(&root.join("ab"), 0o775);
        assert!(
            BlobCache::with_dir(&root).any(&key).is_none(),
            "loose shard: not read"
        );

        set(&root.join("ab"), 0o755);
        assert!(
            BlobCache::with_dir(&root).any(&key).is_some(),
            "readable: used"
        );
        assert_eq!(mode(&root), 0o700, "and made owner-only");
        assert_eq!(mode(&root.join("ab")), 0o700);
    }

    #[test]
    fn a_removal_outranks_a_stale_copy_but_an_outage_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let cache = BlobCache::with_dir(dir.path()).with_meta_ttl(Duration::from_secs(60));
        // Cache `url`'s document, then age it past fresh so the network is asked.
        let warm = |url: &str| {
            assert!(cached_metadata(url, &Fixtures::default().with(url, b"{}"), &cache).is_some());
            let path = cache.meta_path(&metadata_cache_key(url));
            let mut meta: CachedMeta =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            meta.fetched_at -= 3600;
            std::fs::write(&path, serde_json::to_vec(&meta).unwrap()).unwrap();
        };
        let url = "https://registry.npmjs.org/evil";
        warm(url);

        // Unreachable: the stale copy stands in.
        assert_eq!(
            cached_metadata_status(url, &[], &Fixtures::default(), &cache),
            Ok(b"{}".to_vec())
        );
        // Removed: the registry's answer is the news.
        let removed = Fixtures::default().refusing(url, 404);
        assert_eq!(
            cached_metadata_status(url, &[], &removed, &cache),
            Err(FetchError::Status(404))
        );
        // A 403 is a takedown only from the Go proxy; elsewhere, a rate limit.
        let limited = Fixtures::default().refusing(url, 403);
        assert!(cached_metadata_status(url, &[], &limited, &cache).is_ok());
        let go = "https://proxy.golang.org/example.com/evil/@v/v1.0.0.info";
        warm(go);
        let withheld = Fixtures::default().refusing(go, 403);
        assert_eq!(
            cached_metadata_status(go, &[], &withheld, &cache),
            Err(FetchError::Status(403))
        );
    }

    #[test]
    fn header_keys_are_unambiguous() {
        let key = headed_cache_key;
        assert_ne!(
            key("https://x.test/a:k:v", &[]),
            key("https://x.test/a", &[("k", "v")])
        );
        assert_ne!(
            key("https://x.test/a", &[("k", "v|1:j1:w")]),
            key("https://x.test/a", &[("k", "v"), ("j", "w")])
        );
        assert_eq!(
            key("https://x.test/a", &[]),
            metadata_cache_key("https://x.test/a")
        );
    }

    /// A document read with the GitHub token is never served to an anonymous
    /// read of the same URL.
    #[test]
    fn an_authenticated_read_is_cached_apart_from_anonymous_ones() {
        let dir = tempfile::tempdir().unwrap();
        let cache = BlobCache::with_dir(dir.path());
        let url = "https://api.github.com/repos/o/private";
        let net = Fixtures::default().with(url, br#"{"private":true}"#);
        assert!(cached_github_api(url, &net, &cache).is_ok());
        assert_eq!(
            cached_metadata(url, &Fixtures::default(), &cache),
            None,
            "the anonymous read misses and asks the network"
        );
        assert!(cached_github_api(url, &Fixtures::default(), &cache).is_ok());
    }

    /// A query sent with other headers is another entry, like a GET's.
    #[test]
    fn a_post_is_keyed_on_its_headers() {
        let dir = tempfile::tempdir().unwrap();
        let cache = BlobCache::with_dir(dir.path());
        let url = "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery";
        let net = Fixtures::default().with(url, b"{}");
        let accept = [("Accept", "application/json;api-version=3.0-preview.1")];
        assert!(cached_post(url, b"q", &accept, &net, &cache).is_ok());
        assert!(cached_post(url, b"q", &accept, &Fixtures::default(), &cache).is_ok());
        assert!(
            cached_post(url, b"q", &[], &Fixtures::default(), &cache).is_err(),
            "other headers: a miss"
        );
        assert!(
            cached_post(url, b"r", &accept, &Fixtures::default(), &cache).is_err(),
            "another body: a miss"
        );
    }

    /// A reader that panicked while holding the staged sink leaves whole
    /// records behind; they still reach the caller.
    #[test]
    fn a_poisoned_sink_keeps_its_records() {
        let (cache, sink) = BlobCache::disabled().recording();
        let (staged, held) = cache.staged();
        staged.record("https://x.test/doc", 200, None, b"{}");
        let poisoner = held.clone().expect("staged sink");
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.lock().unwrap();
            panic!("a reader panics mid-lookup");
        })
        .join();
        cache.commit(held);
        assert_eq!(sink.lock().unwrap().len(), 1);
    }

    #[test]
    fn a_pinned_lookup_rereads_a_document_that_predates_the_version() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = BlobCache::with_dir(dir.path().to_path_buf());
        let url = "https://registry.npmjs.org/foo";
        // The packument as cached two hours ago, before 1.1.0 was published:
        // inside the pinned TTL, past the versionless one.
        let old = serde_json::json!({
            "dist-tags": {"latest": "1.0.0"},
            "versions": {"1.0.0": {}},
            "time": {"1.0.0": "2024-01-01T00:00:00Z"}
        });
        cache.put(
            &metadata_cache_key(url),
            old.to_string().as_bytes(),
            &CachedMeta {
                fetched_at: now() - 2 * 3600,
                status: 200,
                final_url: url.into(),
                ..CachedMeta::default()
            },
        );
        let new = serde_json::json!({
            "dist-tags": {"latest": "1.1.0"},
            "versions": {"1.0.0": {}, "1.1.0": {"_npmUser": {"name": "mallory"}}},
            "time": {"1.0.0": "2024-01-01T00:00:00Z", "1.1.0": "2024-06-01T00:00:00Z"}
        })
        .to_string();
        let net = Fixtures::default().with(url, new.as_bytes());
        let locator = RefLocator::Purl("pkg:npm/foo@1.1.0".into());

        let (record, sources) = crate::registry::lookup_recorded(&locator, &net, &cache);
        let record = record.expect("record");
        // The copy that didn't list 1.1.0 was re-read, so the release is
        // dated and its publisher known.
        assert_eq!(record.published_at, Some(1_717_200_000)); // 2024-06-01
        assert_eq!(record.publisher.as_deref(), Some("mallory"));
        // Only the document the record came from is among its sources.
        let packuments: Vec<_> = sources.iter().filter(|s| s.url == url).collect();
        assert_eq!(packuments.len(), 1);
        assert_eq!(packuments[0].bytes.as_deref(), Some(new.as_bytes()));
    }

    #[test]
    fn a_cache_entry_is_read_back_under_its_recorded_size() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = BlobCache::with_dir(dir.path().to_path_buf());
        cache.put("k", b"payload", &CachedMeta::default());
        assert_eq!(cache.any("k").map(|(b, _)| b), Some(b"payload".to_vec()));

        // An entry admitted under a bigger cap than the per-fetch one (a
        // container image) is read back under its own size, not refused as
        // oversized.
        let cap = DEFAULT_MAX_FETCH_BYTES;
        let big = CachedMeta {
            size: Some(cap + 1),
            ..CachedMeta::default()
        };
        assert_eq!(big.read_limit(cap), cap + 1);
        // A sidecar can't lift the cap past what any entry may hold.
        let huge = CachedMeta {
            size: Some(u64::MAX),
            ..CachedMeta::default()
        };
        assert_eq!(huge.read_limit(cap), MAX_ENTRY_BYTES);
        // An entry written before sizes were recorded keeps the per-fetch cap.
        assert_eq!(CachedMeta::default().read_limit(cap), cap);

        // A blob whose length disagrees with its sidecar is a miss.
        let other = zstd::encode_all(&b"other"[..], 3).expect("compress");
        std::fs::write(cache.blob_path("k"), other).expect("write");
        assert!(cache.any("k").is_none());
    }
}
