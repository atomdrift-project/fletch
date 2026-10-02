//! The on-disk blob cache: fetched artifacts and registry metadata with their
//! provenance, and the metadata TTL policy.

use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use crate::fetch::transport::{DEFAULT_MAX_FETCH_BYTES, Fetch, FetchError, Fetched, Request};
use crate::fetch::{now, sha256_hex};

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
/// Accepted cost: `dep_pulled` feeds `must_rescan`, so a withdrawal — often
/// *because* something was found malicious — invalidates a known-good vouch, and
/// a long TTL delays noticing that. If it bites, the targeted fix is a short TTL
/// only for coordinates the known-good bloom vouches for, since those are the
/// only ones `must_rescan` can rescue.
///
/// The two mutable tiers are overridable per cache via
/// [`BlobCache::with_registry_ttl`]; the immutable tier is never re-checked.
pub(crate) const META_TTL_IMMUTABLE: Duration = Duration::MAX;

const META_TTL_PINNED_DEFAULT: Duration = Duration::from_secs(90 * 86_400);

const META_TTL_UNPINNED_DEFAULT: Duration = Duration::from_secs(3600);

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
    /// `max_bytes` (an OCI export) is still served, and a blob planted in its
    /// place can expand no further than the entry it replaced. The sidecar is
    /// as writable as the blob, so the recorded size is itself bounded by the
    /// largest cap any fetch path admits. An entry without one falls back to
    /// the per-fetch cap.
    pub(crate) fn read_limit(&self, max_bytes: u64) -> u64 {
        let ceiling = max_bytes.max(crate::oci::MAX_EXPORT_BYTES);
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
#[derive(Debug, Clone)]
pub struct BlobCache {
    dir: PathBuf,
    /// When false, every read misses and every write is a no-op — the cache is
    /// inert. Used to force always-fresh fetches and to keep tests hermetic.
    enabled: bool,
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

    /// Open a cache rooted at an explicit directory (created on first write).
    #[must_use]
    pub fn with_dir(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            enabled: true,
            meta_ttl: TTL_PINNED,
            recorder: None,
            registry_ttl: None,
            max_bytes: DEFAULT_MAX_FETCH_BYTES,
            source_limit: usize::MAX,
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
    /// [`registry_with_sources`](crate::registry::registry_with_sources): the raw
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
    /// recorder.
    pub(crate) fn commit(&self, staged: Option<RawSink>) {
        if let (Some(sink), Some(staged)) = (&self.recorder, staged)
            && let (Ok(mut sources), Ok(mut read)) = (sink.lock(), staged.lock())
        {
            sources.append(&mut read);
        }
    }

    /// Append a served metadata document to the recorder, if one is installed.
    fn record(&self, url: &str, status: u16, content_type: Option<&str>, bytes: &[u8]) {
        if let Some(sink) = &self.recorder
            && let Ok(mut sources) = sink.lock()
        {
            sources.push(RecordedSource {
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

    /// A cache that never touches disk: every lookup misses and every store is a
    /// no-op. The caller always falls through to the network (or its test
    /// fixture), so there is no cross-run or cross-test state — the hermetic
    /// choice for tests, and the way to force an uncached fetch.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            dir: PathBuf::new(),
            enabled: false,
            meta_ttl: TTL_PINNED,
            recorder: None,
            registry_ttl: None,
            max_bytes: DEFAULT_MAX_FETCH_BYTES,
            source_limit: usize::MAX,
        }
    }

    /// The directory holding `key`'s files: one of 256, by the key's first two
    /// hex digits, so no directory grows to the whole cache.
    fn shard(&self, key: &str) -> PathBuf {
        self.dir.join(key.get(..2).unwrap_or("00"))
    }

    pub(crate) fn blob_path(&self, key: &str) -> PathBuf {
        self.shard(key).join(format!("{key}.zst"))
    }

    pub(crate) fn meta_path(&self, key: &str) -> PathBuf {
        self.shard(key).join(format!("{key}.json"))
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
    /// though we wrote the file ourselves: the cache lives in an OS cache
    /// directory, so anything that can write there can swap an entry for a zstd
    /// bomb. One byte past the ceiling is read, so an oversized entry is refused
    /// outright — serving a truncated prefix would hash to something that was
    /// never fetched. The pair is written as two renames, so a concurrent writer
    /// can leave one file from each fetch; a length disagreement is a miss.
    ///
    /// Freshness is measured from the recorded `fetched_at`, not the file
    /// mtime. That leaves the mtime free to record *last access* — bumped on
    /// each hit by [`mark_accessed`](Self::mark_accessed) — so the eviction
    /// sweep retains an entry that is still in use rather than one merely
    /// fetched recently.
    pub(crate) fn read_with<T>(
        &self,
        key: &str,
        max_age: Option<Duration>,
        read: impl FnOnce(&mut dyn Read) -> std::io::Result<T>,
    ) -> Option<(T, CachedMeta)> {
        if !self.enabled {
            return None;
        }
        let blob = std::fs::File::open(self.blob_path(key)).ok()?;
        let blob_mtime = blob.metadata().ok()?.modified().ok()?;
        let meta: CachedMeta =
            serde_json::from_slice(&std::fs::read(self.meta_path(key)).ok()?).ok()?;
        let age = Duration::from_secs(now().saturating_sub(meta.fetched_at));
        if max_age.is_some_and(|max_age| age > max_age) {
            return None;
        }
        let limit = meta.read_limit(self.max_bytes);
        let mut body = Counted {
            inner: zstd::stream::read::Decoder::new(blob)
                .ok()?
                .take(limit.saturating_add(1)),
            count: 0,
        };
        let value = read(&mut body).ok()?;
        if body.count > limit || meta.size.is_some_and(|size| size != body.count) {
            return None;
        }
        self.mark_accessed(key, blob_mtime);
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
            let mut out = std::fs::File::options()
                .write(true)
                .create_new(true)
                .open(spool.path())?;
            std::io::copy(body, &mut out).map(drop)
        })?;
        Some((spool, meta))
    }

    /// A spool for `key`'s body: a file not yet created, removed when the
    /// spool is dropped. It sits beside the entry it will become, on the
    /// cache's own disk — a system temp directory is often memory-backed,
    /// which is what spooling exists to avoid — or, for a disabled cache, in
    /// the system temp directory.
    pub(crate) fn spool(&self, key: &str) -> Spool {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let name = format!(
            "{key}.part.{}.{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        );
        let shard = self.shard(key);
        let dir = if self.enabled && std::fs::create_dir_all(&shard).is_ok() {
            shard
        } else {
            std::env::temp_dir()
        };
        Spool(dir.join(name))
    }

    fn mark_accessed(&self, key: &str, blob_mtime: SystemTime) {
        const TOUCH_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
        if blob_mtime.elapsed().is_ok_and(|age| age < TOUCH_INTERVAL) {
            return; // touched within the last day
        }
        let now = SystemTime::now();
        for path in [self.blob_path(key), self.meta_path(key)] {
            if let Ok(file) = std::fs::File::options().write(true).open(&path) {
                let _ = file.set_modified(now);
            }
        }
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
    #[must_use]
    pub fn load(&self, locator: &str) -> Option<Vec<u8>> {
        self.any(&sha256_hex(locator.as_bytes()))
            .map(|(bytes, _)| bytes)
    }

    /// Store `bytes` and `meta` for `key`. Best-effort — a write failure is
    /// non-fatal (the next run re-fetches).
    pub(crate) fn put(&self, key: &str, bytes: &[u8], meta: &CachedMeta) {
        self.store(key, bytes, bytes.len() as u64, meta);
    }

    /// Store the `size`-byte `body` and `meta` for `key`, compressing it as it
    /// streams. Best-effort, as [`put`](Self::put).
    pub(crate) fn store(&self, key: &str, body: impl Read, size: u64, meta: &CachedMeta) {
        if !self.enabled || std::fs::create_dir_all(self.shard(key)).is_err() {
            return;
        }
        if !write_replacing(&self.blob_path(key), |out| {
            zstd::stream::copy_encode(body, out, 3)
        }) {
            return;
        }
        let meta = CachedMeta {
            size: Some(size),
            ..meta.clone()
        };
        if let Ok(json) = serde_json::to_vec(&meta) {
            write_replacing(&self.meta_path(key), |out| out.write_all(&json));
        }
        // A bulk fetch can outgrow the cache ceiling inside one process, long
        // before the next daily sweep would notice.
        crate::cache_sweep::note_write(&self.dir);
    }
}

/// A temporary file a fetched body is written to, removed when dropped.
pub(crate) struct Spool(PathBuf);

impl Spool {
    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Spool {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// A reader that counts what passes through it.
struct Counted<R> {
    inner: R,
    count: u64,
}

impl<R: Read> Read for Counted<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.count += n as u64;
        Ok(n)
    }
}

/// Read a body to its end.
fn read_all(body: &mut dyn Read) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    body.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Write `path` through a fresh temporary file, with `write`, and rename it
/// into place; `true` when it landed. Best-effort, like the rest of the cache.
///
/// Two properties a plain `fs::write` does not have. The rename is atomic, so
/// a concurrent reader sees either the whole old entry or the whole new one,
/// never a torn prefix that would decompress to the wrong bytes. And both
/// steps replace a *name* rather than writing through one: `create_new` fails
/// on an existing path instead of following it, and `rename` unlinks whatever
/// the destination was. So an entry someone pre-created as a symlink — a live
/// risk wherever `XDG_CACHE_HOME` is shared, as on a CI runner — is destroyed
/// rather than followed into an arbitrary file.
fn write_replacing(
    path: &std::path::Path,
    write: impl FnOnce(&mut std::fs::File) -> std::io::Result<()>,
) -> bool {
    // Unique per process and per call, so two writers never collide on the
    // temporary and neither is left waiting on a stale one.
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let tmp = path.with_extension(format!(
        "tmp.{}.{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let written = std::fs::File::options()
        .create_new(true)
        .write(true)
        .open(&tmp)
        .and_then(|mut f| write(&mut f));
    if written.is_ok() && std::fs::rename(&tmp, path).is_ok() {
        return true;
    }
    let _ = std::fs::remove_file(&tmp);
    false
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
    let key = if headers.is_empty() {
        metadata_cache_key(url)
    } else {
        let joined = headers
            .iter()
            .map(|(k, v)| format!("{k}:{v}"))
            .collect::<Vec<_>>()
            .join(";");
        sha256_hex(format!("meta:{url}:{joined}").as_bytes())
    };
    cached_document(&key, url, cache, || {
        net.send(&Request::get(url).with_headers(headers))
    })
}

/// Like [`cached_metadata`] but for a JSON-RPC `POST` query — the VS Code
/// Marketplace's `extensionquery` has no GET form. Cached by URL + body so a
/// distinct query is a distinct entry.
pub(crate) fn cached_post(
    url: &str,
    body: &[u8],
    headers: &[(&str, &str)],
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Vec<u8>, FetchError> {
    let key = sha256_hex(format!("post:{url}:{}", sha256_hex(body)).as_bytes());
    cached_document(&key, url, cache, || {
        net.send(&Request::post(url, body).with_headers(headers))
    })
}

/// The metadata cache flow every registry read shares: serve a fresh entry,
/// else `send` the request and store what comes back, else fall back to any
/// cached copy however old — an unreachable source still beats no answer.
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
        crate::metrics::metadata(url, "cache", Some(bytes.len()));
        cache.record(url, meta.status, content_type_of(&meta.headers), &bytes);
        return Ok(bytes);
    }
    let f = match send() {
        Ok(f) => f,
        Err(e) => {
            // A stale copy still beats no answer, and outranks the refusal:
            // the document was true once, where the status is only true now.
            if let Some((bytes, meta)) = cache.any(key) {
                crate::metrics::metadata(url, "stale_cache", Some(bytes.len()));
                cache.record(url, meta.status, content_type_of(&meta.headers), &bytes);
                return Ok(bytes);
            }
            crate::metrics::metadata(url, "failed", None);
            return Err(e);
        }
    };
    crate::metrics::metadata(url, "network", Some(f.bytes.len()));
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

    use std::time::Duration;

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

    #[test]
    fn a_cache_entry_that_expands_past_the_cap_is_a_miss() {
        // A zstd bomb planted in the cache directory: a few hundred bytes on
        // disk that expand without bound. It must read as a miss, not be
        // decompressed into memory. The cap is a parameter so this costs
        // kilobytes instead of the 256 MiB production ceiling.
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = |cap| BlobCache::with_dir(dir.path().to_path_buf()).with_max_bytes(cap);
        // An entry from before sizes were recorded: read under the cap alone.
        let plant = |key: &str, blob: &[u8]| {
            let c = cache(0);
            std::fs::create_dir_all(c.blob_path(key).parent().expect("shard")).expect("mkdir");
            std::fs::write(c.blob_path(key), blob).expect("plant blob");
            let meta = serde_json::to_vec(&CachedMeta::default()).expect("meta");
            std::fs::write(c.meta_path(key), meta).expect("plant meta");
        };
        let bomb = zstd::encode_all(&vec![0u8; 1 << 20][..], 3).expect("compress");
        assert!(bomb.len() < 4096, "1 MiB of zeros should compress tiny");
        plant("bomb", &bomb);

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
            "exact",
            &zstd::encode_all(&b"12345"[..], 3).expect("compress"),
        );
        assert_eq!(cache(5).any("exact").map(|(b, _)| b.len()), Some(5));
        assert!(cache(4).any("exact").is_none());
        // An unbounded ceiling must not wrap the `+1` read to zero bytes.
        assert_eq!(cache(u64::MAX).any("exact").map(|(b, _)| b.len()), Some(5));
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

        let (record, sources) = crate::registry::registry_with_sources(&locator, &net, &cache);
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

        // An entry admitted under a bigger cap than the per-fetch one (an OCI
        // export) is read back under its own size, not refused as oversized.
        let cap = DEFAULT_MAX_FETCH_BYTES;
        let big = CachedMeta {
            size: Some(cap + 1),
            ..CachedMeta::default()
        };
        assert_eq!(big.read_limit(cap), cap + 1);
        // A sidecar can't lift the cap past what any fetch path admits.
        let huge = CachedMeta {
            size: Some(u64::MAX),
            ..CachedMeta::default()
        };
        assert_eq!(huge.read_limit(cap), cap.max(crate::oci::MAX_EXPORT_BYTES));
        // An entry written before sizes were recorded keeps the per-fetch cap.
        assert_eq!(CachedMeta::default().read_limit(cap), cap);

        // A blob whose length disagrees with its sidecar is a miss.
        let other = zstd::encode_all(&b"other"[..], 3).expect("compress");
        std::fs::write(cache.blob_path("k"), other).expect("write");
        assert!(cache.any("k").is_none());
    }
}
