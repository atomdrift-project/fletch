//! Resolve external references to URLs, retrieve them safely, cache them, and
//! record rich provenance.
//!
//! [`HttpFetch`] is the real backend; its SSRF guard lives in a custom DNS
//! resolver ([`SafeResolver`]) that refuses any host resolving to a private /
//! loopback / link-local / metadata address, re-checked on every redirect hop.
//! [`Fixtures`] is the offline backend for tests. No recognition logic lives
//! here — references come in, bytes and [`FetchRecord`]s go out.

use std::collections::HashMap;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use filefacts::{HashAlgo, PinnedHash, RefLocator, Reference};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

/// Cache lifetime for a pinned reference — immutable, so a stale hit is
/// still correct (and re-verified).
const TTL_PINNED: Duration = Duration::from_secs(7 * 24 * 3600);
/// Cache lifetime for an unpinned reference — `@latest`/mutable tags can
/// move, so staleness is bounded.
const TTL_UNPINNED: Duration = Duration::from_secs(12 * 3600);
/// Default per-fetch byte ceiling — a single response is abandoned past this
/// unless [`set_max_fetch_bytes`] adjusts it for the process.
pub const DEFAULT_MAX_FETCH_BYTES: u64 = 40 * 1024 * 1024;

/// Process-wide per-fetch byte ceiling. Fetching is process-global (one
/// invocation, one policy), so the limit lives in a single atomic set once at
/// startup rather than threaded through every `get`/`fetch_ref` call — the same
/// shape as the shared HTTP client and blob cache.
static MAX_FETCH_BYTES: AtomicU64 = AtomicU64::new(DEFAULT_MAX_FETCH_BYTES);

/// Set the per-fetch byte ceiling for the process. Call once at startup, before
/// any fetch; subsequent fetches read the new value.
pub fn set_max_fetch_bytes(limit: u64) {
    MAX_FETCH_BYTES.store(limit, Ordering::Relaxed);
}

/// The current per-fetch byte ceiling.
#[must_use]
pub fn max_fetch_bytes() -> u64 {
    MAX_FETCH_BYTES.load(Ordering::Relaxed)
}
/// Redirect-chain cap.
const MAX_REDIRECTS: u32 = 10;

/// The one network operation. Backends: [`HttpFetch`] (real, SSRF-guarded)
/// and [`Fixtures`] (offline tests).
pub trait Fetch {
    /// Retrieve the bytes at `url`, following redirects.
    fn get(&self, url: &str) -> Result<Fetched, FetchError>;

    /// Retrieve the bytes at `url` with extra request `headers`, following
    /// redirects. Defaults to a plain [`get`](Self::get) — a backend overrides
    /// it only when a registry mandates a request header on a GET (e.g. the Snap
    /// Store, which 400s without `Snap-Device-Series`). Test backends that key on
    /// URL alone inherit the default unchanged.
    fn get_with(&self, url: &str, _headers: &[(&str, &str)]) -> Result<Fetched, FetchError> {
        self.get(url)
    }

    /// POST `body` with the given `(name, value)` headers and return the
    /// response. Defaults to unsupported; a backend overrides it only when a
    /// registry needs it — e.g. the VS Code Marketplace's JSON-RPC query, which
    /// has no GET form. POST is not redirect-followed.
    fn post(
        &self,
        _url: &str,
        _body: &[u8],
        _headers: &[(&str, &str)],
    ) -> Result<Fetched, FetchError> {
        Err(FetchError::Refused(
            "POST not supported by this backend".into(),
        ))
    }
}

/// A successful fetch with the provenance the transport observed.
#[derive(Debug, Clone)]
pub struct Fetched {
    /// The retrieved bytes.
    pub bytes: Vec<u8>,
    /// Final URL after redirects (equal to the request URL if none).
    pub final_url: String,
    /// HTTP status code.
    pub status: u16,
    /// Response headers, in arrival order.
    pub headers: Vec<(String, String)>,
    /// Intermediate redirect URLs, in order.
    pub redirects: Vec<String>,
}

/// Why a fetch produced no bytes.
#[derive(Debug, Clone, thiserror::Error)]
pub enum FetchError {
    /// Refused before/at connect — SSRF guard, disallowed scheme, private
    /// host, too many redirects.
    #[error("refused: {0}")]
    Refused(String),
    /// Server returned a non-success status.
    #[error("http status {0}")]
    Status(u16),
    /// Response exceeded the size ceiling.
    #[error("response too large")]
    TooLarge,
    /// The request timed out.
    #[error("timed out")]
    Timeout,
    /// Transport / IO failure.
    #[error("transport: {0}")]
    Transport(String),
}

/// The terminal result of trying to fetch one reference.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Fetched (or served from cache) and, if pinned, verified.
    Ok,
    /// Bytes whose hash did not match the declared pin — a finding.
    PinMismatch,
    /// Locator could not be resolved to a URL (unsupported ecosystem).
    Unresolved,
    /// Not a fetch target (identity / unclassified) — recorded, not fetched.
    Skipped,
    /// The per-run fetch budget was exhausted before this reference — recorded
    /// so the cap is never a silent truncation.
    BudgetExceeded,
    /// The fetch failed; carries the reason.
    Failed(String),
}

/// A fetch edge + provenance for one reference. `source_sha256 → content_sha256`
/// is a self-contained hash→hash edge, so the trigger↔payload link survives
/// content-addressed storage where files are split apart and array position is
/// gone. Serialized into reports so a finding in fetched content can be traced
/// to what was retrieved, from where, when, with what headers, and how it
/// verified.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FetchRecord {
    /// sha256 of the file that declared this reference — the edge's *source*
    /// endpoint. Stamped by [`fetch_references`].
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source_sha256: String,
    /// Byte offset of the declaring reference in the source file — the
    /// citation anchor, so a finding derived from what was fetched can be
    /// pinned to the exact reference site. Stamped by [`fetch_references`]
    /// alongside `source_sha256`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_offset: Option<u64>,
    /// The reference's locator (PURL/URL) as emitted by filefacts.
    pub locator: String,
    /// The URL the locator resolved to. Empty when unresolved/skipped.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub resolved_url: String,
    /// Final URL after redirects, when the fetch reached the network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_url: Option<String>,
    /// Redirect chain, if any.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redirects: Vec<String>,
    /// HTTP status, when the fetch reached the network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Response headers, when the fetch reached the network.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<(String, String)>,
    /// Unix-seconds timestamp of the fetch (the original fetch time for a
    /// cache hit). `0` when no fetch occurred (skipped/unresolved).
    pub fetched_at: u64,
    /// SHA-256 of the fetched bytes — the content (hopper) lookup key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_sha256: Option<String>,
    /// Size of the fetched bytes in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Whether the bytes came from the blob cache rather than the network.
    pub cached: bool,
    /// Whether the bytes were served from cache *past their TTL* because a
    /// fresh fetch couldn't be made (the source was unreachable) — so the
    /// content may be outdated. Always implies `cached`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub stale: bool,
    /// Pin verification: `Some(true/false)` when the reference declared a
    /// verifiable pin (sha256/sha512); `None` when unpinned or the pin
    /// algorithm can't be checked against raw bytes (Go `h1:`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin_verified: Option<bool>,
    /// The terminal outcome.
    pub outcome: Outcome,
}

impl FetchRecord {
    /// A record that never reached the network (skipped / unresolved).
    fn terminal(locator: String, outcome: Outcome) -> Self {
        Self {
            source_sha256: String::new(),
            source_offset: None,
            locator,
            resolved_url: String::new(),
            final_url: None,
            redirects: Vec::new(),
            status: None,
            headers: Vec::new(),
            fetched_at: 0,
            content_sha256: None,
            size: None,
            cached: false,
            stale: false,
            pin_verified: None,
            outcome,
        }
    }
}

/// `skip_serializing_if` helper for a default-`false` flag.
fn is_false(b: &bool) -> bool {
    !*b
}

/// Cached provenance stored next to the bytes, so a cache hit reconstructs
/// the full [`FetchRecord`] (headers, timestamp, redirects) without a fetch.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct CachedMeta {
    fetched_at: u64,
    status: u16,
    final_url: String,
    redirects: Vec<String>,
    headers: Vec<(String, String)>,
}

/// Content-addressed cache of fetched responses — bytes (`<key>.zst`) plus a
/// provenance sidecar (`<key>.json`), keyed by `sha256(locator)`. Two
/// manifests naming the same package share one entry. TTL is the caller's
/// policy (passed to [`BlobCache::fresh`]).
#[derive(Debug, Clone)]
pub struct BlobCache {
    dir: PathBuf,
    /// When false, every read misses and every write is a no-op — the cache is
    /// inert. Used to force always-fresh fetches and to keep tests hermetic.
    enabled: bool,
}

impl BlobCache {
    /// Open the cache under the OS cache directory (`…/fletch/refs`).
    pub fn open() -> anyhow::Result<Self> {
        let dir = dirs::cache_dir()
            .ok_or_else(|| anyhow::anyhow!("no OS cache directory"))?
            .join("fletch")
            .join("refs");
        Ok(Self::with_dir(dir))
    }

    /// Open a cache rooted at an explicit directory (created on first write).
    #[must_use]
    pub fn with_dir(dir: PathBuf) -> Self {
        Self { dir, enabled: true }
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
        }
    }

    fn blob_path(&self, key: &str) -> PathBuf {
        self.dir.join(format!("{key}.zst"))
    }

    fn meta_path(&self, key: &str) -> PathBuf {
        self.dir.join(format!("{key}.json"))
    }

    /// Read a cache entry and its age, regardless of freshness. A missing
    /// sidecar yields default provenance.
    fn read(&self, key: &str) -> Option<(Vec<u8>, CachedMeta, Duration)> {
        if !self.enabled {
            return None;
        }
        let blob = self.blob_path(key);
        let age = std::fs::metadata(&blob)
            .ok()?
            .modified()
            .ok()?
            .elapsed()
            .ok()?;
        let bytes = zstd::decode_all(std::fs::read(&blob).ok()?.as_slice()).ok()?;
        let meta = std::fs::read(self.meta_path(key))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        Some((bytes, meta, age))
    }

    /// Cached bytes + provenance for `key`, if present and younger than
    /// `max_age`.
    fn fresh(&self, key: &str, max_age: Duration) -> Option<(Vec<u8>, CachedMeta)> {
        let (bytes, meta, age) = self.read(key)?;
        (age <= max_age).then_some((bytes, meta))
    }

    /// Cached bytes + provenance for `key` at any age — the fallback when a
    /// fresh fetch can't be made (the source is unreachable).
    fn any(&self, key: &str) -> Option<(Vec<u8>, CachedMeta)> {
        self.read(key).map(|(bytes, meta, _)| (bytes, meta))
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
    fn put(&self, key: &str, bytes: &[u8], meta: &CachedMeta) {
        if !self.enabled {
            return;
        }
        if std::fs::create_dir_all(&self.dir).is_err() {
            return;
        }
        if let Ok(compressed) = zstd::encode_all(bytes, 3) {
            let _ = std::fs::write(self.blob_path(key), compressed);
        }
        if let Ok(json) = serde_json::to_vec(meta) {
            let _ = std::fs::write(self.meta_path(key), json);
        }
    }
}

/// Fetch a registry *metadata* document through the blob cache. Used by
/// [`provenance`](crate::provenance) so a package's facts (publish date, author,
/// downloads) cost one round-trip per cache window and are free on a hit.
///
/// Metadata is small and a release's facts are effectively immutable, so the
/// pinned TTL bounds staleness for the few moving fields (dist-tags, download
/// counts) without re-fetching every scan. A network failure with no cached
/// copy yields `None`; the caller treats that as "unknown".
pub(crate) fn cached_metadata(url: &str, net: &dyn Fetch, cache: &BlobCache) -> Option<Vec<u8>> {
    cached_metadata_with(url, &[], net, cache)
}

/// Like [`cached_metadata`] but attaches request `headers` to the GET, for a
/// registry that mandates one (e.g. the Snap Store's `Snap-Device-Series`). The
/// headers fold into the cache key so a different header set is a distinct
/// entry; an empty set reuses [`cached_metadata`]'s key exactly.
pub(crate) fn cached_metadata_with(
    url: &str,
    headers: &[(&str, &str)],
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Option<Vec<u8>> {
    let key = if headers.is_empty() {
        sha256_hex(format!("meta:{url}").as_bytes())
    } else {
        let joined = headers
            .iter()
            .map(|(k, v)| format!("{k}:{v}"))
            .collect::<Vec<_>>()
            .join(";");
        sha256_hex(format!("meta:{url}:{joined}").as_bytes())
    };
    if let Some((bytes, _)) = cache.fresh(&key, TTL_PINNED) {
        return Some(bytes);
    }
    match net.get_with(url, headers) {
        Ok(f) => {
            let meta = CachedMeta {
                fetched_at: now(),
                status: f.status,
                final_url: f.final_url,
                redirects: f.redirects,
                headers: f.headers,
            };
            cache.put(&key, &f.bytes, &meta);
            Some(f.bytes)
        }
        // Source unreachable: a stale metadata answer still beats none.
        Err(_) => cache.any(&key).map(|(bytes, _)| bytes),
    }
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
) -> Option<Vec<u8>> {
    let key = sha256_hex(format!("post:{url}:{}", sha256_hex(body)).as_bytes());
    if let Some((bytes, _)) = cache.fresh(&key, TTL_PINNED) {
        return Some(bytes);
    }
    match net.post(url, body, headers) {
        Ok(f) => {
            let meta = CachedMeta {
                fetched_at: now(),
                status: f.status,
                final_url: f.final_url,
                redirects: f.redirects,
                headers: f.headers,
            };
            cache.put(&key, &f.bytes, &meta);
            Some(f.bytes)
        }
        Err(_) => cache.any(&key).map(|(bytes, _)| bytes),
    }
}

/// Resolve, fetch (or serve from cache), verify, and record provenance for
/// one reference. Never panics; every path yields a [`FetchRecord`].
#[must_use]
pub fn fetch_ref(r: &Reference, net: &dyn Fetch, cache: &BlobCache) -> FetchRecord {
    fetch_ref_inner(r, net, cache, || true)
}

/// Whether a record represents a live network fetch — so it counts against the
/// [`FetchBudget::max_count`] ceiling. A cache hit (fresh or stale-served), an
/// unresolved locator, a non-target, and a budget-skipped edge do not count, so
/// a re-run over a warm cache is never throttled.
#[must_use]
pub fn counts_against_budget(rec: &FetchRecord) -> bool {
    !rec.cached && matches!(rec.outcome, Outcome::Ok | Outcome::PinMismatch | Outcome::Failed(_))
}

/// [`fetch_ref`], with a `claim_fetch` gate consulted **only on a cache miss**,
/// just before the network is touched. It returns `true` to permit the live
/// fetch (and, in [`fetch_references`], to claim a slot of the count budget) or
/// `false` to record [`Outcome::BudgetExceeded`] instead. Consulting it lazily —
/// after the cache check — is what keeps a cache hit entirely free of the
/// budget: a hit returns before `claim_fetch` is ever called, so it can neither
/// be counted nor (under concurrency) transiently hold a slot from a real miss.
#[must_use]
fn fetch_ref_inner(
    r: &Reference,
    net: &dyn Fetch,
    cache: &BlobCache,
    claim_fetch: impl FnOnce() -> bool,
) -> FetchRecord {
    let locator = locator_string(&r.locator);

    if !r.is_fetch_target() {
        return FetchRecord::terminal(locator, Outcome::Skipped);
    }
    // Resolution may refine the locator: a versionless npm PURL (a manifest
    // range/tag) becomes the concrete `name@<resolved>` it currently points at,
    // so the cache key and the recorded edge name the version actually fetched.
    let Some((locator, url)) = resolved_target(&r.locator, net) else {
        return FetchRecord::terminal(locator, Outcome::Unresolved);
    };

    let key = sha256_hex(locator.as_bytes());
    let max_age = if r.pinned_hash.is_some() {
        TTL_PINNED
    } else {
        TTL_UNPINNED
    };

    if let Some((bytes, meta)) = cache.fresh(&key, max_age) {
        return record(r, locator, url, &bytes, true, false, &meta);
    }

    if !claim_fetch() {
        // Count budget spent: record the edge without fetching so the cap is
        // never a silent truncation, and a later run can still pick it up.
        let mut rec = FetchRecord::terminal(locator, Outcome::BudgetExceeded);
        rec.resolved_url = url;
        return rec;
    }

    match net.get(&url) {
        Ok(f) => {
            let meta = CachedMeta {
                fetched_at: now(),
                status: f.status,
                final_url: f.final_url,
                redirects: f.redirects,
                headers: f.headers,
            };
            cache.put(&key, &f.bytes, &meta);
            record(r, locator, url, &f.bytes, false, false, &meta)
        }
        // The source is unreachable. Fall back to any cached copy, however
        // old — a stale answer beats none — and mark it stale. Only a genuine
        // cache miss is a failure.
        Err(e) => match cache.any(&key) {
            Some((bytes, meta)) => {
                tracing::warn!(locator = %locator, error = %e, "fetch failed; serving stale cache");
                record(r, locator, url, &bytes, true, true, &meta)
            }
            None => {
                let mut rec = FetchRecord::terminal(locator, Outcome::Failed(e.to_string()));
                rec.resolved_url = url;
                rec.fetched_at = now();
                rec
            }
        },
    }
}

/// Per-run ceiling on fetching, so one analysis can't turn into a fetch
/// storm. A manifest with thousands of deps fetches up to the cap; the rest
/// are recorded as [`Outcome::BudgetExceeded`], never silently dropped.
#[derive(Debug, Clone, Copy)]
pub struct FetchBudget {
    /// Maximum number of references to fetch.
    pub max_count: usize,
    /// Maximum total bytes to retrieve.
    pub max_bytes: u64,
}

impl Default for FetchBudget {
    fn default() -> Self {
        Self {
            // A real dependency closure routinely exceeds 256 (a single Rust
            // crate's Cargo.lock can name 400+), so cap at 512 to cover the
            // common case without unbounding a crafted reference fan-out.
            max_count: 512,
            // 5 GiB retrieved per whole run (every hop, every file) — the safety
            // ceiling against a crafted reference chain, not a per-fetch limit
            // (that is `MAX_FETCH_BYTES`).
            max_bytes: 5 * 1024 * 1024 * 1024,
        }
    }
}

/// Per-call ceiling on concurrent fetches. Fetching is network-bound, so this
/// is independent of the CPU pool; it scales with the host and is clamped so a
/// long reference list can't spawn an unbounded number of sockets, while a
/// small host still parallelizes. Uses scoped OS threads rather than a shared
/// rayon/CPU pool so a fetching worker never starves concurrent analysis.
fn fetch_concurrency() -> usize {
    std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(4)
        .clamp(2, 16)
}

/// Fetch every selectable reference, in declaration order, under `budget`,
/// returning one [`FetchRecord`] edge per attempt (including budget-skipped
/// ones), each stamped with `source_sha256` (the file that declared the
/// references) so it is a self-contained hash→hash edge. `fetch_urls` enables
/// raw-URL targets; without it only registry packages (PURLs) are fetched.
/// Identity references (a repository) are never fetched.
///
/// Fetches run concurrently across a bounded pool ([`fetch_concurrency`]); the
/// returned order is always declaration order regardless of completion order.
/// `max_count` bounds *live* fetches only: a slot is claimed atomically the
/// moment a cache miss is about to hit the network, so the live total never
/// exceeds the cap, while cache hits are served before any slot is claimed and
/// so are never counted — a warm re-run is never throttled. Which references win
/// a contested cap is not guaranteed (two equal-priority misses race for the
/// last slot, and live fetches aren't reproducible anyway). `max_bytes` is
/// best-effort: once retrieved bytes cross it the sweep stops and the remaining
/// references are recorded as `BudgetExceeded`.
#[must_use]
pub fn fetch_references(
    refs: &[Reference],
    source_sha256: &str,
    fetch_urls: bool,
    net: &(dyn Fetch + Sync),
    cache: &BlobCache,
    budget: FetchBudget,
) -> Vec<FetchRecord> {
    // Selectable references, in declaration order. Every target is visited; the
    // caps are enforced live below — the byte cap stops the sweep, the count cap
    // gates only *network* fetches (cache hits are always served, never counted).
    let targets: Vec<&Reference> = refs.iter().filter(|r| selected(r, fetch_urls)).collect();
    let fetch_n = if budget.max_bytes == 0 { 0 } else { targets.len() };

    // Sweep targets[0..fetch_n] across a bounded thread pool. Each worker pulls
    // the next index from a shared cursor and stops once the byte budget is
    // spent; results land in per-index slots so output order is stable.
    let mut slots: Vec<Option<FetchRecord>> = (0..fetch_n).map(|_| None).collect();
    if fetch_n > 0 {
        let cursor = AtomicUsize::new(0);
        let bytes_used = AtomicU64::new(0);
        // Live fetches issued so far. A cache hit never bumps this, so a warm
        // re-run serves every reference regardless of `max_count`.
        let net_used = AtomicUsize::new(0);
        let workers = fetch_concurrency().min(fetch_n);
        let collected: Vec<Vec<(usize, FetchRecord)>> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..workers)
                .map(|_| {
                    scope.spawn(|| {
                        let mut local = Vec::new();
                        loop {
                            if bytes_used.load(Ordering::Relaxed) >= budget.max_bytes {
                                break;
                            }
                            let i = cursor.fetch_add(1, Ordering::Relaxed);
                            if i >= fetch_n {
                                break;
                            }
                            // Claim a live-fetch slot atomically, but only when
                            // the ref turns out to be a cache miss — the gate is
                            // consulted inside `fetch_ref_inner`, after the cache
                            // check. So a cache hit never touches `net_used`
                            // (served free), and concurrent workers can never
                            // claim more than `max_count` slots: the live total
                            // is an exact ceiling, not best-effort.
                            let rec = fetch_ref_inner(targets[i], net, cache, || {
                                net_used
                                    .fetch_update(
                                        Ordering::Relaxed,
                                        Ordering::Relaxed,
                                        |n| (n < budget.max_count).then_some(n + 1),
                                    )
                                    .is_ok()
                            });
                            bytes_used.fetch_add(rec.size.unwrap_or(0), Ordering::Relaxed);
                            local.push((i, rec));
                        }
                        local
                    })
                })
                .collect();
            handles.into_iter().filter_map(|h| h.join().ok()).collect()
        });
        for chunk in collected {
            for (i, rec) in chunk {
                slots[i] = Some(rec);
            }
        }
    }

    // Reassemble in declaration order: the fetched record where one exists, a
    // `BudgetExceeded` edge for any index the byte cap cut short. Every record
    // carries its source so it stands alone as an edge.
    let mut records = Vec::with_capacity(targets.len());
    for (i, r) in targets.iter().enumerate() {
        let mut rec = slots.get_mut(i).and_then(Option::take).unwrap_or_else(|| {
            FetchRecord::terminal(locator_string(&r.locator), Outcome::BudgetExceeded)
        });
        rec.source_sha256 = source_sha256.to_string();
        rec.source_offset = Some(r.offset);
        records.push(rec);
    }
    records
}

/// Whether a reference should be fetched: a fetch target whose locator is a
/// package (always) or a raw URL (only with `fetch_urls`).
fn selected(r: &Reference, fetch_urls: bool) -> bool {
    r.is_fetch_target()
        && match r.locator {
            RefLocator::Purl(_) => true,
            RefLocator::Url(_) => fetch_urls,
            // An intra-artifact path is resolved against sibling files, not fetched.
            RefLocator::Path(_) => false,
        }
}

/// Build a record for bytes in hand (network or cache), verifying the pin
/// and choosing the outcome.
fn record(
    r: &Reference,
    locator: String,
    resolved_url: String,
    bytes: &[u8],
    cached: bool,
    stale: bool,
    meta: &CachedMeta,
) -> FetchRecord {
    let content_sha256 = sha256_hex(bytes);
    let pin_verified = verify_pin(r.pinned_hash.as_ref(), bytes, &content_sha256);
    let outcome = if pin_verified == Some(false) {
        Outcome::PinMismatch
    } else {
        Outcome::Ok
    };
    FetchRecord {
        source_sha256: String::new(),
        source_offset: None,
        locator,
        resolved_url,
        final_url: Some(meta.final_url.clone()),
        redirects: meta.redirects.clone(),
        status: Some(meta.status),
        headers: meta.headers.clone(),
        fetched_at: meta.fetched_at,
        content_sha256: Some(content_sha256),
        size: Some(bytes.len() as u64),
        cached,
        stale,
        pin_verified,
        outcome,
    }
}

/// The canonical locator string (the PURL or URL).
fn locator_string(locator: &RefLocator) -> String {
    match locator {
        RefLocator::Purl(s) | RefLocator::Url(s) | RefLocator::Path(s) => s.clone(),
    }
}

/// Resolve a locator to a fetchable URL, or `None` if the ecosystem isn't
/// supported yet (PyPI/Go/alpm need a registry round-trip — follow-ups).
#[must_use]
pub fn resolve(locator: &RefLocator) -> Option<String> {
    match locator {
        RefLocator::Url(u) => Some(u.clone()),
        RefLocator::Purl(p) => resolve_purl(p),
        // An intra-artifact file reference is resolved against the bundle's
        // other files by a consumer, never fetched.
        RefLocator::Path(_) => None,
    }
}

/// Map a PURL to a deterministic download URL for the computable
/// ecosystems (npm, crates.io, GitHub archive).
fn resolve_purl(purl: &str) -> Option<String> {
    let body = purl.strip_prefix("pkg:")?;
    let (ty, rest) = body.split_once('/')?;
    // The version is after the literal `@` (a scope is `%40`, not `@`).
    let (path, version) = rest
        .rsplit_once('@')
        .map_or((rest, None), |(p, v)| (p, Some(v)));
    match ty {
        "npm" => {
            let name = path.replace("%40", "@");
            let base = name.rsplit('/').next().unwrap_or(name.as_str());
            let version = version?;
            Some(format!(
                "https://registry.npmjs.org/{name}/-/{base}-{version}.tgz"
            ))
        }
        "cargo" => {
            let version = version?;
            Some(format!(
                "https://static.crates.io/crates/{path}/{path}-{version}.crate"
            ))
        }
        "github" => {
            let reference = version.unwrap_or("HEAD");
            Some(format!(
                "https://codeload.github.com/{path}/tar.gz/{reference}"
            ))
        }
        "golang" => {
            let version = version?;
            // The default Go module proxy. Module path and version are
            // case-encoded per the GOPROXY protocol.
            Some(format!(
                "https://proxy.golang.org/{}/@v/{}.zip",
                goproxy_escape(path),
                goproxy_escape(version)
            ))
        }
        "gem" => {
            let version = version?;
            Some(format!(
                "https://rubygems.org/downloads/{path}-{version}.gem"
            ))
        }
        "chrome" => {
            // The CRX download service redirects to the current packed
            // extension; `id` is the last path segment (a slug may precede it).
            let id = path.rsplit('/').next().unwrap_or(path);
            Some(format!(
                "https://clients2.google.com/service/update2/crx?response=redirect&prodversion=120&acceptformat=crx2,crx3&x=id%3D{id}%26installsource%3Dondemand%26uc"
            ))
        }
        _ => None,
    }
}

/// Resolve a reference to `(canonical locator, fetchable URL)`. Most ecosystems
/// are a pure name+version → URL mapping ([`resolve`]), and the locator passes
/// through unchanged. The exceptions take a registry round-trip over `net`:
/// PyPI and Composer have no derivable artifact URL, and a versionless npm PURL
/// (a manifest range/tag) is *refined* to the concrete `name@version` it
/// currently points at — that refined locator is returned so it keys the cache
/// and names the fetch edge. `None` when the ecosystem can't be resolved.
fn resolved_target(locator: &RefLocator, net: &dyn Fetch) -> Option<(String, String)> {
    if let RefLocator::Purl(p) = locator
        && let Some(body) = p.strip_prefix("pkg:")
        && let Some((ty, rest)) = body.split_once('/')
    {
        // A scope is `%40`, so a literal `@` only ever separates the version;
        // its absence means the npm dependency named no version.
        if ty == "npm" && !rest.contains('@') {
            return resolve_npm_unversioned(rest, net);
        }
        // Open VSX publishes the exact `.vsix` URL in its API for both a pinned
        // and the latest version, so resolve through it rather than guessing.
        if ty == "openvsx" {
            return resolve_openvsx(rest, net).map(|u| (p.clone(), u));
        }
        // The VS Code Marketplace's `.vsix` lives at a well-known gallery URL,
        // but the latest version (when unpinned) comes from the query API.
        if ty == "vscode" {
            return resolve_vscode(rest, net).map(|u| (p.clone(), u));
        }
        if let Some((path, version)) = rest.rsplit_once('@') {
            // Split any PURL `?qualifiers` off the version. `kind` (`wheel` /
            // `sdist`) lets a PyPI PURL pick the artifact; the bare version is
            // what every download API actually wants.
            let (version, kind) = split_version_kind(version);
            match ty {
                "pypi" => return resolve_pypi(path, version, kind, net).map(|u| (p.clone(), u)),
                "composer" => return resolve_composer(path, version, net).map(|u| (p.clone(), u)),
                _ => {}
            }
        }
    }
    resolve(locator).map(|u| (locator_string(locator), u))
}

// TODO(fetch-latest): a versionless npm dependency (a manifest range/tag/
// wildcard like `^1.11.21`) is resolved to the registry's current
// `dist-tags.latest`, not the highest version the declared range admits.
// Implementing npm's semver range algebra (caret/tilde/comparators/unions/
// hyphen/wildcards) would pull in a semver matcher and a long tail of edge
// cases. For threat assessment the relevant, most-conservative answer is "what
// does this name serve right now" — the attacker-controlled current release —
// and the declared range is preserved as the reference's evidence. Revisit if
// range-accurate resolution is ever needed.
/// Resolve a versionless npm PURL path (`left-pad`, `%40scope/util`) to the
/// concrete `(pkg:npm/<path>@<latest>, tarball URL)` it currently points at, by
/// reading the registry packument's `dist-tags.latest`. The registry's own
/// tarball URL is preferred over the derived one. `None` if the packument can't
/// be fetched/parsed or names no latest version.
fn resolve_npm_unversioned(path: &str, net: &dyn Fetch) -> Option<(String, String)> {
    let name = path.replace("%40", "@");
    let packument = net
        .get(&format!("https://registry.npmjs.org/{name}"))
        .ok()?;
    let doc: serde_json::Value = serde_json::from_slice(&packument.bytes).ok()?;
    let latest = doc.pointer("/dist-tags/latest")?.as_str()?;
    let locator = format!("pkg:npm/{path}@{latest}");
    let url = doc
        .pointer(&format!("/versions/{latest}/dist/tarball"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .or_else(|| resolve_purl(&locator))?;
    Some((locator, url))
}

/// Split a PURL version field on its `?` qualifier string, returning the bare
/// version and the value of the `kind` qualifier if present. PURL qualifiers are
/// `?key=value(&key=value)*`; only `kind` (`wheel`/`sdist`) is consulted, the
/// rest are ignored. `1.2.3?kind=wheel` → `("1.2.3", Some("wheel"))`.
fn split_version_kind(version: &str) -> (&str, Option<&str>) {
    let (bare, qualifiers) = version.split_once('?').unwrap_or((version, ""));
    let kind = qualifiers
        .split('&')
        .find_map(|kv| kv.strip_prefix("kind="));
    (bare, kind)
}

/// PyPI publishes no deterministic download URL (the `files.pythonhosted.org`
/// path carries an undrivable hash segment), so ask the JSON API and pick an
/// artifact from the version's files.
///
/// Default is wheel-first with an sdist fallback, mirroring what a modern `pip
/// install` actually runs on the victim's machine; `?kind=sdist` flips the
/// preference to the source distribution (one per version, carrying `setup.py` /
/// `pyproject.toml` — the install-hook attack surface), and `?kind=wheel` is the
/// default's explicit form. Whichever is preferred, the other is the fallback so
/// a package that ships only one kind still resolves.
fn resolve_pypi(name: &str, version: &str, kind: Option<&str>, net: &dyn Fetch) -> Option<String> {
    let api = format!("https://pypi.org/pypi/{name}/{version}/json");
    let resp = net.get(&api).ok()?;
    let json: serde_json::Value = serde_json::from_slice(&resp.bytes).ok()?;
    let urls = json.get("urls")?.as_array()?;
    let pick = match kind {
        // Explicit source-distribution request: sdist first, wheel as fallback.
        Some("sdist") => pick_sdist(urls).or_else(|| pick_wheel(urls)),
        // Default and explicit `kind=wheel`: wheel first, sdist as fallback.
        _ => pick_wheel(urls).or_else(|| pick_sdist(urls)),
    }
    // Last resort: an unusual files list with neither a recognized wheel nor
    // sdist — take whatever is first rather than resolving to nothing.
    .or_else(|| urls.first())?;
    pick.get("url")
        .and_then(serde_json::Value::as_str)
        .map(String::from)
}

/// The one source distribution among a PyPI version's files (there is at most
/// one per version), or `None` if this version publishes only wheels.
fn pick_sdist(urls: &[serde_json::Value]) -> Option<&serde_json::Value> {
    urls.iter()
        .find(|u| u.get("packagetype").and_then(serde_json::Value::as_str) == Some("sdist"))
}

/// The most representative wheel among a PyPI version's files. A version may
/// publish anywhere from zero wheels (sdist-only) to dozens (one per
/// platform/Python ABI), so the choice is deterministic: prefer the universal
/// pure-Python `py3-none-any` wheel (a single platform-agnostic artifact), then
/// any other `none-any` wheel, then the first platform wheel. `None` if this
/// version publishes no wheel at all.
fn pick_wheel(urls: &[serde_json::Value]) -> Option<&serde_json::Value> {
    let is_wheel = |u: &&serde_json::Value| {
        u.get("packagetype").and_then(serde_json::Value::as_str) == Some("bdist_wheel")
    };
    let filename = |u: &serde_json::Value| -> String {
        u.get("filename")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    urls.iter()
        .filter(is_wheel)
        .find(|u| filename(u).ends_with("-py3-none-any.whl"))
        .or_else(|| {
            urls.iter()
                .filter(is_wheel)
                .find(|u| filename(u).contains("-none-any."))
        })
        .or_else(|| urls.iter().find(is_wheel))
}

/// Open VSX publishes the `.vsix` download URL in its JSON API. `rest` is
/// `<namespace>/<name>[@<version>]`; without a version the API returns the
/// latest release. Returns the `files.download` URL — the exact artifact a
/// client would install.
fn resolve_openvsx(rest: &str, net: &dyn Fetch) -> Option<String> {
    let (path, version) = rest
        .rsplit_once('@')
        .map_or((rest, None), |(p, v)| (p, Some(v)));
    let (ns, name) = path.split_once('/')?;
    let api = match version {
        Some(v) => format!("https://open-vsx.org/api/{ns}/{name}/{v}"),
        None => format!("https://open-vsx.org/api/{ns}/{name}"),
    };
    let resp = net.get(&api).ok()?;
    let json: serde_json::Value = serde_json::from_slice(&resp.bytes).ok()?;
    json.pointer("/files/download")
        .and_then(serde_json::Value::as_str)
        .map(String::from)
}

/// The VS Code Marketplace `.vsix` lives at a deterministic gallery URL once the
/// version is known. `rest` is `<publisher>/<name>[@<version>]`; an unpinned
/// reference resolves the latest version through the JSON-RPC query first.
fn resolve_vscode(rest: &str, net: &dyn Fetch) -> Option<String> {
    let (path, version) = rest
        .rsplit_once('@')
        .map_or((rest, None), |(p, v)| (p, Some(v.to_string())));
    let (publisher, name) = path.split_once('/')?;
    let version = match version {
        Some(v) => v,
        None => {
            let body = format!(
                r#"{{"filters":[{{"criteria":[{{"filterType":7,"value":"{publisher}.{name}"}}]}}],"flags":914}}"#
            );
            let headers = [
                ("Content-Type", "application/json"),
                ("Accept", "application/json;api-version=3.0-preview.1"),
            ];
            let resp = net
                .post(
                    "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery",
                    body.as_bytes(),
                    &headers,
                )
                .ok()?;
            let json: serde_json::Value = serde_json::from_slice(&resp.bytes).ok()?;
            json.pointer("/results/0/extensions/0/versions/0/version")
                .and_then(serde_json::Value::as_str)?
                .to_string()
        }
    };
    Some(format!(
        "https://{publisher}.gallery.vsassets.io/_apis/public/gallery/publisher/{publisher}/extension/{name}/{version}/assetbyname/Microsoft.VisualStudio.Services.VSIXPackage"
    ))
}

/// Composer's download URL lives in Packagist's per-package metadata, not a
/// derivable path. Fetch the v2 metadata, find the matching version, and return
/// its `dist.url` (the exact artifact Composer would install). `name` is
/// `vendor/package`.
fn resolve_composer(name: &str, version: &str, net: &dyn Fetch) -> Option<String> {
    let api = format!("https://repo.packagist.org/p2/{name}.json");
    let resp = net.get(&api).ok()?;
    let json: serde_json::Value = serde_json::from_slice(&resp.bytes).ok()?;
    let versions = json.get("packages")?.get(name)?.as_array()?;
    let want = version.trim_start_matches('v');
    versions
        .iter()
        .find(|v| {
            v.get("version")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|s| s.trim_start_matches('v') == want)
        })
        .and_then(|v| v.get("dist")?.get("url")?.as_str())
        .map(String::from)
}

/// GOPROXY case-encoding: every uppercase ASCII letter becomes `!` followed by
/// its lowercase form, so module paths can't collide on case-insensitive file
/// systems (`github.com/BurntSushi/toml` → `github.com/!burnt!sushi/toml`).
pub(crate) fn goproxy_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_uppercase() {
            out.push('!');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Verify fetched bytes against a declared pin. `None` when there is no pin
/// or the algorithm can't be checked against raw content (Go `h1:` is a
/// tree hash; SHA-1 isn't computed here; future algorithms via the `_`).
fn verify_pin(pin: Option<&PinnedHash>, bytes: &[u8], sha256_hex: &str) -> Option<bool> {
    let pin = pin?;
    match pin.algo {
        HashAlgo::Sha256 => Some(pin.value.eq_ignore_ascii_case(sha256_hex)),
        HashAlgo::Sha512 => {
            // npm `integrity` carries base64.
            use base64::Engine as _;
            let b64 = base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes));
            Some(b64 == pin.value)
        }
        _ => None,
    }
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// SSRF floor: refuse any address that isn't globally routable.
// ---------------------------------------------------------------------------

/// Whether an address must not be fetched — private, loopback, link-local
/// (incl. the 169.254.169.254 metadata endpoint), CGNAT, ULA, or reserved.
/// IPv4-mapped IPv6 is unwrapped so it can't smuggle a private v4 address.
fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_blocked_v4(mapped);
            }
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // unique-local fc00::/7
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
        }
    }
}

fn is_blocked_v4(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local() // 169.254.0.0/16, incl. the cloud metadata IP
        || v4.is_broadcast()
        || v4.is_documentation()
        || v4.is_unspecified()
        || o[0] == 0 // 0.0.0.0/8
        || (o[0] == 100 && (64..=127).contains(&o[1])) // CGNAT 100.64.0.0/10
        || o[0] >= 240 // reserved 240.0.0.0/4
}

/// reqwest DNS resolver that resolves a host and returns only its globally
/// routable addresses, refusing the lookup if none remain. Installed on the
/// client, it runs for the initial request *and every redirect hop*, so an
/// attacker can't redirect into the internal network or DNS-rebind.
#[derive(Debug)]
struct SafeResolver;

impl reqwest::dns::Resolve for SafeResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let resolved = (host.as_str(), 0u16)
                .to_socket_addrs()
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
            let safe: Vec<SocketAddr> = resolved.filter(|a| !is_blocked_ip(a.ip())).collect();
            if safe.is_empty() {
                return Err(format!("refused non-public host: {host}").into());
            }
            Ok(Box::new(safe.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// The real network backend: an HTTPS client whose DNS resolver enforces the
/// SSRF floor. Redirects are followed manually so every hop is re-checked
/// for scheme and the chain is recorded; the response is size-capped.
#[derive(Debug)]
pub struct HttpFetch {
    client: reqwest::blocking::Client,
}

impl HttpFetch {
    /// Build the client. Anonymous (no cookies/credentials), timed out, with
    /// the SSRF-guarding resolver installed.
    pub fn new() -> anyhow::Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .user_agent("fletch")
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            // We follow redirects by hand (per-hop scheme check + chain).
            .redirect(reqwest::redirect::Policy::none())
            .dns_resolver(Arc::new(SafeResolver))
            .build()?;
        Ok(Self { client })
    }
}

/// Read a response body under the per-fetch byte ceiling ([`max_fetch_bytes`]).
/// A declared `Content-Length` over the cap is rejected before a single body
/// byte is read — the common case for an oversize artifact, which a registry or
/// CDN sizes honestly — so we don't pull tens of MB only to discard them. The
/// streaming `take` cap remains the authoritative backstop for a missing or
/// dishonest header.
fn read_body_capped(resp: reqwest::blocking::Response) -> Result<Vec<u8>, FetchError> {
    let limit = max_fetch_bytes();
    if let Some(len) = resp.content_length()
        && len > limit
    {
        return Err(FetchError::TooLarge);
    }
    let mut bytes = Vec::new();
    resp.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| FetchError::Transport(e.to_string()))?;
    if bytes.len() as u64 > limit {
        return Err(FetchError::TooLarge);
    }
    Ok(bytes)
}

impl HttpFetch {
    /// The shared GET path: per-hop https + SSRF enforcement, redirect following,
    /// and the response-size cap. `headers` are attached to every hop. Both
    /// [`Fetch::get`] and [`Fetch::get_with`] funnel through here so the security
    /// floor is defined exactly once.
    fn get_inner(&self, url: &str, headers: &[(&str, &str)]) -> Result<Fetched, FetchError> {
        let mut current =
            reqwest::Url::parse(url).map_err(|e| FetchError::Transport(e.to_string()))?;
        let mut redirects = Vec::new();

        for _ in 0..=MAX_REDIRECTS {
            if current.scheme() != "https" {
                return Err(FetchError::Refused(format!(
                    "non-https scheme: {}",
                    current.scheme()
                )));
            }
            // A literal-IP host never hits the DNS resolver, so the SSRF
            // floor must be enforced here too (incl. bracketed IPv6).
            match current.host_str() {
                Some(host) => {
                    let bare = host
                        .strip_prefix('[')
                        .and_then(|s| s.strip_suffix(']'))
                        .unwrap_or(host);
                    if let Ok(ip) = bare.parse::<IpAddr>()
                        && is_blocked_ip(ip)
                    {
                        return Err(FetchError::Refused(format!("non-public host: {host}")));
                    }
                }
                None => return Err(FetchError::Refused("missing host".into())),
            }
            let mut req = self.client.get(current.clone());
            for (name, value) in headers {
                req = req.header(*name, *value);
            }
            let resp = req.send().map_err(map_send_err)?;
            let status = resp.status();

            if status.is_redirection() {
                // Some servers (e.g. the Chrome Web Store) send a non-ASCII
                // `Location` with raw UTF-8 in the path; `to_str()` rejects that,
                // so fall back to a lossy decode and let `Url::join` percent-
                // encode it. The per-hop https + SSRF checks above still run.
                let location = resp
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .map(|v| {
                        v.to_str()
                            .map(str::to_string)
                            .unwrap_or_else(|_| String::from_utf8_lossy(v.as_bytes()).into_owned())
                    })
                    .ok_or_else(|| FetchError::Transport("redirect without location".into()))?;
                let next = current
                    .join(&location)
                    .map_err(|e| FetchError::Transport(e.to_string()))?;
                redirects.push(current.to_string());
                current = next;
                continue;
            }
            if !status.is_success() {
                return Err(FetchError::Status(status.as_u16()));
            }

            let headers = resp
                .headers()
                .iter()
                .filter_map(|(k, v)| {
                    v.to_str()
                        .ok()
                        .map(|val| (k.as_str().to_string(), val.into()))
                })
                .collect();
            let bytes = read_body_capped(resp)?;
            return Ok(Fetched {
                bytes,
                final_url: current.to_string(),
                status: status.as_u16(),
                headers,
                redirects,
            });
        }
        Err(FetchError::Refused("too many redirects".into()))
    }
}

impl Fetch for HttpFetch {
    fn get(&self, url: &str) -> Result<Fetched, FetchError> {
        self.get_inner(url, &[])
    }

    fn get_with(&self, url: &str, headers: &[(&str, &str)]) -> Result<Fetched, FetchError> {
        self.get_inner(url, headers)
    }

    fn post(
        &self,
        url: &str,
        body: &[u8],
        headers: &[(&str, &str)],
    ) -> Result<Fetched, FetchError> {
        let target = reqwest::Url::parse(url).map_err(|e| FetchError::Transport(e.to_string()))?;
        guard_host(&target)?;
        let mut req = self.client.post(target.clone()).body(body.to_vec());
        for (name, value) in headers {
            req = req.header(*name, *value);
        }
        let resp = req.send().map_err(map_send_err)?;
        let status = resp.status();
        // POST is not redirect-followed: a redirected query endpoint is an error
        // here, not a silent re-POST to another host.
        if !status.is_success() {
            return Err(FetchError::Status(status.as_u16()));
        }
        let resp_headers = resp
            .headers()
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|val| (k.as_str().to_string(), val.into()))
            })
            .collect();
        let bytes = read_body_capped(resp)?;
        Ok(Fetched {
            bytes,
            final_url: target.to_string(),
            status: status.as_u16(),
            headers: resp_headers,
            redirects: Vec::new(),
        })
    }
}

/// The pre-connect floor shared by GET and POST: https only, and refuse a
/// literal-IP host the DNS resolver never sees (the SSRF resolver guards
/// hostname targets; a bare IP must be checked directly).
fn guard_host(url: &reqwest::Url) -> Result<(), FetchError> {
    if url.scheme() != "https" {
        return Err(FetchError::Refused(format!(
            "non-https scheme: {}",
            url.scheme()
        )));
    }
    match url.host_str() {
        Some(host) => {
            let bare = host
                .strip_prefix('[')
                .and_then(|s| s.strip_suffix(']'))
                .unwrap_or(host);
            if let Ok(ip) = bare.parse::<IpAddr>()
                && is_blocked_ip(ip)
            {
                return Err(FetchError::Refused(format!("non-public host: {host}")));
            }
            Ok(())
        }
        None => Err(FetchError::Refused("missing host".into())),
    }
}

// Used as `map_err(map_send_err)`, so it must take the error by value even
// though it only inspects it.
#[allow(clippy::needless_pass_by_value)]
fn map_send_err(e: reqwest::Error) -> FetchError {
    if e.is_timeout() {
        FetchError::Timeout
    } else if e.is_connect() {
        // The SafeResolver's refusal surfaces here.
        FetchError::Refused(e.to_string())
    } else {
        FetchError::Transport(e.to_string())
    }
}

/// In-memory [`Fetch`] backend for tests: a fixed URL → response map. The
/// drop-in for [`HttpFetch`] so the orchestration runs offline.
#[derive(Debug, Default, Clone)]
pub struct Fixtures {
    responses: HashMap<String, Fetched>,
}

impl Fixtures {
    /// Register `bytes` as the 200 response for `url` (no headers/redirects).
    #[must_use]
    pub fn with(self, url: &str, bytes: &[u8]) -> Self {
        self.with_headers(url, bytes, &[])
    }

    /// Register a 200 response with explicit headers.
    #[must_use]
    pub fn with_headers(mut self, url: &str, bytes: &[u8], headers: &[(&str, &str)]) -> Self {
        self.responses.insert(
            url.to_string(),
            Fetched {
                bytes: bytes.to_vec(),
                final_url: url.to_string(),
                status: 200,
                headers: headers
                    .iter()
                    .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                    .collect(),
                redirects: Vec::new(),
            },
        );
        self
    }
}

impl Fetch for Fixtures {
    fn get(&self, url: &str) -> Result<Fetched, FetchError> {
        self.responses
            .get(url)
            .cloned()
            .ok_or_else(|| FetchError::Transport(format!("no fixture for {url}")))
    }

    /// A query's response is deterministic for its endpoint, so fixtures key on
    /// the URL and ignore the body.
    fn post(
        &self,
        url: &str,
        _body: &[u8],
        _headers: &[(&str, &str)],
    ) -> Result<Fetched, FetchError> {
        self.get(url)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use filefacts::RefKind;

    #[test]
    fn resolve_npm_unversioned_picks_latest_tarball() {
        // The packument names a current release; resolution refines the
        // versionless locator to it and returns the registry's tarball URL.
        let packument = br#"{
            "dist-tags": { "latest": "1.12.0" },
            "versions": {
                "1.11.21": { "dist": { "tarball": "https://registry.npmjs.org/easy-day-js/-/easy-day-js-1.11.21.tgz" } },
                "1.12.0":  { "dist": { "tarball": "https://registry.npmjs.org/easy-day-js/-/easy-day-js-1.12.0.tgz" } }
            }
        }"#;
        let net = Fixtures::default().with("https://registry.npmjs.org/easy-day-js", packument);
        assert_eq!(
            resolve_npm_unversioned("easy-day-js", &net),
            Some((
                "pkg:npm/easy-day-js@1.12.0".to_string(),
                "https://registry.npmjs.org/easy-day-js/-/easy-day-js-1.12.0.tgz".to_string()
            ))
        );
        // Scoped name: the `%40` encoding survives into the refined locator.
        let scoped = br#"{"dist-tags":{"latest":"2.0.0"},"versions":{"2.0.0":{"dist":{"tarball":"https://registry.npmjs.org/@scope/util/-/util-2.0.0.tgz"}}}}"#;
        let net = Fixtures::default().with("https://registry.npmjs.org/@scope/util", scoped);
        assert_eq!(
            resolve_npm_unversioned("%40scope/util", &net),
            Some((
                "pkg:npm/%40scope/util@2.0.0".to_string(),
                "https://registry.npmjs.org/@scope/util/-/util-2.0.0.tgz".to_string()
            ))
        );
        // Registry unreachable / unknown package → unresolved.
        assert_eq!(resolve_npm_unversioned("nope", &Fixtures::default()), None);
    }

    #[test]
    fn resolve_pypi_defaults_to_wheel_with_sdist_fallback() {
        let api = "https://pypi.org/pypi/requests/2.28.1/json";
        let body = br#"{"urls":[
            {"packagetype":"bdist_wheel","filename":"requests-2.28.1-py3-none-any.whl","url":"https://files.pythonhosted.org/w/requests-2.28.1-py3-none-any.whl"},
            {"packagetype":"sdist","filename":"requests-2.28.1.tar.gz","url":"https://files.pythonhosted.org/s/requests-2.28.1.tar.gz"}
        ]}"#;
        let net = Fixtures::default().with(api, body);
        let wheel = "https://files.pythonhosted.org/w/requests-2.28.1-py3-none-any.whl".to_string();
        let sdist = "https://files.pythonhosted.org/s/requests-2.28.1.tar.gz".to_string();
        // Default: wheel-first, mirroring `pip install`.
        assert_eq!(resolve_pypi("requests", "2.28.1", None, &net), Some(wheel.clone()));
        // `?kind=wheel` is the default's explicit form.
        assert_eq!(resolve_pypi("requests", "2.28.1", Some("wheel"), &net), Some(wheel));
        // `?kind=sdist` flips to the source distribution.
        assert_eq!(resolve_pypi("requests", "2.28.1", Some("sdist"), &net), Some(sdist));
        // No fixture (registry unreachable / unknown package) → unresolved.
        assert_eq!(resolve_pypi("nope", "9.9.9", None, &Fixtures::default()), None);
    }

    #[test]
    fn resolve_pypi_picks_universal_wheel_and_falls_back_each_way() {
        // A compiled package: many platform wheels plus the universal one. The
        // universal `py3-none-any` wheel must win over the platform wheels.
        let api = "https://pypi.org/pypi/widget/1.0.0/json";
        let body = br#"{"urls":[
            {"packagetype":"bdist_wheel","filename":"widget-1.0.0-cp311-cp311-manylinux_x86_64.whl","url":"https://x/plat.whl"},
            {"packagetype":"bdist_wheel","filename":"widget-1.0.0-py3-none-any.whl","url":"https://x/universal.whl"},
            {"packagetype":"sdist","filename":"widget-1.0.0.tar.gz","url":"https://x/widget.tar.gz"}
        ]}"#;
        let net = Fixtures::default().with(api, body);
        assert_eq!(
            resolve_pypi("widget", "1.0.0", None, &net),
            Some("https://x/universal.whl".to_string())
        );

        // sdist-only version: wheel-first default falls back to the sdist.
        let sonly = "https://pypi.org/pypi/srconly/1.0.0/json";
        let sbody = br#"{"urls":[{"packagetype":"sdist","filename":"srconly-1.0.0.tar.gz","url":"https://x/src.tar.gz"}]}"#;
        let net = Fixtures::default().with(sonly, sbody);
        assert_eq!(
            resolve_pypi("srconly", "1.0.0", None, &net),
            Some("https://x/src.tar.gz".to_string())
        );

        // wheel-only version: explicit `kind=sdist` falls back to the wheel.
        let wonly = "https://pypi.org/pypi/wheelonly/1.0.0/json";
        let wbody = br#"{"urls":[{"packagetype":"bdist_wheel","filename":"wheelonly-1.0.0-py3-none-any.whl","url":"https://x/w.whl"}]}"#;
        let net = Fixtures::default().with(wonly, wbody);
        assert_eq!(
            resolve_pypi("wheelonly", "1.0.0", Some("sdist"), &net),
            Some("https://x/w.whl".to_string())
        );
    }

    #[test]
    fn split_version_kind_parses_purl_qualifiers() {
        assert_eq!(split_version_kind("1.2.3"), ("1.2.3", None));
        assert_eq!(split_version_kind("1.2.3?kind=wheel"), ("1.2.3", Some("wheel")));
        assert_eq!(split_version_kind("1.2.3?kind=sdist"), ("1.2.3", Some("sdist")));
        // Other qualifiers are tolerated; `kind` is found regardless of order.
        assert_eq!(
            split_version_kind("1.2.3?foo=bar&kind=wheel"),
            ("1.2.3", Some("wheel"))
        );
        // A `?` with no `kind` qualifier strips cleanly to the bare version.
        assert_eq!(split_version_kind("1.2.3?foo=bar"), ("1.2.3", None));
    }

    #[test]
    fn resolve_gem_to_rubygems_download() {
        assert_eq!(
            resolve(&RefLocator::Purl("pkg:gem/rails@7.0.4".into())),
            Some("https://rubygems.org/downloads/rails-7.0.4.gem".to_string())
        );
        assert_eq!(resolve(&RefLocator::Purl("pkg:gem/rails".into())), None);
    }

    #[test]
    fn resolve_composer_via_packagist_dist_url() {
        let api = "https://repo.packagist.org/p2/monolog/monolog.json";
        let body = br#"{"packages":{"monolog/monolog":[
            {"version":"3.0.0","dist":{"type":"zip","url":"https://api.github.com/repos/Seldaek/monolog/zipball/abc"}},
            {"version":"2.9.1","dist":{"type":"zip","url":"https://api.github.com/repos/Seldaek/monolog/zipball/old"}}
        ]}}"#;
        let net = Fixtures::default().with(api, body);
        assert_eq!(
            resolve_composer("monolog/monolog", "3.0.0", &net),
            Some("https://api.github.com/repos/Seldaek/monolog/zipball/abc".to_string())
        );
        // Unknown version → no match.
        assert_eq!(resolve_composer("monolog/monolog", "9.9.9", &net), None);
    }

    #[test]
    fn resolve_cargo_crate_to_static_crates_io() {
        assert_eq!(
            resolve(&RefLocator::Purl("pkg:cargo/serde@1.0.0".into())),
            Some("https://static.crates.io/crates/serde/serde-1.0.0.crate".to_string())
        );
        // No version → no fetchable artifact.
        assert_eq!(resolve(&RefLocator::Purl("pkg:cargo/serde".into())), None);
    }

    #[test]
    fn resolve_golang_module_to_goproxy_zip_with_case_encoding() {
        assert_eq!(
            resolve(&RefLocator::Purl(
                "pkg:golang/github.com/BurntSushi/toml@v1.4.0".into()
            )),
            Some("https://proxy.golang.org/github.com/!burnt!sushi/toml/@v/v1.4.0.zip".to_string())
        );
        // A pseudo-version resolves verbatim (no uppercase to encode).
        assert_eq!(
            resolve(&RefLocator::Purl(
                "pkg:golang/codeberg.org/a/b@v0.0.0-20260507212222-cbe932efc123".into()
            )),
            Some(
                "https://proxy.golang.org/codeberg.org/a/b/@v/v0.0.0-20260507212222-cbe932efc123.zip"
                    .to_string()
            )
        );
        // Without a version there is no fetchable artifact.
        assert_eq!(
            resolve(&RefLocator::Purl("pkg:golang/golang.org/x/net".into())),
            None
        );
    }

    fn dep(locator: RefLocator, pin: Option<PinnedHash>) -> Reference {
        Reference {
            locator,
            kind: RefKind::Dependency,
            source: "test".into(),
            evidence: "test".into(),
            offset: 0,
            pinned_hash: pin,
            content_sha256: None,
        }
    }

    #[test]
    fn resolves_npm_scoped_and_unscoped() {
        assert_eq!(
            resolve_purl("pkg:npm/left-pad@1.3.0").as_deref(),
            Some("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz")
        );
        assert_eq!(
            resolve_purl("pkg:npm/%40scope/util@2.1.0").as_deref(),
            Some("https://registry.npmjs.org/@scope/util/-/util-2.1.0.tgz")
        );
        assert_eq!(resolve_purl("pkg:pypi/requests@2.0").as_deref(), None);
    }

    #[test]
    fn fetch_records_provenance_and_cache_preserves_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = BlobCache::with_dir(dir.path().to_path_buf());
        let url = "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz";
        let net = Fixtures::default().with_headers(
            url,
            b"PAYLOAD",
            &[("content-type", "application/gzip")],
        );
        let r = dep(RefLocator::Purl("pkg:npm/left-pad@1.3.0".into()), None);

        let rec = fetch_ref(&r, &net, &cache);
        assert_eq!(rec.outcome, Outcome::Ok);
        assert_eq!(rec.resolved_url, url);
        assert!(!rec.cached);
        assert_eq!(rec.size, Some(7));
        assert_eq!(
            rec.content_sha256.as_deref(),
            Some(&*sha256_hex(b"PAYLOAD"))
        );
        assert!(rec.fetched_at > 0);
        assert_eq!(
            rec.headers,
            vec![("content-type".to_string(), "application/gzip".to_string())]
        );

        // Cache hit reconstructs headers + timestamp from the sidecar.
        let rec2 = fetch_ref(&r, &Fixtures::default(), &cache);
        assert!(rec2.cached);
        assert_eq!(rec2.outcome, Outcome::Ok);
        assert_eq!(rec2.headers, rec.headers);
        assert_eq!(rec2.fetched_at, rec.fetched_at);
    }

    #[test]
    fn pin_mismatch_and_match() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = BlobCache::with_dir(dir.path().to_path_buf());
        let url = "https://static.crates.io/crates/foo/foo-1.0.0.crate";
        let net = Fixtures::default().with(url, b"REAL");

        let wrong = PinnedHash {
            algo: HashAlgo::Sha256,
            value: "0".repeat(64),
        };
        let bad = dep(RefLocator::Purl("pkg:cargo/foo@1.0.0".into()), Some(wrong));
        let rec = fetch_ref(&bad, &net, &cache);
        assert_eq!(rec.outcome, Outcome::PinMismatch);
        assert_eq!(rec.pin_verified, Some(false));

        let good = dep(
            RefLocator::Purl("pkg:cargo/foo@1.0.0".into()),
            Some(PinnedHash {
                algo: HashAlgo::Sha256,
                value: sha256_hex(b"REAL"),
            }),
        );
        let rec = fetch_ref(&good, &net, &cache);
        assert_eq!(rec.outcome, Outcome::Ok);
        assert_eq!(rec.pin_verified, Some(true));
    }

    #[test]
    fn fetch_references_selection_and_budget() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = BlobCache::with_dir(dir.path().to_path_buf());
        let npm_url = "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz";
        let raw_url = "https://evil.test/x.sh";
        let net = Fixtures::default()
            .with(npm_url, b"PKG")
            .with(raw_url, b"SH");

        let refs = vec![
            dep(RefLocator::Purl("pkg:npm/foo@1.0.0".into()), None),
            Reference {
                kind: RefKind::UrlFetch,
                ..dep(RefLocator::Url(raw_url.into()), None)
            },
            Reference {
                kind: RefKind::Repository,
                ..dep(RefLocator::Purl("pkg:github/o/r".into()), None)
            },
        ];

        // Without fetch_urls: only the package (raw URL + repo excluded).
        let recs = fetch_references(
            &refs,
            "trigsha",
            false,
            &net,
            &cache,
            FetchBudget::default(),
        );
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].locator, "pkg:npm/foo@1.0.0");
        // Every edge is stamped with its source endpoint.
        assert_eq!(recs[0].source_sha256, "trigsha");

        // With fetch_urls: package + raw URL; the repository is never fetched.
        let recs = fetch_references(&refs, "trigsha", true, &net, &cache, FetchBudget::default());
        assert_eq!(recs.len(), 2);

        // A budget of one live fetch over a *cold* cache: exactly one ref is
        // fetched and the other is recorded as `BudgetExceeded`, never dropped.
        // (A fresh cache — the prior calls warmed `cache`, and cache hits are
        // served free of the budget, which the next test covers.) Both misses
        // are equal priority, so which one wins the slot isn't guaranteed under
        // the concurrent sweep — assert the multiset, not order.
        let cold_dir = tempfile::tempdir().expect("tempdir");
        let cold_cache = BlobCache::with_dir(cold_dir.path().to_path_buf());
        let recs = fetch_references(
            &refs,
            "trigsha",
            true,
            &net,
            &cold_cache,
            FetchBudget {
                max_count: 1,
                max_bytes: u64::MAX,
            },
        );
        assert_eq!(recs.len(), 2);
        assert_eq!(
            recs.iter().filter(|r| r.outcome == Outcome::Ok).count(),
            1,
            "exactly one live fetch is allowed by the budget"
        );
        assert_eq!(
            recs.iter()
                .filter(|r| r.outcome == Outcome::BudgetExceeded)
                .count(),
            1,
            "the ref past the budget is recorded, not dropped"
        );
        assert!(recs.iter().all(|r| r.source_sha256 == "trigsha"));
    }

    #[test]
    fn cached_references_are_served_free_of_the_count_budget() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = BlobCache::with_dir(dir.path().to_path_buf());
        let npm_url = "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz";
        let raw_url = "https://evil.test/x.sh";
        let net = Fixtures::default()
            .with(npm_url, b"PKG")
            .with(raw_url, b"SH");
        let refs = vec![
            dep(RefLocator::Purl("pkg:npm/foo@1.0.0".into()), None),
            Reference {
                kind: RefKind::UrlFetch,
                ..dep(RefLocator::Url(raw_url.into()), None)
            },
        ];

        // Warm the cache with a generous budget: both are live fetches.
        let warm = fetch_references(&refs, "s", true, &net, &cache, FetchBudget::default());
        assert_eq!(warm.len(), 2);
        assert!(
            warm.iter().all(|r| r.outcome == Outcome::Ok && !r.cached),
            "cold run should fetch both live"
        );

        // Re-run with zero live-fetch budget: cache hits don't count, so both
        // are still served from cache rather than recorded as BudgetExceeded.
        let warm = fetch_references(
            &refs,
            "s",
            true,
            &net,
            &cache,
            FetchBudget {
                max_count: 0,
                max_bytes: u64::MAX,
            },
        );
        assert_eq!(
            warm.iter()
                .filter(|r| r.cached && r.outcome == Outcome::Ok)
                .count(),
            2,
            "a warm re-run is never throttled by the count budget"
        );
    }

    /// A `Fetch` backend that counts how many live network gets are issued, so
    /// tests can assert the count budget exactly against real network activity
    /// rather than inferring it from record outcomes.
    struct CountingFetch {
        inner: Fixtures,
        gets: AtomicUsize,
    }

    impl Fetch for CountingFetch {
        fn get(&self, url: &str) -> Result<Fetched, FetchError> {
            self.gets.fetch_add(1, Ordering::SeqCst);
            self.inner.get(url)
        }
        fn post(
            &self,
            url: &str,
            body: &[u8],
            headers: &[(&str, &str)],
        ) -> Result<Fetched, FetchError> {
            self.gets.fetch_add(1, Ordering::SeqCst);
            self.inner.post(url, body, headers)
        }
    }

    // Build `n` distinct versioned-npm refs (resolved offline, so each fetch is
    // exactly one content `get`) and a matching fixture set.
    fn numbered_npm_refs(n: usize) -> (Fixtures, Vec<Reference>) {
        let mut fx = Fixtures::default();
        let mut refs = Vec::new();
        for i in 0..n {
            let url = format!("https://registry.npmjs.org/p{i}/-/p{i}-1.0.0.tgz");
            fx = fx.with(&url, format!("PKG{i}").as_bytes());
            refs.push(dep(RefLocator::Purl(format!("pkg:npm/p{i}@1.0.0")), None));
        }
        (fx, refs)
    }

    #[test]
    fn live_fetch_count_is_an_exact_ceiling_under_concurrency() {
        // Many cold-cache targets, a small budget, run repeatedly: the
        // reserve-on-miss gate must issue *exactly* `max_count` live gets every
        // time — never more (the race would overshoot the cap) and never fewer
        // (a lost wakeup would strand the budget) — with the rest recorded, in
        // declaration order, as BudgetExceeded.
        let n = 64usize;
        let max_count = 10usize;
        for attempt in 0..50 {
            let dir = tempfile::tempdir().expect("tempdir");
            let cache = BlobCache::with_dir(dir.path().to_path_buf());
            let (fx, refs) = numbered_npm_refs(n);
            let net = CountingFetch {
                inner: fx,
                gets: AtomicUsize::new(0),
            };
            let recs = fetch_references(
                &refs,
                "sha",
                false,
                &net,
                &cache,
                FetchBudget {
                    max_count,
                    max_bytes: u64::MAX,
                },
            );

            assert_eq!(recs.len(), n);
            for (i, rec) in recs.iter().enumerate() {
                assert_eq!(rec.locator, format!("pkg:npm/p{i}@1.0.0"));
            }
            let gets = net.gets.load(Ordering::SeqCst);
            assert_eq!(
                gets, max_count,
                "attempt {attempt}: issued {gets} live fetches for a budget of {max_count}"
            );
            let ok = recs.iter().filter(|r| r.outcome == Outcome::Ok).count();
            let exceeded = recs
                .iter()
                .filter(|r| r.outcome == Outcome::BudgetExceeded)
                .count();
            assert_eq!(ok, max_count, "attempt {attempt}");
            assert_eq!(exceeded, n - max_count, "attempt {attempt}");
        }
    }

    #[test]
    fn cache_hits_never_consume_the_budget_under_concurrency() {
        // Half the targets are pre-cached and interleaved with cold ones. Cache
        // hits must be served free — never blocking a cold ref from the budget,
        // even transiently — so a budget of `max_count` still yields *exactly*
        // `max_count` live gets while every cached ref is served.
        let n = 64usize;
        let max_count = 12usize;
        for attempt in 0..50 {
            let dir = tempfile::tempdir().expect("tempdir");
            let cache = BlobCache::with_dir(dir.path().to_path_buf());
            let (fx, refs) = numbered_npm_refs(n);
            // Warm the even-indexed refs into the cache with an unmetered run.
            let warm: Vec<Reference> = refs.iter().step_by(2).cloned().collect();
            let warmed = fetch_references(&warm, "sha", false, &fx, &cache, FetchBudget::default());
            assert!(warmed.iter().all(|r| r.outcome == Outcome::Ok && !r.cached));

            let net = CountingFetch {
                inner: fx,
                gets: AtomicUsize::new(0),
            };
            let recs = fetch_references(
                &refs,
                "sha",
                false,
                &net,
                &cache,
                FetchBudget {
                    max_count,
                    max_bytes: u64::MAX,
                },
            );

            assert_eq!(recs.len(), n);
            // Every pre-cached (even) ref is served from cache, regardless of budget.
            for even in (0..n).step_by(2) {
                assert!(
                    recs[even].cached && recs[even].outcome == Outcome::Ok,
                    "attempt {attempt}: cached ref {even} should be served free"
                );
            }
            // Live gets are exactly the budget — cache hits neither count nor block.
            let gets = net.gets.load(Ordering::SeqCst);
            assert_eq!(
                gets, max_count,
                "attempt {attempt}: cache hits perturbed the live-fetch budget"
            );
        }
    }

    #[test]
    fn fetch_references_preserves_declaration_order_under_concurrency() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = BlobCache::with_dir(dir.path().to_path_buf());
        // Enough refs to span several concurrent workers, so completion order
        // differs from declaration order — the result must still be in order.
        let n = 20usize;
        let mut net = Fixtures::default();
        let mut refs = Vec::new();
        for i in 0..n {
            let url = format!("https://registry.npmjs.org/p{i}/-/p{i}-1.0.0.tgz");
            net = net.with(&url, format!("PKG{i}").as_bytes());
            refs.push(dep(RefLocator::Purl(format!("pkg:npm/p{i}@1.0.0")), None));
        }
        let recs = fetch_references(&refs, "sha", false, &net, &cache, FetchBudget::default());
        assert_eq!(recs.len(), n);
        for (i, rec) in recs.iter().enumerate() {
            assert_eq!(rec.locator, format!("pkg:npm/p{i}@1.0.0"));
            assert_eq!(rec.outcome, Outcome::Ok);
        }
    }

    #[test]
    fn stale_cache_served_when_source_unreachable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = BlobCache::with_dir(dir.path().to_path_buf());
        let url = "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz";
        let r = dep(RefLocator::Purl("pkg:npm/foo@1.0.0".into()), None); // unpinned → 12h TTL

        // Populate the cache with a working fetch.
        let ok = Fixtures::default().with(url, b"CACHED");
        assert!(!fetch_ref(&r, &ok, &cache).cached);

        // Age the entry well past the 12h unpinned TTL.
        let key = sha256_hex(b"pkg:npm/foo@1.0.0");
        let blob = dir.path().join(format!("{key}.zst"));
        let old = SystemTime::now() - Duration::from_secs(48 * 3600);
        filetime::set_file_mtime(&blob, filetime::FileTime::from_system_time(old)).expect("mtime");

        // The source is now unreachable (no fixture): serve the stale copy.
        let rec = fetch_ref(&r, &Fixtures::default(), &cache);
        assert_eq!(rec.outcome, Outcome::Ok);
        assert!(rec.cached);
        assert!(rec.stale);
        assert_eq!(rec.content_sha256.as_deref(), Some(&*sha256_hex(b"CACHED")));

        // With no cached copy at all, an unreachable source is a failure.
        let empty = BlobCache::with_dir(dir.path().join("empty"));
        let rec = fetch_ref(&r, &Fixtures::default(), &empty);
        assert!(matches!(rec.outcome, Outcome::Failed(_)));
        assert!(!rec.stale);
    }

    #[test]
    fn skipped_and_unresolved() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = BlobCache::with_dir(dir.path().to_path_buf());
        let net = Fixtures::default();

        let repo = Reference {
            kind: RefKind::Repository,
            ..dep(RefLocator::Purl("pkg:github/o/r".into()), None)
        };
        assert_eq!(fetch_ref(&repo, &net, &cache).outcome, Outcome::Skipped);

        let pypi = dep(RefLocator::Purl("pkg:pypi/requests@2.0".into()), None);
        assert_eq!(fetch_ref(&pypi, &net, &cache).outcome, Outcome::Unresolved);
    }

    #[test]
    fn ssrf_blocks_internal_addresses() {
        let blocked = [
            "127.0.0.1",
            "10.0.0.5",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254", // cloud metadata
            "100.64.0.1",      // CGNAT
            "0.0.0.0",
            "240.0.0.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:127.0.0.1", // IPv4-mapped loopback
            "::ffff:10.0.0.1",  // IPv4-mapped private
        ];
        for ip in blocked {
            assert!(
                is_blocked_ip(ip.parse().expect("ip")),
                "{ip} should be blocked"
            );
        }
        let allowed = [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "2606:4700:4700::1111",
        ];
        for ip in allowed {
            assert!(
                !is_blocked_ip(ip.parse().expect("ip")),
                "{ip} should be allowed"
            );
        }
    }

    #[test]
    fn http_refuses_literal_internal_ips_without_network() {
        // The literal-IP / scheme guards run before any send(), so this is
        // offline — a regression test for the resolver-bypass via IP URLs.
        let net = HttpFetch::new().expect("client");
        for url in [
            "https://127.0.0.1/x",
            "https://169.254.169.254/latest/meta-data/",
            "https://[::1]/x",
            "https://10.0.0.1/x",
            "http://example.com/x", // non-https
        ] {
            match net.get(url) {
                Err(FetchError::Refused(_)) => {}
                other => panic!("{url} should be refused, got {other:?}"),
            }
        }
    }
}
