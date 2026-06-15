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
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use filefacts::{ExternalRef, HashAlgo, PinnedHash, RefLocator};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

/// Cache lifetime for a pinned reference — immutable, so a stale hit is
/// still correct (and re-verified).
const TTL_PINNED: Duration = Duration::from_secs(7 * 24 * 3600);
/// Cache lifetime for an unpinned reference — `@latest`/mutable tags can
/// move, so staleness is bounded.
const TTL_UNPINNED: Duration = Duration::from_secs(12 * 3600);
/// Per-fetch byte ceiling — the response is abandoned past this.
pub const MAX_FETCH_BYTES: u64 = 64 * 1024 * 1024;
/// Redirect-chain cap.
const MAX_REDIRECTS: u32 = 10;

/// The one network operation. Backends: [`HttpFetch`] (real, SSRF-guarded)
/// and [`Fixtures`] (offline tests).
pub trait Fetch {
    /// Retrieve the bytes at `url`, following redirects.
    fn get(&self, url: &str) -> Result<Fetched, FetchError>;
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
        Self { dir }
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

/// Resolve, fetch (or serve from cache), verify, and record provenance for
/// one reference. Never panics; every path yields a [`FetchRecord`].
#[must_use]
pub fn fetch_ref(r: &ExternalRef, net: &dyn Fetch, cache: &BlobCache) -> FetchRecord {
    let locator = locator_string(&r.locator);

    if !r.is_fetch_target() {
        return FetchRecord::terminal(locator, Outcome::Skipped);
    }
    let Some(url) = resolved_url(&r.locator, net) else {
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
            max_count: 256,
            max_bytes: 512 * 1024 * 1024,
        }
    }
}

/// Fetch every selectable reference, in order, under `budget`, returning one
/// [`FetchRecord`] edge per attempt (including budget-skipped ones), each
/// stamped with `source_sha256` (the file that declared the references) so it
/// is a self-contained hash→hash edge. `fetch_urls` enables raw-URL targets;
/// without it only registry packages (PURLs) are fetched. Identity references
/// (a repository) are never fetched.
#[must_use]
pub fn fetch_references(
    refs: &[ExternalRef],
    source_sha256: &str,
    fetch_urls: bool,
    net: &dyn Fetch,
    cache: &BlobCache,
    budget: FetchBudget,
) -> Vec<FetchRecord> {
    let mut records = Vec::new();
    let mut count = 0usize;
    let mut bytes = 0u64;
    for r in refs.iter().filter(|r| selected(r, fetch_urls)) {
        let mut rec = if count >= budget.max_count || bytes >= budget.max_bytes {
            FetchRecord::terminal(locator_string(&r.locator), Outcome::BudgetExceeded)
        } else {
            let rec = fetch_ref(r, net, cache);
            count += 1;
            bytes += rec.size.unwrap_or(0);
            rec
        };
        rec.source_sha256 = source_sha256.to_string();
        records.push(rec);
    }
    records
}

/// Whether a reference should be fetched: a fetch target whose locator is a
/// package (always) or a raw URL (only with `fetch_urls`).
fn selected(r: &ExternalRef, fetch_urls: bool) -> bool {
    r.is_fetch_target()
        && match r.locator {
            RefLocator::Purl(_) => true,
            RefLocator::Url(_) => fetch_urls,
        }
}

/// Build a record for bytes in hand (network or cache), verifying the pin
/// and choosing the outcome.
fn record(
    r: &ExternalRef,
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
        RefLocator::Purl(p) => p.clone(),
        RefLocator::Url(u) => u.clone(),
    }
}

/// Resolve a locator to a fetchable URL, or `None` if the ecosystem isn't
/// supported yet (PyPI/Go/alpm need a registry round-trip — follow-ups).
#[must_use]
pub fn resolve(locator: &RefLocator) -> Option<String> {
    match locator {
        RefLocator::Url(u) => Some(u.clone()),
        RefLocator::Purl(p) => resolve_purl(p),
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
        _ => None,
    }
}

/// Resolve a reference to a fetchable URL. Most ecosystems are a pure
/// name+version → URL mapping ([`resolve`]); PyPI and Composer are the
/// exceptions — they have no derivable artifact URL, so each takes a registry
/// round-trip over `net`.
fn resolved_url(locator: &RefLocator, net: &dyn Fetch) -> Option<String> {
    if let RefLocator::Purl(p) = locator
        && let Some(body) = p.strip_prefix("pkg:")
        && let Some((ty, rest)) = body.split_once('/')
        && let Some((path, version)) = rest.rsplit_once('@')
    {
        match ty {
            "pypi" => return resolve_pypi(path, version, net),
            "composer" => return resolve_composer(path, version, net),
            _ => {}
        }
    }
    resolve(locator)
}

/// PyPI publishes no deterministic download URL (the `files.pythonhosted.org`
/// path carries an undrivable hash segment), so ask the JSON API and prefer the
/// source distribution — there is exactly one per version and it carries the
/// actual source, the supply-chain attack surface.
fn resolve_pypi(name: &str, version: &str, net: &dyn Fetch) -> Option<String> {
    let api = format!("https://pypi.org/pypi/{name}/{version}/json");
    let resp = net.get(&api).ok()?;
    let json: serde_json::Value = serde_json::from_slice(&resp.bytes).ok()?;
    let urls = json.get("urls")?.as_array()?;
    let pick = urls
        .iter()
        .find(|u| u.get("packagetype").and_then(serde_json::Value::as_str) == Some("sdist"))
        .or_else(|| urls.first())?;
    pick.get("url")
        .and_then(serde_json::Value::as_str)
        .map(String::from)
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
fn goproxy_escape(s: &str) -> String {
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

impl Fetch for HttpFetch {
    fn get(&self, url: &str) -> Result<Fetched, FetchError> {
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
            let resp = self
                .client
                .get(current.clone())
                .send()
                .map_err(map_send_err)?;
            let status = resp.status();

            if status.is_redirection() {
                let location = resp
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| FetchError::Transport("redirect without location".into()))?;
                let next = current
                    .join(location)
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
            let mut bytes = Vec::new();
            resp.take(MAX_FETCH_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| FetchError::Transport(e.to_string()))?;
            if bytes.len() as u64 > MAX_FETCH_BYTES {
                return Err(FetchError::TooLarge);
            }
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
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use filefacts::RefKind;

    #[test]
    fn resolve_pypi_prefers_sdist_via_json_api() {
        let api = "https://pypi.org/pypi/requests/2.28.1/json";
        let body = br#"{"urls":[
            {"packagetype":"bdist_wheel","url":"https://files.pythonhosted.org/w/requests-2.28.1-py3-none-any.whl"},
            {"packagetype":"sdist","url":"https://files.pythonhosted.org/s/requests-2.28.1.tar.gz"}
        ]}"#;
        let net = Fixtures::default().with(api, body);
        assert_eq!(
            resolve_pypi("requests", "2.28.1", &net),
            Some("https://files.pythonhosted.org/s/requests-2.28.1.tar.gz".to_string())
        );
        // No fixture (registry unreachable / unknown package) → unresolved.
        assert_eq!(resolve_pypi("nope", "9.9.9", &Fixtures::default()), None);
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

    fn dep(locator: RefLocator, pin: Option<PinnedHash>) -> ExternalRef {
        ExternalRef {
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
            ExternalRef {
                kind: RefKind::UrlFetch,
                ..dep(RefLocator::Url(raw_url.into()), None)
            },
            ExternalRef {
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

        // A budget of one: the second selectable ref is recorded, not dropped.
        let recs = fetch_references(
            &refs,
            "trigsha",
            true,
            &net,
            &cache,
            FetchBudget {
                max_count: 1,
                max_bytes: u64::MAX,
            },
        );
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[1].outcome, Outcome::BudgetExceeded);
        assert_eq!(recs[1].source_sha256, "trigsha");
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

        let repo = ExternalRef {
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
