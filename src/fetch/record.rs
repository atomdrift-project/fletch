//! One reference's fetch: resolve, serve from cache or retrieve, verify, and
//! record the provenance edge.

use std::panic::AssertUnwindSafe;
use std::path::Path;
use std::time::{Duration, Instant};

use filefacts::{RefKind, Reference};

use super::cache::{self, CachedMeta, Spool, TTL_PINNED, TTL_UNPINNED};
use super::coverage::Coverage;
use super::resolve::{ResolveError, Target, target};
use super::transport::{Fetch, FetchError, Fetched, Request};
use super::verify::{self, Digests, Pins, verify_pin, verify_purl_checksum};
use super::{BlobCache, locator_str, now, sha256_hex};

/// The terminal result of trying to fetch one reference.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Outcome {
    /// Fetched (or served from cache) and, if pinned, verified.
    Ok,
    /// Bytes whose hash did not match the declared pin — a finding.
    PinMismatch,
    /// A pin was declared, but fletch cannot verify that algorithm over the
    /// downloaded bytes. Never silently treated as an unpinned success.
    UnverifiablePin,
    /// The locator could not be resolved to a URL, for this reason.
    Unresolved(Unresolved),
    /// Not a fetch target (identity / unclassified) — recorded, not fetched.
    Skipped,
    /// The run's fetch budget was exhausted before this reference — recorded
    /// so the cap is never a silent truncation.
    BudgetExceeded,
    /// The fetch, or the registry read its resolution needed, failed for this
    /// reason.
    Failed(FetchError),
}

/// Why a reference resolved to no URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Unresolved {
    /// The package URL does not parse.
    InvalidPurl,
    /// A coordinate that could restructure the registry URL it fills, which no
    /// registry name does (see `safe_coordinate`).
    UnsafeCoordinate,
    /// The reference needs its registry to name the release — a range, a
    /// tag, or no version at all — and the registry, asked, named none.
    NoRelease,
    /// fletch has no artifact source for this reference: its type has none,
    /// or the reference lacks what that source needs.
    Unsupported,
}

/// Where a record's bytes came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Served {
    /// Fetched over the network just now.
    Network,
    /// A cache entry still inside its TTL.
    Cache,
    /// A cache entry past its TTL, served because the source was unreachable,
    /// so the content may be outdated.
    StaleCache,
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
    /// endpoint. Stamped by [`fetch_references`](super::fetch_references).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_sha256: Option<String>,
    /// Byte offset of the declaring reference in the source file — the
    /// citation anchor, so a finding derived from what was fetched can be
    /// pinned to the exact reference site.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_offset: Option<u64>,
    /// The binding class of the declaring reference — how strongly the source
    /// is tied to this content: a `dependency` declared in a manifest or
    /// lockfile, a package named by an install `command`, or a raw
    /// `url_fetch`. This is the trust statement a consumer groups by; a pinned
    /// lockfile entry and a curl in a postinstall hook are different claims.
    /// `undefined` when the record was built without a reference, and omitted
    /// from the wire then.
    #[serde(default = "undefined_kind", skip_serializing_if = "kind_is_undefined")]
    pub kind: RefKind,
    /// The reference's locator (PURL/URL): as emitted by filefacts, or the
    /// canonical, refined PURL its bytes are filed under once resolved.
    pub locator: String,
    /// The URL the locator resolved to. `None` when unresolved/skipped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_url: Option<String>,
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
    /// cache hit). `None` when no fetch occurred (skipped/unresolved).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fetched_at: Option<u64>,
    /// SHA-256 of the fetched bytes — the content-addressed lookup key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_sha256: Option<String>,
    /// Size of the fetched bytes in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Where the bytes came from; `None` when there are none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub served: Option<Served>,
    /// The terminal outcome. A declared pin verified is [`Outcome::Ok`], one
    /// contradicted is [`Outcome::PinMismatch`], and one that could not be
    /// checked is [`Outcome::UnverifiablePin`].
    pub outcome: Outcome,
    /// Declaring dependency scope and installation metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<filefacts::DependencyContext>,
    /// What limited, or decided, how much of the reference was analyzed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub coverage: Vec<Coverage>,
}

impl FetchRecord {
    /// A record that never reached the network (skipped / unresolved).
    #[must_use]
    pub fn terminal(locator: String, outcome: Outcome) -> Self {
        Self {
            source_sha256: None,
            source_offset: None,
            kind: RefKind::Undefined,
            locator,
            resolved_url: None,
            final_url: None,
            redirects: Vec::new(),
            status: None,
            headers: Vec::new(),
            fetched_at: None,
            content_sha256: None,
            size: None,
            served: None,
            outcome,
            context: None,
            coverage: Vec::new(),
        }
    }

    /// Whether the bytes came from the blob cache, fresh or stale, rather than
    /// the network.
    #[must_use]
    pub fn is_cached(&self) -> bool {
        matches!(self.served, Some(Served::Cache | Served::StaleCache))
    }

    /// Whether this record represents a live network fetch — so it counts
    /// against the [`FetchBudget::max_count`](super::FetchBudget::max_count)
    /// ceiling. A cache hit (fresh or stale-served), an unresolved locator, a
    /// non-target, and a budget-skipped edge do not count, so a re-run over a
    /// warm cache is never throttled.
    #[must_use]
    pub fn counts_against_budget(&self) -> bool {
        !self.is_cached()
            && matches!(
                self.outcome,
                Outcome::Ok | Outcome::PinMismatch | Outcome::UnverifiablePin | Outcome::Failed(_)
            )
    }

    /// Copy the declaring reference's binding class, offset and context onto
    /// the record.
    pub(super) fn stamp(&mut self, r: &Reference) {
        self.kind = r.kind;
        self.source_offset = r.offset;
        self.context.clone_from(&r.context);
    }
}

/// `serde(default)` for [`FetchRecord::kind`]: a record serialized without
/// one was not built from a reference.
fn undefined_kind() -> RefKind {
    RefKind::Undefined
}

/// `skip_serializing_if` helper: an unclassified kind carries no information.
#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's `skip_serializing_if` passes a reference"
)]
fn kind_is_undefined(k: &RefKind) -> bool {
    *k == RefKind::Undefined
}

/// Resolve, fetch (or serve from cache), verify, and record provenance for
/// one reference. Every path, a panic inside the fetch included, yields a
/// [`FetchRecord`].
#[must_use]
pub fn fetch_ref(r: &Reference, net: &dyn Fetch, cache: &BlobCache) -> FetchRecord {
    let started = Instant::now();
    let mut rec = fetch_contained(r, net, cache, || true);
    rec.stamp(r);
    crate::metrics::fetch(&rec, started.elapsed());
    rec
}

/// [`fetch_and_record`], with a panic inside it (a parser bug tripped by
/// hostile bytes) contained to this reference as [`FetchError::Internal`].
pub(super) fn fetch_contained(
    r: &Reference,
    net: &dyn Fetch,
    cache: &BlobCache,
    claim_fetch: impl FnOnce() -> bool,
) -> FetchRecord {
    std::panic::catch_unwind(AssertUnwindSafe(|| {
        fetch_and_record(r, net, cache, claim_fetch)
    }))
    .unwrap_or_else(|panic| {
        let message = panic
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
            .unwrap_or("panic");
        let locator = locator_str(&r.locator);
        tracing::error!(
            locator,
            panic = message,
            "fetch panicked; recorded as an internal failure"
        );
        FetchRecord::terminal(
            locator.to_owned(),
            Outcome::Failed(FetchError::Internal(message.to_owned())),
        )
    })
}

/// Every way one reference ends in a record. `claim_fetch` is consulted only
/// on a cache miss, just before the network is touched: `false` records
/// [`Outcome::BudgetExceeded`] instead, so a cache hit never claims a slot of
/// a count budget.
fn fetch_and_record(
    r: &Reference,
    net: &dyn Fetch,
    cache: &BlobCache,
    claim_fetch: impl FnOnce() -> bool,
) -> FetchRecord {
    let written = locator_str(&r.locator);
    if !r.is_fetch_target() {
        tracing::debug!(locator = written, kind = ?r.kind, "not a fetch target; skipped");
        return FetchRecord::terminal(written.to_owned(), Outcome::Skipped);
    }
    let Target { purl, locator, url } = match target(&r.locator, net, cache) {
        Ok(target) => target,
        Err(ResolveError::Unresolved(why)) => {
            tracing::debug!(locator = written, reason = ?why, "unresolved");
            return FetchRecord::terminal(written.to_owned(), Outcome::Unresolved(why));
        }
        Err(ResolveError::Failed(e)) => {
            tracing::debug!(locator = written, error = %e, "registry read for resolution failed");
            let mut rec = FetchRecord::terminal(written.to_owned(), Outcome::Failed(e));
            rec.fetched_at = Some(now());
            return rec;
        }
    };
    // Registry JSON (an npm `dist.tarball`, a PyPI `url`) is as attacker-
    // publishable as a scanned file, so like a URL locator it may name a
    // destination but never pick the container puller's transport: only a
    // container coordinate resolves to `oci://`.
    if url.starts_with("oci://")
        && !purl
            .as_ref()
            .is_some_and(|p| matches!(p.typ(), "oci" | "docker"))
    {
        tracing::debug!(locator = %locator, url = %url, "registry named the container transport; refused");
        return FetchRecord::terminal(locator, Outcome::Unresolved(Unresolved::Unsupported));
    }
    let pins = Pins::new(r.pinned_hash.as_ref(), purl.as_ref());
    let key = sha256_hex(locator.as_bytes());
    let max_age = if r.pinned_hash.is_some() {
        TTL_PINNED
    } else {
        TTL_UNPINNED
    };
    if let Some((examined, meta)) = examine_cached(&pins, &key, Some(max_age), cache) {
        tracing::debug!(locator = %locator, "served from cache");
        return record(&pins, locator, url, &examined, Served::Cache, &meta);
    }
    if !claim_fetch() {
        tracing::debug!(locator = %locator, url = %url, "fetch budget spent; not fetched");
        let mut rec = FetchRecord::terminal(locator, Outcome::BudgetExceeded);
        rec.resolved_url = Some(url);
        return rec;
    }
    // An artifact is spooled to disk as it arrives, judged and cached from
    // there, and never held in memory whole.
    let spool = cache.spool(&key);
    let landed = retrieve(&url, &spool, net).and_then(|f| {
        let meta = CachedMeta {
            fetched_at: now(),
            status: f.status,
            final_url: f.final_url,
            redirects: f.redirects,
            headers: f.headers,
            size: None,
        };
        land(&pins, &key, &spool, &f.bytes, &meta, cache)
            .map(|examined| (examined, meta))
            .map_err(|e| FetchError::Io(format!("spool: {e}")))
    });
    match landed {
        Ok((examined, meta)) => record(&pins, locator, url, &examined, Served::Network, &meta),
        // The source is unreachable. Fall back to any cached copy, however
        // old — a stale answer beats none — and mark it stale. Only a genuine
        // cache miss is a failure.
        Err(e) => match examine_cached(&pins, &key, None, cache) {
            Some((examined, meta)) => {
                tracing::warn!(locator = %locator, error = %e, "fetch failed; serving stale cache");
                record(&pins, locator, url, &examined, Served::StaleCache, &meta)
            }
            None => {
                tracing::debug!(locator = %locator, url = %url, error = %e, "fetch failed; nothing cached");
                // A refused status *did* reach the network, and the code is the
                // whole of what the server said: keep it in the field consumers
                // read as well as in the failure.
                let status = match e {
                    FetchError::Status(status) => Some(status),
                    _ => None,
                };
                let mut rec = FetchRecord::terminal(locator, Outcome::Failed(e));
                rec.resolved_url = Some(url);
                rec.fetched_at = Some(now());
                rec.status = status;
                rec
            }
        },
    }
}

/// Retrieve `url`, spooling the body to `spool`.
///
/// The OCI distribution protocol (token + manifest + blob rounds) doesn't fit
/// one request, so an `oci://` target goes to the puller, which streams the
/// flattened image into the same spool — only when the backend consents
/// ([`Fetch::allows_oci`]), so a refusing or replaying backend keeps its
/// no-network guarantee. The puller enforces its own public-registry allowlist
/// on top of the backend's SSRF guard. The recorded `docker-content-digest`
/// header carries the image's content-addressed identity, stable across
/// producers where the flattened export bytes are not.
///
/// Artifact downloads never carry the GitHub token: their URLs come from a
/// scanned file or a registry response, and the transport grants the token
/// only to repository documents fletch addresses itself.
fn retrieve(url: &str, spool: &Spool, net: &dyn Fetch) -> Result<Fetched, FetchError> {
    if let Some(oci_ref) = url.strip_prefix("oci://") {
        if !net.allows_oci() {
            return Err(FetchError::Refused(
                "oci pull not permitted by this fetch backend".into(),
            ));
        }
        return crate::oci::export(oci_ref, net, spool).map(|digest| Fetched {
            bytes: Vec::new(),
            final_url: url.to_owned(),
            status: 200,
            headers: vec![("docker-content-digest".to_owned(), digest)],
            redirects: Vec::new(),
        });
    }
    net.send(&Request::get(url).spool_to(spool.path()))
}

/// What one read of a body tells: its digests, and how its pins compare
/// (`None` when no pin could be checked).
struct Examined {
    digests: Digests,
    verdict: Option<bool>,
}

/// Read `body` once and judge it against the reference's pins. Two
/// independent digests can ride on one reference: the manifest's pin and a
/// `checksum` qualifier the resolver refined into the locator. Either one
/// disagreeing with the bytes is the verdict; failing that, either one agreeing
/// is; only when neither could be computed is the pin unverified. A Go
/// module-tree pin reads the body as the zip at `zip`.
fn examine(
    pins: &Pins<'_>,
    body: impl std::io::Read,
    zip: Option<&Path>,
) -> std::io::Result<Examined> {
    let digests = verify::digest(body, pins)?;
    let verdict = match (
        verify_pin(pins, &digests, zip),
        verify_purl_checksum(pins, &digests),
    ) {
        (Some(false), _) | (_, Some(false)) => Some(false),
        (Some(true), _) | (_, Some(true)) => Some(true),
        (None, None) => None,
    };
    Ok(Examined { digests, verdict })
}

/// `key`'s cached body, judged as it streams out of the cache — when present
/// and, given a `max_age`, no older than that. A Go module-tree pin reads the
/// archive at random, so for one the body is unpacked to a spool first.
fn examine_cached(
    pins: &Pins<'_>,
    key: &str,
    max_age: Option<Duration>,
    cache: &BlobCache,
) -> Option<(Examined, CachedMeta)> {
    if pins.is_go_tree() {
        let (spool, meta) = cache.unpack(key, max_age)?;
        let examined = std::fs::File::open(spool.path())
            .and_then(|body| examine(pins, body, Some(spool.path())));
        return match examined {
            Ok(examined) => Some((examined, meta)),
            Err(e) => {
                tracing::warn!(key, error = %e, "cached body unreadable; treated as a miss");
                None
            }
        };
    }
    cache.read_with(key, max_age, |body| examine(pins, body, None))
}

/// Bring a fetched body to rest: into the spool — written from `bytes` when
/// the backend handed them back rather than spooling — judged from there, and
/// cached.
fn land(
    pins: &Pins<'_>,
    key: &str,
    spool: &Spool,
    bytes: &[u8],
    meta: &CachedMeta,
    cache: &BlobCache,
) -> std::io::Result<Examined> {
    // Never write through whatever is already at the spool path: an existing
    // file is the transport's own spool only when it handed back no bytes.
    match cache::create_private(spool.path()) {
        Ok(mut file) => std::io::Write::write_all(&mut file, bytes)?,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && bytes.is_empty() => {}
        Err(e) => return Err(e),
    }
    let examined = examine(pins, std::fs::File::open(spool.path())?, Some(spool.path()))?;
    cache.store(
        key,
        std::fs::File::open(spool.path())?,
        examined.digests.size,
        meta,
    );
    Ok(examined)
}

/// Build a record for an examined body, choosing the outcome.
fn record(
    pins: &Pins<'_>,
    locator: String,
    resolved_url: String,
    examined: &Examined,
    served: Served,
    meta: &CachedMeta,
) -> FetchRecord {
    // A declared pin is an integrity requirement: bytes no pin could be
    // checked against (an uncomputable algorithm, a malformed or over-budget
    // module archive) stay explicitly unverified.
    let outcome = match examined.verdict {
        Some(false) => Outcome::PinMismatch,
        None if pins.declared() => Outcome::UnverifiablePin,
        _ => Outcome::Ok,
    };
    if outcome != Outcome::Ok {
        tracing::debug!(locator = %locator, outcome = ?outcome, "pin verdict");
    }
    FetchRecord {
        resolved_url: Some(resolved_url),
        final_url: Some(meta.final_url.clone()),
        redirects: meta.redirects.clone(),
        status: Some(meta.status),
        headers: meta.headers.clone(),
        fetched_at: Some(meta.fetched_at),
        content_sha256: Some(examined.digests.sha256_hex()),
        size: Some(examined.digests.size),
        served: Some(served),
        ..FetchRecord::terminal(locator, outcome)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::fetch::Fixtures;
    use filefacts::{HashAlgo, PinnedHash, RefLocator};
    use sha1::{Digest as _, Sha1};

    /// A declared dependency on `locator`, pinned to `pin`.
    pub(in crate::fetch) fn dep(locator: RefLocator, pin: Option<PinnedHash>) -> Reference {
        let mut r = Reference::new(locator, RefKind::Dependency, "test", "test");
        r.pinned_hash = pin;
        r
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
        let mut r = dep(RefLocator::Purl("pkg:npm/left-pad@1.3.0".into()), None);
        r.offset = Some(42);

        let rec = fetch_ref(&r, &net, &cache);
        assert_eq!(rec.outcome, Outcome::Ok);
        assert_eq!(rec.resolved_url.as_deref(), Some(url));
        assert!(!rec.is_cached());
        assert_eq!(rec.size, Some(7));
        assert_eq!(rec.source_offset, Some(42));
        assert_eq!(rec.kind, RefKind::Dependency);
        assert_eq!(
            rec.content_sha256.as_deref(),
            Some(&*sha256_hex(b"PAYLOAD"))
        );
        assert!(rec.fetched_at.is_some_and(|t| t > 0));
        assert_eq!(
            rec.headers,
            vec![("content-type".to_string(), "application/gzip".to_string())]
        );

        // Cache hit reconstructs headers + timestamp from the sidecar.
        let rec2 = fetch_ref(&r, &Fixtures::default(), &cache);
        assert!(rec2.is_cached());
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
        let outcome = |locator: String, pin: Option<PinnedHash>| {
            fetch_ref(&dep(RefLocator::Purl(locator), pin), &net, &cache).outcome
        };
        let sha256 = |value: String| {
            Some(PinnedHash {
                algo: HashAlgo::Sha256,
                value,
            })
        };
        let locator = || "pkg:cargo/foo@1.0.0".to_owned();
        assert_eq!(
            outcome(locator(), sha256("0".repeat(64))),
            Outcome::PinMismatch
        );
        assert_eq!(outcome(locator(), sha256(sha256_hex(b"REAL"))), Outcome::Ok);
        let declared = |digest: String| format!("pkg:cargo/foo@1.0.0?checksum=sha256:{digest}");
        assert_eq!(outcome(declared(sha256_hex(b"REAL")), None), Outcome::Ok);
        assert_eq!(
            outcome(declared("0".repeat(64)), None),
            Outcome::PinMismatch
        );
    }

    /// filefacts reads an SRI `sha256-<base64>` integrity as a SHA-256 pin in
    /// base64; it verifies the bytes rather than reporting a mismatch.
    #[test]
    fn a_base64_sha256_integrity_pin_verifies() {
        use base64::Engine as _;
        let url = "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz";
        let bytes = b"tarball bytes";
        let net = Fixtures::default().with(url, bytes);
        let pin = PinnedHash {
            algo: HashAlgo::Sha256,
            value: base64::engine::general_purpose::STANDARD
                .encode(<sha2::Sha256 as sha2::Digest>::digest(bytes)),
        };
        let record = fetch_ref(
            &dep(RefLocator::Url(url.into()), Some(pin)),
            &net,
            &BlobCache::disabled(),
        );
        assert_eq!(record.outcome, Outcome::Ok);
    }

    /// A refusal reached the network, so the record keeps the code the server
    /// answered with — consumers read `status`, not the error prose.
    #[test]
    fn a_refused_status_is_recorded_on_the_failure() {
        let url = "https://registry.npmjs.org/gone/-/gone-1.0.0.tgz";
        let r = dep(RefLocator::Purl("pkg:npm/gone@1.0.0".into()), None);
        let net = Fixtures::default().refusing(url, 404);
        let rec = fetch_ref(&r, &net, &BlobCache::disabled());
        assert!(matches!(rec.outcome, Outcome::Failed(_)), "{rec:?}");
        assert_eq!(rec.status, Some(404));
    }

    #[test]
    fn stale_cache_served_when_source_unreachable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = BlobCache::with_dir(dir.path().to_path_buf());
        let url = "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz";
        let r = dep(RefLocator::Purl("pkg:npm/foo@1.0.0".into()), None); // unpinned → 12h TTL

        // Populate the cache with a working fetch.
        let ok = Fixtures::default().with(url, b"CACHED");
        assert!(!fetch_ref(&r, &ok, &cache).is_cached());

        // Age the entry past the 12h unpinned TTL by backdating the recorded
        // fetch time — freshness is measured from `fetched_at`, not the file
        // mtime (which tracks last access for the eviction sweep).
        let key = sha256_hex(b"pkg:npm/foo@1.0.0");
        let meta_path = cache.meta_path(&key);
        let mut meta: CachedMeta =
            serde_json::from_slice(&std::fs::read(&meta_path).expect("read meta")).expect("parse");
        meta.fetched_at = now() - 48 * 3600;
        std::fs::write(&meta_path, serde_json::to_vec(&meta).expect("serialize")).expect("write");

        // The source is now unreachable (no fixture): serve the stale copy.
        let rec = fetch_ref(&r, &Fixtures::default(), &cache);
        assert_eq!(rec.outcome, Outcome::Ok);
        assert!(rec.is_cached());
        assert_eq!(rec.served, Some(Served::StaleCache));
        assert_eq!(rec.content_sha256.as_deref(), Some(&*sha256_hex(b"CACHED")));

        // With no cached copy at all, an unreachable source is a failure.
        let empty = BlobCache::with_dir(dir.path().join("empty"));
        let rec = fetch_ref(&r, &Fixtures::default(), &empty);
        assert!(matches!(rec.outcome, Outcome::Failed(_)));
        assert_eq!(rec.served, None);
    }

    /// A backend that streams the body to the requested spool, as `HttpFetch`
    /// does, and hands back no bytes.
    pub(in crate::fetch) struct Spooling(pub(in crate::fetch) Fixtures);

    impl Fetch for Spooling {
        fn send(&self, request: &Request<'_>) -> Result<Fetched, FetchError> {
            let mut fetched = self.0.send(request)?;
            if let Some(path) = request.spool {
                std::fs::write(path, std::mem::take(&mut fetched.bytes)).expect("spool");
            }
            Ok(fetched)
        }
    }

    /// A body spooled to disk is judged and cached exactly as one handed back
    /// in memory, and no spool outlives its fetch.
    #[test]
    fn a_spooled_body_is_judged_and_cached_like_one_in_memory() {
        let url = "https://registry.npmjs.org/a/-/a-1.0.0.tgz";
        let pin = PinnedHash {
            algo: HashAlgo::Sha256,
            value: sha256_hex(b"ARTIFACT"),
        };
        let r = dep(RefLocator::Purl("pkg:npm/a@1.0.0".into()), Some(pin));
        let backends: [&dyn Fetch; 2] = [
            &Spooling(Fixtures::default().with(url, b"ARTIFACT")),
            &Fixtures::default().with(url, b"ARTIFACT"),
        ];
        for net in backends {
            let dir = tempfile::tempdir().expect("tempdir");
            let cache = BlobCache::with_dir(dir.path().to_path_buf());
            let fetched = fetch_ref(&r, net, &cache);
            assert_eq!(fetched.outcome, Outcome::Ok);
            assert_eq!(fetched.size, Some(8));
            assert_eq!(
                fetched.content_sha256.as_deref(),
                Some(&*sha256_hex(b"ARTIFACT"))
            );
            // The cache holds the body, and a hit judges it the same way.
            assert_eq!(
                cache.load("pkg:npm/a@1.0.0").as_deref(),
                Some(&b"ARTIFACT"[..])
            );
            let hit = fetch_ref(&r, net, &cache);
            assert_eq!(hit.served, Some(Served::Cache));
            assert_eq!(hit.outcome, Outcome::Ok);
            let leftovers: Vec<_> = std::fs::read_dir(dir.path())
                .expect("cache dir")
                .flatten()
                .flat_map(|shard| {
                    std::fs::read_dir(shard.path())
                        .into_iter()
                        .flatten()
                        .flatten()
                })
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .filter(|name| name.contains(".part."))
                .collect();
            assert!(leftovers.is_empty(), "{leftovers:?}");
        }
    }

    #[test]
    fn skipped_and_unresolved() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = BlobCache::with_dir(dir.path().to_path_buf());
        let net = Fixtures::default();

        let mut repo = dep(RefLocator::Purl("pkg:github/o/r".into()), None);
        repo.kind = RefKind::Repository;
        assert_eq!(fetch_ref(&repo, &net, &cache).outcome, Outcome::Skipped);

        // Each says why it has no URL.
        let unresolved =
            |purl: &str| fetch_ref(&dep(RefLocator::Purl(purl.into()), None), &net, &cache).outcome;
        assert_eq!(
            unresolved("pkg:pypi/requests@2.0"),
            Outcome::Unresolved(Unresolved::NoRelease)
        );
        assert_eq!(
            unresolved("pkg:swift/github.com/apple/swift-nio@1.0.0"),
            Outcome::Unresolved(Unresolved::Unsupported)
        );
        assert_eq!(
            unresolved("not a purl"),
            Outcome::Unresolved(Unresolved::InvalidPurl)
        );
        assert_eq!(
            unresolved("pkg:npm/w@..%2F..%2Fx"),
            Outcome::Unresolved(Unresolved::UnsafeCoordinate)
        );
    }

    #[test]
    fn oci_pull_requires_backend_consent() {
        // A backend that hasn't opted in (allows_oci defaults to false) must
        // never have a container pulled behind its back: the reference still
        // resolves, but the fetch is refused rather than routed around the
        // backend to the live registry.
        let r = dep(
            RefLocator::Purl("pkg:oci/nginx?repository_url=docker.io%2Flibrary%2Fnginx".into()),
            None,
        );
        let rec = fetch_ref(&r, &Fixtures::default(), &BlobCache::disabled());
        assert_eq!(
            rec.resolved_url.as_deref(),
            Some("oci://docker.io/library/nginx:latest")
        );
        match &rec.outcome {
            Outcome::Failed(FetchError::Refused(why)) => {
                assert!(why.contains("not permitted"), "{why}");
            }
            other => panic!("want refused-without-network, got {other:?}"),
        }
    }

    /// A registry response naming `oci://` cannot route a package fetch to the
    /// container puller.
    #[test]
    fn a_registry_cannot_select_the_container_puller() {
        let body = br#"{"dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"dist":{"tarball":"oci://docker.io/library/nginx:latest"}}}}"#;
        let net = Fixtures::default().with("https://registry.npmjs.org/pkg", body);
        let rec = fetch_ref(
            &dep(RefLocator::Purl("pkg:npm/pkg".into()), None),
            &net,
            &BlobCache::disabled(),
        );
        assert_eq!(rec.outcome, Outcome::Unresolved(Unresolved::Unsupported));
        assert_eq!(rec.resolved_url, None);
    }

    /// A panic inside one fetch is that reference's failure, recorded, and
    /// [`fetch_ref`] returns rather than unwinding into its caller.
    #[test]
    fn fetch_ref_contains_a_panic() {
        struct Panics;
        impl Fetch for Panics {
            fn send(&self, _: &Request<'_>) -> Result<Fetched, FetchError> {
                panic!("hostile bytes");
            }
        }
        let rec = fetch_ref(
            &dep(RefLocator::Url("https://bad.test/b.sh".into()), None),
            &Panics,
            &BlobCache::disabled(),
        );
        assert_eq!(
            rec.outcome,
            Outcome::Failed(FetchError::Internal("hostile bytes".into()))
        );
        assert_eq!(rec.kind, RefKind::Dependency);
    }

    /// A yarn v1 lockfile pins every entry with a `sha1-` integrity,
    /// and a yarn `resolved` fragment spells the same digest in hex.
    #[test]
    fn sha1_pins_verify_in_either_spelling_and_catch_a_mismatch() {
        use base64::Engine as _;
        let url = "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz";
        let bytes = b"tarball bytes";
        let net = Fixtures::default().with(url, bytes);
        let outcome = |value: String| {
            fetch_ref(
                &dep(
                    RefLocator::Url(url.into()),
                    Some(PinnedHash {
                        algo: HashAlgo::Sha1,
                        value,
                    }),
                ),
                &net,
                &BlobCache::disabled(),
            )
            .outcome
        };
        assert_eq!(
            outcome(base64::engine::general_purpose::STANDARD.encode(Sha1::digest(bytes))),
            Outcome::Ok
        );
        assert_eq!(
            outcome(hex::encode(Sha1::digest(bytes)).to_ascii_uppercase()),
            Outcome::Ok
        );
        assert_eq!(
            outcome(hex::encode(Sha1::digest(b"other bytes"))),
            Outcome::PinMismatch
        );
    }

    /// PURL checksums: a digest fletch cannot compute neither verifies the
    /// bytes nor rescues one that disagrees, and alone it leaves the pin
    /// unverifiable.
    #[test]
    fn purl_checksums_decide_the_outcome() {
        let url = "https://static.crates.io/crates/foo/foo-1.0.0.crate";
        let bytes = b"REAL";
        let net = Fixtures::default().with(url, bytes);
        let outcome = |checksum: String| {
            fetch_ref(
                &dep(
                    RefLocator::Purl(format!("pkg:cargo/foo@1.0.0?checksum={checksum}")),
                    None,
                ),
                &net,
                &BlobCache::disabled(),
            )
            .outcome
        };
        assert_eq!(
            outcome("md5:0123456789abcdef".into()),
            Outcome::UnverifiablePin
        );
        assert_eq!(
            outcome(format!("blake2b-256:abcd,sha256:{}", sha256_hex(bytes))),
            Outcome::Ok
        );
        assert_eq!(
            outcome(format!(
                "blake2b-256:abcd,sha256:{}",
                sha256_hex(b"SUBSTITUTED")
            )),
            Outcome::PinMismatch
        );
        assert_eq!(
            outcome(format!("sha1:{}", hex::encode(Sha1::digest(bytes)))),
            Outcome::Ok
        );
    }

    #[test]
    fn go_tree_pin_controls_fetch_outcome() {
        let url = "https://proxy.golang.org/example.test/m/@v/v1.0.0.zip";
        let reference = dep(
            RefLocator::Url(url.into()),
            Some(PinnedHash {
                algo: HashAlgo::GoModH1,
                value: "7gPDTdAetOil7VBHFXxFU4lStBctQ7LKO/0XF15Bdy8=".into(),
            }),
        );
        for (body, outcome) in [
            ("package m\n", Outcome::Ok),
            ("package changed\n", Outcome::PinMismatch),
        ] {
            let bytes = crate::fetch::go_hash::tests::archive(
                false,
                zip::CompressionMethod::Deflated,
                "example.test/m@v1.0.0/m.go",
                body,
            );
            let record = fetch_ref(
                &reference,
                &Fixtures::default().with(url, &bytes),
                &BlobCache::disabled(),
            );
            assert_eq!(record.outcome, outcome);
        }
    }

    /// Malformed module archives cannot satisfy a declared tree hash.
    #[test]
    fn malformed_go_zip_is_explicitly_unverified() {
        let url = "https://proxy.golang.org/example.test/m/@v/v1.0.0.zip";
        let net = Fixtures::default().with(url, b"module zip");
        let reference = dep(
            RefLocator::Url(url.into()),
            Some(PinnedHash {
                algo: HashAlgo::GoModH1,
                value: "NIvaJDMOsjHA8n1jAhLSgzrAzy1Hgr+hNrb57e+94F0=".into(),
            }),
        );
        let record = fetch_ref(&reference, &net, &BlobCache::disabled());
        assert_eq!(record.outcome, Outcome::UnverifiablePin);
    }

    /// A record serialized without a binding class reads back as undefined,
    /// and an undefined one is not written out.
    #[test]
    fn a_record_without_a_kind_round_trips() {
        let rec: FetchRecord = serde_json::from_value(serde_json::json!({
            "locator": "pkg:npm/left-pad@1.3.0",
            "outcome": "ok",
        }))
        .unwrap();
        assert_eq!(rec.kind, RefKind::Undefined);
        let json = serde_json::to_value(&rec).unwrap();
        assert!(json.get("kind").is_none());
    }
}
