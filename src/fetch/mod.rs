//! Resolve external references to URLs, retrieve them safely, cache them, and
//! record rich provenance.
//!
//! [`HttpFetch`] is the real backend; its SSRF guard lives in a custom DNS
//! resolver (`SafeResolver`) that refuses any host resolving to a private /
//! loopback / link-local / metadata address, re-checked on every redirect hop.
//! [`Fixtures`] is the offline backend for tests. No recognition logic lives
//! here — references come in, bytes and [`FetchRecord`]s go out.

use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use filefacts::{RefKind, RefLocator, Reference};
use sha2::{Digest, Sha256};

use crate::purl::Purl;

mod cache;
mod coordinate;
mod go_hash;
mod select;
mod ssrf;
mod transport;
mod verify;

pub use cache::{BlobCache, RawSink, RecordedSource, refs_dir};
pub(crate) use cache::{
    CachedMeta, META_TTL_IMMUTABLE, Spool, cached_metadata, cached_metadata_status, cached_post,
    store_metadata,
};
pub(crate) use coordinate::{
    is_web_scheme, percent_decode, repository_base, safe_coordinate, safe_filename_part,
};
pub use select::{ArtifactCandidate, ArtifactMatrix, ArtifactTarget, SelectionPolicy};
pub(crate) use select::{
    artifact_candidate, file_name_from_url, file_name_matches, purl_checksums,
};
pub use transport::{
    DEFAULT_MAX_FETCH_BYTES, Fetch, FetchError, Fetched, Fixtures, HttpFetch, Method, Request,
};

use crate::ecosystem::arch::resolve_aur;
use crate::ecosystem::cargo::cargo_artifacts;
use crate::ecosystem::comfyui::resolve_comfyui;
use crate::ecosystem::composer::resolve_composer;
use crate::ecosystem::container::resolve_oci_ref;
use crate::ecosystem::dify::resolve_dify;
use crate::ecosystem::firefox::resolve_firefox;
use crate::ecosystem::gem::gem_artifacts;
use crate::ecosystem::golang::{golang_artifacts, goproxy_escape};
use crate::ecosystem::npm::{
    npm_artifacts, npm_registry_name, npm_version_is_concrete, resolve_npm_dist_tag,
};
use crate::ecosystem::pypi::pypi_artifacts;
use crate::ecosystem::terraform::terraform_artifact;
use crate::ecosystem::vscode::{resolve_openvsx, resolve_vscode};
use cache::{TTL_PINNED, TTL_UNPINNED};
use coordinate::safe_purl_coordinates;
use select::{
    apply_common_candidate_qualifiers, attach_candidate_identities, maybe_selected_artifact_url,
};
use verify::{Digests, verify_pin, verify_purl_checksum};

/// The terminal result of trying to fetch one reference.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Fetched (or served from cache) and, if pinned, verified.
    Ok,
    /// Bytes whose hash did not match the declared pin — a finding.
    PinMismatch,
    /// A pin was declared, but Fletch cannot verify that algorithm over the
    /// downloaded bytes. Never silently treated as an unpinned success.
    UnverifiablePin,
    /// The locator could not be resolved to a URL, for this reason.
    Unresolved(Unresolved),
    /// Not a fetch target (identity / unclassified) — recorded, not fetched.
    Skipped,
    /// The per-run fetch budget was exhausted before this reference — recorded
    /// so the cap is never a silent truncation.
    BudgetExceeded,
    /// The fetch failed, for this reason.
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
    /// The reference needs a registry to name its release — a range, a tag,
    /// or no version at all — and none was named: no release matches, or the
    /// registry could not be asked.
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
    /// endpoint. Stamped by [`fetch_references`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_sha256: Option<String>,
    /// Byte offset of the declaring reference in the source file — the
    /// citation anchor, so a finding derived from what was fetched can be
    /// pinned to the exact reference site. Stamped by [`fetch_references`]
    /// alongside `source_sha256`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_offset: Option<u64>,
    /// The binding class of the declaring reference — how strongly the source
    /// is tied to this content: a `dependency` declared in a manifest or
    /// lockfile, a package named by an install `command`, or a raw
    /// `url_fetch`. This is the trust statement a consumer groups by; a pinned
    /// lockfile entry and a curl in a postinstall hook are different claims.
    /// Stamped by [`fetch_ref`] / [`fetch_references`]; `undefined` on records
    /// predating the field.
    #[serde(default = "undefined_kind", skip_serializing_if = "kind_is_undefined")]
    pub kind: RefKind,
    /// The reference's locator (PURL/URL) as emitted by filefacts.
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
    /// SHA-256 of the fetched bytes — the content (hopper) lookup key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_sha256: Option<String>,
    /// Size of the fetched bytes in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Where the bytes came from; `None` when there are none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub served: Option<Served>,
    /// Pin verification: `Some(true/false)` when the reference declared a
    /// verifiable content or Go module-tree pin; `None` when unpinned,
    /// unsupported, malformed, or over the verification budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin_verified: Option<bool>,
    /// The terminal outcome.
    pub outcome: Outcome,
}

impl FetchRecord {
    /// A record that never reached the network (skipped / unresolved).
    fn terminal(locator: String, outcome: Outcome) -> Self {
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
            pin_verified: None,
            outcome,
        }
    }

    /// Whether the bytes came from the blob cache, fresh or stale, rather than
    /// the network.
    #[must_use]
    pub fn is_cached(&self) -> bool {
        matches!(self.served, Some(Served::Cache | Served::StaleCache))
    }

    /// Whether this record represents a live network fetch — so it counts
    /// against the [`FetchBudget::max_count`] ceiling. A cache hit (fresh or
    /// stale-served), an unresolved locator, a non-target, and a
    /// budget-skipped edge do not count, so a re-run over a warm cache is never
    /// throttled.
    #[must_use]
    pub fn counts_against_budget(&self) -> bool {
        !self.is_cached()
            && matches!(
                self.outcome,
                Outcome::Ok | Outcome::PinMismatch | Outcome::UnverifiablePin | Outcome::Failed(_)
            )
    }
}

/// `skip_serializing_if` helper for a default-`false` flag.
fn is_false(b: &bool) -> bool {
    !*b
}

/// `serde(default)` for [`FetchRecord::kind`] on records predating the field.
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
/// one reference. Never panics; every path yields a [`FetchRecord`].
#[must_use]
pub fn fetch_ref(r: &Reference, net: &dyn Fetch, cache: &BlobCache) -> FetchRecord {
    let mut rec = fetch_ref_inner(r, net, cache, || true);
    rec.kind = r.kind;
    rec
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
    let started = Instant::now();
    let rec = fetch_and_record(r, net, cache, claim_fetch);
    crate::metrics::fetch(&rec, started.elapsed());
    rec
}

/// [`fetch_ref_inner`]'s work: every way one reference ends in a record.
fn fetch_and_record(
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
    let (locator, url) = match resolved_target(&r.locator, net, cache) {
        Ok(target) => target,
        Err(why) => return FetchRecord::terminal(locator, Outcome::Unresolved(why)),
    };

    let key = sha256_hex(locator.as_bytes());
    let max_age = if r.pinned_hash.is_some() {
        TTL_PINNED
    } else {
        TTL_UNPINNED
    };

    if let Some((examined, meta)) = examine_cached(r, &locator, &key, Some(max_age), cache) {
        return record(r, locator, url, &examined, Served::Cache, &meta);
    }

    if !claim_fetch() {
        // Count budget spent: record the edge without fetching so the cap is
        // never a silent truncation, and a later run can still pick it up.
        let mut rec = FetchRecord::terminal(locator, Outcome::BudgetExceeded);
        rec.resolved_url = Some(url);
        return rec;
    }

    // The OCI distribution protocol (token + manifest + blob rounds) doesn't
    // fit the single-URL Fetch backend, so `oci://` targets go to the puller,
    // which enforces its own public-registry allowlist in place of the
    // backend's SSRF guard — but only when the backend consents
    // (`allows_oci`), so a refusing/replaying backend (the `purl` probe, test
    // fixtures) keeps its no-network guarantee. The recorded
    // docker-content-digest header carries the image's content-addressed
    // identity — stable across producers, where the flattened export bytes
    // are not.
    // An artifact is spooled to disk as it arrives, judged and cached from
    // there, and never held in memory whole.
    let spool = cache.spool(&key);
    let fetched = if let Some(oci_ref) = url.strip_prefix("oci://") {
        if net.allows_oci() {
            crate::oci::export(oci_ref).map(|(bytes, digest)| Fetched {
                bytes,
                final_url: url.clone(),
                status: 200,
                headers: vec![("docker-content-digest".to_string(), digest)],
                redirects: Vec::new(),
            })
        } else {
            Err(FetchError::Refused(
                "oci pull not permitted by this fetch backend".into(),
            ))
        }
    } else {
        net.send(&Request::get(&url).spool_to(spool.path()))
    };
    let landed = fetched.and_then(|f| {
        let meta = CachedMeta {
            fetched_at: now(),
            status: f.status,
            final_url: f.final_url,
            redirects: f.redirects,
            headers: f.headers,
            size: None,
        };
        land(r, &locator, &key, &spool, &f.bytes, &meta, cache)
            .map(|examined| (examined, meta))
            .map_err(|e| FetchError::Transport(format!("spool: {e}")))
    });
    match landed {
        Ok((examined, meta)) => record(r, locator, url, &examined, Served::Network, &meta),
        // The source is unreachable. Fall back to any cached copy, however
        // old — a stale answer beats none — and mark it stale. Only a genuine
        // cache miss is a failure.
        Err(e) => match examine_cached(r, &locator, &key, None, cache) {
            Some((examined, meta)) => {
                tracing::warn!(locator = %locator, error = %e, "fetch failed; serving stale cache");
                record(r, locator, url, &examined, Served::StaleCache, &meta)
            }
            None => {
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

/// Per-run ceiling on fetching, so one analysis can't turn into a fetch
/// storm. A manifest with thousands of deps fetches up to the cap; the rest
/// are recorded as [`Outcome::BudgetExceeded`], never silently dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
            // (that is `HttpFetch::with_max_bytes`).
            max_bytes: 5 * 1024 * 1024 * 1024,
        }
    }
}

/// Whether a batch also fetches the URLs a script merely reaches for — a `curl`
/// or `wget` target ([`RefKind::UrlFetch`]). Packages, and dependencies or
/// commanded packages a manifest gives as a raw URL, are fetched either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UrlFetches {
    /// Leave them unfetched.
    Skip,
    /// Fetch them too.
    Include,
}

/// Fetch every selectable reference, in declaration order, under `budget`,
/// returning one [`FetchRecord`] edge per attempt (including budget-skipped
/// ones), each stamped with `source_sha256` (the file that declared the
/// references) so it is a self-contained hash→hash edge. `url_fetches` says
/// whether a script's own URL fetches are among them. Identity references (a
/// repository) are never fetched.
///
/// Fetches run concurrently across a bounded pool of scoped threads; the
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
    url_fetches: UrlFetches,
    net: &(dyn Fetch + Sync),
    cache: &BlobCache,
    budget: FetchBudget,
) -> Vec<FetchRecord> {
    fetch_references_with(
        refs,
        source_sha256,
        url_fetches,
        net,
        cache,
        budget,
        &|_, _| {},
    )
}

/// [`fetch_references`] with a per-completion callback. `on_fetched` fires once
/// for each target the moment its fetch resolves — from whichever pool worker
/// handled it, so it is invoked concurrently and must be `Sync`. It receives the
/// original reference (the caller's own key, before any locator refinement) and
/// the freshly built record, letting a caller drive live progress as each
/// download lands rather than only after the whole batch returns. Budget-clipped
/// targets never fetch, so the callback never fires for them; they surface only
/// in the returned `BudgetExceeded` edges.
pub fn fetch_references_with(
    refs: &[Reference],
    source_sha256: &str,
    url_fetches: UrlFetches,
    net: &(dyn Fetch + Sync),
    cache: &BlobCache,
    budget: FetchBudget,
    on_fetched: &(dyn Fn(&Reference, &FetchRecord) + Sync),
) -> Vec<FetchRecord> {
    // Selectable references, in declaration order. Every target is visited; the
    // caps are enforced live below — the byte cap stops the sweep, the count cap
    // gates only *network* fetches (cache hits are always served, never counted).
    let targets: Vec<&Reference> = refs.iter().filter(|r| selected(r, url_fetches)).collect();
    let fetch_n = if budget.max_bytes == 0 {
        0
    } else {
        targets.len()
    };

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
        // Fetching is network-bound, so the pool scales with the host but is
        // independent of the CPU pool: clamped so a long reference list can't
        // open an unbounded number of sockets while a small host still
        // parallelizes. Scoped OS threads rather than a shared rayon/CPU pool,
        // so a fetching worker never starves concurrent analysis.
        let workers = std::thread::available_parallelism()
            .map(std::num::NonZeroUsize::get)
            .unwrap_or(4)
            .clamp(2, 16)
            .min(fetch_n);
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
                            //
                            // A panic in one fetch (a parser bug tripped by
                            // hostile bytes) is that reference's failure, not
                            // the batch's: caught here, the worker's other
                            // results survive and the rest of the sweep runs.
                            let rec = std::panic::catch_unwind(AssertUnwindSafe(|| {
                                fetch_ref_inner(targets[i], net, cache, || {
                                    net_used
                                        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                                            (n < budget.max_count).then_some(n + 1)
                                        })
                                        .is_ok()
                                })
                            }))
                            .unwrap_or_else(|panic| {
                                // The text the panic was raised with.
                                let message = panic
                                    .downcast_ref::<&str>()
                                    .copied()
                                    .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
                                    .unwrap_or("panic");
                                FetchRecord::terminal(
                                    locator_string(&targets[i].locator),
                                    Outcome::Failed(FetchError::Internal(message.to_string())),
                                )
                            });
                            bytes_used.fetch_add(rec.size.unwrap_or(0), Ordering::Relaxed);
                            // Signal completion before the record is buffered, so
                            // a live progress view advances as each fetch lands
                            // instead of all at once when the batch returns. Keyed
                            // on the original reference (pre-refinement locator).
                            on_fetched(targets[i], &rec);
                            local.push((i, rec));
                        }
                        local
                    })
                })
                .collect();
            // Anything still unwinding came from outside a fetch (the caller's
            // `on_fetched`), so it is the caller's to see, not ours to bury.
            handles
                .into_iter()
                .map(|h| {
                    h.join()
                        .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
                })
                .collect()
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
        rec.source_sha256 = Some(source_sha256.to_string()).filter(|s| !s.is_empty());
        rec.source_offset = Some(r.offset);
        rec.kind = r.kind;
        records.push(rec);
    }
    records
}

/// Whether a reference should be fetched: a fetch target whose locator resolves
/// to fetchable bytes. A package coordinate (PURL) is always fetched. A raw URL
/// is fetched when it *is* a declared dependency or a commanded package — a
/// PKGBUILD `source=()`, a lockfile URL entry — since those are genuine
/// dependencies that merely lack a package coordinate, so they follow the
/// deps/packages policy the caller already applied by [`RefKind`]. Only an
/// opportunistic [`RefKind::UrlFetch`] (a script's `curl`/`wget`) is gated
/// behind `url_fetches`. An intra-artifact path is resolved against sibling
/// files, not fetched.
fn selected(r: &Reference, url_fetches: UrlFetches) -> bool {
    r.is_fetch_target()
        && match r.locator {
            RefLocator::Purl(_) => true,
            RefLocator::Url(_) => {
                matches!(r.kind, RefKind::Dependency | RefKind::Command)
                    || url_fetches == UrlFetches::Include
            }
            RefLocator::Path(_) => false,
        }
}

/// What one read of a body tells: its digests, and how its pins compare.
struct Examined {
    digests: Digests,
    pin_verified: Option<bool>,
}

/// Read `body` once and judge it against the reference's pins. Two
/// independent digests can ride on one reference: the manifest's pin and a
/// `checksum` qualifier the resolver refined into the locator. Either one
/// disagreeing with the bytes is the verdict; failing that, either one agreeing
/// is; only when neither could be computed is the pin unverified. A Go
/// module-tree pin reads the body as the zip at `zip`.
fn examine(
    r: &Reference,
    locator: &str,
    body: impl std::io::Read,
    zip: Option<&std::path::Path>,
) -> std::io::Result<Examined> {
    let digests = verify::digest(body, r.pinned_hash.as_ref(), locator)?;
    let pin_verified = match (
        verify_pin(r.pinned_hash.as_ref(), &digests, zip),
        verify_purl_checksum(locator, &digests),
    ) {
        (Some(false), _) | (_, Some(false)) => Some(false),
        (Some(true), _) | (_, Some(true)) => Some(true),
        (None, None) => None,
    };
    Ok(Examined {
        digests,
        pin_verified,
    })
}

/// `key`'s cached body, judged as it streams out of the cache — when present
/// and, given a `max_age`, no older than that. A Go module-tree pin reads the
/// archive at random, so for one the body is unpacked to a spool first.
fn examine_cached(
    r: &Reference,
    locator: &str,
    key: &str,
    max_age: Option<std::time::Duration>,
    cache: &BlobCache,
) -> Option<(Examined, CachedMeta)> {
    if r.pinned_hash
        .as_ref()
        .is_some_and(|pin| pin.algo == filefacts::HashAlgo::GoModH1)
    {
        let (spool, meta) = cache.unpack(key, max_age)?;
        let body = std::fs::File::open(spool.path()).ok()?;
        let examined = examine(r, locator, body, Some(spool.path())).ok()?;
        return Some((examined, meta));
    }
    cache.read_with(key, max_age, |body| examine(r, locator, body, None))
}

/// Bring a fetched body to rest: into the spool — written from `bytes` when
/// the backend handed them back rather than spooling — judged from there, and
/// cached.
fn land(
    r: &Reference,
    locator: &str,
    key: &str,
    spool: &Spool,
    bytes: &[u8],
    meta: &CachedMeta,
    cache: &BlobCache,
) -> std::io::Result<Examined> {
    if !spool.path().exists() {
        std::fs::write(spool.path(), bytes)?;
    }
    let examined = examine(
        r,
        locator,
        std::fs::File::open(spool.path())?,
        Some(spool.path()),
    )?;
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
    r: &Reference,
    locator: String,
    resolved_url: String,
    examined: &Examined,
    served: Served,
    meta: &CachedMeta,
) -> FetchRecord {
    let pin_verified = examined.pin_verified;
    // A declared tree hash is an integrity requirement too. Malformed or
    // over-budget archives must remain explicitly unverified.
    let declares_content_pin = r.pinned_hash.is_some()
        || crate::purl::Purl::parse(&locator)
            .is_ok_and(|purl| purl.qualifiers().contains_key("checksum"));
    let outcome = if pin_verified == Some(false) {
        Outcome::PinMismatch
    } else if pin_verified.is_none() && declares_content_pin {
        Outcome::UnverifiablePin
    } else {
        Outcome::Ok
    };
    FetchRecord {
        source_sha256: None,
        source_offset: None,
        kind: r.kind,
        locator,
        resolved_url: Some(resolved_url),
        final_url: Some(meta.final_url.clone()),
        redirects: meta.redirects.clone(),
        status: Some(meta.status),
        headers: meta.headers.clone(),
        fetched_at: Some(meta.fetched_at),
        content_sha256: Some(examined.digests.sha256.clone()),
        size: Some(examined.digests.size),
        served: Some(served),
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
/// supported yet. Ecosystems that need a registry round-trip (PyPI, Composer,
/// Firefox, Terraform, the AUR, ComfyUI, Dify, an unversioned npm PURL) resolve
/// in `resolved_target` instead; official-repo alpm (a mirror lookup) is a
/// follow-up.
#[must_use]
pub fn resolve(locator: &RefLocator) -> Option<String> {
    match locator {
        // A URL locator is verbatim text out of a scanned file, so it may name
        // a *destination* but never pick a *transport*. [`fetch_ref`] routes an
        // `oci://` target to the container puller, which runs on its own HTTP
        // stack outside this module's SSRF guard — so without this gate a file
        // that merely mentions `oci://…` selects that path for itself. An
        // `oci://` URL is legitimate only as something [`resolve_purl`] derives
        // from a `pkg:oci` coordinate. Plain `http` still resolves and is
        // refused at connect, which records the more informative outcome.
        RefLocator::Url(u) => is_web_scheme(u).then(|| u.clone()),
        RefLocator::Purl(p) => Purl::parse(p).ok().and_then(|purl| resolve_purl(&purl)),
        // An intra-artifact file reference is resolved against the bundle's
        // other files by a consumer, never fetched.
        RefLocator::Path(_) => None,
    }
}

/// Resolve every concrete artifact variant published for `locator`.
///
/// Unlike [`resolve`], this API may consult registry metadata. It currently
/// expands the ecosystems where artifact variants or compatibility metadata
/// matter most: npm, PyPI, RubyGems, Go modules, and Cargo crates, plus
/// Terraform providers, whose one candidate carries the registry's sha256
/// (see `terraform_artifact`). The returned
/// matrix always retains all discovered variants; the legacy single-URL choice
/// is identified by [`ArtifactCandidate::preferred`].
///
/// PyPI's `file_name` and RubyGems' `platform` are the registered
/// type-specific artifact selectors for these ecosystems; npm, Go, and Cargo
/// have none. A Go `subpath` addresses content inside its one module ZIP, so it
/// is retained as context but never treated as another artifact. Common
/// `download_url`, `file_name`, `repository_url`, `checksum`, and
/// `vers` semantics are also honored (`vers` intentionally yields no concrete
/// candidate until its caller selects a release).
/// Compatibility information that is not a PURL selector is exposed as an
/// attribute: Python wheel/build/ABI/platform tags and npm os/cpu/libc/Node
/// constraints.
#[must_use]
pub fn resolve_artifacts(
    locator: &RefLocator,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Option<ArtifactMatrix> {
    if let Requirement::Resolved(exact) = resolve_requirement(locator, net, cache)? {
        let mut matrix = resolve_artifacts(&exact, net, cache)?;
        matrix.locator = locator_string(locator);
        return Some(matrix);
    }
    let mut locator_text = locator_string(locator);
    let candidates = match locator {
        RefLocator::Url(url) if is_web_scheme(url) => {
            vec![artifact_candidate(url.clone(), "download")]
        }
        RefLocator::Url(_) | RefLocator::Path(_) => return None,
        RefLocator::Purl(raw) => {
            let purl = Purl::parse(raw).ok()?;
            locator_text = purl.canonical();
            let mut candidates = if let Some(url) = purl.qualifier("download_url") {
                if !is_web_scheme(url) {
                    return None;
                }
                let mut candidate = artifact_candidate(url.to_string(), "download");
                candidate.preferred = file_name_matches(&purl, &candidate.file_name);
                vec![candidate]
            } else if purl.qualifier("vers").is_some() {
                // A range describes multiple releases, not one concrete
                // artifact coordinate. Callers must choose a version first.
                Vec::new()
            } else {
                let (path, version) = (purl.encoded_path(), purl.encoded_version());
                let (path, version) = (path.as_str(), version.as_deref());
                if !safe_coordinate(path) || version.is_some_and(|value| !safe_coordinate(value)) {
                    return None;
                }
                match purl.typ() {
                    "npm" => npm_artifacts(path, version, &purl, net, cache),
                    "pypi" => pypi_artifacts(path, version, &purl, net, cache),
                    "gem" => gem_artifacts(path, version, &purl, net, cache),
                    "golang" => golang_artifacts(&purl, path, version, net, cache),
                    "cargo" => cargo_artifacts(&purl, path, version, net, cache),
                    "terraform" => terraform_artifact(path, version, &purl, net, cache)
                        .into_iter()
                        .collect(),
                    _ => return None,
                }
            };
            apply_common_candidate_qualifiers(&purl, &mut candidates);
            attach_candidate_identities(&locator_text, &mut candidates);
            candidates
        }
    };
    Some(ArtifactMatrix {
        locator: locator_text,
        candidates,
    })
}

/// What a reference's declared version requirement resolved to.
#[derive(Debug, PartialEq)]
enum Requirement {
    /// No requirement is declared; the reference resolves as written.
    Absent,
    /// The exact release that satisfies the declared requirement.
    Resolved(RefLocator),
}

/// Resolve declared ranges without silently substituting latest. `None` means
/// a requirement that can't be resolved (or an unsupported ecosystem). The
/// original reference retains requirements, role, and environment markers.
fn resolve_requirement(
    locator: &RefLocator,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Option<Requirement> {
    let RefLocator::Purl(raw) = locator else {
        return Some(Requirement::Absent);
    };
    let purl = Purl::parse(raw).ok()?;
    let Some(requirement) = purl.qualifier("version_requirement") else {
        return Some(Requirement::Absent);
    };
    let name = purl.encoded_path();
    let name = name.as_str();
    if purl.version().is_some() || !safe_coordinate(name) || purl.qualifier("registry").is_some() {
        return None;
    }
    let (resolved, checksum) = match purl.typ() {
        "npm" => {
            // A manifest range is a release constraint, not a dist-tag. Resolve
            // the highest registry version that actually satisfies it so a
            // newer major cannot be mistaken for a dependency the package
            // manager would install.
            let repository = repository_base(&purl, "https://registry.npmjs.org")?;
            let url = format!("{repository}/{}", npm_registry_name(name));
            let bytes =
                cached_metadata(&url, net, &cache.with_meta_ttl(cache.meta_ttl_unpinned()))?;
            let doc: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
            let versions = doc.get("versions")?.as_object()?;
            let version = if let Ok(range) = node_semver::Range::parse(requirement) {
                versions
                    .keys()
                    .filter_map(|spelling| {
                        let version = node_semver::Version::parse(spelling).ok()?;
                        range.satisfies(&version).then_some((version, spelling))
                    })
                    .max_by(|a, b| a.0.cmp(&b.0))?
                    .1
                    .clone()
            } else {
                // Non-semver registry specs are npm dist-tags (for example,
                // `latest`, `next`, or `beta`). Preserve their existing
                // semantics instead of treating them as invalid ranges.
                doc.get("dist-tags")?
                    .get(requirement)?
                    .as_str()?
                    .to_string()
            };
            (version, None)
        }
        "cargo" => {
            // A named/private registry is never redirected to crates.io.
            if purl.qualifier("repository_url").is_some_and(|r| {
                !matches!(
                    r.trim_end_matches('/'),
                    "https://crates.io" | "https://index.crates.io"
                )
            }) {
                return None;
            }
            let range = requirement.parse::<semver::VersionReq>().ok()?;
            let url = format!("https://crates.io/api/v1/crates/{name}");
            let bytes =
                cached_metadata(&url, net, &cache.with_meta_ttl(cache.meta_ttl_unpinned()))?;
            let doc: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
            let candidates = doc.get("versions")?.as_array()?;
            let (version, row) = candidates
                .iter()
                .filter(|v| v.get("yanked").and_then(serde_json::Value::as_bool) != Some(true))
                .filter_map(|row| {
                    let version = row.get("num")?.as_str()?.parse::<semver::Version>().ok()?;
                    range.matches(&version).then_some((version, row))
                })
                .max_by(|a, b| a.0.cmp(&b.0))?;
            (
                version.to_string(),
                row.get("checksum")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string),
            )
        }
        "pypi" => {
            let range = requirement.parse::<pep440_rs::VersionSpecifiers>().ok()?;
            let repository = repository_base(&purl, "https://pypi.org")?;
            let url = format!("{repository}/pypi/{name}/json");
            let bytes =
                cached_metadata(&url, net, &cache.with_meta_ttl(cache.meta_ttl_unpinned()))?;
            let doc: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
            let versions = doc.get("releases")?.as_object()?;
            let (_, spelling) = versions
                .iter()
                .filter(|(_, files)| {
                    files.as_array().is_some_and(|files| {
                        files.iter().any(|f| {
                            f.get("yanked").and_then(serde_json::Value::as_bool) != Some(true)
                        })
                    })
                })
                .filter_map(|(spelling, _)| {
                    let version = spelling.parse::<pep440_rs::Version>().ok()?;
                    (range.contains(&version) && !version.any_prerelease())
                        .then_some((version, spelling))
                })
                .max_by(|a, b| a.0.cmp(&b.0))?;
            (spelling.clone(), None)
        }
        _ => return None,
    };
    // The exact release: the declaration at the resolved version without the
    // requirement it satisfied, plus the registry's checksum when it offers
    // one the declaration didn't. Qualifiers and subpath are kept.
    let mut exact = purl
        .with_qualifier("version_requirement", None)?
        .with_version(&resolved)?;
    if let Some(checksum) =
        checksum.filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        && exact.qualifier("checksum").is_none()
    {
        exact = exact.with_qualifier("checksum", Some(&format!("sha256:{checksum}")))?;
    }
    Some(Requirement::Resolved(RefLocator::Purl(exact.canonical())))
}

/// Refine a manifest requirement before registry-age or reputation gating.
/// Returns `None` on unresolved requirements, never a guessed latest release.
/// The declaration's source/role/evidence remain attached to the exact target.
#[must_use]
pub fn resolve_declared_reference(
    reference: &Reference,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Option<Reference> {
    let mut exact = reference.clone();
    if let Requirement::Resolved(locator) = resolve_requirement(&reference.locator, net, cache)? {
        exact.locator = locator;
    }
    Some(exact)
}

/// Prefer a unique compatible lock pin for a manifest dependency. The caller
/// must supply only the applicable package/workspace lock, not an archive-wide
/// union. Multiple compatible versions stay unresolved rather than guessing.
#[must_use]
pub fn prefer_lock_pin(reference: &Reference, lock: &[Reference]) -> Reference {
    let RefLocator::Purl(raw) = &reference.locator else {
        return reference.clone();
    };
    let Ok(purl) = Purl::parse(raw) else {
        return reference.clone();
    };
    let Some(requirement) = purl.qualifier("version_requirement") else {
        return reference.clone();
    };
    if purl.version().is_some() || purl.qualifier("registry").is_some() {
        return reference.clone();
    }
    let matches: Vec<_> = lock
        .iter()
        .filter(|pin| {
            let RefLocator::Purl(p) = &pin.locator else {
                return false;
            };
            let Ok(pin) = Purl::parse(p) else {
                return false;
            };
            let Some(pin_version) = pin.version() else {
                return false;
            };
            if pin.typ() != purl.typ()
                || pin.encoded_path() != purl.encoded_path()
                || pin.qualifier("repository_url") != purl.qualifier("repository_url")
            {
                return false;
            }
            match purl.typ() {
                "cargo" => requirement
                    .parse::<semver::VersionReq>()
                    .ok()
                    .zip(pin_version.parse::<semver::Version>().ok())
                    .is_some_and(|(r, v)| r.matches(&v)),
                "pypi" => requirement
                    .parse::<pep440_rs::VersionSpecifiers>()
                    .ok()
                    .zip(pin_version.parse::<pep440_rs::Version>().ok())
                    .is_some_and(|(r, v)| r.contains(&v)),
                _ => false,
            }
        })
        .collect();
    let [only] = matches.as_slice() else {
        return reference.clone();
    };
    let mut resolved = reference.clone();
    resolved.locator = only.locator.clone();
    resolved.pinned_hash = only.pinned_hash.clone();
    resolved.content_sha256 = only.content_sha256.clone();
    resolved
}

pub(crate) fn deterministic_artifacts(purl: &Purl, kind: &str) -> Vec<ArtifactCandidate> {
    // The matrix reports the possible artifact even when an exact file_name
    // selector does not match it. In that case no candidate is preferred and
    // the legacy one-URL resolver still returns None.
    let Some(url) = resolve_purl_with_file_selection(purl, false) else {
        return Vec::new();
    };
    let mut candidate = artifact_candidate(url, kind);
    if let Some(subpath) = purl.subpath_string() {
        candidate.attributes.insert("subpath".into(), subpath);
    }
    candidate.preferred = file_name_matches(purl, &candidate.file_name);
    vec![candidate]
}

/// Map a PURL to a deterministic download URL for the computable ecosystems
/// (npm, crates.io, NuGet, Maven Central, GitHub archives), or to the `oci://`
/// pseudo-URL the OCI puller consumes.
pub(crate) fn resolve_purl(purl: &Purl) -> Option<String> {
    resolve_purl_with_file_selection(purl, true)
}

fn resolve_purl_with_file_selection(purl: &Purl, honor_file_name: bool) -> Option<String> {
    let ty = purl.typ();
    // pkg:oci carries its repository on a qualifier and splits version
    // (digest) from tag (qualifier) per its type definition.
    if ty == "oci" || ty == "docker" {
        return Some(resolve_oci_ref(purl));
    }
    // The standard common qualifier is an exact artifact selector and wins
    // over an ecosystem-derived URL. The normal HTTP fetch path still applies
    // its DNS/redirect SSRF guard to the selected destination.
    if let Some(url) = purl.qualifier("download_url") {
        return is_web_scheme(url).then(|| url.to_string());
    }
    let (path, version) = (purl.encoded_path(), purl.encoded_version());
    let (path, version) = (path.as_str(), version.as_deref());
    // Vetted once here rather than at each of the arms below, every one of
    // which interpolates these into a URL.
    if !safe_purl_coordinates(ty, path, version) {
        return None;
    }
    match ty {
        "npm" => {
            let name = path.replace("%40", "@");
            let base = name.rsplit('/').next().unwrap_or(name.as_str());
            let version = version?;
            let repository = repository_base(purl, "https://registry.npmjs.org")?;
            maybe_selected_artifact_url(
                purl,
                format!("{repository}/{name}/-/{base}-{version}.tgz"),
                honor_file_name,
            )
        }
        "cargo" => {
            let version = version?;
            if let Some(repository) = purl.qualifier("repository_url") {
                let repository = repository.trim_end_matches('/');
                if !matches!(repository, "https://crates.io" | "https://index.crates.io") {
                    // Alternate Cargo registries publish their download
                    // template in index config.json; only the metadata-aware
                    // matrix can resolve it.
                    return None;
                }
            }
            maybe_selected_artifact_url(
                purl,
                format!("https://static.crates.io/crates/{path}/{path}-{version}.crate"),
                honor_file_name,
            )
        }
        "github" => {
            let reference = version.unwrap_or("HEAD");
            Some(format!(
                "https://codeload.github.com/{path}/tar.gz/{reference}"
            ))
        }
        "golang" => {
            let version = version?;
            let repository = repository_base(purl, "https://proxy.golang.org")?;
            // The default Go module proxy. Module path and version are
            // case-encoded per the GOPROXY protocol.
            maybe_selected_artifact_url(
                purl,
                format!(
                    "{repository}/{}/@v/{}.zip",
                    goproxy_escape(path),
                    goproxy_escape(version)
                ),
                honor_file_name,
            )
        }
        "gem" => {
            let version = version?;
            let repository = repository_base(purl, "https://rubygems.org")?;
            let suffix = match purl.qualifier("platform") {
                None | Some("ruby") => String::new(),
                Some(value) if safe_filename_part(value) => format!("-{value}"),
                Some(_) => return None,
            };
            maybe_selected_artifact_url(
                purl,
                format!("{repository}/downloads/{path}-{version}{suffix}.gem"),
                honor_file_name,
            )
        }
        "nuget" => {
            // NuGet's flat-container coordinates and filenames are lowercase,
            // even when the package id/version in the PURL are not.
            let version = version?.to_lowercase();
            let id = path.to_lowercase();
            Some(format!(
                "https://api.nuget.org/v3-flatcontainer/{id}/{version}/{id}.{version}.nupkg"
            ))
        }
        "maven" => {
            // The PURL namespace is the dotted group id; Maven Central lays it
            // out as path segments. `type` and `classifier` select a non-default
            // artifact when present; otherwise the installable main JAR wins.
            let version = version?;
            let (group, artifact) = path.split_once('/')?;
            let extension = match purl.qualifier("type") {
                Some(v) if safe_filename_part(v) => v,
                Some(_) => return None,
                None => "jar",
            };
            let classifier = match purl.qualifier("classifier") {
                Some(v) if safe_filename_part(v) => format!("-{v}"),
                Some(_) => return None,
                None => String::new(),
            };
            Some(format!(
                "https://repo1.maven.org/maven2/{}/{artifact}/{version}/{artifact}-{version}{classifier}.{extension}",
                group.replace('.', "/")
            ))
        }
        // `chrome-extension` is the ratified purl-spec spelling of the type.
        "chrome" | "chrome-extension" => {
            // The CRX download service redirects to the current packed
            // extension; `id` is the last path segment (a slug may precede it).
            let id = path.rsplit('/').next().unwrap_or(path);
            Some(format!(
                "https://clients2.google.com/service/update2/crx?response=redirect&prodversion=120&acceptformat=crx2,crx3&x=id%3D{id}%26installsource%3Dondemand%26uc"
            ))
        }
        "clawhub" => {
            // ClawHub's download API takes the slug, plus the owner handle
            // when the purl carries one (slugs are not unique across
            // publishers; a bare shared slug 409s at the registry).
            let (owner, slug) = path.split_once('/').map_or(("", path), |(o, s)| (o, s));
            let mut url = format!("https://clawhub.ai/api/v1/download?slug={slug}");
            if !owner.is_empty() {
                url.push_str("&ownerHandle=");
                url.push_str(owner);
            }
            if let Some(v) = version {
                url.push_str("&version=");
                url.push_str(v);
            }
            Some(url)
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
/// and names the fetch edge. The error says why there is no URL.
fn resolved_target(
    locator: &RefLocator,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<(String, String), Unresolved> {
    let RefLocator::Purl(raw) = locator else {
        return resolve(locator)
            .map(|url| (locator_string(locator), url))
            .ok_or(Unresolved::Unsupported);
    };
    let purl = Purl::parse(raw).ok().ok_or(Unresolved::InvalidPurl)?;
    if let Requirement::Resolved(exact) =
        resolve_requirement(locator, net, cache).ok_or(Unresolved::NoRelease)?
    {
        return resolved_target(&exact, net, cache);
    }
    let p = purl.canonical();
    let ty = purl.typ();
    // An exact download override takes precedence even for ecosystems that
    // normally need metadata (notably versionless npm and PyPI). Apply the
    // common exact-filename selector to it just as the pure resolver does.
    if let Some(url) = purl.qualifier("download_url") {
        return (is_web_scheme(url) && file_name_matches(&purl, &file_name_from_url(url)))
            .then(|| (p, url.to_string()))
            .ok_or(Unresolved::Unsupported);
    }
    if purl.qualifier("vers").is_some() {
        return Err(Unresolved::Unsupported);
    }
    let (coordinate_path, coordinate_version) = (purl.encoded_path(), purl.encoded_version());
    let (coordinate_path, coordinate_version) =
        (coordinate_path.as_str(), coordinate_version.as_deref());
    // Every branch below builds registry URLs from these, as
    // [`resolve_purl`] does; vet them once, the same way.
    if !safe_purl_coordinates(ty, coordinate_path, coordinate_version) {
        return Err(Unresolved::UnsafeCoordinate);
    }
    // Registry metadata can refine a mutable/tagged request to a concrete
    // release and exact artifact. Use that identity for cache/provenance;
    // retain the pure resolver below as the offline compatibility path.
    let needs_matrix = ty == "pypi"
        // Go: the proxy is case-sensitive and a PURL may not be; the
        // matrix asks the proxy which spelling it serves
        // (`golang_artifacts`), the pure resolver cannot.
        || ty == "golang"
        // Terraform: the zip's URL and sha256 exist only in the registry's
        // download API (`terraform_artifact`).
        || ty == "terraform"
        || (ty == "npm"
            && coordinate_version.is_none_or(|version| !npm_version_is_concrete(version)))
        || (ty == "gem" && coordinate_version.is_none())
        || (ty == "cargo"
            && purl.qualifier("repository_url").is_some_and(|repository| {
                !matches!(
                    repository.trim_end_matches('/'),
                    "https://crates.io" | "https://index.crates.io"
                )
            }));
    if needs_matrix
        && let Some(candidate) = resolve_artifacts(locator, net, cache)
            .as_ref()
            .and_then(ArtifactMatrix::preferred)
    {
        let exact = candidate
            .artifact_purl
            .as_ref()
            .or(candidate.release_purl.as_ref())
            .cloned()
            .unwrap_or(p);
        return Ok((exact, candidate.url.clone()));
    }
    // A versionless (or tag-versioned) npm dependency is refined through
    // dist-tags.
    if ty == "npm" {
        match coordinate_version {
            None => {
                return resolve_npm_dist_tag(&purl, "latest", net).ok_or(Unresolved::NoRelease);
            }
            Some(version) if !npm_version_is_concrete(version) => {
                return purl
                    .version()
                    .and_then(|tag| resolve_npm_dist_tag(&purl, tag, net))
                    .ok_or(Unresolved::NoRelease);
            }
            Some(_) => {}
        }
    }
    // Open VSX publishes the exact `.vsix` URL in its API for both a pinned
    // and the latest version, so resolve through it rather than guessing.
    // The ratified `vscode-extension` type covers both stores, Open VSX
    // flagged by its repository_url qualifier (which normalization gives a
    // legacy `pkg:openvsx` too).
    let open_vsx = purl
        .qualifier("repository_url")
        .is_some_and(|url| url.contains("open-vsx.org"));
    if ty == "openvsx" || (ty == "vscode-extension" && open_vsx) {
        return resolve_openvsx(&purl, net)
            .map(|u| (p, u))
            .ok_or(Unresolved::NoRelease);
    }
    // The VS Code Marketplace's `.vsix` lives at a well-known gallery URL,
    // but the latest version (when unpinned) comes from the query API.
    if ty == "vscode" || ty == "vscode-extension" {
        return resolve_vscode(&purl, net)
            .map(|u| (p, u))
            .ok_or(Unresolved::NoRelease);
    }
    // PyPI may publish many files for one release. Honor its registered
    // case-sensitive `file_name` selector (and the legacy `kind` hint),
    // then feed the preferred matrix candidate through the old one-URL
    // fetch contract.
    if ty == "pypi" {
        let version = coordinate_version.ok_or(Unresolved::NoRelease)?;
        return pypi_artifacts(coordinate_path, Some(version), &purl, net, cache)
            .into_iter()
            .find(|candidate| candidate.preferred)
            .map(|candidate| (p, candidate.url))
            .ok_or(Unresolved::NoRelease);
    }
    // AMO publishes the exact XPI URL in its API, as ComfyUI Registry nodes
    // and Dify Marketplace plugins name their artifact only through theirs
    // (a publisher-keyed CDN path; a download key embedding Dify's own
    // checksum). A pinned version goes through its per-version document; an
    // unpinned one follows the current release and is refined to that
    // version for provenance and cache keys.
    if matches!(ty, "firefox" | "comfyui" | "dify") {
        let (version, url) = match ty {
            "firefox" => resolve_firefox(coordinate_path, coordinate_version, net, cache),
            "comfyui" => resolve_comfyui(coordinate_path, coordinate_version, net, cache),
            _ => resolve_dify(coordinate_path, coordinate_version, net, cache),
        }
        .ok_or(Unresolved::NoRelease)?;
        let locator = match coordinate_version {
            Some(_) => p,
            None => purl
                .with_version(&version)
                .ok_or(Unresolved::NoRelease)?
                .canonical(),
        };
        return Ok((locator, url));
    }
    // The AUR serves one artifact per package: the current PKGBUILD-tree
    // snapshot, addressed by *pkgbase* (a split package's snapshot lives
    // under its base, not its own name), which the RPC names exactly.
    // Snapshots track HEAD only, so a pinned version can't select an older
    // release — matching the github/HEAD and npm-latest stance of fetching
    // what the name serves right now. Three spellings route here, the same
    // set the registry lookup folds: `pkg:aur/<name>`, the spec
    // `pkg:alpm/arch/<name>?repository_url=https://aur.archlinux.org`
    // (which normalization folds into the `aur` namespace), and the legacy
    // `pkg:alpm/aur/<name>`.
    if ty == "aur"
        || (ty == "alpm"
            && (coordinate_path.starts_with("aur/")
                || purl
                    .qualifier("repository_url")
                    .is_some_and(|url| url.contains("aur.archlinux.org"))))
    {
        let name = coordinate_path
            .rsplit('/')
            .next()
            .unwrap_or(coordinate_path);
        return Ok((p, resolve_aur(name, net, cache)));
    }
    if ty == "composer"
        && let Some(version) = coordinate_version
    {
        return resolve_composer(coordinate_path, version, net)
            .map(|u| (p, u))
            .ok_or(Unresolved::NoRelease);
    }
    // The matrix is this type's artifact source, so when it named nothing and
    // the offline resolver cannot either, a release is what is missing.
    resolve_purl(&purl)
        .map(|url| (p, url))
        .ok_or(if needs_matrix {
            Unresolved::NoRelease
        } else {
            Unresolved::Unsupported
        })
}

pub(crate) fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// SSRF floor: refuse any address that isn't globally routable.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry_with_sources;

    use filefacts::HashAlgo;
    use filefacts::PinnedHash;
    use filefacts::RefKind;
    use sha1::Sha1;

    /// Resolve a versionless npm PURL path (`left-pad`, `%40scope/util`) to the
    /// concrete `(pkg:npm/<path>@<latest>, tarball URL)` it currently points at, by
    /// reading the registry packument's `dist-tags.latest`. The registry's own
    /// tarball URL is preferred over the derived one. `None` if the packument can't
    /// be fetched/parsed or names no latest version.
    fn resolve_npm_unversioned(
        _path: &str,
        rest: &str,
        net: &dyn Fetch,
    ) -> Option<(String, String)> {
        let purl = Purl::parse(&format!("pkg:npm/{rest}")).ok()?;
        resolve_npm_dist_tag(&purl, "latest", net)
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
    fn resolve_pypi(
        name: &str,
        version: &str,
        kind: Option<&str>,
        net: &dyn Fetch,
        cache: &BlobCache,
    ) -> Option<String> {
        let rest = kind.map_or_else(
            || format!("{name}@{version}"),
            |value| format!("{name}@{version}?kind={value}"),
        );
        let purl = Purl::parse(&format!("pkg:pypi/{rest}")).ok()?;
        pypi_artifacts(name, Some(version), &purl, net, cache)
            .into_iter()
            .find(|candidate| candidate.preferred)
            .map(|candidate| candidate.url)
    }

    #[test]
    fn cargo_requirement_selects_compatible_non_yanked_release() {
        let net=Fixtures::default().with("https://crates.io/api/v1/crates/codec",br#"{"versions":[{"num":"2.0.0","yanked":false},{"num":"1.9.0","yanked":true},{"num":"1.4.2","yanked":false}]}"#);
        let locator = RefLocator::Purl("pkg:cargo/codec?version_requirement=%5E1.2".into());
        let (exact, url) = resolved_target(&locator, &net, &BlobCache::disabled())
            .ok()
            .unwrap();
        assert_eq!(exact, "pkg:cargo/codec@1.4.2");
        assert!(url.ends_with("codec-1.4.2.crate"));
        assert!(
            resolved_target(
                &RefLocator::Purl("pkg:cargo/codec?version_requirement=%3E%3D9".into()),
                &net,
                &BlobCache::disabled()
            )
            .ok()
            .is_none()
        );
    }

    #[test]
    fn a_resolved_requirement_keeps_the_declared_subpath() {
        let net = Fixtures::default().with(
            "https://crates.io/api/v1/crates/codec",
            br#"{"versions":[{"num":"1.4.2","yanked":false}]}"#,
        );
        let declared =
            RefLocator::Purl("pkg:cargo/codec?version_requirement=%5E1.2#src/lib".into());
        let exact = resolve_requirement(&declared, &net, &BlobCache::disabled());
        assert_eq!(
            exact,
            Some(Requirement::Resolved(RefLocator::Purl(
                "pkg:cargo/codec@1.4.2#src/lib".into()
            )))
        );
    }

    #[test]
    fn python_requirement_does_not_pick_incompatible_latest() {
        let net=Fixtures::default().with("https://pypi.org/pypi/codec/json",br#"{"info":{"version":"9.0"},"releases":{"1.2":[{"yanked":false}],"1.9":[{"yanked":true}],"9.0":[{"yanked":false}]}}"#);
        let locator = RefLocator::Purl("pkg:pypi/codec?version_requirement=%3E%3D1%2C%3C2".into());
        assert_eq!(
            resolve_requirement(&locator, &net, &BlobCache::disabled()),
            Some(Requirement::Resolved(RefLocator::Purl(
                "pkg:pypi/codec@1.2".into()
            )))
        );
    }

    #[test]
    fn npm_requirement_selects_compatible_release_and_honors_dist_tag() {
        let packument = br#"{
            "dist-tags": {"latest": "4.0.50", "next": "5.0.0-beta.1"},
            "versions": {
                "3.0.39": {},
                "3.9.0": {},
                "4.0.50": {},
                "5.0.0-beta.1": {}
            }
        }"#;
        let net = Fixtures::default().with("https://registry.npmjs.org/@ai-sdk/groq", packument);
        let cache = BlobCache::disabled();

        // A manifest's ^3 range must not drift to the registry's newer major.
        let range = RefLocator::Purl("pkg:npm/%40ai-sdk/groq?version_requirement=%5E3.0.39".into());
        assert_eq!(
            resolve_requirement(&range, &net, &cache),
            Some(Requirement::Resolved(RefLocator::Purl(
                "pkg:npm/%40ai-sdk/groq@3.9.0".into()
            )))
        );

        // A non-range requirement remains a dist-tag lookup.
        let tag = RefLocator::Purl("pkg:npm/%40ai-sdk/groq?version_requirement=next".into());
        assert_eq!(
            resolve_requirement(&tag, &net, &cache),
            Some(Requirement::Resolved(RefLocator::Purl(
                "pkg:npm/%40ai-sdk/groq@5.0.0-beta.1".into()
            )))
        );
    }

    #[test]
    fn compatible_lock_pin_preserves_build_role_and_rejects_ambiguity() {
        let mut declaration = dep(
            RefLocator::Purl("pkg:cargo/codec?version_requirement=%5E1.2".into()),
            None,
        );
        declaration.source = "Cargo.toml:build-dependencies.aliased".into();
        declaration.evidence = "aliased = { package = codec, version = 1.2 }".into();
        let pin = dep(RefLocator::Purl("pkg:cargo/codec@1.4.2".into()), None);
        let exact = prefer_lock_pin(&declaration, std::slice::from_ref(&pin));
        assert_eq!(exact.locator, pin.locator);
        assert_eq!(exact.source, declaration.source);
        assert_eq!(exact.evidence, declaration.evidence);
        let incompatible = dep(RefLocator::Purl("pkg:cargo/codec@2.0.0".into()), None);
        assert_eq!(prefer_lock_pin(&declaration, &[incompatible]), declaration);
        let second = dep(RefLocator::Purl("pkg:cargo/codec@1.3.0".into()), None);
        assert_eq!(prefer_lock_pin(&declaration, &[pin, second]), declaration);
    }

    #[test]
    fn resolve_npm_unversioned_picks_latest_tarball() {
        // The packument names a current release; resolution refines the
        // versionless locator to it and returns the registry's tarball URL.
        let packument = br#"{
            "dist-tags": { "latest": "1.12.0", "next": "2.0.0-beta.1" },
            "versions": {
                "1.11.21": { "dist": { "tarball": "https://registry.npmjs.org/easy-day-js/-/easy-day-js-1.11.21.tgz" } },
                "1.12.0":  { "dist": { "tarball": "https://registry.npmjs.org/easy-day-js/-/easy-day-js-1.12.0.tgz" } },
                "2.0.0-beta.1": { "dist": { "tarball": "https://registry.npmjs.org/easy-day-js/-/easy-day-js-2.0.0-beta.1.tgz" } }
            }
        }"#;
        let net = Fixtures::default().with("https://registry.npmjs.org/easy-day-js", packument);
        assert_eq!(
            resolve_npm_unversioned("easy-day-js", "easy-day-js", &net),
            Some((
                "pkg:npm/easy-day-js@1.12.0".to_string(),
                "https://registry.npmjs.org/easy-day-js/-/easy-day-js-1.12.0.tgz".to_string()
            ))
        );
        assert_eq!(
            resolved_target(
                &RefLocator::Purl("pkg:npm/easy-day-js@next".into()),
                &net,
                &BlobCache::disabled(),
            )
            .ok(),
            Some((
                "pkg:npm/easy-day-js@2.0.0-beta.1".into(),
                "https://registry.npmjs.org/easy-day-js/-/easy-day-js-2.0.0-beta.1.tgz".into(),
            ))
        );
        // Scoped name: the `%40` encoding survives into the refined locator.
        let scoped = br#"{"dist-tags":{"latest":"2.0.0"},"versions":{"2.0.0":{"dist":{"tarball":"https://registry.npmjs.org/@scope/util/-/util-2.0.0.tgz"}}}}"#;
        let net = Fixtures::default().with("https://registry.npmjs.org/@scope/util", scoped);
        assert_eq!(
            resolve_npm_unversioned("%40scope/util", "%40scope/util", &net),
            Some((
                "pkg:npm/%40scope/util@2.0.0".to_string(),
                "https://registry.npmjs.org/@scope/util/-/util-2.0.0.tgz".to_string()
            ))
        );
        // Registry unreachable / unknown package → unresolved.
        assert_eq!(
            resolve_npm_unversioned("nope", "nope", &Fixtures::default()),
            None
        );
    }

    #[test]
    fn npm_artifact_matrix_keeps_runtime_compatibility_modifiers() {
        let packument = br#"{
            "versions": {"1.2.3": {
                "os": ["linux", "darwin"], "cpu": ["x64", "arm64"],
                "libc": "glibc", "engines": {"node": ">=20"},
                "dist": {
                    "tarball": "https://registry.npmjs.org/native-addon/-/native-addon-1.2.3.tgz",
                    "shasum": "0123456789abcdef",
                    "integrity": "sha512-Zm9v"
                }
            }}
        }"#;
        let net = Fixtures::default().with("https://registry.npmjs.org/native-addon", packument);
        let matrix = resolve_artifacts(
            &RefLocator::Purl("pkg:npm/native-addon@1.2.3".into()),
            &net,
            &BlobCache::disabled(),
        )
        .expect("matrix");
        assert_eq!(matrix.candidates.len(), 1);
        let candidate = matrix.preferred().expect("preferred");
        assert_eq!(candidate.file_name, "native-addon-1.2.3.tgz");
        assert_eq!(
            candidate.attributes.get("kind").map(String::as_str),
            Some("tgz")
        );
        assert_eq!(
            candidate.attributes.get("os").map(String::as_str),
            Some("linux,darwin")
        );
        assert_eq!(
            candidate.attributes.get("cpu").map(String::as_str),
            Some("x64,arm64")
        );
        assert_eq!(
            candidate.attributes.get("libc").map(String::as_str),
            Some("glibc")
        );
        assert_eq!(
            candidate.attributes.get("node").map(String::as_str),
            Some(">=20")
        );
        assert_eq!(
            candidate.checksums.get("sha1").map(String::as_str),
            Some("0123456789abcdef")
        );
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
        // A disabled cache forces the fixture fetch, keeping the test hermetic.
        let cache = BlobCache::disabled();
        // Default: wheel-first, mirroring `pip install`.
        assert_eq!(
            resolve_pypi("requests", "2.28.1", None, &net, &cache),
            Some(wheel.clone())
        );
        // `?kind=wheel` is the default's explicit form.
        assert_eq!(
            resolve_pypi("requests", "2.28.1", Some("wheel"), &net, &cache),
            Some(wheel)
        );
        // `?kind=sdist` flips to the source distribution.
        assert_eq!(
            resolve_pypi("requests", "2.28.1", Some("sdist"), &net, &cache),
            Some(sdist)
        );
        // No fixture (registry unreachable / unknown package) → unresolved.
        assert_eq!(
            resolve_pypi("nope", "9.9.9", None, &Fixtures::default(), &cache),
            None
        );
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
        let cache = BlobCache::disabled();
        assert_eq!(
            resolve_pypi("widget", "1.0.0", None, &net, &cache),
            Some("https://x/universal.whl".to_string())
        );
        assert_eq!(
            resolve_pypi("widget", "1.0.0", Some("wheel"), &net, &cache),
            Some("https://x/universal.whl".to_string())
        );
        assert_eq!(
            resolve_pypi("widget", "1.0.0", Some("sdist"), &net, &cache),
            Some("https://x/widget.tar.gz".to_string())
        );

        // The middle rank: no `py3-none-any`, but a non-py3 universal wheel
        // (`py2.py3-none-any`) is still platform-agnostic and must beat the
        // platform wheels — and must lose to `py3-none-any` when both exist.
        // Listed after the platform wheel so passing cannot be an artifact of
        // input order.
        let mid = "https://pypi.org/pypi/midwidget/1.0.0/json";
        let mbody = br#"{"urls":[
            {"packagetype":"bdist_wheel","filename":"midwidget-1.0.0-cp311-cp311-manylinux_x86_64.whl","url":"https://x/plat.whl"},
            {"packagetype":"bdist_wheel","filename":"midwidget-1.0.0-py2.py3-none-any.whl","url":"https://x/universal2.whl"}
        ]}"#;
        let net = Fixtures::default().with(mid, mbody);
        assert_eq!(
            resolve_pypi("midwidget", "1.0.0", None, &net, &cache),
            Some("https://x/universal2.whl".to_string())
        );

        // sdist-only version: wheel-first default falls back to the sdist.
        let sonly = "https://pypi.org/pypi/srconly/1.0.0/json";
        let sbody = br#"{"urls":[{"packagetype":"sdist","filename":"srconly-1.0.0.tar.gz","url":"https://x/src.tar.gz"}]}"#;
        let net = Fixtures::default().with(sonly, sbody);
        assert_eq!(
            resolve_pypi("srconly", "1.0.0", None, &net, &cache),
            Some("https://x/src.tar.gz".to_string())
        );

        // wheel-only version: explicit `kind=sdist` falls back to the wheel.
        let wonly = "https://pypi.org/pypi/wheelonly/1.0.0/json";
        let wbody = br#"{"urls":[{"packagetype":"bdist_wheel","filename":"wheelonly-1.0.0-py3-none-any.whl","url":"https://x/w.whl"}]}"#;
        let net = Fixtures::default().with(wonly, wbody);
        assert_eq!(
            resolve_pypi("wheelonly", "1.0.0", Some("sdist"), &net, &cache),
            Some("https://x/w.whl".to_string())
        );
    }

    #[test]
    fn pypi_artifact_matrix_exposes_file_and_wheel_tag_dimensions() {
        let api = "https://pypi.org/pypi/widget/1.0.0/json";
        let body = br#"{"urls":[
            {"packagetype":"sdist","filename":"widget-1.0.0.tar.gz","url":"https://x/widget-1.0.0.tar.gz","digests":{"sha256":"srcsha"}},
            {"packagetype":"bdist_wheel","filename":"widget-1.0.0-2-cp313-cp313-musllinux_1_2_aarch64.whl","url":"https://x/widget-musl.whl","python_version":"cp313","requires_python":">=3.10","yanked":true,"yanked_reason":"bad build","digests":{"sha256":"muslsha","blake2b_256":"blake"}},
            {"packagetype":"bdist_wheel","filename":"widget-1.0.0-cp313-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl","url":"https://x/widget-linux.whl"},
            {"packagetype":"bdist_wheel","filename":"widget-1.0.0-py3-none-any.whl","url":"https://x/widget-any.whl"}
        ]}"#;
        let net = Fixtures::default().with(api, body);
        let cache = BlobCache::disabled();
        let matrix = resolve_artifacts(
            &RefLocator::Purl("pkg:pypi/widget@1.0.0".into()),
            &net,
            &cache,
        )
        .expect("matrix");
        assert_eq!(matrix.candidates.len(), 4);
        assert_eq!(
            matrix.preferred().map(|value| value.file_name.as_str()),
            Some("widget-1.0.0-py3-none-any.whl")
        );
        let musl = matrix
            .candidates
            .iter()
            .find(|candidate| candidate.file_name.contains("musllinux"))
            .expect("musl wheel");
        assert_eq!(
            musl.qualifiers.get("file_name").map(String::as_str),
            Some("widget-1.0.0-2-cp313-cp313-musllinux_1_2_aarch64.whl")
        );
        assert_eq!(musl.attributes.get("build").map(String::as_str), Some("2"));
        assert_eq!(
            musl.attributes.get("yanked_reason").map(String::as_str),
            Some("bad build")
        );
        assert_eq!(
            musl.checksums.get("blake2b-256").map(String::as_str),
            Some("blake")
        );
        assert_eq!(
            musl.attributes.get("python").map(String::as_str),
            Some("cp313")
        );
        assert_eq!(
            musl.attributes.get("abi").map(String::as_str),
            Some("cp313")
        );
        assert_eq!(
            musl.attributes.get("platform").map(String::as_str),
            Some("musllinux_1_2_aarch64")
        );

        let exact = "widget-1.0.0-cp313-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl";
        let purl = format!("pkg:pypi/widget@1.0.0?file_name={exact}");
        let selected = resolve_artifacts(&RefLocator::Purl(purl.clone()), &net, &cache)
            .expect("selected matrix");
        assert_eq!(
            selected.preferred().map(|value| value.file_name.as_str()),
            Some(exact)
        );
        assert_eq!(
            resolved_target(&RefLocator::Purl(purl), &net, &cache)
                .ok()
                .map(|(_, url)| url),
            Some("https://x/widget-linux.whl".into())
        );

        let missing = resolve_artifacts(
            &RefLocator::Purl("pkg:pypi/widget@1.0.0?file_name=missing.whl".into()),
            &net,
            &cache,
        )
        .expect("unselected matrix");
        assert!(missing.preferred().is_none());
    }

    #[test]
    fn resolve_gem_to_rubygems_download() {
        assert_eq!(
            resolve(&RefLocator::Purl("pkg:gem/rails@7.0.4".into())),
            Some("https://rubygems.org/downloads/rails-7.0.4.gem".to_string())
        );
        assert_eq!(resolve(&RefLocator::Purl("pkg:gem/rails".into())), None);
        assert_eq!(
            resolve(&RefLocator::Purl(
                "pkg:gem/nokogiri@1.19.4?platform=x86_64-linux-gnu".into()
            )),
            Some("https://rubygems.org/downloads/nokogiri-1.19.4-x86_64-linux-gnu.gem".into())
        );
    }

    #[test]
    fn gem_artifact_matrix_exposes_every_published_platform() {
        let versions = br#"[
            {"number":"1.19.4","platform":"x86_64-linux-musl","sha":"muslsha","ruby_version":">= 3.1"},
            {"number":"1.19.4","platform":"ruby","sha":"rubysha"},
            {"number":"1.19.4","platform":"arm64-darwin","sha":"darwinsha"},
            {"number":"1.19.4","platform":"../../not-a-platform","sha":"badsha"},
            {"number":"1.19.3","platform":"ruby","sha":"oldsha"}
        ]"#;
        let net = Fixtures::default().with(
            "https://rubygems.org/api/v1/versions/nokogiri.json",
            versions,
        );
        let cache = BlobCache::disabled();
        let base = resolve_artifacts(
            &RefLocator::Purl("pkg:gem/nokogiri@1.19.4".into()),
            &net,
            &cache,
        )
        .expect("matrix");
        assert_eq!(base.candidates.len(), 3);
        assert_eq!(
            base.preferred().map(|value| value.file_name.as_str()),
            Some("nokogiri-1.19.4.gem")
        );

        let native = resolve_artifacts(
            &RefLocator::Purl("pkg:gem/nokogiri@1.19.4?platform=x86_64-linux-musl".into()),
            &net,
            &cache,
        )
        .expect("native matrix");
        let selected = native.preferred().expect("native preferred");
        assert_eq!(selected.file_name, "nokogiri-1.19.4-x86_64-linux-musl.gem");
        assert_eq!(
            selected.qualifiers.get("platform").map(String::as_str),
            Some("x86_64-linux-musl")
        );
        assert_eq!(
            selected.checksums.get("sha256").map(String::as_str),
            Some("muslsha")
        );
    }

    #[test]
    fn deterministic_ecosystems_honor_common_artifact_selectors() {
        let go = RefLocator::Purl(
            "pkg:golang/google.golang.org/genproto@v1.2.3#googleapis/api/annotations".into(),
        );
        assert_eq!(
            resolve(&go),
            Some("https://proxy.golang.org/google.golang.org/genproto/@v/v1.2.3.zip".into())
        );
        let matrix = resolve_artifacts(&go, &Fixtures::default(), &BlobCache::disabled())
            .expect("go matrix");
        assert_eq!(
            matrix
                .preferred()
                .and_then(|value| value.attributes.get("subpath"))
                .map(String::as_str),
            Some("googleapis/api/annotations")
        );

        assert!(
            resolve(&RefLocator::Purl(
                "pkg:cargo/serde@1.0.0?file_name=another.crate".into()
            ))
            .is_none()
        );
        let unmatched = resolve_artifacts(
            &RefLocator::Purl("pkg:cargo/serde@1.0.0?file_name=another.crate".into()),
            &Fixtures::default(),
            &BlobCache::disabled(),
        )
        .expect("unselected cargo matrix");
        assert_eq!(unmatched.candidates.len(), 1);
        assert_eq!(unmatched.candidates[0].file_name, "serde-1.0.0.crate");
        assert!(unmatched.preferred().is_none());
        assert_eq!(
            resolve(&RefLocator::Purl(
                "pkg:cargo/serde@1.0.0?file_name=serde-1.0.0.crate".into()
            )),
            Some("https://static.crates.io/crates/serde/serde-1.0.0.crate".into())
        );
        assert_eq!(
            resolve(&RefLocator::Purl(
                "pkg:cargo/serde@1.0.0?download_url=https:%2F%2Fmirror.test%2Fserde.crate".into()
            )),
            Some("https://mirror.test/serde.crate".into())
        );

        let override_purl = RefLocator::Purl(
            "pkg:npm/native-addon?download_url=https:%2F%2Fmirror.test%2Fnative.tgz&file_name=native.tgz"
                .into(),
        );
        assert_eq!(
            resolved_target(&override_purl, &Fixtures::default(), &BlobCache::disabled()).ok(),
            Some((
                locator_string(&override_purl),
                "https://mirror.test/native.tgz".into()
            ))
        );
        let wrong_file = RefLocator::Purl(
            "pkg:npm/native-addon?download_url=https:%2F%2Fmirror.test%2Fnative.tgz&file_name=other.tgz"
                .into(),
        );
        assert!(
            resolved_target(&wrong_file, &Fixtures::default(), &BlobCache::disabled())
                .ok()
                .is_none()
        );
        let override_matrix =
            resolve_artifacts(&wrong_file, &Fixtures::default(), &BlobCache::disabled())
                .expect("unselected override matrix");
        assert_eq!(override_matrix.candidates.len(), 1);
        assert!(override_matrix.preferred().is_none());
    }

    #[test]
    fn alternate_repositories_and_ranges_do_not_fall_back_to_public_defaults() {
        let npm_repo = "https://npm.example.test";
        let npm_doc = br#"{"versions":{"1.2.3":{"dist":{"tarball":"https://cdn.example.test/pkg-1.2.3.tgz"}}}}"#;
        let pypi_api = "https://python.example.test/pypi/widget/1.0/json";
        let pypi_doc = br#"{"urls":[{"packagetype":"sdist","filename":"widget-1.0.tar.gz","url":"https://python.example.test/files/widget-1.0.tar.gz"}]}"#;
        let gem_api = "https://gems.example.test/api/v1/versions/widget.json";
        let gem_doc = br#"[{"number":"1.0","platform":"ruby"}]"#;
        let cargo_config = "https://cargo.example.test/index/config.json";
        let cargo_doc = br#"{"dl":"https://cargo.example.test/files/{lowerprefix}/{crate}/{version}/{crate}.crate"}"#;
        let net = Fixtures::default()
            .with(&format!("{npm_repo}/pkg"), npm_doc)
            .with(pypi_api, pypi_doc)
            .with(gem_api, gem_doc)
            .with(cargo_config, cargo_doc);
        let cache = BlobCache::disabled();

        let cases = [
            (
                "pkg:npm/pkg@1.2.3?repository_url=https:%2F%2Fnpm.example.test",
                "https://cdn.example.test/pkg-1.2.3.tgz",
            ),
            (
                "pkg:pypi/widget@1.0?repository_url=https:%2F%2Fpython.example.test",
                "https://python.example.test/files/widget-1.0.tar.gz",
            ),
            (
                "pkg:gem/widget@1.0?repository_url=https:%2F%2Fgems.example.test",
                "https://gems.example.test/downloads/widget-1.0.gem",
            ),
            (
                "pkg:cargo/serde@1.0.0?repository_url=https:%2F%2Fcargo.example.test%2Findex",
                "https://cargo.example.test/files/se/rd/serde/1.0.0/serde.crate",
            ),
        ];
        for (purl, expected) in cases {
            let matrix = resolve_artifacts(&RefLocator::Purl(purl.into()), &net, &cache)
                .expect("supported matrix");
            assert_eq!(
                matrix.preferred().map(|candidate| candidate.url.as_str()),
                Some(expected),
                "repository for {purl}"
            );
        }

        assert_eq!(
            resolve(&RefLocator::Purl(
                "pkg:golang/example.com/Mod@v1.0.0?repository_url=https:%2F%2Fgo.example.test"
                    .into()
            )),
            Some("https://go.example.test/example.com/!mod/@v/v1.0.0.zip".into())
        );
        assert!(
            resolve(&RefLocator::Purl(
                "pkg:cargo/serde@1.0.0?repository_url=https:%2F%2Fcargo.example.test%2Findex"
                    .into()
            ))
            .is_none()
        );

        let range = RefLocator::Purl("pkg:npm/pkg?vers=vers:npm%2F%3E%3D1.0.0".into());
        let matrix = resolve_artifacts(&range, &net, &cache).expect("range matrix");
        assert!(matrix.candidates.is_empty());
        assert!(resolved_target(&range, &net, &cache).ok().is_none());
    }

    #[test]
    fn resolve_nuget_and_maven_artifacts() {
        assert_eq!(
            resolve(&RefLocator::Purl(
                "pkg:nuget/Newtonsoft.Json@13.0.3".into()
            )),
            Some(
                "https://api.nuget.org/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg"
                    .to_string()
            )
        );
        assert_eq!(
            resolve(&RefLocator::Purl(
                "pkg:maven/com.google.guava/guava@32.1.3-jre".into()
            )),
            Some(
                "https://repo1.maven.org/maven2/com/google/guava/guava/32.1.3-jre/guava-32.1.3-jre.jar"
                    .to_string()
            )
        );
        assert_eq!(
            resolve(&RefLocator::Purl(
                "pkg:maven/org.example/tool@1.2.0?classifier=sources&type=zip".into()
            )),
            Some(
                "https://repo1.maven.org/maven2/org/example/tool/1.2.0/tool-1.2.0-sources.zip"
                    .to_string()
            )
        );
        assert_eq!(
            resolve(&RefLocator::Purl(
                "pkg:maven/org.example/tool@1.2.0?classifier=..%2Fsecret".into()
            )),
            None
        );
    }

    /// The registry's download API for one Terraform provider platform.
    fn terraform_download(os: &str, arch: &str, bytes: &[u8]) -> (String, String) {
        let file = format!("terraform-provider-docker_3.0.2_{os}_{arch}.zip");
        let url = format!(
            "https://github.com/kreuzwerker/terraform-provider-docker/releases/download/v3.0.2/{file}"
        );
        let info = serde_json::json!({
            "os": os, "arch": arch, "filename": file, "download_url": url,
            "shasum": sha256_hex(bytes).to_ascii_uppercase(),
        });
        (info.to_string(), url)
    }

    const TERRAFORM_DOCKER: &str = "https://registry.terraform.io/v1/providers/kreuzwerker/docker";

    #[test]
    fn terraform_fetch_verifies_the_registry_shasum() {
        let (info, zip) = terraform_download("linux", "amd64", b"ZIP");
        let api = format!("{TERRAFORM_DOCKER}/3.0.2/download/linux/amd64");
        let net = Fixtures::default()
            .with(&api, info.as_bytes())
            .with(&zip, b"ZIP");
        let cache = BlobCache::disabled();
        // A mixed-case address is the same provider.
        let reference = dep(
            RefLocator::Purl("pkg:terraform/Kreuzwerker/Docker@3.0.2".into()),
            None,
        );
        let rec = fetch_ref(&reference, &net, &cache);
        assert_eq!(rec.outcome, Outcome::Ok);
        assert_eq!(rec.pin_verified, Some(true));
        assert_eq!(rec.resolved_url.as_deref(), Some(&*zip));
        assert_eq!(
            rec.locator,
            format!(
                "pkg:terraform/kreuzwerker/docker@3.0.2?checksum=sha256:{}\
                 &file_name=terraform-provider-docker_3.0.2_linux_amd64.zip",
                sha256_hex(b"ZIP")
            )
        );

        // Bytes that disagree with the registry's shasum are a finding.
        let net = Fixtures::default()
            .with(&api, info.as_bytes())
            .with(&zip, b"SUBSTITUTED");
        let rec = fetch_ref(&reference, &net, &cache);
        assert_eq!(rec.outcome, Outcome::PinMismatch);
        assert_eq!(rec.pin_verified, Some(false));

        // Without a well-formed shasum nothing can be verified: refuse.
        let unsigned = info.replace(&sha256_hex(b"ZIP").to_ascii_uppercase(), "abc");
        let net = Fixtures::default()
            .with(&api, unsigned.as_bytes())
            .with(&zip, b"ZIP");
        assert_eq!(
            fetch_ref(&reference, &net, &cache).outcome,
            Outcome::Unresolved(Unresolved::NoRelease)
        );
    }

    #[test]
    fn terraform_falls_back_to_the_first_listed_platform() {
        let (info, zip) = terraform_download("darwin", "arm64", b"ZIP");
        let versions = serde_json::json!({"versions": [
            {"version": "3.0.1", "platforms": [{"os": "linux", "arch": "amd64"}]},
            {"version": "3.0.2", "platforms": [
                {"os": "darwin", "arch": "arm64"}, {"os": "windows", "arch": "amd64"}
            ]},
        ]})
        .to_string();
        let net = Fixtures::default()
            .refusing(
                &format!("{TERRAFORM_DOCKER}/3.0.2/download/linux/amd64"),
                404,
            )
            .with(&format!("{TERRAFORM_DOCKER}/versions"), versions.as_bytes())
            .with(
                &format!("{TERRAFORM_DOCKER}/3.0.2/download/darwin/arm64"),
                info.as_bytes(),
            );
        let cache = BlobCache::disabled();
        let locator = RefLocator::Purl("pkg:terraform/kreuzwerker/docker@3.0.2".into());
        let (exact, url) = resolved_target(&locator, &net, &cache).ok().unwrap();
        assert_eq!(url, zip);
        assert!(exact.ends_with("&file_name=terraform-provider-docker_3.0.2_darwin_arm64.zip"));

        // Only a 404 means "no such platform"; an unreachable registry is not
        // a reason to pick a different build.
        let net = Fixtures::default()
            .with(&format!("{TERRAFORM_DOCKER}/versions"), versions.as_bytes())
            .with(
                &format!("{TERRAFORM_DOCKER}/3.0.2/download/darwin/arm64"),
                info.as_bytes(),
            );
        assert_eq!(resolved_target(&locator, &net, &cache).ok(), None);
    }

    #[test]
    fn terraform_versionless_resolves_the_current_release() {
        let (info, zip) = terraform_download("linux", "amd64", b"ZIP");
        let net = Fixtures::default()
            .with(
                TERRAFORM_DOCKER,
                br#"{"id":"kreuzwerker/docker/3.0.2","version":"3.0.2"}"#,
            )
            .with(
                &format!("{TERRAFORM_DOCKER}/3.0.2/download/linux/amd64"),
                info.as_bytes(),
            );
        let locator = RefLocator::Purl("pkg:terraform/kreuzwerker/docker".into());
        let (exact, url) = resolved_target(&locator, &net, &BlobCache::disabled())
            .ok()
            .unwrap();
        assert_eq!(url, zip);
        assert!(exact.starts_with("pkg:terraform/kreuzwerker/docker@3.0.2?checksum=sha256:"));
    }

    #[test]
    fn resolve_firefox_uses_exact_version_and_refines_latest() {
        let pinned_api =
            "https://addons.mozilla.org/api/v5/addons/addon/surf-click/versions/1.0.9/";
        let latest_api = "https://addons.mozilla.org/api/v5/addons/addon/surf-click/";
        let xpi = "https://addons.mozilla.org/firefox/downloads/file/4909333/surf_click-1.0.9.xpi";
        let pinned = serde_json::json!({
            "version": "1.0.9",
            "file": {"url": xpi}
        })
        .to_string();
        let latest = serde_json::json!({
            "current_version": {
                "version": "1.0.9",
                "file": {"url": xpi}
            }
        })
        .to_string();
        let net = Fixtures::default()
            .with(pinned_api, pinned.as_bytes())
            .with(latest_api, latest.as_bytes())
            .with(xpi, b"XPI");
        let cache = BlobCache::disabled();

        assert_eq!(
            resolved_target(
                &RefLocator::Purl("pkg:firefox/surf-click@1.0.9".into()),
                &net,
                &cache
            )
            .ok(),
            Some(("pkg:firefox/surf-click@1.0.9".to_string(), xpi.to_string()))
        );
        assert_eq!(
            resolved_target(
                &RefLocator::Purl("pkg:firefox/surf-click".into()),
                &net,
                &cache
            )
            .ok(),
            Some(("pkg:firefox/surf-click@1.0.9".to_string(), xpi.to_string()))
        );
        let rec = fetch_ref(
            &dep(
                RefLocator::Purl("pkg:firefox/surf-click@1.0.9".into()),
                None,
            ),
            &net,
            &cache,
        );
        assert_eq!(rec.outcome, Outcome::Ok);
        assert_eq!(rec.resolved_url.as_deref(), Some(xpi));
        assert_eq!(rec.content_sha256.as_deref(), Some(&*sha256_hex(b"XPI")));

        // A mismatched per-version response is refused rather than silently
        // substituting another release for the requested artifact.
        let wrong = serde_json::json!({
            "version": "1.0.8",
            "file": {"url": "https://example.invalid/wrong.xpi"}
        })
        .to_string();
        let net = Fixtures::default().with(pinned_api, wrong.as_bytes());
        assert_eq!(
            resolved_target(
                &RefLocator::Purl("pkg:firefox/surf-click@1.0.9".into()),
                &net,
                &cache
            )
            .ok(),
            None
        );
    }

    #[test]
    fn resolve_comfyui_uses_exact_version_and_refines_latest() {
        let base = "https://api.comfy.org/nodes/comfyui-loopstrip/install";
        let pinned_api = format!("{base}?version=1.3.1");
        // The CDN path is the publisher's, not derivable from the node id.
        let zip = "https://cdn.comfy.org/serhiiyashyn-sf/comfyui-loopstrip/1.3.1/node.zip";
        let doc = serde_json::json!({
            "node_id": "comfyui-loopstrip", "version": "1.3.1", "downloadUrl": zip
        })
        .to_string();
        let net = Fixtures::default()
            .with(&pinned_api, doc.as_bytes())
            .with(base, doc.as_bytes())
            .with(zip, b"ZIP");
        let cache = BlobCache::disabled();
        let exact = "pkg:comfyui/comfyui-loopstrip@1.3.1";
        for purl in [exact, "pkg:comfyui/comfyui-loopstrip"] {
            assert_eq!(
                resolved_target(&RefLocator::Purl(purl.into()), &net, &cache).ok(),
                Some((exact.to_string(), zip.to_string())),
                "{purl}"
            );
        }
        let rec = fetch_ref(&dep(RefLocator::Purl(exact.into()), None), &net, &cache);
        assert_eq!(rec.outcome, Outcome::Ok);
        assert_eq!(rec.content_sha256.as_deref(), Some(&*sha256_hex(b"ZIP")));

        // Another release or another node in the answer is refused, as is a
        // namespaced id (the registry has none).
        for wrong in [
            serde_json::json!({"node_id": "comfyui-loopstrip", "version": "1.3.0", "downloadUrl": zip}),
            serde_json::json!({"node_id": "other-node", "version": "1.3.1", "downloadUrl": zip}),
        ] {
            let net = Fixtures::default().with(&pinned_api, wrong.to_string().as_bytes());
            assert_eq!(
                resolved_target(&RefLocator::Purl(exact.into()), &net, &cache).ok(),
                None
            );
        }
        assert_eq!(
            resolved_target(
                &RefLocator::Purl("pkg:comfyui/owner/comfyui-loopstrip@1.3.1".into()),
                &net,
                &cache
            )
            .ok(),
            None
        );
    }

    #[test]
    fn resolve_dify_downloads_by_unique_identifier() {
        let base = "https://marketplace.dify.ai/api/v1/plugins/fr3on/eval-loop";
        let identifier = format!("fr3on/eval-loop:0.1.1@{}", "b2".repeat(32));
        let pkg = format!(
            "https://marketplace.dify.ai/api/v1/plugins/download?unique_identifier=fr3on%2Feval-loop:0.1.1%40{}",
            "b2".repeat(32)
        );
        let pinned = serde_json::json!({"code": 0, "data": {"version": {
            "version": "0.1.1", "unique_identifier": identifier
        }}})
        .to_string();
        let latest = serde_json::json!({"code": 0, "data": {"plugin": {
            "latest_version": "0.1.1", "latest_package_identifier": identifier
        }}})
        .to_string();
        let net = Fixtures::default()
            .with(&format!("{base}/0.1.1"), pinned.as_bytes())
            .with(base, latest.as_bytes())
            .with(&pkg, b"DIFYPKG");
        let cache = BlobCache::disabled();
        let exact = "pkg:dify/fr3on/eval-loop@0.1.1";
        for purl in [exact, "pkg:dify/fr3on/eval-loop"] {
            assert_eq!(
                resolved_target(&RefLocator::Purl(purl.into()), &net, &cache).ok(),
                Some((exact.to_string(), pkg.clone())),
                "{purl}"
            );
        }
        let rec = fetch_ref(&dep(RefLocator::Purl(exact.into()), None), &net, &cache);
        assert_eq!(rec.outcome, Outcome::Ok);
        assert_eq!(
            rec.content_sha256.as_deref(),
            Some(&*sha256_hex(b"DIFYPKG"))
        );

        // An identifier naming another plugin or release is refused, as is a
        // bare name (the marketplace keys every plugin by its org).
        for wrong in [
            format!("evil/eval-loop:0.1.1@{}", "b2".repeat(32)),
            format!("fr3on/eval-loop:0.1.0@{}", "b2".repeat(32)),
            "fr3on/eval-loop:0.1.1@not-a-checksum".to_string(),
        ] {
            let doc = serde_json::json!({"data": {"version": {
                "version": "0.1.1", "unique_identifier": wrong
            }}})
            .to_string();
            let net = Fixtures::default().with(&format!("{base}/0.1.1"), doc.as_bytes());
            assert_eq!(
                resolved_target(&RefLocator::Purl(exact.into()), &net, &cache).ok(),
                None,
                "{wrong}"
            );
        }
        assert_eq!(
            resolved_target(
                &RefLocator::Purl("pkg:dify/eval-loop@0.1.1".into()),
                &net,
                &cache
            )
            .ok(),
            None
        );
    }

    #[test]
    fn resolve_clawhub_download_url() {
        assert_eq!(
            resolve(&RefLocator::Purl("pkg:clawhub/owner/cool-skill@1.0.2".into())),
            Some(
                "https://clawhub.ai/api/v1/download?slug=cool-skill&ownerHandle=owner&version=1.0.2"
                    .to_string()
            )
        );
        // A bare slug (no owner, no version) still resolves.
        assert_eq!(
            resolve(&RefLocator::Purl("pkg:clawhub/coolskill".into())),
            Some("https://clawhub.ai/api/v1/download?slug=coolskill".to_string())
        );
    }

    #[test]
    fn oci_pull_requires_backend_consent() {
        // A backend that hasn't opted in (allows_oci defaults to false) must
        // never have a container pulled behind its back: the reference still
        // resolves (the probe's download_url), but the fetch is refused
        // rather than routed around the backend to the live registry.
        let r = Reference {
            locator: RefLocator::Purl(
                "pkg:oci/nginx?repository_url=docker.io%2Flibrary%2Fnginx".into(),
            ),
            kind: RefKind::Dependency,
            source: "test".into(),
            evidence: String::new(),
            offset: 0,
            pinned_hash: None,
            content_sha256: None,
        };
        let rec = fetch_ref(&r, &Fixtures::default(), &BlobCache::disabled());
        assert_eq!(
            rec.resolved_url.as_deref(),
            Some("oci://docker.io/library/nginx:latest")
        );
        match &rec.outcome {
            Outcome::Failed(FetchError::Refused(why)) => {
                assert!(why.contains("not permitted"), "{why}")
            }
            other => panic!("want refused-without-network, got {other:?}"),
        }
    }

    #[test]
    fn resolve_oci_to_pseudo_url() {
        // Tag from the qualifier, repository from the percent-encoded
        // repository_url (the pkgparse canonical form).
        assert_eq!(
            resolve(&RefLocator::Purl(
                "pkg:oci/nginx?repository_url=docker.io%2Flibrary%2Fnginx&tag=1.25".into()
            )),
            Some("oci://docker.io/library/nginx:1.25".to_string())
        );
        // A sha256 digest is the version and wins over any tag.
        assert_eq!(
            resolve(&RefLocator::Purl(
                "pkg:oci/img@sha256:244fd47e07d10?repository_url=ghcr.io%2Fowner%2Fimg&tag=v1"
                    .into()
            )),
            Some("oci://ghcr.io/owner/img@sha256:244fd47e07d10".to_string())
        );
        // No qualifier, no version: Docker Hub's implied coordinates, latest.
        assert_eq!(
            resolve(&RefLocator::Purl("pkg:oci/nginx".into())),
            Some("oci://docker.io/library/nginx:latest".to_string())
        );
        // Legacy pkg:docker with namespace and a tag in the version slot.
        assert_eq!(
            resolve(&RefLocator::Purl(
                "pkg:docker/smartentry/debian@dc437cc87d10".into()
            )),
            Some("oci://docker.io/smartentry/debian:dc437cc87d10".to_string())
        );
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
    fn selected_gates_urls_by_kind_not_just_locator() {
        let with_kind = |locator: RefLocator, kind: RefKind| Reference {
            locator,
            kind,
            source: "test".into(),
            evidence: "test".into(),
            offset: 0,
            pinned_hash: None,
            content_sha256: None,
        };
        let url = || RefLocator::Url("https://example.com/x.tar.gz".into());
        let purl = || RefLocator::Purl("pkg:npm/left-pad@1.3.0".into());

        // A declared dependency or a commanded package expressed as a raw URL (a
        // PKGBUILD `source=()`, a lockfile URL entry) is a genuine fetch target
        // regardless of `url_fetches` — it follows the deps/packages policy.
        assert!(selected(
            &with_kind(url(), RefKind::Dependency),
            UrlFetches::Skip
        ));
        assert!(selected(
            &with_kind(url(), RefKind::Command),
            UrlFetches::Skip
        ));

        // An opportunistic URL fetch (a script's curl/wget) stays behind the flag.
        assert!(!selected(
            &with_kind(url(), RefKind::UrlFetch),
            UrlFetches::Skip
        ));
        assert!(selected(
            &with_kind(url(), RefKind::UrlFetch),
            UrlFetches::Include
        ));

        // A package coordinate is always fetched; a repository is identity — its
        // non-fetch-target kind short-circuits `selected` before the locator.
        assert!(selected(
            &with_kind(purl(), RefKind::Dependency),
            UrlFetches::Skip
        ));
        assert!(!selected(
            &with_kind(url(), RefKind::Repository),
            UrlFetches::Include
        ));
    }

    #[test]
    fn resolves_npm_scoped_and_unscoped() {
        let resolve_purl = |raw: &str| resolve_purl(&Purl::parse(raw).unwrap());
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
        assert_eq!(rec.resolved_url.as_deref(), Some(url));
        assert!(!rec.is_cached());
        assert_eq!(rec.size, Some(7));
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

        let declared = dep(
            RefLocator::Purl(format!(
                "pkg:cargo/foo@1.0.0?checksum=sha256:{}",
                sha256_hex(b"REAL")
            )),
            None,
        );
        let rec = fetch_ref(&declared, &net, &cache);
        assert_eq!(rec.outcome, Outcome::Ok);
        assert_eq!(rec.pin_verified, Some(true));

        let declared_bad = dep(
            RefLocator::Purl(format!(
                "pkg:cargo/foo@1.0.0?checksum=sha256:{}",
                "0".repeat(64)
            )),
            None,
        );
        let rec = fetch_ref(&declared_bad, &net, &cache);
        assert_eq!(rec.outcome, Outcome::PinMismatch);
        assert_eq!(rec.pin_verified, Some(false));
    }

    /// A backend that panics when asked for one URL, as a parser bug tripped
    /// by hostile bytes would, and otherwise serves `inner`.
    struct PanicsOn {
        url: &'static str,
        inner: Fixtures,
    }

    impl Fetch for PanicsOn {
        fn send(&self, request: &Request<'_>) -> Result<Fetched, FetchError> {
            if request.url == self.url {
                panic!("hostile bytes");
            }
            self.inner.send(request)
        }
    }

    #[test]
    fn a_panicking_fetch_fails_alone() {
        let ok = "https://ok.test/a.sh";
        let bad = "https://bad.test/b.sh";
        let net = PanicsOn {
            url: bad,
            inner: Fixtures::default().with(ok, b"A"),
        };
        let refs: Vec<Reference> = [bad, ok]
            .into_iter()
            .map(|url| dep(RefLocator::Url(url.into()), None))
            .collect();
        let recs = fetch_references(
            &refs,
            "src",
            UrlFetches::Include,
            &net,
            &BlobCache::disabled(),
            FetchBudget::default(),
        );
        // The panic is that reference's failure, not a budget cut, and the
        // other reference is still fetched.
        assert_eq!(
            recs[0].outcome,
            Outcome::Failed(FetchError::Internal("hostile bytes".into()))
        );
        assert_eq!(recs[1].outcome, Outcome::Ok);
    }

    #[test]
    fn a_panic_in_the_callers_callback_reaches_the_caller() {
        let url = "https://ok.test/a.sh";
        let net = Fixtures::default().with(url, b"A");
        let refs = [dep(RefLocator::Url(url.into()), None)];
        let run = std::panic::catch_unwind(|| {
            fetch_references_with(
                &refs,
                "src",
                UrlFetches::Include,
                &net,
                &BlobCache::disabled(),
                FetchBudget::default(),
                &|_, _| panic!("caller bug"),
            )
        });
        assert!(run.is_err(), "the caller's panic must not be swallowed");
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

        // Without URL fetches: only the package (raw URL + repo excluded).
        let recs = fetch_references(
            &refs,
            "trigsha",
            UrlFetches::Skip,
            &net,
            &cache,
            FetchBudget::default(),
        );
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].locator, "pkg:npm/foo@1.0.0");
        // Every edge is stamped with its source endpoint and binding class.
        assert_eq!(recs[0].source_sha256.as_deref(), Some("trigsha"));
        assert_eq!(recs[0].kind, RefKind::Dependency);

        // With fetch_urls: package + raw URL; the repository is never fetched.
        let recs = fetch_references(
            &refs,
            "trigsha",
            UrlFetches::Include,
            &net,
            &cache,
            FetchBudget::default(),
        );
        assert_eq!(recs.len(), 2);
        // The raw URL's edge carries its own binding class, and it serializes
        // (`kind` is how a consumer distinguishes a pinned lockfile entry from
        // a curl in an install hook — the edge must say which claim it makes).
        let url_rec = recs
            .iter()
            .find(|r| r.locator == raw_url)
            .expect("raw URL edge");
        assert_eq!(url_rec.kind, RefKind::UrlFetch);
        let json = serde_json::to_value(url_rec).expect("serialize edge");
        assert_eq!(json["kind"], serde_json::json!("url_fetch"));

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
            UrlFetches::Include,
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
        assert!(
            recs.iter()
                .all(|r| r.source_sha256.as_deref() == Some("trigsha"))
        );
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
        let warm = fetch_references(
            &refs,
            "s",
            UrlFetches::Include,
            &net,
            &cache,
            FetchBudget::default(),
        );
        assert_eq!(warm.len(), 2);
        assert!(
            warm.iter()
                .all(|r| r.outcome == Outcome::Ok && !r.is_cached()),
            "cold run should fetch both live"
        );

        // Re-run with zero live-fetch budget: cache hits don't count, so both
        // are still served from cache rather than recorded as BudgetExceeded.
        let warm = fetch_references(
            &refs,
            "s",
            UrlFetches::Include,
            &net,
            &cache,
            FetchBudget {
                max_count: 0,
                max_bytes: u64::MAX,
            },
        );
        assert_eq!(
            warm.iter()
                .filter(|r| r.is_cached() && r.outcome == Outcome::Ok)
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
        fn send(&self, request: &Request<'_>) -> Result<Fetched, FetchError> {
            self.gets.fetch_add(1, Ordering::SeqCst);
            self.inner.send(request)
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
                UrlFetches::Skip,
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
            let warmed = fetch_references(
                &warm,
                "sha",
                UrlFetches::Skip,
                &fx,
                &cache,
                FetchBudget::default(),
            );
            assert!(
                warmed
                    .iter()
                    .all(|r| r.outcome == Outcome::Ok && !r.is_cached())
            );

            let net = CountingFetch {
                inner: fx,
                gets: AtomicUsize::new(0),
            };
            let recs = fetch_references(
                &refs,
                "sha",
                UrlFetches::Skip,
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
                    recs[even].is_cached() && recs[even].outcome == Outcome::Ok,
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
        let recs = fetch_references(
            &refs,
            "sha",
            UrlFetches::Skip,
            &net,
            &cache,
            FetchBudget::default(),
        );
        assert_eq!(recs.len(), n);
        for (i, rec) in recs.iter().enumerate() {
            assert_eq!(rec.locator, format!("pkg:npm/p{i}@1.0.0"));
            assert_eq!(rec.outcome, Outcome::Ok);
        }
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
        // mtime (which now tracks last access for the eviction sweep).
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
    struct Spooling(Fixtures);

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
            assert_eq!(fetched.pin_verified, Some(true));
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
            assert_eq!(hit.pin_verified, Some(true));
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

        let repo = Reference {
            kind: RefKind::Repository,
            ..dep(RefLocator::Purl("pkg:github/o/r".into()), None)
        };
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
    fn aur_purl_fetches_pkgbase_snapshot() {
        let rpc = "https://aur.archlinux.org/rpc/v5/info?arg%5B%5D=yay";
        // The RPC names the snapshot by *pkgbase* (here differing from the
        // package name, the split-package case a derived URL would get wrong).
        let rpc_body = br#"{"resultcount":1,"results":[{"Name":"yay","PackageBase":"yay-base","URLPath":"/cgit/aur.git/snapshot/yay-base.tar.gz"}]}"#;
        let snapshot = "https://aur.archlinux.org/cgit/aur.git/snapshot/yay-base.tar.gz";
        let net = Fixtures::default()
            .with(rpc, rpc_body)
            .with(snapshot, b"SNAPSHOT");

        // All three AUR spellings resolve to the same snapshot, including the
        // spec form carrying a version (snapshots track HEAD; the version
        // can't pin) and the non-spec `?qualifiers@version` ordering older
        // hopper exports emitted.
        for purl in [
            "pkg:aur/yay",
            "pkg:alpm/aur/yay",
            "pkg:alpm/arch/yay@12.0-1?repository_url=https://aur.archlinux.org",
            "pkg:alpm/arch/yay?repository_url=https://aur.archlinux.org@12.0-1",
        ] {
            let dir = tempfile::tempdir().expect("tempdir");
            let cache = BlobCache::with_dir(dir.path().to_path_buf());
            let rec = fetch_ref(&dep(RefLocator::Purl(purl.into()), None), &net, &cache);
            assert_eq!(rec.outcome, Outcome::Ok, "{purl}");
            assert_eq!(rec.resolved_url.as_deref(), Some(snapshot), "{purl}");
        }

        // RPC unreachable → the name-derived snapshot fallback still fetches.
        let derived = "https://aur.archlinux.org/cgit/aur.git/snapshot/yay.tar.gz";
        let net = Fixtures::default().with(derived, b"SNAPSHOT");
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = BlobCache::with_dir(dir.path().to_path_buf());
        let rec = fetch_ref(
            &dep(RefLocator::Purl("pkg:aur/yay".into()), None),
            &net,
            &cache,
        );
        assert_eq!(rec.outcome, Outcome::Ok);
        assert_eq!(rec.resolved_url.as_deref(), Some(derived));
    }

    #[test]
    fn a_url_locator_cannot_select_the_container_puller() {
        // `oci://` reaches the OCI puller, which runs outside this module's
        // SSRF-guarded client. It must only ever come from a `pkg:oci`
        // coordinate, never from a URL a scanned file supplied.
        for url in [
            "oci://docker.io/library/nginx:latest",
            "OCI://docker.io/library/nginx:latest",
            "file:///etc/passwd",
            "ftp://example.com/x.tgz",
        ] {
            assert_eq!(
                resolve(&RefLocator::Url(url.to_string())),
                None,
                "{url} must not resolve from a URL locator"
            );
        }
        // A `pkg:oci` coordinate still produces the pseudo-URL, and the web
        // schemes still resolve — `http` so it can be refused at connect with
        // the more specific reason.
        assert_eq!(
            resolve(&RefLocator::Purl("pkg:oci/nginx".to_string())),
            Some("oci://docker.io/library/nginx:latest".to_string())
        );
        for url in ["https://example.com/x.tgz", "HTTPS://example.com/x.tgz"] {
            assert_eq!(
                resolve(&RefLocator::Url(url.to_string())),
                Some(url.to_string())
            );
        }
    }

    #[test]
    fn crafted_coordinates_never_reach_a_url() {
        // Each of these restructures the endpoint it is interpolated into:
        // climbing out of the intended path, or truncating it into a query or
        // fragment. The URL's host is a literal so none can move it — but the
        // bytes would be filed under a coordinate they did not come from.
        for purl in [
            "pkg:npm/../../../evil@1.0.0",
            "pkg:cargo/serde@../../../evil",
            "pkg:golang/github.com/a/../../../../evil@v1.0.0",
            "pkg:maven/com.example/lib@1.0/../../../../evil",
            // A `#` before any `?` is not stripped as a qualifier, so it does
            // reach the interpolation and would truncate the path.
            "pkg:gem/rails#frag@1.0",
            "pkg:nuget/pkg@1.0\\..\\..\\evil",
            "pkg:github/owner/repo@a b",
        ] {
            assert_eq!(
                resolve(&RefLocator::Purl(purl.to_string())),
                None,
                "{purl} must not resolve to a URL"
            );
        }
        // The guard must not reject the punctuation real coordinates carry:
        // dots in a group id, slashes in a module path, a Debian epoch `:`,
        // a `+` build tag, and npm's percent-encoded scope marker.
        for purl in [
            "pkg:npm/%40babel/core@7.24.0",
            "pkg:golang/github.com/BurntSushi/toml@v1.4.0",
            "pkg:maven/com.google.guava/guava@32.1.3-jre",
            "pkg:cargo/serde@1.0.0",
            "pkg:github/owner/repo@v1.0.0+build.1",
        ] {
            assert!(
                resolve(&RefLocator::Purl(purl.to_string())).is_some(),
                "{purl} is a real coordinate and must still resolve"
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
            match net.send(&Request::get(url)) {
                Err(FetchError::Refused(_)) => {}
                other => panic!("{url} should be refused, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_resolver_refusal_says_why() {
        // `localhost` comes from the hosts file, so this stays offline. The
        // name passes the literal-IP guard and is refused by the resolver,
        // whose reason must survive reqwest's "error sending request" wrapper.
        let net = HttpFetch::new().expect("client");
        match net.send(&Request::get("https://localhost/x")) {
            Err(FetchError::Refused(why)) => {
                assert!(why.contains("non-public host: localhost"), "{why}");
            }
            other => panic!("localhost should be refused by the resolver, got {other:?}"),
        }
    }

    #[test]
    fn a_vscode_publisher_must_be_a_hostname_label() {
        let url = |purl: &str| {
            resolved_target(
                &RefLocator::Purl(purl.into()),
                &Fixtures::default(),
                &BlobCache::disabled(),
            )
            .ok()
            .map(|(_, url)| url)
        };
        assert!(
            url("pkg:vscode/ms-python/python@2024.1.0")
                .is_some_and(|u| u.starts_with("https://ms-python.gallery.vsassets.io/"))
        );
        // The publisher is a label of the gallery's hostname, so anything that
        // would add a label or isn't a publisher ID is refused, as is a
        // version that climbs out of the gallery path.
        for purl in [
            "pkg:vscode/evil.example/x@1.0.0",
            "pkg:vscode/a_b/x@1.0.0",
            "pkg:vscode/-pub/x@1.0.0",
            "pkg:vscode/pub/x@..%2F..%2Fx",
        ] {
            assert_eq!(url(purl), None, "{purl}");
        }
    }

    #[test]
    fn percent_encoded_path_structure_never_reaches_a_registry_url() {
        for purl in [
            "pkg:cargo/foo%2F..%2Fbar@1.0.0",
            "pkg:npm/foo%2Fbar@1.0.0",
            "pkg:gem/foo%2Fbar@1.0.0",
        ] {
            assert_eq!(resolve(&RefLocator::Purl(purl.into())), None, "{purl}");
        }
    }

    #[test]
    fn npm_matrix_never_invents_unknown_versions_or_ranges() {
        let body = br#"{"dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"dist":{"tarball":"https://x/pkg-1.0.0.tgz"}}}}"#;
        let net = Fixtures::default().with("https://registry.npmjs.org/pkg", body);
        for purl in [
            "pkg:npm/pkg@9.9.9",
            "pkg:npm/pkg@1.x",
            "pkg:npm/pkg@%3E%3D1",
        ] {
            let matrix =
                resolve_artifacts(&RefLocator::Purl(purl.into()), &net, &BlobCache::disabled())
                    .expect("npm matrix");
            assert!(matrix.candidates.is_empty(), "{purl}");
        }
    }

    #[test]
    fn npm_integrity_is_promoted_to_a_hex_checksum() {
        let body = br#"{"versions":{"1.0.0":{"dist":{"tarball":"https://x/pkg.tgz","integrity":"sha512-Zm9v"}}}}"#;
        let net = Fixtures::default().with("https://registry.npmjs.org/pkg", body);
        let matrix = resolve_artifacts(
            &RefLocator::Purl("pkg:npm/pkg@1.0.0".into()),
            &net,
            &BlobCache::disabled(),
        )
        .expect("npm matrix");
        assert_eq!(
            matrix.candidates[0]
                .checksums
                .get("sha512")
                .map(String::as_str),
            Some("666f6f")
        );
    }

    #[test]
    fn pypi_platform_wheels_do_not_beat_a_portable_sdist_without_a_target() {
        let api = "https://pypi.org/pypi/native/1.0/json";
        let body = br#"{"urls":[
            {"packagetype":"bdist_wheel","filename":"native-1.0-cp313-cp313-macosx_14_0_arm64.whl","url":"https://x/mac.whl"},
            {"packagetype":"bdist_wheel","filename":"native-1.0-cp313-cp313-manylinux_2_17_x86_64.whl","url":"https://x/linux.whl"},
            {"packagetype":"sdist","filename":"native-1.0.tar.gz","url":"https://x/native.tar.gz"}
        ]}"#;
        let net = Fixtures::default().with(api, body);
        let matrix = resolve_artifacts(
            &RefLocator::Purl("pkg:pypi/native@1.0".into()),
            &net,
            &BlobCache::disabled(),
        )
        .expect("pypi matrix");
        assert_eq!(
            matrix
                .preferred()
                .map(|candidate| candidate.file_name.as_str()),
            Some("native-1.0.tar.gz")
        );
    }

    #[test]
    fn pypi_yanked_universal_wheel_does_not_beat_a_healthy_sdist() {
        let api = "https://pypi.org/pypi/yanked/1.0/json";
        let body = br#"{"urls":[
            {"packagetype":"bdist_wheel","filename":"yanked-1.0-py3-none-any.whl","url":"https://x/yanked.whl","yanked":true},
            {"packagetype":"sdist","filename":"yanked-1.0.tar.gz","url":"https://x/healthy.tar.gz"}
        ]}"#;
        let net = Fixtures::default().with(api, body);
        let matrix = resolve_artifacts(
            &RefLocator::Purl("pkg:pypi/yanked@1.0".into()),
            &net,
            &BlobCache::disabled(),
        )
        .expect("pypi matrix");
        assert_eq!(
            matrix.preferred().map(|candidate| candidate.url.as_str()),
            Some("https://x/healthy.tar.gz")
        );
    }

    #[test]
    fn gem_without_a_ruby_build_has_no_targetless_preference() {
        let body = br#"[{"number":"1.0","platform":"x86_64-linux"},{"number":"1.0","platform":"arm64-darwin"}]"#;
        let net =
            Fixtures::default().with("https://rubygems.org/api/v1/versions/native.json", body);
        let matrix = resolve_artifacts(
            &RefLocator::Purl("pkg:gem/native@1.0".into()),
            &net,
            &BlobCache::disabled(),
        )
        .expect("gem matrix");
        assert!(matrix.preferred().is_none());
    }

    #[test]
    fn selector_uses_explicit_python_target_tags() {
        let api = "https://pypi.org/pypi/native/1.0/json";
        let body = br#"{"urls":[
            {"packagetype":"bdist_wheel","filename":"native-1.0-cp313-cp313-macosx_14_0_arm64.whl","url":"https://x/mac.whl"},
            {"packagetype":"bdist_wheel","filename":"native-1.0-cp313-cp313-manylinux_2_17_x86_64.whl","url":"https://x/linux.whl"},
            {"packagetype":"sdist","filename":"native-1.0.tar.gz","url":"https://x/native.tar.gz"}
        ]}"#;
        let net = Fixtures::default().with(api, body);
        let matrix = resolve_artifacts(
            &RefLocator::Purl("pkg:pypi/native@1.0".into()),
            &net,
            &BlobCache::disabled(),
        )
        .expect("pypi matrix");
        let target = ArtifactTarget {
            python_tags: vec!["cp313".into()],
            abi_tags: vec!["cp313".into()],
            python_platform_tags: vec!["manylinux_2_17_x86_64".into()],
            ..ArtifactTarget::default()
        };
        assert_eq!(
            matrix
                .select(&target, &SelectionPolicy::default())
                .map(|candidate| candidate.url.as_str()),
            Some("https://x/linux.whl")
        );
    }

    #[test]
    fn selector_does_not_treat_a_py2_wheel_as_runtime_agnostic() {
        let api = "https://pypi.org/pypi/legacy/1.0/json";
        let body = br#"{"urls":[
            {"packagetype":"bdist_wheel","filename":"legacy-1.0-py2-none-any.whl","url":"https://x/py2.whl"},
            {"packagetype":"sdist","filename":"legacy-1.0.tar.gz","url":"https://x/legacy.tar.gz"}
        ]}"#;
        let net = Fixtures::default().with(api, body);
        let matrix = resolve_artifacts(
            &RefLocator::Purl("pkg:pypi/legacy@1.0".into()),
            &net,
            &BlobCache::disabled(),
        )
        .expect("pypi matrix");
        let target = ArtifactTarget {
            python_tags: vec!["cp313".into(), "py3".into()],
            abi_tags: vec!["cp313".into(), "abi3".into(), "none".into()],
            python_platform_tags: vec!["any".into()],
            ..ArtifactTarget::default()
        };
        assert_eq!(
            matrix
                .select(&target, &SelectionPolicy::default())
                .map(|candidate| candidate.url.as_str()),
            Some("https://x/legacy.tar.gz")
        );
    }

    #[test]
    fn selector_enforces_python_and_node_runtime_versions() {
        let pypi = br#"{"urls":[
            {"packagetype":"bdist_wheel","filename":"runtime-1.0-py3-none-any.whl","url":"https://x/runtime.whl","requires_python":">=3.10"},
            {"packagetype":"sdist","filename":"runtime-1.0.tar.gz","url":"https://x/runtime.tar.gz"}
        ]}"#;
        let npm = br#"{"versions":{"1.0.0":{"engines":{"node":">=20"},"dist":{"tarball":"https://x/runtime.tgz"}}}}"#;
        let net = Fixtures::default()
            .with("https://pypi.org/pypi/runtime/1.0/json", pypi)
            .with("https://registry.npmjs.org/runtime", npm);
        let cache = BlobCache::disabled();
        let python = resolve_artifacts(
            &RefLocator::Purl("pkg:pypi/runtime@1.0".into()),
            &net,
            &cache,
        )
        .expect("pypi matrix");
        let py39 = ArtifactTarget {
            python_version: Some("3.9".into()),
            ..ArtifactTarget::default()
        };
        assert_eq!(
            python
                .select(&py39, &SelectionPolicy::default())
                .map(|candidate| candidate.url.as_str()),
            Some("https://x/runtime.tar.gz")
        );

        let node = resolve_artifacts(
            &RefLocator::Purl("pkg:npm/runtime@1.0.0".into()),
            &net,
            &cache,
        )
        .expect("npm matrix");
        let node18 = ArtifactTarget {
            node_version: Some("18.20.0".into()),
            ..ArtifactTarget::default()
        };
        assert!(node.select(&node18, &SelectionPolicy::default()).is_none());
        let node20 = ArtifactTarget {
            node_version: Some("20.0.0".into()),
            ..ArtifactTarget::default()
        };
        assert!(node.select(&node20, &SelectionPolicy::default()).is_some());
    }

    #[test]
    fn allow_yanked_is_fallback_only() {
        let api = "https://pypi.org/pypi/fallback/1.0/json";
        let body = br#"{"urls":[
            {"packagetype":"bdist_wheel","filename":"fallback-1.0-py3-none-any.whl","url":"https://x/yanked.whl","yanked":true},
            {"packagetype":"sdist","filename":"fallback-1.0.tar.gz","url":"https://x/healthy.tar.gz"}
        ]}"#;
        let net = Fixtures::default().with(api, body);
        let matrix = resolve_artifacts(
            &RefLocator::Purl("pkg:pypi/fallback@1.0".into()),
            &net,
            &BlobCache::disabled(),
        )
        .expect("pypi matrix");
        assert_eq!(
            matrix
                .select(
                    &ArtifactTarget::default(),
                    &SelectionPolicy {
                        allow_yanked: true,
                        prefer_source: false,
                    },
                )
                .map(|candidate| candidate.url.as_str()),
            Some("https://x/healthy.tar.gz")
        );
    }

    #[test]
    fn declared_checksum_conflict_makes_candidate_unselectable() {
        let body = br#"{"urls":[{"packagetype":"sdist","filename":"demo-1.0.tar.gz","url":"https://x/demo.tar.gz","digests":{"sha256":"aaaaaaaa"}}]}"#;
        let net = Fixtures::default().with("https://pypi.org/pypi/demo/1.0/json", body);
        let matrix = resolve_artifacts(
            &RefLocator::Purl("pkg:pypi/demo@1.0?checksum=sha256:bbbbbbbb".into()),
            &net,
            &BlobCache::disabled(),
        )
        .expect("pypi matrix");
        assert!(matrix.preferred().is_none());
        assert!(
            matrix
                .select(&ArtifactTarget::default(), &SelectionPolicy::default())
                .is_none()
        );
    }

    #[test]
    fn unsupported_declared_checksum_is_not_reported_as_ok() {
        let url = "https://static.crates.io/crates/foo/foo-1.0.0.crate";
        let net = Fixtures::default().with(url, b"REAL");
        let reference = dep(
            RefLocator::Purl("pkg:cargo/foo@1.0.0?checksum=md5:0123456789abcdef".into()),
            None,
        );
        let record = fetch_ref(&reference, &net, &BlobCache::disabled());
        assert_eq!(record.outcome, Outcome::UnverifiablePin);
        assert_eq!(record.pin_verified, None);
    }

    /// PyPI publishes `blake2b_256` and `md5` alongside the `sha256` we can
    /// check, so a digest we cannot compute must not erase one we confirmed.
    #[test]
    fn a_supported_checksum_verifies_beside_an_unsupported_one() {
        let url = "https://static.crates.io/crates/foo/foo-1.0.0.crate";
        let bytes = b"REAL";
        let net = Fixtures::default().with(url, bytes);
        let reference = dep(
            RefLocator::Purl(format!(
                "pkg:cargo/foo@1.0.0?checksum=blake2b-256:abcd,sha256:{}",
                sha256_hex(bytes)
            )),
            None,
        );
        let record = fetch_ref(&reference, &net, &BlobCache::disabled());
        assert_eq!(record.outcome, Outcome::Ok);
        assert_eq!(record.pin_verified, Some(true));
    }

    /// A yarn v1 lockfile pins every entry with a legacy `sha1-` integrity.
    #[test]
    fn a_legacy_sha1_integrity_pin_verifies() {
        use base64::Engine as _;
        let url = "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz";
        let bytes = b"tarball bytes";
        let net = Fixtures::default().with(url, bytes);
        let reference = dep(
            RefLocator::Url(url.into()),
            Some(PinnedHash {
                algo: HashAlgo::Sha1,
                value: base64::engine::general_purpose::STANDARD.encode(Sha1::digest(bytes)),
            }),
        );
        let record = fetch_ref(&reference, &net, &BlobCache::disabled());
        assert_eq!(record.outcome, Outcome::Ok);
        assert_eq!(record.pin_verified, Some(true));
    }

    /// A yarn `resolved` fragment spells the same digest in hex.
    #[test]
    fn a_hex_spelled_sha1_pin_verifies() {
        let url = "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz";
        let bytes = b"tarball bytes";
        let net = Fixtures::default().with(url, bytes);
        let reference = dep(
            RefLocator::Url(url.into()),
            Some(PinnedHash {
                algo: HashAlgo::Sha1,
                value: hex::encode(Sha1::digest(bytes)).to_ascii_uppercase(),
            }),
        );
        let record = fetch_ref(&reference, &net, &BlobCache::disabled());
        assert_eq!(record.outcome, Outcome::Ok);
        assert_eq!(record.pin_verified, Some(true));
    }

    #[test]
    fn a_mismatched_sha1_integrity_pin_is_a_finding() {
        let url = "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz";
        let net = Fixtures::default().with(url, b"tarball bytes");
        let reference = dep(
            RefLocator::Url(url.into()),
            Some(PinnedHash {
                algo: HashAlgo::Sha1,
                value: hex::encode(Sha1::digest(b"other bytes")),
            }),
        );
        let record = fetch_ref(&reference, &net, &BlobCache::disabled());
        assert_eq!(record.outcome, Outcome::PinMismatch);
        assert_eq!(record.pin_verified, Some(false));
    }

    /// The direction that matters: an algorithm we cannot compute must not
    /// rescue a supported digest that *disagrees* with the bytes.
    #[test]
    fn a_mismatched_supported_checksum_beats_an_unsupported_one() {
        let url = "https://static.crates.io/crates/foo/foo-1.0.0.crate";
        let net = Fixtures::default().with(url, b"REAL");
        let reference = dep(
            RefLocator::Purl(format!(
                "pkg:cargo/foo@1.0.0?checksum=blake2b-256:abcd,sha256:{}",
                sha256_hex(b"SUBSTITUTED")
            )),
            None,
        );
        let record = fetch_ref(&reference, &net, &BlobCache::disabled());
        assert_eq!(record.outcome, Outcome::PinMismatch);
        assert_eq!(record.pin_verified, Some(false));
    }

    #[test]
    fn a_purl_declared_sha1_checksum_is_verified() {
        let url = "https://static.crates.io/crates/foo/foo-1.0.0.crate";
        let bytes = b"REAL";
        let net = Fixtures::default().with(url, bytes);
        let reference = dep(
            RefLocator::Purl(format!(
                "pkg:cargo/foo@1.0.0?checksum=sha1:{}",
                hex::encode(Sha1::digest(bytes))
            )),
            None,
        );
        let record = fetch_ref(&reference, &net, &BlobCache::disabled());
        assert_eq!(record.outcome, Outcome::Ok);
        assert_eq!(record.pin_verified, Some(true));
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
        for (body, outcome, verified) in [
            ("package m\n", Outcome::Ok, true),
            ("package changed\n", Outcome::PinMismatch, false),
        ] {
            let bytes = go_hash::tests::archive(
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
            assert_eq!(record.pin_verified, Some(verified));
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
        assert_eq!(record.pin_verified, None);
    }

    /// The same rule the digest list follows, one level up: a manifest pin in
    /// an algorithm we cannot compute must not erase a `checksum` qualifier
    /// that did confirm the bytes.
    #[test]
    fn an_uncomputable_manifest_pin_does_not_erase_a_verified_checksum() {
        let artifact = "https://files.pythonhosted.org/demo-1.0.tar.gz";
        let bytes = b"artifact bytes";
        let body = format!(
            r#"{{"urls":[{{"packagetype":"sdist","filename":"demo-1.0.tar.gz","url":"{artifact}","digests":{{"sha256":"{}"}}}}]}}"#,
            sha256_hex(bytes)
        );
        let net = Fixtures::default()
            .with("https://pypi.org/pypi/demo/1.0/json", body.as_bytes())
            .with(artifact, bytes);
        let record = fetch_ref(
            &dep(
                RefLocator::Purl("pkg:pypi/demo@1.0".into()),
                Some(PinnedHash {
                    algo: HashAlgo::GoModH1,
                    value: "NIvaJDMOsjHA8n1jAhLSgzrAzy1Hgr+hNrb57e+94F0=".into(),
                }),
            ),
            &net,
            &BlobCache::disabled(),
        );
        assert_eq!(record.outcome, Outcome::Ok);
        assert_eq!(record.pin_verified, Some(true));
    }

    #[test]
    fn registry_candidate_refines_locator_and_verifies_its_checksum() {
        let artifact = "https://files.pythonhosted.org/demo-1.0.tar.gz";
        let bytes = b"artifact bytes";
        let digest = sha256_hex(bytes);
        let body = format!(
            r#"{{"urls":[{{"packagetype":"sdist","filename":"demo-1.0.tar.gz","url":"{artifact}","digests":{{"sha256":"{digest}"}}}}]}}"#
        );
        let net = Fixtures::default()
            .with("https://pypi.org/pypi/demo/1.0/json", body.as_bytes())
            .with(artifact, bytes);
        let record = fetch_ref(
            &dep(RefLocator::Purl("pkg:pypi/demo@1.0".into()), None),
            &net,
            &BlobCache::disabled(),
        );
        assert_eq!(record.outcome, Outcome::Ok);
        assert_eq!(record.pin_verified, Some(true));
        assert!(record.locator.contains("checksum=sha256:"));
        assert!(record.locator.contains("file_name=demo-1.0.tar.gz"));
    }

    #[test]
    fn cargo_checksum_template_uses_the_sparse_index_record() {
        let repository = "https://cargo.example.test/index";
        let config = br#"{"dl":"https://cargo.example.test/files/{crate}/{version}/{sha256-checksum}.crate"}"#;
        let index = br#"{"name":"serde","vers":"1.0.0","cksum":"abc123"}"#;
        let net = Fixtures::default()
            .with(&format!("{repository}/config.json"), config)
            .with(&format!("{repository}/se/rd/serde"), index);
        let matrix = resolve_artifacts(
            &RefLocator::Purl(
                "pkg:cargo/serde@1.0.0?repository_url=https:%2F%2Fcargo.example.test%2Findex"
                    .into(),
            ),
            &net,
            &BlobCache::disabled(),
        )
        .expect("cargo matrix");
        let candidate = matrix.preferred().expect("cargo artifact");
        assert_eq!(
            candidate.url,
            "https://cargo.example.test/files/serde/1.0.0/abc123.crate"
        );
        assert_eq!(
            candidate.checksums.get("sha256").map(String::as_str),
            Some("abc123")
        );
    }

    #[test]
    fn every_purl_candidate_carries_release_and_artifact_identity() {
        let body = br#"{"urls":[{"packagetype":"sdist","filename":"demo-1.0.tar.gz","url":"https://x/demo.tar.gz"}]}"#;
        let net = Fixtures::default().with("https://pypi.org/pypi/demo/1.0/json", body);
        let matrix = resolve_artifacts(
            &RefLocator::Purl("pkg:pypi/demo@1.0".into()),
            &net,
            &BlobCache::disabled(),
        )
        .expect("matrix");
        let candidate = &matrix.candidates[0];
        assert_eq!(candidate.release_purl.as_deref(), Some("pkg:pypi/demo@1.0"));
        assert_eq!(
            candidate.artifact_purl.as_deref(),
            Some("pkg:pypi/demo@1.0?file_name=demo-1.0.tar.gz")
        );
    }

    #[test]
    fn registry_with_sources_returns_record_and_raw_documents() {
        let packument = serde_json::json!({
            "dist-tags": {"latest": "1.3.0"},
            "versions": {"1.3.0": {"license": "MIT"}},
            "time": {"1.3.0": "2021-04-23T10:00:00.000Z"},
            "maintainers": [{"name": "una"}],
        })
        .to_string();
        let net = Fixtures::default().with_headers(
            "https://registry.npmjs.org/left-pad",
            packument.as_bytes(),
            &[("Content-Type", "application/json")],
        );
        // Disabled cache: every read is a fresh fetch through the recorder.
        let (record, sources) = registry_with_sources(
            &RefLocator::Purl("pkg:npm/left-pad@1.3.0".into()),
            &net,
            &BlobCache::disabled(),
        );

        let record = record.expect("record");
        assert_eq!(record.ecosystem, "npm");
        assert_eq!(record.name, "left-pad");

        // The raw packument is captured verbatim, with its transport facts — the
        // downloads endpoint isn't in the fixtures, so it fails and isn't recorded.
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].url, "https://registry.npmjs.org/left-pad");
        assert_eq!(sources[0].status, 200);
        assert_eq!(sources[0].content_type.as_deref(), Some("application/json"));
        let bytes = sources[0].bytes.as_deref().expect("kept: no source limit");
        assert_eq!(sources[0].size, bytes.len() as u64);
        let body: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        assert_eq!(body["dist-tags"]["latest"], "1.3.0");

        // Past the cache's source limit the document is still named, with
        // its size, but its bytes are not copied.
        let (_, sources) = registry_with_sources(
            &RefLocator::Purl("pkg:npm/left-pad@1.3.0".into()),
            &net,
            &BlobCache::disabled().with_source_limit(16),
        );
        assert_eq!(sources[0].url, "https://registry.npmjs.org/left-pad");
        assert_eq!(sources[0].size, bytes.len() as u64);
        assert_eq!(sources[0].bytes, None);
    }
}
