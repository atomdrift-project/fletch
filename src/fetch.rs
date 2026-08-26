//! Resolve external references to URLs, retrieve them safely, cache them, and
//! record rich provenance.
//!
//! [`HttpFetch`] is the real backend; its SSRF guard lives in a custom DNS
//! resolver (`SafeResolver`) that refuses any host resolving to a private /
//! loopback / link-local / metadata address, re-checked on every redirect hop.
//! [`Fixtures`] is the offline backend for tests. No recognition logic lives
//! here — references come in, bytes and [`FetchRecord`]s go out.

use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use filefacts::{HashAlgo, PinnedHash, RefKind, RefLocator, Reference};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

/// One concrete archive published for a package coordinate.
///
/// `qualifiers` contains the PURL selectors that identify this exact artifact
/// (for example PyPI's `file_name` or RubyGems' `platform`). `attributes`
/// contains ecosystem metadata that describes compatibility but is not itself
/// a registered PURL qualifier (`python`, `abi`, npm `cpu`, and similar).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactCandidate {
    /// Canonical release-level PURL shared by sibling artifacts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_purl: Option<String>,
    /// Canonical PURL including selectors for this exact published artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_purl: Option<String>,
    /// Direct URL for this archive.
    pub url: String,
    /// Archive basename as published by the registry.
    pub file_name: String,
    /// Exact PURL qualifier values that select this candidate.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub qualifiers: BTreeMap<String, String>,
    /// Ecosystem-specific file type and compatibility tags.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, String>,
    /// Registry-provided or PURL-declared content digests, keyed by the
    /// standard lowercase algorithm name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub checksums: BTreeMap<String, String>,
    /// Whether the legacy single-URL API would choose this candidate.
    #[serde(default, skip_serializing_if = "is_false")]
    pub preferred: bool,
}

/// All concrete archives a registry publishes for one PURL release.
///
/// This additive API preserves [`resolve`]'s single-URL contract while letting
/// scanners enumerate platform, ABI, and file-format variants. Exactly one
/// candidate is normally marked [`ArtifactCandidate::preferred`]; no candidate
/// is preferred when an explicit selector names an artifact the registry did
/// not return.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactMatrix {
    /// The requested locator, retained for correlation with the caller's input.
    pub locator: String,
    /// Concrete artifact variants in deterministic preference order.
    pub candidates: Vec<ArtifactCandidate>,
}

impl ArtifactMatrix {
    /// The candidate selected by the backward-compatible single-URL policy.
    #[must_use]
    pub fn preferred(&self) -> Option<&ArtifactCandidate> {
        self.candidates.iter().find(|candidate| candidate.preferred)
    }

    /// Select one compatible artifact for an explicit target and policy.
    /// Enumeration itself remains target-neutral.
    #[must_use]
    pub fn select(
        &self,
        target: &ArtifactTarget,
        policy: &SelectionPolicy,
    ) -> Option<&ArtifactCandidate> {
        let exact = crate::purl::Purl::parse(&self.locator)
            .ok()
            .is_some_and(|purl| {
                purl.qualifiers().keys().any(|key| {
                    matches!(
                        key.as_str(),
                        "file_name" | "platform" | "download_url" | "kind"
                    )
                })
            });
        self.candidates
            .iter()
            .filter(|candidate| !exact || candidate.preferred)
            .filter_map(|candidate| {
                candidate_score(candidate, target, policy).map(|score| (score, candidate))
            })
            .min_by(|(left_score, left), (right_score, right)| {
                left_score
                    .cmp(right_score)
                    .then_with(|| left.file_name.cmp(&right.file_name))
            })
            .map(|(_, candidate)| candidate)
    }
}

/// Compatibility information supplied by a caller selecting an artifact.
///
/// Python and Ruby publish ecosystem-specific compatibility tags, so callers
/// pass the tags their runtime accepts rather than Fletch guessing from a host
/// triple. Empty tag lists mean “portable artifacts only.”
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactTarget {
    /// Operating system (`linux`, `darwin`, `win32`, ...).
    pub os: Option<String>,
    /// CPU architecture (`x64`, `arm64`, `x86_64`, ...).
    pub arch: Option<String>,
    /// C library where relevant (`glibc`, `musl`).
    pub libc: Option<String>,
    /// Accepted Python interpreter tags, best first (`cp313`, `py3`, ...).
    #[serde(default)]
    pub python_tags: Vec<String>,
    /// Accepted Python ABI tags (`cp313`, `abi3`, `none`, ...).
    #[serde(default)]
    pub abi_tags: Vec<String>,
    /// Accepted Python platform tags (`manylinux_2_17_x86_64`, ...).
    #[serde(default)]
    pub python_platform_tags: Vec<String>,
    /// Concrete Python runtime version used for `Requires-Python` checks.
    pub python_version: Option<String>,
    /// Concrete Node.js runtime version used for npm `engines.node` checks.
    pub node_version: Option<String>,
    /// Accepted RubyGems platform strings (`x86_64-linux`, ...).
    #[serde(default)]
    pub gem_platforms: Vec<String>,
}

/// Policy choices kept separate from registry enumeration and host identity.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectionPolicy {
    /// Permit a yanked/withdrawn artifact when no healthy candidate exists.
    pub allow_yanked: bool,
    /// Prefer source distributions over compatible binaries.
    pub prefer_source: bool,
}

fn candidate_score(
    candidate: &ArtifactCandidate,
    target: &ArtifactTarget,
    policy: &SelectionPolicy,
) -> Option<u16> {
    if candidate.attributes.contains_key("checksum_mismatch") {
        return None;
    }
    if !policy.allow_yanked && candidate.attributes.contains_key("yanked") {
        return None;
    }
    if let Some(constraint) = candidate.attributes.get("requires_python")
        && let Some(version) = target.python_version.as_deref()
    {
        let specifiers = constraint.parse::<pep440_rs::VersionSpecifiers>().ok()?;
        let version = version.parse::<pep440_rs::Version>().ok()?;
        if !specifiers.contains(&version) {
            return None;
        }
    }
    if let Some(constraint) = candidate.attributes.get("node")
        && let Some(version) = target.node_version.as_deref()
    {
        let range = node_semver::Range::parse(constraint).ok()?;
        let version = node_semver::Version::parse(version).ok()?;
        if !range.satisfies(&version) {
            return None;
        }
    }
    for (attribute, requested) in [
        ("os", target.os.as_deref()),
        ("cpu", target.arch.as_deref()),
        ("libc", target.libc.as_deref()),
    ] {
        if let Some(constraint) = candidate.attributes.get(attribute)
            && !runtime_constraint_matches(constraint, requested)
        {
            return None;
        }
    }

    let kind = candidate.attributes.get("kind").map(String::as_str);
    let natural = match kind {
        Some("wheel") => {
            let python = candidate.attributes.get("python").map(String::as_str)?;
            let abi = candidate.attributes.get("abi").map(String::as_str)?;
            let platform = candidate.attributes.get("platform").map(String::as_str)?;
            if !compressed_tag_matches(python, &target.python_tags, python.starts_with("py"))
                || !compressed_tag_matches(abi, &target.abi_tags, abi == "none")
                || !compressed_tag_matches(
                    platform,
                    &target.python_platform_tags,
                    platform == "any",
                )
            {
                return None;
            }
            if policy.prefer_source { 4 } else { 0 }
        }
        Some("sdist") => {
            if policy.prefer_source {
                0
            } else {
                1
            }
        }
        Some("gem") => {
            let platform = candidate
                .qualifiers
                .get("platform")
                .map_or("ruby", String::as_str);
            if platform != "ruby" && !target.gem_platforms.iter().any(|tag| tag == platform) {
                return None;
            }
            u16::from(platform != "ruby")
        }
        _ => 0,
    };
    Some(natural + 100 * u16::from(candidate.attributes.contains_key("yanked")))
}

fn compressed_tag_matches(actual: &str, accepted: &[String], targetless_compatible: bool) -> bool {
    if accepted.is_empty() {
        return targetless_compatible;
    }
    actual
        .split('.')
        .any(|tag| accepted.iter().any(|accepted| accepted == tag))
}

fn runtime_constraint_matches(constraint: &str, requested: Option<&str>) -> bool {
    let Some(requested) = requested else {
        return constraint
            .split(',')
            .map(str::trim)
            .all(|value| value.starts_with('!'));
    };
    if constraint.split(',').map(str::trim).any(|value| {
        value
            .strip_prefix('!')
            .is_some_and(|denied| runtime_value_matches(denied, requested))
    }) {
        return false;
    }
    let mut allowed = constraint
        .split(',')
        .map(str::trim)
        .filter(|value| !value.starts_with('!'));
    allowed.clone().next().is_none() || allowed.any(|value| runtime_value_matches(value, requested))
}

fn runtime_value_matches(candidate: &str, requested: &str) -> bool {
    candidate == requested
        || matches!(
            (candidate, requested),
            ("x86_64" | "amd64" | "x64", "x86_64" | "amd64" | "x64")
                | ("aarch64" | "arm64", "aarch64" | "arm64")
                | ("windows" | "win32", "windows" | "win32")
        )
}

/// Cache lifetime for a pinned reference — immutable, so a stale hit is
/// still correct (and re-verified).
const TTL_PINNED: Duration = Duration::from_secs(7 * 24 * 3600);
/// Cache lifetime for an unpinned reference — `@latest`/mutable tags can
/// move, so staleness is bounded.
const TTL_UNPINNED: Duration = Duration::from_secs(12 * 3600);

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
///   self-heal from a bad parse.
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
/// The two mutable tiers are overridable per process via [`set_registry_ttl`];
/// the immutable tier is never re-checked.
pub(crate) const META_TTL_IMMUTABLE: Duration = Duration::MAX;
const META_TTL_PINNED_DEFAULT: Duration = Duration::from_secs(90 * 86_400);
const META_TTL_UNPINNED_DEFAULT: Duration = Duration::from_secs(3600);

/// Process-wide override for the two mutable metadata TTLs, in seconds. `0` means
/// "unset" — the tiered defaults ([`META_TTL_PINNED_DEFAULT`]/
/// [`META_TTL_UNPINNED_DEFAULT`]) apply. Any other value collapses both mutable
/// tiers to that lifetime, so a large value effectively caches indefinitely
/// (offline/air-gapped) and a small one revalidates aggressively.
static REGISTRY_TTL_OVERRIDE_SECS: AtomicU64 = AtomicU64::new(0);

/// Override both mutable registry-metadata TTLs for the process. `None` clears
/// the override (the 4h-pinned / 1h-unpinned defaults resume). Call once at
/// startup, before any registry lookup. The immutable tier is unaffected — a
/// released version's file list is never re-fetched regardless.
pub fn set_registry_ttl(ttl: Option<Duration>) {
    let secs = ttl.map_or(0, |d| d.as_secs().max(1));
    REGISTRY_TTL_OVERRIDE_SECS.store(secs, Ordering::Relaxed);
}

/// Metadata TTL for a pinned (versioned) lookup's mutable packument.
#[must_use]
pub(crate) fn meta_ttl_pinned() -> Duration {
    match REGISTRY_TTL_OVERRIDE_SECS.load(Ordering::Relaxed) {
        0 => META_TTL_PINNED_DEFAULT,
        secs => Duration::from_secs(secs),
    }
}

/// Metadata TTL for an unpinned (`latest`/versionless) lookup.
#[must_use]
pub(crate) fn meta_ttl_unpinned() -> Duration {
    match REGISTRY_TTL_OVERRIDE_SECS.load(Ordering::Relaxed) {
        0 => META_TTL_UNPINNED_DEFAULT,
        secs => Duration::from_secs(secs),
    }
}
/// Default per-fetch byte ceiling — a single response is abandoned past this
/// unless [`set_max_fetch_bytes`] adjusts it for the process.
pub const DEFAULT_MAX_FETCH_BYTES: u64 = 256 * 1024 * 1024;

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

    /// Whether an `oci://` target may be pulled. The OCI distribution protocol
    /// (token + manifest + blob rounds) runs on the puller's own HTTP stack,
    /// not through this backend — so a backend that exists to refuse or replay
    /// traffic (the `purl` probe, test fixtures) must not have containers
    /// pulled behind its back. Default `false`: only the backend that owns
    /// real network policy ([`HttpFetch`]) opts in, and the puller's
    /// public-registry allowlist stands in for its SSRF guard.
    fn allows_oci(&self) -> bool {
        false
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
    /// A pin was declared, but Fletch cannot verify that algorithm over the
    /// downloaded bytes. Never silently treated as an unpinned success.
    UnverifiablePin,
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
            kind: RefKind::Undefined,
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

/// `serde(default)` for [`FetchRecord::kind`] on records predating the field.
fn undefined_kind() -> RefKind {
    RefKind::Undefined
}

/// `skip_serializing_if` helper: an unclassified kind carries no information.
#[allow(clippy::trivially_copy_pass_by_ref)] // signature dictated by serde
fn kind_is_undefined(k: &RefKind) -> bool {
    *k == RefKind::Undefined
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

/// One raw provider document a registry lookup read, captured by a recording
/// [`BlobCache`] — the verbatim bytes plus the transport facts (`status`,
/// `content_type`) observed when they were first fetched. The re-parsing backup a
/// consumer archives alongside the normalized record.
#[derive(Debug, Clone)]
pub struct RecordedSource {
    /// The URL the document was fetched from.
    pub url: String,
    /// HTTP status observed at fetch time (carried through the cache sidecar).
    pub status: u16,
    /// `Content-Type` header at fetch time, when present.
    pub content_type: Option<String>,
    /// The document bytes, verbatim.
    pub bytes: Vec<u8>,
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
    /// ([`cached_metadata`], [`cached_metadata_with`], [`cached_post`]).
    /// [`registry`](crate::registry::registry) overrides it per PURL via
    /// [`with_meta_ttl`](Self::with_meta_ttl); artifact fetches ignore it.
    meta_ttl: Duration,
    /// When set, every metadata document this cache serves — from a hit or a
    /// fresh fetch — is appended to the sink as `(url, bytes)`, so a caller can
    /// recover the raw provider documents a registry lookup consumed without
    /// re-deriving fletch's per-ecosystem fetch recipe. `None` = no recording.
    recorder: Option<RawSink>,
}

/// The blob cache root (`…/fletch/refs`), or `None` when no OS cache directory
/// can be determined. This is the directory [`crate::cache_sweep`] reclaims.
#[must_use]
pub fn refs_dir() -> Option<PathBuf> {
    Some(dirs::cache_dir()?.join("fletch").join("refs"))
}

impl BlobCache {
    /// Open the cache under the OS cache directory (`…/fletch/refs`).
    pub fn open() -> anyhow::Result<Self> {
        let dir = refs_dir().ok_or_else(|| anyhow::anyhow!("no OS cache directory"))?;
        Ok(Self::with_dir(dir))
    }

    /// Open a cache rooted at an explicit directory (created on first write).
    #[must_use]
    pub fn with_dir(dir: PathBuf) -> Self {
        Self {
            dir,
            enabled: true,
            meta_ttl: TTL_PINNED,
            recorder: None,
        }
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

    /// Append a served metadata document to the recorder, if one is installed.
    fn record(&self, url: &str, status: u16, content_type: Option<&str>, bytes: &[u8]) {
        if let Some(sink) = &self.recorder
            && let Ok(mut sources) = sink.lock()
        {
            sources.push(RecordedSource {
                url: url.to_string(),
                status,
                content_type: content_type.map(str::to_string),
                bytes: bytes.to_vec(),
            });
        }
    }

    /// A clone whose registry-*metadata* reads tolerate up to `ttl` of staleness
    /// — [`Duration::MAX`] caches indefinitely. Only [`cached_metadata`],
    /// [`cached_metadata_with`], and [`cached_post`] consult it; artifact fetches
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
        }
    }

    fn blob_path(&self, key: &str) -> PathBuf {
        self.dir.join(format!("{key}.zst"))
    }

    fn meta_path(&self, key: &str) -> PathBuf {
        self.dir.join(format!("{key}.json"))
    }

    /// Read a cache entry and its age, regardless of freshness. Both the blob
    /// and its `.json` sidecar must be present and valid; a missing or
    /// unreadable sidecar is a cache miss rather than fabricated default
    /// provenance (a blob can outlive its sidecar — e.g. a partial write, or the
    /// cache sweep evicting one of the pair — and serving `status: 0`,
    /// `final_url: ""` provenance would silently falsify a `FetchRecord`).
    ///
    /// Freshness (`age`) is measured from the recorded `fetched_at`, not the file
    /// mtime. That leaves the mtime free to record *last access* — bumped on each
    /// hit by [`mark_accessed`] — so the eviction sweep retains an entry that is
    /// still in use rather than one merely fetched recently.
    fn read(&self, key: &str) -> Option<(Vec<u8>, CachedMeta, Duration)> {
        if !self.enabled {
            return None;
        }
        let blob = self.blob_path(key);
        let blob_mtime = std::fs::metadata(&blob).ok()?.modified().ok()?;
        let bytes = read_blob_capped(&blob, max_fetch_bytes())?;
        let meta: CachedMeta =
            serde_json::from_slice(&std::fs::read(self.meta_path(key)).ok()?).ok()?;
        let age = Duration::from_secs(now().saturating_sub(meta.fetched_at));
        self.mark_accessed(key, blob_mtime);
        Some((bytes, meta, age))
    }

    /// Record that this entry was just used, so the eviction sweep (which ages by
    /// mtime) keeps it while it is in use. Rewrites the mtime of both the blob and
    /// its sidecar to now, but only when the current mtime is already a day stale,
    /// to avoid a metadata write on every cache hit. Best-effort; a failure just
    /// means the entry ages from its previous access instead.
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
            write_replacing(&self.blob_path(key), &compressed);
        }
        if let Ok(json) = serde_json::to_vec(meta) {
            write_replacing(&self.meta_path(key), &json);
        }
    }
}

/// Decompress a cache blob, refusing one that expands past `limit`.
///
/// Bounded even though we wrote the file ourselves: the cache lives in an OS
/// cache directory, so anything that can write there can swap an entry for a
/// zstd bomb. Every other decompressor in this crate is capped, and leaving
/// this one open is only safe for as long as that assumption holds. Reads one
/// byte past the ceiling so an oversized entry is rejected outright — serving a
/// truncated prefix would hash to something that was never fetched.
///
/// `None` on any failure, which the caller already treats as a cache miss.
fn read_blob_capped(path: &std::path::Path, limit: u64) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    zstd::stream::read::Decoder::new(std::fs::File::open(path).ok()?)
        .ok()?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() as u64 <= limit).then_some(bytes)
}

/// Write `bytes` to `path` through a fresh temporary file and rename it into
/// place. Best-effort, like the rest of the cache.
///
/// Two properties a plain `fs::write` does not have. The rename is atomic, so
/// a concurrent reader sees either the whole old entry or the whole new one,
/// never a torn prefix that would decompress to the wrong bytes. And both
/// steps replace a *name* rather than writing through one: `create_new` fails
/// on an existing path instead of following it, and `rename` unlinks whatever
/// the destination was. So an entry someone pre-created as a symlink — a live
/// risk wherever `XDG_CACHE_HOME` is shared, as on a CI runner — is destroyed
/// rather than followed into an arbitrary file.
fn write_replacing(path: &std::path::Path, bytes: &[u8]) {
    use std::io::Write as _;

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
        .and_then(|mut f| f.write_all(bytes));
    if written.is_ok() && std::fs::rename(&tmp, path).is_ok() {
        return;
    }
    let _ = std::fs::remove_file(&tmp);
}

/// The `Content-Type` header value (case-insensitive), if any.
fn content_type_of(headers: &[(String, String)]) -> Option<&str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.as_str())
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
    cached_document(&key, url, cache, || net.get_with(url, headers))
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
    cached_document(&key, url, cache, || net.post(url, body, headers))
}

/// The metadata cache flow every registry read shares: serve a fresh entry,
/// else `send` the request and store what comes back, else fall back to any
/// cached copy however old — an unreachable source still beats no answer.
/// Whatever is served is handed to the cache's recorder, so a caller archiving
/// provenance sees the document exactly once per read.
fn cached_document(
    key: &str,
    url: &str,
    cache: &BlobCache,
    send: impl FnOnce() -> Result<Fetched, FetchError>,
) -> Option<Vec<u8>> {
    if let Some((bytes, meta)) = cache.fresh(key, cache.meta_ttl) {
        cache.record(url, meta.status, content_type_of(&meta.headers), &bytes);
        return Some(bytes);
    }
    let Ok(f) = send() else {
        let (bytes, meta) = cache.any(key)?;
        cache.record(url, meta.status, content_type_of(&meta.headers), &bytes);
        return Some(bytes);
    };
    let meta = CachedMeta {
        fetched_at: now(),
        status: f.status,
        final_url: f.final_url,
        redirects: f.redirects,
        headers: f.headers,
    };
    cache.put(key, &f.bytes, &meta);
    cache.record(url, meta.status, content_type_of(&meta.headers), &f.bytes);
    Some(f.bytes)
}

/// Resolve, fetch (or serve from cache), verify, and record provenance for
/// one reference. Never panics; every path yields a [`FetchRecord`].
#[must_use]
pub fn fetch_ref(r: &Reference, net: &dyn Fetch, cache: &BlobCache) -> FetchRecord {
    let mut rec = fetch_ref_inner(r, net, cache, || true);
    rec.kind = r.kind;
    rec
}

/// Whether a record represents a live network fetch — so it counts against the
/// [`FetchBudget::max_count`] ceiling. A cache hit (fresh or stale-served), an
/// unresolved locator, a non-target, and a budget-skipped edge do not count, so
/// a re-run over a warm cache is never throttled.
#[must_use]
pub fn counts_against_budget(rec: &FetchRecord) -> bool {
    !rec.cached
        && matches!(
            rec.outcome,
            Outcome::Ok | Outcome::PinMismatch | Outcome::UnverifiablePin | Outcome::Failed(_)
        )
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
    let Some((locator, url)) = resolved_target(&r.locator, net, cache) else {
        return FetchRecord::terminal(locator, Outcome::Unresolved);
    };

    let key = sha256_hex(locator.as_bytes());
    let max_age = if r.pinned_hash.is_some() {
        TTL_PINNED
    } else {
        TTL_UNPINNED
    };

    if let Some((bytes, meta)) = cache.fresh(&key, max_age) {
        return record(r, locator, url, &bytes, Served::Cache, &meta);
    }

    if !claim_fetch() {
        // Count budget spent: record the edge without fetching so the cap is
        // never a silent truncation, and a later run can still pick it up.
        let mut rec = FetchRecord::terminal(locator, Outcome::BudgetExceeded);
        rec.resolved_url = url;
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
    let fetched = if let Some(oci_ref) = url.strip_prefix("oci://") {
        if net.allows_oci() {
            crate::oci::export(oci_ref)
                .map(|(bytes, digest)| Fetched {
                    bytes,
                    final_url: url.clone(),
                    status: 200,
                    headers: digest
                        .map(|d| vec![("docker-content-digest".to_string(), d)])
                        .unwrap_or_default(),
                    redirects: Vec::new(),
                })
                .map_err(FetchError::Transport)
        } else {
            Err(FetchError::Refused(
                "oci pull not permitted by this fetch backend".into(),
            ))
        }
    } else {
        net.get(&url)
    };
    match fetched {
        Ok(f) => {
            let meta = CachedMeta {
                fetched_at: now(),
                status: f.status,
                final_url: f.final_url,
                redirects: f.redirects,
                headers: f.headers,
            };
            cache.put(&key, &f.bytes, &meta);
            record(r, locator, url, &f.bytes, Served::Network, &meta)
        }
        // The source is unreachable. Fall back to any cached copy, however
        // old — a stale answer beats none — and mark it stale. Only a genuine
        // cache miss is a failure.
        Err(e) => match cache.any(&key) {
            Some((bytes, meta)) => {
                tracing::warn!(locator = %locator, error = %e, "fetch failed; serving stale cache");
                record(r, locator, url, &bytes, Served::StaleCache, &meta)
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
/// Fetches run concurrently across a bounded pool (`fetch_concurrency`); the
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
    fetch_references_with(
        refs,
        source_sha256,
        fetch_urls,
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
    fetch_urls: bool,
    net: &(dyn Fetch + Sync),
    cache: &BlobCache,
    budget: FetchBudget,
    on_fetched: &(dyn Fn(&Reference, &FetchRecord) + Sync),
) -> Vec<FetchRecord> {
    // Selectable references, in declaration order. Every target is visited; the
    // caps are enforced live below — the byte cap stops the sweep, the count cap
    // gates only *network* fetches (cache hits are always served, never counted).
    let targets: Vec<&Reference> = refs.iter().filter(|r| selected(r, fetch_urls)).collect();
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
                                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                                        (n < budget.max_count).then_some(n + 1)
                                    })
                                    .is_ok()
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
/// behind `fetch_urls`. An intra-artifact path is resolved against sibling
/// files, not fetched.
fn selected(r: &Reference, fetch_urls: bool) -> bool {
    r.is_fetch_target()
        && match r.locator {
            RefLocator::Purl(_) => true,
            RefLocator::Url(_) => {
                matches!(r.kind, RefKind::Dependency | RefKind::Command) || fetch_urls
            }
            RefLocator::Path(_) => false,
        }
}

/// Where bytes in hand came from. One choice rather than two `bool`s, because
/// only three of the four flag combinations are real: a stale serve is by
/// definition a cache serve, so `!cached && stale` must be unrepresentable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Served {
    /// Fetched over the network just now.
    Network,
    /// A cache entry still inside its TTL.
    Cache,
    /// A cache entry past its TTL, served because the source was unreachable.
    StaleCache,
}

/// Build a record for bytes in hand, verifying the pin and choosing the outcome.
fn record(
    r: &Reference,
    locator: String,
    resolved_url: String,
    bytes: &[u8],
    served: Served,
    meta: &CachedMeta,
) -> FetchRecord {
    let content_sha256 = sha256_hex(bytes);
    let mut verifications = Vec::new();
    if r.pinned_hash.is_some() {
        verifications.push(verify_pin(r.pinned_hash.as_ref(), bytes, &content_sha256));
    }
    if purl_declares_checksum(&locator) {
        verifications.push(verify_purl_checksum(&locator, bytes, &content_sha256));
    }
    let pin_verified = if verifications.is_empty() {
        None
    } else if verifications.contains(&Some(false)) {
        Some(false)
    } else if verifications.iter().any(Option::is_none) {
        None
    } else {
        Some(true)
    };
    let outcome = if pin_verified == Some(false) {
        Outcome::PinMismatch
    } else if pin_verified.is_none() && reference_declares_pin(r, &locator) {
        Outcome::UnverifiablePin
    } else {
        Outcome::Ok
    };
    FetchRecord {
        source_sha256: String::new(),
        source_offset: None,
        kind: r.kind,
        locator,
        resolved_url,
        final_url: Some(meta.final_url.clone()),
        redirects: meta.redirects.clone(),
        status: Some(meta.status),
        headers: meta.headers.clone(),
        fetched_at: meta.fetched_at,
        content_sha256: Some(content_sha256),
        size: Some(bytes.len() as u64),
        cached: matches!(served, Served::Cache | Served::StaleCache),
        stale: served == Served::StaleCache,
        pin_verified,
        outcome,
    }
}

fn reference_declares_pin(reference: &Reference, locator: &str) -> bool {
    reference.pinned_hash.is_some() || purl_declares_checksum(locator)
}

fn purl_declares_checksum(locator: &str) -> bool {
    crate::purl::Purl::parse(locator)
        .ok()
        .is_some_and(|purl| purl.qualifiers().contains_key("checksum"))
}

/// The canonical locator string (the PURL or URL).
fn locator_string(locator: &RefLocator) -> String {
    match locator {
        RefLocator::Purl(s) | RefLocator::Url(s) | RefLocator::Path(s) => s.clone(),
    }
}

/// Resolve a locator to a fetchable URL, or `None` if the ecosystem isn't
/// supported yet. Ecosystems that need a registry round-trip (PyPI, Composer,
/// Firefox, the AUR, an unversioned npm PURL) resolve in `resolved_target`
/// instead; official-repo alpm (a mirror lookup) is a follow-up.
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
        RefLocator::Purl(p) => crate::purl::normalize(p).and_then(|purl| resolve_purl(&purl)),
        // An intra-artifact file reference is resolved against the bundle's
        // other files by a consumer, never fetched.
        RefLocator::Path(_) => None,
    }
}

/// Resolve every concrete artifact variant published for `locator`.
///
/// Unlike [`resolve`], this API may consult registry metadata. It currently
/// expands the ecosystems where artifact variants or compatibility metadata
/// matter most: npm, PyPI, RubyGems, Go modules, and Cargo crates. The returned
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
    let mut locator_text = locator_string(locator);
    let candidates = match locator {
        RefLocator::Url(url) if is_web_scheme(url) => {
            vec![artifact_candidate(url.clone(), "download")]
        }
        RefLocator::Url(_) | RefLocator::Path(_) => return None,
        RefLocator::Purl(purl) => {
            let purl = crate::purl::normalize(purl)?;
            locator_text.clone_from(&purl);
            let (ty, rest) = crate::purl::scheme_type_rest(&purl)?;
            let mut candidates = if let Some(url) = purl_qualifier(rest, "download_url") {
                if !is_web_scheme(&url) {
                    return None;
                }
                let mut candidate = artifact_candidate(url, "download");
                candidate.preferred = file_name_matches(rest, &candidate.file_name);
                vec![candidate]
            } else if purl_qualifier(rest, "vers").is_some() {
                // A range describes multiple releases, not one concrete
                // artifact coordinate. Callers must choose a version first.
                Vec::new()
            } else {
                let (path, version) = split_path_version(rest);
                if !safe_coordinate(path) || version.is_some_and(|value| !safe_coordinate(value)) {
                    return None;
                }
                match ty.as_str() {
                    "npm" => npm_artifacts(path, version, rest, net, cache),
                    "pypi" => pypi_artifacts(path, version, rest, net, cache),
                    "gem" => gem_artifacts(path, version, rest, net, cache),
                    "golang" => deterministic_artifacts(&purl, rest, "zip"),
                    "cargo" => cargo_artifacts(&purl, path, version, rest, net, cache),
                    _ => return None,
                }
            };
            apply_common_candidate_qualifiers(rest, &mut candidates);
            attach_candidate_identities(&purl, &mut candidates);
            candidates
        }
    };
    Some(ArtifactMatrix {
        locator: locator_text,
        candidates,
    })
}

fn artifact_candidate(url: String, kind: &str) -> ArtifactCandidate {
    let file_name = file_name_from_url(&url);
    let mut attributes = BTreeMap::new();
    attributes.insert("kind".to_string(), kind.to_string());
    ArtifactCandidate {
        release_purl: None,
        artifact_purl: None,
        url,
        file_name,
        qualifiers: BTreeMap::new(),
        attributes,
        checksums: BTreeMap::new(),
        preferred: true,
    }
}

fn file_name_from_url(url: &str) -> String {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    percent_decode(path.rsplit('/').next().unwrap_or_default())
}

fn deterministic_artifacts(purl: &str, rest: &str, kind: &str) -> Vec<ArtifactCandidate> {
    // The matrix reports the possible artifact even when an exact file_name
    // selector does not match it. In that case no candidate is preferred and
    // the legacy one-URL resolver still returns None.
    let Some(url) = resolve_purl_with_file_selection(purl, false) else {
        return Vec::new();
    };
    let mut candidate = artifact_candidate(url, kind);
    if let Some(subpath) = rest.split_once('#').map(|(_, value)| percent_decode(value))
        && !subpath.is_empty()
    {
        candidate.attributes.insert("subpath".into(), subpath);
    }
    candidate.preferred = file_name_matches(rest, &candidate.file_name);
    vec![candidate]
}

fn cargo_artifacts(
    purl: &str,
    name: &str,
    version: Option<&str>,
    rest: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Vec<ArtifactCandidate> {
    let Some(repository) = purl_qualifier(rest, "repository_url") else {
        return deterministic_artifacts(purl, rest, "crate");
    };
    let repository = repository.trim_end_matches('/');
    if matches!(repository, "https://crates.io" | "https://index.crates.io") {
        return deterministic_artifacts(purl, rest, "crate");
    }
    let repository = repository.strip_prefix("sparse+").unwrap_or(repository);
    if !is_web_scheme(repository) {
        return Vec::new();
    }
    let Some(version) = version.map(percent_decode) else {
        return Vec::new();
    };
    let config_url = format!("{repository}/config.json");
    let Some(download) = cached_metadata(&config_url, net, &cache.with_meta_ttl(meta_ttl_pinned()))
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|config| config.get("dl")?.as_str().map(str::to_string))
    else {
        return Vec::new();
    };
    let mut checksums = purl_checksums(rest);
    if !checksums.contains_key("sha256")
        && let Some(checksum) = cargo_index_checksum(repository, name, &version, net, cache)
    {
        checksums.insert("sha256".into(), checksum);
    }
    let url = cargo_download_url(
        &download,
        name,
        &version,
        checksums.get("sha256").map(String::as_str),
    );
    let Some(url) = url else {
        return Vec::new();
    };
    let mut candidate = artifact_candidate(url, "crate");
    candidate.checksums = checksums;
    candidate
        .qualifiers
        .insert("repository_url".into(), repository.to_string());
    candidate.preferred = file_name_matches(rest, &candidate.file_name);
    vec![candidate]
}

fn cargo_index_checksum(
    repository: &str,
    name: &str,
    version: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Option<String> {
    let lower = name.to_ascii_lowercase();
    let prefix = cargo_registry_prefix(&lower)?;
    let index_url = format!("{repository}/{prefix}/{lower}");
    let bytes = cached_metadata(&index_url, net, &cache.with_meta_ttl(meta_ttl_pinned()))?;
    std::str::from_utf8(&bytes)
        .ok()?
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find_map(|entry| {
            (entry.get("vers")?.as_str()? == version)
                .then(|| entry.get("cksum")?.as_str().map(str::to_string))
                .flatten()
        })
}

fn cargo_download_url(
    template: &str,
    name: &str,
    version: &str,
    sha256: Option<&str>,
) -> Option<String> {
    if template.contains("{sha256-checksum}") && sha256.is_none() {
        // This template cannot be expanded without either an explicit PURL
        // checksum or the crate's index record. Never invent the digest.
        return None;
    }
    let prefix = cargo_registry_prefix(name)?;
    let lowerprefix = cargo_registry_prefix(&name.to_ascii_lowercase())?;
    let has_markers = template.contains('{');
    let expanded = template
        .replace("{crate}", name)
        .replace("{version}", version)
        .replace("{prefix}", &prefix)
        .replace("{lowerprefix}", &lowerprefix)
        .replace("{sha256-checksum}", sha256.unwrap_or_default());
    let url = if has_markers {
        expanded
    } else {
        format!(
            "{}/{name}/{version}/download",
            expanded.trim_end_matches('/')
        )
    };
    is_web_scheme(&url).then_some(url)
}

fn cargo_registry_prefix(name: &str) -> Option<String> {
    let characters: Vec<char> = name.chars().collect();
    Some(match characters.len() {
        0 => return None,
        1 => "1".to_string(),
        2 => "2".to_string(),
        3 => format!("3/{}", characters[0]),
        _ => format!(
            "{}{}/{}{}",
            characters[0], characters[1], characters[2], characters[3]
        ),
    })
}

fn npm_artifacts(
    path: &str,
    requested_version: Option<&str>,
    rest: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Vec<ArtifactCandidate> {
    let name = npm_registry_name(path);
    let ttl = if requested_version.is_some() {
        meta_ttl_pinned()
    } else {
        meta_ttl_unpinned()
    };
    let Some(repository) = repository_base(rest, "https://registry.npmjs.org") else {
        return Vec::new();
    };
    let api = format!("{repository}/{name}");
    let doc = cached_metadata(&api, net, &cache.with_meta_ttl(ttl))
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
    let requested = requested_version.map(percent_decode);
    let resolved = requested.as_ref().map_or_else(
        || {
            doc.as_ref()?
                .pointer("/dist-tags/latest")?
                .as_str()
                .map(str::to_string)
        },
        |value| {
            doc.as_ref()
                .and_then(|document| document.get("versions"))
                .and_then(|versions| versions.get(value))
                .map(|_| value.clone())
                .or_else(|| {
                    doc.as_ref()?
                        .get("dist-tags")?
                        .get(value)?
                        .as_str()
                        .map(str::to_string)
                })
        },
    );
    let Some(version) = resolved else {
        return Vec::new();
    };
    let version_doc = doc
        .as_ref()
        .and_then(|value| value.get("versions"))
        .and_then(|versions| versions.get(&version));
    let base_name = name.rsplit('/').next().unwrap_or(name.as_str());
    let url = version_doc
        .and_then(|value| value.pointer("/dist/tarball"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .or_else(|| Some(format!("{repository}/{name}/-/{base_name}-{version}.tgz")));
    let Some(url) = url else {
        return Vec::new();
    };
    let mut candidate = artifact_candidate(url, "tgz");
    candidate.attributes.insert("version".into(), version);
    for key in ["os", "cpu", "libc"] {
        if let Some(value) = version_doc
            .and_then(|doc| doc.get(key))
            .and_then(json_string_list)
        {
            candidate.attributes.insert(key.to_string(), value);
        }
    }
    if let Some(node) = version_doc
        .and_then(|doc| doc.pointer("/engines/node"))
        .and_then(serde_json::Value::as_str)
    {
        candidate.attributes.insert("node".into(), node.to_string());
    }
    if let Some(integrity) = version_doc
        .and_then(|doc| doc.pointer("/dist/integrity"))
        .and_then(serde_json::Value::as_str)
    {
        candidate
            .attributes
            .insert("integrity".into(), integrity.to_string());
        add_sri_checksums(integrity, &mut candidate.checksums);
    }
    if let Some(sha1) = version_doc
        .and_then(|doc| doc.pointer("/dist/shasum"))
        .and_then(serde_json::Value::as_str)
    {
        candidate.checksums.insert("sha1".into(), sha1.to_string());
    }
    candidate.preferred = file_name_matches(rest, &candidate.file_name);
    vec![candidate]
}

fn add_sri_checksums(integrity: &str, checksums: &mut BTreeMap<String, String>) {
    use base64::Engine as _;
    for token in integrity.split_ascii_whitespace() {
        let Some((algorithm, encoded)) = token.split_once('-') else {
            continue;
        };
        let Some(bytes) = base64::engine::general_purpose::STANDARD
            .decode(encoded.split('?').next().unwrap_or(encoded))
            .ok()
        else {
            continue;
        };
        checksums
            .entry(algorithm.to_ascii_lowercase())
            .or_insert_with(|| hex::encode(bytes));
    }
}

fn npm_registry_name(path: &str) -> String {
    if path
        .get(..3)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("%40"))
    {
        format!("@{}", &path[3..])
    } else {
        path.to_string()
    }
}

fn json_string_list(value: &serde_json::Value) -> Option<String> {
    if let Some(value) = value.as_str() {
        return Some(value.to_string());
    }
    let values = value
        .as_array()?
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect::<Vec<_>>();
    (!values.is_empty()).then(|| values.join(","))
}

fn pypi_artifacts(
    name: &str,
    version: Option<&str>,
    rest: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Vec<ArtifactCandidate> {
    let Some(repository) = repository_base(rest, "https://pypi.org") else {
        return Vec::new();
    };
    let api = version.map_or_else(
        || format!("{repository}/pypi/{name}/json"),
        |value| format!("{repository}/pypi/{name}/{value}/json"),
    );
    let ttl = if version.is_some() {
        META_TTL_IMMUTABLE
    } else {
        meta_ttl_unpinned()
    };
    let Some(doc) = cached_metadata(&api, net, &cache.with_meta_ttl(ttl))
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
    else {
        return Vec::new();
    };
    let resolved_version = version
        .map(percent_decode)
        .or_else(|| doc.pointer("/info/version")?.as_str().map(str::to_string))
        .unwrap_or_default();
    let Some(urls) = doc.get("urls").and_then(serde_json::Value::as_array) else {
        return Vec::new();
    };
    let mut candidates: Vec<_> = urls
        .iter()
        .filter_map(|file| pypi_candidate(file, name, &resolved_version))
        .collect();
    let exact = purl_qualifier(rest, "file_name");
    let kind = purl_qualifier(rest, "kind");
    candidates.sort_by_key(|candidate| {
        (
            pypi_rank(candidate, exact.as_deref(), kind.as_deref()),
            candidate.file_name.clone(),
        )
    });
    let preferred = if let Some(file_name) = exact.as_deref() {
        candidates
            .iter()
            .position(|candidate| candidate.file_name == file_name)
    } else {
        (!candidates.is_empty()).then_some(0)
    }
    .or_else(|| (exact.is_none() && !candidates.is_empty()).then_some(0));
    for (index, candidate) in candidates.iter_mut().enumerate() {
        candidate.preferred = Some(index) == preferred;
    }
    candidates
}

fn pypi_candidate(
    file: &serde_json::Value,
    name: &str,
    version: &str,
) -> Option<ArtifactCandidate> {
    let url = file.get("url")?.as_str()?.to_string();
    let file_name = file
        .get("filename")
        .and_then(serde_json::Value::as_str)
        .map_or_else(|| file_name_from_url(&url), str::to_string);
    let package_type = file
        .get("packagetype")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("distribution");
    let kind = match package_type {
        "bdist_wheel" => "wheel",
        "sdist" => "sdist",
        other => other,
    };
    let mut qualifiers = BTreeMap::new();
    qualifiers.insert("file_name".into(), file_name.clone());
    let mut attributes = BTreeMap::new();
    attributes.insert("kind".into(), kind.to_string());
    attributes.insert("version".into(), version.to_string());
    if kind == "wheel" {
        attributes.extend(wheel_attributes(&file_name, name, version));
    }
    for key in ["python_version", "requires_python"] {
        if let Some(value) = file.get(key).and_then(serde_json::Value::as_str) {
            attributes.insert(key.to_string(), value.to_string());
        }
    }
    if file
        .get("yanked")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        attributes.insert("yanked".into(), "true".into());
    }
    if let Some(reason) = file
        .get("yanked_reason")
        .and_then(serde_json::Value::as_str)
    {
        attributes.insert("yanked_reason".into(), reason.to_string());
    }
    let checksums = file
        .get("digests")
        .and_then(serde_json::Value::as_object)
        .map(|digests| {
            digests
                .iter()
                .filter_map(|(algorithm, value)| {
                    value.as_str().map(|digest| {
                        (
                            algorithm.to_ascii_lowercase().replace('_', "-"),
                            digest.to_string(),
                        )
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Some(ArtifactCandidate {
        release_purl: None,
        artifact_purl: None,
        url,
        file_name,
        qualifiers,
        attributes,
        checksums,
        preferred: false,
    })
}

fn wheel_attributes(file_name: &str, name: &str, version: &str) -> BTreeMap<String, String> {
    let mut attributes = BTreeMap::new();
    let Some(stem) = file_name.strip_suffix(".whl") else {
        return attributes;
    };

    // Wheel filenames are `{distribution}-{version}(-{build})?-{python}-{abi}-{platform}`.
    // Distribution punctuation is normalized to underscores, so remove the
    // known coordinate prefix before deciding whether the optional build tag
    // exists. Counting every `-` in the full filename misclassifies legacy
    // distributions containing a hyphen as a build tag.
    let distribution = name
        .chars()
        .map(|ch| match ch {
            '-' | '.' => '_',
            other => other.to_ascii_lowercase(),
        })
        .collect::<String>();
    let version = version.replace('-', "_");
    let prefix = format!("{distribution}-{version}-");
    let suffix = stem
        .get(..prefix.len())
        .filter(|actual| actual.eq_ignore_ascii_case(&prefix))
        .and_then(|_| stem.get(prefix.len()..))
        .unwrap_or(stem);
    let parts: Vec<&str> = suffix.split('-').collect();
    if parts.len() < 3 {
        return attributes;
    }
    let tag = parts.len() - 3;
    attributes.insert("python".into(), parts[tag].to_string());
    attributes.insert("abi".into(), parts[tag + 1].to_string());
    attributes.insert("platform".into(), parts[tag + 2].to_string());
    if parts.len() == 4 {
        attributes.insert("build".into(), parts[0].to_string());
    }
    attributes
}

fn pypi_rank(
    candidate: &ArtifactCandidate,
    exact: Option<&str>,
    requested_kind: Option<&str>,
) -> u8 {
    if let Some(file_name) = exact {
        return u8::from(candidate.file_name != file_name);
    }
    let kind = candidate.attributes.get("kind").map(String::as_str);
    let natural = if kind == Some("wheel") {
        let python = candidate.attributes.get("python").map(String::as_str);
        let abi = candidate.attributes.get("abi").map(String::as_str);
        let platform = candidate.attributes.get("platform").map(String::as_str);
        if python == Some("py3") && abi == Some("none") && platform == Some("any") {
            0
        } else if abi == Some("none") && platform == Some("any") {
            1
        } else {
            3
        }
    } else if kind == Some("sdist") {
        2
    } else {
        4
    };
    let requested = if requested_kind.is_some_and(|requested| kind != Some(requested)) {
        10 + natural
    } else {
        natural
    };
    requested
        + if candidate.attributes.contains_key("yanked") {
            20
        } else {
            0
        }
}

fn gem_artifacts(
    name: &str,
    requested_version: Option<&str>,
    rest: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Vec<ArtifactCandidate> {
    let Some(repository) = repository_base(rest, "https://rubygems.org") else {
        return Vec::new();
    };
    let api = format!("{repository}/api/v1/versions/{name}.json");
    let ttl = if requested_version.is_some() {
        meta_ttl_pinned()
    } else {
        meta_ttl_unpinned()
    };
    let entries = cached_metadata(&api, net, &cache.with_meta_ttl(ttl))
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default();
    let requested = requested_version.map(percent_decode);
    let resolved =
        requested.or_else(|| entries.first()?.get("number")?.as_str().map(str::to_string));
    let Some(version) = resolved else {
        return Vec::new();
    };
    let mut candidates: Vec<_> = entries
        .iter()
        .filter(|entry| {
            entry.get("number").and_then(serde_json::Value::as_str) == Some(version.as_str())
        })
        .filter(|entry| {
            entry
                .get("platform")
                .and_then(serde_json::Value::as_str)
                .is_none_or(safe_filename_part)
        })
        .map(|entry| gem_candidate(&repository, name, &version, entry))
        .collect();
    if candidates.is_empty() {
        return Vec::new();
    }
    candidates.sort_by(|left, right| left.file_name.cmp(&right.file_name));
    let explicit_platform = purl_qualifier(rest, "platform");
    let wanted = explicit_platform.as_deref().unwrap_or("ruby");
    let mut preferred = candidates.iter().position(|candidate| {
        candidate
            .qualifiers
            .get("platform")
            .is_some_and(|platform| platform == wanted)
    });
    if let Some(file_name) = purl_qualifier(rest, "file_name") {
        preferred = candidates
            .iter()
            .position(|candidate| candidate.file_name == file_name);
    }
    for (index, candidate) in candidates.iter_mut().enumerate() {
        candidate.preferred = Some(index) == preferred;
    }
    candidates.sort_by_key(|candidate| !candidate.preferred);
    candidates
}

fn gem_candidate(
    repository: &str,
    name: &str,
    version: &str,
    entry: &serde_json::Value,
) -> ArtifactCandidate {
    let platform = entry
        .get("platform")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("ruby");
    let mut candidate = gem_candidate_for_platform(repository, name, version, platform);
    if let Some(sha256) = entry.get("sha").and_then(serde_json::Value::as_str)
        && !sha256.is_empty()
    {
        candidate
            .checksums
            .insert("sha256".into(), sha256.to_string());
    }
    for key in ["ruby_version", "rubygems_version"] {
        if let Some(value) = entry.get(key).and_then(serde_json::Value::as_str) {
            candidate.attributes.insert(key.into(), value.to_string());
        }
    }
    candidate
}

fn gem_candidate_for_platform(
    repository: &str,
    name: &str,
    version: &str,
    platform: &str,
) -> ArtifactCandidate {
    let suffix = if platform == "ruby" {
        String::new()
    } else {
        format!("-{platform}")
    };
    let file_name = format!("{name}-{version}{suffix}.gem");
    let mut qualifiers = BTreeMap::new();
    qualifiers.insert("platform".into(), platform.to_string());
    let mut attributes = BTreeMap::new();
    attributes.insert("kind".into(), "gem".into());
    attributes.insert("version".into(), version.to_string());
    ArtifactCandidate {
        release_purl: None,
        artifact_purl: None,
        url: format!("{repository}/downloads/{file_name}"),
        file_name,
        qualifiers,
        attributes,
        checksums: BTreeMap::new(),
        preferred: false,
    }
}

fn file_name_matches(rest: &str, actual: &str) -> bool {
    purl_qualifier(rest, "file_name").is_none_or(|wanted| wanted == actual)
}

fn selected_artifact_url(rest: &str, url: String) -> Option<String> {
    file_name_matches(rest, &file_name_from_url(&url)).then_some(url)
}

fn maybe_selected_artifact_url(rest: &str, url: String, honor_file_name: bool) -> Option<String> {
    if honor_file_name {
        selected_artifact_url(rest, url)
    } else {
        Some(url)
    }
}

/// Whether a URL names a web scheme this module's own client can carry.
/// Compared ASCII-case-insensitively, since schemes are.
fn is_web_scheme(url: &str) -> bool {
    let b = url.as_bytes();
    b.get(..7)
        .is_some_and(|p| p.eq_ignore_ascii_case(b"http://"))
        || b.get(..8)
            .is_some_and(|p| p.eq_ignore_ascii_case(b"https://"))
}

/// Split a PURL body (everything after `pkg:<type>/`) into its coordinate path
/// and version, dropping any `?qualifiers`. The version follows the literal `@`
/// (a scope is `%40`, not `@`). Tolerates the non-spec `?qualifiers@version`
/// ordering older hopper exports emitted (a version appended to a
/// qualifier-bearing purl_base): a trailing `@<v>` inside the qualifier tail is
/// read as the misplaced version when `<v>` is free of `=`/`&`/`/`, any of
/// which would mark it as part of a qualifier value instead.
fn split_path_version(rest: &str) -> (&str, Option<&str>) {
    // A subpath selects content *inside* the package, not a different archive.
    // Strip it before interpreting the package coordinate or qualifiers.
    let rest = rest
        .split_once('#')
        .map_or(rest, |(coordinate, _)| coordinate);
    let (bare, quals) = match rest.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (rest, None),
    };
    let (path, version) = bare
        .rsplit_once('@')
        .map_or((bare, None), |(p, v)| (p, Some(v)));
    let version = version.or_else(|| {
        let (_, v) = quals?.rsplit_once('@')?;
        (!v.is_empty() && !v.contains(['=', '&', '/'])).then_some(v)
    });
    (path, version)
}

/// Map a PURL to a deterministic download URL for the computable ecosystems
/// (npm, crates.io, NuGet, Maven Central, GitHub archives), or to the `oci://`
/// pseudo-URL the OCI puller consumes.
fn resolve_purl(purl: &str) -> Option<String> {
    resolve_purl_with_file_selection(purl, true)
}

fn resolve_purl_with_file_selection(purl: &str, honor_file_name: bool) -> Option<String> {
    // Scheme and type are case-insensitive per spec; the shared splitter folds
    // their case and trims, so any spelling `purl::normalize` accepts resolves.
    let (ty, rest) = crate::purl::scheme_type_rest(purl)?;
    // pkg:oci carries its repository on a qualifier and splits version
    // (digest) from tag (qualifier) per its type definition, so it parses
    // `rest` itself rather than using the generic path@version split.
    if ty == "oci" || ty == "docker" {
        return resolve_oci_ref(rest);
    }
    // The standard common qualifier is an exact artifact selector and wins
    // over an ecosystem-derived URL. The normal HTTP fetch path still applies
    // its DNS/redirect SSRF guard to the selected destination.
    if let Some(url) = purl_qualifier(rest, "download_url") {
        return is_web_scheme(&url).then_some(url);
    }
    let (path, version) = split_path_version(rest);
    // Vetted once here rather than at each of the arms below, every one of
    // which interpolates these into a URL.
    let version_is_safe = version.is_none_or(|value| {
        if ty == "maven" {
            safe_coordinate_inner(value, true)
        } else {
            safe_coordinate(value)
        }
    });
    if !safe_coordinate(path) || !version_is_safe {
        return None;
    }
    match ty.as_str() {
        "npm" => {
            let name = path.replace("%40", "@");
            let base = name.rsplit('/').next().unwrap_or(name.as_str());
            let version = version?;
            let repository = repository_base(rest, "https://registry.npmjs.org")?;
            maybe_selected_artifact_url(
                rest,
                format!("{repository}/{name}/-/{base}-{version}.tgz"),
                honor_file_name,
            )
        }
        "cargo" => {
            let version = version?;
            if let Some(repository) = purl_qualifier(rest, "repository_url") {
                let repository = repository.trim_end_matches('/');
                if !matches!(repository, "https://crates.io" | "https://index.crates.io") {
                    // Alternate Cargo registries publish their download
                    // template in index config.json; only the metadata-aware
                    // matrix can resolve it.
                    return None;
                }
            }
            maybe_selected_artifact_url(
                rest,
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
            let repository = repository_base(rest, "https://proxy.golang.org")?;
            // The default Go module proxy. Module path and version are
            // case-encoded per the GOPROXY protocol.
            maybe_selected_artifact_url(
                rest,
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
            let repository = repository_base(rest, "https://rubygems.org")?;
            let platform = purl_qualifier(rest, "platform");
            let suffix = match platform.as_deref() {
                None | Some("ruby") => String::new(),
                Some(value) if safe_filename_part(value) => format!("-{value}"),
                Some(_) => return None,
            };
            maybe_selected_artifact_url(
                rest,
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
            let extension = match purl_qualifier(rest, "type") {
                Some(v) if safe_filename_part(&v) => v,
                Some(_) => return None,
                None => "jar".to_string(),
            };
            let classifier = match purl_qualifier(rest, "classifier") {
                Some(v) if safe_filename_part(&v) => format!("-{v}"),
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

/// Read one PURL qualifier from `rest`, percent-decoding its value. Qualifiers
/// follow the coordinate/version after `?` and are an unordered `&` list.
fn purl_qualifier(rest: &str, key: &str) -> Option<String> {
    let qualifiers = rest.split_once('?')?.1;
    let qualifiers = qualifiers
        .split_once('#')
        .map_or(qualifiers, |(values, _)| values);
    qualifiers.split('&').find_map(|q| {
        let (k, v) = q.split_once('=')?;
        k.eq_ignore_ascii_case(key).then(|| percent_decode(v))
    })
}

fn repository_base(rest: &str, default: &str) -> Option<String> {
    match purl_qualifier(rest, "repository_url") {
        Some(repository) if is_web_scheme(&repository) => {
            Some(repository.trim_end_matches('/').to_string())
        }
        Some(_) => None,
        None => Some(default.to_string()),
    }
}

fn purl_checksums(rest: &str) -> BTreeMap<String, String> {
    purl_qualifier(rest, "checksum")
        .map(|value| {
            value
                .split(',')
                .filter_map(|checksum| {
                    let (algorithm, digest) = checksum.split_once(':')?;
                    (!algorithm.is_empty() && !digest.is_empty()).then(|| {
                        (
                            algorithm.to_ascii_lowercase().replace('_', "-"),
                            digest.to_ascii_lowercase(),
                        )
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn apply_common_candidate_qualifiers(rest: &str, candidates: &mut [ArtifactCandidate]) {
    let declared = purl_checksums(rest);
    let repository = purl_qualifier(rest, "repository_url");
    let vcs = purl_qualifier(rest, "vcs_url");
    let download = purl_qualifier(rest, "download_url");
    let file_name = purl_qualifier(rest, "file_name");
    for candidate in candidates {
        if let Some(repository) = repository.as_ref() {
            candidate
                .qualifiers
                .insert("repository_url".into(), repository.clone());
        }
        if let Some(vcs) = vcs.as_ref() {
            candidate.qualifiers.insert("vcs_url".into(), vcs.clone());
        }
        if let Some(download) = download.as_ref() {
            candidate
                .qualifiers
                .insert("download_url".into(), download.clone());
        }
        if let Some(file_name) = file_name.as_ref()
            && candidate.file_name == *file_name
        {
            candidate
                .qualifiers
                .entry("file_name".into())
                .or_insert_with(|| file_name.clone());
        }
        for (algorithm, digest) in &declared {
            if candidate
                .checksums
                .get(algorithm)
                .is_some_and(|published| !published.eq_ignore_ascii_case(digest))
            {
                candidate.preferred = false;
                candidate
                    .attributes
                    .insert("checksum_mismatch".into(), "true".into());
            }
            candidate
                .checksums
                .entry(algorithm.clone())
                .or_insert_with(|| digest.clone());
        }
    }
}

fn attach_candidate_identities(release: &str, candidates: &mut [ArtifactCandidate]) {
    for candidate in candidates {
        let version = candidate.attributes.get("version").map(String::as_str);
        let release_purl = crate::purl::release_identity_at(release, version);
        candidate.release_purl.clone_from(&release_purl);
        let mut selectors = candidate.qualifiers.clone();
        if !candidate.checksums.is_empty() {
            selectors.insert(
                "checksum".into(),
                candidate
                    .checksums
                    .iter()
                    .map(|(algorithm, digest)| format!("{algorithm}:{digest}"))
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        candidate.artifact_purl = release_purl
            .as_deref()
            .and_then(|release| crate::purl::artifact_identity(release, &selectors));
    }
}

/// Whether a decoded PURL qualifier can safely be embedded as one artifact
/// filename component. Reject separators and URL delimiters instead of letting
/// a crafted classifier/type change the Maven repository path.
fn safe_filename_part(value: &str) -> bool {
    !value.is_empty()
        && !value
            .bytes()
            .any(|b| matches!(b, b'/' | b'\\' | b'?' | b'#'))
}

/// Whether a PURL's coordinate path or version may be interpolated into a
/// registry URL.
///
/// Every ecosystem builds its endpoint by `format!`-ing these straight into a
/// path or query, and they come from a scanned manifest — attacker-controlled.
/// The literal `https://host/` prefix means no value can move the *host*, but
/// it can still restructure the rest of the URL: `..` climbs out of the
/// intended path, `?`/`#` truncate it into a query or fragment, and `\` is a
/// path separator under the WHATWG rules the URL parser applies. The result is
/// a record whose bytes came from somewhere other than the coordinate it is
/// filed under — provenance the whole tool rests on.
///
/// Rejecting is safe: no registry issues a name or version containing these,
/// so a coordinate that does is not a package. It resolves to
/// [`Outcome::Unresolved`] and is recorded, never silently dropped.
pub(crate) fn safe_coordinate(value: &str) -> bool {
    safe_coordinate_inner(value, false)
}

fn safe_coordinate_inner(value: &str, allow_encoded_space: bool) -> bool {
    let decoded = percent_decode(value);
    value.bytes().filter(|byte| *byte == b'/').count()
        == decoded.bytes().filter(|byte| *byte == b'/').count()
        && !decoded
            .split('/')
            .any(|segment| segment == ".." || segment == ".")
        && !value
            .bytes()
            .any(|b| b.is_ascii_control() || matches!(b, b' ' | b'\\' | b'?' | b'#' | b'"'))
        && !decoded.bytes().any(|b| {
            b.is_ascii_control()
                || matches!(b, b'\\' | b'?' | b'#' | b'"')
                || (b == b' ' && !allow_encoded_space)
        })
}

/// Resolve a `pkg:oci` (or legacy `pkg:docker`) purl body to the `oci://`
/// pseudo-URL the OCI puller consumes: `oci://<repo>[@sha256:…|:tag]`. The
/// repository path rides the purl's percent-encoded `repository_url`
/// qualifier; without one, Docker Hub's implied coordinates apply. A
/// `sha256:…` version is the content-addressed digest and wins over any
/// mutable `tag` qualifier; with neither, `latest` — matching what forager's
/// crane path pulls for a bare reference.
fn resolve_oci_ref(rest: &str) -> Option<String> {
    let (bare, quals) = rest.split_once('?').map_or((rest, ""), |(b, q)| (b, q));
    let (name, version) = bare
        .rsplit_once('@')
        .map_or((bare, None), |(n, v)| (n, Some(v)));
    if name.is_empty() {
        return None;
    }
    let mut repo = None;
    let mut tag = None;
    for q in quals.split('&') {
        if let Some((k, v)) = q.split_once('=') {
            match k {
                "repository_url" => repo = Some(percent_decode(v)),
                "tag" => tag = Some(v.to_string()),
                _ => {}
            }
        }
    }
    let repo = repo.unwrap_or_else(|| {
        // Host-less refs live on Docker Hub; single-segment ones under library/.
        match name.split_once('/') {
            Some((first, _)) if first.contains('.') || first.contains(':') => name.to_string(),
            Some(_) => format!("docker.io/{name}"),
            None => format!("docker.io/library/{name}"),
        }
    });
    Some(match (version, tag.as_deref()) {
        (Some(d), _) if d.starts_with("sha256:") => format!("oci://{repo}@{d}"),
        // A legacy pkg:docker version slot may carry a plain tag.
        (Some(t), _) | (None, Some(t)) => format!("oci://{repo}:{t}"),
        (None, None) => format!("oci://{repo}:latest"),
    })
}

/// Decode percent-escapes (`%2F` → '/'). Malformed escapes pass through
/// literally rather than failing — a best-effort mirror of how lenient purl
/// parsers treat them.
pub(crate) fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let decoded = (b[i] == b'%' && i + 2 < b.len())
            .then(|| {
                let hex = std::str::from_utf8(&b[i + 1..i + 3]).ok()?;
                u8::from_str_radix(hex, 16).ok()
            })
            .flatten();
        match decoded {
            Some(c) => {
                out.push(c);
                i += 3;
            }
            None => {
                out.push(b[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Resolve a reference to `(canonical locator, fetchable URL)`. Most ecosystems
/// are a pure name+version → URL mapping ([`resolve`]), and the locator passes
/// through unchanged. The exceptions take a registry round-trip over `net`:
/// PyPI and Composer have no derivable artifact URL, and a versionless npm PURL
/// (a manifest range/tag) is *refined* to the concrete `name@version` it
/// currently points at — that refined locator is returned so it keys the cache
/// and names the fetch edge. `None` when the ecosystem can't be resolved.
fn resolved_target(
    locator: &RefLocator,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Option<(String, String)> {
    if let RefLocator::Purl(raw) = locator
        && let Some(p) = crate::purl::normalize(raw)
        && let Some((ty, rest)) = crate::purl::scheme_type_rest(&p)
    {
        let ty = ty.as_str();
        // An exact download override takes precedence even for ecosystems that
        // normally need metadata (notably versionless npm and PyPI). Apply the
        // common exact-filename selector to it just as the pure resolver does.
        if let Some(url) = purl_qualifier(rest, "download_url") {
            return (is_web_scheme(&url) && file_name_matches(rest, &file_name_from_url(&url)))
                .then(|| (p.clone(), url));
        }
        if purl_qualifier(rest, "vers").is_some() {
            return None;
        }
        let (coordinate_path, coordinate_version) = split_path_version(rest);
        // Registry metadata can refine a mutable/tagged request to a concrete
        // release and exact artifact. Use that identity for cache/provenance;
        // retain the pure resolver below as the offline compatibility path.
        let needs_matrix = ty == "pypi"
            || (ty == "npm"
                && coordinate_version.is_none_or(|version| !npm_version_is_concrete(version)))
            || (ty == "gem" && coordinate_version.is_none())
            || (ty == "cargo"
                && purl_qualifier(rest, "repository_url").is_some_and(|repository| {
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
                .unwrap_or_else(|| p.clone());
            return Some((exact, candidate.url.clone()));
        }
        // A scope is `%40`, so `split_path_version` can distinguish it from a
        // real version separator even when qualifier values themselves contain
        // `@`. A versionless npm dependency is refined through dist-tags.
        if ty == "npm" {
            match coordinate_version {
                None => return resolve_npm_dist_tag(coordinate_path, rest, "latest", net),
                Some(version) if !npm_version_is_concrete(version) => {
                    return resolve_npm_dist_tag(
                        coordinate_path,
                        rest,
                        &percent_decode(version),
                        net,
                    );
                }
                Some(_) => {}
            }
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
        // The ratified `vscode-extension` type covers both stores; Open VSX is
        // flagged by its repository_url qualifier (read off the raw purl — the
        // path/version split drops qualifiers).
        if ty == "vscode-extension" {
            return if p.contains("open-vsx.org") {
                resolve_openvsx(rest, net).map(|u| (p.clone(), u))
            } else {
                resolve_vscode(rest, net).map(|u| (p.clone(), u))
            };
        }
        // PyPI may publish many files for one release. Honor its registered
        // case-sensitive `file_name` selector (and the legacy `kind` hint),
        // then feed the preferred matrix candidate through the old one-URL
        // fetch contract.
        if ty == "pypi" {
            let (path, version) = split_path_version(rest);
            let version = version?;
            return pypi_artifacts(path, Some(version), rest, net, cache)
                .into_iter()
                .find(|candidate| candidate.preferred)
                .map(|candidate| (p.clone(), candidate.url));
        }
        // AMO publishes the exact XPI URL in its API. A pinned PURL uses the
        // direct per-version endpoint; an unpinned one follows current_version
        // and is refined to the concrete version for provenance and cache keys.
        if ty == "firefox" {
            let (path, requested) = split_path_version(rest);
            let (version, url) = resolve_firefox(path, requested, net, cache)?;
            let locator =
                requested.map_or_else(|| format!("pkg:firefox/{path}@{version}"), |_| p.clone());
            return Some((locator, url));
        }
        // The AUR serves one artifact per package: the current PKGBUILD-tree
        // snapshot, addressed by *pkgbase* (a split package's snapshot lives
        // under its base, not its own name), which the RPC names exactly.
        // Snapshots track HEAD only, so a pinned version can't select an older
        // release — matching the github/HEAD and npm-latest stance of fetching
        // what the name serves right now. Three spellings route here, the same
        // set the registry lookup folds: `pkg:aur/<name>`, the spec
        // `pkg:alpm/arch/<name>?repository_url=https://aur.archlinux.org`, and
        // the legacy `pkg:alpm/aur/<name>`.
        if ty == "aur"
            || (ty == "alpm" && (p.contains("aur.archlinux.org") || rest.starts_with("aur/")))
        {
            let (path, _) = split_path_version(rest);
            let name = path.rsplit('/').next().unwrap_or(path);
            return Some((p.clone(), resolve_aur(name, net, cache)));
        }
        if let Some((path, version)) = rest.rsplit_once('@') {
            // Split any PURL `?qualifiers` off the version; the bare version is
            // what every download API actually wants.
            let (version, _) = split_version_kind(version);
            if ty == "composer" {
                return resolve_composer(path, version, net).map(|u| (p.clone(), u));
            }
        }
    }
    match locator {
        RefLocator::Purl(raw) => {
            let canonical = crate::purl::normalize(raw)?;
            resolve(&RefLocator::Purl(canonical.clone())).map(|url| (canonical, url))
        }
        _ => resolve(locator).map(|url| (locator_string(locator), url)),
    }
}

/// The AUR snapshot URL for `name`: ask the (cached) RPC for the package's
/// `URLPath`, which names the pkgbase snapshot. Falls back to the name-derived
/// snapshot path — correct whenever pkgbase == name — when the RPC is
/// unreachable or names no such package, so an RPC blip can't kill a fetch that
/// would have succeeded; a genuinely absent package then 404s at the snapshot,
/// recording a failed fetch rather than an unresolvable locator.
fn resolve_aur(name: &str, net: &dyn Fetch, cache: &BlobCache) -> String {
    let api = format!("https://aur.archlinux.org/rpc/v5/info?arg%5B%5D={name}");
    cached_metadata(&api, net, cache)
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|doc| {
            Some(format!(
                "https://aur.archlinux.org{}",
                doc.pointer("/results/0/URLPath")?.as_str()?
            ))
        })
        .unwrap_or_else(|| format!("https://aur.archlinux.org/cgit/aur.git/snapshot/{name}.tar.gz"))
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
#[cfg(test)]
fn resolve_npm_unversioned(path: &str, rest: &str, net: &dyn Fetch) -> Option<(String, String)> {
    resolve_npm_dist_tag(path, rest, "latest", net)
}

fn npm_version_is_concrete(version: &str) -> bool {
    let version = percent_decode(version);
    let version = version.strip_prefix('v').unwrap_or(&version);
    version
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_digit())
        && !version.bytes().any(|byte| {
            byte.is_ascii_whitespace()
                || matches!(
                    byte,
                    b'*' | b'x' | b'X' | b'<' | b'>' | b'=' | b'^' | b'~' | b'|'
                )
        })
}

fn resolve_npm_dist_tag(
    path: &str,
    rest: &str,
    tag: &str,
    net: &dyn Fetch,
) -> Option<(String, String)> {
    let name = npm_registry_name(path);
    let repository = repository_base(rest, "https://registry.npmjs.org")?;
    let packument = net.get(&format!("{repository}/{name}")).ok()?;
    let doc: serde_json::Value = serde_json::from_slice(&packument.bytes).ok()?;
    let version = doc.get("dist-tags")?.get(tag)?.as_str()?;
    let coordinate_tail = rest.strip_prefix(path).unwrap_or_default();
    let tail = if let Some(version_tail) = coordinate_tail.strip_prefix('@') {
        version_tail
            .find(['?', '#'])
            .map_or("", |index| &version_tail[index..])
    } else {
        coordinate_tail
    };
    let locator = format!("pkg:npm/{path}@{version}{tail}");
    let url = doc
        .get("versions")
        .and_then(|versions| versions.get(version))
        .and_then(|release| release.pointer("/dist/tarball"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .or_else(|| resolve_purl(&locator))?;
    if !file_name_matches(rest, &file_name_from_url(&url)) {
        return None;
    }
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
#[cfg(test)]
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
    pypi_artifacts(name, Some(version), &rest, net, cache)
        .into_iter()
        .find(|candidate| candidate.preferred)
        .map(|candidate| candidate.url)
}

/// Resolve a Firefox Add-ons slug to the XPI AMO serves. A requested version
/// goes through the immutable per-version endpoint, so an old pin can never be
/// silently replaced by the latest release. Without a version, the add-on
/// document's `current_version` supplies both the concrete version and file.
fn resolve_firefox(
    path: &str,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Option<(String, String)> {
    let slug = path.rsplit('/').next().unwrap_or(path);
    if slug.is_empty() {
        return None;
    }
    let (api, ttl) = match version {
        Some(v) => (
            format!("https://addons.mozilla.org/api/v5/addons/addon/{slug}/versions/{v}/"),
            META_TTL_IMMUTABLE,
        ),
        None => (
            format!("https://addons.mozilla.org/api/v5/addons/addon/{slug}/"),
            meta_ttl_unpinned(),
        ),
    };
    let bytes = cached_metadata(&api, net, &cache.with_meta_ttl(ttl))?;
    let json: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let release = if version.is_some() {
        &json
    } else {
        json.get("current_version")?
    };
    let resolved_version = release.get("version")?.as_str()?.to_string();
    // Defensive equality check: a malformed or surprising API response must
    // not substitute another release for an explicitly requested version.
    if version.is_some_and(|want| want != resolved_version) {
        return None;
    }
    let url = release.pointer("/file/url")?.as_str()?.to_string();
    Some((resolved_version, url))
}

/// Open VSX publishes the `.vsix` download URL in its JSON API. `rest` is
/// `<namespace>/<name>[@<version>]`; without a version the API returns the
/// latest release. Returns the `files.download` URL — the exact artifact a
/// client would install.
fn resolve_openvsx(rest: &str, net: &dyn Fetch) -> Option<String> {
    let (path, version) = split_path_version(rest);
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
    let (path, version) = split_path_version(rest);
    let version = version.map(str::to_string);
    let (publisher, name) = path.split_once('/')?;
    let version = match version {
        Some(v) => v,
        None => {
            // Built with the JSON writer, never `format!`: `publisher` and
            // `name` come from the PURL, so a `"` in either would otherwise
            // close the string literal and let the caller restructure the
            // query — returning some *other* extension's record under this
            // coordinate, which is exactly the judgement this feeds.
            let body = serde_json::to_vec(&serde_json::json!({
                "filters": [{"criteria": [{"filterType": 7, "value": format!("{publisher}.{name}")}]}],
                "flags": 914,
            }))
            .ok()?;
            let headers = [
                ("Content-Type", "application/json"),
                ("Accept", "application/json;api-version=3.0-preview.1"),
            ];
            let resp = net
                .post(
                    "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery",
                    &body,
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

/// GOPROXY case-encoding: every unescaped uppercase ASCII letter becomes `!`
/// followed by its lowercase form, so module paths can't collide on
/// case-insensitive file systems (`github.com/BurntSushi/toml` →
/// `github.com/!burnt!sushi/toml`).
///
/// A PURL is already percent-encoded. Its `%HH` triplets are URL escapes, not
/// native module text, and must pass through atomically: turning the `B` in
/// `%2B` into `!b` changes `+` into the invalid URL text `%2!b`. This matters
/// for every Go `+incompatible` version, and applies equally to escapes in a
/// module path or any future version spelling.
pub(crate) fn goproxy_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            let mut rest = chars.clone();
            if let (Some(hi), Some(lo)) = (rest.next(), rest.next())
                && hi.is_ascii_hexdigit()
                && lo.is_ascii_hexdigit()
            {
                out.push(c);
                out.push(hi);
                out.push(lo);
                chars = rest;
                continue;
            }
        }
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

fn verify_purl_checksum(locator: &str, bytes: &[u8], sha256_hex: &str) -> Option<bool> {
    let (_, rest) = crate::purl::scheme_type_rest(locator)?;
    let checksums = purl_checksums(rest);
    if checksums.is_empty() {
        return None;
    }
    let sha512 = checksums
        .contains_key("sha512")
        .then(|| hex::encode(Sha512::digest(bytes)));
    let mut unsupported = false;
    for (algorithm, expected) in checksums {
        let actual = match algorithm.as_str() {
            "sha256" => sha256_hex,
            "sha512" => sha512.as_deref().unwrap_or_default(),
            _ => {
                unsupported = true;
                continue;
            }
        };
        if !expected.eq_ignore_ascii_case(actual) {
            return Some(false);
        }
    }
    (!unsupported).then_some(true)
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
///
/// This is an allowlist-shaped problem solved with a denylist, because
/// `is_global` is still unstable. So it is written to fail closed on the
/// *spellings* of an internal address rather than on one canonical form: every
/// way v6 can carry a v4 destination is unwrapped and re-checked.
fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_v4(v4),
        IpAddr::V6(v6) => is_blocked_v6(v6),
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
        || v4.is_multicast() // 224.0.0.0/4
        || o[0] == 0 // 0.0.0.0/8
        || (o[0] == 100 && (64..=127).contains(&o[1])) // CGNAT 100.64.0.0/10
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // IETF protocol assignments
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // benchmarking 198.18.0.0/15
        || o[0] >= 240 // reserved 240.0.0.0/4
}

/// Whether an IPv6 address must not be fetched.
///
/// The transition mechanisms are the interesting part. Each one embeds an IPv4
/// destination that a translator or relay on the host's path will carry for
/// you, so each is a way to spell an internal v4 target in v6 — and a guard
/// that only understands `::ffff:a.b.c.d` waves the rest through. Rather than
/// ban the prefixes outright (which would break fletch on a NAT64-only
/// network, where reaching any public v4 host legitimately goes through
/// `64:ff9b::`), unwrap the embedded address and apply the v4 rules to it.
fn is_blocked_v6(v6: Ipv6Addr) -> bool {
    // Both v4-in-v6 forms: `::ffff:a.b.c.d` (mapped) and the deprecated
    // `::a.b.c.d` (compatible) that `to_ipv4_mapped` alone does not see. This
    // also subsumes `::1` and `::`, which unwrap into the blocked 0.0.0.0/8.
    if let Some(v4) = v6.to_ipv4() {
        return is_blocked_v4(v4);
    }
    let s = v6.segments();
    let embedded = |hi: u16, lo: u16| Ipv4Addr::from((u32::from(hi) << 16) | u32::from(lo));
    if s[0] == 0x2002 && is_blocked_v4(embedded(s[1], s[2])) {
        return true; // 6to4: 2002:<v4>::/48
    }
    if s[0] == 0x0064 && s[1] == 0xff9b && is_blocked_v4(embedded(s[6], s[7])) {
        return true; // NAT64 well-known prefix: 64:ff9b::<v4>/96
    }
    v6.is_loopback()
        || v6.is_unspecified()
        || v6.is_multicast() // ff00::/8
        || (s[0] & 0xfe00) == 0xfc00 // unique-local fc00::/7
        || (s[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
        || (s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0x0001) // NAT64 local-use /48
        || (s[0] == 0x2001 && s[1] == 0x0000) // Teredo 2001::/32
        || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation 2001:db8::/32
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
            // Re-checked on every hop, so a redirect can't escape the floor.
            guard_host(&current)?;
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

            let headers = response_headers(&resp);
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
        let headers = response_headers(&resp);
        let bytes = read_body_capped(resp)?;
        Ok(Fetched {
            bytes,
            final_url: target.to_string(),
            status: status.as_u16(),
            headers,
            redirects: Vec::new(),
        })
    }

    // The real-network backend is the one place container pulls are welcome:
    // the puller's public-registry allowlist covers the SSRF posture that
    // guard_host provides for plain URL fetches.
    fn allows_oci(&self) -> bool {
        true
    }
}

/// Response headers as owned pairs, dropping any whose value isn't text.
fn response_headers(resp: &reqwest::blocking::Response) -> Vec<(String, String)> {
    resp.headers()
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|val| (k.as_str().to_string(), val.to_string()))
        })
        .collect()
}

/// The pre-connect floor every request passes — each GET hop and the one POST:
/// https only, and refuse a literal-IP host the DNS resolver never sees (the
/// SSRF resolver guards hostname targets; a bare IP must be checked directly).
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
            ),
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
            resolved_target(&RefLocator::Purl(purl), &net, &cache).map(|(_, url)| url),
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
    fn split_version_kind_parses_purl_qualifiers() {
        assert_eq!(split_version_kind("1.2.3"), ("1.2.3", None));
        assert_eq!(
            split_version_kind("1.2.3?kind=wheel"),
            ("1.2.3", Some("wheel"))
        );
        assert_eq!(
            split_version_kind("1.2.3?kind=sdist"),
            ("1.2.3", Some("sdist"))
        );
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
            resolved_target(&override_purl, &Fixtures::default(), &BlobCache::disabled()),
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
            resolved_target(&wrong_file, &Fixtures::default(), &BlobCache::disabled()).is_none()
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
        assert!(resolved_target(&range, &net, &cache).is_none());
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
            ),
            Some(("pkg:firefox/surf-click@1.0.9".to_string(), xpi.to_string()))
        );
        assert_eq!(
            resolved_target(
                &RefLocator::Purl("pkg:firefox/surf-click".into()),
                &net,
                &cache
            ),
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
        assert_eq!(rec.resolved_url, xpi);
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
            ),
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
        assert_eq!(rec.resolved_url, "oci://docker.io/library/nginx:latest");
        match &rec.outcome {
            Outcome::Failed(e) => assert!(e.contains("not permitted"), "{e}"),
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
        // Canonical PURLs percent-encode `+`. The escape is already valid URL
        // syntax and GOPROXY's case transform must not rewrite its hex digits.
        assert_eq!(
            resolve(&RefLocator::Purl(
                "pkg:golang/github.com/gofrs/uuid@v4.4.0%2Bincompatible".into()
            )),
            Some(
                "https://proxy.golang.org/github.com/gofrs/uuid/@v/v4.4.0%2Bincompatible.zip"
                    .to_string()
            )
        );
        // The rule is about percent triplets, not this one suffix: escapes in
        // either component survive while ordinary uppercase text is encoded.
        assert_eq!(
            goproxy_escape("Example.com/A%2FB@v1%2bmeta"),
            "!example.com/!a%2F!b@v1%2bmeta"
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
        // regardless of `fetch_urls` — it follows the deps/packages policy.
        assert!(selected(&with_kind(url(), RefKind::Dependency), false));
        assert!(selected(&with_kind(url(), RefKind::Command), false));

        // An opportunistic URL fetch (a script's curl/wget) stays behind the flag.
        assert!(!selected(&with_kind(url(), RefKind::UrlFetch), false));
        assert!(selected(&with_kind(url(), RefKind::UrlFetch), true));

        // A package coordinate is always fetched; a repository is identity — its
        // non-fetch-target kind short-circuits `selected` before the locator.
        assert!(selected(&with_kind(purl(), RefKind::Dependency), false));
        assert!(!selected(&with_kind(url(), RefKind::Repository), true));
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
        // Every edge is stamped with its source endpoint and binding class.
        assert_eq!(recs[0].source_sha256, "trigsha");
        assert_eq!(recs[0].kind, RefKind::Dependency);

        // With fetch_urls: package + raw URL; the repository is never fetched.
        let recs = fetch_references(&refs, "trigsha", true, &net, &cache, FetchBudget::default());
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

        // Age the entry past the 12h unpinned TTL by backdating the recorded
        // fetch time — freshness is measured from `fetched_at`, not the file
        // mtime (which now tracks last access for the eviction sweep).
        let key = sha256_hex(b"pkg:npm/foo@1.0.0");
        let meta_path = dir.path().join(format!("{key}.json"));
        let mut meta: CachedMeta =
            serde_json::from_slice(&std::fs::read(&meta_path).expect("read meta")).expect("parse");
        meta.fetched_at = now() - 48 * 3600;
        std::fs::write(&meta_path, serde_json::to_vec(&meta).expect("serialize")).expect("write");

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
        for ext in ["zst", "json"] {
            let p = dir.path().join(format!("{key}.{ext}"));
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
        let blob = dir.path().join(format!("{key}.zst"));
        let mtime = std::fs::metadata(&blob).unwrap().modified().unwrap();
        assert!(
            mtime.elapsed().unwrap() < Duration::from_secs(120),
            "the cache hit refreshed the last-access mtime"
        );
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
    fn split_path_version_tolerates_misplaced_version() {
        // Spec order: version before qualifiers, qualifiers dropped.
        assert_eq!(
            split_path_version("arch/yay@1.0-1"),
            ("arch/yay", Some("1.0-1"))
        );
        assert_eq!(
            split_path_version("arch/yay@1.0-1?repository_url=https://aur.archlinux.org"),
            ("arch/yay", Some("1.0-1"))
        );
        assert_eq!(split_path_version("arch/yay"), ("arch/yay", None));
        // The non-spec `?qualifiers@version` ordering older hopper exports
        // emitted: the trailing version is still found.
        assert_eq!(
            split_path_version("arch/yay?repository_url=https://aur.archlinux.org@1.0-1"),
            ("arch/yay", Some("1.0-1"))
        );
        // A qualifier value containing `@` (URL userinfo) is not a version.
        assert_eq!(
            split_path_version("arch/yay?repository_url=https://user@example.com/repo"),
            ("arch/yay", None)
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
            assert_eq!(rec.resolved_url, snapshot, "{purl}");
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
        assert_eq!(rec.resolved_url, derived);
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
    fn a_cache_entry_that_expands_past_the_cap_is_a_miss() {
        // A zstd bomb planted in the cache directory: a few hundred bytes on
        // disk that expand without bound. It must read as a miss, not be
        // decompressed into memory. The cap is a parameter so this costs
        // kilobytes instead of the 256 MiB production ceiling.
        let dir = tempfile::tempdir().expect("tempdir");
        let blob = dir.path().join("bomb.zst");
        let bomb = zstd::encode_all(&vec![0u8; 1 << 20][..], 3).expect("compress");
        assert!(bomb.len() < 4096, "1 MiB of zeros should compress tiny");
        std::fs::write(&blob, &bomb).expect("plant");

        assert_eq!(
            read_blob_capped(&blob, 1024),
            None,
            "an entry expanding past the cap must not be served"
        );
        // The same entry is served whole when it fits.
        assert_eq!(
            read_blob_capped(&blob, 1 << 20).map(|b| b.len()),
            Some(1 << 20)
        );
        // A blob exactly at the ceiling is still valid — the `+1` read must not
        // reject the boundary case.
        let exact = dir.path().join("exact.zst");
        std::fs::write(&exact, zstd::encode_all(&b"12345"[..], 3).expect("c")).expect("w");
        assert_eq!(read_blob_capped(&exact, 5).map(|b| b.len()), Some(5));
        assert_eq!(read_blob_capped(&exact, 4), None);
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
        std::fs::create_dir_all(dir.path().join("refs")).expect("mkdir");
        let key = sha256_hex(b"some-locator");
        let blob = dir.path().join("refs").join(format!("{key}.zst"));
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
            // Alternate spellings of an internal v4 target. Each of these
            // reaches the same place as an entry above, via a translator or
            // relay, and each passed a guard that only unwrapped `::ffff:`.
            "::127.0.0.1",        // deprecated IPv4-compatible loopback
            "::169.254.169.254",  // IPv4-compatible cloud metadata
            "2002:7f00:1::",      // 6to4 wrapping 127.0.0.1
            "2002:a9fe:a9fe::",   // 6to4 wrapping 169.254.169.254
            "64:ff9b::7f00:1",    // NAT64 wrapping 127.0.0.1
            "64:ff9b::a9fe:a9fe", // NAT64 wrapping 169.254.169.254
            "64:ff9b:1::1",       // NAT64 local-use prefix
            "2001:0:1234::1",     // Teredo
            "2001:db8::1",        // documentation
            "ff02::1",            // multicast
            "224.0.0.1",          // v4 multicast
            "198.18.0.1",         // benchmarking range
            "192.0.0.1",          // IETF protocol assignments
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
            // A NAT64/6to4 wrapper around a *public* v4 stays reachable: on an
            // IPv6-only network that is the only route to it.
            "64:ff9b::8080:808", // NAT64 wrapping 8.8.8.8
            "2002:101:101::",    // 6to4 wrapping 1.1.1.1
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
    fn selector_enforces_npm_os_cpu_and_libc_constraints() {
        let body = br#"{"versions":{"1.0.0":{"os":["linux","!darwin"],"cpu":["x64"],"libc":"glibc","dist":{"tarball":"https://x/native.tgz"}}}}"#;
        let net = Fixtures::default().with("https://registry.npmjs.org/native", body);
        let matrix = resolve_artifacts(
            &RefLocator::Purl("pkg:npm/native@1.0.0".into()),
            &net,
            &BlobCache::disabled(),
        )
        .expect("npm matrix");
        let linux = ArtifactTarget {
            os: Some("linux".into()),
            arch: Some("x86_64".into()),
            libc: Some("glibc".into()),
            ..ArtifactTarget::default()
        };
        assert!(matrix.select(&linux, &SelectionPolicy::default()).is_some());
        let mac = ArtifactTarget {
            os: Some("darwin".into()),
            ..linux
        };
        assert!(matrix.select(&mac, &SelectionPolicy::default()).is_none());
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
            RefLocator::Purl("pkg:cargo/foo@1.0.0?checksum=sha1:0123456789abcdef".into()),
            None,
        );
        let record = fetch_ref(&reference, &net, &BlobCache::disabled());
        assert_eq!(record.outcome, Outcome::UnverifiablePin);
        assert_eq!(record.pin_verified, None);
    }

    #[test]
    fn one_supported_and_one_unsupported_checksum_is_unverifiable() {
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
        assert_eq!(record.outcome, Outcome::UnverifiablePin);
        assert_eq!(record.pin_verified, None);
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
}
