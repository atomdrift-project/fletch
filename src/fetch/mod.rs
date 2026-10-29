//! Resolve external references to URLs, retrieve them safely, cache them, and
//! record rich provenance.
//!
//! [`HttpFetch`] is the real backend; its SSRF guard lives in a custom DNS
//! resolver (`SafeResolver`) that refuses any host resolving to a private /
//! loopback / link-local / metadata address, re-checked on every redirect hop.
//! `Fixtures` (feature `test-util`) is the offline backend for tests. No recognition logic lives
//! here — references come in, bytes and [`FetchRecord`]s go out.
//!
//! - [`resolve`] and [`resolve_artifacts`] map a locator to its artifact URL
//!   and the registry's artifact variants, through one per-ecosystem table.
//! - [`fetch_ref`] fetches, verifies and records one reference.
//! - [`fetch_references`] fetches a file's references concurrently under a
//!   run-wide [`FetchBudget`].

use std::time::{SystemTime, UNIX_EPOCH};

use filefacts::RefLocator;
use sha2::{Digest, Sha256};

mod batch;
pub(crate) mod cache;
mod coordinate;
mod coverage;
mod go_hash;
mod record;
mod requirement;
mod resolve;
mod select;
mod ssrf;
mod transport;
mod verify;

#[cfg(test)]
mod tests;

pub use batch::{FetchBudget, UrlFetches, fetch_references};
pub use cache::{BlobCache, RawSink, RecordedSource, refs_dir};
pub(crate) use cache::{
    CachedMeta, META_TTL_IMMUTABLE, cached_github_api, cached_metadata, cached_metadata_status,
    cached_post, store_metadata,
};
pub(crate) use coordinate::{
    is_crates_io, is_http_url, is_web_scheme, percent_decode, repository_base, safe_coordinate,
    safe_filename_part, safe_purl_coordinates, url_host_is,
};
pub use coverage::{CandidateSource, Coverage};
pub use record::{FetchRecord, Outcome, Served, Unresolved, fetch_ref};
pub use requirement::{prefer_lock_pin, resolve_declared_reference};
pub(crate) use resolve::deterministic_artifacts;
pub use resolve::{ResolveError, resolve, resolve_artifacts};
pub use select::{ArtifactCandidate, ArtifactKind, ArtifactMatrix};
pub(crate) use select::{
    artifact_candidate, file_name_from_url, file_name_matches, purl_checksums,
};
#[cfg(any(test, feature = "test-util"))]
pub use transport::Fixtures;
pub use transport::{
    DEFAULT_MAX_FETCH_BYTES, Fetch, FetchError, Fetched, HttpFetch, Method, Request,
};

/// The locator's text: the PURL, URL or path as written. Empty for a locator
/// kind this fletch predates, which names nothing it can fetch or cite.
pub(crate) fn locator_str(locator: &RefLocator) -> &str {
    match locator {
        RefLocator::Purl(s) | RefLocator::Url(s) | RefLocator::Path(s) => s,
        _ => "",
    }
}

/// SHA-256 of `data`, lowercase hex.
pub(crate) fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// The current Unix time in seconds; 0, logged, on a clock set before 1970.
pub(crate) fn now() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(elapsed) => elapsed.as_secs(),
        Err(e) => {
            tracing::warn!(error = %e, "system clock is before the Unix epoch; recording time 0");
            0
        }
    }
}
