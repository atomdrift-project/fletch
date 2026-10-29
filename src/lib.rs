//! fletch — find and fetch the external references discovered in analyzed files.
//!
//! filefacts owns *parsing* and the declared dependencies it can read straight
//! out of a manifest, plus the [`filefacts::Reference`] vocabulary everyone
//! speaks. fletch owns the rest: the fuzzy *discovery* of undeclared/imperative
//! references (a `curl … | sh`, an `npm install` in a `RUN`, a URL stashed in a
//! shell variable) and the *retrieval* of every reference, declared or not.
//!
//! Three modules, deliberately walled apart so the dangerous half stays
//! auditable:
//! - [`find`] — recognition over filefacts facts. Heuristic, evolving.
//! - [`fetch`] — resolve a reference to a URL, retrieve it through an
//!   SSRF-guarded client, cache it, verify any pin, record provenance. Pure
//!   mechanism; no recognition logic ever leaks in here.
//! - [`registry`] — look up and normalize a package's *registry metadata*
//!   (publish date, author, downloads, rating) across ecosystems into a
//!   [`filefacts::Registry`], so a consumer can judge a dependency before paying
//!   to fetch and analyze its bytes.
//!
//! Beside them, [`purl`] parses and normalizes package URLs, [`metrics`] names
//! the events a deployment counts, and [`cache_sweep`] keeps the blob cache
//! within its budget.
//!
//! Consumers compose: analyze a file → [`find`] its references → [`fetch`]
//! them → analyze what came back. fletch never analyzes; it finds and fetches.
//!
//! A registry lookup, against a canned backend so it runs offline:
//!
//! ```
//! use fletch::fetch::{BlobCache, Fixtures};
//! use fletch::{RefLocator, registry};
//!
//! let packument = br#"{"dist-tags":{"latest":"1.3.0"},
//!     "time":{"1.3.0":"2021-04-23T10:00:00Z"},"versions":{"1.3.0":{}}}"#;
//! let net = Fixtures::default().with("https://registry.npmjs.org/left-pad", packument);
//! let locator = RefLocator::Purl("pkg:npm/left-pad@1.3.0".into());
//! let record = registry::lookup(&locator, &net, &BlobCache::disabled())?;
//! assert_eq!(record.published_at, Some(1_619_172_000));
//! # Ok::<(), fletch::RegistryError>(())
//! ```

pub mod cache_sweep;
mod distro;
mod ecosystem;
pub mod fetch;
pub mod find;
pub mod metrics;
mod oci;
pub mod purl;
pub mod registry;

// The reference vocabulary fletch's public API speaks, re-exported so consumers
// need not depend on filefacts directly just to name these types.
pub use filefacts::{HashAlgo, PinnedHash, RefKind, RefLocator, Reference, Registry};
pub use registry::RegistryError;
