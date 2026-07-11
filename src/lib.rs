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
//!   to fetch and scan its bytes.
//!
//! Consumers compose: analyze a file (cleave) → [`find`] its references →
//! [`fetch`] them → analyze what came back. fletch never analyzes; it finds and
//! fetches.

pub mod distro;
pub mod fetch;
pub mod find;
mod oci;
pub mod purl;
pub mod registry;

// The reference vocabulary fletch's public API speaks, re-exported so consumers
// (e.g. scan) need not depend on filefacts directly just to name these types.
pub use filefacts::{HashAlgo, PinnedHash, RefKind, RefLocator, Reference, Registry};
pub use purl::url_to_purl;
pub use registry::{registry, registry_with_sources};
