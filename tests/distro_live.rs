//! Live, network-bound smoke tests for the distro index registries — they hit
//! real mirrors, so they are `#[ignore]`d and run on demand:
//!
//! ```sh
//! cargo test --test distro_live -- --ignored --nocapture
//! ```
//!
//! Their job is to catch what mocked unit tests can't: that the real
//! decompression (multi-stream gzip, zstd, xz), tar extraction, and streaming
//! index/XML scanning actually run end-to-end against the current upstream
//! layouts.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use fletch::fetch::{BlobCache, HttpFetch};
use fletch::{RefLocator, Registry, RegistryError, registry};

/// Each maps to a distinct decompression/parse path; assert the package resolved
/// with a plausible version so a broken pipeline (bad URL, format drift) fails
/// loudly rather than silently degrading to "unknown".
#[test]
#[ignore = "network"]
fn distro_indices_resolve_live() {
    let net = HttpFetch::new().expect("http client");
    // A fresh cache per run, so a stale copy from an earlier run never passes.
    let dir = tempfile::tempdir().expect("tempdir");
    let cache = BlobCache::with_dir(dir.path());
    let lookup = |purl: &str| -> Result<Registry, RegistryError> {
        registry::lookup(&RefLocator::Purl(purl.into()), &net, &cache)
    };
    let cases = [
        ("pkg:apk/alpine/curl", true),   // multi-stream gzip + tar + APKINDEX
        ("pkg:apk/wolfi/curl", true),    // same format; every build listed, the latest reported
        ("pkg:deb/debian/curl", false),  // gzip + control stanzas (no date)
        ("pkg:deb/ubuntu/curl", false),  // gzip + control stanzas
        ("pkg:rpm/opensuse/curl", true), // zstd + streaming primary.xml
        ("pkg:rpm/rpmfusion/ffmpeg", true), // gzip + streaming primary.xml (curl isn't in rpmfusion)
        ("pkg:freebsd/curl", false),        // zstd + tar + ndjson
        ("pkg:netbsd/curl", true),          // redirect + gzip + pkg_summary
        ("pkg:openbsd/curl", false),        // ls-style index listing
    ];
    for (purl, expect_date) in cases {
        let r = lookup(purl).unwrap_or_else(|e| panic!("{purl} did not resolve: {e}"));
        assert!(!r.version.is_empty(), "{purl} resolved with empty version");
        println!(
            "{purl:>26} -> {} v{}  date={:?}  home={:?}",
            r.ecosystem, r.version, r.published_at, r.homepage
        );
        if expect_date {
            assert!(r.published_at.is_some(), "{purl} should carry a build time");
        }
    }
    assert_eq!(
        lookup("pkg:apk/alpine/no-such-package-fletch-live").err(),
        Some(RegistryError::NotFound)
    );
}
