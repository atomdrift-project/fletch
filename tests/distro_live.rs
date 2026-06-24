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
use fletch::{RefLocator, Registry, registry};

fn lookup(purl: &str) -> Option<Registry> {
    let net = HttpFetch::new().expect("http client");
    let cache = BlobCache::with_dir(std::env::temp_dir().join("fletch-distro-live"));
    registry(&RefLocator::Purl(purl.into()), &net, &cache)
}

/// Each maps to a distinct decompression/parse path; assert the package resolved
/// with a plausible version so a broken pipeline (bad URL, format drift) fails
/// loudly rather than silently degrading to "unknown".
#[test]
#[ignore = "network"]
fn distro_indices_resolve_live() {
    let cases = [
        ("pkg:alpine/curl", true),      // multi-stream gzip + tar + APKINDEX
        ("pkg:wolfi/curl", false),      // same format; this build's time is unset (t:0)
        ("pkg:debian/curl", false),     // gzip + control stanzas (no date)
        ("pkg:ubuntu/curl", false),     // gzip + control stanzas
        ("pkg:opensuse/curl", true),    // zstd + streaming primary.xml
        ("pkg:rpmfusion/ffmpeg", true), // gzip + streaming primary.xml (curl isn't in rpmfusion)
        ("pkg:freebsd/curl", false),    // zstd + tar + ndjson
        ("pkg:netbsd/curl", true),      // redirect + gzip + pkg_summary
        ("pkg:openbsd/curl", false),    // ls-style index listing
    ];
    for (purl, expect_date) in cases {
        let r = lookup(purl).unwrap_or_else(|| panic!("{purl} did not resolve"));
        assert!(!r.version.is_empty(), "{purl} resolved with empty version");
        println!(
            "{purl:>20} -> {} v{}  date={:?}  home={:?}",
            r.ecosystem, r.version, r.published_at, r.homepage
        );
        if expect_date {
            assert!(r.published_at.is_some(), "{purl} should carry a build time");
        }
    }
}
