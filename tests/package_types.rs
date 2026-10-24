//! Download bytes identify their registry ecosystem even when cached by digest.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use filefacts::{FileId, RefKind, RefLocator, Reference};
use fletch::fetch::{BlobCache, Fixtures, Outcome, fetch_ref};

#[test]
fn package_downloads_keep_their_type_independently_of_the_filename() {
    let cases: &[(&str, &str, &[u8])] = &[
        (
            "crate",
            "cargo/demo",
            include_bytes!("data/package-types/crate.tar.gz"),
        ),
        (
            "pub",
            "pub/demo",
            include_bytes!("data/package-types/pub.tar.gz"),
        ),
        (
            "cran",
            "cran/demo",
            include_bytes!("data/package-types/cran.tar.gz"),
        ),
        (
            "cpan",
            "cpan/AUTHOR/Demo",
            include_bytes!("data/package-types/cpan.tar.gz"),
        ),
        (
            "hackage",
            "hackage/demo",
            include_bytes!("data/package-types/hackage.tar.gz"),
        ),
        (
            "hex",
            "hex/demo",
            include_bytes!("data/package-types/hex.tar"),
        ),
        (
            "composer",
            "composer/vendor/demo",
            include_bytes!("data/package-types/composer.zip"),
        ),
    ];
    let dir = tempfile::tempdir().unwrap();
    let cache = BlobCache::with_dir(dir.path());
    for (label, coordinate, data) in cases {
        // The exact-download qualifier is supported for every ecosystem and
        // deliberately supplies a URL without a format-bearing suffix.
        let url = format!("https://packages.example.test/download/{label}");
        let reference = Reference::new(
            RefLocator::Purl(format!("pkg:{coordinate}@1.2.3?download_url={url}")),
            RefKind::Dependency,
            "test",
            "",
        );
        let record = fetch_ref(&reference, &Fixtures::default().with(&url, data), &cache);
        assert!(matches!(record.outcome, Outcome::Ok), "{record:?}");
        let bytes = cache.load(&record.locator).expect("download cached");
        assert_eq!(FileId::from_bytes(&bytes).file_type().label(), *label);
    }
}
