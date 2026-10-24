//! A fetched Go proxy response keeps its type even when cached by digest.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use filefacts::{FileId, FileType, RefKind, RefLocator, Reference};
use fletch::fetch::{BlobCache, Fixtures, Outcome, fetch_ref};
use std::path::Path;

#[test]
fn go_module_purl_download_is_identified_from_bytes() {
    let data = include_bytes!("data/go-module-stream.zip");
    let url = "https://proxy.golang.org/example.com/hello/@v/v1.2.3.zip";
    let net = Fixtures::default().with(url, data).with(
        "https://proxy.golang.org/example.com/hello/@v/v1.2.3.info",
        br#"{"Version":"v1.2.3"}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let cache = BlobCache::with_dir(dir.path());
    let reference = Reference::new(
        RefLocator::Purl("pkg:golang/example.com/hello@v1.2.3".into()),
        RefKind::Dependency,
        "test",
        "",
    );
    let record = fetch_ref(&reference, &net, &cache);
    assert!(matches!(record.outcome, Outcome::Ok), "{record:?}");
    let bytes = cache.load(&record.locator).expect("download cached");
    for name in ["v1.2.3.zip", record.content_sha256.as_deref().unwrap()] {
        assert_eq!(
            FileId::from_path_and_bytes(Path::new(name), &bytes).file_type(),
            FileType::GoModule
        );
    }
}
