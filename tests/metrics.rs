//! The metric events a deployment counts, as a subscriber sees them.

use fletch::fetch::{BlobCache, Fixtures, fetch_ref};
use fletch::metrics::TARGET;
use fletch::{RefKind, RefLocator, Reference};
use std::sync::{Arc, Mutex, PoisonError};
use tracing::field::{Field, Visit};
use tracing::span;

/// A subscriber that keeps each metric event's fields as text.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<Vec<(String, String)>>>>);

struct Fields(Vec<(String, String)>);

impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0
            .push((field.name().to_string(), format!("{value:?}")));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.push((field.name().to_string(), value.to_string()));
    }
}

impl tracing::Subscriber for Capture {
    fn register_callsite(
        &self,
        _: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::sometimes()
    }

    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.target() == TARGET
    }

    fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }

    fn record(&self, _: &span::Id, _: &span::Record<'_>) {}

    fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut fields = Fields(Vec::new());
        event.record(&mut fields);
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(fields.0);
    }

    fn enter(&self, _: &span::Id) {}

    fn exit(&self, _: &span::Id) {}
}

/// The events captured, each reduced to the named fields it carries.
fn events(capture: &Capture, names: &[&str]) -> Vec<Vec<String>> {
    capture
        .0
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .map(|fields| {
            names
                .iter()
                .map(|name| {
                    fields
                        .iter()
                        .find(|(n, _)| n == name)
                        .map_or_else(|| "-".to_string(), |(_, v)| v.clone())
                })
                .collect()
        })
        .collect()
}

#[test]
fn fetches_lookups_and_reads_are_counted() {
    let dep = |purl: &str| Reference {
        locator: RefLocator::Purl(purl.into()),
        kind: RefKind::Dependency,
        source: "test".into(),
        evidence: String::new(),
        offset: 0,
        pinned_hash: None,
        content_sha256: None,
    };
    let tarball = "https://registry.npmjs.org/a/-/a-1.0.0.tgz";
    let net = Fixtures::default()
        .with(tarball, b"bytes")
        .refusing("https://registry.npmjs.org/b/-/b-1.0.0.tgz", 404)
        .refusing("https://pypi.org/pypi/gone/json", 404);
    let dir = tempfile::tempdir().expect("tempdir");
    let cache = BlobCache::with_dir(dir.path().to_path_buf());
    let capture = Capture::default();
    // A process of its own (this file), and a global subscriber: under a
    // thread-local one, tests elsewhere touching the same callsites race
    // tracing's interest cache and events go missing.
    tracing::subscriber::set_global_default(capture.clone()).expect("first subscriber");
    {
        let _ = fetch_ref(&dep("pkg:npm/a@1.0.0"), &net, &cache);
        let _ = fetch_ref(&dep("pkg:npm/a@1.0.0"), &net, &cache);
        let _ = fetch_ref(&dep("pkg:npm/b@1.0.0"), &net, &cache);
        let _ = fetch_ref(&dep("pkg:swift/x/y@1.0.0"), &net, &cache);
        let _ = fletch::try_registry(&RefLocator::Purl("pkg:pypi/gone".into()), &net, &cache);
    }
    assert_eq!(
        events(
            &capture,
            &[
                "event",
                "ecosystem",
                "outcome",
                "detail",
                "status",
                "served",
                "bytes"
            ]
        ),
        [
            ["fetch", "npm", "ok", "-", "200", "network", "5"],
            ["fetch", "npm", "ok", "-", "200", "cache", "5"],
            ["fetch", "npm", "failed", "status", "404", "-", "-"],
            ["fetch", "swift", "unresolved", "unsupported", "-", "-", "-"],
            ["metadata", "-", "-", "-", "-", "failed", "-"],
            ["registry", "pypi", "-", "-", "-", "-", "-"],
        ]
        .map(|row| row.map(str::to_string).to_vec())
    );
    assert_eq!(
        events(&capture, &["event", "host", "result"])[4..],
        [
            ["metadata", "pypi.org", "-"],
            ["registry", "-", "not_found"],
        ]
        .map(|row| row.map(str::to_string).to_vec())
    );
}
