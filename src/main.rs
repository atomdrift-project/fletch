//! `fletch` — a thin command-line companion to the library.
//!
//! One subcommand today:
//!
//! - `registry <purl>` — resolve, fetch, and normalize a package's registry
//!   metadata, printing a `{record, sources}` JSON envelope to stdout: the
//!   normalized [`fletch::Registry`] a consumer (scan) reasons over, plus the
//!   raw provider document(s) it was derived from, so the snapshot can be
//!   archived and re-normalized later without a re-fetch. Exit `2` when the
//!   ecosystem is unsupported or the registry can't be reached (empty stdout),
//!   so a caller can tell "no record" from a usage error (exit `1`).
//!
//! This exists so a non-Rust collector (forager) can obtain exactly the record
//! scan consumes, instead of maintaining a parallel, drifting metadata fetcher:
//! fletch is the single owner of how a PURL becomes a [`fletch::Registry`].

use std::cell::RefCell;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use serde::Serialize;

use fletch::Registry;
use fletch::RefLocator;
use fletch::fetch::{BlobCache, Fetch, FetchError, Fetched, HttpFetch};

/// The CLI envelope: the normalized record scan consumes, alongside the raw
/// provider responses it was derived from (archived for forensics / re-parsing).
#[derive(Serialize)]
struct Envelope {
    record: Registry,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    sources: Vec<Source>,
}

/// One raw provider document observed while building the record. `body` carries
/// it verbatim when it parses as JSON (the common case — npm, PyPI, crates, …);
/// otherwise `body_b64` holds the bytes (an HTML listing, a compressed index).
#[derive(Serialize, Clone)]
struct Source {
    url: String,
    status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body_b64: Option<String>,
}

/// A [`Fetch`] decorator that records every successful response flowing through
/// it. Wrapping the real client (with the cache disabled, so every lookup hits
/// the network) lets the CLI capture the raw source documents `registry()`
/// fetches without threading collection through each per-ecosystem normalizer.
struct Recorder<'a> {
    inner: &'a dyn Fetch,
    sources: RefCell<Vec<Source>>,
}

impl<'a> Recorder<'a> {
    fn new(inner: &'a dyn Fetch) -> Self {
        Self {
            inner,
            sources: RefCell::new(Vec::new()),
        }
    }

    fn record(&self, f: &Fetched) {
        let content_type = f
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.clone());
        let (body, body_b64) = match serde_json::from_slice::<serde_json::Value>(&f.bytes) {
            Ok(v) => (Some(v), None),
            Err(_) => (
                None,
                Some(base64::engine::general_purpose::STANDARD.encode(&f.bytes)),
            ),
        };
        self.sources.borrow_mut().push(Source {
            url: f.final_url.clone(),
            status: f.status,
            content_type,
            body,
            body_b64,
        });
    }
}

impl Fetch for Recorder<'_> {
    fn get(&self, url: &str) -> Result<Fetched, FetchError> {
        let r = self.inner.get(url);
        if let Ok(f) = &r {
            self.record(f);
        }
        r
    }

    fn get_with(&self, url: &str, headers: &[(&str, &str)]) -> Result<Fetched, FetchError> {
        let r = self.inner.get_with(url, headers);
        if let Ok(f) = &r {
            self.record(f);
        }
        r
    }

    fn post(&self, url: &str, body: &[u8], headers: &[(&str, &str)]) -> Result<Fetched, FetchError> {
        let r = self.inner.post(url, body, headers);
        if let Ok(f) = &r {
            self.record(f);
        }
        r
    }
}

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("registry") => {
            let purl = args
                .next()
                .ok_or_else(|| anyhow::anyhow!("usage: fletch registry <purl>"))?;
            run_registry(&purl)
        }
        _ => {
            eprintln!("usage: fletch registry <purl>");
            std::process::exit(1);
        }
    }
}

fn run_registry(purl: &str) -> anyhow::Result<()> {
    let net = HttpFetch::new()?;
    // Disable the on-disk cache so every metadata fetch reaches the network and
    // flows through the recorder — otherwise a cache hit would yield the record
    // with no captured `sources`. A registry lookup hits each endpoint once, so
    // there is nothing to cache within a single invocation anyway.
    let cache = BlobCache::disabled();
    let recorder = Recorder::new(&net);

    let locator = RefLocator::Purl(purl.to_string());
    let Some(record) = fletch::registry(&locator, &recorder, &cache) else {
        // Unsupported ecosystem or the registry couldn't be reached: no record.
        std::process::exit(2);
    };

    // Stamp the wall-clock-relative signals at collection time — the producer's
    // one chance, since `release_times` is transient and never serialized. A
    // consumer can still re-derive plain age from `published_at` at scan time.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| anyhow::anyhow!("system clock before unix epoch: {e}"))?
        .as_secs();

    let envelope = Envelope {
        record: record.with_age(now),
        sources: recorder.sources.into_inner(),
    };

    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &envelope)?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{Fetch, FetchError, Fetched, Recorder};

    /// A backend that returns a fixed response, to exercise the recorder without
    /// touching the network.
    struct Stub {
        bytes: Vec<u8>,
        content_type: Option<&'static str>,
    }

    impl Fetch for Stub {
        fn get(&self, url: &str) -> Result<Fetched, FetchError> {
            Ok(Fetched {
                bytes: self.bytes.clone(),
                final_url: url.to_string(),
                status: 200,
                headers: self
                    .content_type
                    .map(|ct| vec![("Content-Type".to_string(), ct.to_string())])
                    .unwrap_or_default(),
                redirects: Vec::new(),
            })
        }
    }

    #[test]
    fn records_json_source_inline() {
        let stub = Stub {
            bytes: br#"{"hello":"world"}"#.to_vec(),
            content_type: Some("application/json"),
        };
        let rec = Recorder::new(&stub);
        let f = rec.get("https://registry.example/pkg").unwrap();
        assert_eq!(f.status, 200);

        let sources = rec.sources.into_inner();
        assert_eq!(sources.len(), 1);
        let s = &sources[0];
        assert_eq!(s.url, "https://registry.example/pkg");
        assert_eq!(s.status, 200);
        assert_eq!(s.content_type.as_deref(), Some("application/json"));
        // A JSON body is preserved verbatim, not base64-wrapped.
        assert_eq!(s.body.as_ref().unwrap()["hello"], "world");
        assert!(s.body_b64.is_none());
    }

    #[test]
    fn base64_encodes_non_json_source() {
        let stub = Stub {
            bytes: b"<html>a chrome listing, not json</html>".to_vec(),
            content_type: Some("text/html"),
        };
        let rec = Recorder::new(&stub);
        rec.get("https://store.example/detail/x").unwrap();

        let sources = rec.sources.into_inner();
        assert_eq!(sources.len(), 1);
        // Non-JSON bytes fall back to base64 so nothing is lost or corrupted.
        assert!(sources[0].body.is_none());
        assert!(sources[0].body_b64.is_some());
    }
}
