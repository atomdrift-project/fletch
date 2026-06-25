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

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use serde::Serialize;

use fletch::Registry;
use fletch::RefLocator;
use fletch::fetch::{BlobCache, HttpFetch, RecordedSource};

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

/// Map a recorded raw document onto the CLI's [`Source`] shape: a JSON body
/// inline (the common npm/PyPI/crates case), anything else base64 in `body_b64`.
fn source_from_recorded(s: RecordedSource) -> Source {
    let (body, body_b64) = match serde_json::from_slice::<serde_json::Value>(&s.bytes) {
        Ok(v) => (Some(v), None),
        Err(_) => (
            None,
            Some(base64::engine::general_purpose::STANDARD.encode(&s.bytes)),
        ),
    };
    Source {
        url: s.url,
        status: s.status,
        content_type: s.content_type,
        body,
        body_b64,
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
    // Disable the on-disk cache so every metadata document is fetched fresh and
    // recorded — a cache hit would still be recorded, but a disabled cache keeps
    // the CLI's snapshot current rather than serving a stale prior run.
    let cache = BlobCache::disabled();

    let locator = RefLocator::Purl(purl.to_string());
    let (record, sources) = fletch::registry_with_sources(&locator, &net, &cache);
    let Some(record) = record else {
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
        sources: sources.into_iter().map(source_from_recorded).collect(),
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
    use super::source_from_recorded;
    use fletch::fetch::RecordedSource;

    #[test]
    fn maps_json_source_inline() {
        let source = source_from_recorded(RecordedSource {
            url: "https://registry.example/pkg".to_string(),
            status: 200,
            content_type: Some("application/json".to_string()),
            bytes: br#"{"hello":"world"}"#.to_vec(),
        });
        assert_eq!(source.url, "https://registry.example/pkg");
        assert_eq!(source.status, 200);
        assert_eq!(source.content_type.as_deref(), Some("application/json"));
        // A JSON body is preserved verbatim, not base64-wrapped.
        assert_eq!(source.body.as_ref().unwrap()["hello"], "world");
        assert!(source.body_b64.is_none());
    }

    #[test]
    fn maps_non_json_source_to_base64() {
        let source = source_from_recorded(RecordedSource {
            url: "https://store.example/detail/x".to_string(),
            status: 200,
            content_type: Some("text/html".to_string()),
            bytes: b"<html>a chrome listing, not json</html>".to_vec(),
        });
        // Non-JSON bytes fall back to base64 so nothing is lost or corrupted.
        assert!(source.body.is_none());
        assert!(source.body_b64.is_some());
    }
}
