//! `fletch` — a thin command-line companion to the library.
//!
//! Two subcommands today:
//!
//! - `registry <purl>` — resolve, fetch, and normalize a package's registry
//!   metadata, printing a `{record, sources}` JSON envelope to stdout: the
//!   normalized [`fletch::Registry`] a consumer (scan) reasons over, plus the
//!   raw provider document(s) it was derived from, so the snapshot can be
//!   archived and re-normalized later without a re-fetch. Exit `2` when the
//!   ecosystem is unsupported or the registry can't be reached (empty stdout),
//!   so a caller can tell "no record" from a usage error (exit `1`).
//!
//! - `purl <purl>` — report, without any network I/O, how fletch reads one
//!   PURL: the parsed coordinates, the registry endpoint the type routes to,
//!   and the artifact URL the fetcher resolves. This is the cross-tool
//!   consistency surface hopper's `pkgparse` tests drive, so the generator and
//!   this fetcher can never silently drift apart.
//!
//! This exists so a non-Rust collector (forager) can obtain exactly the record
//! scan consumes, instead of maintaining a parallel, drifting metadata fetcher:
//! fletch is the single owner of how a PURL becomes a [`fletch::Registry`].

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use serde::Serialize;

use fletch::fetch::{BlobCache, HttpFetch, RecordedSource};
use fletch::{RefKind, RefLocator, Reference, Registry};

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
    // Reclaim stale/oversized blob-cache entries on a detached thread. Cheap and
    // self-gated to once a day; the cache is populated by consumers (scan), but
    // any process that links fletch can reclaim it.
    fletch::cache_sweep::cleanup();

    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("registry") => {
            let purl = args
                .next()
                .ok_or_else(|| anyhow::anyhow!("usage: fletch registry <purl>"))?;
            run_registry(&purl)
        }
        Some("purl") => {
            let purl = args
                .next()
                .ok_or_else(|| anyhow::anyhow!("usage: fletch purl <purl> | fletch purl -"))?;
            if purl == "-" {
                run_purl_batch()
            } else {
                run_purl(&purl)
            }
        }
        _ => {
            eprintln!("usage: fletch registry <purl> | fletch purl <purl>");
            std::process::exit(1);
        }
    }
}

/// The `purl` probe report: how fletch reads one PURL, with no network I/O.
/// `registry_url` is the first endpoint the registry lookup would contact
/// (evidence of which registry the type routes to; absent when the type is
/// unknown), `download_url` the artifact URL the fetcher resolved (absent when
/// resolution itself needs a live registry round-trip, e.g. PyPI).
#[derive(Serialize)]
struct PurlProbe {
    purl: String,
    #[serde(rename = "type")]
    typ: String,
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    /// [`fletch::purl::normalize`]d spelling — the canonical form; hopper's
    /// `pkgparse.CanonicalizePURL` must produce exactly this (crosscheck-tested).
    #[serde(skip_serializing_if = "Option::is_none")]
    normalized: Option<String>,
    /// [`fletch::purl::identity`] key form — what the bloom filters key on.
    #[serde(skip_serializing_if = "Option::is_none")]
    identity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    registry_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    download_url: Option<String>,
}

/// A [`fletch::fetch::Fetch`] backend that records every URL it is asked for
/// and refuses it, so the probe can observe routing without touching the
/// network.
#[derive(Default)]
struct ProbeNet(std::sync::Mutex<Vec<String>>);

impl fletch::fetch::Fetch for ProbeNet {
    fn get(&self, url: &str) -> Result<fletch::fetch::Fetched, fletch::fetch::FetchError> {
        if let Ok(mut seen) = self.0.lock() {
            seen.push(url.to_string());
        }
        Err(fletch::fetch::FetchError::Refused("probe".into()))
    }

    // The VS Code Marketplace query is a POST; record it too, so the probe
    // reports that route instead of an empty answer.
    fn post(
        &self,
        url: &str,
        _body: &[u8],
        _headers: &[(&str, &str)],
    ) -> Result<fletch::fetch::Fetched, fletch::fetch::FetchError> {
        if let Ok(mut seen) = self.0.lock() {
            seen.push(url.to_string());
        }
        Err(fletch::fetch::FetchError::Refused("probe".into()))
    }
}

/// Batch form of [`run_purl`]: one PURL per stdin line, one JSON probe per
/// stdout line, in order. A line that doesn't parse still emits a probe (just
/// the `purl` field) rather than aborting, so a differential sweep can push
/// thousands of adversarial inputs through a single process.
fn run_purl_batch() -> anyhow::Result<()> {
    let stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();
    for line in std::io::BufRead::lines(stdin) {
        let purl = line?;
        let probe_out = probe_purl(&purl);
        serde_json::to_writer(&mut stdout, &probe_out)?;
        stdout.write_all(b"\n")?;
    }
    stdout.flush()?;
    Ok(())
}

/// Report how fletch parses, routes, and resolves one PURL — offline. Exit `2`
/// (empty stdout) when the string doesn't parse as a PURL at all, so a caller
/// can tell "not a purl" from a usage error (exit `1`).
///
/// This is the cross-tool consistency surface: hopper's `pkgparse` tests feed
/// the PURLs it generates through this subcommand and assert fletch reads back
/// the same coordinates and knows where to fetch them.
fn run_purl(purl: &str) -> anyhow::Result<()> {
    if fletch::registry::parse_purl(purl).is_none() {
        std::process::exit(2);
    }
    print_json(&probe_purl(purl))
}

/// Write one JSON document as a line on stdout — the shape both subcommands
/// answer in.
fn print_json(value: &impl Serialize) -> anyhow::Result<()> {
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, value)?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}

/// Assemble the offline probe for one PURL. Every field but `purl` is empty or
/// absent when the corresponding read fails, so batch callers see one probe
/// per input no matter how malformed the input is.
fn probe_purl(purl: &str) -> PurlProbe {
    let (typ, path, version) = fletch::registry::parse_purl(purl).unwrap_or_default();
    let cache = BlobCache::disabled();
    let locator = RefLocator::Purl(purl.to_string());

    // Route probe: the first URL the registry lookup asks for names the
    // registry this type resolves to; the probe refuses it, so nothing is
    // actually fetched.
    let probe = ProbeNet::default();
    let _ = fletch::registry(&locator, &probe, &cache);
    let registry_url = probe.0.lock().ok().and_then(|seen| seen.first().cloned());

    // Resolution probe: run the real fetch path against the refusing backend.
    // A resolvable PURL surfaces its download URL on the (expectedly failed)
    // record; `Unresolved` means the fetcher has no artifact mapping.
    let reference = Reference {
        locator,
        kind: RefKind::Dependency,
        source: "cli".to_string(),
        evidence: String::new(),
        offset: 0,
        pinned_hash: None,
        content_sha256: None,
    };
    let rec = fletch::fetch::fetch_ref(&reference, &ProbeNet::default(), &cache);
    let download_url = (!rec.resolved_url.is_empty()).then(|| rec.resolved_url.clone());

    PurlProbe {
        purl: purl.to_string(),
        typ,
        path,
        version,
        normalized: fletch::purl::normalize(purl),
        identity: fletch::purl::identity(purl),
        registry_url,
        download_url,
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

    print_json(&Envelope {
        record: record.with_age(now),
        sources: sources.into_iter().map(source_from_recorded).collect(),
    })
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
