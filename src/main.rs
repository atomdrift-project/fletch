//! `fletch` — a thin command-line companion to the library.
//!
//! - `registry <purl>` — resolve, fetch, and normalize a package's registry
//!   metadata, printing a `{record, sources}` JSON envelope to stdout: the
//!   normalized [`fletch::Registry`], plus the raw provider document(s) it was
//!   derived from, so the snapshot can be archived and re-normalized later
//!   without a re-fetch. This lets a non-Rust collector obtain exactly the
//!   record the library produces instead of maintaining a parallel metadata
//!   fetcher.
//!
//! - `purl <purl>` — report, without any network I/O, how fletch reads one
//!   PURL: the parsed coordinates, the registry endpoint the type routes to,
//!   and the artifact URL the fetcher resolves. `purl -` reads one PURL per
//!   stdin line and answers one JSON probe per line. A PURL generator can
//!   test against this to stay consistent with the fetcher.
//!
//! Exit status: `0` on success; `1` for a usage error or an I/O failure; `2`
//! when the argument is not a package URL or the registry has no record for
//! it (stdout empty, the reason on stderr).

use std::io::Write;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use serde::Serialize;

use fletch::fetch::{BlobCache, HttpFetch, RecordedSource};
use fletch::purl::Purl;
use fletch::{RefKind, RefLocator, Reference, Registry, registry};

const USAGE: &str = "\
usage: fletch registry <purl>
       fletch purl <purl>
       fletch purl -
       fletch --help | --version

Diagnostics go to stderr at the level FLETCH_LOG names
(error, warn, info, debug, trace; default warn).
";

/// Send the library's `tracing` events to stderr at the level `FLETCH_LOG`
/// names, `warn` when unset or unrecognized; stdout stays the JSON channel.
fn init_logging() {
    let level = std::env::var("FLETCH_LOG")
        .ok()
        .and_then(|level| {
            level
                .parse::<tracing_subscriber::filter::LevelFilter>()
                .ok()
        })
        .unwrap_or(tracing_subscriber::filter::LevelFilter::WARN);
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(level)
        .init();
}

/// Exit status for an argument that is not a package URL, or a package with
/// no registry record.
const NO_RECORD: u8 = 2;

fn main() -> ExitCode {
    init_logging();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let outcome = match args.as_slice() {
        ["-h" | "--help"] => {
            print!("{USAGE}");
            Ok(ExitCode::SUCCESS)
        }
        ["-V" | "--version"] => {
            println!("fletch {}", env!("CARGO_PKG_VERSION"));
            Ok(ExitCode::SUCCESS)
        }
        ["registry", purl] => run_registry(purl),
        ["purl", "-"] => run_purl_batch(),
        ["purl", purl] => run_purl(purl),
        _ => {
            eprint!("{USAGE}");
            Ok(ExitCode::FAILURE)
        }
    };
    outcome.unwrap_or_else(|error| {
        eprintln!("fletch: {error:#}");
        ExitCode::FAILURE
    })
}

/// The CLI envelope: the normalized record, alongside the raw provider
/// responses it was derived from (archived for forensics / re-parsing).
#[derive(Serialize)]
struct Envelope {
    record: Registry,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    sources: Vec<Source>,
}

/// One raw provider document observed while building the record. `body` carries
/// it verbatim when it parses as JSON (the common case — npm, PyPI, crates, …);
/// otherwise `body_b64` holds the bytes (an HTML listing, a compressed index).
/// A document over the cache's source limit carries neither, and `truncated`.
#[derive(Serialize, Clone)]
struct Source {
    url: String,
    status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,
    size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body_b64: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    truncated: bool,
}

/// Map a recorded raw document onto the CLI's [`Source`] shape: a JSON body
/// inline, anything else base64 in `body_b64`, and no body at all for a
/// document whose bytes were not kept.
fn source_from_recorded(s: RecordedSource) -> Source {
    let (body, body_b64) = match &s.bytes {
        None => (None, None),
        Some(bytes) => match serde_json::from_slice::<serde_json::Value>(bytes) {
            Ok(v) => (Some(v), None),
            Err(_) => (
                None,
                Some(base64::engine::general_purpose::STANDARD.encode(bytes)),
            ),
        },
    };
    Source {
        truncated: s.bytes.is_none(),
        url: s.url,
        status: s.status,
        content_type: s.content_type,
        size: s.size,
        body,
        body_b64,
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
    /// [`fletch::purl::normalize`]d spelling — the canonical form.
    #[serde(skip_serializing_if = "Option::is_none")]
    normalized: Option<String>,
    /// [`fletch::purl::identity`] key form — the package's identity key.
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
    fn send(
        &self,
        request: &fletch::fetch::Request<'_>,
    ) -> Result<fletch::fetch::Fetched, fletch::fetch::FetchError> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(request.url.to_string());
        Err(fletch::fetch::FetchError::Refused("probe".into()))
    }
}

/// `purl <purl>`: print the probe for one PURL, or exit `2` with the reason
/// when it is not a package URL.
fn run_purl(purl: &str) -> anyhow::Result<ExitCode> {
    if let Err(error) = Purl::parse(purl) {
        // Escaped: the PURL is often feed data, and may carry terminal
        // control sequences.
        eprintln!("fletch: {}: {error}", purl.escape_debug());
        return Ok(ExitCode::from(NO_RECORD));
    }
    print_json(&probe_purl(purl))?;
    Ok(ExitCode::SUCCESS)
}

/// Batch form of [`run_purl`]: one PURL per stdin line, one JSON probe per
/// stdout line, in order. A line that doesn't parse still emits a probe (just
/// the `purl` field) rather than aborting, so a differential sweep can push
/// thousands of adversarial inputs through a single process.
fn run_purl_batch() -> anyhow::Result<ExitCode> {
    let stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();
    for line in std::io::BufRead::lines(stdin) {
        serde_json::to_writer(&mut stdout, &probe_purl(&line?))?;
        stdout.write_all(b"\n")?;
    }
    stdout.flush()?;
    Ok(ExitCode::SUCCESS)
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
    let (typ, path, version) = Purl::parse(purl)
        .map(|p| (p.typ().to_string(), p.encoded_path(), p.encoded_version()))
        .unwrap_or_default();
    let cache = BlobCache::disabled();
    let locator = RefLocator::Purl(purl.to_string());

    // Route probe: the first URL the registry lookup asks for names the
    // registry this type resolves to. The probe refuses every request, so the
    // lookup itself always fails; its error says nothing the URL doesn't.
    let probe = ProbeNet::default();
    let _always_refused = registry::lookup(&locator, &probe, &cache);
    let registry_url = probe
        .0
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .into_iter()
        .next();

    // Resolution probe: run the real fetch path against the refusing backend.
    // A resolvable PURL surfaces its download URL on the (expectedly failed)
    // record; `Unresolved` means the fetcher has no artifact mapping.
    let reference = Reference::new(locator, RefKind::Dependency, "cli", "");
    let download_url =
        fletch::fetch::fetch_ref(&reference, &ProbeNet::default(), &cache).resolved_url;

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

/// `registry <purl>`: print the record envelope, or exit `2` with the reason
/// there is none.
fn run_registry(purl: &str) -> anyhow::Result<ExitCode> {
    let net = HttpFetch::new()?.with_github_token(std::env::var("GITHUB_TOKEN").ok());
    // A disabled cache fetches and records every document fresh, so the
    // snapshot is current rather than a stale prior run's.
    let cache = BlobCache::disabled();

    let locator = RefLocator::Purl(purl.to_string());
    let (record, sources) = registry::lookup_recorded(&locator, &net, &cache);
    let record = match record {
        Ok(record) => record,
        Err(why) => {
            eprintln!(
                "fletch: no registry record for {}: {why}",
                purl.escape_debug()
            );
            return Ok(ExitCode::from(NO_RECORD));
        }
    };

    // Stamp the wall-clock-relative signals at collection time — the producer's
    // one chance, since `release_times` is transient and never serialized. A
    // consumer can still re-derive plain age from `published_at` later.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| anyhow::anyhow!("system clock before unix epoch: {e}"))?
        .as_secs();

    print_json(&Envelope {
        record: record.with_age(now),
        sources: sources.into_iter().map(source_from_recorded).collect(),
    })?;
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::source_from_recorded;
    use fletch::fetch::RecordedSource;

    fn recorded(content_type: &str, bytes: Option<&[u8]>) -> RecordedSource {
        RecordedSource {
            url: "https://registry.example/pkg".to_string(),
            status: 200,
            content_type: Some(content_type.to_string()),
            size: 17,
            bytes: bytes.map(<[u8]>::to_vec),
        }
    }

    #[test]
    fn maps_json_source_inline() {
        let source =
            source_from_recorded(recorded("application/json", Some(br#"{"hello":"world"}"#)));
        assert_eq!(source.url, "https://registry.example/pkg");
        assert_eq!(source.status, 200);
        assert_eq!(source.content_type.as_deref(), Some("application/json"));
        // A JSON body is preserved verbatim, not base64-wrapped.
        assert_eq!(source.body.as_ref().unwrap()["hello"], "world");
        assert!(source.body_b64.is_none());
        assert!(!source.truncated);
    }

    #[test]
    fn maps_non_json_source_to_base64() {
        let source = source_from_recorded(recorded("text/html", Some(b"<html>a listing</html>")));
        // Non-JSON bytes fall back to base64 so nothing is lost or corrupted.
        assert!(source.body.is_none());
        assert!(source.body_b64.is_some());
        assert!(!source.truncated);
    }

    #[test]
    fn an_unkept_source_is_truncated_not_empty() {
        let source = source_from_recorded(recorded("application/json", None));
        assert!(source.truncated);
        let json = serde_json::to_value(&source).unwrap();
        assert!(json.get("body").is_none());
        assert!(
            json.get("body_b64").is_none(),
            "no empty body stands in for the bytes"
        );
        assert_eq!(json["truncated"], true);
        assert_eq!(json["size"], 17);
    }
}
