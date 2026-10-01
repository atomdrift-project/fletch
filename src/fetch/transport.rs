//! The one network operation: the [`Fetch`] trait, its real HTTPS backend
//! ([`HttpFetch`]), and the offline [`Fixtures`] backend for tests.

use std::collections::HashMap;
use std::io::Read;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::fetch::ssrf::{NonPublicHost, SafeResolver, guard_host};

/// Default per-fetch byte ceiling — a single response is abandoned past this
/// unless [`set_max_fetch_bytes`] adjusts it for the process.
pub const DEFAULT_MAX_FETCH_BYTES: u64 = 256 * 1024 * 1024;

/// Process-wide per-fetch byte ceiling. Fetching is process-global (one
/// invocation, one policy), so the limit lives in a single atomic set once at
/// startup rather than threaded through every `get`/`fetch_ref` call — the same
/// shape as the shared HTTP client and blob cache.
static MAX_FETCH_BYTES: AtomicU64 = AtomicU64::new(DEFAULT_MAX_FETCH_BYTES);

/// Set the per-fetch byte ceiling for the process. Call once at startup, before
/// any fetch; subsequent fetches read the new value.
pub fn set_max_fetch_bytes(limit: u64) {
    MAX_FETCH_BYTES.store(limit, Ordering::Relaxed);
}

/// The current per-fetch byte ceiling.
#[must_use]
pub fn max_fetch_bytes() -> u64 {
    MAX_FETCH_BYTES.load(Ordering::Relaxed)
}

/// Redirect-chain cap.
const MAX_REDIRECTS: u32 = 10;

/// Wall-clock ceiling on one GET or POST, redirect hops and body included. The
/// blocking client's own timeout bounds each read, not the whole body, so a
/// server sending a byte every few seconds could otherwise hold a worker until
/// the size cap.
const REQUEST_DEADLINE: Duration = Duration::from_secs(600);

/// The one network operation. Backends: [`HttpFetch`] (real, SSRF-guarded)
/// and [`Fixtures`] (offline tests).
pub trait Fetch {
    /// Retrieve the bytes at `url`, following redirects.
    fn get(&self, url: &str) -> Result<Fetched, FetchError>;

    /// Retrieve the bytes at `url` with extra request `headers`, following
    /// redirects. Defaults to a plain [`get`](Self::get) — a backend overrides
    /// it only when a registry mandates a request header on a GET (e.g. the Snap
    /// Store, which 400s without `Snap-Device-Series`). Test backends that key on
    /// URL alone inherit the default unchanged.
    fn get_with(&self, url: &str, _headers: &[(&str, &str)]) -> Result<Fetched, FetchError> {
        self.get(url)
    }

    /// [`get_with`](Self::get_with), but a status the server *answered* with
    /// comes back as the [`Fetched`] it is — status and body — instead of
    /// [`FetchError::Status`]. For the one registry whose refusal body says
    /// something: proxy.golang.org's 404 names the module path it would have
    /// accepted (see `goproxy_canonical_path`). The default keeps the plain
    /// behaviour, so a backend that has not opted in still reports refusals
    /// as errors and nothing downstream changes for it.
    fn get_any_status(&self, url: &str, headers: &[(&str, &str)]) -> Result<Fetched, FetchError> {
        self.get_with(url, headers)
    }

    /// POST `body` with the given `(name, value)` headers and return the
    /// response. Defaults to unsupported; a backend overrides it only when a
    /// registry needs it — e.g. the VS Code Marketplace's JSON-RPC query, which
    /// has no GET form. POST is not redirect-followed.
    fn post(
        &self,
        _url: &str,
        _body: &[u8],
        _headers: &[(&str, &str)],
    ) -> Result<Fetched, FetchError> {
        Err(FetchError::Refused(
            "POST not supported by this backend".into(),
        ))
    }

    /// Whether an `oci://` target may be pulled. The OCI distribution protocol
    /// (token + manifest + blob rounds) runs on the puller's own HTTP stack,
    /// not through this backend — so a backend that exists to refuse or replay
    /// traffic (the `purl` probe, test fixtures) must not have containers
    /// pulled behind its back. Default `false`: only the backend that owns
    /// real network policy ([`HttpFetch`]) opts in, and the puller's
    /// public-registry allowlist stands in for its SSRF guard.
    fn allows_oci(&self) -> bool {
        false
    }
}

/// A successful fetch with the provenance the transport observed.
#[derive(Debug, Clone)]
pub struct Fetched {
    /// The retrieved bytes.
    pub bytes: Vec<u8>,
    /// Final URL after redirects (equal to the request URL if none).
    pub final_url: String,
    /// HTTP status code.
    pub status: u16,
    /// Response headers, in arrival order.
    pub headers: Vec<(String, String)>,
    /// Intermediate redirect URLs, in order.
    pub redirects: Vec<String>,
}

/// Why a fetch produced no bytes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FetchError {
    /// Refused before/at connect — SSRF guard, disallowed scheme, private
    /// host, too many redirects.
    #[error("refused: {0}")]
    Refused(String),
    /// Server returned a non-success status.
    #[error("http status {0}")]
    Status(u16),
    /// Response exceeded the size ceiling.
    #[error("response too large")]
    TooLarge,
    /// The request timed out.
    #[error("timed out")]
    Timeout,
    /// Transport / IO failure.
    #[error("transport: {0}")]
    Transport(String),
}

/// The real network backend: an HTTPS client whose DNS resolver enforces the
/// SSRF floor. Redirects are followed manually so every hop is re-checked
/// for scheme and the chain is recorded; the response is size-capped.
#[derive(Debug)]
pub struct HttpFetch {
    client: reqwest::blocking::Client,
}

impl HttpFetch {
    /// Build the client. Anonymous (no cookies/credentials), timed out, with
    /// the SSRF-guarding resolver installed.
    pub fn new() -> Result<Self, reqwest::Error> {
        let client = reqwest::blocking::Client::builder()
            .user_agent("fletch")
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            // Through a proxy, the proxy resolves the target host and
            // SafeResolver only ever sees the proxy's, so `HTTPS_PROXY` in the
            // environment would switch the SSRF guard off.
            .no_proxy()
            // We follow redirects by hand (per-hop scheme check + chain).
            .redirect(reqwest::redirect::Policy::none())
            .dns_resolver(Arc::new(SafeResolver))
            .build()?;
        Ok(Self { client })
    }
}

/// Read a response body under the per-fetch byte ceiling ([`max_fetch_bytes`])
/// and the request's `deadline`. A declared `Content-Length` over the cap is
/// rejected before a single body byte is read — the common case for an
/// oversize artifact, which a registry or CDN sizes honestly — so we don't pull
/// tens of MB only to discard them. The streaming cap in [`read_bounded`]
/// remains the authoritative backstop for a missing or dishonest header.
fn read_body_capped(
    resp: reqwest::blocking::Response,
    deadline: Instant,
) -> Result<Vec<u8>, FetchError> {
    let limit = max_fetch_bytes();
    if let Some(len) = resp.content_length()
        && len > limit
    {
        return Err(FetchError::TooLarge);
    }
    read_bounded(resp, limit, deadline)
}

/// Read `r` to the end, refusing more than `limit` bytes and giving up once
/// `deadline` passes. The deadline is checked between reads, so it can be
/// overrun by at most one read's own timeout.
fn read_bounded(mut r: impl Read, limit: u64, deadline: Instant) -> Result<Vec<u8>, FetchError> {
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    loop {
        if Instant::now() >= deadline {
            return Err(FetchError::Timeout);
        }
        let n = match r.read(&mut chunk) {
            Ok(0) => return Ok(bytes),
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(FetchError::Transport(e.to_string())),
        };
        if (bytes.len() + n) as u64 > limit {
            return Err(FetchError::TooLarge);
        }
        bytes.extend_from_slice(&chunk[..n]);
    }
}

/// Whether a caller header rides along on a redirect hop. A hop to another
/// origin drops the credential-bearing ones, as reqwest's own redirect policy
/// would; everything else (`Accept`, registry-specific selectors) is kept.
fn forward_header(name: &str, same_origin: bool) -> bool {
    same_origin
        || !["authorization", "cookie", "proxy-authorization"]
            .iter()
            .any(|sensitive| name.eq_ignore_ascii_case(sensitive))
}

impl HttpFetch {
    /// The shared GET path: per-hop https + SSRF enforcement, redirect following,
    /// the response-size cap and the [`REQUEST_DEADLINE`]. `headers` are
    /// attached to every hop, less credentials once a hop leaves the starting
    /// origin ([`forward_header`]). Every GET funnels through here so the
    /// security floor is defined exactly once. `any_status` returns a
    /// non-success response as a [`Fetched`] rather than a
    /// [`FetchError::Status`]; redirects and the host guard apply either way.
    fn get_inner(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        any_status: bool,
    ) -> Result<Fetched, FetchError> {
        let deadline = Instant::now() + REQUEST_DEADLINE;
        let mut current =
            reqwest::Url::parse(url).map_err(|e| FetchError::Transport(e.to_string()))?;
        let origin = current.origin();
        let mut redirects = Vec::new();

        for _ in 0..=MAX_REDIRECTS {
            if Instant::now() >= deadline {
                return Err(FetchError::Timeout);
            }
            // Re-checked on every hop, so a redirect can't escape the floor.
            guard_host(&current)?;
            let same_origin = current.origin() == origin;
            let mut req = self.client.get(current.clone());
            for (name, value) in headers {
                if forward_header(name, same_origin) {
                    req = req.header(*name, *value);
                }
            }
            let resp = req.send().map_err(map_send_err)?;
            let status = resp.status();

            if status.is_redirection() {
                // Some servers (e.g. the Chrome Web Store) send a non-ASCII
                // `Location` with raw UTF-8 in the path; `to_str()` rejects that,
                // so fall back to a lossy decode and let `Url::join` percent-
                // encode it. The per-hop https + SSRF checks above still run.
                let location = resp
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .map(|v| {
                        v.to_str()
                            .map(str::to_string)
                            .unwrap_or_else(|_| String::from_utf8_lossy(v.as_bytes()).into_owned())
                    })
                    .ok_or_else(|| FetchError::Transport("redirect without location".into()))?;
                let next = current
                    .join(&location)
                    .map_err(|e| FetchError::Transport(e.to_string()))?;
                redirects.push(current.to_string());
                current = next;
                continue;
            }
            if !status.is_success() && !any_status {
                return Err(FetchError::Status(status.as_u16()));
            }

            let headers = response_headers(&resp);
            let bytes = read_body_capped(resp, deadline)?;
            return Ok(Fetched {
                bytes,
                final_url: current.to_string(),
                status: status.as_u16(),
                headers,
                redirects,
            });
        }
        Err(FetchError::Refused("too many redirects".into()))
    }
}

impl Fetch for HttpFetch {
    fn get(&self, url: &str) -> Result<Fetched, FetchError> {
        self.get_inner(url, &[], false)
    }

    fn get_with(&self, url: &str, headers: &[(&str, &str)]) -> Result<Fetched, FetchError> {
        self.get_inner(url, headers, false)
    }

    fn get_any_status(&self, url: &str, headers: &[(&str, &str)]) -> Result<Fetched, FetchError> {
        self.get_inner(url, headers, true)
    }

    fn post(
        &self,
        url: &str,
        body: &[u8],
        headers: &[(&str, &str)],
    ) -> Result<Fetched, FetchError> {
        let deadline = Instant::now() + REQUEST_DEADLINE;
        let target = reqwest::Url::parse(url).map_err(|e| FetchError::Transport(e.to_string()))?;
        guard_host(&target)?;
        let mut req = self.client.post(target.clone()).body(body.to_vec());
        for (name, value) in headers {
            req = req.header(*name, *value);
        }
        let resp = req.send().map_err(map_send_err)?;
        let status = resp.status();
        // POST is not redirect-followed: a redirected query endpoint is an error
        // here, not a silent re-POST to another host.
        if !status.is_success() {
            return Err(FetchError::Status(status.as_u16()));
        }
        let headers = response_headers(&resp);
        let bytes = read_body_capped(resp, deadline)?;
        Ok(Fetched {
            bytes,
            final_url: target.to_string(),
            status: status.as_u16(),
            headers,
            redirects: Vec::new(),
        })
    }

    // The real-network backend is the one place container pulls are welcome:
    // the puller's public-registry allowlist covers the SSRF posture that
    // guard_host provides for plain URL fetches.
    fn allows_oci(&self) -> bool {
        true
    }
}

/// Response headers as owned pairs, dropping any whose value isn't text.
fn response_headers(resp: &reqwest::blocking::Response) -> Vec<(String, String)> {
    resp.headers()
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|val| (k.as_str().to_string(), val.to_string()))
        })
        .collect()
}

// Used as `map_err(map_send_err)`, so it must take the error by value even
// though it only inspects it.
#[allow(clippy::needless_pass_by_value)]
fn map_send_err(e: reqwest::Error) -> FetchError {
    // reqwest's own message stops at "error sending request for url (…)"; the
    // cause (the resolver's refusal, a DNS or TLS failure) is in the chain.
    let mut message = e.to_string();
    let mut refused = false;
    let mut source = std::error::Error::source(&e);
    while let Some(cause) = source {
        refused |= cause.is::<NonPublicHost>();
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    if e.is_timeout() {
        FetchError::Timeout
    } else if refused {
        FetchError::Refused(message)
    } else {
        FetchError::Transport(message)
    }
}

/// In-memory [`Fetch`] backend for tests: a fixed URL → response map. The
/// drop-in for [`HttpFetch`] so the orchestration runs offline.
#[derive(Debug, Default, Clone)]
pub struct Fixtures {
    responses: HashMap<String, Fetched>,
    refusals: HashMap<String, u16>,
    /// Bodies for refusals, served only through
    /// [`get_any_status`](Fetch::get_any_status).
    refusal_bodies: HashMap<String, Vec<u8>>,
}

impl Fixtures {
    /// Register `bytes` as the 200 response for `url` (no headers/redirects).
    #[must_use]
    pub fn with(self, url: &str, bytes: &[u8]) -> Self {
        self.with_headers(url, bytes, &[])
    }

    /// Register `url` as a refusal carrying `status`, the way a real client
    /// reports one: an error, with no body reaching the caller. A registry's
    /// refusal is sometimes an answer, so a test has to be able to spell one.
    #[must_use]
    pub fn refusing(mut self, url: &str, status: u16) -> Self {
        self.refusals.insert(url.to_string(), status);
        self
    }
    /// [`refusing`](Self::refusing), with the body the server sent along —
    /// reachable only through [`get_any_status`](Fetch::get_any_status), the
    /// way a real client exposes it.
    #[must_use]
    pub fn refusing_with_body(mut self, url: &str, status: u16, body: &[u8]) -> Self {
        self.refusals.insert(url.to_string(), status);
        self.refusal_bodies.insert(url.to_string(), body.to_vec());
        self
    }

    /// Register a 200 response with explicit headers.
    #[must_use]
    pub fn with_headers(mut self, url: &str, bytes: &[u8], headers: &[(&str, &str)]) -> Self {
        self.responses.insert(
            url.to_string(),
            Fetched {
                bytes: bytes.to_vec(),
                final_url: url.to_string(),
                status: 200,
                headers: headers
                    .iter()
                    .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                    .collect(),
                redirects: Vec::new(),
            },
        );
        self
    }
}

impl Fetch for Fixtures {
    fn get(&self, url: &str) -> Result<Fetched, FetchError> {
        if let Some(status) = self.refusals.get(url) {
            return Err(FetchError::Status(*status));
        }
        self.responses
            .get(url)
            .cloned()
            .ok_or_else(|| FetchError::Transport(format!("no fixture for {url}")))
    }

    fn get_any_status(&self, url: &str, _headers: &[(&str, &str)]) -> Result<Fetched, FetchError> {
        if let Some(status) = self.refusals.get(url) {
            return Ok(Fetched {
                bytes: self.refusal_bodies.get(url).cloned().unwrap_or_default(),
                final_url: url.to_string(),
                status: *status,
                headers: Vec::new(),
                redirects: Vec::new(),
            });
        }
        self.get(url)
    }
    /// A query's response is deterministic for its endpoint, so fixtures key on
    /// the URL and ignore the body.
    fn post(
        &self,
        url: &str,
        _body: &[u8],
        _headers: &[(&str, &str)],
    ) -> Result<Fetched, FetchError> {
        self.get(url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Read;
    use std::time::Duration;
    use std::time::Instant;

    #[test]
    fn a_body_read_honours_the_cap_and_an_unbounded_ceiling() {
        let later = Instant::now() + Duration::from_secs(60);
        assert_eq!(
            read_bounded(&b"12345"[..], 5, later).ok(),
            Some(b"12345".to_vec())
        );
        assert!(matches!(
            read_bounded(&b"12345"[..], 4, later),
            Err(FetchError::TooLarge)
        ));
        // `u64::MAX` is a legal `set_max_fetch_bytes` value and must read the
        // whole body, not wrap to an empty one.
        assert_eq!(
            read_bounded(&b"12345"[..], u64::MAX, later).ok(),
            Some(b"12345".to_vec())
        );
    }

    #[test]
    fn a_trickling_body_is_cut_off_at_the_deadline() {
        // Never-ending, one byte per read, each read well inside any per-read
        // timeout: only the whole-request deadline stops it.
        struct Trickle;
        impl Read for Trickle {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                std::thread::sleep(Duration::from_millis(1));
                buf[0] = b'x';
                Ok(1)
            }
        }
        let deadline = Instant::now() + Duration::from_millis(30);
        assert!(matches!(
            read_bounded(Trickle, u64::MAX, deadline),
            Err(FetchError::Timeout)
        ));
    }

    #[test]
    fn credentials_do_not_follow_a_cross_origin_redirect() {
        for name in ["Authorization", "cookie", "Proxy-Authorization"] {
            assert!(
                forward_header(name, true),
                "{name} stays on the same origin"
            );
            assert!(
                !forward_header(name, false),
                "{name} must not leave the origin"
            );
        }
        // Non-credential headers a registry needs survive the hop.
        for name in ["Accept", "Content-Type", "Snap-Device-Series"] {
            assert!(
                forward_header(name, false),
                "{name} must survive a redirect"
            );
        }
    }
}
