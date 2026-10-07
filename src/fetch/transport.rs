//! The one network operation: the [`Fetch`] trait, its real HTTPS backend
//! ([`HttpFetch`]), and the offline [`Fixtures`] backend for tests.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::fetch::ssrf::{NonPublicHost, SafeResolver, guard_host};

/// Default per-fetch byte ceiling — a single response is abandoned past this
/// unless [`HttpFetch::with_max_bytes`] sets another.
pub const DEFAULT_MAX_FETCH_BYTES: u64 = 256 * 1024 * 1024;

/// Redirect-chain cap.
const MAX_REDIRECTS: u32 = 10;

/// The longest a request waits out a server's request to back off. A longer
/// one fails the request instead — and every request to that host until the
/// time is up, without asking it again.
const MAX_BACKOFF_WAIT: Duration = Duration::from_secs(30);

/// How many back-offs one request waits out before failing.
const BACKOFF_RETRIES: u32 = 3;

/// Wall-clock ceiling on one GET or POST, redirect hops and body included. The
/// blocking client's own timeout bounds each read, not the whole body, so a
/// server sending a byte every few seconds could otherwise hold a worker until
/// the size cap.
const REQUEST_DEADLINE: Duration = Duration::from_secs(600);

/// What a [`Request`] does: a GET, which follows redirects, or a POST of a
/// body, which does not (a redirected query endpoint is an error, not a silent
/// re-POST to another host).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Method<'a> {
    /// Retrieve the resource.
    Get,
    /// Send this body — for the one registry query with no GET form, the VS
    /// Code Marketplace's JSON-RPC `extensionquery`.
    Post(&'a [u8]),
}

/// One request to a [`Fetch`] backend: everything about it travels together,
/// so a wrapping backend that forwards [`send`](Fetch::send) forwards it all.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Request<'a> {
    /// The URL to ask.
    pub url: &'a str,
    /// GET or POST.
    pub method: Method<'a>,
    /// Extra `(name, value)` headers, for a registry that mandates one (the
    /// Snap Store 400s without `Snap-Device-Series`).
    pub headers: &'a [(&'a str, &'a str)],
    /// Return a status the server answered with as the [`Fetched`] it is —
    /// status and body — instead of [`FetchError::Status`]. For the one
    /// registry whose refusal body says something: proxy.golang.org's 404
    /// names the module path it would have accepted (see
    /// `goproxy_canonical_path`).
    pub any_status: bool,
    /// Write the body to this file, which must not exist yet, instead of
    /// returning it in [`Fetched::bytes`] — for an artifact, which need never
    /// be held in memory whole. A backend that cannot may return the bytes
    /// instead; the caller writes them out itself.
    pub spool: Option<&'a Path>,
}

impl<'a> Request<'a> {
    /// A plain GET of `url`.
    #[must_use]
    pub fn get(url: &'a str) -> Self {
        Self {
            url,
            method: Method::Get,
            headers: &[],
            any_status: false,
            spool: None,
        }
    }

    /// A POST of `body` to `url`.
    #[must_use]
    pub fn post(url: &'a str, body: &'a [u8]) -> Self {
        Self {
            method: Method::Post(body),
            ..Self::get(url)
        }
    }

    /// This request, carrying `headers`.
    #[must_use]
    pub fn with_headers(self, headers: &'a [(&'a str, &'a str)]) -> Self {
        Self { headers, ..self }
    }

    /// This request, its body written to `path` (see [`spool`](Self::spool)).
    #[must_use]
    pub fn spool_to(self, path: &'a Path) -> Self {
        Self {
            spool: Some(path),
            ..self
        }
    }

    /// This request, answered with whatever status the server sends (see
    /// [`any_status`](Self::any_status)).
    #[must_use]
    pub fn any_status(self) -> Self {
        Self {
            any_status: true,
            ..self
        }
    }
}

/// The one network operation. Backends: [`HttpFetch`] (real, SSRF-guarded)
/// and [`Fixtures`] (offline tests).
pub trait Fetch {
    /// Carry out `request`.
    fn send(&self, request: &Request<'_>) -> Result<Fetched, FetchError>;

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
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, thiserror::Error, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
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
    /// fletch itself failed while handling the reference — a parser bug
    /// tripped by hostile bytes, contained to this one fetch.
    #[error("internal error: {0}")]
    Internal(String),
}

impl FetchError {
    /// Whether a later fetch pass may succeed without changing the reference.
    /// Policy refusals, ordinary HTTP errors and integrity failures are not
    /// transient. Transport failures remain visible after retries are spent.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Timeout | Self::Transport(_) | Self::Status(408 | 429 | 500 | 502 | 503 | 504)
        )
    }
}

/// Retry connection establishment for GET only, before any body or spool file
/// exists. The caller classifies reqwest errors, retaining SSRF refusals.
fn retry_get_send<T>(
    deadline: Instant,
    mut send: impl FnMut() -> Result<T, (FetchError, bool)>,
    mut pause: impl FnMut(Duration),
) -> Result<T, FetchError> {
    for attempt in 0..=2 {
        if Instant::now() >= deadline {
            return Err(FetchError::Timeout);
        }
        match send() {
            Ok(value) => return Ok(value),
            Err((error, retry)) => {
                if !retry || !error.is_retryable() || attempt == 2 {
                    return Err(error);
                }
                let delay = Duration::from_millis(250 << attempt);
                if deadline.saturating_duration_since(Instant::now()) <= delay {
                    return Err(FetchError::Timeout);
                }
                pause(delay);
            }
        }
    }
    Err(FetchError::Internal(
        "retry loop exhausted without an outcome".into(),
    ))
}

/// The real network backend: an HTTPS client whose DNS resolver enforces the
/// SSRF floor. Redirects are followed manually so every hop is re-checked
/// for scheme and the chain is recorded; the response is size-capped.
#[derive(Debug)]
pub struct HttpFetch {
    client: reqwest::blocking::Client,
    /// A response is abandoned past this many bytes.
    max_bytes: u64,
    /// Hosts that asked to be left alone, shared by every request through this
    /// client, so its workers learn it once rather than each the hard way.
    backoff: Backoff,
    /// Sent to `api.github.com` only, lifting its anonymous rate limit.
    github_token: Option<Secret>,
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
        Ok(Self {
            client,
            max_bytes: DEFAULT_MAX_FETCH_BYTES,
            backoff: Backoff::default(),
            github_token: None,
        })
    }

    /// This client, authenticating to the GitHub API with `token`. Anonymous,
    /// the API allows 60 requests an hour per address, and both GitHub repo
    /// lookups and Composer downloads (Packagist's dist URLs are API zipballs)
    /// go through it. The token is sent to `api.github.com` alone — not to the
    /// host its downloads redirect to.
    #[must_use]
    pub fn with_github_token(self, token: Option<String>) -> Self {
        Self {
            github_token: token.filter(|t| !t.is_empty()).map(Secret),
            ..self
        }
    }

    /// This client, abandoning any response past `limit` bytes instead of
    /// [`DEFAULT_MAX_FETCH_BYTES`].
    #[must_use]
    pub fn with_max_bytes(self, limit: u64) -> Self {
        Self {
            max_bytes: limit,
            ..self
        }
    }
}

/// Read a response body under the per-fetch byte ceiling (`limit`) and the
/// request's `deadline` — into memory, or into the new file `spool`, leaving
/// the returned bytes empty. A declared `Content-Length` over the cap is
/// rejected before a single body byte is read — the common case for an
/// oversize artifact, which a registry or CDN sizes honestly — so we don't pull
/// tens of MB only to discard them. The streaming cap in [`copy_bounded`]
/// remains the authoritative backstop for a missing or dishonest header.
fn read_body_capped(
    resp: reqwest::blocking::Response,
    limit: u64,
    deadline: Instant,
    spool: Option<&Path>,
) -> Result<Vec<u8>, FetchError> {
    if let Some(len) = resp.content_length()
        && len > limit
    {
        return Err(FetchError::TooLarge);
    }
    let mut bytes = Vec::new();
    let Some(path) = spool else {
        copy_bounded(resp, &mut bytes, limit, deadline)?;
        return Ok(bytes);
    };
    let spool_error = |e: std::io::Error| FetchError::Transport(format!("spool: {e}"));
    let file = std::fs::File::options()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(spool_error)?;
    let mut out = std::io::BufWriter::new(file);
    copy_bounded(resp, &mut out, limit, deadline)?;
    out.flush().map_err(spool_error)?;
    Ok(bytes)
}

/// Copy `r` to its end into `out`, refusing more than `limit` bytes and giving
/// up once `deadline` passes. The deadline is checked between reads, so it can
/// be overrun by at most one read's own timeout.
fn copy_bounded(
    mut r: impl Read,
    out: &mut impl Write,
    limit: u64,
    deadline: Instant,
) -> Result<(), FetchError> {
    let mut copied = 0u64;
    let mut chunk = [0u8; 16 * 1024];
    loop {
        if Instant::now() >= deadline {
            return Err(FetchError::Timeout);
        }
        let n = match r.read(&mut chunk) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(FetchError::Transport(e.to_string())),
        };
        if copied + n as u64 > limit {
            return Err(FetchError::TooLarge);
        }
        out.write_all(&chunk[..n])
            .map_err(|e| FetchError::Transport(e.to_string()))?;
        copied += n as u64;
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
    fn get(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        any_status: bool,
        spool: Option<&Path>,
    ) -> Result<Fetched, FetchError> {
        let deadline = Instant::now() + REQUEST_DEADLINE;
        let mut current =
            reqwest::Url::parse(url).map_err(|e| FetchError::Transport(e.to_string()))?;
        let origin = current.origin();
        let mut redirects = Vec::new();
        let (mut hops, mut waits) = (0, 0);

        loop {
            if Instant::now() >= deadline {
                return Err(FetchError::Timeout);
            }
            // Re-checked on every hop, so a redirect can't escape the floor.
            guard_host(&current)?;
            let host = current.host_str().unwrap_or_default().to_string();
            self.backoff.wait(&host, deadline)?;
            let same_origin = current.origin() == origin;
            let mut req = self.client.get(current.clone());
            for (name, value) in headers {
                if forward_header(name, same_origin) {
                    req = req.header(*name, *value);
                }
            }
            if let Some(token) = self.token_for(&host, headers) {
                req = req.bearer_auth(token);
            }
            let resp = retry_get_send(
                deadline,
                || {
                    let request = req.try_clone().ok_or_else(|| {
                        (
                            FetchError::Internal("GET request cannot be cloned".into()),
                            false,
                        )
                    })?;
                    request
                        .timeout(
                            deadline
                                .saturating_duration_since(Instant::now())
                                .min(Duration::from_secs(30)),
                        )
                        .send()
                        .map_err(|error| {
                            let retry = error.is_connect() || error.is_timeout();
                            (map_send_err(error), retry)
                        })
                },
                std::thread::sleep,
            )?;
            let status = resp.status();

            if let Some(delay) = get_back_off_delay(status, resp.headers(), waits) {
                self.backoff.hold(&host, delay, status.as_u16());
                if waits < BACKOFF_RETRIES && delay <= MAX_BACKOFF_WAIT {
                    waits += 1;
                    continue;
                }
                return Err(FetchError::Status(status.as_u16()));
            }
            if status.is_redirection() {
                if hops == MAX_REDIRECTS {
                    return Err(FetchError::Refused("too many redirects".into()));
                }
                hops += 1;
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
            let bytes = read_body_capped(resp, self.max_bytes, deadline, spool)?;
            return Ok(Fetched {
                bytes,
                final_url: current.to_string(),
                status: status.as_u16(),
                headers,
                redirects,
            });
        }
    }

    /// The GitHub token, when `host` is the GitHub API and the caller has not
    /// supplied credentials of its own.
    fn token_for(&self, host: &str, headers: &[(&str, &str)]) -> Option<&str> {
        let caller_auth = headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("authorization"));
        (host == "api.github.com" && !caller_auth).then_some(self.github_token.as_ref()?.0.as_str())
    }
}

impl Fetch for HttpFetch {
    fn send(&self, request: &Request<'_>) -> Result<Fetched, FetchError> {
        match request.method {
            Method::Get => self.get(
                request.url,
                request.headers,
                request.any_status,
                request.spool,
            ),
            Method::Post(body) => self.post(
                request.url,
                body,
                request.headers,
                request.any_status,
                request.spool,
            ),
        }
    }

    // The real-network backend is the one place container pulls are welcome:
    // the puller's public-registry allowlist covers the SSRF posture that
    // guard_host provides for plain URL fetches.
    fn allows_oci(&self) -> bool {
        true
    }
}

impl HttpFetch {
    fn post(
        &self,
        url: &str,
        body: &[u8],
        headers: &[(&str, &str)],
        any_status: bool,
        spool: Option<&Path>,
    ) -> Result<Fetched, FetchError> {
        let deadline = Instant::now() + REQUEST_DEADLINE;
        let target = reqwest::Url::parse(url).map_err(|e| FetchError::Transport(e.to_string()))?;
        guard_host(&target)?;
        let host = target.host_str().unwrap_or_default().to_string();
        let mut waits = 0;
        let resp = loop {
            self.backoff.wait(&host, deadline)?;
            let mut req = self.client.post(target.clone()).body(body.to_vec());
            for (name, value) in headers {
                req = req.header(*name, *value);
            }
            if let Some(token) = self.token_for(&host, headers) {
                req = req.bearer_auth(token);
            }
            let resp = req.send().map_err(map_send_err)?;
            let Some(delay) = back_off_delay(resp.status(), resp.headers(), waits) else {
                break resp;
            };
            self.backoff.hold(&host, delay, resp.status().as_u16());
            if waits == BACKOFF_RETRIES || delay > MAX_BACKOFF_WAIT {
                return Err(FetchError::Status(resp.status().as_u16()));
            }
            waits += 1;
        };
        let status = resp.status();
        // POST is not redirect-followed: a redirected query endpoint is an error
        // here, not a silent re-POST to another host.
        if !status.is_success() && !any_status {
            return Err(FetchError::Status(status.as_u16()));
        }
        let headers = response_headers(&resp);
        let bytes = read_body_capped(resp, self.max_bytes, deadline, spool)?;
        Ok(Fetched {
            bytes,
            final_url: target.to_string(),
            status: status.as_u16(),
            headers,
            redirects: Vec::new(),
        })
    }
}

/// Hosts that asked to be left alone (`429`, `Retry-After`, an exhausted rate
/// limit): until when, and the status that asked.
#[derive(Debug, Default)]
struct Backoff(Mutex<HashMap<String, (Instant, u16)>>);

impl Backoff {
    /// Wait until `host` may be asked again — when that is within
    /// [`MAX_BACKOFF_WAIT`] and before `deadline`; otherwise fail now with the
    /// status that asked for the pause, leaving the host alone.
    fn wait(&self, host: &str, deadline: Instant) -> Result<(), FetchError> {
        let held = self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(host)
            .copied();
        let Some((until, status)) = held else {
            return Ok(());
        };
        let pause = until.saturating_duration_since(Instant::now());
        if pause.is_zero() {
            return Ok(());
        }
        if pause > MAX_BACKOFF_WAIT || Instant::now() + pause >= deadline {
            return Err(FetchError::Status(status));
        }
        std::thread::sleep(pause);
        Ok(())
    }

    /// Leave `host` alone for `delay`, unless it is already held longer.
    fn hold(&self, host: &str, delay: Duration, status: u16) {
        crate::metrics::backoff(host, status, delay);
        let now = Instant::now();
        let until = now + delay;
        let mut held = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        held.retain(|_, (when, _)| *when > now);
        let entry = held.entry(host.to_string()).or_insert((until, status));
        if entry.0 < until {
            *entry = (until, status);
        }
        drop(held);
    }
}

/// How long a response asks us to wait before asking again, when it asks: a
/// `429`, a `503` with `Retry-After`, or a rate limit GitHub has exhausted or
/// throttled (a `403` with `x-ratelimit-remaining: 0`, reset at
/// `x-ratelimit-reset`, or with `Retry-After`). A `429` that names no time
/// backs off 1 s, 2 s, 4 s.
fn get_back_off_delay(
    status: reqwest::StatusCode,
    headers: &reqwest::header::HeaderMap,
    waits: u32,
) -> Option<Duration> {
    back_off_delay(status, headers, waits).or_else(|| {
        matches!(status.as_u16(), 408 | 500 | 502 | 503 | 504)
            .then(|| Duration::from_secs(1 << waits.min(5)))
    })
}

fn back_off_delay(
    status: reqwest::StatusCode,
    headers: &reqwest::header::HeaderMap,
    waits: u32,
) -> Option<Duration> {
    let number = |name: &str| headers.get(name)?.to_str().ok()?.trim().parse::<u64>().ok();
    let retry_after = number("retry-after").map(Duration::from_secs);
    let exhausted = number("x-ratelimit-remaining") == Some(0);
    let reset = number("x-ratelimit-reset")
        .map(|at| Duration::from_secs(at.saturating_sub(crate::fetch::now())));
    match status.as_u16() {
        429 => Some(
            retry_after
                .or(reset.filter(|_| exhausted))
                .unwrap_or(Duration::from_secs(1 << waits.min(5))),
        ),
        503 => retry_after,
        403 if exhausted || retry_after.is_some() => {
            Some(retry_after.or(reset).unwrap_or(Duration::from_secs(60)))
        }
        _ => None,
    }
}

/// A credential, kept out of `Debug` output.
struct Secret(String);

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
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

#[expect(
    clippy::needless_pass_by_value,
    reason = "used as `map_err(map_send_err)`, which hands over the error by value"
)]
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
    if refused {
        FetchError::Refused(message)
    } else if e.is_timeout() {
        FetchError::Timeout
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
    /// Bodies for refusals, served only to an
    /// [`any_status`](Request::any_status) request.
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
    /// reachable only by an [`any_status`](Request::any_status) request, the
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
    /// A query's response is deterministic for its endpoint, so a POST is
    /// keyed on its URL like a GET, and headers and body are ignored.
    fn send(&self, request: &Request<'_>) -> Result<Fetched, FetchError> {
        let url = request.url;
        if let Some(&status) = self.refusals.get(url) {
            if !request.any_status {
                return Err(FetchError::Status(status));
            }
            return Ok(Fetched {
                bytes: self.refusal_bodies.get(url).cloned().unwrap_or_default(),
                final_url: url.to_string(),
                status,
                headers: Vec::new(),
                redirects: Vec::new(),
            });
        }
        self.responses
            .get(url)
            .cloned()
            .ok_or_else(|| FetchError::Transport(format!("no fixture for {url}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Read;
    use std::time::Duration;
    use std::time::Instant;

    #[test]
    fn a_server_asking_to_back_off_is_heard() {
        use reqwest::StatusCode;
        use reqwest::header::{HeaderMap, HeaderValue};
        let headers = |pairs: &[(&'static str, &str)]| {
            let mut map = HeaderMap::new();
            for (name, value) in pairs {
                map.insert(*name, HeaderValue::from_str(value).unwrap());
            }
            map
        };
        let none = HeaderMap::new();
        let secs = Duration::from_secs;
        // A 429 says how long, or backs off exponentially.
        let asked = headers(&[("retry-after", "7")]);
        assert_eq!(
            back_off_delay(StatusCode::TOO_MANY_REQUESTS, &asked, 0),
            Some(secs(7))
        );
        assert_eq!(
            back_off_delay(StatusCode::TOO_MANY_REQUESTS, &none, 2),
            Some(secs(4))
        );
        // A 503 waits only when asked to.
        assert_eq!(
            back_off_delay(StatusCode::SERVICE_UNAVAILABLE, &none, 0),
            None
        );
        assert_eq!(
            back_off_delay(StatusCode::SERVICE_UNAVAILABLE, &asked, 0),
            Some(secs(7))
        );
        // GitHub's exhausted rate limit is a 403 that resets at a stated time.
        let reset = (crate::fetch::now() + 600).to_string();
        let exhausted = headers(&[
            ("x-ratelimit-remaining", "0"),
            ("x-ratelimit-reset", &reset),
        ]);
        let pause = back_off_delay(StatusCode::FORBIDDEN, &exhausted, 0).unwrap();
        assert!(pause > secs(590) && pause <= secs(600), "{pause:?}");
        // An ordinary refusal is an answer, not a request to wait.
        assert_eq!(back_off_delay(StatusCode::FORBIDDEN, &none, 0), None);
        assert_eq!(back_off_delay(StatusCode::NOT_FOUND, &asked, 0), None);
    }

    #[test]
    fn a_host_held_back_is_waited_out_or_refused() {
        let backoff = Backoff::default();
        let deadline = Instant::now() + Duration::from_secs(600);
        backoff.hold("slow.test", Duration::from_millis(20), 429);
        let started = Instant::now();
        assert_eq!(backoff.wait("slow.test", deadline), Ok(()));
        assert!(started.elapsed() >= Duration::from_millis(15));
        // A pause past the cap fails at once, for every request to the host,
        // without asking it again.
        backoff.hold("limited.test", Duration::from_secs(3600), 403);
        assert_eq!(
            backoff.wait("limited.test", deadline),
            Err(FetchError::Status(403))
        );
        assert_eq!(backoff.wait("other.test", deadline), Ok(()));
        // A shorter hold never cuts a longer one short.
        backoff.hold("limited.test", Duration::from_millis(1), 429);
        assert_eq!(
            backoff.wait("limited.test", deadline),
            Err(FetchError::Status(403))
        );
    }

    #[test]
    fn the_github_token_goes_to_the_api_alone_and_never_prints() {
        let net = HttpFetch::new()
            .unwrap()
            .with_github_token(Some("ghp_secret".into()));
        assert_eq!(net.token_for("api.github.com", &[]), Some("ghp_secret"));
        assert_eq!(net.token_for("codeload.github.com", &[]), None);
        assert_eq!(
            net.token_for("api.github.com", &[("Authorization", "token theirs")]),
            None
        );
        assert!(!format!("{net:?}").contains("ghp_secret"));
    }

    /// [`copy_bounded`] into memory.
    fn read_bounded(r: impl Read, limit: u64, deadline: Instant) -> Result<Vec<u8>, FetchError> {
        let mut bytes = Vec::new();
        copy_bounded(r, &mut bytes, limit, deadline).map(|()| bytes)
    }

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
        // `u64::MAX` is a legal `with_max_bytes` value and must read the
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

#[cfg(test)]
mod retry_tests {
    use super::*;
    #[test]
    fn transient_get_succeeds_after_bounded_backoff() {
        let mut attempts = 0;
        let mut delays = Vec::new();
        let result = retry_get_send(
            Instant::now() + Duration::from_secs(10),
            || {
                attempts += 1;
                if attempts < 3 {
                    Err((FetchError::Transport("DNS unavailable".into()), true))
                } else {
                    Ok(42)
                }
            },
            |delay| delays.push(delay),
        );
        assert_eq!(result, Ok(42));
        assert_eq!(attempts, 3);
        assert_eq!(
            delays,
            vec![Duration::from_millis(250), Duration::from_millis(500)]
        );
    }
    #[test]
    fn persistent_failure_is_returned_after_three_attempts() {
        let mut attempts = 0;
        let error = FetchError::Timeout;
        let result: Result<(), _> = retry_get_send(
            Instant::now() + Duration::from_secs(10),
            || {
                attempts += 1;
                Err((error.clone(), true))
            },
            |_| {},
        );
        assert_eq!(result, Err(error));
        assert_eq!(attempts, 3);
    }
    #[test]
    fn policy_refusal_and_nonconnection_errors_are_never_retried() {
        for (error, retry) in [
            (FetchError::Refused("private address".into()), true),
            (FetchError::TooLarge, true),
            (FetchError::Status(404), true),
            (FetchError::Internal("parser".into()), true),
            (FetchError::Transport("invalid header".into()), false),
        ] {
            let mut attempts = 0;
            let result: Result<(), _> = retry_get_send(
                Instant::now() + Duration::from_secs(10),
                || {
                    attempts += 1;
                    Err((error.clone(), retry))
                },
                |_| panic!("must not sleep"),
            );
            assert_eq!(result, Err(error));
            assert_eq!(attempts, 1);
        }
    }
    #[test]
    fn retry_wait_cannot_exceed_deadline() {
        let result: Result<(), _> = retry_get_send(
            Instant::now() + Duration::from_millis(20),
            || Err((FetchError::Timeout, true)),
            |_| panic!("must not sleep"),
        );
        assert_eq!(result, Err(FetchError::Timeout));
        let result: Result<(), _> =
            retry_get_send(Instant::now(), || panic!("must not send"), |_| {});
        assert_eq!(result, Err(FetchError::Timeout));
    }
    #[test]
    fn extra_server_retries_are_get_only_and_honor_retry_after() {
        let mut headers = reqwest::header::HeaderMap::new();
        for code in [408, 500, 502, 503, 504] {
            let status = reqwest::StatusCode::from_u16(code).unwrap();
            assert!(get_back_off_delay(status, &headers, 0).is_some());
            assert!(back_off_delay(status, &headers, 0).is_none());
        }
        headers.insert("retry-after", "5".parse().unwrap());
        assert_eq!(
            get_back_off_delay(reqwest::StatusCode::SERVICE_UNAVAILABLE, &headers, 0),
            Some(Duration::from_secs(5))
        );
        for code in [400, 401, 404] {
            assert!(
                get_back_off_delay(reqwest::StatusCode::from_u16(code).unwrap(), &headers, 0)
                    .is_none()
            );
        }
    }
}
