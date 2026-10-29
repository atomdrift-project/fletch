//! The one network operation: the [`Fetch`] trait, its real HTTPS backend
//! ([`HttpFetch`]), and, with the `test-util` feature, the offline `Fixtures`
//! backend for tests.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use reqwest::StatusCode;
use reqwest::header::HeaderMap;

use crate::fetch::ssrf::{NonPublicHost, SafeResolver, guard_host};

/// Default per-fetch byte ceiling — a single response is abandoned past this
/// unless [`HttpFetch::with_max_bytes`] sets another.
pub const DEFAULT_MAX_FETCH_BYTES: u64 = 256 * 1024 * 1024;

/// The in-memory body ceiling for a host fletch did not choose (see
/// [`HttpFetch::body_limit`]). Far above any registry document such a host
/// legitimately serves.
const MAX_FOREIGN_DOCUMENT_BYTES: u64 = 32 * 1024 * 1024;

/// The registry hosts fletch names itself, whose documents keep the full
/// per-fetch ceiling: npm's and PyPI's package documents legitimately run to
/// tens of megabytes, and distro indexes further. A host missing here only
/// gets the smaller [`MAX_FOREIGN_DOCUMENT_BYTES`].
const REGISTRY_HOSTS: &[&str] = &[
    "addons.mozilla.org",
    "api.anaconda.org",
    "api.comfy.org",
    "api.github.com",
    "api.jsr.io",
    "api.npmjs.org",
    "api.nuget.org",
    "api.snapcraft.io",
    "api.wordpress.org",
    "archive.ubuntu.com",
    "archlinux.org",
    "aur.archlinux.org",
    "azuresearch-usnc.nuget.org",
    "cdn.netbsd.org",
    "cdn.openbsd.org",
    "chromewebstore.google.com",
    "clawhub.ai",
    "clojars.org",
    "crandb.r-pkg.org",
    "crates.io",
    "deb.debian.org",
    "dl-cdn.alpinelinux.org",
    "download.opensuse.org",
    "download1.rpmfusion.org",
    "fastapi.metacpan.org",
    "formulae.brew.sh",
    "hex.pm",
    "hub.docker.com",
    "huggingface.co",
    "index.crates.io",
    "marketplace.dify.ai",
    "marketplace.visualstudio.com",
    "mdapi.fedoraproject.org",
    "open-vsx.org",
    "packagist.org",
    "packages.wolfi.dev",
    "pkg.freebsd.org",
    "plugins.jetbrains.com",
    "proxy.golang.org",
    "pub.dev",
    "pypi.org",
    "quay.io",
    "registry.npmjs.org",
    "registry.terraform.io",
    "repo.packagist.org",
    "repo1.maven.org",
    "rubygems.org",
    "search.maven.org",
    "snapcraft.io",
];

/// Redirect-chain cap.
const MAX_REDIRECTS: usize = 10;

/// The longest a request waits out a server's request to back off. A longer
/// one fails the request instead — and every request to that host until the
/// time is up, without asking it again.
const MAX_BACKOFF_WAIT: Duration = Duration::from_secs(30);

/// The longest a host is left alone, however long it asks for: a day outlasts
/// any honest rate-limit window, and the bound keeps `Instant` arithmetic on a
/// server-chosen number from overflowing.
const MAX_HOLD: Duration = Duration::from_secs(24 * 60 * 60);

/// How many pauses one request waits out before failing.
const BACKOFF_RETRIES: u32 = 3;

/// How many times a GET whose connection failed is sent again.
const CONNECT_RETRIES: u32 = 2;

/// Wall-clock ceiling on one GET or POST, redirect hops and body included. The
/// blocking client's own timeout bounds each read, not the whole body, so a
/// server sending a byte every few seconds could otherwise hold a worker until
/// the size cap.
const REQUEST_DEADLINE: Duration = Duration::from_secs(600);

/// The longest one send waits for a response to begin.
const SEND_TIMEOUT: Duration = Duration::from_secs(30);

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
    /// status and body — instead of [`FetchError::Status`]. For a refusal
    /// that says something: proxy.golang.org's 404 names the module path it
    /// would have accepted (see `goproxy_canonical_path`), and a container
    /// registry's 401 names where to get a token.
    pub any_status: bool,
    /// Write the body to this file, which must not exist yet, instead of
    /// returning it in [`Fetched::bytes`] — for an artifact, which need never
    /// be held in memory whole. With [`any_status`](Self::any_status), a
    /// refusal's body is written there too. A backend that cannot may return
    /// the bytes instead; the caller writes them out itself.
    pub spool: Option<&'a Path>,
    /// Ask for the backend's GitHub token, if it has one. Set only where
    /// fletch itself names the GitHub URL, never for one a scanned file or a
    /// registry response chose: the token can read every private repository
    /// its owner can. The backend still sends it only to a repository document
    /// (`https://api.github.com/repos/{owner}/{repo}`), and never once the
    /// redirect chain has left that origin.
    pub github_auth: bool,
    /// A response-size ceiling below the backend's own, for a caller that
    /// knows how large the answer can be (a manifest, a token, a layer of a
    /// declared size). It can only lower the backend's ceiling, never raise
    /// it. `None` keeps the backend's.
    pub max_bytes: Option<u64>,
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
            github_auth: false,
            max_bytes: None,
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

    /// This request, authenticated to the GitHub API (see
    /// [`github_auth`](Self::github_auth)).
    #[must_use]
    pub fn github_auth(self) -> Self {
        Self {
            github_auth: true,
            ..self
        }
    }

    /// This request, abandoned past `limit` response bytes or the backend's
    /// own ceiling, whichever is lower (see [`max_bytes`](Self::max_bytes)).
    #[must_use]
    pub fn max_bytes(self, limit: u64) -> Self {
        Self {
            max_bytes: Some(limit),
            ..self
        }
    }
}

/// The one network operation. Backends: [`HttpFetch`] (real, SSRF-guarded)
/// and `Fixtures` (offline tests, behind the `test-util` feature).
///
/// `Sync`, so one backend serves a batch's workers and a container pull's
/// concurrent blob reads alike.
pub trait Fetch: Sync {
    /// Carry out `request`.
    fn send(&self, request: &Request<'_>) -> Result<Fetched, FetchError>;

    /// Whether an `oci://` target may be pulled. The OCI distribution protocol
    /// (token + manifest + blob rounds) runs through this backend like any
    /// other request, but a pull is many requests to a few public registries,
    /// so a backend that exists to refuse or replay traffic (the `purl` probe,
    /// test fixtures) opts out of it wholesale. Default `false`: only the
    /// backend that owns real network policy ([`HttpFetch`]) opts in, and the
    /// puller's public-registry allowlist applies on top of its SSRF guard.
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
    /// Network transport failure (connect, TLS, a broken body stream).
    #[error("transport: {0}")]
    Transport(String),
    /// Local disk failure while spooling or examining fetched bytes.
    #[error("io: {0}")]
    Io(String),
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
            Self::Timeout
                | Self::Transport(_)
                | Self::Io(_)
                | Self::Status(408 | 429 | 500 | 502 | 503 | 504)
        )
    }
}

/// Send a GET, sending it again — at most [`CONNECT_RETRIES`] more times, and
/// only before `deadline` — while it fails to connect. `send` returns each
/// failure classified, with whether it happened before any response began;
/// nothing else is retried, so an SSRF refusal or an HTTP status never is.
fn retry_get_send<T>(
    deadline: Instant,
    mut send: impl FnMut() -> Result<T, (FetchError, bool)>,
    mut pause: impl FnMut(Duration),
) -> Result<T, FetchError> {
    let mut attempt = 0;
    loop {
        if Instant::now() >= deadline {
            return Err(FetchError::Timeout);
        }
        let (error, connecting) = match send() {
            Ok(value) => return Ok(value),
            Err(failure) => failure,
        };
        if !connecting || !error.is_retryable() || attempt == CONNECT_RETRIES {
            return Err(error);
        }
        let delay = Duration::from_millis(250 << attempt);
        if deadline.saturating_duration_since(Instant::now()) <= delay {
            return Err(FetchError::Timeout);
        }
        attempt += 1;
        tracing::debug!(
            target: "transport",
            %error,
            attempt,
            delay_ms = delay.as_millis(),
            "connection failed; retrying"
        );
        pause(delay);
    }
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
    /// Lifts GitHub's anonymous API rate limit; see [`Self::github_token`].
    github_token: Option<Secret>,
}

impl HttpFetch {
    /// Build the client. Anonymous (no cookies/credentials), timed out, with
    /// the SSRF-guarding resolver installed. Fails only when the TLS backend
    /// cannot be initialised.
    pub fn new() -> Result<Self, FetchError> {
        let client = reqwest::blocking::Client::builder()
            .user_agent("fletch")
            .timeout(SEND_TIMEOUT)
            .connect_timeout(Duration::from_secs(10))
            // Through a proxy, the proxy resolves the target host and
            // SafeResolver only ever sees the proxy's, so `HTTPS_PROXY` in the
            // environment would switch the SSRF guard off.
            .no_proxy()
            // We follow redirects by hand (per-hop scheme check + chain).
            .redirect(reqwest::redirect::Policy::none())
            .dns_resolver(Arc::new(SafeResolver))
            .build()
            .map_err(|e| FetchError::Transport(format!("http client: {e}")))?;
        Ok(Self {
            client,
            max_bytes: DEFAULT_MAX_FETCH_BYTES,
            backoff: Backoff::default(),
            github_token: None,
        })
    }

    /// This client, authenticating to the GitHub API with `token`. Anonymous,
    /// the API allows 60 requests an hour per address. The token is sent only
    /// to a GitHub repository document fletch itself asked for
    /// (`https://api.github.com/repos/{owner}/{repo}`, see
    /// [`Request::github_auth`]), never along a redirect that has left that
    /// origin. Prefer a token without private-repository scope: it is only
    /// here for the rate limit.
    #[must_use]
    pub fn with_github_token(self, token: Option<String>) -> Self {
        Self {
            github_token: token.filter(|t| !t.is_empty()).map(Secret),
            ..self
        }
    }

    /// This client, abandoning any response past `limit` bytes instead of
    /// [`DEFAULT_MAX_FETCH_BYTES`]. No request can raise it: it bounds each
    /// layer of a container image as well.
    #[must_use]
    pub fn with_max_bytes(self, limit: u64) -> Self {
        Self {
            max_bytes: limit,
            ..self
        }
    }

    /// The shared GET path: per-hop https + SSRF enforcement, redirect following,
    /// the response-size cap and the [`REQUEST_DEADLINE`]. `headers` are
    /// attached to every hop, less credentials once the chain has left the
    /// starting origin ([`forward_header`]). Every GET funnels through here so
    /// the security floor is defined exactly once. `any_status` returns a
    /// non-success response as a [`Fetched`] rather than a
    /// [`FetchError::Status`]; redirects and the host guard apply either way.
    fn get(&self, request: &Request<'_>) -> Result<Fetched, FetchError> {
        let deadline = Instant::now() + REQUEST_DEADLINE;
        let mut current =
            reqwest::Url::parse(request.url).map_err(|e| FetchError::Transport(e.to_string()))?;
        let limit = self.body_limit(request, &current);
        let mut chain = Chain::new(&current);
        let mut redirects = Vec::new();
        let mut waits = 0;

        loop {
            if Instant::now() >= deadline {
                return Err(FetchError::Timeout);
            }
            // Re-checked on every hop, so a redirect can't escape the floor.
            guard_host(&current)?;
            let left_origin = chain.hop(&current);
            let host = current.host_str().unwrap_or_default().to_string();
            self.backoff.wait(&host, deadline)?;
            let mut req = self.client.get(current.clone());
            for (name, value) in request.headers {
                if forward_header(name, left_origin) {
                    req = req.header(*name, *value);
                }
            }
            if let Some(token) = self.github_token(request, left_origin) {
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
                                .min(SEND_TIMEOUT),
                        )
                        .send()
                        .map_err(|error| {
                            let connecting = error.is_connect() || error.is_timeout();
                            (map_send_err(error), connecting)
                        })
                },
                std::thread::sleep,
            )?;
            let status = resp.status();
            if self.wait_out(&host, status, resp.headers(), &mut waits, deadline, true)? {
                continue;
            }
            if status.is_redirection() {
                if redirects.len() == MAX_REDIRECTS {
                    tracing::debug!(target: "transport", host, "refused: too many redirects");
                    return Err(FetchError::Refused("too many redirects".into()));
                }
                // Some servers (e.g. the Chrome Web Store) send a non-ASCII
                // `Location` with raw UTF-8 in the path, so it is decoded
                // lossily and `Url::join` percent-encodes it. The per-hop
                // https + SSRF checks above still run.
                let location = resp
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
                    .ok_or_else(|| FetchError::Transport("redirect without location".into()))?;
                let next = current
                    .join(&location)
                    .map_err(|e| FetchError::Transport(e.to_string()))?;
                // Host and path only: a redirect's query is often a signature.
                tracing::debug!(
                    target: "transport",
                    status = status.as_u16(),
                    from = host,
                    to = next.host_str().unwrap_or_default(),
                    path = next.path(),
                    hop = redirects.len() + 1,
                    "following redirect"
                );
                redirects.push(current.to_string());
                current = next;
                continue;
            }
            return response(
                resp,
                request,
                limit,
                deadline,
                current.to_string(),
                redirects,
            );
        }
    }

    /// POST the request's body. Not redirect-followed: a redirected query
    /// endpoint is an error here, not a silent re-POST to another host, and a
    /// transient server error is not retried.
    fn post(&self, request: &Request<'_>, body: &[u8]) -> Result<Fetched, FetchError> {
        let deadline = Instant::now() + REQUEST_DEADLINE;
        let target =
            reqwest::Url::parse(request.url).map_err(|e| FetchError::Transport(e.to_string()))?;
        let limit = self.body_limit(request, &target);
        guard_host(&target)?;
        let host = target.host_str().unwrap_or_default().to_string();
        let mut waits = 0;
        let resp = loop {
            self.backoff.wait(&host, deadline)?;
            let mut req = self.client.post(target.clone()).body(body.to_vec());
            for (name, value) in request.headers {
                req = req.header(*name, *value);
            }
            if let Some(token) = self.github_token(request, false) {
                req = req.bearer_auth(token);
            }
            let resp = req.send().map_err(map_send_err)?;
            if !self.wait_out(
                &host,
                resp.status(),
                resp.headers(),
                &mut waits,
                deadline,
                false,
            )? {
                break resp;
            }
        };
        response(
            resp,
            request,
            limit,
            deadline,
            target.to_string(),
            Vec::new(),
        )
    }

    /// The response-size ceiling for `request`, which starts at `url`: the
    /// backend's, or the request's own when that is lower — then lowered to
    /// [`MAX_FOREIGN_DOCUMENT_BYTES`] for a body held in memory from a host
    /// fletch did not choose. That host came from a `repository_url` in a
    /// scanned file, and a document it serves is parsed whole into a JSON tree
    /// several times its size, so the artifact-sized cap would let one hostile
    /// reply cost gigabytes. Decided by the first hop: a redirect is the chosen
    /// host's to make (openSUSE's mirror network).
    fn body_limit(&self, request: &Request<'_>, url: &reqwest::Url) -> u64 {
        let ceiling = request
            .max_bytes
            .map_or(self.max_bytes, |limit| limit.min(self.max_bytes));
        let chosen = url
            .host_str()
            .is_some_and(|host| REGISTRY_HOSTS.contains(&host));
        if request.spool.is_some() || chosen {
            ceiling
        } else {
            ceiling.min(MAX_FOREIGN_DOCUMENT_BYTES)
        }
    }

    /// The GitHub token for one hop of `request`, when it may carry it — the
    /// one place that decides. The token can read every private repository
    /// its owner can, so it goes only where all of these hold:
    /// - the caller opted in ([`Request::github_auth`]), which fletch does
    ///   only for URLs it builds itself;
    /// - the request names a repository document,
    ///   `https://api.github.com/repos/{owner}/{repo}` and nothing longer, so
    ///   no other API endpoint (`…/zipball/main`, `…/contents/.env`) ever
    ///   sees it;
    /// - the redirect chain has never left that origin (`left_origin` is
    ///   latched by the caller);
    /// - the caller sent no `Authorization` of its own.
    fn github_token(&self, request: &Request<'_>, left_origin: bool) -> Option<&str> {
        let token = self.github_token.as_ref()?;
        let caller_auth = request
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("authorization"));
        let allowed = request.github_auth
            && !left_origin
            && !caller_auth
            && is_github_repository_document(request.url);
        allowed.then_some(token.0.as_str())
    }

    /// Act on a response that asks for a pause ([`pause`]): `Ok(true)` to send
    /// the request again, `Ok(false)` when it asks for none. A host-wide pause
    /// is recorded for every request through this client and waited out by
    /// [`Backoff::wait`] before the next send; a per-request one is slept here.
    /// Past [`BACKOFF_RETRIES`] pauses, or a pause longer than
    /// [`MAX_BACKOFF_WAIT`], the response's status is the answer.
    fn wait_out(
        &self,
        host: &str,
        status: StatusCode,
        headers: &HeaderMap,
        waits: &mut u32,
        deadline: Instant,
        retry_transient: bool,
    ) -> Result<bool, FetchError> {
        let Some(pause) = pause(status, headers, *waits, retry_transient) else {
            return Ok(false);
        };
        let code = status.as_u16();
        let delay = match pause {
            Pause::Host(delay) => {
                self.backoff.hold(host, delay, code);
                delay
            }
            Pause::Request(delay) => delay,
        };
        if *waits >= BACKOFF_RETRIES
            || delay > MAX_BACKOFF_WAIT
            || deadline.saturating_duration_since(Instant::now()) <= delay
        {
            tracing::debug!(
                target: "transport",
                host,
                status = code,
                waits = *waits,
                delay_ms = delay.as_millis(),
                "not waiting any longer; failing the request"
            );
            return Err(FetchError::Status(code));
        }
        *waits += 1;
        if let Pause::Request(delay) = pause {
            tracing::debug!(
                target: "transport",
                host,
                status = code,
                attempt = *waits,
                delay_ms = delay.as_millis(),
                "transient server error; retrying"
            );
            std::thread::sleep(delay);
        }
        Ok(true)
    }
}

impl Fetch for HttpFetch {
    fn send(&self, request: &Request<'_>) -> Result<Fetched, FetchError> {
        match request.method {
            Method::Get => self.get(request),
            Method::Post(body) => self.post(request, body),
        }
    }

    // The real-network backend is the one place container pulls are welcome:
    // every pull request still passes guard_host and SafeResolver here, and
    // the puller's public-registry allowlist narrows it further.
    fn allows_oci(&self) -> bool {
        true
    }
}

/// A redirect chain's starting origin, and whether the chain has left it.
#[derive(Debug)]
struct Chain {
    origin: url::Origin,
    left: bool,
}

impl Chain {
    fn new(start: &reqwest::Url) -> Self {
        Self {
            origin: start.origin(),
            left: false,
        }
    }

    /// Record a hop to `url`, returning whether the chain has left its
    /// starting origin by now. Latched: a chain that has left never regains
    /// the origin's credentials, even on a hop back to it (A → B → A).
    fn hop(&mut self, url: &reqwest::Url) -> bool {
        self.left |= url.origin() != self.origin;
        self.left
    }
}

/// Whether `url` is exactly a GitHub repository document,
/// `https://api.github.com/repos/{owner}/{repo}`: no port, credentials,
/// query, fragment or further path, and names of GitHub's own alphabet.
fn is_github_repository_document(url: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(url) else {
        return false;
    };
    let name = |segment: Option<&str>| {
        segment.is_some_and(|s| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        })
    };
    let Some(mut segments) = url.path_segments() else {
        return false;
    };
    url.scheme() == "https"
        && url.host_str() == Some("api.github.com")
        && url.port().is_none()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && segments.next() == Some("repos")
        && name(segments.next())
        && name(segments.next())
        && segments.next().is_none()
}

/// A finished response as a [`Fetched`]: its status checked (unless the
/// request takes `any_status`) and its body read under `limit` and `deadline`.
fn response(
    resp: reqwest::blocking::Response,
    request: &Request<'_>,
    limit: u64,
    deadline: Instant,
    final_url: String,
    redirects: Vec<String>,
) -> Result<Fetched, FetchError> {
    let status = resp.status();
    if !status.is_success() && !request.any_status {
        return Err(FetchError::Status(status.as_u16()));
    }
    let headers = response_headers(&resp);
    let bytes = read_body_capped(resp, limit, deadline, request.spool)?;
    Ok(Fetched {
        bytes,
        final_url,
        status: status.as_u16(),
        headers,
        redirects,
    })
}

/// Read a response body under the per-fetch byte ceiling (`limit`) and the
/// request's `deadline` — into memory, or into the new file `spool`, leaving
/// the returned bytes empty. A declared `Content-Length` over the cap is
/// rejected before a single body byte is read — the common case for an
/// oversize artifact, which a registry or CDN sizes honestly — so we don't pull
/// tens of MB only to discard them; an honest one sizes the buffer up front.
/// The streaming cap in [`copy_bounded`] remains the authoritative backstop
/// for a missing or dishonest header.
fn read_body_capped(
    resp: reqwest::blocking::Response,
    limit: u64,
    deadline: Instant,
    spool: Option<&Path>,
) -> Result<Vec<u8>, FetchError> {
    let declared = resp.content_length();
    if let Some(len) = declared
        && len > limit
    {
        return Err(FetchError::TooLarge);
    }
    let Some(path) = spool else {
        let capacity = declared.map_or(0, |len| usize::try_from(len.min(limit)).unwrap_or(0));
        let mut bytes = Vec::with_capacity(capacity);
        copy_bounded(resp, &mut bytes, limit, deadline)?;
        return Ok(bytes);
    };
    let spool_error = |e: std::io::Error| {
        tracing::warn!(target: "transport", path = %path.display(), error = %e, "cannot spool response");
        FetchError::Io(format!("spool: {e}"))
    };
    let file = crate::fetch::cache::create_private(path).map_err(spool_error)?;
    let mut out = std::io::BufWriter::new(file);
    copy_bounded(resp, &mut out, limit, deadline)?;
    out.flush().map_err(spool_error)?;
    Ok(Vec::new())
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
            .map_err(|e| FetchError::Io(e.to_string()))?;
        copied += n as u64;
    }
}

/// Whether a caller header rides along on a redirect hop. Once the chain has
/// left its starting origin the credential-bearing ones are dropped, as
/// reqwest's own redirect policy would; everything else (`Accept`,
/// registry-specific selectors) is kept.
fn forward_header(name: &str, left_origin: bool) -> bool {
    !left_origin
        || !["authorization", "cookie", "proxy-authorization"]
            .iter()
            .any(|sensitive| name.eq_ignore_ascii_case(sensitive))
}

/// How a response asks to be retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pause {
    /// The host asked every client to wait: a `429`, a `Retry-After`, or a
    /// rate limit it reports exhausted. Every request through this client
    /// waits it out.
    Host(Duration),
    /// A transient server failure: this one request is retried after a local
    /// sleep, and the host is left to every other request.
    Request(Duration),
}

/// How long a response asks us to wait before asking again, and whom it
/// binds. A `429` names its time (`Retry-After`, or an exhausted limit's
/// reset), else backs off 1 s, 2 s, 4 s. GitHub reports an exhausted or
/// throttled rate limit as a `403` with `x-ratelimit-remaining: 0` or
/// `Retry-After`. A `408` or `500`/`502`/`503`/`504` naming a `Retry-After`
/// speaks for the host; without one it is this request's failure, retried
/// alone 1 s, 2 s, 4 s later when `retry_transient` (a GET).
fn pause(
    status: StatusCode,
    headers: &HeaderMap,
    waits: u32,
    retry_transient: bool,
) -> Option<Pause> {
    let number = |name: &str| headers.get(name)?.to_str().ok()?.trim().parse::<u64>().ok();
    let retry_after = number("retry-after").map(Duration::from_secs);
    let exhausted = number("x-ratelimit-remaining") == Some(0);
    let reset = number("x-ratelimit-reset")
        .map(|at| Duration::from_secs(at.saturating_sub(crate::fetch::now())));
    let exponential = Duration::from_secs(1 << waits.min(5));
    match status.as_u16() {
        429 => Some(Pause::Host(
            retry_after
                .or(reset.filter(|_| exhausted))
                .unwrap_or(exponential),
        )),
        403 if exhausted || retry_after.is_some() => Some(Pause::Host(
            retry_after.or(reset).unwrap_or(Duration::from_secs(60)),
        )),
        408 | 500 | 502 | 503 | 504 => match retry_after {
            Some(delay) => Some(Pause::Host(delay)),
            None => retry_transient.then_some(Pause::Request(exponential)),
        },
        _ => None,
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
            tracing::debug!(
                target: "transport",
                host,
                status,
                remaining_ms = pause.as_millis(),
                "host is backing us off; failing without asking"
            );
            return Err(FetchError::Status(status));
        }
        tracing::debug!(
            target: "transport",
            host,
            status,
            delay_ms = pause.as_millis(),
            "waiting out host back-off"
        );
        std::thread::sleep(pause);
        Ok(())
    }

    /// Leave `host` alone for `delay`, unless it is already held longer.
    fn hold(&self, host: &str, delay: Duration, status: u16) {
        crate::metrics::backoff(host, status, delay);
        let now = Instant::now();
        // A hostile `Retry-After: 18446744073709551615` must not panic the
        // addition; past `MAX_BACKOFF_WAIT` any hold already means "fail now".
        let until = now + delay.min(MAX_HOLD);
        let mut held = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        held.retain(|_, (when, _)| *when > now);
        let entry = held.entry(host.to_string()).or_insert((until, status));
        if entry.0 < until {
            *entry = (until, status);
        }
        drop(held);
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

// ---------------------------------------------------------------------------
// Offline test backend, compiled for this crate's tests and, behind the
// `test-util` feature, for a dependent's.
// ---------------------------------------------------------------------------

/// In-memory [`Fetch`] backend for tests: a fixed URL → response map. The
/// drop-in for [`HttpFetch`] so the orchestration runs offline. Available
/// with the `test-util` feature.
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug, Default, Clone)]
pub struct Fixtures {
    responses: HashMap<String, Fetched>,
    refusals: HashMap<String, u16>,
    /// Bodies for refusals, served only to an
    /// [`any_status`](Request::any_status) request.
    refusal_bodies: HashMap<String, Vec<u8>>,
}

#[cfg(any(test, feature = "test-util"))]
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

#[cfg(any(test, feature = "test-util"))]
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

    #[test]
    fn http_refuses_literal_internal_ips_without_network() {
        // The literal-IP / scheme guards run before any send(), so this is
        // offline — a regression test for the resolver-bypass via IP URLs.
        let net = HttpFetch::new().expect("client");
        for url in [
            "https://127.0.0.1/x",
            "https://169.254.169.254/latest/meta-data/",
            "https://[::1]/x",
            "https://10.0.0.1/x",
            "http://example.com/x", // non-https
        ] {
            match net.send(&Request::get(url)) {
                Err(FetchError::Refused(_)) => {}
                other => panic!("{url} should be refused, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_resolver_refusal_says_why() {
        // `localhost` comes from the hosts file, so this stays offline. The
        // name passes the literal-IP guard and is refused by the resolver,
        // whose reason must survive reqwest's "error sending request" wrapper.
        let net = HttpFetch::new().expect("client");
        match net.send(&Request::get("https://localhost/x")) {
            Err(FetchError::Refused(why)) => {
                assert!(why.contains("non-public host: localhost"), "{why}");
            }
            other => panic!("localhost should be refused by the resolver, got {other:?}"),
        }
    }

    use reqwest::header::HeaderValue;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(*name, HeaderValue::from_str(value).unwrap());
        }
        map
    }

    fn status(code: u16) -> StatusCode {
        StatusCode::from_u16(code).unwrap()
    }

    #[test]
    fn a_server_asking_to_back_off_is_heard() {
        let none = HeaderMap::new();
        let secs = Duration::from_secs;
        // A 429 says how long, or backs off exponentially.
        let asked = headers(&[("retry-after", "7")]);
        assert_eq!(
            pause(status(429), &asked, 0, false),
            Some(Pause::Host(secs(7)))
        );
        assert_eq!(
            pause(status(429), &none, 2, false),
            Some(Pause::Host(secs(4)))
        );
        // A 503 holds the host only when it names a time.
        assert_eq!(pause(status(503), &none, 0, false), None);
        assert_eq!(
            pause(status(503), &asked, 0, false),
            Some(Pause::Host(secs(7)))
        );
        // GitHub's exhausted rate limit is a 403 that resets at a stated time.
        let reset = (crate::fetch::now() + 600).to_string();
        let exhausted = headers(&[
            ("x-ratelimit-remaining", "0"),
            ("x-ratelimit-reset", &reset),
        ]);
        let Some(Pause::Host(wait)) = pause(status(403), &exhausted, 0, false) else {
            panic!("an exhausted rate limit holds the host");
        };
        assert!(wait > secs(590) && wait <= secs(600), "{wait:?}");
        // An ordinary refusal is an answer, not a request to wait.
        assert_eq!(pause(status(403), &none, 0, true), None);
        for code in [400, 401, 404] {
            assert_eq!(pause(status(code), &asked, 0, true), None, "{code}");
        }
    }

    /// One worker's 500 is its own request's failure: retried alone, after a
    /// local sleep, never a hold on every request to the host.
    #[test]
    fn a_transient_server_error_never_holds_the_host() {
        let none = HeaderMap::new();
        for code in [408, 500, 502, 503, 504] {
            assert_eq!(
                pause(status(code), &none, 1, true),
                Some(Pause::Request(Duration::from_secs(2))),
                "{code}: a GET retries alone"
            );
            assert_eq!(
                pause(status(code), &none, 0, false),
                None,
                "{code}: a POST does not"
            );
        }
        // Naming a time speaks for the host, though.
        let asked = headers(&[("retry-after", "5")]);
        assert_eq!(
            pause(status(500), &asked, 0, true),
            Some(Pause::Host(Duration::from_secs(5)))
        );
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
    fn a_hostile_retry_after_cannot_overflow_the_hold() {
        let backoff = Backoff::default();
        backoff.hold("hostile.test", Duration::MAX, 429);
        let deadline = Instant::now() + REQUEST_DEADLINE;
        assert_eq!(
            backoff.wait("hostile.test", deadline),
            Err(FetchError::Status(429))
        );
    }

    #[test]
    fn the_github_token_goes_to_repository_documents_alone_and_never_prints() {
        let net = HttpFetch::new()
            .unwrap()
            .with_github_token(Some("ghp_secret".into()));
        let repo = "https://api.github.com/repos/o/r";
        let token = |request: Request<'_>| net.github_token(&request, false);
        assert_eq!(token(Request::get(repo).github_auth()), Some("ghp_secret"));
        assert_eq!(token(Request::get(repo)), None, "opt-in per request");
        assert_eq!(
            token(
                Request::get(repo)
                    .github_auth()
                    .with_headers(&[("Authorization", "token theirs")])
            ),
            None,
            "the caller's own credentials win"
        );
        assert_eq!(
            net.github_token(&Request::get(repo).github_auth(), true),
            None,
            "never once the chain has left the origin"
        );
        // A registry-chosen API URL (Packagist's zipball) or any other
        // endpoint goes anonymously.
        for other in [
            "https://api.github.com/repos/victim/private/zipball/main",
            "https://api.github.com/repos/victim/private/contents/.env",
            "https://api.github.com/repos/o",
            "https://api.github.com/user",
            "https://api.github.com/repos/o/r?ref=x",
            "https://api.github.com:8443/repos/o/r",
            "https://api.github.com/repos/o%2Fx/r",
            "https://codeload.github.com/repos/o/r",
            "http://api.github.com/repos/o/r",
        ] {
            assert_eq!(token(Request::get(other).github_auth()), None, "{other}");
        }
        assert!(!format!("{net:?}").contains("ghp_secret"));
    }

    /// A → B → A: the hop back to the starting origin is still past a hop
    /// that left it, so it carries no credentials.
    #[test]
    fn leaving_the_origin_is_latched() {
        let url = |u: &str| reqwest::Url::parse(u).unwrap();
        let a = url("https://api.github.com/repos/o/r");
        let mut chain = Chain::new(&a);
        assert!(!chain.hop(&a));
        assert!(!chain.hop(&url("https://api.github.com/repositories/1")));
        assert!(chain.hop(&url("https://evil.example/bounce")));
        assert!(
            chain.hop(&a),
            "back at the origin, still past a foreign hop"
        );
    }

    #[test]
    fn credentials_do_not_follow_a_cross_origin_redirect() {
        for name in ["Authorization", "cookie", "Proxy-Authorization"] {
            assert!(
                forward_header(name, false),
                "{name} stays on the same origin"
            );
            assert!(
                !forward_header(name, true),
                "{name} must not leave the origin"
            );
        }
        // Non-credential headers a registry needs survive the hop.
        for name in ["Accept", "Content-Type", "Snap-Device-Series"] {
            assert!(forward_header(name, true), "{name} must survive a redirect");
        }
    }

    /// A request may lower the operator's ceiling for itself, never raise it.
    #[test]
    fn a_request_cannot_raise_the_operator_ceiling() {
        let net = HttpFetch::new().unwrap().with_max_bytes(1000);
        let registry = reqwest::Url::parse("https://registry.npmjs.org/x").unwrap();
        let limit = |request: Request<'_>| net.body_limit(&request, &registry);
        assert_eq!(limit(Request::get(registry.as_str())), 1000);
        assert_eq!(limit(Request::get(registry.as_str()).max_bytes(10)), 10);
        assert_eq!(
            limit(Request::get(registry.as_str()).max_bytes(1 << 40)),
            1000
        );
        // A document from a host fletch did not choose is capped lower still.
        let net = HttpFetch::new().unwrap();
        let foreign = reqwest::Url::parse("https://evil.example/x").unwrap();
        assert_eq!(
            net.body_limit(&Request::get(foreign.as_str()), &foreign),
            MAX_FOREIGN_DOCUMENT_BYTES
        );
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
        // Never-ending, one byte per read: only the whole-request deadline
        // stops it. The deadline is already past, so no read is waited on.
        struct Endless;
        impl Read for Endless {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                buf[0] = b'x';
                Ok(1)
            }
        }
        assert!(matches!(
            read_bounded(Endless, u64::MAX, Instant::now()),
            Err(FetchError::Timeout)
        ));
    }

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
}
