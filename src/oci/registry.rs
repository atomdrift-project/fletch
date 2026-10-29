//! The registry half of a pull: the OCI distribution protocol (token
//! handshake, manifest, blobs) spoken over the caller's [`Fetch`] backend,
//! with every blob spooled to disk and held to its declared size and digest.

use std::collections::HashMap;
use std::io::Read;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use serde::Deserialize;

use super::flatten::Encoding;
use crate::fetch::cache::{Spool, create_private};
use crate::fetch::{Fetch, FetchError, Fetched, Request};

/// Ceiling on how many layers an image may declare. Real images sit far below
/// it — Docker's historical aufs limit was 127 — so this only ever fires on a
/// manifest built to be pathological. It bounds the *per-layer* work (a blob
/// request, a decoder and two tar parses each) that the byte cap alone does
/// not: a manifest of a hundred thousand near-empty layers costs almost no
/// bytes. Checked on the manifest, before any blob is requested.
const MAX_LAYERS: usize = 256;

/// Registries an `oci://` pull may talk to. The reference host comes from a
/// purl's `repository_url` qualifier — feed-supplied data — so only
/// well-known public registries are reachable. Extend deliberately, never
/// dynamically.
const ALLOWED_REGISTRIES: &[&str] = &[
    "docker.io",
    "index.docker.io",
    "registry-1.docker.io",
    "ghcr.io",
    "quay.io",
    "gcr.io",
    "registry.k8s.io",
    "public.ecr.aws",
];

/// Docker Hub's API host, which its other spellings stand for.
const DOCKER_HUB: &str = "registry-1.docker.io";

const OCI_LAYER: &str = "application/vnd.oci.image.layer.v1.tar";
const OCI_LAYER_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
const OCI_LAYER_ZSTD: &str = "application/vnd.oci.image.layer.v1.tar+zstd";
const DOCKER_LAYER: &str = "application/vnd.docker.image.rootfs.diff.tar";
const DOCKER_LAYER_GZIP: &str = "application/vnd.docker.image.rootfs.diff.tar.gzip";

/// The manifest shapes asked for: an image manifest, or an index (manifest
/// list) to pick the platform's manifest from — OCI and Docker spellings.
const MANIFEST_ACCEPT: &str = "application/vnd.oci.image.index.v1+json, \
     application/vnd.docker.distribution.manifest.list.v2+json, \
     application/vnd.oci.image.manifest.v1+json, \
     application/vnd.docker.distribution.manifest.v2+json";

/// The largest manifest or index read. Real ones are a few KiB; a manifest at
/// the layer ceiling is well under this.
const MAX_MANIFEST_BYTES: u64 = 4 << 20;

/// The largest token-realm reply read: a JSON object around one bearer token.
const MAX_TOKEN_REPLY_BYTES: u64 = 1 << 20;

/// The longest bearer token accepted. Registry JWTs run to a few KiB.
const MAX_TOKEN_BYTES: usize = 16 << 10;

/// The least response a blob request admits, whatever the layer's declared
/// size: room for a `401` challenge or an error body, which a 32-byte empty
/// layer's own size would refuse.
const MIN_BLOB_RESPONSE_BYTES: u64 = 64 << 10;

/// Blobs one pull reads at once: enough to overlap round trips to a
/// registry's CDN without opening a socket per layer.
const BLOB_WORKERS: usize = 4;

/// Wall-clock bound on the whole pull. Each request carries the backend's own
/// deadline as well, so this can be overrun by at most one request.
const PULL_DEADLINE: Duration = Duration::from_secs(30 * 60);

/// One pulled layer: its blob on disk, and how that blob is encoded.
pub(super) struct Blob {
    pub(super) spool: Spool,
    pub(super) encoding: Encoding,
}

/// Anonymous pull of the linux/amd64 image `reference` through `net` — the
/// platform go-containerregistry's `crane` resolves by default — with each
/// layer spooled beside `out`. Returns the layers in manifest (base → top)
/// order, which the flatten depends on, and the manifest digest (the
/// platform manifest's, for an index).
///
/// Every layer is vetted with [`vet_layers`] before the first blob request,
/// and none is fetched from anywhere but the registry.
pub(super) fn pull(
    reference: &str,
    net: &dyn Fetch,
    out: &Spool,
    cap: u64,
) -> Result<(Vec<Blob>, String), FetchError> {
    let image = ImageRef::parse(reference)?;
    tracing::debug!(
        target: "oci",
        host = image.host,
        repository = image.repository,
        reference = image.reference,
        "pulling image"
    );
    let mut session = Session {
        net,
        image: &image,
        token: None,
        deadline: Instant::now() + PULL_DEADLINE,
    };
    let (mut manifest, mut digest) = session.manifest(&image.reference)?;
    if let Some(entries) = &manifest.manifests {
        let entry = entries
            .iter()
            .find(|entry| {
                entry
                    .platform
                    .as_ref()
                    .is_some_and(|p| p.os == "linux" && p.architecture == "amd64")
            })
            .ok_or_else(|| FetchError::Refused("no linux/amd64 image in the index".into()))?;
        if !valid_digest(&entry.digest) {
            return Err(FetchError::Refused(format!(
                "index entry digest {:?} is malformed",
                entry.digest
            )));
        }
        digest = entry.digest.clone();
        tracing::debug!(target: "oci", digest, "selected the linux/amd64 manifest");
        (manifest, _) = session.manifest(&digest)?;
        if manifest.manifests.is_some() {
            return Err(FetchError::Refused(
                "index entry is another index, not an image".into(),
            ));
        }
    }
    let layers = manifest
        .layers
        .ok_or_else(|| FetchError::Refused("manifest lists no layers".into()))?;
    let encodings = vet_layers(&layers, cap)?;
    let spools = session.blobs(&layers, out)?;
    let blobs = spools
        .into_iter()
        .zip(encodings)
        .map(|(spool, encoding)| Blob { spool, encoding })
        .collect();
    Ok((blobs, digest))
}

/// A parsed `oci://` reference: the registry's API host, the repository, and
/// what to ask the manifest endpoint for (a digest when pinned, else a tag).
#[derive(Debug, PartialEq, Eq)]
struct ImageRef {
    host: String,
    repository: String,
    reference: String,
}

impl ImageRef {
    /// Parse `[host/]repository[:tag][@digest]` strictly — every part is
    /// interpolated into a registry URL, so anything outside the distribution
    /// spec's grammar is refused rather than escaped. A host-less name is on
    /// Docker Hub, and a single-segment one under `library/`. The registry
    /// must be on [`ALLOWED_REGISTRIES`].
    fn parse(reference: &str) -> Result<Self, FetchError> {
        let bad = || FetchError::Refused(format!("bad OCI reference {reference:?}"));
        let (rest, digest) = match reference.split_once('@') {
            Some((rest, digest)) => (rest, Some(digest)),
            None => (reference, None),
        };
        // The tag follows the last ':' after the last '/' — an earlier ':' is
        // a registry port.
        let last = rest.rfind('/').map_or(0, |i| i + 1);
        let (name, tag) = match rest[last..].rfind(':') {
            Some(i) => (&rest[..last + i], Some(&rest[last + i + 1..])),
            None => (rest, None),
        };
        let (host, repository) = match name.split_once('/') {
            Some((first, path)) if first.contains(['.', ':']) || first == "localhost" => {
                (first, path)
            }
            _ => ("docker.io", name),
        };
        // Host names are case-insensitive and 443 is https's own port, so
        // `GHCR.IO:443` is ghcr.io; anything else must match exactly.
        let host = host.to_ascii_lowercase();
        let host = host.strip_suffix(":443").unwrap_or(&host);
        if !ALLOWED_REGISTRIES.contains(&host) {
            return Err(FetchError::Refused(format!(
                "registry {host:?} not in the public allowlist"
            )));
        }
        let docker_hub = matches!(host, "docker.io" | "index.docker.io" | DOCKER_HUB);
        let repository = if docker_hub && !repository.contains('/') {
            format!("library/{repository}")
        } else {
            repository.to_string()
        };
        if !valid_repository(&repository)
            || tag.is_some_and(|t| !valid_tag(t))
            || digest.is_some_and(|d| !valid_digest(d))
        {
            return Err(bad());
        }
        Ok(Self {
            host: if docker_hub { DOCKER_HUB } else { host }.to_string(),
            repository,
            reference: digest.or(tag).unwrap_or("latest").to_string(),
        })
    }
}

/// A repository path: `/`-separated lowercase components, each starting and
/// ending with an alphanumeric and otherwise `[a-z0-9._-]`.
fn valid_repository(repository: &str) -> bool {
    repository.len() <= 255
        && repository.split('/').all(|part| {
            let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
            part.bytes().next().is_some_and(alnum)
                && part.bytes().last().is_some_and(alnum)
                && part
                    .bytes()
                    .all(|b| alnum(b) || matches!(b, b'.' | b'_' | b'-'))
        })
}

/// A tag: `[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}`.
fn valid_tag(tag: &str) -> bool {
    tag.len() <= 128
        && tag
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_')
        && tag
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// A digest this module can verify: `sha256:` or `sha512:` and the full
/// lowercase hex of that hash.
fn valid_digest(digest: &str) -> bool {
    let hex = |h: &str, len: usize| {
        h.len() == len && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    };
    digest.strip_prefix("sha256:").is_some_and(|h| hex(h, 64))
        || digest.strip_prefix("sha512:").is_some_and(|h| hex(h, 128))
}

/// A running digest under one of the algorithms [`valid_digest`] accepts.
enum Hasher {
    Sha256(sha2::Sha256),
    Sha512(sha2::Sha512),
}

impl Hasher {
    /// A hasher for `digest`'s algorithm, by its prefix.
    fn new(digest: &str) -> Option<Self> {
        use sha2::Digest as _;
        if digest.starts_with("sha256:") {
            Some(Self::Sha256(sha2::Sha256::new()))
        } else if digest.starts_with("sha512:") {
            Some(Self::Sha512(sha2::Sha512::new()))
        } else {
            None
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        use sha2::Digest as _;
        match self {
            Self::Sha256(h) => h.update(bytes),
            Self::Sha512(h) => h.update(bytes),
        }
    }

    /// The digest, spelled `algorithm:hex`.
    fn finish(self) -> String {
        use sha2::Digest as _;
        match self {
            Self::Sha256(h) => format!("sha256:{}", hex::encode(h.finalize())),
            Self::Sha512(h) => format!("sha512:{}", hex::encode(h.finalize())),
        }
    }
}

/// The digest of `bytes` under `digest`'s algorithm, spelled like it.
fn digest_of(digest: &str, bytes: &[u8]) -> Option<String> {
    let mut hasher = Hasher::new(digest)?;
    hasher.update(bytes);
    Some(hasher.finish())
}

/// A content descriptor: what a manifest says about a layer, or an index
/// about a platform's manifest.
#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Descriptor {
    media_type: String,
    digest: String,
    size: u64,
    urls: Option<Vec<String>>,
    platform: Option<Platform>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Platform {
    os: String,
    architecture: String,
}

/// An image manifest (`layers`) or an index (`manifests`).
#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Manifest {
    schema_version: u32,
    manifests: Option<Vec<Descriptor>>,
    layers: Option<Vec<Descriptor>>,
}

/// One registry, spoken to anonymously through `net`: the bearer token its
/// challenge led to, once one has been needed, and the pull's deadline.
struct Session<'a> {
    net: &'a dyn Fetch,
    image: &'a ImageRef,
    token: Option<String>,
    deadline: Instant,
}

impl Session<'_> {
    /// GET `url` from the registry — its body into `spool` when one is given —
    /// answering a `401` challenge once with an anonymous pull token. Any
    /// other non-success status is an error.
    fn get(
        &mut self,
        url: &str,
        accept: Option<&str>,
        limit: u64,
        spool: Option<&Spool>,
    ) -> Result<Fetched, FetchError> {
        let mut resp = self.send(url, accept, limit, spool)?;
        if resp.status == 401 && self.token.is_none() {
            let challenge = header(&resp, "www-authenticate")
                .ok_or_else(|| FetchError::Refused("401 without a challenge".into()))?;
            self.token = Some(self.pull_token(challenge)?);
            if let Some(spool) = spool {
                // The challenge's own body, spooled where the blob goes.
                discard(spool)?;
            }
            resp = self.send(url, accept, limit, spool)?;
        }
        success(resp)
    }

    fn send(
        &self,
        url: &str,
        accept: Option<&str>,
        limit: u64,
        spool: Option<&Spool>,
    ) -> Result<Fetched, FetchError> {
        if Instant::now() >= self.deadline {
            return Err(FetchError::Timeout);
        }
        let bearer = self.token.as_ref().map(|token| format!("Bearer {token}"));
        let mut headers = Vec::new();
        if let Some(accept) = accept {
            headers.push(("Accept", accept));
        }
        // Dropped by the transport on any hop that leaves the registry's
        // origin, so a blob's CDN redirect never sees it.
        if let Some(bearer) = &bearer {
            headers.push(("Authorization", bearer.as_str()));
        }
        let mut request = Request::get(url)
            .with_headers(&headers)
            .any_status()
            .max_bytes(limit);
        if let Some(spool) = spool {
            request = request.spool_to(spool.path());
        }
        self.net.send(&request)
    }

    /// An anonymous pull token from the realm a `Bearer` challenge names. The
    /// realm is registry-supplied, so it is held to https here and to the
    /// transport's SSRF floor like every other request, and the scope asked
    /// for is this repository's pull — not whatever the challenge proposes.
    /// The token goes into a header, so anything but visible ASCII is refused.
    fn pull_token(&self, challenge: &str) -> Result<String, FetchError> {
        let params = bearer_challenge(challenge)
            .ok_or_else(|| FetchError::Refused("unsupported auth challenge".into()))?;
        let mut realm = params
            .get("realm")
            .and_then(|realm| url::Url::parse(realm).ok())
            .filter(|realm| realm.scheme() == "https")
            .ok_or_else(|| FetchError::Refused("auth realm is not an https URL".into()))?;
        {
            let mut query = realm.query_pairs_mut();
            if let Some(service) = params.get("service") {
                query.append_pair("service", service);
            }
            query.append_pair(
                "scope",
                &format!("repository:{}:pull", self.image.repository),
            );
        }
        if Instant::now() >= self.deadline {
            return Err(FetchError::Timeout);
        }
        tracing::debug!(
            target: "oci",
            realm = realm.host_str().unwrap_or_default(),
            repository = self.image.repository,
            "requesting an anonymous pull token"
        );
        let resp = self.net.send(
            &Request::get(realm.as_str())
                .with_headers(&[("Accept", "application/json")])
                .max_bytes(MAX_TOKEN_REPLY_BYTES),
        )?;
        #[derive(Deserialize)]
        struct Reply {
            token: Option<String>,
            access_token: Option<String>,
        }
        let reply: Reply = serde_json::from_slice(&resp.bytes)
            .map_err(|e| FetchError::Refused(format!("auth token reply: {e}")))?;
        let token = reply
            .token
            .or(reply.access_token)
            .filter(|token| {
                !token.is_empty()
                    && token.len() <= MAX_TOKEN_BYTES
                    && token.bytes().all(|b| b.is_ascii_graphic())
            })
            .ok_or_else(|| FetchError::Refused("auth token missing or malformed".into()))?;
        tracing::debug!(target: "oci", bytes = token.len(), "pull token issued");
        Ok(token)
    }

    /// The manifest `reference` names, and its digest. The body is checked
    /// against the digest a pinned `reference` names and against the
    /// registry's own `Docker-Content-Digest`, so a registry (or anything
    /// between) cannot substitute another image under a pinned name.
    fn manifest(&mut self, reference: &str) -> Result<(Manifest, String), FetchError> {
        let url = format!(
            "https://{}/v2/{}/manifests/{reference}",
            self.image.host, self.image.repository
        );
        let resp = self.get(&url, Some(MANIFEST_ACCEPT), MAX_MANIFEST_BYTES, None)?;
        let pinned = valid_digest(reference).then_some(reference);
        let expect = pinned.unwrap_or("sha256:");
        let digest = digest_of(expect, &resp.bytes)
            .ok_or_else(|| FetchError::Refused(format!("unsupported digest {expect:?}")))?;
        let mismatch = |claimed: &str| {
            FetchError::Refused(format!("manifest digest {digest} does not match {claimed}"))
        };
        if let Some(pinned) = pinned
            && pinned != digest
        {
            return Err(mismatch(pinned));
        }
        if let Some(claimed) = header(&resp, "docker-content-digest")
            && digest_of(claimed, &resp.bytes).is_some_and(|actual| actual != claimed)
        {
            return Err(mismatch(claimed));
        }
        let manifest: Manifest = serde_json::from_slice(&resp.bytes)
            .map_err(|e| FetchError::Refused(format!("malformed manifest: {e}")))?;
        if manifest.schema_version != 2 {
            return Err(FetchError::Refused(format!(
                "unsupported manifest schema {}",
                manifest.schema_version
            )));
        }
        tracing::debug!(
            target: "oci",
            reference,
            digest,
            index = manifest.manifests.is_some(),
            layers = manifest.layers.as_ref().map(Vec::len),
            "manifest verified"
        );
        Ok((manifest, digest))
    }

    /// Every blob `descs` name, each spooled beside `out` and held to its
    /// declared size and digest, returned in order. The first is read alone,
    /// so a registry that wants a token only for blobs has its challenge
    /// answered once; the rest are read [`BLOB_WORKERS`] at a time with that
    /// token, and the first failure stops the others taking new work.
    fn blobs(&mut self, descs: &[Descriptor], out: &Spool) -> Result<Vec<Spool>, FetchError> {
        let spools: Vec<Spool> = (0..descs.len())
            .map(|i| out.beside(&format!("layer{i}")))
            .collect();
        let mut jobs = descs.iter().zip(&spools);
        let Some((first, spool)) = jobs.next() else {
            return Ok(spools);
        };
        let resp = self.get(&self.blob_url(first), None, blob_limit(first), Some(spool))?;
        land(first, &resp, spool)?;

        let jobs: Vec<_> = jobs.collect();
        let this = &*self;
        let next = AtomicUsize::new(0);
        let failed = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let workers: Vec<_> = (0..BLOB_WORKERS.min(jobs.len()))
                .map(|_| {
                    scope.spawn(|| {
                        while !failed.load(Ordering::Relaxed) {
                            let Some(&(desc, spool)) =
                                jobs.get(next.fetch_add(1, Ordering::Relaxed))
                            else {
                                break;
                            };
                            if let Err(error) = this.blob(desc, spool) {
                                failed.store(true, Ordering::Relaxed);
                                return Err(error);
                            }
                        }
                        Ok(())
                    })
                })
                .collect();
            // Every worker is joined before the first failure is reported, so
            // none outlives the spools it writes.
            let mut outcome = Ok(());
            for worker in workers {
                let joined = worker.join().unwrap_or_else(|payload| {
                    let message = panic_message(payload.as_ref());
                    tracing::warn!(target: "oci", message, "blob worker panicked");
                    Err(FetchError::Internal(format!(
                        "blob worker panicked: {message}"
                    )))
                });
                if outcome.is_ok() {
                    outcome = joined;
                }
            }
            outcome
        })?;
        Ok(spools)
    }

    /// GET the blob `desc` names into `spool` with the token already in hand
    /// — a fresh challenge mid-pull is an error rather than a race between
    /// workers to fetch another token — and hold it to its declaration.
    fn blob(&self, desc: &Descriptor, spool: &Spool) -> Result<(), FetchError> {
        let resp =
            success(self.send(&self.blob_url(desc), None, blob_limit(desc), Some(spool))?)?;
        land(desc, &resp, spool)
    }

    /// The registry URL of the blob `desc` names.
    fn blob_url(&self, desc: &Descriptor) -> String {
        format!(
            "https://{}/v2/{}/blobs/{}",
            self.image.host, self.image.repository, desc.digest
        )
    }
}

/// The most of a response to read for `desc`'s blob: its declared size, but
/// never less than [`MIN_BLOB_RESPONSE_BYTES`]. [`verify`] holds the body to
/// the exact declared size.
fn blob_limit(desc: &Descriptor) -> u64 {
    desc.size.max(MIN_BLOB_RESPONSE_BYTES)
}

/// `resp`, unless its status is not a success.
fn success(resp: Fetched) -> Result<Fetched, FetchError> {
    if (200..300).contains(&resp.status) {
        Ok(resp)
    } else {
        Err(FetchError::Status(resp.status))
    }
}

/// Bring `desc`'s blob to rest in `spool` — written from `resp`'s bytes when
/// the backend handed them back rather than spooling — and [`verify`] it.
fn land(desc: &Descriptor, resp: &Fetched, spool: &Spool) -> Result<(), FetchError> {
    let io = |e: std::io::Error| FetchError::Io(format!("layer {}: {e}", desc.digest));
    match create_private(spool.path()) {
        Ok(mut file) => std::io::Write::write_all(&mut file, &resp.bytes).map_err(io)?,
        // The transport's own spool, when it handed back no bytes.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && resp.bytes.is_empty() => {}
        Err(e) => return Err(io(e)),
    }
    verify(desc, spool)
}

/// Hold the blob in `spool` to the size and digest `desc` declares, reading
/// it once from disk.
fn verify(desc: &Descriptor, spool: &Spool) -> Result<(), FetchError> {
    let io = |e: std::io::Error| FetchError::Io(format!("layer {}: {e}", desc.digest));
    let mut hasher = Hasher::new(&desc.digest)
        .ok_or_else(|| FetchError::Refused(format!("unsupported digest {:?}", desc.digest)))?;
    let mut file = std::fs::File::open(spool.path()).map_err(io)?;
    let mut chunk = vec![0u8; 64 << 10];
    let mut size = 0u64;
    loop {
        let n = match file.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(io(e)),
        };
        hasher.update(&chunk[..n]);
        size += n as u64;
    }
    if size != desc.size {
        return Err(FetchError::Refused(format!(
            "layer {} is {size} bytes, not the {} its manifest declares",
            desc.digest, desc.size
        )));
    }
    if hasher.finish() != desc.digest {
        return Err(FetchError::Refused(format!(
            "layer {} does not match its digest",
            desc.digest
        )));
    }
    tracing::debug!(target: "oci", digest = desc.digest, size, "layer verified");
    Ok(())
}

/// Remove `spool`'s file, if any, so it can be written afresh.
fn discard(spool: &Spool) -> Result<(), FetchError> {
    match std::fs::remove_file(spool.path()) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            Err(FetchError::Io(format!("discard spool: {e}")))
        }
        _ => Ok(()),
    }
}

/// What a panicking thread said, when it said it as text.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> &str {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("non-text panic payload")
}

/// A response header's value, by case-insensitive name.
fn header<'a>(resp: &'a Fetched, name: &str) -> Option<&'a str> {
    resp.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// The parameters of a `Bearer` `WWW-Authenticate` challenge
/// (`Bearer realm="…",service="…",scope="…"`), keys lowercased. Values may be
/// quoted strings (with `\` escapes) or bare tokens; `None` for any other
/// scheme or a challenge that does not parse.
fn bearer_challenge(challenge: &str) -> Option<HashMap<String, String>> {
    let (scheme, mut rest) = challenge.trim().split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let mut params = HashMap::new();
    loop {
        rest = rest.trim_start_matches([' ', '\t', ',']);
        if rest.is_empty() {
            return Some(params);
        }
        let (key, after) = rest.split_once('=')?;
        let key = key.trim();
        if key.is_empty() || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return None;
        }
        let after = after.trim_start();
        let value = if let Some(quoted) = after.strip_prefix('"') {
            let mut value = String::new();
            let mut chars = quoted.char_indices();
            let end = loop {
                match chars.next()? {
                    (i, '"') => break i,
                    (_, '\\') => value.push(chars.next()?.1),
                    (_, c) => value.push(c),
                }
            };
            rest = &quoted[end + 1..];
            value
        } else {
            let end = after.find(',').unwrap_or(after.len());
            rest = &after[end..];
            after[..end].trim().to_string()
        };
        params.insert(key.to_ascii_lowercase(), value);
    }
}

/// How a layer of `media_type` is encoded; `None` for a type the flatten
/// cannot read. The deprecated non-distributable types are deliberately
/// absent: their whole purpose is a blob served from foreign `urls`, which
/// [`vet_layers`] refuses.
fn encoding(media_type: &str) -> Option<Encoding> {
    match media_type {
        OCI_LAYER | DOCKER_LAYER => Some(Encoding::Tar),
        OCI_LAYER_GZIP | DOCKER_LAYER_GZIP => Some(Encoding::Gzip),
        OCI_LAYER_ZSTD => Some(Encoding::Zstd),
        _ => None,
    }
}

/// Refuse a manifest before any blob is requested: no layers, more than
/// [`MAX_LAYERS`], a media type the flatten can't read, a foreign `urls`
/// fallback, a digest that is not plain `algorithm:hex` (it is interpolated
/// into the blob URL), or declared sizes that sum past `cap`. Each size and
/// digest is then enforced on the bytes actually received. Returns each
/// layer's encoding.
fn vet_layers(layers: &[Descriptor], cap: u64) -> Result<Vec<Encoding>, FetchError> {
    if layers.is_empty() {
        return Err(FetchError::Refused("image has no layers".into()));
    }
    if layers.len() > MAX_LAYERS {
        return Err(FetchError::TooLarge);
    }
    let mut total: u64 = 0;
    let mut encodings = Vec::with_capacity(layers.len());
    for layer in layers {
        let encoding = encoding(&layer.media_type).ok_or_else(|| {
            FetchError::Refused(format!(
                "unsupported layer media type {:?}",
                layer.media_type
            ))
        })?;
        if !valid_digest(&layer.digest) {
            return Err(FetchError::Refused(format!(
                "layer digest {:?} is malformed",
                layer.digest
            )));
        }
        if layer.urls.as_ref().is_some_and(|urls| !urls.is_empty()) {
            return Err(FetchError::Refused(format!(
                "layer {} names foreign urls",
                layer.digest
            )));
        }
        total = total.saturating_add(layer.size);
        encodings.push(encoding);
    }
    if total > cap {
        return Err(FetchError::TooLarge);
    }
    Ok(encodings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fetch::BlobCache;
    use crate::oci::tests::FakeRegistry;

    /// A manifest descriptor for a plain layer declaring `size` bytes.
    fn desc(size: u64) -> Descriptor {
        Descriptor {
            media_type: OCI_LAYER.to_string(),
            digest: format!("sha256:{}", "0".repeat(64)),
            size,
            ..Descriptor::default()
        }
    }

    #[test]
    fn absurd_layer_counts_are_refused() {
        // Near-empty layers cost almost nothing in bytes, so the byte cap can
        // never catch this — only the count can, and before any blob request.
        let many: Vec<Descriptor> = (0..=MAX_LAYERS).map(|_| desc(0)).collect();
        assert!(
            matches!(vet_layers(&many, 100), Err(FetchError::TooLarge)),
            "a manifest over the layer ceiling must be refused"
        );
        assert!(vet_layers(&many[..MAX_LAYERS], 100).is_ok());
    }

    #[test]
    fn a_manifest_is_vetted_before_any_blob_is_pulled() {
        // Declared sizes are capped in aggregate, like the expanded ones.
        assert!(vet_layers(&[desc(40), desc(40)], 100).is_ok());
        assert!(vet_layers(&[desc(40), desc(40), desc(40)], 100).is_err());
        assert!(vet_layers(&[desc(u64::MAX), desc(1)], 100).is_err());
        assert!(vet_layers(&[], 100).is_err());
        // A foreign url is a fetch from any host, outside the registry
        // allowlist.
        let foreign = Descriptor {
            urls: Some(vec!["https://169.254.169.254/latest".into()]),
            ..desc(1)
        };
        assert!(
            matches!(vet_layers(&[foreign], 100), Err(FetchError::Refused(why)) if why.contains("foreign"))
        );
        // As are the layer types that exist to use that fallback.
        let nondistributable = Descriptor {
            media_type: "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip".into(),
            ..desc(1)
        };
        assert!(
            matches!(vet_layers(&[nondistributable], 100), Err(FetchError::Refused(why)) if why.contains("media type"))
        );
        // Each layer's encoding comes back for the flatten.
        let gzip = Descriptor {
            media_type: DOCKER_LAYER_GZIP.into(),
            ..desc(1)
        };
        assert_eq!(
            vet_layers(&[desc(1), gzip], 100),
            Ok(vec![Encoding::Tar, Encoding::Gzip])
        );
    }

    #[test]
    fn a_negative_layer_size_does_not_parse() {
        let manifest = r#"{"schemaVersion":2,"layers":[{"mediaType":"x","digest":"y","size":-1}]}"#;
        assert!(serde_json::from_str::<Manifest>(manifest).is_err());
    }

    #[test]
    fn a_malformed_layer_digest_is_refused() {
        for digest in [
            "sha256:../../x",
            "sha256:",
            "sha256:00",
            "md5:00",
            "sha256:AB",
        ] {
            let bad = Descriptor {
                digest: digest.into(),
                ..desc(1)
            };
            assert!(
                matches!(vet_layers(&[bad], 100), Err(FetchError::Refused(_))),
                "{digest:?} must be refused"
            );
        }
    }

    #[test]
    fn disallowed_registry_is_refused() {
        let registry = FakeRegistry::default();
        let dir = tempfile::tempdir().unwrap();
        let out = BlobCache::with_dir(dir.path()).spool("abcd");
        let Err(err) = pull(
            "internal.corp:5000/secret/image:latest",
            &registry,
            &out,
            100,
        ) else {
            panic!("pull of a non-allowlisted registry must fail");
        };
        assert!(
            matches!(&err, FetchError::Refused(why) if why.contains("not in the public allowlist")),
            "{err}"
        );
        assert!(registry.requests().is_empty(), "refused before any request");
    }

    #[test]
    fn references_parse_strictly() {
        let parse = |r: &str| ImageRef::parse(r).map(|i| (i.host, i.repository, i.reference));
        let hub = |repo: &str, reference: &str| {
            Ok((
                DOCKER_HUB.to_string(),
                repo.to_string(),
                reference.to_string(),
            ))
        };
        assert_eq!(parse("nginx"), hub("library/nginx", "latest"));
        assert_eq!(
            parse("docker.io/library/nginx:1.25"),
            hub("library/nginx", "1.25")
        );
        assert_eq!(
            parse("index.docker.io/myorg/app"),
            hub("myorg/app", "latest")
        );
        assert_eq!(
            parse("GHCR.IO:443/owner/img"),
            Ok(("ghcr.io".into(), "owner/img".into(), "latest".into())),
            "a registry's case and https's own port are spelling, not identity"
        );
        let digest = format!("sha256:{}", "a".repeat(64));
        assert_eq!(
            parse(&format!("ghcr.io/owner/img:v1@{digest}")),
            Ok(("ghcr.io".into(), "owner/img".into(), digest.clone()))
        );
        for bad in [
            "ghcr.io/owner/img@sha256:244fd47e07d10", // short digest
            "ghcr.io/Owner/img",                      // uppercase
            "ghcr.io/owner/../img",
            "ghcr.io/owner/img:bad?tag",
            "ghcr.io/owner/img:",
            "ghcr.io/owner//img",
            "ghcr.io/owner/img#x",
            "ghcr.io/owner/img%2F..",
            "ghcr.io/owner/img@md5:00",
            "ghcr.io:444/owner/img", // another port is another server
        ] {
            assert!(ImageRef::parse(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn bearer_challenges_parse_robustly() {
        let got = bearer_challenge(
            r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io", scope="repository:a/b:pull",error="x\"y""#,
        )
        .unwrap();
        assert_eq!(got["realm"], "https://auth.docker.io/token");
        assert_eq!(got["service"], "registry.docker.io");
        assert_eq!(got["error"], "x\"y");
        assert_eq!(
            bearer_challenge(r#"bearer realm=https://r.test/t"#).unwrap()["realm"],
            "https://r.test/t"
        );
        assert!(bearer_challenge(r#"Basic realm="x""#).is_none());
        assert!(bearer_challenge(r#"Bearer realm="unterminated"#).is_none());
        assert!(bearer_challenge("Bearer =x").is_none());
    }

    #[test]
    fn digests_are_computed_under_the_named_algorithm() {
        let sha512 = digest_of("sha512:", b"x").unwrap();
        assert!(sha512.starts_with("sha512:") && valid_digest(&sha512));
        assert_eq!(
            digest_of("sha256:", b"").as_deref(),
            Some("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert_eq!(digest_of("md5:", b""), None);
    }
}
