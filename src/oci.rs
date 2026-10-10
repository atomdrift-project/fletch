//! Pull an OCI image and flatten it to a single rootfs tarball — the Rust
//! analog of forager's `crane.Pull` + `crane.Export` (go-containerregistry)
//! path, so both producers emit the same artifact shape (an xz-compressed tar
//! of the merged filesystem) for the same `pkg:oci` identity. The bytes are
//! NOT guaranteed identical across the two implementations (tar header and xz
//! encoder details differ); cross-implementation identity comes from the
//! manifest digest, which [`export`] returns and the fetch layer records.
//!
//! The distribution protocol is spoken here over the caller's
//! [`Fetch`] backend — a token handshake, then manifest and blob GETs — so
//! every request, the token realm and the blob CDN a registry redirects to
//! included, passes the same per-hop https and SSRF floor as any other fetch.
//! Pulls are additionally restricted to an allowlist of public registries:
//! `repository_url` is feed-supplied data, and an image is a large, costly
//! artifact to let a scanned file aim anywhere. For the same reason a layer
//! naming foreign `urls` is refused.

use crate::fetch::{Fetch, FetchError, Fetched, Request};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::io::{Cursor, Read, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Uncompressed-tar size cap, matching forager's `maxContainerBytes` guard:
/// a generous runaway stop for pathological images, not a package-size cap.
pub(crate) const MAX_EXPORT_BYTES: u64 = 2 << 30; // 2 GiB

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

/// The layer encodings we can flatten. The deprecated non-distributable types
/// are deliberately absent: their whole purpose is a blob served from foreign
/// `urls`, which [`vet_layers`] refuses.
const ACCEPTED_LAYER_TYPES: &[&str] = &[
    OCI_LAYER,
    OCI_LAYER_GZIP,
    OCI_LAYER_ZSTD,
    DOCKER_LAYER,
    DOCKER_LAYER_GZIP,
];

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

/// Blobs one pull reads at once: enough to overlap round trips to a
/// registry's CDN without opening a socket per layer.
const BLOB_WORKERS: usize = 4;

/// Wall-clock bound on the whole pull. Each request carries the backend's own
/// deadline as well, so this can be overrun by at most one request.
const PULL_DEADLINE: Duration = Duration::from_secs(30 * 60);

/// Bound on flattening and recompressing the layers: the CPU-bound half of an
/// export, which [`PULL_DEADLINE`] does not cover. Checked per tar entry.
const FLATTEN_DEADLINE: Duration = Duration::from_secs(30 * 60);

/// Longest entry or link name a layer may carry: Linux's `PATH_MAX`. Names are
/// attacker-sized (a GNU or PAX long name is bounded only by the layer), and
/// shadowing hashes every ancestor of a name, so an unbounded name costs time
/// quadratic in its length.
const MAX_PATH: usize = 4096;

/// Pull `reference` (`host/path:tag` or `host/path@sha256:…`, as produced by
/// `resolve_purl`'s `oci://` pseudo-URL) through `net` and export the
/// flattened rootfs as an xz-compressed tar. Returns the bytes and the image's
/// manifest digest — the content-addressed identity that is stable across
/// implementations.
pub(crate) fn export(reference: &str, net: &dyn Fetch) -> Result<(Vec<u8>, String), FetchError> {
    let (layers, digest) = pull(reference, net)?;
    let layers = decompress_all(layers, MAX_EXPORT_BYTES)?;
    let tar_xz = flatten_to_tar_xz(&layers)?;
    Ok((tar_xz, digest))
}

/// One downloaded layer blob, still in its transfer encoding.
struct Layer {
    data: Vec<u8>,
    media_type: String,
}

/// Decompress every layer, refusing an image whose layers together exceed
/// `cap` bytes once expanded.
///
/// The total is what matters, not the per-layer size. The flatten needs all
/// layers resident at once, so bounding each one individually bounds nothing:
/// N layers each just under the ceiling costs N times the ceiling. Compression
/// makes that cheap to mount — a few MB of crafted gzip expands to the ceiling
/// per layer, so a small download becomes an arbitrarily large allocation. The
/// running total is checked as each layer lands, so an oversized image is
/// refused partway through rather than after it is all in memory.
fn decompress_all(layers: Vec<Layer>, cap: u64) -> Result<Vec<Vec<u8>>, FetchError> {
    let mut total: u64 = 0;
    let mut out = Vec::with_capacity(layers.len());
    for layer in layers {
        // Only what is left of the budget: a full `cap` per layer would let
        // the last one inflate to `cap` again on top of everything resident.
        let bytes = decompress(layer, cap.saturating_sub(total))?;
        total = total.saturating_add(bytes.len() as u64);
        if total > cap {
            return Err(FetchError::TooLarge);
        }
        out.push(bytes);
    }
    Ok(out)
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

/// The digest of `bytes` under `digest`'s algorithm, spelled like it.
fn digest_of(digest: &str, bytes: &[u8]) -> Option<String> {
    use sha2::Digest as _;
    if digest.starts_with("sha256:") {
        Some(format!(
            "sha256:{}",
            hex::encode(sha2::Sha256::digest(bytes))
        ))
    } else if digest.starts_with("sha512:") {
        Some(format!(
            "sha512:{}",
            hex::encode(sha2::Sha512::digest(bytes))
        ))
    } else {
        None
    }
}

/// A content descriptor: what a manifest says about a layer, or an index
/// about a platform's manifest.
#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Descriptor {
    media_type: String,
    digest: String,
    size: i64,
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
    /// GET `url` from the registry, answering a `401` challenge once with an
    /// anonymous pull token. Any other non-success status is an error.
    fn get(&mut self, url: &str, accept: Option<&str>, limit: u64) -> Result<Fetched, FetchError> {
        let mut resp = self.send(url, accept, limit)?;
        if resp.status == 401 && self.token.is_none() {
            let challenge = header(&resp, "www-authenticate")
                .ok_or_else(|| FetchError::Refused("401 without a challenge".into()))?;
            self.token = Some(self.pull_token(challenge)?);
            resp = self.send(url, accept, limit)?;
        }
        if !(200..300).contains(&resp.status) {
            return Err(FetchError::Status(resp.status));
        }
        Ok(resp)
    }

    fn send(&self, url: &str, accept: Option<&str>, limit: u64) -> Result<Fetched, FetchError> {
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
        self.net.send(
            &Request::get(url)
                .with_headers(&headers)
                .any_status()
                .max_bytes(limit),
        )
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
            .map_err(|e| FetchError::Transport(format!("auth token reply: {e}")))?;
        reply
            .token
            .or(reply.access_token)
            .filter(|token| {
                !token.is_empty()
                    && token.len() <= MAX_TOKEN_BYTES
                    && token.bytes().all(|b| b.is_ascii_graphic())
            })
            .ok_or_else(|| FetchError::Refused("auth token missing or malformed".into()))
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
        let resp = self.get(&url, Some(MANIFEST_ACCEPT), MAX_MANIFEST_BYTES)?;
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
            .map_err(|e| FetchError::Transport(format!("manifest: {e}")))?;
        if manifest.schema_version != 2 {
            return Err(FetchError::Refused(format!(
                "unsupported manifest schema {}",
                manifest.schema_version
            )));
        }
        Ok((manifest, digest))
    }

    /// Every blob `descs` name, in order, each held to its declared size and
    /// digest. The first is read alone, so a registry that wants a token only
    /// for blobs has its challenge answered once; the rest are read
    /// [`BLOB_WORKERS`] at a time with that token, and the first failure stops
    /// the others taking new work.
    fn blobs(&mut self, descs: &[Descriptor]) -> Result<Vec<Layer>, FetchError> {
        let Some((first, rest)) = descs.split_first() else {
            return Ok(Vec::new());
        };
        let (url, limit) = self.blob_url(first)?;
        let first = layer(first, self.get(&url, None, limit)?)?;
        let this = &*self;
        let next = AtomicUsize::new(0);
        let failed = AtomicBool::new(false);
        let mut done: Vec<(usize, Result<Layer, FetchError>)> = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..BLOB_WORKERS.min(rest.len()))
                .map(|_| {
                    scope.spawn(|| {
                        let mut got = Vec::new();
                        while !failed.load(Ordering::Relaxed) {
                            let i = next.fetch_add(1, Ordering::Relaxed);
                            let Some(desc) = rest.get(i) else {
                                break;
                            };
                            let read = this
                                .blob_url(desc)
                                .and_then(|(url, limit)| this.get_shared(&url, limit))
                                .and_then(|resp| layer(desc, resp));
                            failed.fetch_or(read.is_err(), Ordering::Relaxed);
                            got.push((i, read));
                        }
                        got
                    })
                })
                .collect();
            // A worker that panicked loses its reads; the count check below
            // turns that into an error rather than a shorter image.
            workers
                .into_iter()
                .flat_map(|worker| worker.join().unwrap_or_default())
                .collect()
        });
        done.sort_by_key(|(i, _)| *i);
        let mut layers = vec![first];
        for (_, read) in done {
            layers.push(read?);
        }
        if layers.len() != descs.len() {
            return Err(FetchError::Internal("a blob read was lost".into()));
        }
        Ok(layers)
    }

    /// GET a blob with the token already in hand: a fresh challenge mid-pull
    /// is an error rather than a race between workers to fetch another token.
    fn get_shared(&self, url: &str, limit: u64) -> Result<Fetched, FetchError> {
        let resp = self.send(url, None, limit)?;
        if !(200..300).contains(&resp.status) {
            return Err(FetchError::Status(resp.status));
        }
        Ok(resp)
    }

    /// The registry URL of the blob `desc` names, and the most of a response
    /// to read for it: its declared size, but never less than room for a
    /// `401` challenge or error body — a 32-byte empty layer's limit would
    /// otherwise refuse the challenge itself. [`layer`] holds the body to the
    /// exact declared size.
    fn blob_url(&self, desc: &Descriptor) -> Result<(String, u64), FetchError> {
        let size = u64::try_from(desc.size)
            .map_err(|e| FetchError::Refused(format!("layer {} size: {e}", desc.digest)))?;
        let url = format!(
            "https://{}/v2/{}/blobs/{}",
            self.image.host, self.image.repository, desc.digest
        );
        Ok((url, size.max(64 << 10)))
    }
}

/// The layer `resp` carries, held to the size and digest `desc` declares.
fn layer(desc: &Descriptor, resp: Fetched) -> Result<Layer, FetchError> {
    let size = u64::try_from(desc.size)
        .map_err(|e| FetchError::Refused(format!("layer {} size: {e}", desc.digest)))?;
    if resp.bytes.len() as u64 != size {
        return Err(FetchError::Refused(format!(
            "layer {} is {} bytes, not the {size} its manifest declares",
            desc.digest,
            resp.bytes.len()
        )));
    }
    if digest_of(&desc.digest, &resp.bytes).as_deref() != Some(desc.digest.as_str()) {
        return Err(FetchError::Refused(format!(
            "layer {} does not match its digest",
            desc.digest
        )));
    }
    Ok(Layer {
        data: resp.bytes,
        media_type: desc.media_type.clone(),
    })
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

/// Anonymous pull of the linux/amd64 image — the same default platform
/// go-containerregistry's crane resolves, so both exporters flatten the same
/// per-platform manifest of a multi-arch index. Returns the layers in manifest
/// (base → top) order, which the flatten depends on, and the manifest digest
/// (the platform manifest's, for an index).
///
/// Every layer is vetted with [`vet_layers`] before the first blob request,
/// and none is fetched from anywhere but the registry.
fn pull(reference: &str, net: &dyn Fetch) -> Result<(Vec<Layer>, String), FetchError> {
    let image = ImageRef::parse(reference)?;
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
    vet_layers(&layers, MAX_EXPORT_BYTES)?;
    let layers = session.blobs(&layers)?;
    Ok((layers, digest))
}

/// Refuse a manifest before any blob is requested: no layers, more than
/// [`MAX_LAYERS`], a media type [`decompress`] can't handle, a foreign `urls`
/// fallback, a digest that is not plain `algorithm:hex` (it is interpolated
/// into the blob URL), or declared sizes that are negative or sum past `cap`.
/// Each size and digest is then enforced on the bytes actually received.
fn vet_layers(layers: &[Descriptor], cap: u64) -> Result<(), FetchError> {
    if layers.is_empty() {
        return Err(FetchError::Refused("image has no layers".into()));
    }
    if layers.len() > MAX_LAYERS {
        return Err(FetchError::TooLarge);
    }
    let mut total: u64 = 0;
    for layer in layers {
        if !ACCEPTED_LAYER_TYPES.contains(&layer.media_type.as_str()) {
            return Err(FetchError::Refused(format!(
                "unsupported layer media type {:?}",
                layer.media_type
            )));
        }
        let hex = layer
            .digest
            .strip_prefix("sha256:")
            .or_else(|| layer.digest.strip_prefix("sha512:"));
        if !hex.is_some_and(|h| {
            !h.is_empty() && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        }) {
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
        let size = u64::try_from(layer.size).map_err(|e| {
            FetchError::Refused(format!("layer {} size {}: {e}", layer.digest, layer.size))
        })?;
        total = total.saturating_add(size);
    }
    if total > cap {
        return Err(FetchError::TooLarge);
    }
    Ok(())
}

/// Decode one layer blob to its plain tar bytes, by media-type suffix, reading
/// one byte past `cap` so an over-cap layer is rejected rather than truncated
/// into a tar that would parse as something else.
fn decompress(layer: Layer, cap: u64) -> Result<Vec<u8>, FetchError> {
    let mut out = Vec::new();
    if layer.media_type.ends_with("gzip") {
        flate2::read::MultiGzDecoder::new(Cursor::new(&layer.data))
            .take(cap.saturating_add(1))
            .read_to_end(&mut out)
    } else if layer.media_type.ends_with("zstd") {
        zstd::stream::read::Decoder::new(Cursor::new(&layer.data))
            .map_err(|e| FetchError::Transport(format!("zstd: {e}")))?
            .take(cap.saturating_add(1))
            .read_to_end(&mut out)
    } else {
        // Already a plain tar: hand the buffer on rather than copying it.
        out = layer.data;
        Ok(0)
    }
    .map_err(|e| FetchError::Transport(format!("decompress layer ({}): {e}", layer.media_type)))?;
    if out.len() as u64 > cap {
        return Err(FetchError::TooLarge);
    }
    Ok(out)
}

/// Flatten decompressed layer tars (base → top order, as the manifest lists
/// them) into one xz-compressed rootfs tar.
///
/// Semantics follow `crane.Export` / `mutate.Extract`: walk layers *top-down*,
/// the highest layer's copy of a path wins, and a `.wh.<name>` whiteout
/// tombstones that path (and, for a directory, everything under it) in the
/// layers below. Within one layer the *last* copy of a path wins, as it does
/// when containerd or Docker extract the layer; crane keeps the first, which
/// would let a layer show this scanner a benign file while the runtime
/// installs the one after it. Entries that tar readers parse differently are
/// refused outright (see [`vet_entry`]).
/// One deliberate divergence: the OCI image-spec's opaque-whiteout marker
/// (`.wh..wh..opq`, hiding a directory's lower-layer *contents* while keeping
/// the directory) is honored per spec, which crane's Extract famously is not —
/// spec correctness wins over bug parity, and identity is digest-based anyway.
fn flatten_to_tar_xz(layers: &[Vec<u8>]) -> Result<Vec<u8>, FetchError> {
    let deadline = Instant::now() + FLATTEN_DEADLINE;
    let xz = xz2::write::XzEncoder::new(Vec::new(), 6);
    let mut builder = tar::Builder::new(LimitWriter {
        w: xz,
        limit: MAX_EXPORT_BYTES,
        written: 0,
    });

    // Paths already emitted (exact-match dedup: a higher layer's file shadows
    // the same path below, never its siblings).
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    // What higher layers hide from lower ones.
    let mut shadows = Shadows::default();

    for layer in layers.iter().rev() {
        // Pass 1: collect this layer's markers. They constrain the layers
        // BELOW this one, not this layer's own entries, so they are staged
        // and merged in only after pass 2. (Tar reading is forward-only, so
        // each pass opens a fresh Archive over the in-memory bytes.)
        let mut layer_tombstones: Vec<Vec<u8>> = Vec::new();
        let mut layer_opaque: Vec<Vec<u8>> = Vec::new();
        // Each path's last entry in this layer — the one that is emitted —
        // and whether it is something other than a directory.
        let mut last: HashMap<Vec<u8>, (usize, bool)> = HashMap::new();
        let mut archive = tar::Archive::new(Cursor::new(layer.as_slice()));
        archive.set_ignore_zeros(true);
        for (i, entry) in archive
            .entries()
            .map_err(|e| FetchError::Transport(format!("layer tar: {e}")))?
            .enumerate()
        {
            if Instant::now() >= deadline {
                return Err(FetchError::Timeout);
            }
            let mut entry = entry.map_err(|e| FetchError::Transport(format!("layer tar: {e}")))?;
            vet_entry(&mut entry)?;
            let path = clean_path(&entry.path_bytes());
            let (dir, base) = split_dir_base(&path);
            if base == b".wh..wh..opq" {
                layer_opaque.push(dir.to_vec());
            } else if let Some(target) = base.strip_prefix(b".wh.") {
                layer_tombstones.push(join_dir(dir, target));
            }
            let replaces =
                !base.starts_with(b".wh.") && replaces_directory(entry.header().entry_type());
            last.insert(path, (i, replaces));
        }
        // A file, link or device where a lower layer had a directory replaces
        // that directory outright when a runtime applies the layer, so
        // everything beneath it below is gone — as if the directory were
        // opaque. (The path itself is deduplicated by `seen`.)
        layer_opaque.extend(
            last.iter()
                .filter(|(path, (_, replaces))| *replaces && !path.is_empty())
                .map(|(path, _)| path.clone()),
        );

        // Pass 2: emit entries not shadowed by HIGHER layers.
        let mut archive = tar::Archive::new(Cursor::new(layer.as_slice()));
        archive.set_ignore_zeros(true);
        for (i, entry) in archive
            .entries()
            .map_err(|e| FetchError::Transport(format!("layer tar: {e}")))?
            .enumerate()
        {
            if Instant::now() >= deadline {
                return Err(FetchError::Timeout);
            }
            let mut entry = entry.map_err(|e| FetchError::Transport(format!("layer tar: {e}")))?;
            let path = clean_path(&entry.path_bytes());
            // An entry that cleans away to nothing names the archive root
            // itself (`./`, `.`, `/`, `..`). It carries no content, and
            // `tar::Builder` refuses an empty path outright — so emitting it
            // would abort the export. `./` opens virtually every layer any
            // real builder produces, so this is the common case, not the
            // adversarial one.
            if path.is_empty() {
                continue;
            }
            let (_, base) = split_dir_base(&path);
            if base.starts_with(b".wh.") {
                continue; // marker, never emitted
            }
            if last.get(&path).map(|&(last, _)| last) != Some(i)
                || seen.contains(&path)
                || shadows.hides(&path)
            {
                continue;
            }
            append_entry(&mut builder, &mut entry, &path)?;
            seen.insert(path);
        }

        for path in layer_tombstones {
            shadows.tombstone(path);
        }
        for path in layer_opaque {
            shadows.opaque(path);
        }
    }

    let limit = builder
        .into_inner()
        .map_err(|e| FetchError::Transport(format!("finish tar: {e}")))?;
    limit
        .w
        .finish()
        .map_err(|e| FetchError::Transport(format!("finish xz: {e}")))
}

/// Refuse an entry that tar readers disagree on, so the rootfs analyzed is the
/// one a container runtime extracts. tar-rs takes the *first* of a repeated PAX
/// `path`/`linkpath`/`size` record where Go (containerd) takes the last, and
/// treats an empty one as set where Go ignores it; a GNU long name with an
/// embedded NUL is cut at the NUL by Go but not by tar-rs. Each lets one layer
/// read as two different file sets. Names past [`MAX_PATH`] are refused too.
fn vet_entry(entry: &mut tar::Entry<'_, Cursor<&[u8]>>) -> Result<(), FetchError> {
    let refuse = |why: &str| {
        Err(FetchError::Refused(format!(
            "ambiguous layer tar entry: {why}"
        )))
    };
    for name in [Some(entry.path_bytes()), entry.link_name_bytes()]
        .into_iter()
        .flatten()
    {
        if name.len() > MAX_PATH {
            return refuse("name longer than PATH_MAX");
        }
        if name.contains(&0) {
            return refuse("NUL in name");
        }
    }
    let Some(pax) = entry
        .pax_extensions()
        .map_err(|e| FetchError::Transport(format!("layer tar: {e}")))?
    else {
        return Ok(());
    };
    let mut keys: HashSet<&[u8]> = HashSet::new();
    for ext in pax {
        let ext = ext.map_err(|e| FetchError::Transport(format!("layer tar pax: {e}")))?;
        let key = ext.key_bytes();
        if matches!(key, b"path" | b"linkpath" | b"size")
            && (ext.value_bytes().is_empty() || !keys.insert(key))
        {
            return refuse("empty or repeated PAX record");
        }
    }
    Ok(())
}

/// Copy one tar entry (path, link target, body) into the output under a
/// header built afresh, regenerating long-name/long-link extensions so paths
/// the source encoded via PAX/GNU records survive the transplant.
///
/// Never the source header itself: its size field need not frame the body
/// tar-rs yields (a PAX `size`, a GNU sparse map, a link with a nonzero size),
/// and copying it would let a layer's bytes parse as forged entries of the
/// output. So only the file types a rootfs holds are kept, sparse and
/// contiguous files become regular ones of their real size, and metadata
/// records (PAX globals, GNU volume and multivolume headers) and unknown types
/// are dropped.
///
/// The entry *name* is the cleaned path. A symlink's *target* is copied
/// verbatim, deliberately: absolute and `..`-relative targets are how a real
/// rootfs is built (`usr/sbin/x -> ../bin/y`, `/etc/alternatives/…`), so
/// rewriting them would misrepresent the filesystem being analyzed. A hard
/// link's target is another way of naming an entry *in the archive*, so it is
/// cleaned exactly as names are: it then matches the entry it links to, and
/// cannot point an extractor outside the root (`../../etc/passwd`). One that
/// cleans to the root names no file, and is dropped like a root entry.
fn append_entry<W: Write>(
    builder: &mut tar::Builder<W>,
    entry: &mut tar::Entry<'_, Cursor<&[u8]>>,
    path: &[u8],
) -> Result<(), FetchError> {
    use tar::EntryType as T;
    let src = entry.header();
    let kind = match src.entry_type() {
        T::Regular | T::Continuous | T::GNUSparse => T::Regular,
        kind @ (T::Directory | T::Symlink | T::Link | T::Char | T::Block | T::Fifo) => kind,
        _ => return Ok(()),
    };
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(kind);
    header.set_size(0);
    header.set_mode(src.mode().unwrap_or(0o644) & 0o7777);
    header.set_uid(src.uid().unwrap_or(0));
    header.set_gid(src.gid().unwrap_or(0));
    header.set_mtime(src.mtime().unwrap_or(0));
    if let Ok(Some(name)) = src.username() {
        let _ = header.set_username(name);
    }
    if let Ok(Some(name)) = src.groupname() {
        let _ = header.set_groupname(name);
    }
    if matches!(kind, T::Char | T::Block)
        && let (Ok(Some(major)), Ok(Some(minor))) = (src.device_major(), src.device_minor())
    {
        let _ = header.set_device_major(major);
        let _ = header.set_device_minor(minor);
    }
    if kind.is_symlink() || kind.is_hard_link() {
        let mut target = entry
            .link_name_bytes()
            .ok_or_else(|| FetchError::Refused("link entry without target".into()))?
            .into_owned();
        if kind.is_hard_link() {
            target = clean_path(&target);
            if target.is_empty() {
                return Ok(());
            }
        }
        builder
            .append_link(&mut header, bytes_path(path), bytes_path(&target))
            .map_err(|e| FetchError::Transport(format!("append link: {e}")))
    } else if kind == T::Regular {
        header.set_size(entry.size());
        builder
            .append_data(&mut header, bytes_path(path), entry)
            .map_err(|e| FetchError::Transport(format!("append entry: {e}")))
    } else {
        builder
            .append_data(&mut header, bytes_path(path), std::io::empty())
            .map_err(|e| FetchError::Transport(format!("append entry: {e}")))
    }
}

/// `path::Clean`-alike over raw tar path bytes, mirroring crane's
/// `path.Clean("/"+name)` (then dropping the leading `/`): resolve `.` and `..`
/// segments and collapse separators, so every layer spelling of one file
/// (`./etc/passwd`, `/etc/passwd`, `etc/passwd`, `foo/../etc/passwd`) keys the
/// same entry.
///
/// Resolving `..` is load-bearing twice over, because layer entry names are
/// attacker-controlled.
///
/// First, availability: a `..` left in a name reaches `tar::Builder`, which
/// refuses to write it ("paths in archives must not have `..`") and fails the
/// whole export. One such entry, anywhere in any layer, therefore aborts the
/// analysis of the entire image — a one-byte way for a hostile image to opt out
/// of being scanned. Anchoring at the root, as `path.Clean("/"+name)` does,
/// confines the name to `etc/cron.d/x` and the image flattens.
///
/// Second, correctness of shadowing: the cleaned path is the key for `seen`
/// and for whiteout matching, so an unresolved `a/../b` compares unequal to
/// `b` and would slip past a tombstone meant to hide it.
///
/// Note the traversal itself was never *written* — the tar crate's write-side
/// check was the backstop. Not relying on a dependency's incidental validation
/// for a security property is the point.
fn clean_path(raw: &[u8]) -> Vec<u8> {
    let mut out: Vec<&[u8]> = Vec::new();
    for segment in raw.split(|&b| b == b'/') {
        match segment {
            // Empty (a leading, trailing, or doubled `/`) and `.` are no-ops.
            b"" | b"." => {}
            // Anchored at the root, so a `..` above it has nothing to pop.
            b".." => {
                out.pop();
            }
            name => out.push(name),
        }
    }
    out.join(&b'/')
}

/// Split a cleaned path into (directory, basename); the directory is empty
/// for a root-level name.
fn split_dir_base(path: &[u8]) -> (&[u8], &[u8]) {
    match path.iter().rposition(|&b| b == b'/') {
        Some(i) => (&path[..i], &path[i + 1..]),
        None => (b"", path),
    }
}

fn join_dir(dir: &[u8], base: &[u8]) -> Vec<u8> {
    if dir.is_empty() {
        return base.to_vec();
    }
    let mut v = Vec::with_capacity(dir.len() + 1 + base.len());
    v.extend_from_slice(dir);
    v.push(b'/');
    v.extend_from_slice(base);
    v
}

/// Whether an entry kind is something [`append_entry`] emits other than a
/// directory — what replaces a lower layer's directory at the same path.
fn replaces_directory(kind: tar::EntryType) -> bool {
    use tar::EntryType as T;
    matches!(
        kind,
        T::Regular
            | T::Continuous
            | T::GNUSparse
            | T::Symlink
            | T::Link
            | T::Char
            | T::Block
            | T::Fifo
    )
}

/// What higher layers hide from lower ones: paths tombstoned by a `.wh.`
/// marker (the path and its subtree) and directories made opaque (everything
/// strictly beneath them — the root included, as `""`).
///
/// Each path is kept beside its keyed hash, so [`hides`](Self::hides) can test
/// every ancestor of a name in one pass over it: the prefix hashes are built
/// incrementally, and only a hash hit is confirmed against the path itself.
/// Looking each prefix up afresh would rehash it, which is quadratic in the
/// name's length.
#[derive(Default)]
struct Shadows {
    state: std::hash::RandomState,
    tombstones: HashSet<Vec<u8>>,
    tombstone_hashes: HashSet<u64>,
    opaque: HashSet<Vec<u8>>,
    opaque_hashes: HashSet<u64>,
}

impl Shadows {
    fn hash(&self, path: &[u8]) -> u64 {
        use std::hash::{BuildHasher as _, Hasher as _};
        let mut hasher = self.state.build_hasher();
        hasher.write(path);
        hasher.finish()
    }

    fn tombstone(&mut self, path: Vec<u8>) {
        self.tombstone_hashes.insert(self.hash(&path));
        self.tombstones.insert(path);
    }

    fn opaque(&mut self, path: Vec<u8>) {
        self.opaque_hashes.insert(self.hash(&path));
        self.opaque.insert(path);
    }

    /// Whether `path` is hidden: it or an ancestor is tombstoned, or an
    /// ancestor directory is opaque.
    fn hides(&self, path: &[u8]) -> bool {
        use std::hash::{BuildHasher as _, Hasher as _};
        if self.tombstones.contains(path) || self.opaque.contains(b"".as_slice()) {
            return true;
        }
        // `Hasher::write` streams, so feeding the name chunk by chunk and
        // finishing a clone at each '/' yields each ancestor's hash.
        let mut hasher = self.state.build_hasher();
        let mut start = 0;
        for (i, _) in path.iter().enumerate().filter(|&(_, &b)| b == b'/') {
            hasher.write(&path[start..i]);
            start = i;
            let hash = hasher.clone().finish();
            let ancestor = &path[..i];
            if (self.tombstone_hashes.contains(&hash) && self.tombstones.contains(ancestor))
                || (self.opaque_hashes.contains(&hash) && self.opaque.contains(ancestor))
            {
                return true;
            }
        }
        false
    }
}

/// Borrow a raw tar entry name as a `Path`.
///
/// Unix `OsStr` is arbitrary bytes, so this is a zero-copy view. Windows has no
/// equivalent — its `OsStr` is WTF-8 over UTF-16 code units, not bytes — so
/// there the name is borrowed only when it is valid UTF-8, which OCI layer
/// entry names are in practice. A non-UTF-8 name has no Windows path
/// representation at all; it yields an empty path rather than a lossily
/// mangled one, so the caller's `append_*` fails loudly instead of writing an
/// entry under a corrupted name.
#[cfg(unix)]
fn bytes_path(b: &[u8]) -> &std::path::Path {
    use std::os::unix::ffi::OsStrExt;
    std::path::Path::new(std::ffi::OsStr::from_bytes(b))
}

#[cfg(not(unix))]
fn bytes_path(b: &[u8]) -> &std::path::Path {
    std::path::Path::new(std::str::from_utf8(b).unwrap_or(""))
}

/// Forward writes until more than `limit` bytes pass, then fail — bounding the
/// uncompressed tar the flatten feeds into xz, exactly like forager's
/// `limitWriter` around `crane.Export`.
struct LimitWriter<W: Write> {
    w: W,
    limit: u64,
    written: u64,
}

impl<W: Write> Write for LimitWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.written + buf.len() as u64 > self.limit {
            return Err(std::io::Error::other("container image exceeds size cap"));
        }
        let n = self.w.write(buf)?;
        self.written += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.w.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an in-memory layer tar of regular files.
    fn layer(entries: &[(&str, &str)]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (path, content) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_size(content.len() as u64);
            h.set_mode(0o644);
            b.append_data(&mut h, path, content.as_bytes()).unwrap();
        }
        b.into_inner().unwrap()
    }

    /// Build a layer tar containing a name `tar::Builder` would refuse to
    /// write (`..` segments), by laying down the 512-byte ustar header by
    /// hand. A hostile registry is under no obligation to use a well-behaved
    /// tar writer, so the fixture must not either.
    fn hostile_layer(entries: &[(&str, &str)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (path, content) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_size(content.len() as u64);
            h.set_mode(0o644);
            h.set_entry_type(tar::EntryType::Regular);
            let name = path.as_bytes();
            assert!(name.len() <= 100, "fixture name must fit the ustar field");
            h.as_old_mut().name[..name.len()].copy_from_slice(name);
            h.set_cksum();
            out.extend_from_slice(h.as_bytes());
            out.extend_from_slice(content.as_bytes());
            out.resize(out.len().div_ceil(512) * 512, 0); // pad to a block
        }
        out.extend_from_slice(&[0u8; 1024]); // end-of-archive
        out
    }

    /// Decode a flattened .tar.xz back to (path, content) pairs, in order.
    fn entries_of(tar_xz: &[u8]) -> Vec<(String, String)> {
        let mut raw = Vec::new();
        xz2::read::XzDecoder::new(Cursor::new(tar_xz))
            .read_to_end(&mut raw)
            .unwrap();
        let mut archive = tar::Archive::new(Cursor::new(raw.as_slice()));
        archive
            .entries()
            .unwrap()
            .map(|e| {
                let mut e = e.unwrap();
                let p = e.path().unwrap().display().to_string();
                let mut bytes = Vec::new();
                e.read_to_end(&mut bytes).unwrap();
                (p, String::from_utf8_lossy(&bytes).into_owned())
            })
            .collect()
    }

    #[test]
    fn top_layer_overrides_and_whiteout_deletes() {
        let base = layer(&[
            ("etc/passwd", "base"),
            ("data/old.txt", "old"),
            ("data/keep.txt", "keep"),
        ]);
        let top = layer(&[("etc/passwd", "top"), ("data/.wh.old.txt", "")]);
        let got = entries_of(&flatten_to_tar_xz(&[base, top]).unwrap());

        // Top layer's entries come first (crane's top-down walk), the
        // override wins, the whiteout target and marker are both absent.
        assert_eq!(
            got,
            vec![
                ("etc/passwd".into(), "top".into()),
                ("data/keep.txt".into(), "keep".into()),
            ]
        );
    }

    #[test]
    fn opaque_dir_hides_lower_contents_recursively() {
        let base = layer(&[
            ("cfg/old.conf", "old"),
            ("cfg/sub/x", "x"),
            ("root.txt", "r"),
        ]);
        let top = layer(&[("cfg/.wh..wh..opq", ""), ("cfg/new.conf", "new")]);
        let got = entries_of(&flatten_to_tar_xz(&[base, top]).unwrap());
        assert_eq!(
            got,
            vec![
                ("cfg/new.conf".into(), "new".into()),
                ("root.txt".into(), "r".into()),
            ]
        );
    }

    #[test]
    fn whiteout_of_a_directory_hides_its_subtree() {
        let base = layer(&[("bin/tool", "t"), ("bin/sub/y", "y"), ("lib/z", "z")]);
        let top = layer(&[(".wh.bin", "")]);
        let got = entries_of(&flatten_to_tar_xz(&[base, top]).unwrap());
        assert_eq!(got, vec![("lib/z".into(), "z".into())]);
    }

    #[test]
    fn path_spellings_key_the_same_file() {
        // `./etc/passwd` and `etc/passwd` are the same path; the top layer's
        // spelling must still shadow the base.
        let base = layer(&[("etc/passwd", "base")]);
        let top = layer(&[("./etc/passwd", "top")]);
        let got = entries_of(&flatten_to_tar_xz(&[base, top]).unwrap());
        assert_eq!(got, vec![("etc/passwd".into(), "top".into())]);
    }

    /// A plain (uncompressed) layer of `n` bytes.
    fn raw_layer(n: usize) -> Layer {
        Layer {
            data: vec![0u8; n],
            media_type: OCI_LAYER.to_string(),
        }
    }

    #[test]
    fn layers_are_capped_in_aggregate_not_individually() {
        // Each layer is comfortably under the cap; together they are over it.
        // Capping only per-layer would admit all three, and the flatten holds
        // every layer at once — so the ceiling has to be on the sum.
        let under = decompress_all(vec![raw_layer(40), raw_layer(40)], 100);
        assert!(under.is_ok(), "80 bytes under a 100-byte cap: {under:?}");

        let over = decompress_all(vec![raw_layer(40), raw_layer(40), raw_layer(40)], 100);
        assert!(
            matches!(over, Err(FetchError::TooLarge)),
            "120 bytes must not pass a 100-byte cap"
        );
    }

    #[test]
    fn a_single_oversized_layer_is_refused() {
        let one = decompress_all(vec![raw_layer(101)], 100);
        assert!(one.is_err(), "a lone over-cap layer must be refused");
    }

    /// A manifest descriptor for a plain layer declaring `size` bytes.
    fn desc(size: i64) -> Descriptor {
        Descriptor {
            media_type: OCI_LAYER.to_string(),
            digest: "sha256:00".into(),
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
            matches!(
                vet_layers(&many, MAX_EXPORT_BYTES),
                Err(FetchError::TooLarge)
            ),
            "a manifest over the layer ceiling must be refused"
        );
        assert!(vet_layers(&many[..MAX_LAYERS], MAX_EXPORT_BYTES).is_ok());
    }

    #[test]
    fn a_manifest_is_vetted_before_any_blob_is_pulled() {
        // Declared sizes are capped in aggregate, like the decompressed ones.
        assert!(vet_layers(&[desc(40), desc(40)], 100).is_ok());
        assert!(vet_layers(&[desc(40), desc(40), desc(40)], 100).is_err());
        assert!(vet_layers(&[desc(-1)], 100).is_err());
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
    }

    #[test]
    fn a_pull_from_inside_an_async_caller_does_not_panic() {
        // `fetch_ref` is sync but public, so an async caller can reach the
        // puller from a thread already driving a runtime. The puller owns no
        // runtime of its own, so there is no nested `block_on` to panic.
        let image = TestImage::new();
        let outer = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let got = outer.block_on(async { export("docker.io/hello:latest", &image.registry) });
        assert!(got.is_ok(), "{got:?}");
    }

    #[test]
    fn a_layer_cannot_outgrow_its_declared_size() {
        // A backend that ignores the request's byte cap is still held to the
        // manifest's size, so a registry can't stream more than it promised.
        let image = TestImage::new();
        let mut bigger = image.layer.clone();
        bigger.extend_from_slice(&[0; 512]);
        image.registry.serve(&image.blob_url(), &bigger, &[]);
        let got = export("docker.io/hello:latest", &image.registry);
        assert!(
            matches!(&got, Err(FetchError::Refused(why)) if why.contains("declares")),
            "{got:?}"
        );
    }

    #[test]
    fn root_entry_does_not_abort_the_export() {
        // Virtually every layer built by `docker build`/buildkit opens with a
        // `./` entry for the archive root. It cleans to the empty path, which
        // `tar::Builder` rejects outright ("paths in archives must have at
        // least one component") — so failing to skip it fails the export of
        // almost every real image, not just a crafted one.
        let base = layer(&[("./", ""), ("etc/passwd", "root:x:0:0")]);
        let got = entries_of(&flatten_to_tar_xz(&[base]).expect("root entry must not abort"));
        assert_eq!(got, vec![("etc/passwd".into(), "root:x:0:0".into())]);
    }

    #[test]
    fn rootish_names_are_skipped_not_fatal() {
        // The same hazard reached deliberately: every spelling that cleans away
        // to nothing must be dropped, never turned into a failed export.
        let evil = hostile_layer(&[("..", "x"), ("/", "y"), (".", "z"), ("keep", "k")]);
        let got = entries_of(&flatten_to_tar_xz(&[evil]).expect("must not abort"));
        assert_eq!(got, vec![("keep".into(), "k".into())]);
    }

    #[test]
    fn traversal_names_are_anchored_at_the_root() {
        // Layer entry names are attacker-controlled. Before this was anchored,
        // `tar::Builder` rejected the `..` and failed the whole export, so a
        // single crafted name let an image opt out of being analyzed at all.
        let evil = hostile_layer(&[
            ("../../../../etc/cron.d/x", "pwn"),
            ("a/b/../../../etc/shadow", "pwn2"),
        ]);
        let got = entries_of(&flatten_to_tar_xz(&[evil]).unwrap());
        assert_eq!(
            got,
            vec![
                ("etc/cron.d/x".into(), "pwn".into()),
                ("etc/shadow".into(), "pwn2".into()),
            ]
        );
        assert!(
            !got.iter().any(|(p, _)| p.contains("..")),
            "no emitted path may retain a traversal segment: {got:?}"
        );
    }

    /// Hard links name another entry of the archive, so their targets are
    /// cleaned as entry names are — matching the cleaned name of what they
    /// link to, and anchored at the root. Symlink targets describe the image's
    /// filesystem and are kept as written.
    #[test]
    fn hard_link_targets_are_cleaned_like_names() {
        fn link(path: &str, kind: tar::EntryType, target: &str) -> Vec<u8> {
            let mut h = tar::Header::new_gnu();
            h.set_size(0);
            h.set_mode(0o644);
            h.set_entry_type(kind);
            h.as_old_mut().name[..path.len()].copy_from_slice(path.as_bytes());
            h.as_old_mut().linkname[..target.len()].copy_from_slice(target.as_bytes());
            h.set_cksum();
            h.as_bytes().to_vec()
        }
        let mut layer = hostile_layer(&[("./usr/bin/a", "A")]);
        layer.truncate(layer.len() - 1024); // reopen past the end-of-archive
        for entry in [
            link("usr/bin/b", tar::EntryType::Link, "./usr/bin/a"),
            link("x", tar::EntryType::Link, "../../../etc/passwd"),
            link("root", tar::EntryType::Link, "../"),
            link("usr/sbin/y", tar::EntryType::Symlink, "../bin/a"),
        ] {
            layer.extend_from_slice(&entry);
        }
        layer.extend_from_slice(&[0u8; 1024]);

        let mut raw = Vec::new();
        xz2::read::XzDecoder::new(Cursor::new(flatten_to_tar_xz(&[layer]).unwrap()))
            .read_to_end(&mut raw)
            .unwrap();
        let links: Vec<(String, String)> = tar::Archive::new(Cursor::new(raw.as_slice()))
            .entries()
            .unwrap()
            .filter_map(|e| {
                let e = e.unwrap();
                let target = e.link_name().unwrap()?.display().to_string();
                Some((e.path().unwrap().display().to_string(), target))
            })
            .collect();
        assert_eq!(
            links,
            vec![
                ("usr/bin/b".into(), "usr/bin/a".into()),
                ("x".into(), "etc/passwd".into()),
                ("usr/sbin/y".into(), "../bin/a".into()),
            ]
        );
    }

    #[test]
    fn traversal_spelling_cannot_evade_a_whiteout() {
        // The cleaned path is the shadowing key, so an unresolved `a/../secret`
        // would compare unequal to the tombstoned `secret` and survive.
        let base = hostile_layer(&[("dir/../secret", "leaked"), ("keep", "k")]);
        let top = layer(&[(".wh.secret", "")]);
        let got = entries_of(&flatten_to_tar_xz(&[base, top]).unwrap());
        assert_eq!(got, vec![("keep".into(), "k".into())]);
    }

    #[test]
    fn markers_only_constrain_lower_layers() {
        // A whiteout and a fresh file for the same path in ONE layer: the
        // layer's own file must survive (markers apply strictly below).
        let base = layer(&[("app/a", "old")]);
        let top = layer(&[("app/.wh.a", ""), ("app/a", "new")]);
        let got = entries_of(&flatten_to_tar_xz(&[base, top]).unwrap());
        assert_eq!(got, vec![("app/a".into(), "new".into())]);
    }

    /// A raw 512-byte header block: `name`, `kind`, and a declared `size`.
    fn raw_header(name: &str, kind: tar::EntryType, size: u64) -> Vec<u8> {
        let mut h = tar::Header::new_ustar();
        h.set_size(size);
        h.set_mode(0o644);
        h.set_entry_type(kind);
        h.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
        h.set_cksum();
        h.as_bytes().to_vec()
    }

    /// A layer of one PAX extension block carrying `records`, then the entry
    /// `name` whose ustar header declares size 0 and whose body is `body`.
    fn pax_layer(records: &str, name: &str, body: &[u8]) -> Vec<u8> {
        let mut out = raw_header("pax", tar::EntryType::XHeader, records.len() as u64);
        out.extend_from_slice(records.as_bytes());
        out.resize(out.len().div_ceil(512) * 512, 0);
        out.extend_from_slice(&raw_header(name, tar::EntryType::Regular, 0));
        out.extend_from_slice(body);
        out.resize(out.len().div_ceil(512) * 512, 0);
        out.extend_from_slice(&[0u8; 1024]);
        out
    }

    #[test]
    fn a_pax_size_cannot_forge_entries_in_the_output() {
        // The body tar-rs reads (PAX `size=512`) is itself a header block. A
        // copied header would still say 0 bytes, so a reader of the output
        // would parse the body as an entry that never existed in the image.
        let forged = raw_header("etc/forged", tar::EntryType::Regular, 0);
        let layer = pax_layer("12 size=512\n", "f", &forged);
        let got = entries_of(&flatten_to_tar_xz(&[layer]).unwrap());
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].0, "f");
        assert_eq!(got[0].1.len(), 512);
    }

    #[test]
    fn ambiguous_pax_records_are_refused() {
        // Go keeps the last `path`, tar-rs the first: two readings of one layer.
        for records in ["12 path=abc\n12 path=xyz\n", "8 path=\n"] {
            let layer = pax_layer(records, "f", b"");
            assert!(
                matches!(flatten_to_tar_xz(&[layer]), Err(FetchError::Refused(_))),
                "{records:?} must be refused"
            );
        }
    }

    #[test]
    fn overlong_names_are_refused() {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(0);
        h.set_mode(0o644);
        b.append_data(&mut h, "a/".repeat(MAX_PATH / 2 + 1), std::io::empty())
            .unwrap();
        let layer = b.into_inner().unwrap();
        assert!(matches!(
            flatten_to_tar_xz(&[layer]),
            Err(FetchError::Refused(_))
        ));
    }

    #[test]
    fn the_last_copy_of_a_path_in_a_layer_wins() {
        // containerd and Docker extract a layer in order, so the later copy is
        // the one that runs; showing the first would hide it.
        let layer = layer(&[("usr/bin/sshd", "benign"), ("usr/bin/sshd", "evil")]);
        let got = entries_of(&flatten_to_tar_xz(&[layer]).unwrap());
        assert_eq!(got, vec![("usr/bin/sshd".into(), "evil".into())]);
    }

    /// A layer holding one symlink `path` → `target`.
    fn symlink_layer(path: &str, target: &str) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_size(0);
        h.set_mode(0o777);
        b.append_link(&mut h, path, target).unwrap();
        b.into_inner().unwrap()
    }

    #[test]
    fn a_directory_replaced_by_a_file_hides_what_was_beneath_it() {
        // A runtime applying the top layer removes the `etc` directory to put
        // a file there, so `etc/cron.d/evil` from below never reaches the
        // container — and must not reach the analysis as if it did.
        let base = layer(&[("etc/cron.d/evil", "x"), ("etcetera", "kept")]);
        let top = layer(&[("etc", "now a file")]);
        let got = entries_of(&flatten_to_tar_xz(&[base, top]).unwrap());
        assert_eq!(
            got,
            vec![
                ("etc".into(), "now a file".into()),
                ("etcetera".into(), "kept".into())
            ]
        );

        // Likewise a symlink in the directory's place.
        let base = layer(&[("opt/app/bin", "x")]);
        let top = symlink_layer("opt", "/srv");
        let got = entries_of(&flatten_to_tar_xz(&[base, top]).unwrap());
        assert_eq!(got, vec![("opt".into(), String::new())]);
    }

    #[test]
    fn a_directory_over_a_directory_still_merges() {
        let base = layer(&[("etc/passwd", "base")]);
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Directory);
        h.set_size(0);
        h.set_mode(0o755);
        b.append_data(&mut h, "etc", std::io::empty()).unwrap();
        let top = b.into_inner().unwrap();
        let got = entries_of(&flatten_to_tar_xz(&[base, top]).unwrap());
        assert!(
            got.contains(&("etc/passwd".into(), "base".into())),
            "{got:?}"
        );
    }

    #[test]
    fn shadows_test_each_ancestor_exactly() {
        let mut shadows = Shadows::default();
        shadows.tombstone(b"a/b".to_vec());
        shadows.opaque(b"x".to_vec());
        assert!(shadows.hides(b"a/b"), "the tombstoned path");
        assert!(shadows.hides(b"a/b/c/d"), "beneath it");
        assert!(!shadows.hides(b"a/bc"), "a sibling sharing its prefix");
        assert!(!shadows.hides(b"a"), "its parent");
        assert!(!shadows.hides(b"x"), "an opaque directory itself survives");
        assert!(shadows.hides(b"x/y"), "what is beneath it does not");
        let deep = "d/".repeat(2000) + "f";
        assert!(!shadows.hides(deep.as_bytes()));
        shadows.opaque(Vec::new());
        assert!(shadows.hides(b"anything"), "a root opaque hides everything");
    }

    #[test]
    fn a_root_opaque_marker_hides_every_lower_layer() {
        let base = layer(&[("etc/passwd", "base")]);
        let top = layer(&[(".wh..wh..opq", ""), ("new", "n")]);
        let got = entries_of(&flatten_to_tar_xz(&[base, top]).unwrap());
        assert_eq!(got, vec![("new".into(), "n".into())]);
    }

    #[test]
    fn a_malformed_layer_digest_is_refused() {
        for digest in ["sha256:../../x", "sha256:", "md5:00", "sha256:AB"] {
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

    /// Opt-in live check (`cargo test -- --ignored oci`): pulls the tiny
    /// hello-world image and flattens it. Everything else in this module is
    /// hermetic; this is the one place the real protocol gets exercised.
    #[test]
    #[ignore = "live network: pulls docker.io/library/hello-world"]
    fn live_export_hello_world() {
        let net = crate::fetch::HttpFetch::new().expect("client");
        let (tar_xz, digest) =
            export("docker.io/library/hello-world:latest", &net).expect("export");
        assert!(
            digest.starts_with("sha256:"),
            "manifest digest must be recorded"
        );
        let entries = entries_of(&tar_xz);
        assert!(
            entries.iter().any(|(p, _)| p == "hello"),
            "flattened rootfs should contain the hello binary: {entries:?}"
        );
    }

    /// Opt-in live check (`cargo test --lib -- --ignored oci`) against an image
    /// with a *real* filesystem.
    ///
    /// Deliberately Debian and not Alpine. `hello-world` above is `FROM
    /// scratch` — one file, no directory entries — and Alpine's layer happens
    /// to carry no root entry either, so neither exercises the `./` entry that
    /// aborted the export. Of the six most common base images, four do carry
    /// one (debian-slim, python-slim, busybox, nginx); the alpine-derived two
    /// do not. Picking one of the four is the difference between this test
    /// catching that class and sailing past it.
    #[test]
    #[ignore = "live network: pulls docker.io/library/debian"]
    fn live_export_debian_rootfs() {
        let net = crate::fetch::HttpFetch::new().expect("client");
        let (tar_xz, digest) =
            export("docker.io/library/debian:stable-slim", &net).expect("export");
        assert!(digest.starts_with("sha256:"));
        let entries = entries_of(&tar_xz);
        assert!(
            entries.iter().any(|(p, _)| p == "etc/debian_version"),
            "flattened rootfs should carry etc/debian_version ({} entries)",
            entries.len()
        );
        assert!(
            !entries
                .iter()
                .any(|(p, _)| p.is_empty() || p.contains("..")),
            "no empty or traversing path may reach the output"
        );
    }

    #[test]
    fn disallowed_registry_is_refused() {
        let registry = FakeRegistry::default();
        let Err(err) = pull("internal.corp:5000/secret/image:latest", &registry) else {
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
    fn a_pull_follows_the_token_flow_and_picks_linux_amd64() {
        let image = TestImage::new();
        let (tar_xz, digest) = export("docker.io/hello:latest", &image.registry).unwrap();
        assert_eq!(digest, image.amd64_digest, "the platform manifest's digest");
        assert_eq!(entries_of(&tar_xz), vec![("hello".into(), "hi".into())]);

        let requests = image.registry.requests();
        let realm: Vec<_> = requests
            .iter()
            .filter(|(url, _)| url.starts_with(REALM))
            .collect();
        assert_eq!(realm.len(), 1, "one token for the whole pull: {requests:?}");
        assert_eq!(realm[0].1, None, "the realm is asked anonymously");
        assert!(
            realm[0]
                .0
                .contains("scope=repository%3Alibrary%2Fhello%3Apull"),
            "the scope is this repository's pull, not the challenge's: {}",
            realm[0].0
        );
        let blob = requests
            .iter()
            .find(|(url, _)| url.contains("/blobs/"))
            .expect("blob request");
        assert_eq!(blob.1.as_deref(), Some("Bearer t0ken"));
    }

    #[test]
    fn a_blob_that_does_not_match_its_digest_is_refused() {
        let image = TestImage::new();
        let mut forged = image.layer.clone();
        forged[0] ^= 1; // same size, different bytes
        image.registry.serve(&image.blob_url(), &forged, &[]);
        let got = export("docker.io/hello:latest", &image.registry);
        assert!(
            matches!(&got, Err(FetchError::Refused(why)) if why.contains("digest")),
            "{got:?}"
        );
    }

    #[test]
    fn a_manifest_that_does_not_match_its_digest_is_refused() {
        // The index names the amd64 manifest by digest; another body served
        // under that digest is a substitution.
        let image = TestImage::new();
        let other = manifest_json(&image.layer, 1);
        image
            .registry
            .serve(&image.amd64_url(), other.as_bytes(), &[]);
        let got = export("docker.io/hello:latest", &image.registry);
        assert!(
            matches!(&got, Err(FetchError::Refused(why)) if why.contains("manifest digest")),
            "{got:?}"
        );

        // So is a tag response whose body is not what the registry's own
        // Docker-Content-Digest says it is.
        let image = TestImage::new();
        let lie = format!("sha256:{}", "0".repeat(64));
        image.registry.serve(
            &image.tag_url(),
            image.index.as_bytes(),
            &[("Docker-Content-Digest", &lie)],
        );
        let got = export("docker.io/hello:latest", &image.registry);
        assert!(
            matches!(&got, Err(FetchError::Refused(why)) if why.contains("manifest digest")),
            "{got:?}"
        );
    }

    #[test]
    fn a_plain_http_realm_is_refused_unasked() {
        let image = TestImage::new();
        image
            .registry
            .challenge("Bearer realm=\"http://auth.docker.io/token\",service=\"x\"");
        let got = export("docker.io/hello:latest", &image.registry);
        assert!(
            matches!(&got, Err(FetchError::Refused(why)) if why.contains("https")),
            "{got:?}"
        );
        assert!(
            image
                .registry
                .requests()
                .iter()
                .all(|(url, _)| !url.starts_with("http://")),
            "the realm was never asked"
        );
    }

    #[test]
    fn a_token_that_could_inject_headers_is_refused() {
        for token in ["t0ken\r\nX-Evil: 1", "has space", ""] {
            let image = TestImage::new();
            let reply = serde_json::json!({ "token": token }).to_string();
            image.registry.serve(REALM, reply.as_bytes(), &[]);
            let got = export("docker.io/hello:latest", &image.registry);
            assert!(
                matches!(&got, Err(FetchError::Refused(why)) if why.contains("token")),
                "{token:?}: {got:?}"
            );
        }
    }

    const REALM: &str = "https://auth.docker.io/token";

    /// A registry that demands a bearer token for everything under `/v2/`,
    /// issues `t0ken` from [`REALM`], and records each request with the
    /// `Authorization` it carried.
    #[derive(Default)]
    struct FakeRegistry {
        responses: std::sync::Mutex<HashMap<String, Fetched>>,
        challenge: std::sync::Mutex<String>,
        log: std::sync::Mutex<Vec<(String, Option<String>)>>,
    }

    impl FakeRegistry {
        fn serve(&self, url: &str, bytes: &[u8], headers: &[(&str, &str)]) {
            let fetched = Fetched {
                bytes: bytes.to_vec(),
                final_url: url.to_string(),
                status: 200,
                headers: headers
                    .iter()
                    .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                    .collect(),
                redirects: Vec::new(),
            };
            self.responses
                .lock()
                .unwrap()
                .insert(url.to_string(), fetched);
        }

        fn challenge(&self, challenge: &str) {
            *self.challenge.lock().unwrap() = challenge.to_string();
        }

        fn requests(&self) -> Vec<(String, Option<String>)> {
            self.log.lock().unwrap().clone()
        }
    }

    impl Fetch for FakeRegistry {
        fn send(&self, request: &Request<'_>) -> Result<Fetched, FetchError> {
            let auth = request
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
                .map(|(_, v)| (*v).to_string());
            self.log
                .lock()
                .unwrap()
                .push((request.url.to_string(), auth.clone()));
            let key = request.url.split('?').next().unwrap_or_default();
            if request.url.contains("/v2/") && auth.as_deref() != Some("Bearer t0ken") {
                return Ok(Fetched {
                    bytes: Vec::new(),
                    final_url: request.url.to_string(),
                    status: 401,
                    headers: vec![(
                        "www-authenticate".into(),
                        self.challenge.lock().unwrap().clone(),
                    )],
                    redirects: Vec::new(),
                });
            }
            self.responses
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or(FetchError::Status(404))
        }

        fn allows_oci(&self) -> bool {
            true
        }
    }

    fn sha256(bytes: &[u8]) -> String {
        format!("sha256:{}", crate::fetch::sha256_hex(bytes))
    }

    #[test]
    fn concurrently_read_layers_flatten_in_manifest_order() {
        let registry = FakeRegistry::default();
        registry.challenge(&format!(
            "Bearer realm=\"{REALM}\",service=\"registry.docker.io\""
        ));
        registry.serve(REALM, br#"{"token":"t0ken"}"#, &[]);
        // Ten layers each rewrite `f`; the top one's must win.
        let layers: Vec<Vec<u8>> = (0..10)
            .map(|n| layer(&[("f", &n.to_string()), (&format!("only{n}"), "x")]))
            .collect();
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "layers": layers.iter().map(|l| serde_json::json!(
                {"mediaType": OCI_LAYER, "digest": sha256(l), "size": l.len()}
            )).collect::<Vec<_>>()
        })
        .to_string();
        registry.serve(
            &format!("https://{DOCKER_HUB}/v2/library/stack/manifests/latest"),
            manifest.as_bytes(),
            &[],
        );
        for l in &layers {
            registry.serve(
                &format!("https://{DOCKER_HUB}/v2/library/stack/blobs/{}", sha256(l)),
                l,
                &[],
            );
        }
        let (export, _) = export("docker.io/library/stack:latest", &registry).expect("export");
        let entries = entries_of(&export);
        let f: Vec<_> = entries.iter().filter(|(p, _)| p == "f").collect();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].1, "9", "the top layer's copy wins");
        for n in 0..10 {
            assert!(
                entries.iter().any(|(p, _)| *p == format!("only{n}")),
                "layer {n} kept"
            );
        }
    }

    /// An image manifest of the one plain layer `layer`; `salt` varies the
    /// body without changing what it describes.
    fn manifest_json(layer: &[u8], salt: u32) -> String {
        serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                       "digest": sha256(b"{}"), "size": 2},
            "layers": [{"mediaType": OCI_LAYER, "digest": sha256(layer), "size": layer.len()}],
            "annotations": {"salt": salt.to_string()}
        })
        .to_string()
    }

    /// `docker.io/library/hello`: a two-platform index whose linux/amd64
    /// manifest has one layer holding `hello`, served by a [`FakeRegistry`].
    struct TestImage {
        registry: FakeRegistry,
        layer: Vec<u8>,
        index: String,
        amd64_digest: String,
    }

    impl TestImage {
        fn new() -> Self {
            let layer = layer(&[("hello", "hi")]);
            let amd64 = manifest_json(&layer, 0);
            let arm64 = manifest_json(&layer, 1);
            let amd64_digest = sha256(amd64.as_bytes());
            let index = serde_json::json!({
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [
                    {"mediaType": "application/vnd.oci.image.manifest.v1+json",
                     "digest": sha256(arm64.as_bytes()), "size": arm64.len(),
                     "platform": {"os": "linux", "architecture": "arm64"}},
                    {"mediaType": "application/vnd.oci.image.manifest.v1+json",
                     "digest": amd64_digest, "size": amd64.len(),
                     "platform": {"os": "linux", "architecture": "amd64"}}
                ]
            })
            .to_string();
            let image = Self {
                registry: FakeRegistry::default(),
                layer,
                index,
                amd64_digest,
            };
            image.registry.challenge(&format!(
                "Bearer realm=\"{REALM}\",service=\"registry.docker.io\",scope=\"repository:other/repo:push\""
            ));
            image.registry.serve(REALM, br#"{"token":"t0ken"}"#, &[]);
            image.registry.serve(
                &image.tag_url(),
                image.index.as_bytes(),
                &[("Docker-Content-Digest", &sha256(image.index.as_bytes()))],
            );
            image
                .registry
                .serve(&image.amd64_url(), amd64.as_bytes(), &[]);
            image.registry.serve(&image.blob_url(), &image.layer, &[]);
            image
        }

        fn tag_url(&self) -> String {
            format!("https://{DOCKER_HUB}/v2/library/hello/manifests/latest")
        }

        fn amd64_url(&self) -> String {
            format!(
                "https://{DOCKER_HUB}/v2/library/hello/manifests/{}",
                self.amd64_digest
            )
        }

        fn blob_url(&self) -> String {
            format!(
                "https://{DOCKER_HUB}/v2/library/hello/blobs/{}",
                sha256(&self.layer)
            )
        }
    }
}
