//! Pull an OCI image and flatten it to a single rootfs tarball: an
//! xz-compressed tar of the merged filesystem, as go-containerregistry's
//! [`crane export`](https://github.com/google/go-containerregistry/blob/main/cmd/crane/doc/crane_export.md)
//! produces for the same image. The bytes are not guaranteed identical to
//! another exporter's (tar header and xz encoder details differ); an image's
//! identity across implementations is its manifest digest, which [`export`]
//! returns and the fetch layer records.
//!
//! The distribution protocol ([`registry`]) is spoken over the caller's
//! [`Fetch`] backend — a token handshake, then manifest and blob GETs — so
//! every request, the token realm and the blob CDN a registry redirects to
//! included, passes the same per-hop https and SSRF floor as any other fetch.
//! Pulls are additionally restricted to an allowlist of public registries:
//! `repository_url` is feed-supplied data, and an image is a large, costly
//! artifact to let a scanned file aim anywhere. For the same reason a layer
//! naming foreign `urls` is refused.
//!
//! Nothing is held in memory whole: each layer is spooled to disk as it
//! arrives and verified there, both flatten passes ([`flatten`]) decode it
//! from disk as they read, and the export streams into the caller's spool.
//!
//! The export is for analysis only and must never be extracted to disk: it
//! keeps the image's symlink targets (absolute and `..`-relative), device
//! nodes and setuid bits.

use std::io::Write;

use crate::fetch::cache::{MAX_ENTRY_BYTES, Spool, create_private};
use crate::fetch::{Fetch, FetchError};

mod flatten;
mod registry;

/// Ceiling on an image: its layers' declared sizes together, their expanded
/// tars together, and the flattened tar. A generous runaway stop for
/// pathological images, not a package-size cap. Each layer is also a single
/// response, so the backend's per-fetch ceiling bounds it.
const MAX_EXPORT_BYTES: u64 = 2 << 30;

// xz's worst-case expansion of incompressible input is a fraction of a
// percent, so an export always fits a cache entry.
const _: () = assert!(MAX_EXPORT_BYTES + MAX_EXPORT_BYTES / 64 <= MAX_ENTRY_BYTES);

/// Pull `reference` (`host/path:tag` or `host/path@sha256:…`, as produced by
/// `resolve_purl`'s `oci://` pseudo-URL) through `net` and write the flattened
/// rootfs into `out`, as an xz-compressed tar. `out` must not exist yet; the
/// layers are spooled beside it and removed before this returns. Returns the
/// image's manifest digest — the content-addressed identity that is stable
/// across implementations.
pub(crate) fn export(reference: &str, net: &dyn Fetch, out: &Spool) -> Result<String, FetchError> {
    let exported = pull_and_flatten(reference, net, out);
    match &exported {
        Ok(digest) => tracing::debug!(target: "oci", reference, digest, "image exported"),
        Err(error) => tracing::debug!(target: "oci", reference, %error, "image export failed"),
    }
    exported
}

fn pull_and_flatten(reference: &str, net: &dyn Fetch, out: &Spool) -> Result<String, FetchError> {
    let (blobs, digest) = registry::pull(reference, net, out, MAX_EXPORT_BYTES)?;
    let layers: Vec<flatten::Layer<'_>> = blobs
        .iter()
        .map(|blob| flatten::Layer {
            path: blob.spool.path(),
            encoding: blob.encoding,
        })
        .collect();
    let io = |e: std::io::Error| FetchError::Io(format!("export: {e}"));
    let file = create_private(out.path()).map_err(io)?;
    flatten::flatten(&layers, std::io::BufWriter::new(file), MAX_EXPORT_BYTES)?
        .flush()
        .map_err(io)?;
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fetch::{BlobCache, Fetched, Request};
    use std::collections::HashMap;
    use std::io::Read;
    use std::sync::Mutex;

    /// Build an in-memory layer tar of regular files.
    pub(super) fn layer(entries: &[(&str, &str)]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (path, content) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_size(content.len() as u64);
            h.set_mode(0o644);
            b.append_data(&mut h, path, content.as_bytes()).unwrap();
        }
        b.into_inner().unwrap()
    }

    /// Build a layer tar containing names `tar::Builder` would refuse to
    /// write (`..` segments), by laying down the 512-byte ustar header by
    /// hand. A hostile registry is under no obligation to use a well-behaved
    /// tar writer, so the fixture must not either.
    pub(super) fn hostile_layer(entries: &[(&str, &str)]) -> Vec<u8> {
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
    pub(super) fn entries_of(tar_xz: &[u8]) -> Vec<(String, String)> {
        let mut raw = Vec::new();
        xz2::read::XzDecoder::new(tar_xz)
            .read_to_end(&mut raw)
            .unwrap();
        let mut archive = tar::Archive::new(raw.as_slice());
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

    /// Export `reference` from `net` into a scratch cache shard: the tar.xz,
    /// the digest, and every other file the export left in the shard.
    pub(super) fn export_bytes(
        reference: &str,
        net: &dyn Fetch,
    ) -> Result<(Vec<u8>, String, Vec<String>), FetchError> {
        let dir = tempfile::tempdir().unwrap();
        let out = BlobCache::with_dir(dir.path()).spool("abcd");
        let exported = export(reference, net, &out);
        let shard = out.path().parent().unwrap();
        let left: Vec<String> = std::fs::read_dir(shard)
            .unwrap()
            .flatten()
            .filter(|e| e.path() != out.path())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        let digest = exported?;
        Ok((std::fs::read(out.path()).unwrap(), digest, left))
    }

    pub(super) const REALM: &str = "https://auth.docker.io/token";
    pub(super) const HUB: &str = "https://registry-1.docker.io";

    /// A registry that demands a bearer token for everything under `/v2/`,
    /// issues `t0ken` from [`REALM`], and records each request with the
    /// `Authorization` it carried and whether it asked to be spooled. Like
    /// [`HttpFetch`](crate::fetch::HttpFetch), it writes a spooled request's
    /// body — a refusal's included — to the spool and hands back no bytes.
    #[derive(Default)]
    pub(super) struct FakeRegistry {
        responses: Mutex<HashMap<String, Fetched>>,
        challenge: Mutex<String>,
        log: Mutex<Vec<(String, Option<String>, bool)>>,
        panics_at: Mutex<Option<String>>,
    }

    impl FakeRegistry {
        pub(super) fn serve(&self, url: &str, bytes: &[u8], headers: &[(&str, &str)]) {
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

        pub(super) fn challenge(&self, challenge: &str) {
            *self.challenge.lock().unwrap() = challenge.to_string();
        }

        /// `(url, authorization, spooled)` for every request, in order.
        pub(super) fn requests(&self) -> Vec<(String, Option<String>, bool)> {
            self.log.lock().unwrap().clone()
        }

        fn answer(&self, request: &Request<'_>, auth: Option<&str>) -> Result<Fetched, FetchError> {
            let key = request.url.split('?').next().unwrap_or_default();
            if self.panics_at.lock().unwrap().as_deref() == Some(key) {
                panic!("backend bug at {key}");
            }
            if request.url.contains("/v2/") && auth != Some("Bearer t0ken") {
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
    }

    impl Fetch for FakeRegistry {
        fn send(&self, request: &Request<'_>) -> Result<Fetched, FetchError> {
            let auth = request
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
                .map(|(_, v)| (*v).to_string());
            self.log.lock().unwrap().push((
                request.url.to_string(),
                auth.clone(),
                request.spool.is_some(),
            ));
            let mut fetched = self.answer(request, auth.as_deref())?;
            if let Some(path) = request.spool {
                let mut file = create_private(path).map_err(|e| FetchError::Io(e.to_string()))?;
                std::io::Write::write_all(&mut file, &fetched.bytes).unwrap();
                fetched.bytes.clear();
            }
            Ok(fetched)
        }

        fn allows_oci(&self) -> bool {
            true
        }
    }

    pub(super) fn sha256(bytes: &[u8]) -> String {
        format!("sha256:{}", crate::fetch::sha256_hex(bytes))
    }

    /// An image manifest of the plain `layers`; `salt` varies the body
    /// without changing what it describes.
    fn manifest_json(layers: &[&[u8]], salt: u32) -> String {
        serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                       "digest": sha256(b"{}"), "size": 2},
            "layers": layers.iter().map(|l| serde_json::json!(
                {"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": sha256(l), "size": l.len()}
            )).collect::<Vec<_>>(),
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
            let amd64 = manifest_json(&[&layer], 0);
            let arm64 = manifest_json(&[&layer], 1);
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
            format!("{HUB}/v2/library/hello/manifests/latest")
        }

        fn amd64_url(&self) -> String {
            format!("{HUB}/v2/library/hello/manifests/{}", self.amd64_digest)
        }

        fn blob_url(&self) -> String {
            format!("{HUB}/v2/library/hello/blobs/{}", sha256(&self.layer))
        }
    }

    #[test]
    fn a_pull_follows_the_token_flow_and_picks_linux_amd64() {
        let image = TestImage::new();
        let (tar_xz, digest, _) = export_bytes("docker.io/hello:latest", &image.registry).unwrap();
        assert_eq!(digest, image.amd64_digest, "the platform manifest's digest");
        assert_eq!(entries_of(&tar_xz), vec![("hello".into(), "hi".into())]);

        let requests = image.registry.requests();
        let realm: Vec<_> = requests
            .iter()
            .filter(|(url, ..)| url.starts_with(REALM))
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
            .find(|(url, ..)| url.contains("/blobs/"))
            .expect("blob request");
        assert_eq!(blob.1.as_deref(), Some("Bearer t0ken"));
    }

    /// Every blob goes to disk, never into memory, and the layer spools are
    /// gone once the export is written — a challenge spooled where a blob
    /// was to go included.
    #[test]
    fn a_pull_spools_every_layer_and_leaves_only_its_output() {
        let image = TestImage::new();
        let (_, _, left) = export_bytes("docker.io/hello:latest", &image.registry).unwrap();
        assert!(left.is_empty(), "left behind: {left:?}");
        let requests = image.registry.requests();
        let blobs: Vec<_> = requests
            .iter()
            .filter(|(url, ..)| url.contains("/blobs/"))
            .collect();
        assert!(!blobs.is_empty());
        assert!(blobs.iter().all(|(_, _, spooled)| *spooled), "{blobs:?}");
        assert!(
            requests
                .iter()
                .filter(|(url, ..)| url.contains("/manifests/"))
                .all(|(_, _, spooled)| !spooled),
            "manifests are small and parsed in memory"
        );
    }

    #[test]
    fn a_layer_cannot_outgrow_its_declared_size() {
        // A backend that ignores the request's byte cap is still held to the
        // manifest's size, so a registry can't stream more than it promised.
        let image = TestImage::new();
        let mut bigger = image.layer.clone();
        bigger.extend_from_slice(&[0; 512]);
        image.registry.serve(&image.blob_url(), &bigger, &[]);
        let got = export_bytes("docker.io/hello:latest", &image.registry);
        assert!(
            matches!(&got, Err(FetchError::Refused(why)) if why.contains("declares")),
            "{got:?}"
        );
    }

    #[test]
    fn a_blob_that_does_not_match_its_digest_is_refused() {
        let image = TestImage::new();
        let mut forged = image.layer.clone();
        forged[0] ^= 1; // same size, different bytes
        image.registry.serve(&image.blob_url(), &forged, &[]);
        let got = export_bytes("docker.io/hello:latest", &image.registry);
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
        let other = manifest_json(&[&image.layer], 1);
        image
            .registry
            .serve(&image.amd64_url(), other.as_bytes(), &[]);
        let got = export_bytes("docker.io/hello:latest", &image.registry);
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
        let got = export_bytes("docker.io/hello:latest", &image.registry);
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
        let got = export_bytes("docker.io/hello:latest", &image.registry);
        assert!(
            matches!(&got, Err(FetchError::Refused(why)) if why.contains("https")),
            "{got:?}"
        );
        assert!(
            image
                .registry
                .requests()
                .iter()
                .all(|(url, ..)| !url.starts_with("http://")),
            "the realm was never asked"
        );
    }

    #[test]
    fn a_token_that_could_inject_headers_is_refused() {
        for token in ["t0ken\r\nX-Evil: 1", "has space", ""] {
            let image = TestImage::new();
            let reply = serde_json::json!({ "token": token }).to_string();
            image.registry.serve(REALM, reply.as_bytes(), &[]);
            let got = export_bytes("docker.io/hello:latest", &image.registry);
            assert!(
                matches!(&got, Err(FetchError::Refused(why)) if why.contains("token")),
                "{token:?}: {got:?}"
            );
        }
    }

    /// A ten-layer image served as `docker.io/library/stack`.
    fn stack() -> (FakeRegistry, Vec<Vec<u8>>) {
        let registry = FakeRegistry::default();
        registry.challenge(&format!(
            "Bearer realm=\"{REALM}\",service=\"registry.docker.io\""
        ));
        registry.serve(REALM, br#"{"token":"t0ken"}"#, &[]);
        // Ten layers each rewrite `f`; the top one's must win.
        let layers: Vec<Vec<u8>> = (0..10)
            .map(|n| layer(&[("f", &n.to_string()), (&format!("only{n}"), "x")]))
            .collect();
        let refs: Vec<&[u8]> = layers.iter().map(Vec::as_slice).collect();
        registry.serve(
            &format!("{HUB}/v2/library/stack/manifests/latest"),
            manifest_json(&refs, 0).as_bytes(),
            &[],
        );
        for l in &layers {
            registry.serve(
                &format!("{HUB}/v2/library/stack/blobs/{}", sha256(l)),
                l,
                &[],
            );
        }
        (registry, layers)
    }

    #[test]
    fn concurrently_read_layers_flatten_in_manifest_order() {
        let (registry, _) = stack();
        let (export, _, left) = export_bytes("docker.io/library/stack:latest", &registry).unwrap();
        assert!(left.is_empty(), "left behind: {left:?}");
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

    /// A worker that panics is a failed pull that says so, never a shorter
    /// image, and leaves no spool behind.
    #[test]
    fn a_panicking_blob_worker_fails_the_pull() {
        let (registry, layers) = stack();
        *registry.panics_at.lock().unwrap() = Some(format!(
            "{HUB}/v2/library/stack/blobs/{}",
            sha256(&layers[5])
        ));
        let got = export_bytes("docker.io/library/stack:latest", &registry);
        assert!(
            matches!(&got, Err(FetchError::Internal(why)) if why.contains("backend bug")),
            "{got:?}"
        );
    }

    /// Opt-in live check (`cargo test -- --ignored oci`): pulls the tiny
    /// hello-world image and flattens it. Everything else in this module is
    /// hermetic; this is the one place the real protocol gets exercised.
    #[test]
    #[ignore = "live network: pulls docker.io/library/hello-world"]
    fn live_export_hello_world() {
        let net = crate::fetch::HttpFetch::new().expect("client");
        let (tar_xz, digest, _) =
            export_bytes("docker.io/library/hello-world:latest", &net).expect("export");
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
    /// with a *real* filesystem. Debian rather than Alpine: Debian's layer
    /// opens with a `./` root entry, which Alpine's and `hello-world`'s lack,
    /// so only this one exercises that path end to end.
    #[test]
    #[ignore = "live network: pulls docker.io/library/debian"]
    fn live_export_debian_rootfs() {
        let net = crate::fetch::HttpFetch::new().expect("client");
        let (tar_xz, digest, _) =
            export_bytes("docker.io/library/debian:stable-slim", &net).expect("export");
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
}
