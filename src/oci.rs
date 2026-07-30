//! Pull an OCI image and flatten it to a single rootfs tarball — the Rust
//! analog of forager's `crane.Pull` + `crane.Export` (go-containerregistry)
//! path, so both producers emit the same artifact shape (an xz-compressed tar
//! of the merged filesystem) for the same `pkg:oci` identity. The bytes are
//! NOT guaranteed identical across the two implementations (tar header and xz
//! encoder details differ); cross-implementation identity comes from the
//! manifest digest, which [`export`] returns and the fetch layer records.
//!
//! Transport caveat: the OCI distribution protocol is a token handshake plus
//! manifest and blob rounds, not a single URL, so pulls go through
//! oci-client's own HTTP stack rather than the [`crate::fetch::Fetch`]
//! backend. Two consequences, both deliberate:
//! - hermetic tests must never fetch a `pkg:oci` reference (the flatten stage
//!   is pure and tested against fixture layers instead);
//! - the fetch backend's SSRF guard does not see these requests, so pulls are
//!   restricted to an allowlist of public registries — `repository_url` is
//!   feed-supplied data and must not steer requests at internal hosts.

use std::collections::HashSet;
use std::io::{Cursor, Read, Write};

use oci_client::client::{ClientConfig, ImageLayer, linux_amd64_resolver};
use oci_client::manifest::{
    IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE, IMAGE_DOCKER_LAYER_TAR_MEDIA_TYPE,
    IMAGE_LAYER_GZIP_MEDIA_TYPE, IMAGE_LAYER_MEDIA_TYPE,
    IMAGE_LAYER_NONDISTRIBUTABLE_GZIP_MEDIA_TYPE, IMAGE_LAYER_NONDISTRIBUTABLE_MEDIA_TYPE,
};
use oci_client::secrets::RegistryAuth;
use oci_client::{Client, Reference};

/// Uncompressed-tar size cap, matching forager's `maxContainerBytes` guard:
/// a generous runaway stop for pathological images, not a package-size cap.
const MAX_EXPORT_BYTES: u64 = 2 << 30; // 2 GiB

/// Registries an `oci://` pull may talk to. The reference host comes from a
/// purl's `repository_url` qualifier — feed-supplied data — and these pulls
/// bypass the fetch backend's SSRF guard, so only well-known public registries
/// are reachable. Extend deliberately, never dynamically.
const ALLOWED_REGISTRIES: &[&str] = &[
    "docker.io",
    "index.docker.io", // oci-client's canonical spelling of docker.io
    "registry-1.docker.io",
    "ghcr.io",
    "quay.io",
    "gcr.io",
    "registry.k8s.io",
    "public.ecr.aws",
];

/// The layer encodings we can flatten. zstd variants are handled by suffix in
/// [`decompress`], but the pull-time accept list uses the ratified constants.
const ACCEPTED_LAYER_TYPES: &[&str] = &[
    IMAGE_LAYER_MEDIA_TYPE,
    IMAGE_LAYER_GZIP_MEDIA_TYPE,
    "application/vnd.oci.image.layer.v1.tar+zstd",
    IMAGE_DOCKER_LAYER_TAR_MEDIA_TYPE,
    IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE,
    IMAGE_LAYER_NONDISTRIBUTABLE_MEDIA_TYPE,
    IMAGE_LAYER_NONDISTRIBUTABLE_GZIP_MEDIA_TYPE,
];

/// Pull `reference` (`host/path:tag` or `host/path@sha256:…`, as produced by
/// `resolve_purl`'s `oci://` pseudo-URL) and export the flattened rootfs as an
/// xz-compressed tar. Returns the bytes and the image's manifest digest — the
/// content-addressed identity that is stable across implementations.
pub(crate) fn export(reference: &str) -> Result<(Vec<u8>, Option<String>), String> {
    let image = pull(reference)?;
    let digest = image.digest.clone();
    let layers = image
        .layers
        .iter()
        .map(decompress)
        .collect::<Result<Vec<_>, String>>()?;
    let tar_xz = flatten_to_tar_xz(&layers)?;
    Ok((tar_xz, digest))
}

/// Anonymous pull of the linux/amd64 image — the same default platform
/// go-containerregistry's crane resolves, so both exporters flatten the same
/// per-platform manifest of a multi-arch index.
fn pull(reference: &str) -> Result<oci_client::client::ImageData, String> {
    let re: Reference = reference
        .parse()
        .map_err(|e| format!("bad OCI reference {reference:?}: {e}"))?;
    let registry = re.resolve_registry();
    if !ALLOWED_REGISTRIES.contains(&registry) {
        return Err(format!("registry {registry:?} not in the public allowlist"));
    }
    let client = Client::new(ClientConfig {
        platform_resolver: Some(Box::new(linux_amd64_resolver)),
        ..ClientConfig::default()
    });
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {e}"))?;
    rt.block_on(client.pull(&re, &RegistryAuth::Anonymous, ACCEPTED_LAYER_TYPES.to_vec()))
        .map_err(|e| format!("pull {reference}: {e}"))
}

/// Decode one layer blob to its plain tar bytes, by media-type suffix.
fn decompress(layer: &ImageLayer) -> Result<Vec<u8>, String> {
    let data = layer.data.as_ref();
    let mut out = Vec::new();
    if layer.media_type.ends_with("gzip") {
        flate2::read::MultiGzDecoder::new(Cursor::new(data))
            .take(MAX_EXPORT_BYTES + 1)
            .read_to_end(&mut out)
    } else if layer.media_type.ends_with("zstd") {
        zstd::stream::read::Decoder::new(Cursor::new(data))
            .map_err(|e| format!("zstd: {e}"))?
            .take(MAX_EXPORT_BYTES + 1)
            .read_to_end(&mut out)
    } else {
        return Ok(data.to_vec());
    }
    .map_err(|e| format!("decompress layer ({}): {e}", layer.media_type))?;
    if out.len() as u64 > MAX_EXPORT_BYTES {
        return Err("layer exceeds the export size cap".into());
    }
    Ok(out)
}

/// Flatten decompressed layer tars (base → top order, as the manifest lists
/// them) into one xz-compressed rootfs tar.
///
/// Semantics follow `crane.Export` / `mutate.Extract`: walk layers *top-down*,
/// the first occurrence of a path wins, and a `.wh.<name>` whiteout tombstones
/// that path (and, for a directory, everything under it) in the layers below.
/// One deliberate divergence: the OCI image-spec's opaque-whiteout marker
/// (`.wh..wh..opq`, hiding a directory's lower-layer *contents* while keeping
/// the directory) is honored per spec, which crane's Extract famously is not —
/// spec correctness wins over bug parity, and identity is digest-based anyway.
fn flatten_to_tar_xz(layers: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    let xz = xz2::write::XzEncoder::new(Vec::new(), 6);
    let mut builder = tar::Builder::new(LimitWriter {
        w: xz,
        limit: MAX_EXPORT_BYTES,
        written: 0,
    });

    // Paths already emitted (exact-match dedup: a higher layer's file shadows
    // the same path below, never its siblings).
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    // Paths tombstoned by a higher layer's `.wh.` marker: the path itself and,
    // when it names a directory, its whole subtree are hidden below.
    let mut tombstones: HashSet<Vec<u8>> = HashSet::new();
    // Directories opaqued by a higher layer's `.wh..wh..opq`: all lower-layer
    // entries strictly under them are hidden.
    let mut opaque: HashSet<Vec<u8>> = HashSet::new();

    for layer in layers.iter().rev() {
        // Pass 1: collect this layer's markers. They constrain the layers
        // BELOW this one, not this layer's own entries, so they are staged
        // and merged in only after pass 2. (Tar reading is forward-only, so
        // each pass opens a fresh Archive over the in-memory bytes.)
        let mut layer_tombstones: HashSet<Vec<u8>> = HashSet::new();
        let mut layer_opaque: HashSet<Vec<u8>> = HashSet::new();
        let mut archive = tar::Archive::new(Cursor::new(layer.as_slice()));
        archive.set_ignore_zeros(true);
        for entry in archive.entries().map_err(|e| format!("layer tar: {e}"))? {
            let entry = entry.map_err(|e| format!("layer tar: {e}"))?;
            let path = clean_path(&entry.path_bytes());
            let (dir, base) = split_dir_base(&path);
            if base == b".wh..wh..opq" {
                layer_opaque.insert(dir.to_vec());
            } else if let Some(target) = base.strip_prefix(b".wh.") {
                layer_tombstones.insert(join_dir(dir, target));
            }
        }

        // Pass 2: emit entries not shadowed by HIGHER layers.
        let mut archive = tar::Archive::new(Cursor::new(layer.as_slice()));
        archive.set_ignore_zeros(true);
        for entry in archive.entries().map_err(|e| format!("layer tar: {e}"))? {
            let mut entry = entry.map_err(|e| format!("layer tar: {e}"))?;
            let path = clean_path(&entry.path_bytes());
            let (_, base) = split_dir_base(&path);
            if base.starts_with(b".wh.") {
                continue; // marker, never emitted
            }
            if seen.contains(&path) || shadowed(&path, &tombstones, &opaque) {
                continue;
            }
            append_entry(&mut builder, &mut entry, &path)?;
            seen.insert(path);
        }

        tombstones.extend(layer_tombstones);
        opaque.extend(layer_opaque);
    }

    let limit = builder
        .into_inner()
        .map_err(|e| format!("finish tar: {e}"))?;
    limit
        .w
        .finish()
        .map_err(|e| format!("finish xz: {e}"))
}

/// Copy one tar entry (header, path, link target, body) into the output,
/// regenerating long-name/long-link extensions so paths the source encoded
/// via PAX/GNU records survive the transplant.
fn append_entry<W: Write>(
    builder: &mut tar::Builder<W>,
    entry: &mut tar::Entry<'_, Cursor<&[u8]>>,
    path: &[u8],
) -> Result<(), String> {
    let mut header = entry.header().clone();
    let kind = header.entry_type();
    if kind.is_symlink() || kind.is_hard_link() {
        let target = entry
            .link_name_bytes()
            .ok_or_else(|| "link entry without target".to_string())?
            .into_owned();
        builder
            .append_link(&mut header, bytes_path(path), bytes_path(&target))
            .map_err(|e| format!("append link: {e}"))
    } else {
        builder
            .append_data(&mut header, bytes_path(path), entry)
            .map_err(|e| format!("append entry: {e}"))
    }
}

/// `path::Clean`-alike over raw tar path bytes: strip `./` and leading `/`,
/// so layer spellings (`./etc/passwd`, `/etc/passwd`, `etc/passwd`) all key
/// the same file, mirroring crane's `path.Clean("/"+name)` normalization.
fn clean_path(raw: &[u8]) -> Vec<u8> {
    let mut p = raw;
    loop {
        if let Some(rest) = p.strip_prefix(b"./") {
            p = rest;
        } else if let Some(rest) = p.strip_prefix(b"/") {
            p = rest;
        } else {
            break;
        }
    }
    p.strip_suffix(b"/").unwrap_or(p).to_vec()
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

/// Whether a path is hidden by higher-layer markers: the path or any ancestor
/// is tombstoned, or any ancestor directory is opaque.
fn shadowed(path: &[u8], tombstones: &HashSet<Vec<u8>>, opaque: &HashSet<Vec<u8>>) -> bool {
    if tombstones.contains(path) {
        return true;
    }
    let mut end = path.len();
    while let Some(i) = path[..end].iter().rposition(|&b| b == b'/') {
        let ancestor = &path[..i];
        if tombstones.contains(ancestor) || opaque.contains(ancestor) {
            return true;
        }
        end = i;
    }
    false
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
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
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
        let base = layer(&[("cfg/old.conf", "old"), ("cfg/sub/x", "x"), ("root.txt", "r")]);
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

    #[test]
    fn markers_only_constrain_lower_layers() {
        // A whiteout and a fresh file for the same path in ONE layer: the
        // layer's own file must survive (markers apply strictly below).
        let base = layer(&[("app/a", "old")]);
        let top = layer(&[("app/.wh.a", ""), ("app/a", "new")]);
        let got = entries_of(&flatten_to_tar_xz(&[base, top]).unwrap());
        assert_eq!(got, vec![("app/a".into(), "new".into())]);
    }

    /// Opt-in live check (`cargo test -- --ignored oci`): pulls the tiny
    /// hello-world image and flattens it. Everything else in this module is
    /// hermetic; this is the one place the real protocol gets exercised.
    #[test]
    #[ignore = "live network: pulls docker.io/library/hello-world"]
    fn live_export_hello_world() {
        let (tar_xz, digest) = export("docker.io/library/hello-world:latest").expect("export");
        assert!(digest.is_some(), "manifest digest must be recorded");
        let entries = entries_of(&tar_xz);
        assert!(
            entries.iter().any(|(p, _)| p == "hello"),
            "flattened rootfs should contain the hello binary: {entries:?}"
        );
    }

    #[test]
    fn disallowed_registry_is_refused() {
        let Err(err) = pull("internal.corp:5000/secret/image:latest") else {
            panic!("pull of a non-allowlisted registry must fail");
        };
        assert!(err.contains("not in the public allowlist"), "{err}");
    }
}
