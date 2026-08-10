//! OS-distro package registries whose metadata lives in a *compressed index or
//! catalog* rather than a per-package JSON API — the half of
//! [`registry`](crate::registry) that needs decompression and index parsing.
//!
//! Each ecosystem publishes one large index per repository: Alpine and Wolfi an
//! `APKINDEX.tar.gz`, Debian and Ubuntu a `Packages.gz`, openSUSE and RPM Fusion
//! a `repomd.xml` → `primary.xml.{zst,gz,xz}`, NetBSD a `pkg_summary.gz`,
//! FreeBSD a `packagesite.pkg` (tar.xz). We fetch the index through the blob
//! cache (so the multi-megabyte download is paid once per cache window), stream
//! it through a pure-Rust decompressor, and scan it stanza-by-stanza for the one
//! package asked about — never holding the whole decompressed index in memory.
//!
//! Like the rest of registry lookup this is best-effort: an unreachable mirror,
//! an absent package, or a moved index layout yields `None`, and the caller
//! treats that as "unknown" rather than an error. The repository coordinates
//! (release, architecture) are pinned to current defaults below; they track the
//! distributions over time exactly as the upstream index URLs do.

use std::io::{BufRead, BufReader, Cursor, Read, Write};

use serde_json::Value;

use filefacts::Registry;

use crate::fetch::{BlobCache, Fetch, cached_metadata};
use crate::registry::{parse_ts, strip_email};

/// Ceiling on a single index's *decompressed* size. The 64 MiB download cap
/// already bounds the compressed input; this backstops a decompression bomb
/// (a tiny input inflating without limit) and the streaming scanners never hold
/// more than one stanza regardless.
const DECOMP_CAP: u64 = 512 * 1024 * 1024;

/// Read size for the streaming XML scanner.
const XML_CHUNK: usize = 64 * 1024;

// --- public per-distro entry points -----------------------------------------

/// Alpine Linux: the `main` then `community` `APKINDEX` of the current stable
/// release. The index records the maintainer, license, homepage, and a build
/// timestamp — a full registry record.
pub fn alpine(name: &str, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    const REPOS: [&str; 2] = [
        "https://dl-cdn.alpinelinux.org/alpine/latest-stable/main/x86_64/APKINDEX.tar.gz",
        "https://dl-cdn.alpinelinux.org/alpine/latest-stable/community/x86_64/APKINDEX.tar.gz",
    ];
    REPOS
        .iter()
        .find_map(|url| apkindex_lookup(url, name, "alpine", net, cache))
}

/// Wolfi (Chainguard's distroless base): a single rolling `APKINDEX`, same
/// format as Alpine.
pub fn wolfi(name: &str, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    apkindex_lookup(
        "https://packages.wolfi.dev/os/x86_64/APKINDEX.tar.gz",
        name,
        "wolfi",
        net,
        cache,
    )
}

/// Debian: the `stable/main` binary `Packages` index. It carries the maintainer,
/// description, and homepage but no upload time, so age stays unknown.
pub fn debian(name: &str, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    deb_lookup(
        "https://deb.debian.org/debian/dists/stable/main/binary-amd64/Packages.gz",
        name,
        "debian",
        net,
        cache,
    )
}

/// Ubuntu: the current LTS `main` then `universe` binary `Packages` index, same
/// control format as Debian.
pub fn ubuntu(name: &str, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    const REPOS: [&str; 2] = [
        "https://archive.ubuntu.com/ubuntu/dists/noble/main/binary-amd64/Packages.gz",
        "https://archive.ubuntu.com/ubuntu/dists/noble/universe/binary-amd64/Packages.gz",
    ];
    REPOS
        .iter()
        .find_map(|url| deb_lookup(url, name, "ubuntu", net, cache))
}

/// openSUSE Tumbleweed (`oss` repo): the `primary.xml` referenced by `repomd.xml`
/// carries the summary, license, homepage, and a build time.
pub fn opensuse(name: &str, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    rpm_repo_lookup(
        "https://download.opensuse.org/tumbleweed/repo/oss",
        name,
        "opensuse",
        net,
        cache,
    )
}

/// RPM Fusion (free, Fedora rawhide): same `repomd`/`primary.xml` layout as a
/// Fedora repository.
pub fn rpmfusion(name: &str, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    rpm_repo_lookup(
        "https://download1.rpmfusion.org/free/fedora/development/rawhide/Everything/x86_64/os",
        name,
        "rpmfusion",
        net,
        cache,
    )
}

/// NetBSD (pkgsrc binary packages): `pkg_summary` is an RFC822-ish index with
/// the comment, homepage, license, maintainer, and build date.
pub fn netbsd(name: &str, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    let bytes = cached_metadata(
        "https://cdn.netbsd.org/pub/pkgsrc/packages/NetBSD/x86_64/10.0/All/pkg_summary.gz",
        net,
        cache,
    )?;
    let reader = BufReader::new(gunzip(bytes));
    each_stanza(reader, |stanza| pkg_summary_record(stanza, name))
}

/// FreeBSD (binary pkg): `packagesite.pkg` is a zstd-compressed tar whose
/// `packagesite.yaml` is newline-delimited JSON, one object per package, with
/// the comment, maintainer, homepage (`www`), and licenses.
pub fn freebsd(name: &str, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    let bytes = cached_metadata(
        "https://pkg.freebsd.org/FreeBSD:14:amd64/latest/packagesite.pkg",
        net,
        cache,
    )?;
    let tar = unzstd(bytes)?;
    let yaml = tar_find(&tar, "packagesite.yaml")?;
    let text = std::str::from_utf8(&yaml).ok()?;
    text.lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .find(|o| o.get("name").and_then(Value::as_str) == Some(name))
        .map(|o| packagesite_record(&o, name))
}

/// OpenBSD: there is no metadata index — only the packages directory listing —
/// so this recovers just the current version from the published filenames. The
/// `snapshots` tree always reflects the live package set (a numbered release is
/// frozen and eventually pruned).
pub fn openbsd(name: &str, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    let bytes = cached_metadata(
        "https://cdn.openbsd.org/pub/OpenBSD/snapshots/packages/amd64/index.txt",
        net,
        cache,
    )?;
    let text = std::str::from_utf8(&bytes).ok()?;
    let version = openbsd_version(text, name)?;
    Some(Registry {
        ecosystem: "openbsd".into(),
        name: name.to_string(),
        version,
        ..Default::default()
    })
}

// --- APK (Alpine, Wolfi) ----------------------------------------------------

/// Fetch one `APKINDEX.tar.gz`, extract its `APKINDEX` member, and scan it.
fn apkindex_lookup(
    url: &str,
    name: &str,
    ecosystem: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Option<Registry> {
    let bytes = cached_metadata(url, net, cache)?;
    // APKINDEX.tar.gz concatenates a signature stream and the control stream;
    // decompress both, then pull the `APKINDEX` text from the archive.
    let mut out = Vec::new();
    flate2::read::MultiGzDecoder::new(Cursor::new(bytes))
        .take(DECOMP_CAP)
        .read_to_end(&mut out)
        .ok()?;
    let index = tar_find(&out, "APKINDEX")?;
    let text = std::str::from_utf8(&index).ok()?;
    each_stanza(BufReader::new(Cursor::new(text)), |stanza| {
        apkindex_record(stanza, name, ecosystem)
    })
}

/// Map one matching `APKINDEX` stanza (single-letter `K:value` lines).
fn apkindex_record(stanza: &str, name: &str, ecosystem: &str) -> Option<Registry> {
    if field(stanza, "P:").as_deref() != Some(name) {
        return None;
    }
    Some(Registry {
        ecosystem: ecosystem.into(),
        name: name.to_string(),
        version: field(stanza, "V:").unwrap_or_default(),
        // `t:0` is a "build time unset" sentinel (reproducible builds), not a
        // 1970 publish — treat it as unknown.
        published_at: field(stanza, "t:")
            .and_then(|t| t.parse::<u64>().ok())
            .filter(|&t| t > 0),
        author: field(stanza, "m:").map(|m| strip_email(&m)),
        description: field(stanza, "T:"),
        homepage: field(stanza, "U:"),
        license: field(stanza, "L:"),
        ..Default::default()
    })
}

// --- Debian / Ubuntu (control format) ---------------------------------------

/// Fetch one gzip `Packages` index and scan its control stanzas.
fn deb_lookup(
    url: &str,
    name: &str,
    ecosystem: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Option<Registry> {
    let bytes = cached_metadata(url, net, cache)?;
    let reader = BufReader::new(gunzip(bytes));
    let eco = ecosystem.to_string();
    each_stanza(reader, |stanza| deb_record(stanza, name, &eco))
}

/// Map one matching Debian control stanza (`Key: value`, with folded
/// continuation lines for multi-line descriptions).
fn deb_record(stanza: &str, name: &str, ecosystem: &str) -> Option<Registry> {
    if field(stanza, "Package:").as_deref() != Some(name) {
        return None;
    }
    Some(Registry {
        ecosystem: ecosystem.into(),
        name: name.to_string(),
        version: field(stanza, "Version:").unwrap_or_default(),
        author: field(stanza, "Maintainer:").map(|m| strip_email(&m)),
        // The control `Description` is a one-line synopsis then folded lines.
        description: field(stanza, "Description:"),
        homepage: field(stanza, "Homepage:"),
        ..Default::default()
    })
}

// --- RPM (openSUSE, RPM Fusion) ---------------------------------------------

/// Resolve `repomd.xml` to the `primary.xml` location, fetch and decompress it
/// (by its `.zst`/`.gz`/`.xz` suffix), and scan it for the package.
fn rpm_repo_lookup(
    base: &str,
    name: &str,
    ecosystem: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Option<Registry> {
    let repomd = cached_metadata(&format!("{base}/repodata/repomd.xml"), net, cache)?;
    let href = primary_href(std::str::from_utf8(&repomd).ok()?)?;
    let bytes = cached_metadata(&format!("{base}/{href}"), net, cache)?;
    let reader: Box<dyn Read> = match href.rsplit('.').next()? {
        "zst" => Box::new(zstd::stream::read::Decoder::new(Cursor::new(bytes)).ok()?),
        "gz" => Box::new(gunzip(bytes)),
        "xz" => Box::new(Cursor::new(unxz(bytes)?)),
        _ => return None,
    };
    each_xml_package(reader.take(DECOMP_CAP), |pkg| {
        rpm_primary_record(pkg, name, ecosystem)
    })
}

/// The `<location href="…primary.xml.*"/>` from `repomd.xml`.
fn primary_href(xml: &str) -> Option<String> {
    let data = xml
        .split("<data ")
        .find(|d| d.starts_with("type=\"primary\""))?;
    let anchor = "href=\"";
    let start = data.find(anchor)? + anchor.len();
    let rest = &data[start..];
    Some(rest[..rest.find('"')?].to_string())
}

/// Map one matching `<package>` element from `primary.xml`.
fn rpm_primary_record(pkg: &str, name: &str, ecosystem: &str) -> Option<Registry> {
    if tag_text(pkg, "name").as_deref() != Some(name) {
        return None;
    }
    // `<version epoch="0" ver="8.5.0" rel="1.2"/>`
    let version = attr(pkg, "<version", "ver")
        .map(|ver| match attr(pkg, "<version", "rel") {
            Some(rel) => format!("{ver}-{rel}"),
            None => ver,
        })
        .unwrap_or_default();
    Some(Registry {
        ecosystem: ecosystem.into(),
        name: name.to_string(),
        version,
        // `<time file="…" build="…"/>` — build is Unix seconds (0 = unset).
        published_at: attr(pkg, "<time", "build")
            .and_then(|b| b.parse::<u64>().ok())
            .filter(|&t| t > 0),
        author: tag_text(pkg, "rpm:vendor").or_else(|| tag_text(pkg, "packager")),
        description: tag_text(pkg, "summary"),
        homepage: tag_text(pkg, "url"),
        license: tag_text(pkg, "rpm:license"),
        ..Default::default()
    })
}

// --- NetBSD / FreeBSD / OpenBSD ---------------------------------------------

/// Map one matching `pkg_summary` stanza (`KEY=value`). `PKGNAME` is
/// `name-version`, so the version is the tail after `name-`.
fn pkg_summary_record(stanza: &str, name: &str) -> Option<Registry> {
    let pkgname = field(stanza, "PKGNAME=")?;
    let version = pkgname.strip_prefix(name)?.strip_prefix('-')?.to_string();
    Some(Registry {
        ecosystem: "netbsd".into(),
        name: name.to_string(),
        version,
        published_at: field(stanza, "BUILD_DATE=").and_then(|d| parse_ts(&d)),
        author: field(stanza, "MAINTAINER=").map(|m| strip_email(&m)),
        description: field(stanza, "COMMENT="),
        homepage: field(stanza, "HOMEPAGE="),
        license: field(stanza, "LICENSE="),
        ..Default::default()
    })
}

/// Map one FreeBSD `packagesite.yaml` object.
fn packagesite_record(o: &Value, name: &str) -> Registry {
    Registry {
        ecosystem: "freebsd".into(),
        name: name.to_string(),
        version: o
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        author: o.get("maintainer").and_then(Value::as_str).map(strip_email),
        description: o.get("comment").and_then(Value::as_str).map(str::to_string),
        homepage: o.get("www").and_then(Value::as_str).map(str::to_string),
        license: o
            .pointer("/licenses/0")
            .and_then(Value::as_str)
            .map(str::to_string),
        ..Default::default()
    }
}

/// The version of `name` from an OpenBSD packages `index.txt` (ls-style lines
/// ending in `<name>-<version>.tgz`).
fn openbsd_version(listing: &str, name: &str) -> Option<String> {
    let prefix = format!("{name}-");
    listing.split_whitespace().find_map(|tok| {
        let file = tok.rsplit('/').next().unwrap_or(tok);
        let stem = file.strip_suffix(".tgz")?.strip_prefix(&prefix)?;
        // A version starts with a digit, so `foo-2.0` matches but `foo-bar` (a
        // different package sharing the prefix) does not.
        stem.starts_with(|c: char| c.is_ascii_digit())
            .then(|| stem.to_string())
    })
}

// --- decompression + archive helpers ----------------------------------------

/// A streaming gzip reader over owned compressed `bytes`, capped against a bomb.
/// A non-gzip body surfaces as a read error when the scanner pulls from it.
fn gunzip(bytes: Vec<u8>) -> impl Read {
    flate2::read::MultiGzDecoder::new(Cursor::new(bytes)).take(DECOMP_CAP)
}

/// Fully decompress a zstd stream into a capped buffer (FreeBSD's catalog),
/// bounded against a bomb by `DECOMP_CAP`.
fn unzstd(bytes: Vec<u8>) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    zstd::stream::read::Decoder::new(Cursor::new(bytes))
        .ok()?
        .take(DECOMP_CAP)
        .read_to_end(&mut out)
        .ok()?;
    Some(out)
}

/// Fully decompress an xz stream into a capped buffer (lzma-rs has no streaming
/// reader; an `.xz` primary index is bounded by `DECOMP_CAP`).
fn unxz(bytes: Vec<u8>) -> Option<Vec<u8>> {
    let mut sink = CappedSink {
        buf: Vec::new(),
        cap: DECOMP_CAP as usize,
    };
    lzma_rs::xz_decompress(&mut Cursor::new(bytes), &mut sink).ok()?;
    Some(sink.buf)
}

/// A `Write` that refuses to grow past `cap`, bounding a decompression bomb.
struct CappedSink {
    buf: Vec<u8>,
    cap: usize,
}

impl Write for CappedSink {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.buf.len() + data.len() > self.cap {
            return Err(std::io::Error::other("decompressed output exceeds cap"));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Find a member by exact name (or `…/name`) in an uncompressed POSIX/ustar tar,
/// transparently spanning the concatenated archives an `APKINDEX` packs.
fn tar_find(data: &[u8], member: &str) -> Option<Vec<u8>> {
    let mut pos = 0;
    while pos + 512 <= data.len() {
        let header = &data[pos..pos + 512];
        let name_len = header[..100].iter().position(|&b| b == 0).unwrap_or(100);
        let name = std::str::from_utf8(&header[..name_len]).unwrap_or("");
        if name.is_empty() {
            pos += 512; // zero block: end-of-archive padding between streams
            continue;
        }
        // The size is attacker-supplied, so narrow it by `try_from` rather than
        // `as`: on a 32-bit target a declared size above `usize::MAX` would
        // otherwise wrap to a small one and walk the archive off its real frame.
        let size = usize::try_from(octal(&header[124..136])?).ok()?;
        let start = pos + 512;
        let end = start.checked_add(size)?;
        if end > data.len() {
            return None;
        }
        if name == member || name.ends_with(&format!("/{member}")) {
            return Some(data[start..end].to_vec());
        }
        pos = start + size.div_ceil(512) * 512;
    }
    None
}

/// Parse a tar header's space/NUL-padded octal numeric field.
fn octal(field: &[u8]) -> Option<u64> {
    let s = std::str::from_utf8(field)
        .ok()?
        .trim_matches(|c| c == ' ' || c == '\0');
    u64::from_str_radix(s, 8).ok()
}

// --- index scanners ---------------------------------------------------------

/// Stream `reader` and hand each blank-line-delimited stanza to `f` until it
/// returns `Some` (early exit). Holds at most one stanza, so a 100 MiB index is
/// scanned in constant memory.
fn each_stanza<R: BufRead, T>(reader: R, mut f: impl FnMut(&str) -> Option<T>) -> Option<T> {
    let mut stanza = String::new();
    for line in reader.lines() {
        let line = line.ok()?;
        if line.is_empty() {
            if !stanza.is_empty() {
                if let Some(t) = f(&stanza) {
                    return Some(t);
                }
                stanza.clear();
            }
        } else {
            stanza.push_str(&line);
            stanza.push('\n');
        }
    }
    (!stanza.is_empty()).then(|| f(&stanza)).flatten()
}

/// Stream `reader`, isolating each `<package …>…</package>` element and handing
/// its text to `f` until it returns `Some`. Buffers at most one element plus a
/// read chunk, so a multi-hundred-MiB `primary.xml` is scanned without holding
/// it whole.
fn each_xml_package<R: Read, T>(mut reader: R, mut f: impl FnMut(&str) -> Option<T>) -> Option<T> {
    const OPEN: &[u8] = b"<package";
    const CLOSE: &[u8] = b"</package>";
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; XML_CHUNK];
    loop {
        let n = reader.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        loop {
            let Some(start) = find_sub(&buf, OPEN) else {
                // No element start yet; keep only a possible partial `<package`.
                let keep = OPEN.len().saturating_sub(1).min(buf.len());
                buf.drain(..buf.len() - keep);
                break;
            };
            // Drop anything before the element to bound memory.
            buf.drain(..start);
            let Some(rel) = find_sub(&buf, CLOSE) else {
                break; // element not yet complete; read more
            };
            let end = rel + CLOSE.len();
            if let Ok(text) = std::str::from_utf8(&buf[..end])
                && let Some(t) = f(text)
            {
                return Some(t);
            }
            buf.drain(..end);
        }
    }
}

/// Byte-substring search (indices), small-needle naive scan.
fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

// --- field extraction -------------------------------------------------------

/// The value of the first line beginning `prefix` (`Package:`, `P:`, `KEY=`),
/// trimmed. A folded/continuation line (the only other place the prefix could
/// reappear) starts with whitespace, so it never shadows the real field.
fn field(stanza: &str, prefix: &str) -> Option<String> {
    stanza
        .lines()
        .find_map(|l| l.strip_prefix(prefix))
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// The text of the first `<tag>…</tag>` (no attributes assumed on the open tag).
fn tag_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let start = xml.find(&open)? + open.len();
    let rest = &xml[start..];
    let end = rest.find(&format!("</{tag}>"))?;
    Some(unescape_xml(rest[..end].trim()))
}

/// The value of attribute `attr` on the element opening with `open` (e.g.
/// `attr(pkg, "<version", "ver")`).
fn attr(xml: &str, open: &str, attr: &str) -> Option<String> {
    let tag_start = xml.find(open)?;
    let tag = &xml[tag_start..xml[tag_start..].find('>')? + tag_start];
    let anchor = format!("{attr}=\"");
    let start = tag.find(&anchor)? + anchor.len();
    let rest = &tag[start..];
    Some(rest[..rest.find('"')?].to_string())
}

/// Decode the five predefined XML entities a primary.xml summary may carry.
fn unescape_xml(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn apkindex_record_maps_fields() {
        let stanza = "C:Q1xxx\nP:curl\nV:8.5.0-r0\nA:x86_64\n\
                      T:URL retrieval utility\nU:https://curl.se/\nL:curl\n\
                      m:Nat <nat@example.test>\nt:1619172000\no:curl\n";
        let r = apkindex_record(stanza, "curl", "alpine").expect("record");
        assert_eq!(r.ecosystem, "alpine");
        assert_eq!(r.version, "8.5.0-r0");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(r.author.as_deref(), Some("Nat"));
        assert_eq!(r.homepage.as_deref(), Some("https://curl.se/"));
        assert_eq!(r.license.as_deref(), Some("curl"));
        // A non-matching name in the same stanza shape yields nothing.
        assert!(apkindex_record(stanza, "wget", "alpine").is_none());
    }

    #[test]
    fn deb_record_maps_fields() {
        let stanza = "Package: nginx\nVersion: 1.24.0-1\n\
                      Maintainer: Debian Nginx <pkg-nginx@lists.debian.test>\n\
                      Homepage: https://nginx.org\n\
                      Description: small web server\n more text here\n";
        let r = deb_record(stanza, "nginx", "debian").expect("record");
        assert_eq!(r.version, "1.24.0-1");
        assert_eq!(r.author.as_deref(), Some("Debian Nginx"));
        assert_eq!(r.homepage.as_deref(), Some("https://nginx.org"));
        assert_eq!(r.description.as_deref(), Some("small web server"));
        assert_eq!(r.published_at, None);
    }

    #[test]
    fn rpm_primary_record_maps_fields() {
        let pkg = r#"<package type="rpm"><name>curl</name><arch>x86_64</arch>
            <version epoch="0" ver="8.5.0" rel="1.2"/>
            <summary>A tool for transferring data</summary>
            <url>https://curl.se/</url>
            <time file="1619172000" build="1619172000"/>
            <format><rpm:license>MIT</rpm:license><rpm:vendor>openSUSE</rpm:vendor></format>
            </package>"#;
        let r = rpm_primary_record(pkg, "curl", "opensuse").expect("record");
        assert_eq!(r.version, "8.5.0-1.2");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(r.license.as_deref(), Some("MIT"));
        assert_eq!(r.author.as_deref(), Some("openSUSE"));
        assert_eq!(r.homepage.as_deref(), Some("https://curl.se/"));
    }

    #[test]
    fn primary_href_picks_primary() {
        let xml = r#"<repomd><data type="filelists"><location href="repodata/a-filelists.xml.gz"/></data>
            <data type="primary"><location href="repodata/b-primary.xml.zst"/></data></repomd>"#;
        assert_eq!(
            primary_href(xml).as_deref(),
            Some("repodata/b-primary.xml.zst")
        );
    }

    #[test]
    fn pkg_summary_record_extracts_version() {
        let stanza = "PKGNAME=curl-8.5.0\nCOMMENT=Client for URLs\n\
                      HOMEPAGE=https://curl.se/\nLICENSE=mit\n\
                      MAINTAINER=pkgsrc <pkgsrc@example.test>\n\
                      BUILD_DATE=2021-04-23 10:00:00 +0000\n";
        let r = pkg_summary_record(stanza, "curl").expect("record");
        assert_eq!(r.ecosystem, "netbsd");
        assert_eq!(r.version, "8.5.0");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(r.description.as_deref(), Some("Client for URLs"));
        assert_eq!(r.author.as_deref(), Some("pkgsrc"));
        // A different package sharing no prefix must not match.
        assert!(pkg_summary_record(stanza, "wget").is_none());
    }

    #[test]
    fn packagesite_record_maps_fields() {
        let o = serde_json::json!({
            "name": "curl", "version": "8.5.0", "comment": "URL transfer tool",
            "www": "https://curl.se/", "maintainer": "ports@freebsd.test",
            "licenses": ["MIT"]
        });
        let r = packagesite_record(&o, "curl");
        assert_eq!(r.ecosystem, "freebsd");
        assert_eq!(r.version, "8.5.0");
        assert_eq!(r.homepage.as_deref(), Some("https://curl.se/"));
        assert_eq!(r.license.as_deref(), Some("MIT"));
    }

    #[test]
    fn openbsd_version_from_listing() {
        // The real index.txt is an `ls -l` listing; the filename is the last
        // whitespace-separated token.
        let listing = "-rw-r--r--  1 0  0  2560218 Jun 23 15:16:56 2026 curl-8.20.0.tgz\n\
                       -rw-r--r--  1 0  0  3120044 Jun 23 15:16:57 2026 curl-http3-8.20.0.tgz\n\
                       -rw-r--r--  1 0  0   450112 Jun 23 15:17:01 2026 wget-1.21.4.tgz\n";
        assert_eq!(openbsd_version(listing, "curl").as_deref(), Some("8.20.0"));
        assert_eq!(openbsd_version(listing, "wget").as_deref(), Some("1.21.4"));
        assert!(openbsd_version(listing, "nginx").is_none());
    }

    #[test]
    fn each_stanza_streams_and_early_exits() {
        let text = "Package: a\nVersion: 1\n\nPackage: b\nVersion: 2\n\nPackage: c\nVersion: 3\n";
        let got = each_stanza(BufReader::new(Cursor::new(text)), |s| {
            deb_record(s, "b", "debian")
        })
        .expect("found b");
        assert_eq!(got.version, "2");
    }

    #[test]
    fn each_xml_package_isolates_elements() {
        let xml = "<metadata><package><name>a</name><version ver=\"1\"/></package>\
                   <package><name>curl</name><version ver=\"9\"/>\
                   <url>https://curl.se/</url></package></metadata>";
        let r = each_xml_package(Cursor::new(xml), |p| {
            rpm_primary_record(p, "curl", "opensuse")
        })
        .expect("found curl");
        assert_eq!(r.version, "9");
        assert_eq!(r.homepage.as_deref(), Some("https://curl.se/"));
    }

    #[test]
    fn gunzip_and_tar_find_round_trip() {
        // Build a tiny gzip of a one-member tar and read the member back.
        let mut tar = Vec::new();
        let mut header = [0u8; 512];
        header[..8].copy_from_slice(b"APKINDEX");
        // size field (octal) at 124..136: 5 bytes of payload "hello".
        header[124..124 + 7].copy_from_slice(b"0000005");
        tar.extend_from_slice(&header);
        tar.extend_from_slice(b"hello");
        tar.resize(512 + 512, 0); // pad payload block
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(&tar).unwrap();
        let gz = enc.finish().unwrap();

        let mut out = Vec::new();
        flate2::read::MultiGzDecoder::new(Cursor::new(gz))
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(tar_find(&out, "APKINDEX").as_deref(), Some(&b"hello"[..]));
    }

    #[test]
    fn capped_sink_rejects_overflow() {
        let mut sink = CappedSink {
            buf: Vec::new(),
            cap: 4,
        };
        assert!(sink.write_all(b"ok").is_ok());
        assert!(sink.write_all(b"too much").is_err());
    }
}
