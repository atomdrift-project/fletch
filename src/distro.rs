//! OS-distro package registries whose metadata lives in a *compressed index or
//! catalog* rather than a per-package JSON API — the half of
//! [`registry`](mod@crate::registry) that needs decompression and index parsing.
//!
//! Each ecosystem publishes one large index per repository: Alpine and Wolfi an
//! `APKINDEX.tar.gz`, Debian and Ubuntu a `Packages.gz`, openSUSE and RPM Fusion
//! a `repomd.xml` → `primary.xml.{zst,gz,xz}`, NetBSD a `pkg_summary.gz`,
//! FreeBSD a `packagesite.pkg` (tar.xz). We fetch the index through the blob
//! cache (so the multi-megabyte download is paid once per cache window), stream
//! it through a decompressor stanza by stanza — never holding the whole
//! decompressed index — and keep a compact listing of every package, so the
//! next lookup against the same index is a map read (see [`PARSED`]).
//!
//! An unreachable mirror, an absent package, or a moved index layout is an
//! error saying which. The repository coordinates (release, architecture) are
//! pinned to current defaults below; they track the distributions over time
//! exactly as the upstream index URLs do.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Cursor, Read};
use std::sync::{Arc, Mutex, PoisonError};

use filefacts::Registry;
use serde::Deserialize;

use crate::ecosystem::{parse_ts, strip_email};
use crate::fetch::{BlobCache, Fetch, cached_metadata_status, sha256_hex};
use crate::registry::RegistryError;

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
pub(crate) fn alpine(
    name: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    const REPOS: [&str; 2] = [
        "https://dl-cdn.alpinelinux.org/alpine/latest-stable/main/x86_64/APKINDEX.tar.gz",
        "https://dl-cdn.alpinelinux.org/alpine/latest-stable/community/x86_64/APKINDEX.tar.gz",
    ];
    first_listing(&REPOS, |url| {
        lookup(url, parse_apkindex, name, "alpine", net, cache)
    })
}

/// Wolfi (Chainguard's distroless base): a single rolling `APKINDEX`, same
/// format as Alpine.
pub(crate) fn wolfi(
    name: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    lookup(
        "https://packages.wolfi.dev/os/x86_64/APKINDEX.tar.gz",
        parse_apkindex,
        name,
        "wolfi",
        net,
        cache,
    )
}

/// Debian: the `stable/main` binary `Packages` index. It carries the maintainer,
/// description, and homepage but no upload time, so age stays unknown.
pub(crate) fn debian(
    name: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    lookup(
        "https://deb.debian.org/debian/dists/stable/main/binary-amd64/Packages.gz",
        parse_packages,
        name,
        "debian",
        net,
        cache,
    )
}

/// Ubuntu: the current LTS `main` then `universe` binary `Packages` index, same
/// control format as Debian.
pub(crate) fn ubuntu(
    name: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    const REPOS: [&str; 2] = [
        "https://archive.ubuntu.com/ubuntu/dists/noble/main/binary-amd64/Packages.gz",
        "https://archive.ubuntu.com/ubuntu/dists/noble/universe/binary-amd64/Packages.gz",
    ];
    first_listing(&REPOS, |url| {
        lookup(url, parse_packages, name, "ubuntu", net, cache)
    })
}

/// openSUSE Tumbleweed (`oss` repo): the `primary.xml` referenced by `repomd.xml`
/// carries the summary, license, homepage, and a build time.
pub(crate) fn opensuse(
    name: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
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
pub(crate) fn rpmfusion(
    name: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
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
pub(crate) fn netbsd(
    name: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    lookup(
        "https://cdn.netbsd.org/pub/pkgsrc/packages/NetBSD/x86_64/10.0/All/pkg_summary.gz",
        parse_pkg_summary,
        name,
        "netbsd",
        net,
        cache,
    )
}

/// FreeBSD (binary pkg): `packagesite.pkg` is a zstd-compressed tar whose
/// `packagesite.yaml` is newline-delimited JSON, one object per package, with
/// the comment, maintainer, homepage (`www`), and licenses.
pub(crate) fn freebsd(
    name: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    lookup(
        "https://pkg.freebsd.org/FreeBSD:14:amd64/latest/packagesite.pkg",
        parse_packagesite,
        name,
        "freebsd",
        net,
        cache,
    )
}

/// OpenBSD: there is no metadata index — only the packages directory listing —
/// so this recovers just the current version from the published filenames. The
/// `snapshots` tree always reflects the live package set (a numbered release is
/// frozen and eventually pruned).
pub(crate) fn openbsd(
    name: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    const URL: &str = "https://cdn.openbsd.org/pub/OpenBSD/snapshots/packages/amd64/index.txt";
    let bytes = index(URL, net, cache)?;
    let text = std::str::from_utf8(&bytes).map_err(|e| unreadable(URL, e))?;
    let version = openbsd_version(text, name).ok_or(RegistryError::NotFound)?;
    Ok(Registry {
        ecosystem: "openbsd".into(),
        name: name.to_string(),
        version,
        ..Default::default()
    })
}

// --- parsed indexes ---------------------------------------------------------

/// One package's facts from an index, kept small: a parsed Debian index holds
/// some sixty thousand.
#[derive(Debug, Default)]
struct Listing {
    version: Box<str>,
    published_at: Option<u64>,
    author: Option<Box<str>>,
    description: Option<Box<str>>,
    homepage: Option<Box<str>>,
    license: Option<Box<str>>,
}

impl Listing {
    /// The registry record of package `name` in `ecosystem`.
    fn record(&self, ecosystem: &str, name: &str) -> Registry {
        let text = |s: &Option<Box<str>>| s.as_deref().map(str::to_string);
        Registry {
            ecosystem: ecosystem.into(),
            name: name.to_string(),
            version: self.version.to_string(),
            published_at: self.published_at,
            author: text(&self.author),
            description: text(&self.description),
            homepage: text(&self.homepage),
            license: text(&self.license),
            ..Default::default()
        }
    }
}

/// An index's packages by name. Where an index lists a name twice, the first
/// listing stands.
type Listings = HashMap<Box<str>, Listing>;

/// Reads an index's bytes, fetched from `url`, into its listings.
type Parser = fn(&str, Vec<u8>) -> Result<Listings, RegistryError>;

/// The indexes this process parsed most recently, newest first, keyed by URL
/// and by the digest of the bytes parsed. A burst of lookups against one index
/// — a Dockerfile's `apt-get install` line — decompresses and parses it once,
/// and an index the cache has refreshed is parsed afresh. Only a few are kept:
/// a parsed Debian or Ubuntu `universe` index is some 17 MB, openSUSE's 13 MB.
static PARSED: Mutex<Vec<Parsed>> = Mutex::new(Vec::new());

/// How many parsed indexes [`PARSED`] keeps.
const PARSED_KEEP: usize = 4;

struct Parsed {
    url: String,
    digest: String,
    listings: Arc<Listings>,
}

/// Package `name`'s record from the index at `url`, read by `parse`.
fn lookup(
    url: &str,
    parse: Parser,
    name: &str,
    ecosystem: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    // Fetched on every lookup, parsed only when new: the fetch is what keeps
    // the index fresh and records it as a source.
    let bytes = index(url, net, cache)?;
    let digest = sha256_hex(&bytes);
    // Held across the parse, so lookups racing on one index wait for a single
    // parse instead of each repeating it.
    let mut parsed = PARSED.lock().unwrap_or_else(PoisonError::into_inner);
    let entry = match parsed
        .iter()
        .position(|p| p.url == url && p.digest == digest)
    {
        Some(i) => parsed.remove(i),
        None => Parsed {
            url: url.to_string(),
            digest,
            listings: Arc::new(parse(url, bytes)?),
        },
    };
    let listings = Arc::clone(&entry.listings);
    parsed.insert(0, entry);
    parsed.truncate(PARSED_KEEP);
    drop(parsed);
    listings
        .get(name)
        .map(|listing| listing.record(ecosystem, name))
        .ok_or(RegistryError::NotFound)
}

/// Every listing in the stanzas of `reader`.
fn stanza_listings<R: BufRead>(
    url: &str,
    reader: R,
    listing: fn(&str) -> Option<(Box<str>, Listing)>,
) -> Result<Listings, RegistryError> {
    let mut listings = Listings::new();
    stanzas(reader, |stanza| {
        if let Some((name, found)) = listing(stanza) {
            listings.entry(name).or_insert(found);
        }
    })
    .map_err(|e| unreadable(url, e))?;
    Ok(listings)
}

// --- APK (Alpine, Wolfi) ----------------------------------------------------

/// An `APKINDEX.tar.gz`: a signature stream and the control stream, gzipped
/// back to back, whose `APKINDEX` member holds `K:value` stanzas.
fn parse_apkindex(url: &str, bytes: Vec<u8>) -> Result<Listings, RegistryError> {
    let mut out = Vec::new();
    flate2::read::MultiGzDecoder::new(Cursor::new(bytes))
        .take(DECOMP_CAP)
        .read_to_end(&mut out)
        .map_err(|e| unreadable(url, e))?;
    let apkindex = tar_find(&out, "APKINDEX").ok_or_else(|| unreadable(url, "no APKINDEX"))?;
    stanza_listings(url, Cursor::new(apkindex), apkindex_listing)
}

/// One `APKINDEX` stanza (single-letter `K:value` lines).
fn apkindex_listing(stanza: &str) -> Option<(Box<str>, Listing)> {
    let name = field(stanza, "P:")?;
    Some((
        name.into(),
        Listing {
            version: field(stanza, "V:").unwrap_or_default().into(),
            // `t:0` is a "build time unset" sentinel (reproducible builds), not
            // a 1970 publish — treat it as unknown.
            published_at: field(stanza, "t:")
                .and_then(|t| t.parse::<u64>().ok())
                .filter(|&t| t > 0),
            author: field(stanza, "m:").map(|m| strip_email(&m).into()),
            description: field(stanza, "T:").map(Into::into),
            homepage: field(stanza, "U:").map(Into::into),
            license: field(stanza, "L:").map(Into::into),
        },
    ))
}

// --- Debian / Ubuntu (control format) ---------------------------------------

/// A gzip `Packages` index of control stanzas.
fn parse_packages(url: &str, bytes: Vec<u8>) -> Result<Listings, RegistryError> {
    stanza_listings(url, BufReader::new(gunzip(bytes)), deb_listing)
}

/// One Debian control stanza (`Key: value`, with folded continuation lines
/// for multi-line descriptions).
fn deb_listing(stanza: &str) -> Option<(Box<str>, Listing)> {
    let name = field(stanza, "Package:")?;
    Some((
        name.into(),
        Listing {
            version: field(stanza, "Version:").unwrap_or_default().into(),
            author: field(stanza, "Maintainer:").map(|m| strip_email(&m).into()),
            // The control `Description` is a one-line synopsis then folded lines.
            description: field(stanza, "Description:").map(Into::into),
            homepage: field(stanza, "Homepage:").map(Into::into),
            ..Default::default()
        },
    ))
}

// --- RPM (openSUSE, RPM Fusion) ---------------------------------------------

/// Resolve `repomd.xml` to the `primary.xml` location and look the package up
/// there.
fn rpm_repo_lookup(
    base: &str,
    name: &str,
    ecosystem: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let repomd_url = format!("{base}/repodata/repomd.xml");
    let repomd = index(&repomd_url, net, cache)?;
    let href = std::str::from_utf8(&repomd)
        .ok()
        .and_then(primary_href)
        .ok_or_else(|| unreadable(&repomd_url, "no primary index"))?;
    lookup(
        &format!("{base}/{href}"),
        parse_primary,
        name,
        ecosystem,
        net,
        cache,
    )
}

/// A `primary.xml`, compressed as its `.zst`/`.gz`/`.xz` suffix says.
fn parse_primary(url: &str, bytes: Vec<u8>) -> Result<Listings, RegistryError> {
    let reader: Box<dyn Read> = match url.rsplit('.').next() {
        Some("zst") => Box::new(
            zstd::stream::read::Decoder::new(Cursor::new(bytes)).map_err(|e| unreadable(url, e))?,
        ),
        Some("gz") => Box::new(gunzip(bytes)),
        Some("xz") => Box::new(xz2::read::XzDecoder::new_multi_decoder(Cursor::new(bytes))),
        _ => return Err(unreadable(url, "unknown compression")),
    };
    let mut listings = Listings::new();
    xml_packages(reader.take(DECOMP_CAP), |pkg| {
        if let Some((name, found)) = rpm_listing(pkg) {
            listings.entry(name).or_insert(found);
        }
    })
    .map_err(|e| unreadable(url, e))?;
    Ok(listings)
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

/// One `<package>` element of `primary.xml`.
fn rpm_listing(pkg: &str) -> Option<(Box<str>, Listing)> {
    let name = tag_text(pkg, "name")?;
    // `<version epoch="0" ver="8.5.0" rel="1.2"/>`
    let version = attr(pkg, "<version", "ver")
        .map(|ver| match attr(pkg, "<version", "rel") {
            Some(rel) => format!("{ver}-{rel}"),
            None => ver,
        })
        .unwrap_or_default();
    Some((
        name.into(),
        Listing {
            version: version.into(),
            // `<time file="…" build="…"/>` — build is Unix seconds (0 = unset).
            published_at: attr(pkg, "<time", "build")
                .and_then(|b| b.parse::<u64>().ok())
                .filter(|&t| t > 0),
            author: tag_text(pkg, "rpm:vendor")
                .or_else(|| tag_text(pkg, "packager"))
                .map(Into::into),
            description: tag_text(pkg, "summary").map(Into::into),
            homepage: tag_text(pkg, "url").map(Into::into),
            license: tag_text(pkg, "rpm:license").map(Into::into),
        },
    ))
}

// --- NetBSD / FreeBSD / OpenBSD ---------------------------------------------

/// A gzip `pkg_summary` of `KEY=value` stanzas.
fn parse_pkg_summary(url: &str, bytes: Vec<u8>) -> Result<Listings, RegistryError> {
    stanza_listings(url, BufReader::new(gunzip(bytes)), pkg_summary_listing)
}

/// One `pkg_summary` stanza. `PKGNAME` is `name-version`, and a pkgsrc version
/// never contains a hyphen (revisions are `nbN`), so the version is everything
/// after the *last* one. Splitting there rather than after `name-` keeps `git`
/// from matching `git-base-2.45.2`.
fn pkg_summary_listing(stanza: &str) -> Option<(Box<str>, Listing)> {
    let pkgname = field(stanza, "PKGNAME=")?;
    let (name, version) = pkgname.rsplit_once('-')?;
    Some((
        name.into(),
        Listing {
            version: version.into(),
            published_at: field(stanza, "BUILD_DATE=").and_then(|d| parse_ts(&d)),
            author: field(stanza, "MAINTAINER=").map(|m| strip_email(&m).into()),
            description: field(stanza, "COMMENT=").map(Into::into),
            homepage: field(stanza, "HOMEPAGE=").map(Into::into),
            license: field(stanza, "LICENSE=").map(Into::into),
        },
    ))
}

/// A zstd `packagesite.pkg` tar, whose `packagesite.yaml` is one JSON object
/// per line. Streamed from the archive line by line: decompressed whole, the
/// catalog is over a hundred megabytes.
fn parse_packagesite(url: &str, bytes: Vec<u8>) -> Result<Listings, RegistryError> {
    let decoder =
        zstd::stream::read::Decoder::new(Cursor::new(bytes)).map_err(|e| unreadable(url, e))?;
    let mut archive = tar::Archive::new(decoder.take(DECOMP_CAP));
    for entry in archive.entries().map_err(|e| unreadable(url, e))? {
        let entry = entry.map_err(|e| unreadable(url, e))?;
        if !entry.path_bytes().ends_with(b"packagesite.yaml") {
            continue;
        }
        let mut listings = Listings::new();
        let mut yaml = BufReader::new(entry);
        let mut line = Vec::new();
        while yaml
            .read_until(b'\n', &mut line)
            .map_err(|e| unreadable(url, e))?
            > 0
        {
            if let Some((name, found)) = serde_json::from_slice::<Packagesite>(&line)
                .ok()
                .and_then(packagesite_listing)
            {
                listings.entry(name).or_insert(found);
            }
            line.clear();
        }
        return Ok(listings);
    }
    Err(unreadable(url, "no packagesite.yaml"))
}

/// One package in FreeBSD's `packagesite.yaml`, as far as the record reads it.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Packagesite {
    name: Option<String>,
    version: Option<String>,
    maintainer: Option<String>,
    comment: Option<String>,
    www: Option<String>,
    licenses: Option<Vec<String>>,
}

/// One FreeBSD `packagesite.yaml` object.
fn packagesite_listing(p: Packagesite) -> Option<(Box<str>, Listing)> {
    Some((
        p.name?.into(),
        Listing {
            version: p.version.unwrap_or_default().into(),
            author: p.maintainer.as_deref().map(|m| strip_email(m).into()),
            description: p.comment.map(Into::into),
            homepage: p.www.map(Into::into),
            license: p
                .licenses
                .and_then(|l| l.into_iter().next())
                .map(Into::into),
            ..Default::default()
        },
    ))
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
        // The field is space/NUL-padded octal.
        let size = std::str::from_utf8(&header[124..136])
            .ok()?
            .trim_matches(|c| c == ' ' || c == '\0');
        let size = usize::try_from(u64::from_str_radix(size, 8).ok()?).ok()?;
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

/// Fetch an index document through the metadata cache.
fn index(url: &str, net: &dyn Fetch, cache: &BlobCache) -> Result<Vec<u8>, RegistryError> {
    Ok(cached_metadata_status(url, &[], net, cache)?)
}

/// The index at `url` arrived but could not be read as one.
fn unreadable(url: &str, reason: impl std::fmt::Display) -> RegistryError {
    RegistryError::Malformed {
        url: url.to_string(),
        reason: reason.to_string(),
    }
}

/// The first of `repos` that lists the package, in order. When none does, a
/// repository that could not be read says more than "not found".
fn first_listing(
    repos: &[&str],
    lookup: impl Fn(&str) -> Result<Registry, RegistryError>,
) -> Result<Registry, RegistryError> {
    let mut why = RegistryError::NotFound;
    for repo in repos {
        match lookup(repo) {
            Ok(record) => return Ok(record),
            Err(RegistryError::NotFound) => {}
            Err(error) => why = error,
        }
    }
    Err(why)
}

// --- index scanners ---------------------------------------------------------

/// Stream `reader` and hand each blank-line-delimited stanza to `f`, holding
/// at most one stanza, so a 100 MiB index is read in constant memory. A line
/// that is not UTF-8 is read lossily: one stray byte must not cost the index.
fn stanzas<R: BufRead>(mut reader: R, mut f: impl FnMut(&str)) -> std::io::Result<()> {
    let mut stanza = String::new();
    let mut line = Vec::new();
    loop {
        line.clear();
        let at_end = reader.read_until(b'\n', &mut line)? == 0;
        let text = String::from_utf8_lossy(&line);
        let text = text.trim_end_matches(['\n', '\r']);
        if text.is_empty() {
            if !stanza.is_empty() {
                f(&stanza);
                stanza.clear();
            }
            if at_end {
                return Ok(());
            }
        } else {
            stanza.push_str(text);
            stanza.push('\n');
        }
    }
}

/// Stream `reader`, isolating each `<package …>…</package>` element and handing
/// its text to `f`. Buffers at most one element plus a read chunk, so a
/// multi-hundred-MiB `primary.xml` is read without holding it whole.
fn xml_packages<R: Read>(mut reader: R, mut f: impl FnMut(&str)) -> std::io::Result<()> {
    const OPEN: &[u8] = b"<package";
    const CLOSE: &[u8] = b"</package>";
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; XML_CHUNK];
    loop {
        let n = reader.read(&mut chunk)?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
        // Hand over every complete element, then drop what has been handled
        // in one move rather than one per element.
        let mut done = 0;
        loop {
            let Some(start) = find_sub(&buf[done..], OPEN).map(|i| done + i) else {
                // Keep only what could be a `<package` split across reads.
                done = done.max(buf.len().saturating_sub(OPEN.len() - 1));
                break;
            };
            let Some(end) = find_sub(&buf[start..], CLOSE).map(|i| start + i + CLOSE.len()) else {
                done = start; // incomplete: read more
                break;
            };
            if let Ok(text) = std::str::from_utf8(&buf[start..end]) {
                f(text);
            }
            done = end;
        }
        buf.drain(..done);
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
mod tests {
    use super::*;
    use crate::fetch::Fixtures;
    use std::io::Write as _;

    #[test]
    fn apkindex_listing_maps_fields() {
        let stanza = "C:Q1xxx\nP:curl\nV:8.5.0-r0\nA:x86_64\n\
                      T:URL retrieval utility\nU:https://curl.se/\nL:curl\n\
                      m:Nat <nat@example.test>\nt:1619172000\no:curl\n";
        let (name, listing) = apkindex_listing(stanza).expect("listing");
        assert_eq!(&*name, "curl");
        let r = listing.record("alpine", &name);
        assert_eq!(r.ecosystem, "alpine");
        assert_eq!(r.version, "8.5.0-r0");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(r.author.as_deref(), Some("Nat"));
        assert_eq!(r.homepage.as_deref(), Some("https://curl.se/"));
        assert_eq!(r.license.as_deref(), Some("curl"));
    }

    #[test]
    fn deb_listing_maps_fields() {
        let stanza = "Package: nginx\nVersion: 1.24.0-1\n\
                      Maintainer: Debian Nginx <pkg-nginx@lists.debian.test>\n\
                      Homepage: https://nginx.org\n\
                      Description: small web server\n more text here\n";
        let (name, listing) = deb_listing(stanza).expect("listing");
        assert_eq!(&*name, "nginx");
        let r = listing.record("debian", &name);
        assert_eq!(r.version, "1.24.0-1");
        assert_eq!(r.author.as_deref(), Some("Debian Nginx"));
        assert_eq!(r.homepage.as_deref(), Some("https://nginx.org"));
        assert_eq!(r.description.as_deref(), Some("small web server"));
        assert_eq!(r.published_at, None);
    }

    #[test]
    fn rpm_listing_maps_fields() {
        let pkg = r#"<package type="rpm"><name>curl</name><arch>x86_64</arch>
            <version epoch="0" ver="8.5.0" rel="1.2"/>
            <summary>A tool for transferring data</summary>
            <url>https://curl.se/</url>
            <time file="1619172000" build="1619172000"/>
            <format><rpm:license>MIT</rpm:license><rpm:vendor>openSUSE</rpm:vendor></format>
            </package>"#;
        let (name, listing) = rpm_listing(pkg).expect("listing");
        assert_eq!(&*name, "curl");
        let r = listing.record("opensuse", &name);
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
    fn pkg_summary_listing_extracts_version() {
        let stanza = "PKGNAME=curl-8.5.0\nCOMMENT=Client for URLs\n\
                      HOMEPAGE=https://curl.se/\nLICENSE=mit\n\
                      MAINTAINER=pkgsrc <pkgsrc@example.test>\n\
                      BUILD_DATE=2021-04-23 10:00:00 +0000\n";
        let (name, listing) = pkg_summary_listing(stanza).expect("listing");
        assert_eq!(&*name, "curl");
        let r = listing.record("netbsd", &name);
        assert_eq!(r.ecosystem, "netbsd");
        assert_eq!(r.version, "8.5.0");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(r.description.as_deref(), Some("Client for URLs"));
        assert_eq!(r.author.as_deref(), Some("pkgsrc"));
        // A name that merely starts with another is its own package: `git`
        // must not claim `git-base`'s listing.
        let base = "PKGNAME=git-base-2.45.2nb1\nCOMMENT=GIT core\n";
        let (name, listing) = pkg_summary_listing(base).expect("listing");
        assert_eq!(&*name, "git-base");
        assert_eq!(&*listing.version, "2.45.2nb1");
    }

    #[test]
    fn packagesite_listing_maps_fields() {
        let o = serde_json::from_value(serde_json::json!({
            "name": "curl", "version": "8.5.0", "comment": "URL transfer tool",
            "www": "https://curl.se/", "maintainer": "ports@freebsd.test",
            "licenses": ["MIT"]
        }))
        .unwrap();
        let (name, listing) = packagesite_listing(o).expect("listing");
        assert_eq!(&*name, "curl");
        let r = listing.record("freebsd", &name);
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
    fn stanzas_are_read_one_at_a_time() {
        // A stray non-UTF-8 byte costs only its own line.
        let text = b"Package: a\nVersion: 1\n\nPackage: b\nDescription: caf\xe9\n\n\nPackage: c\n";
        let mut seen = Vec::new();
        stanzas(BufReader::new(Cursor::new(&text[..])), |s| {
            seen.push(field(s, "Package:"));
        })
        .expect("read");
        assert_eq!(seen, [Some("a".into()), Some("b".into()), Some("c".into())]);
    }

    /// A reader that hands out a few bytes at a time, so elements and markers
    /// straddle reads.
    struct Trickle<'a>(&'a [u8]);

    impl Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.0.len().min(buf.len()).min(5);
            buf[..n].copy_from_slice(&self.0[..n]);
            self.0 = &self.0[n..];
            Ok(n)
        }
    }

    #[test]
    fn xml_packages_isolates_elements_across_reads() {
        let xml = "<metadata><package><name>a</name><version ver=\"1\"/></package>\
                   <package><name>curl</name><version ver=\"9\"/>\
                   <url>https://curl.se/</url><packager>x</packager></package></metadata>";
        let mut names = Vec::new();
        xml_packages(Trickle(xml.as_bytes()), |p| names.push(tag_text(p, "name"))).expect("read");
        assert_eq!(names, [Some("a".into()), Some("curl".into())]);
    }

    /// An index is parsed once for any number of lookups, and again only when
    /// its bytes change.
    #[test]
    fn an_index_is_parsed_once_per_content() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static PARSES: AtomicUsize = AtomicUsize::new(0);
        fn counted(url: &str, bytes: Vec<u8>) -> Result<Listings, RegistryError> {
            PARSES.fetch_add(1, Ordering::SeqCst);
            stanza_listings(url, Cursor::new(bytes), deb_listing)
        }
        let url = "https://distro.test/parsed-once/Packages";
        let cache = BlobCache::disabled();
        let net =
            Fixtures::default().with(url, b"Package: a\nVersion: 1\n\nPackage: b\nVersion: 2\n");
        let version = |net: &Fixtures, name: &str| {
            lookup(url, counted, name, "debian", net, &cache).map(|r| r.version)
        };
        assert_eq!(version(&net, "a"), Ok("1".into()));
        assert_eq!(version(&net, "b"), Ok("2".into()));
        assert_eq!(version(&net, "z"), Err(RegistryError::NotFound));
        assert_eq!(PARSES.load(Ordering::SeqCst), 1);

        let refreshed = Fixtures::default().with(url, b"Package: a\nVersion: 3\n");
        assert_eq!(version(&refreshed, "a"), Ok("3".into()));
        assert_eq!(PARSES.load(Ordering::SeqCst), 2);
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
    fn an_xz_primary_index_is_read_like_the_other_codecs() {
        // The xz branch streams through the same `DECOMP_CAP`-bounded reader as
        // gzip and zstd.
        let primary = br#"<metadata><package type="rpm"><name>curl</name>
            <version epoch="0" ver="8.5.0" rel="1.2"/></package></metadata>"#;
        let mut xz = xz2::write::XzEncoder::new(Vec::new(), 6);
        xz.write_all(primary).unwrap();
        let xz = xz.finish().unwrap();
        let repomd = br#"<repomd><data type="primary"><location href="repodata/p-primary.xml.xz"/></data></repomd>"#;
        let net = crate::fetch::Fixtures::default()
            .with("https://repo.test/repodata/repomd.xml", repomd)
            .with("https://repo.test/repodata/p-primary.xml.xz", &xz);
        let r = rpm_repo_lookup(
            "https://repo.test",
            "curl",
            "opensuse",
            &net,
            &BlobCache::disabled(),
        )
        .expect("record");
        assert_eq!(r.version, "8.5.0-1.2");
    }
}
