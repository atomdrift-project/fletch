//! OS-distro package registries whose metadata lives in a *compressed index or
//! catalog* rather than a per-package JSON API — the half of
//! [`registry`](mod@crate::registry) that needs decompression and index parsing.
//!
//! Each ecosystem publishes one large index per repository: Alpine and Wolfi an
//! `APKINDEX.tar.gz`, Debian and Ubuntu a `Packages.gz`, openSUSE and RPM Fusion
//! a `repomd.xml` → `primary.xml.{zst,gz,xz}`, NetBSD a `pkg_summary.gz`,
//! FreeBSD a `packagesite.pkg` (a zstd-compressed tar). Each index is fetched
//! through the blob cache (so the multi-megabyte download is paid once per
//! cache window), streamed through a decompressor entry by entry — never
//! holding the whole decompressed index — and reduced to a compact listing of
//! every package, so the next lookup against the same index is a map read
//! (see [`PARSED`]).
//!
//! An unreachable mirror, an absent package, and an index that does not read
//! as its format are distinct errors: an index that yields no listings is
//! [`RegistryError::Malformed`], never a [`RegistryError::NotFound`] for every
//! package. The repository coordinates (release, architecture) are fixed below
//! to each distribution's current defaults.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::io::{BufRead, BufReader, Cursor, Read};
use std::sync::{Arc, LazyLock, Mutex, PoisonError};

use filefacts::{Ecosystem, Registry};
use serde::Deserialize;
use sha2::{Digest as _, Sha512};

use crate::ecosystem::{strip_email, unix_secs};
use crate::fetch::{BlobCache, Fetch, cached_metadata_status, sha256_hex};
use crate::registry::RegistryError;

// Ceilings on each index's *decompressed* size. The per-fetch download cap
// bounds the compressed input; these backstop a decompression bomb (a tiny
// input inflating without limit), whose CPU time and listings would otherwise
// be unbounded. Each sits at three times or more the largest real index of its
// format (sizes as published in October 2026). Exceeding one is an error,
// never a silent truncation that would report a package past the cut as absent.

/// `APKINDEX`: Wolfi's x86_64 index, which lists every release of every
/// package, is 38 MB; Alpine's `community` is 11 MB.
const APKINDEX_CAP: u64 = 128 << 20;

/// Debian/Ubuntu `Packages`: Ubuntu noble `universe` (amd64) is 73 MB, Debian
/// stable `main` 57 MB.
const PACKAGES_CAP: u64 = 256 << 20;

/// `primary.xml`: openSUSE Tumbleweed `oss` is 173 MB.
const PRIMARY_CAP: u64 = 512 << 20;

/// FreeBSD `packagesite.yaml`: FreeBSD 14 amd64 `latest` is 66 MB.
const PACKAGESITE_CAP: u64 = 256 << 20;

/// NetBSD `pkg_summary`: NetBSD 10.0 x86_64 is 34 MB.
const PKG_SUMMARY_CAP: u64 = 128 << 20;

/// Ceiling on the distinct packages one index lists. The largest real index
/// lists some 65 thousand (Ubuntu noble `universe`); without a bound, a
/// decompressed index of minimal entries would build a listing map many times
/// its own size.
const MAX_LISTINGS: usize = 1 << 18;

/// Ceiling on one line, stanza, or `<package>` element of an index. Real ones
/// are kilobytes; without a bound, one endless element would be buffered
/// whole.
const MAX_ELEMENT: usize = 16 * 1024 * 1024;

/// The xz decoder's memory ceiling: well above the 65 MiB `xz -9` needs, far
/// below what a crafted header could otherwise ask for.
const XZ_MEMLIMIT: u64 = 256 * 1024 * 1024;

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
        lookup(url, parse_apkindex, name, Ecosystem::Alpine, net, cache)
    })
}

/// Wolfi (Chainguard's distroless base): a single rolling `APKINDEX`, same
/// format as Alpine, listing every release of each package.
pub(crate) fn wolfi(
    name: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    lookup(
        "https://packages.wolfi.dev/os/x86_64/APKINDEX.tar.gz",
        parse_apkindex,
        name,
        Ecosystem::Wolfi,
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
        Ecosystem::Debian,
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
        lookup(url, parse_packages, name, Ecosystem::Ubuntu, net, cache)
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
        Ecosystem::Opensuse,
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
        Ecosystem::Rpmfusion,
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
        Ecosystem::Netbsd,
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
        Ecosystem::Freebsd,
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
    if !text.contains(".tgz") {
        return Err(unreadable(URL, "no package files listed"));
    }
    let version = openbsd_version(text, name).ok_or_else(|| not_found(URL, name))?;
    let mut registry = Registry::new(Ecosystem::Openbsd, name.to_string());
    registry.version = version;
    Ok(registry)
}

// --- parsed indexes ---------------------------------------------------------

/// One package's facts from an index, kept small: a parsed Debian index holds
/// some sixty thousand.
#[derive(Debug)]
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
    fn record(&self, ecosystem: Ecosystem, name: &str) -> Registry {
        let text = |s: &Option<Box<str>>| s.as_deref().map(str::to_string);
        let mut registry = Registry::new(ecosystem, name.to_string());
        registry.version = self.version.to_string();
        registry.published_at = self.published_at;
        registry.author = text(&self.author);
        registry.description = text(&self.description);
        registry.homepage = text(&self.homepage);
        registry.license = text(&self.license);
        registry
    }
}

/// An index's packages by name.
type Listings = HashMap<Box<str>, Listing>;

/// Reads an index's bytes, fetched from `url`, into its listings.
type Parser = fn(&str, Vec<u8>) -> Result<Listings, RegistryError>;

/// The listings read from an index's entries (stanzas, elements, or lines),
/// and how many entries did not read as a listing.
#[derive(Default)]
struct Tally {
    listings: Listings,
    entries: usize,
    failed: usize,
}

impl Tally {
    /// Count one entry, keeping its listing when it read as one. Where an
    /// index lists a name more than once (Wolfi lists every release), the
    /// latest-built listing stands, and on a tie the first.
    fn add(&mut self, parsed: Option<(Box<str>, Listing)>) -> std::io::Result<()> {
        self.entries += 1;
        let Some((name, listing)) = parsed else {
            self.failed += 1;
            return Ok(());
        };
        match self.listings.entry(name) {
            Entry::Occupied(mut held) => {
                if listing.published_at > held.get().published_at {
                    held.insert(listing);
                }
            }
            Entry::Vacant(slot) => {
                slot.insert(listing);
            }
        }
        if self.listings.len() > MAX_LISTINGS {
            return Err(std::io::Error::other(format!(
                "index lists more than {MAX_LISTINGS} packages"
            )));
        }
        Ok(())
    }

    /// The listings of the index at `url`, refused when it yielded none: an
    /// index whose format has changed must not answer "not found" for every
    /// package.
    fn finish(self, url: &str) -> Result<Listings, RegistryError> {
        let Self {
            listings,
            entries,
            failed,
        } = self;
        if listings.is_empty() {
            return Err(unreadable(
                url,
                format_args!("no package listings ({failed} of {entries} entries unreadable)"),
            ));
        }
        tracing::debug!(
            url,
            listings = listings.len(),
            entries,
            failed,
            "index parsed"
        );
        Ok(listings)
    }
}

/// Every index this process has parsed, with the checksum of the bytes
/// parsed, by a name that stays put: the index URL, or for an RPM repository
/// its base URL, since its primary index is renamed whenever it changes. A
/// burst of lookups against one index — a Dockerfile's `apt-get install` line —
/// decompresses and parses it once, and an index the cache has refreshed is
/// parsed afresh. All are kept: there are a dozen, a parsed Debian or Ubuntu
/// `universe` index the largest at some 17 MB.
static PARSED: LazyLock<Mutex<HashMap<String, Arc<Slot>>>> = LazyLock::new(Mutex::default);

/// One index's parse, behind its own lock: lookups racing on an index wait for
/// a single parse of it, while lookups on the others go on.
type Slot = Mutex<Option<Parsed>>;

struct Parsed {
    checksum: Checksum,
    listings: Arc<Listings>,
}

/// Package `name`'s record from the index at `url`, read by `parse`.
fn lookup(
    url: &str,
    parse: Parser,
    name: &str,
    ecosystem: Ecosystem,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    find(
        &*listings(url, url, None, parse, net, cache)?,
        url,
        name,
        ecosystem,
    )
}

/// Package `name`'s record in `ecosystem` from the `listings` of the index at
/// `url`.
fn find(
    listings: &Listings,
    url: &str,
    name: &str,
    ecosystem: Ecosystem,
) -> Result<Registry, RegistryError> {
    listings
        .get(name)
        .map(|listing| listing.record(ecosystem, name))
        .ok_or_else(|| not_found(url, name))
}

/// The listings of the index at `url`, kept as [`PARSED`]`[slot]` — refused
/// when its digest is not the `expected` one its repository published.
fn listings(
    slot: &str,
    url: &str,
    expected: Option<&Checksum>,
    parse: Parser,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Arc<Listings>, RegistryError> {
    // Read on every lookup, parsed only when its content changes: the read is
    // what keeps the index fresh and records it among the lookup's sources.
    let bytes = index(url, net, cache)?;
    let checksum = match expected {
        Some(want) => {
            let got = want.algorithm.digest(&bytes);
            if got != *want {
                return Err(unreadable(
                    url,
                    format_args!("{} checksum differs from repomd.xml", want.algorithm.name()),
                ));
            }
            tracing::debug!(
                url,
                algorithm = want.algorithm.name(),
                "index matches the checksum repomd.xml publishes"
            );
            got
        }
        None => Algorithm::Sha256.digest(&bytes),
    };
    let slot = Arc::clone(
        PARSED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(slot.to_string())
            .or_default(),
    );
    let mut parsed = slot.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(current) = parsed.as_ref().filter(|p| p.checksum == checksum) {
        tracing::debug!(url, "index unchanged; reusing its parsed listings");
        return Ok(Arc::clone(&current.listings));
    }
    tracing::debug!(url, bytes = bytes.len(), "parsing index");
    let listings = Arc::new(parse(url, bytes)?);
    *parsed = Some(Parsed {
        checksum,
        listings: Arc::clone(&listings),
    });
    drop(parsed);
    Ok(listings)
}

/// Every listing in the stanzas of `reader`.
fn stanza_listings<R: BufRead>(
    url: &str,
    reader: R,
    listing: fn(&str) -> Option<(Box<str>, Listing)>,
) -> Result<Listings, RegistryError> {
    let mut tally = Tally::default();
    stanzas(reader, |stanza| tally.add(listing(stanza))).map_err(|e| unreadable(url, e))?;
    tally.finish(url)
}

// --- APK (Alpine, Wolfi) ----------------------------------------------------

/// An `APKINDEX.tar.gz`: a signature tar and the index tar, gzipped back to
/// back, whose `APKINDEX` member holds `K:value` stanzas. The signature tar
/// carries no end-of-archive blocks and the index tar does, so zero blocks are
/// read past rather than taken as the end.
fn parse_apkindex(url: &str, bytes: Vec<u8>) -> Result<Listings, RegistryError> {
    let mut archive = tar::Archive::new(Capped::new(gunzip(bytes), APKINDEX_CAP, url));
    archive.set_ignore_zeros(true);
    let apkindex = member(&mut archive, "APKINDEX", url)?;
    stanza_listings(url, BufReader::new(apkindex), apkindex_listing)
}

/// One `APKINDEX` stanza (single-letter `K:value` lines).
fn apkindex_listing(stanza: &str) -> Option<(Box<str>, Listing)> {
    let name = field(stanza, "P:")?;
    Some((
        name.into(),
        Listing {
            version: field(stanza, "V:")?.into(),
            // `t:0` is a "build time unset" marker (reproducible builds), not
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
    let reader = Capped::new(gunzip(bytes), PACKAGES_CAP, url);
    stanza_listings(url, BufReader::new(reader), deb_listing)
}

/// One Debian control stanza (`Key: value`, with folded continuation lines
/// for multi-line descriptions).
fn deb_listing(stanza: &str) -> Option<(Box<str>, Listing)> {
    let name = field(stanza, "Package:")?;
    Some((
        name.into(),
        Listing {
            version: field(stanza, "Version:")?.into(),
            published_at: None,
            author: field(stanza, "Maintainer:").map(|m| strip_email(&m).into()),
            // The control `Description` is a one-line synopsis then folded lines.
            description: field(stanza, "Description:").map(Into::into),
            homepage: field(stanza, "Homepage:").map(Into::into),
            license: None,
        },
    ))
}

// --- RPM (openSUSE, RPM Fusion) ---------------------------------------------

/// Resolve `repomd.xml` to the `primary.xml` location and look the package up
/// there.
fn rpm_repo_lookup(
    base: &str,
    name: &str,
    ecosystem: Ecosystem,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let repomd_url = format!("{base}/repodata/repomd.xml");
    let repomd = index(&repomd_url, net, cache)?;
    let repomd = std::str::from_utf8(&repomd).map_err(|e| unreadable(&repomd_url, e))?;
    let primary =
        primary_data(repomd).ok_or_else(|| unreadable(&repomd_url, "no primary index"))?;
    let href = primary_href(primary)
        .ok_or_else(|| unreadable(&repomd_url, "no primary index location"))?;
    // `primary.xml` is served from third-party mirrors (openSUSE's
    // MirrorCache redirects), `repomd.xml` from the origin: hold the mirror to
    // the checksum the origin published. A repository that publishes none, or
    // only one of an algorithm not held here, is refused rather than read
    // unverified.
    let expected = primary_checksum(primary).map_err(|reason| unreadable(&repomd_url, reason))?;
    let url = format!("{base}/{href}");
    let listings = listings(base, &url, Some(&expected), parse_primary, net, cache)?;
    find(&listings, &url, name, ecosystem)
}

/// A `primary.xml`, compressed as its `.zst`/`.gz`/`.xz` suffix says.
fn parse_primary(url: &str, bytes: Vec<u8>) -> Result<Listings, RegistryError> {
    let reader: Box<dyn Read> = match url.rsplit('.').next() {
        Some("zst") => Box::new(
            zstd::stream::read::Decoder::new(Cursor::new(bytes)).map_err(|e| unreadable(url, e))?,
        ),
        Some("gz") => Box::new(gunzip(bytes)),
        Some("xz") => Box::new(xz2::read::XzDecoder::new_stream(
            Cursor::new(bytes),
            xz2::stream::Stream::new_stream_decoder(XZ_MEMLIMIT, xz2::stream::CONCATENATED)
                .map_err(|e| unreadable(url, e))?,
        )),
        _ => return Err(unreadable(url, "unknown compression")),
    };
    let mut tally = Tally::default();
    xml_packages(Capped::new(reader, PRIMARY_CAP, url), |pkg| {
        tally.add(rpm_listing(pkg))
    })
    .map_err(|e| unreadable(url, e))?;
    tally.finish(url)
}

/// A digest algorithm `repomd.xml` may publish that is strong enough to hold
/// a mirror to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Algorithm {
    Sha256,
    Sha512,
}

impl Algorithm {
    /// The algorithm `repomd.xml` spells `name`, if it is one held here.
    fn parse(name: &str) -> Option<Self> {
        match name {
            "sha256" => Some(Self::Sha256),
            "sha512" => Some(Self::Sha512),
            _ => None,
        }
    }

    /// The name `repomd.xml` spells this algorithm with.
    fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
        }
    }

    /// The length of this algorithm's digest in hex.
    fn hex_len(self) -> usize {
        match self {
            Self::Sha256 => 64,
            Self::Sha512 => 128,
        }
    }

    /// This algorithm's digest of `bytes`.
    fn digest(self, bytes: &[u8]) -> Checksum {
        let hex = match self {
            Self::Sha256 => sha256_hex(bytes),
            Self::Sha512 => hex::encode(Sha512::digest(bytes)),
        };
        Checksum {
            algorithm: self,
            hex,
        }
    }
}

/// A digest of an index: its algorithm and lowercase hex.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Checksum {
    algorithm: Algorithm,
    hex: String,
}

/// The `<data type="primary">` element of `repomd.xml`.
fn primary_data(xml: &str) -> Option<&str> {
    let data = xml
        .split("<data ")
        .find(|d| d.starts_with("type=\"primary\""))?;
    Some(data.split("</data>").next().unwrap_or(data))
}

/// The checksum the `<data type="primary">` element publishes for the
/// compressed `primary.xml` (`<checksum>`, not the decompressed
/// `<open-checksum>`), or why it publishes none that can be held to.
fn primary_checksum(data: &str) -> Result<Checksum, String> {
    const OPEN: &str = "<checksum";
    let start = data.find(OPEN).ok_or("no primary index checksum")?;
    let element = &data[start..];
    let kind = attr(element, OPEN, "type").ok_or("primary index checksum has no type")?;
    let algorithm = Algorithm::parse(&kind)
        .ok_or_else(|| format!("unsupported primary index checksum type {kind:?}"))?;
    let hex = element
        .split_once('>')
        .and_then(|(_, rest)| rest.split_once('<'))
        .map(|(text, _)| text.trim())
        .filter(|hex| {
            hex.len() == algorithm.hex_len() && hex.bytes().all(|b| b.is_ascii_hexdigit())
        })
        .ok_or_else(|| format!("malformed {} primary index checksum", algorithm.name()))?;
    Ok(Checksum {
        algorithm,
        hex: hex.to_ascii_lowercase(),
    })
}

/// The `<location href="…primary.xml.*"/>` of the `<data type="primary">`
/// element.
fn primary_href(data: &str) -> Option<&str> {
    let anchor = "href=\"";
    let rest = &data[data.find(anchor)? + anchor.len()..];
    Some(&rest[..rest.find('"')?])
}

/// One `<package>` element of `primary.xml`.
fn rpm_listing(pkg: &str) -> Option<(Box<str>, Listing)> {
    let name = tag_text(pkg, "name")?;
    // `<version epoch="0" ver="8.5.0" rel="1.2"/>`
    let ver = attr(pkg, "<version", "ver").filter(|v| !v.is_empty())?;
    let version = match attr(pkg, "<version", "rel") {
        Some(rel) => format!("{ver}-{rel}"),
        None => ver,
    };
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
    let reader = Capped::new(gunzip(bytes), PKG_SUMMARY_CAP, url);
    stanza_listings(url, BufReader::new(reader), pkg_summary_listing)
}

/// One `pkg_summary` stanza. `PKGNAME` is `name-version`, and a pkgsrc version
/// never contains a hyphen (revisions are `nbN`), so the version is everything
/// after the *last* one. Splitting there rather than after `name-` keeps `git`
/// from matching `git-base-2.45.2`.
fn pkg_summary_listing(stanza: &str) -> Option<(Box<str>, Listing)> {
    let pkgname = field(stanza, "PKGNAME=")?;
    let (name, version) = pkgname
        .rsplit_once('-')
        .filter(|(name, version)| !name.is_empty() && !version.is_empty())?;
    Some((
        name.into(),
        Listing {
            version: version.into(),
            published_at: field(stanza, "BUILD_DATE=").and_then(|d| unix_secs(&d)),
            author: field(stanza, "MAINTAINER=").map(|m| strip_email(&m).into()),
            description: field(stanza, "COMMENT=").map(Into::into),
            homepage: field(stanza, "HOMEPAGE=").map(Into::into),
            license: field(stanza, "LICENSE=").map(Into::into),
        },
    ))
}

/// A zstd `packagesite.pkg` tar, whose `packagesite.yaml` is one JSON object
/// per line. Streamed from the archive line by line: decompressed whole, the
/// catalog is tens of megabytes.
fn parse_packagesite(url: &str, bytes: Vec<u8>) -> Result<Listings, RegistryError> {
    let decoder =
        zstd::stream::read::Decoder::new(Cursor::new(bytes)).map_err(|e| unreadable(url, e))?;
    let mut archive = tar::Archive::new(Capped::new(decoder, PACKAGESITE_CAP, url));
    let mut yaml = BufReader::new(member(&mut archive, "packagesite.yaml", url)?);
    let mut tally = Tally::default();
    let mut line = Vec::new();
    while read_line(&mut yaml, &mut line).map_err(|e| unreadable(url, e))? > 0 {
        if line.trim_ascii().is_empty() {
            continue;
        }
        let parsed = serde_json::from_slice::<Packagesite>(&line)
            .ok()
            .and_then(packagesite_listing);
        tally.add(parsed).map_err(|e| unreadable(url, e))?;
    }
    tally.finish(url)
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
        p.name.filter(|n| !n.is_empty())?.into(),
        Listing {
            version: p.version.filter(|v| !v.is_empty())?.into(),
            published_at: None,
            author: p.maintainer.as_deref().map(|m| strip_email(m).into()),
            description: p.comment.map(Into::into),
            homepage: p.www.map(Into::into),
            license: p
                .licenses
                .and_then(|l| l.into_iter().next())
                .map(Into::into),
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

/// A streaming gzip reader over owned compressed `bytes`. A non-gzip body
/// surfaces as a read error when the scanner pulls from it.
fn gunzip(bytes: Vec<u8>) -> flate2::read::MultiGzDecoder<Cursor<Vec<u8>>> {
    flate2::read::MultiGzDecoder::new(Cursor::new(bytes))
}

/// A decompressed stream that fails once more than `cap` bytes have come out
/// of it, rather than ending there: one byte past the cap is read, so the cap
/// itself is still allowed, and every read after the cap fails too.
struct Capped<'a, R> {
    inner: std::io::Take<R>,
    cap: u64,
    url: &'a str,
}

impl<'a, R: Read> Capped<'a, R> {
    /// `inner`, the decompressed index at `url`, held to `cap` bytes.
    fn new(inner: R, cap: u64, url: &'a str) -> Self {
        Self {
            inner: inner.take(cap.saturating_add(1)),
            cap,
            url,
        }
    }
}

impl<R: Read> Read for Capped<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if self.inner.limit() == 0 {
            tracing::warn!(
                url = self.url,
                cap = self.cap,
                "index exceeds its decompression cap"
            );
            return Err(std::io::Error::other(format!(
                "decompressed index exceeds {} bytes",
                self.cap
            )));
        }
        Ok(n)
    }
}

/// [`BufRead::read_until`] a newline, refusing a line past [`MAX_ELEMENT`].
fn read_line(reader: &mut impl BufRead, line: &mut Vec<u8>) -> std::io::Result<usize> {
    line.clear();
    let n = reader
        .take(MAX_ELEMENT as u64 + 1)
        .read_until(b'\n', line)?;
    if line.len() > MAX_ELEMENT {
        return Err(std::io::Error::other("index line too long"));
    }
    Ok(n)
}

/// The member of `archive` named `name` (or `…/name`), positioned to be read
/// in place: the archive streams, so nothing before or after it is held.
fn member<'a, R: Read + 'a>(
    archive: &'a mut tar::Archive<R>,
    name: &str,
    url: &str,
) -> Result<tar::Entry<'a, R>, RegistryError> {
    for entry in archive.entries().map_err(|e| unreadable(url, e))? {
        let entry = entry.map_err(|e| unreadable(url, e))?;
        let found = {
            let path = entry.path_bytes();
            path.strip_suffix(name.as_bytes())
                .is_some_and(|dir| dir.is_empty() || dir.ends_with(b"/"))
        };
        if found {
            return Ok(entry);
        }
    }
    Err(unreadable(url, format_args!("no {name} member")))
}

/// Fetch an index document through the metadata cache.
fn index(url: &str, net: &dyn Fetch, cache: &BlobCache) -> Result<Vec<u8>, RegistryError> {
    match cached_metadata_status(url, &[], net, cache) {
        Ok(bytes) => {
            tracing::debug!(url, bytes = bytes.len(), "index read");
            Ok(bytes)
        }
        Err(error) => {
            tracing::debug!(url, %error, "index unavailable");
            Err(error.into())
        }
    }
}

/// The index at `url` arrived but could not be read as one.
fn unreadable(url: &str, reason: impl std::fmt::Display) -> RegistryError {
    let reason = reason.to_string();
    tracing::warn!(url, reason = %reason.escape_debug(), "index unreadable");
    RegistryError::Malformed {
        url: url.to_string(),
        reason,
    }
}

/// The index at `url` was read and does not list package `name`.
fn not_found(url: &str, name: &str) -> RegistryError {
    tracing::debug!(url, name = %name.escape_debug(), "package not in the index");
    RegistryError::NotFound
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
            Err(error) => {
                tracing::debug!(url = repo, %error, "repository unreadable; trying the next");
                why = error;
            }
        }
    }
    Err(why)
}

// --- index scanners ---------------------------------------------------------

/// Stream `reader` and hand each blank-line-delimited stanza to `f`, holding
/// at most one stanza, so a 100 MiB index is read in constant memory. A line
/// that is not UTF-8 is read lossily: one stray byte must not cost the index.
fn stanzas<R: BufRead>(
    mut reader: R,
    mut f: impl FnMut(&str) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let mut stanza = String::new();
    let mut line = Vec::new();
    loop {
        let at_end = read_line(&mut reader, &mut line)? == 0;
        let text = String::from_utf8_lossy(&line);
        let text = text.trim_end_matches(['\n', '\r']);
        if text.is_empty() {
            if !stanza.is_empty() {
                f(&stanza)?;
                stanza.clear();
            }
            if at_end {
                return Ok(());
            }
        } else {
            if stanza.len() + text.len() > MAX_ELEMENT {
                return Err(std::io::Error::other("index stanza too long"));
            }
            stanza.push_str(text);
            stanza.push('\n');
        }
    }
}

/// Stream `reader`, isolating each `<package …>…</package>` element and handing
/// its text to `f` (read lossily, as [`stanzas`] reads a line). Buffers at most
/// one element (up to [`MAX_ELEMENT`]) plus a read chunk, so a
/// multi-hundred-MiB `primary.xml` is read without holding it whole. An
/// element still open after a read resumes its close-tag search where the
/// last one stopped, so one long element costs linear time, not a rescan per
/// chunk.
fn xml_packages<R: Read>(
    mut reader: R,
    mut f: impl FnMut(&str) -> std::io::Result<()>,
) -> std::io::Result<()> {
    const OPEN: &[u8] = b"<package";
    const CLOSE: &[u8] = b"</package>";
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; XML_CHUNK];
    // How much of the open element at the front of `buf` was already searched.
    let mut searched: usize = 0;
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
            // A close tag may straddle the previous read, so step back over it.
            let from = start + std::mem::take(&mut searched).saturating_sub(CLOSE.len() - 1);
            let Some(end) = find_sub(&buf[from..], CLOSE).map(|i| from + i + CLOSE.len()) else {
                if buf.len() - start > MAX_ELEMENT {
                    return Err(std::io::Error::other("index element too long"));
                }
                searched = buf.len() - start;
                done = start; // incomplete: read more
                break;
            };
            f(&String::from_utf8_lossy(&buf[start..end]))?;
            done = end;
        }
        buf.drain(..done);
    }
}

/// Byte-substring search (indices), naive for the small needles it is given.
fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

// --- field extraction -------------------------------------------------------

/// The value of the first line beginning `prefix` (`Package:`, `P:`, `KEY=`),
/// trimmed; `None` when absent or empty. A folded/continuation line (the only
/// other place the prefix could reappear) starts with whitespace, so it never
/// shadows the real field.
fn field(stanza: &str, prefix: &str) -> Option<String> {
    stanza
        .lines()
        .find_map(|l| l.strip_prefix(prefix))
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// The text of the first `<tag>…</tag>` (no attributes assumed on the open
/// tag); `None` when absent or empty.
fn tag_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let start = xml.find(&open)? + open.len();
    let rest = &xml[start..];
    let end = rest.find(&format!("</{tag}>"))?;
    // The five predefined XML entities a primary.xml summary may carry.
    Some(
        rest[..end]
            .trim()
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&amp;", "&"),
    )
    .filter(|text| !text.is_empty())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fetch::Fixtures;
    use filefacts::RefLocator;
    use std::io::Write as _;

    const DEBIAN: &str = "https://deb.debian.org/debian/dists/stable/main/binary-amd64/Packages.gz";

    /// The record the dispatcher returns for `purl`.
    fn resolve(purl: &str, net: &Fixtures) -> Result<Registry, RegistryError> {
        crate::registry::lookup(&RefLocator::Purl(purl.into()), net, &BlobCache::disabled())
    }

    fn gz(data: &[u8]) -> Vec<u8> {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    /// A ustar archive of `members`, with its end-of-archive blocks.
    fn tar_of(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, data) in members {
            let mut header = tar::Header::new_ustar();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            builder.append_data(&mut header, path, *data).unwrap();
        }
        builder.into_inner().unwrap()
    }

    /// An `APKINDEX.tar.gz` as `abuild` lays one out: a signature tar cut
    /// short of its end-of-archive blocks, then the index tar, each gzipped.
    fn apkindex_tar_gz(apkindex: &[u8]) -> Vec<u8> {
        let mut signature = tar_of(&[(".SIGN.RSA.test.rsa.pub", b"signature")]);
        signature.truncate(signature.len() - 1024);
        let mut out = gz(&signature);
        out.extend(gz(&tar_of(&[
            ("DESCRIPTION", b"v3.20"),
            ("APKINDEX", apkindex),
        ])));
        out
    }

    /// A `repomd.xml` publishing `checksum` (an element, or nothing) for the
    /// primary index at `href`.
    fn repomd(checksum: &str, href: &str) -> String {
        format!(
            r#"<repomd><data type="primary">{checksum}
            <open-checksum type="sha256">{zero}</open-checksum>
            <location href="{href}"/></data></repomd>"#,
            zero = "0".repeat(64)
        )
    }

    const PRIMARY: &[u8] = br#"<metadata><package type="rpm"><name>curl</name>
        <version epoch="0" ver="8.5.0" rel="1.2"/></package></metadata>"#;

    #[test]
    fn apkindex_listing_maps_fields() {
        let stanza = "C:Q1xxx\nP:curl\nV:8.5.0-r0\nA:x86_64\n\
                      T:URL retrieval utility\nU:https://curl.se/\nL:curl\n\
                      m:Nat <nat@example.test>\nt:1619172000\no:curl\n";
        let (name, listing) = apkindex_listing(stanza).expect("listing");
        assert_eq!(&*name, "curl");
        let r = listing.record(Ecosystem::Alpine, &name);
        assert_eq!(r.ecosystem, Ecosystem::Alpine);
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
        let r = listing.record(Ecosystem::Debian, &name);
        assert_eq!(r.version, "1.24.0-1");
        assert_eq!(r.author.as_deref(), Some("Debian Nginx"));
        assert_eq!(r.homepage.as_deref(), Some("https://nginx.org"));
        assert_eq!(r.description.as_deref(), Some("small web server"));
        assert_eq!(r.published_at, None);
    }

    #[test]
    fn an_entry_without_a_version_is_not_a_listing() {
        assert!(deb_listing("Package: nginx\n").is_none());
        assert!(apkindex_listing("P:curl\nV:\n").is_none());
        assert!(rpm_listing("<package><name>curl</name></package>").is_none());
        assert!(pkg_summary_listing("PKGNAME=curl-\n").is_none());
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
        let r = listing.record(Ecosystem::Opensuse, &name);
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
            primary_data(xml).and_then(primary_href),
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
        let r = listing.record(Ecosystem::Netbsd, &name);
        assert_eq!(r.ecosystem, Ecosystem::Netbsd);
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
        let r = listing.record(Ecosystem::Freebsd, &name);
        assert_eq!(r.ecosystem, Ecosystem::Freebsd);
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
    fn an_openbsd_listing_of_no_packages_is_malformed() {
        let url = "https://cdn.openbsd.org/pub/OpenBSD/snapshots/packages/amd64/index.txt";
        let net = Fixtures::default().with(url, b"<html>moved</html>");
        let got = resolve("pkg:openbsd/curl", &net);
        assert!(
            matches!(got, Err(RegistryError::Malformed { .. })),
            "{got:?}"
        );
    }

    #[test]
    fn stanzas_are_read_one_at_a_time() {
        // A stray non-UTF-8 byte costs only its own line.
        let text = b"Package: a\nVersion: 1\n\nPackage: b\nDescription: caf\xe9\n\n\nPackage: c\n";
        let mut seen = Vec::new();
        stanzas(BufReader::new(Cursor::new(&text[..])), |s| {
            seen.push(field(s, "Package:"));
            Ok(())
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
        xml_packages(Trickle(xml.as_bytes()), |p| {
            names.push(tag_text(p, "name"));
            Ok(())
        })
        .expect("read");
        assert_eq!(names, [Some("a".into()), Some("curl".into())]);
    }

    #[test]
    fn a_non_utf8_element_is_read_not_dropped() {
        let xml =
            b"<metadata><package><name>a</name><summary>caf\xe9</summary></package></metadata>";
        let mut names = Vec::new();
        xml_packages(Cursor::new(&xml[..]), |p| {
            names.push(tag_text(p, "name"));
            Ok(())
        })
        .expect("read");
        assert_eq!(names, [Some("a".into())]);
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
            lookup(url, counted, name, Ecosystem::Debian, net, &cache).map(|r| r.version)
        };
        assert_eq!(version(&net, "a"), Ok("1".into()));
        assert_eq!(version(&net, "b"), Ok("2".into()));
        assert_eq!(version(&net, "z"), Err(RegistryError::NotFound));
        assert_eq!(PARSES.load(Ordering::SeqCst), 1);

        let refreshed = Fixtures::default().with(url, b"Package: a\nVersion: 3\n");
        assert_eq!(version(&refreshed, "a"), Ok("3".into()));
        assert_eq!(PARSES.load(Ordering::SeqCst), 2);
    }

    /// A slow parse of one index holds up lookups on that index alone.
    #[test]
    fn one_index_parsing_does_not_hold_up_another() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::{Duration, Instant};
        static STARTED: AtomicBool = AtomicBool::new(false);
        static RELEASED: AtomicBool = AtomicBool::new(false);
        /// Parses only once the test lets it, or after ten seconds.
        fn slow(url: &str, bytes: Vec<u8>) -> Result<Listings, RegistryError> {
            STARTED.store(true, Ordering::SeqCst);
            let give_up = Instant::now() + Duration::from_secs(10);
            while !RELEASED.load(Ordering::SeqCst) && Instant::now() < give_up {
                std::thread::sleep(Duration::from_millis(1));
            }
            stanza_listings(url, Cursor::new(bytes), deb_listing)
        }
        let (a, b) = (
            "https://distro.test/slow/Packages",
            "https://distro.test/fast/Packages",
        );
        let net = Fixtures::default()
            .with(a, b"Package: a\nVersion: 1\n")
            .with(b, b"Package: b\nVersion: 2\n");
        let cache = BlobCache::disabled();
        std::thread::scope(|scope| {
            let parsing = scope.spawn(|| lookup(a, slow, "a", Ecosystem::Debian, &net, &cache));
            while !STARTED.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(1));
            }
            let started = Instant::now();
            let other = lookup(b, stanza_listings_deb, "b", Ecosystem::Debian, &net, &cache);
            assert_eq!(other.map(|r| r.version), Ok("2".into()));
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "waited on the other parse"
            );
            RELEASED.store(true, Ordering::SeqCst);
            assert_eq!(
                parsing.join().expect("no panic").map(|r| r.version),
                Ok("1".into())
            );
        });
    }

    fn stanza_listings_deb(url: &str, bytes: Vec<u8>) -> Result<Listings, RegistryError> {
        stanza_listings(url, Cursor::new(bytes), deb_listing)
    }

    #[test]
    fn a_decoded_name_with_a_plus_resolves() {
        let packages = gz(b"Package: libstdc++6\nVersion: 14.2.0-19\n\n\
                            Package: curl\nVersion: 8.14.1-2\n");
        let net = Fixtures::default().with(DEBIAN, &packages);
        let r = resolve("pkg:deb/debian/libstdc%2B%2B6", &net).expect("record");
        assert_eq!(r.name, "libstdc++6");
        assert_eq!(r.version, "14.2.0-19");
    }

    #[test]
    fn a_requested_build_is_the_record_s_version() {
        let url = "https://packages.wolfi.dev/os/x86_64/APKINDEX.tar.gz";
        let index = apkindex_tar_gz(b"P:curl\nV:8.23.0-r2\nt:1792705649\n\n");
        let net = Fixtures::default().with(url, &index);
        let r = resolve("pkg:apk/wolfi/curl@7.0.0-r0", &net).expect("record");
        assert_eq!(r.version, "7.0.0-r0");
        assert_eq!(r.published_at, None, "never the current build's date");
        assert_eq!(r.latest_version.as_deref(), Some("8.23.0-r2"));
        let r = resolve("pkg:apk/wolfi/curl@8.23.0-r2", &net).expect("record");
        assert_eq!(r.published_at, Some(1_792_705_649));
        assert_eq!(r.latest_version.as_deref(), Some("8.23.0-r2"));
    }

    #[test]
    fn an_apkindex_is_streamed_past_its_signature_tar() {
        let url = "https://dl-cdn.alpinelinux.org/alpine/latest-stable/main/x86_64/APKINDEX.tar.gz";
        let index = apkindex_tar_gz(
            b"P:musl\nV:1.2.5-r0\nt:1700000000\n\n\
                                      P:libstdc++\nV:14.2.0-r4\nm:Ann <a@example.test>\n\n",
        );
        let net = Fixtures::default().with(url, &index);
        let r = resolve("pkg:apk/alpine/libstdc%2B%2B", &net).expect("record");
        assert_eq!(r.name, "libstdc++");
        assert_eq!(r.version, "14.2.0-r4");
        assert_eq!(r.author.as_deref(), Some("Ann"));

        let unsigned = gz(&tar_of(&[("DESCRIPTION", b"v3.20")]));
        let got = parse_apkindex(url, unsigned);
        assert!(
            matches!(got, Err(RegistryError::Malformed { .. })),
            "{got:?}"
        );
    }

    #[test]
    fn wolfi_reports_the_latest_build_of_a_package() {
        // Wolfi's index lists every release of a package, oldest first.
        let url = "https://packages.wolfi.dev/os/x86_64/APKINDEX.tar.gz";
        let index = apkindex_tar_gz(
            b"P:curl\nV:7.87.0-r0\nt:0\n\n\
                                      P:curl\nV:8.9.1-r4\nt:1725390890\n\n\
                                      P:curl\nV:8.23.0-r2\nt:1792705649\n\n\
                                      P:curl\nV:8.10.0-r0\nt:1726038056\n\n",
        );
        let net = Fixtures::default().with(url, &index);
        let r = resolve("pkg:apk/wolfi/curl", &net).expect("record");
        assert_eq!(r.version, "8.23.0-r2");
        assert_eq!(r.published_at, Some(1_792_705_649));
    }

    #[test]
    fn an_index_that_yields_no_listings_is_malformed_not_not_found() {
        let read = |index: &[u8]| parse_packages(DEBIAN, gz(index));
        // Some unreadable stanzas cost only themselves.
        let mixed =
            read(b"Source: x\n\nPackage: curl\nVersion: 8\n\nPackage: y\n").expect("listings");
        assert_eq!(mixed.len(), 1);
        // A format change, or nothing at all, is not "every package absent".
        for index in [&b"Source: x\nVersion: 1\n\nPackage: y\n"[..], b"", b"\n\n"] {
            let got = read(index);
            assert!(
                matches!(got, Err(RegistryError::Malformed { .. })),
                "{got:?}"
            );
        }
        let net = Fixtures::default().with(DEBIAN, &gz(b"Source: curl\nVersion: 8\n"));
        let got = resolve("pkg:deb/debian/curl", &net);
        assert!(
            matches!(got, Err(RegistryError::Malformed { .. })),
            "{got:?}"
        );
    }

    #[test]
    fn freebsd_catalog_lines_that_fail_are_counted_not_fatal() {
        let catalog = |yaml: &[u8]| {
            let tar = tar_of(&[("packagesite.yaml.sig", b"sig"), ("packagesite.yaml", yaml)]);
            zstd::encode_all(Cursor::new(tar), 3).unwrap()
        };
        let url = "https://pkg.freebsd.org/FreeBSD:14:amd64/latest/packagesite.pkg";
        let good = catalog(
            b"not json\n{\"name\":\"nover\"}\n\n\
                             {\"name\":\"curl\",\"version\":\"8.5.0\"}\n",
        );
        let net = Fixtures::default().with(url, &good);
        let r = resolve("pkg:freebsd/curl", &net).expect("record");
        assert_eq!(r.version, "8.5.0");

        let got = parse_packagesite(url, catalog(b"not json\n{\"name\":\"nover\"}\n"));
        assert!(
            matches!(got, Err(RegistryError::Malformed { .. })),
            "{got:?}"
        );
    }

    #[test]
    fn an_xz_primary_index_is_read_like_the_other_codecs() {
        let mut xz = xz2::write::XzEncoder::new(Vec::new(), 6);
        xz.write_all(PRIMARY).unwrap();
        let xz = xz.finish().unwrap();
        let checksum = format!(r#"<checksum type="sha256">{}</checksum>"#, sha256_hex(&xz));
        let net = Fixtures::default()
            .with(
                "https://repo-xz.test/repodata/repomd.xml",
                repomd(&checksum, "repodata/p-primary.xml.xz").as_bytes(),
            )
            .with("https://repo-xz.test/repodata/p-primary.xml.xz", &xz);
        let r = rpm_repo_lookup(
            "https://repo-xz.test",
            "curl",
            Ecosystem::Opensuse,
            &net,
            &BlobCache::disabled(),
        )
        .expect("record");
        assert_eq!(r.version, "8.5.0-1.2");
    }

    #[test]
    fn a_mirrored_primary_index_must_match_repomd() {
        let primary = gz(PRIMARY);
        let lookup = |base: &str, checksum: &str| {
            let net = Fixtures::default()
                .with(
                    &format!("{base}/repodata/repomd.xml"),
                    repomd(checksum, "repodata/p-primary.xml.gz").as_bytes(),
                )
                .with(&format!("{base}/repodata/p-primary.xml.gz"), &primary);
            rpm_repo_lookup(
                base,
                "curl",
                Ecosystem::Opensuse,
                &net,
                &BlobCache::disabled(),
            )
        };
        let element =
            |kind: &str, hex: &str| format!(r#"<checksum type="{kind}">{hex}</checksum>"#);
        let sha512 = hex::encode(Sha512::digest(&primary));
        let verified = [
            (
                "https://sum-256.test",
                element("sha256", &sha256_hex(&primary).to_uppercase()),
            ),
            ("https://sum-512.test", element("sha512", &sha512)),
        ];
        for (base, checksum) in verified {
            assert_eq!(
                lookup(base, &checksum).map(|r| r.version),
                Ok("8.5.0-1.2".into()),
                "{checksum}"
            );
        }
        let refused = [
            ("https://bad-256.test", element("sha256", &"a".repeat(64))),
            ("https://bad-512.test", element("sha512", &"a".repeat(128))),
            // A digest of one algorithm is not read as another's.
            (
                "https://short-512.test",
                element("sha512", &sha256_hex(&primary)),
            ),
            ("https://md5.test", element("md5", &"a".repeat(32))),
            ("https://sha1.test", element("sha", &"a".repeat(40))),
            (
                "https://untyped.test",
                format!("<checksum>{sha512}</checksum>"),
            ),
            ("https://unsummed.test", String::new()),
        ];
        for (base, checksum) in refused {
            let got = lookup(base, &checksum);
            assert!(
                matches!(got, Err(RegistryError::Malformed { .. })),
                "{checksum}: {got:?}"
            );
        }
    }

    #[test]
    fn a_repomd_that_is_not_utf8_is_malformed() {
        let net = Fixtures::default().with(
            "https://repo-latin1.test/repodata/repomd.xml",
            b"<repomd>\xff</repomd>",
        );
        let got = rpm_repo_lookup(
            "https://repo-latin1.test",
            "curl",
            Ecosystem::Opensuse,
            &net,
            &BlobCache::disabled(),
        );
        assert!(
            matches!(got, Err(RegistryError::Malformed { .. })),
            "{got:?}"
        );
    }

    #[test]
    fn a_decompressed_index_past_the_cap_is_an_error_not_a_prefix() {
        let url = "https://distro.test/capped";
        let read = |cap: u64| {
            let mut out = Vec::new();
            Capped::new(Cursor::new([0u8; 10]), cap, url).read_to_end(&mut out)
        };
        assert_eq!(read(10).ok(), Some(10));
        assert!(read(9).is_err());

        let index = b"Package: a\nVersion: 1\n\nPackage: b\nVersion: 2\n";
        let capped = Capped::new(Cursor::new(index), 30, url);
        let got = stanza_listings(url, BufReader::new(capped), deb_listing);
        assert!(
            matches!(got, Err(RegistryError::Malformed { .. })),
            "{got:?}"
        );
    }

    #[test]
    fn an_index_of_too_many_packages_is_refused() {
        let mut tally = Tally::default();
        let listing = || Listing {
            version: "1".into(),
            published_at: None,
            author: None,
            description: None,
            homepage: None,
            license: None,
        };
        for n in 0..MAX_LISTINGS {
            tally
                .add(Some((n.to_string().into(), listing())))
                .expect("within the cap");
        }
        assert!(
            tally.add(Some(("0".into(), listing()))).is_ok(),
            "a repeat adds nothing"
        );
        assert!(tally.add(Some(("one more".into(), listing()))).is_err());
    }

    #[test]
    fn an_endless_index_element_is_refused() {
        let mut xml = b"<metadata><package><name>a</name>".to_vec();
        xml.resize(MAX_ELEMENT + XML_CHUNK * 2, b'x');
        let got = xml_packages(Cursor::new(xml), |_| Ok(()));
        assert!(got.is_err());

        let line = vec![b'x'; MAX_ELEMENT + 1];
        assert!(stanzas(Cursor::new(line), |_| Ok(())).is_err());
    }

    #[test]
    fn a_close_tag_split_across_reads_is_still_found() {
        // Elements far longer than one read, closed across a read boundary.
        let mut xml = b"<metadata><package><name>a</name>".to_vec();
        xml.resize(XML_CHUNK * 3 - 4, b' ');
        xml.extend_from_slice(b"</package><package><name>b</name></package>");
        let mut names = Vec::new();
        xml_packages(Cursor::new(xml), |p| {
            names.push(tag_text(p, "name"));
            Ok(())
        })
        .expect("read");
        assert_eq!(names, [Some("a".into()), Some("b".into())]);
    }
}
