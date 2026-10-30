//! Arch Linux's official repositories and the AUR: registry metadata and
//! artifact resolution.

use filefacts::{Ecosystem, Registry};
use serde::Deserialize;
use serde::de::IgnoredAny;

use crate::ecosystem::{Coordinates, fetch_json, flag, null_default, unix_secs};
use crate::fetch::{BlobCache, Fetch, cached_metadata, safe_coordinate};
use crate::registry::RegistryError;

/// The Arch Linux repositories `archlinux.org` answers for, as an `alpm`
/// namespace: the vendor itself, then its official repos, stable ones first.
pub(crate) const REPOSITORIES: &[&str] = &[
    "arch",
    "core",
    "extra",
    "multilib",
    "community",
    "testing",
    "core-testing",
    "extra-testing",
    "multilib-testing",
    "community-testing",
    "staging",
    "core-staging",
    "extra-staging",
    "gnome-unstable",
    "kde-unstable",
];

/// The repositories a current package is downloaded from: the stable ones,
/// each with a fixed `/packages/{repo}/os/{arch}/` path.
const DOWNLOAD_REPOSITORIES: &[&str] = &["core", "extra", "multilib"];

/// The AUR snapshot URL for `name`: ask the (cached) RPC for the package's
/// `URLPath`, which names the pkgbase snapshot. Falls back to the name-derived
/// snapshot path — correct whenever pkgbase == name — when the RPC is
/// unreachable or names no such package, so an RPC blip can't kill a fetch that
/// would have succeeded; a genuinely absent package then 404s at the snapshot,
/// recording a failed fetch rather than an unresolvable locator.
pub(crate) fn resolve_aur(name: &str, net: &dyn Fetch, cache: &BlobCache) -> String {
    let api = aur_info_url(name);
    let fallback = || format!("https://aur.archlinux.org/cgit/aur.git/snapshot/{name}.tar.gz");
    let Some(path) = cached_metadata(&api, net, cache)
        .and_then(|bytes| serde_json::from_slice::<AurInfo>(&bytes).ok())
        .and_then(|doc| doc.results.into_iter().next()?.url_path)
    else {
        tracing::debug!(url = %api, "aur snapshot path unknown; deriving it from the name");
        return fallback();
    };
    // Concatenated onto the host, so anything but a snapshot path
    // (`@evil.test/x`, `.evil.test/x`) would move the host itself.
    match path.strip_prefix("/cgit/aur.git/snapshot/") {
        Some(snapshot) if safe_coordinate(snapshot) => format!("https://aur.archlinux.org{path}"),
        _ => {
            tracing::debug!(
                url = %api,
                path = %path.escape_debug(),
                "aur snapshot path refused: not a snapshot path; deriving it from the name"
            );
            fallback()
        }
    }
}

/// Resolve the current official-repository package, not an installed version.
/// The package API supplies repository and architecture; only the stable
/// repositories and Arch's x86_64/any artifacts are accepted, x86_64 first.
pub(crate) fn resolve_arch_current(
    name: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<String, RegistryError> {
    if !safe_coordinate(name) {
        tracing::debug!(name = %name.escape_debug(), "arch download refused: unsafe name");
        return Err(RegistryError::UnsafeCoordinate);
    }
    let url = search_url(name);
    let doc: ArchSearch = fetch_json(&url, net, cache)
        .inspect_err(|error| tracing::debug!(url, %error, "arch download unresolved"))?;
    let Some((repo, arch)) = named(&doc, name, DOWNLOAD_REPOSITORIES)
        .filter_map(|(repo, p)| match p.arch.as_deref()? {
            arch @ ("x86_64" | "any") => Some((repo, arch)),
            _ => None,
        })
        .min_by_key(|&(_, arch)| arch != "x86_64")
    else {
        tracing::debug!(url = %url, "arch download unresolved: no stable x86_64 or any package of that name");
        return Err(RegistryError::NoRecord);
    };
    Ok(format!(
        "https://archlinux.org/packages/{repo}/os/{arch}/{name}/download/"
    ))
}

/// The search results named exactly `name` in one of `repositories`
/// (compared ASCII-case-insensitively), in `repositories` order, each paired
/// with the matching entry of `repositories` rather than the document's own
/// spelling, so no URL is built from the latter. The search
/// matches more than the exact name and spans every repository, so its
/// first hit may be another package, or this one somewhere else.
fn named<'a>(
    doc: &'a ArchSearch,
    name: &'a str,
    repositories: &'a [&'a str],
) -> impl Iterator<Item = (&'a str, &'a ArchPackage)> + 'a {
    repositories.iter().flat_map(move |&repo| {
        doc.results
            .iter()
            .filter(move |p| {
                p.pkgname.as_deref() == Some(name)
                    && p.repo
                        .as_deref()
                        .is_some_and(|r| r.eq_ignore_ascii_case(repo))
            })
            .map(move |p| (repo, p))
    })
}

/// The archlinux.org package search for `name`.
fn search_url(name: &str) -> String {
    format!("https://archlinux.org/packages/search/json/?name={name}")
}

/// The AUR RPC `info` query for `name`.
fn aur_info_url(name: &str) -> String {
    format!("https://aur.archlinux.org/rpc/v5/info?arg%5B%5D={name}")
}

/// Look up the package `c` names in Arch Linux's official repositories: the
/// one its namespace names, or any of them for the `arch` vendor namespace,
/// stable repositories first. Recency comes from `last_update`; an
/// out-of-date flag is the deprecation analogue. AUR-only packages aren't
/// here, so they are `NotFound`.
pub(crate) fn official(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let one;
    let repositories: &[&str] = match c.namespace() {
        [repo] if repo != "arch" => {
            one = [repo.as_str()];
            &one
        }
        _ => REPOSITORIES,
    };
    let doc: ArchSearch = fetch_json(&search_url(c.encoded_name()), net, cache)?;
    let Some((repo, r)) = named(&doc, c.name(), repositories).next() else {
        tracing::debug!(
            name = %c.name().escape_debug(),
            ?repositories,
            hits = doc.results.len(),
            "arch lookup: no search hit is this package in these repositories"
        );
        return Err(RegistryError::NotFound);
    };
    tracing::debug!(name = %c.name().escape_debug(), repo, "arch lookup matched");
    let version = match (r.pkgver.as_deref(), r.pkgrel.as_deref()) {
        (Some(v), Some(rel)) => format!("{v}-{rel}"),
        (Some(v), None) => v.to_string(),
        _ => String::new(),
    };

    let mut registry = Registry::new(Ecosystem::Arch, c.name().to_string());
    registry.version = version;
    registry.published_at = r
        .last_update
        .as_deref()
        .or(r.build_date.as_deref())
        .and_then(unix_secs);
    registry.author = r.packager.clone();
    registry.description = r.pkgdesc.clone();
    registry.homepage = r.url.clone();
    registry.license = r.licenses.first().cloned();
    registry.maintainers = r
        .maintainers
        .as_ref()
        .and_then(|m| u32::try_from(m.len()).ok());
    registry.deprecated = flag(Some(r.flag_date.is_some()), "flagged out-of-date");
    Ok(registry)
}

/// Look up the package `c` names in the AUR through the RPC `info` endpoint.
/// The AUR has no downloads; its custody signal is the maintainer set, and
/// `LastModified` (when the PKGBUILD last changed) is the supply-chain
/// "age". Official repo packages aren't in the AUR, so they return an empty
/// result → `NotFound`.
pub(crate) fn user(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let doc: AurInfo = fetch_json(&aur_info_url(c.encoded_name()), net, cache)?;
    let r = doc
        .results
        .into_iter()
        .next()
        .ok_or(RegistryError::NotFound)?;

    let mut registry = Registry::new(
        Ecosystem::Aur,
        r.name.clone().unwrap_or_else(|| c.name().to_string()),
    );
    registry.version = r.version.unwrap_or_default();
    // LastModified is a Unix-seconds integer already.
    registry.published_at = r.last_modified;
    // FirstSubmitted is the package's birth; the gap to LastModified is the
    // dormancy a revived abandoned package would show.
    registry.first_published_at = r.first_submitted;
    // The primary maintainer plus any co-maintainers — the custody set.
    registry.maintainers = Some(
        u32::try_from(r.co_maintainers.len())
            .unwrap_or(u32::MAX)
            .saturating_add(u32::from(r.maintainer.is_some())),
    );
    registry.author = r.maintainer.clone();
    registry.publisher = r.maintainer;
    registry.title = r.name;
    registry.description = r.description;
    registry.homepage = r.url;
    registry.deprecated = flag(r.out_of_date.map(|t| t > 0), "flagged out-of-date");
    // The AUR's popularity score (votes decayed by age) and the votes
    // behind it: the AUR case `Registry::rating` names.
    registry.rating = r
        .popularity
        .filter(|p| p.is_finite() && *p >= 0.0)
        .map(|p| p as f32);
    registry.rating_count = r.num_votes;
    Ok(registry)
}

/// An AUR RPC `info` response.
#[derive(Deserialize)]
struct AurInfo {
    results: Vec<AurPackage>,
}

/// One package in an AUR RPC `info` response.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AurPackage {
    name: Option<String>,
    version: Option<String>,
    last_modified: Option<u64>,
    first_submitted: Option<u64>,
    maintainer: Option<String>,
    #[serde(deserialize_with = "null_default")]
    co_maintainers: Vec<IgnoredAny>,
    description: Option<String>,
    #[serde(rename = "URL")]
    url: Option<String>,
    #[serde(rename = "URLPath")]
    url_path: Option<String>,
    out_of_date: Option<u64>,
    popularity: Option<f64>,
    num_votes: Option<u64>,
}

/// An archlinux.org package search response.
#[derive(Deserialize)]
struct ArchSearch {
    results: Vec<ArchPackage>,
}

/// One package in an archlinux.org search response.
#[derive(Default, Deserialize)]
#[serde(default)]
struct ArchPackage {
    pkgname: Option<String>,
    repo: Option<String>,
    arch: Option<String>,
    pkgver: Option<String>,
    pkgrel: Option<String>,
    last_update: Option<String>,
    build_date: Option<String>,
    packager: Option<String>,
    pkgdesc: Option<String>,
    url: Option<String>,
    #[serde(deserialize_with = "null_default")]
    licenses: Vec<String>,
    maintainers: Option<Vec<IgnoredAny>>,
    flag_date: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::fetch::Fixtures;
    use filefacts::RefLocator;

    fn look(purl: &str, net: &Fixtures) -> Result<Registry, RegistryError> {
        crate::registry::lookup(&RefLocator::Purl(purl.into()), net, &BlobCache::disabled())
    }

    #[test]
    fn aur_rpc_maps_custody_and_modified() {
        let rpc = serde_json::json!({
            "resultcount": 1,
            "results": [{
                "Name": "yay", "Version": "12.0.0-1", "Description": "AUR helper",
                "URL": "https://github.test/yay", "Maintainer": "jverify",
                "CoMaintainers": ["alice", "bob"],
                "NumVotes": 1234, "Popularity": 42.5,
                "FirstSubmitted": 1_600_000_000u64, "LastModified": 1_619_172_000u64,
                "OutOfDate": serde_json::Value::Null
            }]
        })
        .to_string();
        let net = Fixtures::default().with(
            "https://aur.archlinux.org/rpc/v5/info?arg%5B%5D=yay",
            rpc.as_bytes(),
        );
        let p = look("pkg:alpm/aur/yay", &net).expect("provenance");
        assert_eq!(p.ecosystem, Ecosystem::Aur);
        assert_eq!(p.published_at, Some(1_619_172_000));
        assert_eq!(p.first_published_at, Some(1_600_000_000));
        // Primary maintainer + two co-maintainers = a custody set of three.
        assert_eq!(p.maintainers, Some(3));
        assert_eq!(p.author.as_deref(), Some("jverify"));
        assert_eq!(p.publisher.as_deref(), Some("jverify"));
        assert_eq!(p.rating, Some(42.5));
        assert_eq!(p.rating_count, Some(1234));
        assert_eq!(p.deprecated, None);
    }

    #[test]
    fn an_out_of_date_aur_package_is_flagged() {
        let rpc = br#"{"results":[{"Name":"old","OutOfDate":1700000000}]}"#;
        let net =
            Fixtures::default().with("https://aur.archlinux.org/rpc/v5/info?arg%5B%5D=old", rpc);
        let p = look("pkg:alpm/aur/old", &net).expect("record");
        assert_eq!(p.deprecated.as_deref(), Some("flagged out-of-date"));
    }

    #[test]
    fn arch_packages_normalizes() {
        let doc = serde_json::json!({"results": [{
            "pkgname": "pacman", "repo": "core", "pkgver": "7.1.0", "pkgrel": "2",
            "pkgdesc": "A library-based package manager", "url": "https://archlinux.org/pacman/",
            "licenses": ["GPL-2.0-or-later"], "packager": "eworm",
            "maintainers": ["anthraxx", "Foxboron"],
            "last_update": "2021-04-23T10:00:00.379Z", "flag_date": null
        }]})
        .to_string();
        let net = Fixtures::default().with(
            "https://archlinux.org/packages/search/json/?name=pacman",
            doc.as_bytes(),
        );
        let r = look("pkg:alpm/arch/pacman", &net).expect("registry");
        assert_eq!(r.ecosystem, Ecosystem::Arch);
        assert_eq!(r.version, "7.1.0-2");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(r.author.as_deref(), Some("eworm"));
        assert_eq!(r.license.as_deref(), Some("GPL-2.0-or-later"));
        assert_eq!(r.maintainers, Some(2));
        assert_eq!(r.deprecated, None);
    }

    #[test]
    fn the_record_is_the_named_package_in_the_named_repository() {
        // The search's first hits are another package and this package in
        // another repository; neither is the record asked for.
        let doc = serde_json::json!({"results": [
            {"pkgname": "pacman-contrib", "repo": "extra", "pkgver": "9"},
            {"pkgname": "pacman", "repo": "core-testing", "pkgver": "8", "flag_date": "2024-01-01"},
            {"pkgname": "pacman", "repo": "evil", "pkgver": "6"},
            {"pkgname": "pacman", "repo": "core", "pkgver": "7"}
        ]})
        .to_string();
        let net = Fixtures::default().with(
            "https://archlinux.org/packages/search/json/?name=pacman",
            doc.as_bytes(),
        );
        let version = |purl: &str| look(purl, &net).map(|r| r.version);
        assert_eq!(version("pkg:alpm/core/pacman").as_deref(), Ok("7"));
        assert_eq!(version("pkg:alpm/core-testing/pacman").as_deref(), Ok("8"));
        // The vendor namespace takes any official repository, stable first.
        assert_eq!(version("pkg:alpm/arch/pacman").as_deref(), Ok("7"));
        assert_eq!(
            version("pkg:alpm/multilib/pacman"),
            Err(RegistryError::NotFound)
        );
        let flagged = look("pkg:alpm/core-testing/pacman", &net).expect("record");
        assert_eq!(flagged.deprecated.as_deref(), Some("flagged out-of-date"));
    }

    #[test]
    fn official_download_uses_matching_name_and_safe_repository() {
        let doc = serde_json::json!({"results": [
            {"pkgname":"bash-extra", "repo":"core", "arch":"x86_64"},
            {"pkgname":"bash", "repo":"../../evil", "arch":"x86_64"},
            {"pkgname":"bash", "repo":"core-testing", "arch":"x86_64"},
            {"pkgname":"bash", "repo":"Core", "arch":"x86_64"}
        ]})
        .to_string();
        let net = Fixtures::default().with(
            "https://archlinux.org/packages/search/json/?name=bash",
            doc.as_bytes(),
        );
        assert_eq!(
            resolve_arch_current("bash", &net, &BlobCache::disabled())
                .ok()
                .as_deref(),
            Some("https://archlinux.org/packages/core/os/x86_64/bash/download/")
        );
        assert!(
            resolve_arch_current("../bash", &net, &BlobCache::disabled())
                .ok()
                .is_none()
        );
    }

    #[test]
    fn the_aur_snapshot_comes_from_the_rpc_or_the_name() {
        let rpc =
            br#"{"results":[{"Name":"yay-bin","URLPath":"/cgit/aur.git/snapshot/yay.tar.gz"}]}"#;
        let hostile = br#"{"results":[{"URLPath":"@evil.test/x.tar.gz"}]}"#;
        let net = Fixtures::default()
            .with(
                "https://aur.archlinux.org/rpc/v5/info?arg%5B%5D=yay-bin",
                rpc,
            )
            .with(
                "https://aur.archlinux.org/rpc/v5/info?arg%5B%5D=bad",
                hostile,
            );
        let cache = BlobCache::disabled();
        assert_eq!(
            resolve_aur("yay-bin", &net, &cache),
            "https://aur.archlinux.org/cgit/aur.git/snapshot/yay.tar.gz"
        );
        assert_eq!(
            resolve_aur("bad", &net, &cache),
            "https://aur.archlinux.org/cgit/aur.git/snapshot/bad.tar.gz"
        );
        assert_eq!(
            resolve_aur("gone", &net, &cache),
            "https://aur.archlinux.org/cgit/aur.git/snapshot/gone.tar.gz"
        );
    }
}
