//! Arch Linux and the AUR: registry metadata and artifact resolution.

use filefacts::Registry;
use serde::Deserialize;
use serde::de::IgnoredAny;

use crate::ecosystem::{fetch_json, null_default, parse_ts};
use crate::fetch::{BlobCache, Fetch, cached_metadata};
use crate::registry::RegistryError;

/// The AUR snapshot URL for `name`: ask the (cached) RPC for the package's
/// `URLPath`, which names the pkgbase snapshot. Falls back to the name-derived
/// snapshot path — correct whenever pkgbase == name — when the RPC is
/// unreachable or names no such package, so an RPC blip can't kill a fetch that
/// would have succeeded; a genuinely absent package then 404s at the snapshot,
/// recording a failed fetch rather than an unresolvable locator.
pub(crate) fn resolve_aur(name: &str, net: &dyn Fetch, cache: &BlobCache) -> String {
    let api = format!("https://aur.archlinux.org/rpc/v5/info?arg%5B%5D={name}");
    cached_metadata(&api, net, cache)
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|doc| {
            Some(format!(
                "https://aur.archlinux.org{}",
                doc.pointer("/results/0/URLPath")?.as_str()?
            ))
        })
        .unwrap_or_else(|| format!("https://aur.archlinux.org/cgit/aur.git/snapshot/{name}.tar.gz"))
}

/// AUR: the RPC `info` endpoint. The AUR has no downloads; its custody signal
/// is the maintainer plus vote count and popularity score, and `LastModified`
/// (when the PKGBUILD last changed) is the supply-chain-relevant "age". Official
/// repo packages aren't in the AUR, so they return an empty result → `NotFound`.
pub(crate) fn aur(
    name: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let url = format!("https://aur.archlinux.org/rpc/v5/info?arg%5B%5D={name}");
    let doc: AurInfo = fetch_json(&url, net, cache)?;
    let r = doc
        .results
        .into_iter()
        .next()
        .ok_or(RegistryError::NotFound)?;

    Ok(Registry {
        ecosystem: "aur".into(),
        name: r.name.clone().unwrap_or_else(|| name.to_string()),
        version: r.version.unwrap_or_default(),
        // LastModified is a Unix-seconds integer already.
        published_at: r.last_modified,
        // FirstSubmitted is the package's birth; the gap to LastModified is the
        // dormancy a revived abandoned package would show.
        first_published_at: r.first_submitted,
        // The primary maintainer plus any co-maintainers — the custody set.
        maintainers: Some(u32::from(r.maintainer.is_some()) + r.co_maintainers.len() as u32),
        author: r.maintainer.clone(),
        publisher: r.maintainer,
        title: r.name,
        description: r.description,
        homepage: r.url,
        rating: r.popularity.map(|f| f as f32),
        rating_count: r.num_votes,
        deprecated: r
            .out_of_date
            .and_then(|t| (t > 0).then(|| "flagged out-of-date".to_string())),
        ..Default::default()
    })
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
    popularity: Option<f64>,
    num_votes: Option<u64>,
    out_of_date: Option<u64>,
}

/// Arch Linux official repositories: the packages site exposes a JSON search.
/// Recency comes from `last_update`; an out-of-date flag is the deprecation
/// analogue. AUR-only packages aren't here, so they are `NotFound`.
pub(crate) fn arch(
    name: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let doc: ArchSearch = fetch_json(
        &format!("https://archlinux.org/packages/search/json/?name={name}"),
        net,
        cache,
    )?;
    let r = doc
        .results
        .into_iter()
        .next()
        .ok_or(RegistryError::NotFound)?;
    let version = match (r.pkgver.as_deref(), r.pkgrel.as_deref()) {
        (Some(v), Some(rel)) => format!("{v}-{rel}"),
        (Some(v), None) => v.to_string(),
        _ => String::new(),
    };

    Ok(Registry {
        ecosystem: "arch".into(),
        name: r.pkgname.unwrap_or_else(|| name.to_string()),
        version,
        published_at: r
            .last_update
            .as_deref()
            .or(r.build_date.as_deref())
            .and_then(parse_ts),
        author: r.packager,
        description: r.pkgdesc,
        homepage: r.url,
        license: r.licenses.into_iter().next(),
        maintainers: r.maintainers.map(|m| m.len() as u32),
        deprecated: r.flag_date.map(|_| "flagged out-of-date".to_string()),
        ..Default::default()
    })
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
    use crate::ecosystem::test_cache;
    use crate::fetch::ArtifactTarget;
    use crate::fetch::SelectionPolicy;
    use crate::fetch::resolve_artifacts;
    use filefacts::RefLocator;

    use crate::fetch::{BlobCache, Fixtures};

    #[test]
    fn selector_enforces_npm_os_cpu_and_libc_constraints() {
        let body = br#"{"versions":{"1.0.0":{"os":["linux","!darwin"],"cpu":["x64"],"libc":"glibc","dist":{"tarball":"https://x/native.tgz"}}}}"#;
        let net = Fixtures::default().with("https://registry.npmjs.org/native", body);
        let matrix = resolve_artifacts(
            &RefLocator::Purl("pkg:npm/native@1.0.0".into()),
            &net,
            &BlobCache::disabled(),
        )
        .expect("npm matrix");
        let linux = ArtifactTarget {
            os: Some("linux".into()),
            arch: Some("x86_64".into()),
            libc: Some("glibc".into()),
            ..ArtifactTarget::default()
        };
        assert!(matrix.select(&linux, &SelectionPolicy::default()).is_some());
        let mac = ArtifactTarget {
            os: Some("darwin".into()),
            ..linux
        };
        assert!(matrix.select(&mac, &SelectionPolicy::default()).is_none());
    }

    #[test]
    fn aur_rpc_maps_votes_and_modified() {
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
        let cache = BlobCache::disabled();
        let p = aur("yay", &net, &cache).expect("provenance");
        assert_eq!(p.ecosystem, "aur");
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
    fn arch_packages_normalizes() {
        let doc = serde_json::json!({"results": [{
            "pkgname": "pacman", "pkgver": "7.1.0", "pkgrel": "2",
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
        let r = arch("pacman", &net, &test_cache("arch")).expect("registry");
        assert_eq!(r.ecosystem, "arch");
        assert_eq!(r.version, "7.1.0-2");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(r.author.as_deref(), Some("eworm"));
        assert_eq!(r.maintainers, Some(2));
        assert_eq!(r.deprecated, None);
    }
}
