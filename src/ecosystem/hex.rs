//! Hex: registry metadata.

use filefacts::{Ecosystem, Registry};
use serde::Deserialize;
use std::collections::BTreeMap;

use crate::ecosystem::{Coordinates, fetch_json, non_empty, null_default, unix_secs};
use crate::fetch::{BlobCache, Fetch};
use crate::registry::RegistryError;

/// hex.pm's package document: downloads and links, every release with its own
/// `inserted_at` publish time, and the retired releases keyed by version. A
/// namespace other than `hexpm` names a private organization's repository,
/// which the public document does not describe.
pub(crate) fn lookup(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let name = c.bare_name(&["hexpm"])?;
    let doc: Package = fetch_json(&format!("https://hex.pm/api/packages/{name}"), net, cache)?;
    // A package with no stable release has a `null` latest stable version;
    // its newest pre-release is then the latest there is.
    let latest = doc
        .latest_stable_version
        .as_deref()
        .or(doc.latest_version.as_deref());
    let version = c.target(latest);
    // A version the releases list lacks gets no date rather than the newest
    // release's; the package's own `inserted_at` is its first release.
    let release = doc
        .releases
        .iter()
        .find(|r| r.version.as_deref() == Some(version));
    if release.is_none() {
        tracing::debug!(
            package = %c.name().escape_debug(),
            version = %version.escape_debug(),
            "hex release not listed; leaving it undated"
        );
    }
    let retirement = doc.retirements.as_ref().and_then(|r| r.get(version));
    // Only a listed release in a document that reports retirements is known
    // to be live.
    let version_removed = match (retirement, release, &doc.retirements) {
        (Some(_), _, _) => Some(true),
        (None, Some(_), Some(_)) => Some(false),
        _ => None,
    };
    let deprecated = retirement
        .filter(|r| r.reason.as_deref() == Some("deprecated"))
        .map(|r| {
            r.message
                .clone()
                .unwrap_or_else(|| "deprecated".to_string())
        });

    let mut registry = Registry::new(Ecosystem::Hex, c.name().to_string());
    registry.version = version.to_string();
    registry.published_at = release
        .and_then(|r| r.inserted_at.as_deref())
        .and_then(unix_secs);
    registry.first_published_at = doc.inserted_at.as_deref().and_then(unix_secs);
    registry.latest_version = latest.map(str::to_string);
    registry.description = doc.meta.description;
    registry.license = doc.meta.licenses.into_iter().next();
    registry.repository = links_repo(&doc.meta.links);
    registry.downloads_total = doc.downloads.all;
    registry.downloads_recent = doc.downloads.recent;
    registry.deprecated = deprecated;
    registry.version_removed = version_removed;
    Ok(registry)
}

/// The source repository in a package's free-form `links` map: the first
/// forge or repository link by its conventional key. `None` when there is
/// none — any other link (docs, a changelog, a sponsor page) is not the
/// source.
fn links_repo(links: &BTreeMap<String, String>) -> Option<String> {
    [
        "GitHub",
        "Github",
        "github",
        "GitLab",
        "Repository",
        "Source",
    ]
    .iter()
    .find_map(|key| links.get(*key))
    .cloned()
}

/// The parts of a hex.pm package document the registry record reads.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Package {
    latest_stable_version: Option<String>,
    latest_version: Option<String>,
    inserted_at: Option<String>,
    #[serde(deserialize_with = "null_default")]
    releases: Vec<Release>,
    /// The retired releases, keyed by version.
    retirements: Option<BTreeMap<String, Retirement>>,
    #[serde(deserialize_with = "null_default")]
    meta: Meta,
    #[serde(deserialize_with = "null_default")]
    downloads: Downloads,
}

/// One entry of the package's release list.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Release {
    version: Option<String>,
    inserted_at: Option<String>,
}

/// Why a release was retired: `reason` is one of `other`, `invalid`,
/// `security`, `deprecated` or `renamed`.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Retirement {
    reason: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    message: Option<String>,
}

/// The publisher-supplied `meta` block.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Meta {
    #[serde(deserialize_with = "non_empty")]
    description: Option<String>,
    #[serde(deserialize_with = "null_default")]
    licenses: Vec<String>,
    #[serde(deserialize_with = "null_default")]
    links: BTreeMap<String, String>,
}

/// The `downloads` counters.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Downloads {
    all: Option<u64>,
    recent: Option<u64>,
}

#[cfg(test)]
mod tests {
    use crate::fetch::{BlobCache, Fixtures};
    use crate::registry::{RegistryError, lookup};
    use filefacts::{Ecosystem, RefLocator, Registry};

    fn look(net: &Fixtures, purl: &str) -> Result<Registry, RegistryError> {
        lookup(&RefLocator::Purl(purl.into()), net, &BlobCache::disabled())
    }

    fn package(doc: &serde_json::Value) -> Fixtures {
        Fixtures::default().with(
            "https://hex.pm/api/packages/plug",
            doc.to_string().as_bytes(),
        )
    }

    #[test]
    fn hex_api_normalizes() {
        let net = package(&serde_json::json!({
            "latest_stable_version": "1.20.1",
            "downloads": {"all": 159_722_813u64, "recent": 3_812_427u64},
            "meta": {"description": "Compose web applications", "licenses": ["Apache-2.0"],
                     "links": {"GitHub": "https://github.com/elixir-plug/plug"}},
            "releases": [{"version": "1.20.1", "inserted_at": "2021-04-23T10:00:00.000000Z"}],
            "retirements": {}
        }));
        let r = look(&net, "pkg:hex/plug").expect("registry");
        assert_eq!(r.ecosystem, Ecosystem::Hex);
        assert_eq!(r.version, "1.20.1");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(r.license.as_deref(), Some("Apache-2.0"));
        assert_eq!(
            r.repository.as_deref(),
            Some("https://github.com/elixir-plug/plug")
        );
        assert_eq!(r.downloads_total, Some(159_722_813));
        assert_eq!(r.version_removed, Some(false));
        assert_eq!(r.deprecated, None);
    }

    #[test]
    fn a_retired_release_is_removed_and_a_deprecated_one_says_why() {
        let net = package(&serde_json::json!({
            "latest_stable_version": "1.20.3",
            "releases": [
                {"version": "1.20.3", "inserted_at": "2026-07-09T09:42:46Z"},
                {"version": "1.20.1", "inserted_at": "2025-01-01T00:00:00Z"},
                {"version": "1.0.0", "inserted_at": "2016-01-01T00:00:00Z"},
                {"version": "0.9.0", "inserted_at": "2015-06-01T00:00:00Z"}
            ],
            "retirements": {
                "1.20.1": {"reason": "invalid", "message": "Accidental breaking change"},
                "1.0.0": {"reason": "deprecated", "message": "Use 1.20 instead"},
                "0.9.0": {"reason": "deprecated", "message": null}
            }
        }));
        let r = look(&net, "pkg:hex/plug@1.20.1").expect("registry");
        assert_eq!(r.version_removed, Some(true));
        assert_eq!(r.deprecated, None, "a retirement that is not a deprecation");

        let r = look(&net, "pkg:hex/plug@1.0.0").expect("registry");
        assert_eq!(r.version_removed, Some(true));
        assert_eq!(r.deprecated.as_deref(), Some("Use 1.20 instead"));

        let r = look(&net, "pkg:hex/plug@0.9.0").expect("registry");
        assert_eq!(r.deprecated.as_deref(), Some("deprecated"));

        let r = look(&net, "pkg:hex/plug").expect("registry");
        assert_eq!(r.version, "1.20.3");
        assert_eq!(r.version_removed, Some(false));
    }

    #[test]
    fn only_a_source_link_is_the_repository() {
        let net = package(&serde_json::json!({
            "latest_stable_version": "1.0.0",
            "meta": {"links": {"Changelog": "https://example.test/changes",
                               "Docs": "https://example.test/docs"}}
        }));
        assert_eq!(
            look(&net, "pkg:hex/plug").expect("registry").repository,
            None
        );
    }

    #[test]
    fn a_private_organization_is_not_the_public_package() {
        let net = package(&serde_json::json!({"latest_stable_version": "1.0.0"}));
        assert_eq!(
            look(&net, "pkg:hex/acme/plug"),
            Err(RegistryError::OffRegistry)
        );
        assert!(look(&net, "pkg:hex/hexpm/plug").is_ok());
    }
}
