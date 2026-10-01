//! Hex: registry metadata and artifact resolution.

use filefacts::Registry;
use serde::Deserialize;
use std::collections::BTreeMap;

use crate::ecosystem::{fetch_json, null_default, parse_ts, present};
use crate::fetch::{BlobCache, Fetch, percent_decode};
use crate::registry::RegistryError;

/// hex.pm: a clean JSON API. The package doc carries downloads and links; each
/// entry in the release list has its own `inserted_at` publish time.
pub(crate) fn hex_pm(
    name: &str,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let doc: Package = fetch_json(&format!("https://hex.pm/api/packages/{name}"), net, cache)?;
    // `latest_version` stands in only when `latest_stable_version` is absent;
    // a `null` stable version stays unknown.
    let latest = doc
        .latest_stable_version
        .as_ref()
        .unwrap_or(&doc.latest_version)
        .as_deref();
    let requested = version.map(percent_decode);
    let version = requested.as_deref().or(latest).unwrap_or_default();
    // A version the releases list lacks gets no date rather than the newest
    // release's; the package's own `inserted_at` is its first release.
    let published_at = doc
        .releases
        .iter()
        .find(|r| r.version.as_deref() == Some(version))
        .and_then(|r| r.inserted_at.as_deref())
        .and_then(parse_ts);

    Ok(Registry {
        ecosystem: "hex".into(),
        name: name.to_string(),
        version: version.to_string(),
        published_at,
        first_published_at: doc.inserted_at.as_deref().and_then(parse_ts),
        latest_version: latest.map(str::to_string),
        description: doc.meta.description,
        license: doc.meta.licenses.into_iter().next(),
        repository: links_repo(&doc.meta.links),
        downloads_total: doc.downloads.all,
        downloads_recent: doc.downloads.recent,
        ..Default::default()
    })
}

/// Pick a source-repository URL from a registry's free-form links map (hex.pm),
/// preferring a forge link, else any value.
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
    .or_else(|| links.values().next())
    .cloned()
}

/// The parts of a hex.pm package document the registry record reads.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Package {
    #[serde(deserialize_with = "present")]
    latest_stable_version: Option<Option<String>>,
    latest_version: Option<String>,
    inserted_at: Option<String>,
    #[serde(deserialize_with = "null_default")]
    releases: Vec<Release>,
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

/// The publisher-supplied `meta` block.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Meta {
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
    use super::*;
    use crate::ecosystem::test_cache;

    use crate::fetch::Fixtures;

    #[test]
    fn hex_api_normalizes() {
        let doc = serde_json::json!({
            "latest_stable_version": "1.20.1",
            "downloads": {"all": 159_722_813u64, "recent": 3_812_427u64},
            "meta": {"description": "Compose web applications", "licenses": ["Apache-2.0"],
                     "links": {"GitHub": "https://github.com/elixir-plug/plug"}},
            "releases": [{"version": "1.20.1", "inserted_at": "2021-04-23T10:00:00.000000Z"}]
        })
        .to_string();
        let net = Fixtures::default().with("https://hex.pm/api/packages/plug", doc.as_bytes());
        let r = hex_pm("plug", None, &net, &test_cache("hex")).expect("registry");
        assert_eq!(r.ecosystem, "hex");
        assert_eq!(r.version, "1.20.1");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(r.license.as_deref(), Some("Apache-2.0"));
        assert_eq!(
            r.repository.as_deref(),
            Some("https://github.com/elixir-plug/plug")
        );
        assert_eq!(r.downloads_total, Some(159_722_813));
    }
}
