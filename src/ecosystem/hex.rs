//! Hex: registry metadata and artifact resolution.

use filefacts::Registry;
use serde_json::Value;

use crate::ecosystem::{json_meta, parse_ts};
use crate::fetch::{BlobCache, Fetch, percent_decode};

/// hex.pm: a clean JSON API. The package doc carries downloads and links; each
/// entry in the release list has its own `inserted_at` publish time.
pub(crate) fn hex_pm(
    name: &str,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Option<Registry> {
    let doc = json_meta(&format!("https://hex.pm/api/packages/{name}"), net, cache)?;
    let latest = doc
        .get("latest_stable_version")
        .or_else(|| doc.get("latest_version"))
        .and_then(Value::as_str);
    let requested = version.map(percent_decode);
    let version = requested.as_deref().or(latest).unwrap_or_default();
    // A version the releases list lacks gets no date rather than the newest
    // release's; the package's own `inserted_at` is its first release.
    let published_at = doc
        .get("releases")
        .and_then(Value::as_array)
        .and_then(|rs| {
            rs.iter()
                .find(|r| r.get("version").and_then(Value::as_str) == Some(version))?
                .get("inserted_at")
                .and_then(Value::as_str)
                .and_then(parse_ts)
        });
    let meta = doc.get("meta");

    Some(Registry {
        ecosystem: "hex".into(),
        name: name.to_string(),
        version: version.to_string(),
        published_at,
        first_published_at: doc
            .get("inserted_at")
            .and_then(Value::as_str)
            .and_then(parse_ts),
        latest_version: latest.map(str::to_string),
        description: meta
            .and_then(|m| m.get("description"))
            .and_then(Value::as_str)
            .map(str::to_string),
        license: meta
            .and_then(|m| m.pointer("/licenses/0"))
            .and_then(Value::as_str)
            .map(str::to_string),
        repository: meta.and_then(|m| m.get("links")).and_then(links_repo),
        downloads_total: doc.pointer("/downloads/all").and_then(Value::as_u64),
        downloads_recent: doc.pointer("/downloads/recent").and_then(Value::as_u64),
        ..Default::default()
    })
}

/// Pick a source-repository URL from a registry's free-form links map (hex.pm),
/// preferring a forge link, else any value.
fn links_repo(links: &Value) -> Option<String> {
    let map = links.as_object()?;
    for key in [
        "GitHub",
        "Github",
        "github",
        "GitLab",
        "Repository",
        "Source",
    ] {
        if let Some(u) = map.get(key).and_then(Value::as_str) {
            return Some(u.to_string());
        }
    }
    map.values()
        .filter_map(Value::as_str)
        .next()
        .map(str::to_string)
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
