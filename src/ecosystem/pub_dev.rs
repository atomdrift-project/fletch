//! Pub.dev: registry metadata and artifact resolution.

use filefacts::Registry;
use serde::Deserialize;

use crate::ecosystem::{fetch_json, null_default, parse_ts};
use crate::fetch::{BlobCache, Fetch, percent_decode};
use crate::registry::RegistryError;

/// pub.dev: the package endpoint carries the latest release inline and every
/// version under `versions[]`, each with its `published` time and pubspec.
pub(crate) fn pub_dev(
    name: &str,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let doc: Package = fetch_json(&format!("https://pub.dev/api/packages/{name}"), net, cache)?;
    let latest = doc.latest.as_ref().and_then(|l| l.version.as_deref());
    let requested = version.map(percent_decode);
    // A version the list lacks describes no release: it gets no date rather
    // than latest's, though its identity text still comes from latest's
    // pubspec.
    let rel = match requested.as_deref() {
        Some(want) => doc
            .versions
            .iter()
            .find(|v| v.version.as_deref() == Some(want)),
        None => doc.latest.as_ref(),
    };
    let spec = rel.or(doc.latest.as_ref()).and_then(|r| r.pubspec.as_ref());

    Ok(Registry {
        ecosystem: "pub".into(),
        name: name.to_string(),
        version: rel
            .and_then(|r| r.version.clone())
            .or(requested)
            .unwrap_or_default(),
        published_at: rel.and_then(|r| r.published.as_deref()).and_then(parse_ts),
        latest_version: latest.map(str::to_string),
        description: spec.and_then(|s| s.description.clone()),
        homepage: spec.and_then(|s| s.homepage.clone()),
        repository: spec.and_then(|s| s.repository.clone()),
        ..Default::default()
    })
}

/// The parts of a pub.dev package document the registry record reads.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Package {
    latest: Option<PackageVersion>,
    #[serde(deserialize_with = "null_default")]
    versions: Vec<PackageVersion>,
}

/// One published version: its number, publish time, and pubspec.
#[derive(Default, Deserialize)]
#[serde(default)]
struct PackageVersion {
    version: Option<String>,
    published: Option<String>,
    pubspec: Option<Pubspec>,
}

/// The parts of a version's pubspec the registry record reads.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Pubspec {
    description: Option<String>,
    homepage: Option<String>,
    repository: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::test_cache;

    use crate::fetch::Fixtures;

    #[test]
    fn pub_dev_normalizes() {
        let doc = serde_json::json!({
            "name": "http",
            "latest": {"version": "1.6.0", "published": "2021-04-23T10:00:00.000000Z",
                       "pubspec": {"description": "Future-based HTTP requests",
                                   "repository": "https://github.com/dart-lang/http"}},
            "versions": [{"version": "1.6.0", "published": "2021-04-23T10:00:00.000000Z",
                          "pubspec": {"description": "Future-based HTTP requests",
                                      "repository": "https://github.com/dart-lang/http"}}]
        })
        .to_string();
        let net = Fixtures::default().with("https://pub.dev/api/packages/http", doc.as_bytes());
        let r = pub_dev("http", None, &net, &test_cache("pub")).expect("registry");
        assert_eq!(r.ecosystem, "pub");
        assert_eq!(r.version, "1.6.0");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(
            r.repository.as_deref(),
            Some("https://github.com/dart-lang/http")
        );
    }
}
