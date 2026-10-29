//! Pub.dev: registry metadata.

use filefacts::{Ecosystem, Registry};
use serde::Deserialize;

use crate::ecosystem::{Coordinates, fetch_json, non_empty, null_default, unix_secs};
use crate::fetch::{BlobCache, Fetch};
use crate::registry::RegistryError;

/// pub.dev's package document: the latest release inline and every version
/// under `versions[]`, each with its `published` time, its `retracted` flag,
/// and its pubspec.
pub(crate) fn lookup(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let name = c.bare_name(&[])?;
    let doc: Package = fetch_json(&format!("https://pub.dev/api/packages/{name}"), net, cache)?;
    let latest = doc.latest.as_ref().and_then(|l| l.version.as_deref());
    // A version the list lacks describes no release: it gets no date rather
    // than latest's, though its identity text still comes from latest's
    // pubspec.
    let release = match c.version() {
        Some(want) => doc
            .versions
            .iter()
            .find(|v| v.version.as_deref() == Some(want)),
        None => doc.latest.as_ref(),
    };
    if release.is_none() {
        tracing::debug!(
            package = %c.name().escape_debug(),
            version = %c.target(latest).escape_debug(),
            "pub.dev version not listed; leaving it undated"
        );
    }
    let spec = release
        .or(doc.latest.as_ref())
        .and_then(|r| r.pubspec.as_ref());

    let mut registry = Registry::new(Ecosystem::Pub, c.name().to_string());
    registry.version = c.target(latest).to_string();
    registry.published_at = release
        .and_then(|r| r.published.as_deref())
        .and_then(unix_secs);
    registry.latest_version = latest.map(str::to_string);
    registry.description = spec.and_then(|s| s.description.clone());
    registry.homepage = spec.and_then(|s| s.homepage.clone());
    registry.repository = spec.and_then(|s| s.repository.clone());
    // pub.dev sends `retracted` only for a retracted version, so a listed
    // version without it is live.
    registry.version_removed = release.map(|r| r.retracted);
    Ok(registry)
}

/// The parts of a pub.dev package document the registry record reads.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Package {
    latest: Option<PackageVersion>,
    #[serde(deserialize_with = "null_default")]
    versions: Vec<PackageVersion>,
}

/// One published version: its number, publish time, retraction, and pubspec.
#[derive(Default, Deserialize)]
#[serde(default)]
struct PackageVersion {
    version: Option<String>,
    published: Option<String>,
    #[serde(deserialize_with = "null_default")]
    retracted: bool,
    pubspec: Option<Pubspec>,
}

/// The parts of a version's pubspec the registry record reads.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Pubspec {
    #[serde(deserialize_with = "non_empty")]
    description: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    homepage: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    repository: Option<String>,
}

#[cfg(test)]
mod tests {
    use crate::fetch::{BlobCache, Fixtures};
    use crate::registry::lookup;
    use filefacts::{Ecosystem, RefLocator};

    #[test]
    fn pub_dev_normalizes() {
        let release = |version: &str, published: &str| {
            serde_json::json!({"version": version, "published": published,
                "pubspec": {"description": "Future-based HTTP requests",
                            "repository": "https://github.com/dart-lang/http", "homepage": ""}})
        };
        let mut retracted = release("1.5.0", "2020-01-01T00:00:00.000000Z");
        retracted["retracted"] = true.into();
        let doc = serde_json::json!({
            "name": "http",
            "latest": release("1.6.0", "2021-04-23T10:00:00.000000Z"),
            "versions": [retracted, release("1.6.0", "2021-04-23T10:00:00.000000Z")]
        })
        .to_string();
        let net = Fixtures::default().with("https://pub.dev/api/packages/http", doc.as_bytes());
        let look = |purl: &str| {
            lookup(&RefLocator::Purl(purl.into()), &net, &BlobCache::disabled()).expect("registry")
        };
        let r = look("pkg:pub/http");
        assert_eq!(r.ecosystem, Ecosystem::Pub);
        assert_eq!(r.version, "1.6.0");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(
            r.repository.as_deref(),
            Some("https://github.com/dart-lang/http")
        );
        assert_eq!(r.homepage, None, "an empty homepage is unknown");
        assert_eq!(r.version_removed, Some(false));

        let r = look("pkg:pub/http@1.5.0");
        assert_eq!(r.version, "1.5.0");
        assert_eq!(r.version_removed, Some(true), "a retracted version");
    }
}
