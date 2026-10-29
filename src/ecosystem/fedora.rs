//! Fedora packages: registry metadata.

use filefacts::{Ecosystem, Registry};
use serde::Deserialize;

use crate::ecosystem::{Coordinates, fetch_json, non_empty};
use crate::fetch::{BlobCache, Fetch};
use crate::registry::RegistryError;

/// Fedora (Rawhide via mdapi): the per-package record carries the current
/// `version-release`, summary, and homepage. mdapi reports no build time, so
/// age stays unknown.
pub(crate) fn lookup(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let doc: Package = fetch_json(
        &format!(
            "https://mdapi.fedoraproject.org/rawhide/pkg/{}",
            c.encoded_name()
        ),
        net,
        cache,
    )?;
    let latest = doc.version.map(|v| match doc.release {
        Some(release) => format!("{v}-{release}"),
        None => v,
    });
    let mut registry = Registry::new(
        Ecosystem::Fedora,
        doc.basename.unwrap_or_else(|| c.name().to_string()),
    );
    registry.version = c.target(latest.as_deref()).to_string();
    registry.latest_version = latest;
    registry.description = doc.summary.or(doc.description);
    registry.homepage = doc.url;
    registry.license = doc.license;
    Ok(registry)
}

/// The parts of an mdapi package record the registry record reads.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Package {
    #[serde(deserialize_with = "non_empty")]
    basename: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    version: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    release: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    summary: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    description: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    url: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    license: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use filefacts::RefLocator;

    use crate::fetch::Fixtures;

    fn curl() -> Fixtures {
        let doc = serde_json::json!({
            "basename": "curl", "version": "8.21.0", "release": "3.fc45",
            "summary": "A command line tool for transferring data", "license": "curl",
            "url": "https://curl.se/"
        })
        .to_string();
        Fixtures::default().with(
            "https://mdapi.fedoraproject.org/rawhide/pkg/curl",
            doc.as_bytes(),
        )
    }

    fn look(purl: &str) -> Registry {
        crate::registry::lookup(
            &RefLocator::Purl(purl.into()),
            &curl(),
            &BlobCache::disabled(),
        )
        .expect("registry")
    }

    #[test]
    fn fedora_mdapi_normalizes() {
        let r = look("pkg:rpm/fedora/curl");
        assert_eq!(r.ecosystem, Ecosystem::Fedora);
        assert_eq!(r.version, "8.21.0-3.fc45");
        assert_eq!(r.latest_version.as_deref(), Some("8.21.0-3.fc45"));
        assert_eq!(r.homepage.as_deref(), Some("https://curl.se/"));
        assert_eq!(r.license.as_deref(), Some("curl"));
        assert_eq!(r.published_at, None);
    }

    #[test]
    fn a_requested_version_is_the_record_version() {
        let r = look("pkg:rpm/fedora/curl@8.0.0-1.fc40");
        assert_eq!(r.version, "8.0.0-1.fc40");
        assert_eq!(r.latest_version.as_deref(), Some("8.21.0-3.fc45"));
    }
}
