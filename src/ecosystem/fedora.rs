//! Fedora: registry metadata and artifact resolution.

use filefacts::Registry;
use serde::Deserialize;

use crate::ecosystem::fetch_json;
use crate::fetch::{BlobCache, Fetch};
use crate::registry::RegistryError;

/// Fedora (Rawhide via mdapi): the per-package record carries the version,
/// summary, and homepage. mdapi reports no build time, so age stays unknown.
pub(crate) fn fedora(
    name: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let doc: Package = fetch_json(
        &format!("https://mdapi.fedoraproject.org/rawhide/pkg/{name}"),
        net,
        cache,
    )?;
    let version = match (doc.version.as_deref(), doc.release.as_deref()) {
        (Some(v), Some(rel)) => format!("{v}-{rel}"),
        (Some(v), None) => v.to_string(),
        _ => String::new(),
    };

    Ok(Registry {
        ecosystem: "fedora".into(),
        name: doc.basename.unwrap_or_else(|| name.to_string()),
        version,
        description: doc.summary.or(doc.description),
        homepage: doc.url,
        license: doc.license.filter(|s| !s.is_empty()),
        ..Default::default()
    })
}

/// The parts of an mdapi package record the registry record reads.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Package {
    basename: Option<String>,
    version: Option<String>,
    release: Option<String>,
    summary: Option<String>,
    description: Option<String>,
    url: Option<String>,
    license: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::test_cache;

    use crate::fetch::Fixtures;

    #[test]
    fn fedora_mdapi_normalizes() {
        let doc = serde_json::json!({
            "basename": "curl", "version": "8.21.0", "release": "3.fc45",
            "summary": "A command line tool for transferring data", "license": "curl",
            "url": "https://curl.se/"
        })
        .to_string();
        let net = Fixtures::default().with(
            "https://mdapi.fedoraproject.org/rawhide/pkg/curl",
            doc.as_bytes(),
        );
        let r = fedora("curl", &net, &test_cache("fedora")).expect("registry");
        assert_eq!(r.ecosystem, "fedora");
        assert_eq!(r.version, "8.21.0-3.fc45");
        assert_eq!(r.homepage.as_deref(), Some("https://curl.se/"));
        assert_eq!(r.published_at, None);
    }
}
