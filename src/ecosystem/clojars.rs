//! Clojars: registry metadata and artifact resolution.

use filefacts::Registry;
use serde::Deserialize;

use crate::ecosystem::{fetch_json, null_default};
use crate::fetch::{BlobCache, Fetch};
use crate::registry::RegistryError;

/// Clojars: the artifacts API returns lifetime downloads, the SCM link, and the
/// license, but no publish date — so `published_at` stays unknown.
pub(crate) fn clojars(
    path: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let doc: Artifact = fetch_json(
        &format!("https://clojars.org/api/artifacts/{path}"),
        net,
        cache,
    )?;
    let name = match (doc.group_name.as_deref(), doc.jar_name.as_deref()) {
        (Some(g), Some(j)) if g != j => format!("{g}/{j}"),
        (_, Some(j)) => j.to_string(),
        _ => path.to_string(),
    };

    Ok(Registry {
        ecosystem: "clojars".into(),
        name,
        // An artifact with only snapshots has a `null` latest release; its
        // newest snapshot is then the version there is.
        version: doc
            .latest_release
            .or_else(|| doc.latest_version.clone())
            .unwrap_or_default(),
        latest_version: doc.latest_version,
        description: doc.description,
        homepage: doc.homepage,
        repository: doc.scm.and_then(|scm| scm.url),
        license: doc.licenses.into_iter().next().and_then(|l| l.name),
        downloads_total: doc.downloads,
        ..Default::default()
    })
}

/// The parts of a Clojars artifact document the registry record reads.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Artifact {
    group_name: Option<String>,
    jar_name: Option<String>,
    latest_release: Option<String>,
    latest_version: Option<String>,
    description: Option<String>,
    homepage: Option<String>,
    scm: Option<Scm>,
    #[serde(deserialize_with = "null_default")]
    licenses: Vec<License>,
    downloads: Option<u64>,
}

/// The artifact's `scm` block, read for its `url`.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Scm {
    url: Option<String>,
}

/// One entry of the artifact's `licenses` list.
#[derive(Default, Deserialize)]
#[serde(default)]
struct License {
    name: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::test_cache;

    use crate::fetch::Fixtures;

    #[test]
    fn clojars_artifacts_normalizes() {
        let doc = serde_json::json!({
            "group_name": "ring", "jar_name": "ring", "latest_release": "1.15.5",
            "latest_version": "1.15.5", "description": "A Clojure web library",
            "homepage": "https://github.com/ring-clojure/ring", "downloads": 11_285_905u64,
            "scm": {"url": "https://github.com/ring-clojure/ring"},
            "licenses": [{"name": "The MIT License"}]
        })
        .to_string();
        let net =
            Fixtures::default().with("https://clojars.org/api/artifacts/ring", doc.as_bytes());
        let r = clojars("ring", &net, &test_cache("clojars")).expect("registry");
        assert_eq!(r.ecosystem, "clojars");
        assert_eq!(r.name, "ring");
        assert_eq!(r.version, "1.15.5");
        assert_eq!(r.license.as_deref(), Some("The MIT License"));
        assert_eq!(r.downloads_total, Some(11_285_905));
        assert_eq!(r.published_at, None);
    }
}
