//! Clojars: registry metadata.

use filefacts::{Ecosystem, Registry};
use serde::Deserialize;

use crate::ecosystem::{Coordinates, fetch_json, non_empty, null_default};
use crate::fetch::{BlobCache, Fetch};
use crate::registry::RegistryError;

/// Clojars' artifacts API: lifetime downloads, the SCM link, and the license,
/// but no publish dates, so `published_at` stays unknown. An artifact is
/// `group/artifact`, or its bare name when the group is the same.
pub(crate) fn lookup(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let path = match c.namespace() {
        [] => c.encoded_name().to_string(),
        _ => {
            let (group, artifact) = c.pair()?;
            format!("{group}/{artifact}")
        }
    };
    let doc: Artifact = fetch_json(
        &format!("https://clojars.org/api/artifacts/{path}"),
        net,
        cache,
    )?;
    let name = match (doc.group_name.as_deref(), doc.jar_name.as_deref()) {
        (Some(g), Some(j)) if g != j => format!("{g}/{j}"),
        (_, Some(j)) => j.to_string(),
        _ => c.full_name(),
    };
    // An artifact with only snapshots has a `null` latest release; its newest
    // snapshot is then the version there is.
    let latest = doc.latest_release.or(doc.latest_version);

    let mut record = c.record(Ecosystem::Clojars, name, latest);
    record.description = doc.description;
    record.homepage = doc.homepage;
    record.repository = doc.scm.and_then(|scm| scm.url);
    record.license = doc.licenses.into_iter().find_map(|l| l.name);
    record.downloads_total = doc.downloads;
    Ok(record)
}

/// The parts of a Clojars artifact document the registry record reads.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Artifact {
    group_name: Option<String>,
    jar_name: Option<String>,
    latest_release: Option<String>,
    latest_version: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    description: Option<String>,
    #[serde(deserialize_with = "non_empty")]
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
    #[serde(deserialize_with = "non_empty")]
    url: Option<String>,
}

/// One entry of the artifact's `licenses` list.
#[derive(Default, Deserialize)]
#[serde(default)]
struct License {
    #[serde(deserialize_with = "non_empty")]
    name: Option<String>,
}

#[cfg(test)]
mod tests {
    use crate::ecosystem::look;
    use crate::fetch::Fixtures;
    use crate::registry::RegistryError;
    use filefacts::Ecosystem;

    #[test]
    fn clojars_artifacts_normalizes() {
        let doc = serde_json::json!({
            "group_name": "ring", "jar_name": "ring", "latest_release": "1.15.5",
            "latest_version": "1.16.0-SNAPSHOT", "description": "A Clojure web library",
            "homepage": "https://github.com/ring-clojure/ring", "downloads": 11_285_905u64,
            "scm": {"url": "https://github.com/ring-clojure/ring"},
            "licenses": [{"name": "The MIT License"}]
        })
        .to_string();
        let net = Fixtures::default()
            .with("https://clojars.org/api/artifacts/ring", doc.as_bytes())
            .with(
                "https://clojars.org/api/artifacts/ring/ring",
                doc.as_bytes(),
            );
        let r = look("pkg:clojars/ring", &net).expect("registry");
        assert_eq!(r.ecosystem, Ecosystem::Clojars);
        assert_eq!(r.name, "ring");
        assert_eq!(r.version, "1.15.5");
        assert_eq!(r.license.as_deref(), Some("The MIT License"));
        assert_eq!(r.downloads_total, Some(11_285_905));
        assert_eq!(r.published_at, None);

        // A requested release is the one described, undated: the API has no
        // per-release dates.
        let r = look("pkg:clojars/ring/ring@1.9.0", &net).expect("registry");
        // A snapshot is not the latest release.
        assert_eq!(r.version, "1.9.0");
        assert_eq!(r.latest_version.as_deref(), Some("1.15.5"));
        assert_eq!(r.published_at, None);
    }

    #[test]
    fn an_artifact_is_group_and_name_or_a_bare_name() {
        let net = Fixtures::default();
        assert_eq!(
            look("pkg:clojars/a/b/c", &net),
            Err(RegistryError::UnsafeCoordinate)
        );
    }
}
