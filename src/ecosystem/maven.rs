//! Maven Central: registry metadata.

use filefacts::Registry;
use serde::Deserialize;

use crate::ecosystem::{Coordinates, fetch_json, secs_from_millis};
use crate::fetch::{BlobCache, Fetch};
use crate::registry::RegistryError;

/// Maven Central's solrsearch `gav` core: one document per release with its
/// publish `timestamp` in milliseconds, newest first, so the first document
/// for exactly these coordinates (or the version asked for) is the answer.
/// An artifact is always `group/artifact`.
pub(crate) fn lookup(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let (group, artifact) = c.pair()?;
    let mut q = format!("g:%22{group}%22+AND+a:%22{artifact}%22");
    if let Some(v) = c.encoded_version() {
        q.push_str(&format!("+AND+v:%22{v}%22"));
    }
    let doc: SolrSearch = fetch_json(
        &format!("https://search.maven.org/solrsearch/select?q={q}&core=gav&rows=20&wt=json"),
        net,
        cache,
    )?;
    // An empty result is Maven Central saying it has no such artifact or
    // version. Only a document for exactly these coordinates counts: search
    // ranks, and another artifact's release must not stand in for this one.
    let want_group = c.namespace().join("/");
    let Some(d) =
        doc.response.docs.iter().find(|d| {
            d.g.as_deref() == Some(want_group.as_str()) && d.a.as_deref() == Some(c.name())
        })
    else {
        tracing::debug!(
            group = %want_group.escape_debug(),
            artifact = %c.name().escape_debug(),
            "Maven Central has no document for these coordinates"
        );
        return Err(RegistryError::NotFound);
    };

    Ok(Registry {
        ecosystem: "maven".into(),
        name: format!("{want_group}:{}", c.name()),
        version: c.target(d.v.as_deref()).to_string(),
        published_at: d.timestamp.and_then(secs_from_millis),
        // With a version filter the result set is that one version, so "latest"
        // is only meaningful for an unversioned query.
        latest_version: if c.version().is_none() {
            d.v.clone()
        } else {
            None
        },
        ..Default::default()
    })
}

/// A Maven Central solrsearch answer.
#[derive(Deserialize)]
struct SolrSearch {
    response: SolrResponse,
}

/// The matching documents, newest first.
#[derive(Deserialize)]
struct SolrResponse {
    docs: Vec<SolrDoc>,
}

/// One release (`gav` core): its version and publish time in milliseconds.
#[derive(Default, Deserialize)]
#[serde(default)]
struct SolrDoc {
    g: Option<String>,
    a: Option<String>,
    v: Option<String>,
    timestamp: Option<f64>,
}

#[cfg(test)]
mod tests {
    use crate::fetch::{BlobCache, Fixtures};
    use crate::registry::{RegistryError, lookup};
    use filefacts::{RefLocator, Registry};

    const GUAVA: &str = "https://search.maven.org/solrsearch/select?q=g:%22com.google.guava%22+AND+a:%22guava%22&core=gav&rows=20&wt=json";

    fn look(net: &Fixtures, purl: &str) -> Result<Registry, RegistryError> {
        lookup(&RefLocator::Purl(purl.into()), net, &BlobCache::disabled())
    }

    #[test]
    fn only_the_requested_coordinates_answer() {
        let doc = serde_json::json!({"response": {"docs": [
            {"g": "com.evil", "a": "guava", "v": "99.0", "timestamp": 1u64},
            {"g": "com.google.guava", "a": "guava", "v": "33.4.8-jre", "timestamp": 1_619_172_000_000u64}
        ]}})
        .to_string();
        let net = Fixtures::default().with(GUAVA, doc.as_bytes());
        let r = look(&net, "pkg:maven/com.google.guava/guava").expect("registry");
        assert_eq!(r.version, "33.4.8-jre");

        let only_other = serde_json::json!({"response": {"docs": [
            {"g": "com.evil", "a": "guava", "v": "99.0"}
        ]}})
        .to_string();
        let net = Fixtures::default().with(GUAVA, only_other.as_bytes());
        assert_eq!(
            look(&net, "pkg:maven/com.google.guava/guava").err(),
            Some(RegistryError::NotFound)
        );
    }

    #[test]
    fn maven_solrsearch_normalizes() {
        let doc = serde_json::json!({"response": {"docs": [
            {"g": "com.google.guava", "a": "guava", "v": "33.4.8-jre", "timestamp": 1_619_172_000_000u64}
        ]}})
        .to_string();
        let net = Fixtures::default().with(GUAVA, doc.as_bytes());
        let r = look(&net, "pkg:maven/com.google.guava/guava").expect("registry");
        assert_eq!(r.ecosystem, "maven");
        assert_eq!(r.name, "com.google.guava:guava");
        assert_eq!(r.version, "33.4.8-jre");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(r.latest_version.as_deref(), Some("33.4.8-jre"));
    }

    #[test]
    fn a_negative_timestamp_is_unknown_not_the_epoch() {
        let doc = serde_json::json!({"response": {"docs": [
            {"g": "com.google.guava", "a": "guava", "v": "1.0", "timestamp": -5000}
        ]}})
        .to_string();
        let net = Fixtures::default().with(GUAVA, doc.as_bytes());
        let r = look(&net, "pkg:maven/com.google.guava/guava").expect("registry");
        assert_eq!(r.published_at, None);
    }

    #[test]
    fn an_artifact_is_exactly_group_and_name() {
        let net = Fixtures::default();
        for purl in ["pkg:maven/com/google/guava", "pkg:maven/a/b/c/guava"] {
            assert_eq!(
                look(&net, purl),
                Err(RegistryError::UnsafeCoordinate),
                "{purl}"
            );
        }
    }
}
