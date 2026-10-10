//! Maven Central: registry metadata and artifact resolution.

use filefacts::Registry;
use serde::Deserialize;

use crate::ecosystem::fetch_json;
use crate::fetch::{BlobCache, Fetch, percent_decode};
use crate::registry::RegistryError;

/// Maven Central: the solrsearch `gav` core returns one document per release
/// with its publish `timestamp` (ms). `path` is `<group>/<artifact>`; results
/// sort newest-first, so the first doc (or the version match) is the answer.
pub(crate) fn maven(
    path: &str,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let Some((group, artifact)) = path.split_once('/') else {
        return Err(RegistryError::NoRecord);
    };
    let mut q = format!("g:%22{group}%22+AND+a:%22{artifact}%22");
    if let Some(v) = version {
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
    let (want_group, want_artifact) = (percent_decode(group), percent_decode(artifact));
    let Some(d) = doc.response.docs.iter().find(|d| {
        d.g.as_deref() == Some(want_group.as_str())
            && d.a.as_deref() == Some(want_artifact.as_str())
    }) else {
        return Err(RegistryError::NotFound);
    };

    Ok(Registry {
        ecosystem: "maven".into(),
        name: format!("{group}:{artifact}"),
        version: d.v.clone().unwrap_or_default(),
        published_at: d.timestamp.map(|ms| ms / 1000),
        // With a version filter the result set is that one version, so "latest"
        // is only meaningful for an unversioned query.
        latest_version: if version.is_none() { d.v.clone() } else { None },
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
    timestamp: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::test_cache;

    use crate::fetch::Fixtures;

    #[test]
    fn only_the_requested_coordinates_answer() {
        let url = "https://search.maven.org/solrsearch/select?q=g:%22com.google.guava%22+AND+a:%22guava%22&core=gav&rows=20&wt=json";
        let doc = serde_json::json!({"response": {"docs": [
            {"g": "com.evil", "a": "guava", "v": "99.0", "timestamp": 1u64},
            {"g": "com.google.guava", "a": "guava", "v": "33.4.8-jre", "timestamp": 1_619_172_000_000u64}
        ]}})
        .to_string();
        let net = Fixtures::default().with(url, doc.as_bytes());
        let r = maven("com.google.guava/guava", None, &net, &test_cache("m")).expect("registry");
        assert_eq!(r.version, "33.4.8-jre");

        let only_other = serde_json::json!({"response": {"docs": [
            {"g": "com.evil", "a": "guava", "v": "99.0"}
        ]}})
        .to_string();
        let net = Fixtures::default().with(url, only_other.as_bytes());
        assert_eq!(
            maven("com.google.guava/guava", None, &net, &test_cache("m")).err(),
            Some(RegistryError::NotFound)
        );
    }

    #[test]
    fn maven_solrsearch_normalizes() {
        let doc = serde_json::json!({"response": {"docs": [
            {"g": "com.google.guava", "a": "guava", "v": "33.4.8-jre", "timestamp": 1_619_172_000_000u64}
        ]}})
        .to_string();
        let net = Fixtures::default().with(
            "https://search.maven.org/solrsearch/select?q=g:%22com.google.guava%22+AND+a:%22guava%22&core=gav&rows=20&wt=json",
            doc.as_bytes(),
        );
        let r =
            maven("com.google.guava/guava", None, &net, &test_cache("maven")).expect("registry");
        assert_eq!(r.ecosystem, "maven");
        assert_eq!(r.name, "com.google.guava:guava");
        assert_eq!(r.version, "33.4.8-jre");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(r.latest_version.as_deref(), Some("33.4.8-jre"));
    }
}
