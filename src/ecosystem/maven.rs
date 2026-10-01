//! Maven Central: registry metadata and artifact resolution.

use filefacts::Registry;
use serde_json::Value;

use crate::ecosystem::json_meta;
use crate::fetch::{BlobCache, Fetch};

/// Maven Central: the solrsearch `gav` core returns one document per release
/// with its publish `timestamp` (ms). `path` is `<group>/<artifact>`; results
/// sort newest-first, so the first doc (or the version match) is the answer.
pub(crate) fn maven(
    path: &str,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Option<Registry> {
    let (group, artifact) = path.split_once('/')?;
    let mut q = format!("g:%22{group}%22+AND+a:%22{artifact}%22");
    if let Some(v) = version {
        q.push_str(&format!("+AND+v:%22{v}%22"));
    }
    let doc = json_meta(
        &format!("https://search.maven.org/solrsearch/select?q={q}&core=gav&rows=20&wt=json"),
        net,
        cache,
    )?;
    let d = doc.pointer("/response/docs/0")?;

    Some(Registry {
        ecosystem: "maven".into(),
        name: format!("{group}:{artifact}"),
        version: d
            .get("v")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        published_at: d
            .get("timestamp")
            .and_then(Value::as_u64)
            .map(|ms| ms / 1000),
        // With a version filter the result set is that one version, so "latest"
        // is only meaningful for an unversioned query.
        latest_version: if version.is_none() {
            d.get("v").and_then(Value::as_str).map(str::to_string)
        } else {
            None
        },
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::test_cache;

    use crate::fetch::Fixtures;

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
