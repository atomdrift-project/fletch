//! Clojars: registry metadata and artifact resolution.

use filefacts::Registry;
use serde_json::Value;

use crate::ecosystem::json_meta;
use crate::fetch::{BlobCache, Fetch};

/// Clojars: the artifacts API returns lifetime downloads, the SCM link, and the
/// license, but no publish date — so `published_at` stays unknown.
pub(crate) fn clojars(path: &str, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    let doc = json_meta(
        &format!("https://clojars.org/api/artifacts/{path}"),
        net,
        cache,
    )?;
    let group = doc.get("group_name").and_then(Value::as_str);
    let jar = doc.get("jar_name").and_then(Value::as_str);
    let name = match (group, jar) {
        (Some(g), Some(j)) if g != j => format!("{g}/{j}"),
        (_, Some(j)) => j.to_string(),
        _ => path.to_string(),
    };

    Some(Registry {
        ecosystem: "clojars".into(),
        name,
        version: doc
            .get("latest_release")
            .or_else(|| doc.get("latest_version"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        latest_version: doc
            .get("latest_version")
            .and_then(Value::as_str)
            .map(str::to_string),
        description: doc
            .get("description")
            .and_then(Value::as_str)
            .map(str::to_string),
        homepage: doc
            .get("homepage")
            .and_then(Value::as_str)
            .map(str::to_string),
        repository: doc
            .pointer("/scm/url")
            .and_then(Value::as_str)
            .map(str::to_string),
        license: doc
            .pointer("/licenses/0/name")
            .and_then(Value::as_str)
            .map(str::to_string),
        downloads_total: doc.get("downloads").and_then(Value::as_u64),
        ..Default::default()
    })
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
