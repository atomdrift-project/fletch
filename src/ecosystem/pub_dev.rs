//! Pub.dev: registry metadata and artifact resolution.

use filefacts::Registry;
use serde_json::Value;

use crate::ecosystem::{json_meta, parse_ts};
use crate::fetch::{BlobCache, Fetch, percent_decode};

/// pub.dev: the package endpoint carries the latest release inline and every
/// version under `versions[]`, each with its `published` time and pubspec.
pub(crate) fn pub_dev(
    name: &str,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Option<Registry> {
    let doc = json_meta(&format!("https://pub.dev/api/packages/{name}"), net, cache)?;
    let latest = doc.pointer("/latest/version").and_then(Value::as_str);
    let requested = version.map(percent_decode);
    // A version the list lacks describes no release: it gets no date rather
    // than latest's, though its identity text still comes from latest's
    // pubspec.
    let rel = match requested.as_deref() {
        Some(want) => doc
            .get("versions")
            .and_then(Value::as_array)
            .and_then(|vs| {
                vs.iter()
                    .find(|v| v.get("version").and_then(Value::as_str) == Some(want))
            }),
        None => doc.get("latest"),
    };
    let spec = rel
        .or_else(|| doc.get("latest"))
        .and_then(|r| r.get("pubspec"));

    Some(Registry {
        ecosystem: "pub".into(),
        name: name.to_string(),
        version: rel
            .and_then(|r| r.get("version"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .or(requested)
            .unwrap_or_default(),
        published_at: rel
            .and_then(|r| r.get("published"))
            .and_then(Value::as_str)
            .and_then(parse_ts),
        latest_version: latest.map(str::to_string),
        description: spec
            .and_then(|s| s.get("description"))
            .and_then(Value::as_str)
            .map(str::to_string),
        homepage: spec
            .and_then(|s| s.get("homepage"))
            .and_then(Value::as_str)
            .map(str::to_string),
        repository: spec
            .and_then(|s| s.get("repository"))
            .and_then(Value::as_str)
            .map(str::to_string),
        ..Default::default()
    })
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
