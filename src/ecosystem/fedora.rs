//! Fedora: registry metadata and artifact resolution.

use filefacts::Registry;
use serde_json::Value;

use crate::ecosystem::json_meta;
use crate::fetch::{BlobCache, Fetch};

/// Fedora (Rawhide via mdapi): the per-package record carries the version,
/// summary, and homepage. mdapi reports no build time, so age stays unknown.
pub(crate) fn fedora(name: &str, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    let doc = json_meta(
        &format!("https://mdapi.fedoraproject.org/rawhide/pkg/{name}"),
        net,
        cache,
    )?;
    let version = match (
        doc.get("version").and_then(Value::as_str),
        doc.get("release").and_then(Value::as_str),
    ) {
        (Some(v), Some(rel)) => format!("{v}-{rel}"),
        (Some(v), None) => v.to_string(),
        _ => String::new(),
    };

    Some(Registry {
        ecosystem: "fedora".into(),
        name: doc
            .get("basename")
            .and_then(Value::as_str)
            .unwrap_or(name)
            .to_string(),
        version,
        description: doc
            .get("summary")
            .and_then(Value::as_str)
            .or_else(|| doc.get("description").and_then(Value::as_str))
            .map(str::to_string),
        homepage: doc.get("url").and_then(Value::as_str).map(str::to_string),
        license: doc
            .get("license")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
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
