//! CRAN: registry metadata and artifact resolution.

use filefacts::Registry;
use serde_json::Value;

use crate::ecosystem::{json_meta, parse_ts, strip_email};
use crate::fetch::{BlobCache, Fetch};

/// CRAN: the crandb mirror serves one JSON document per package with the
/// description, license, maintainer, and the `Date/Publication` of the release.
pub(crate) fn cran(name: &str, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    let doc = json_meta(&format!("https://crandb.r-pkg.org/{name}"), net, cache)?;

    Some(Registry {
        ecosystem: "cran".into(),
        name: doc
            .get("Package")
            .and_then(Value::as_str)
            .unwrap_or(name)
            .to_string(),
        version: doc
            .get("Version")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        published_at: doc
            .get("Date/Publication")
            .and_then(Value::as_str)
            .and_then(parse_ts),
        author: doc
            .get("Maintainer")
            .and_then(Value::as_str)
            .map(strip_email),
        description: doc.get("Title").and_then(Value::as_str).map(str::to_string),
        // CRAN crowds several URLs into one field; keep the first.
        homepage: doc
            .get("URL")
            .and_then(Value::as_str)
            .and_then(|urls| urls.lines().map(str::trim).find(|l| !l.is_empty()))
            .map(str::to_string),
        license: doc
            .get("License")
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
    fn cran_crandb_normalizes() {
        let doc = serde_json::json!({
            "Package": "jsonlite", "Version": "2.0.0",
            "Title": "A Simple and Robust JSON Parser", "License": "MIT + file LICENSE",
            "Maintainer": "Jeroen Ooms <jeroenooms@gmail.com>",
            "URL": "https://jeroen.r-universe.dev/jsonlite\nhttps://arxiv.org/abs/1403.2805",
            "Date/Publication": "2021-04-23 10:00:00 UTC"
        })
        .to_string();
        let net = Fixtures::default().with("https://crandb.r-pkg.org/jsonlite", doc.as_bytes());
        let r = cran("jsonlite", &net, &test_cache("cran")).expect("registry");
        assert_eq!(r.ecosystem, "cran");
        assert_eq!(r.version, "2.0.0");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(r.author.as_deref(), Some("Jeroen Ooms"));
        assert_eq!(
            r.homepage.as_deref(),
            Some("https://jeroen.r-universe.dev/jsonlite")
        );
    }
}
