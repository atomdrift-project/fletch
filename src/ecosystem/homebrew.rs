//! Homebrew: registry metadata and artifact resolution.

use filefacts::Registry;
use serde_json::Value;

use crate::ecosystem::{deprecation_flag, json_meta};
use crate::fetch::{BlobCache, Fetch};

pub(crate) fn homebrew(name: &str, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    let doc = json_meta(
        &format!("https://formulae.brew.sh/api/formula/{name}.json"),
        net,
        cache,
    )?;

    Some(Registry {
        ecosystem: "homebrew".into(),
        name: doc
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or(name)
            .to_string(),
        version: doc
            .pointer("/versions/stable")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        description: doc.get("desc").and_then(Value::as_str).map(str::to_string),
        homepage: doc
            .get("homepage")
            .and_then(Value::as_str)
            .map(str::to_string),
        license: doc
            .get("license")
            .and_then(Value::as_str)
            .map(str::to_string),
        // The 30-day analytics map counts installs per invocation; sum them.
        downloads_recent: doc
            .pointer("/analytics/install/30d")
            .and_then(Value::as_object)
            .map(|m| m.values().filter_map(Value::as_u64).sum::<u64>()),
        deprecated: deprecation_flag(&doc, "deprecated", "deprecated")
            .or_else(|| deprecation_flag(&doc, "disabled", "disabled")),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::test_cache;

    use crate::fetch::Fixtures;

    #[test]
    fn homebrew_formula_normalizes() {
        let doc = serde_json::json!({
            "name": "wget", "desc": "Internet file retriever",
            "homepage": "https://www.gnu.org/software/wget/", "license": "GPL-3.0-or-later",
            "versions": {"stable": "1.25.0"}, "deprecated": false, "disabled": false,
            "analytics": {"install": {"30d": {"wget": 20_568u64, "wget --HEAD": 26u64}}}
        })
        .to_string();
        let net = Fixtures::default().with(
            "https://formulae.brew.sh/api/formula/wget.json",
            doc.as_bytes(),
        );
        let r = homebrew("wget", &net, &test_cache("homebrew")).expect("registry");
        assert_eq!(r.ecosystem, "homebrew");
        assert_eq!(r.version, "1.25.0");
        assert_eq!(r.license.as_deref(), Some("GPL-3.0-or-later"));
        assert_eq!(r.downloads_recent, Some(20_594));
        assert_eq!(r.deprecated, None);
    }
}
