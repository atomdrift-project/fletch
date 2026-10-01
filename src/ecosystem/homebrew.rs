//! Homebrew: registry metadata and artifact resolution.

use filefacts::Registry;
use serde::Deserialize;
use std::collections::HashMap;

use crate::ecosystem::{fetch_json, flag};
use crate::fetch::{BlobCache, Fetch};
use crate::registry::RegistryError;

/// Homebrew: the formula JSON carries the stable version, description, license,
/// and 30-day install analytics. It records no publish date.
pub(crate) fn homebrew(
    name: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let doc: Formula = fetch_json(
        &format!("https://formulae.brew.sh/api/formula/{name}.json"),
        net,
        cache,
    )?;

    Ok(Registry {
        ecosystem: "homebrew".into(),
        name: doc.name.unwrap_or_else(|| name.to_string()),
        version: doc.versions.and_then(|v| v.stable).unwrap_or_default(),
        description: doc.desc,
        homepage: doc.homepage,
        license: doc.license,
        // The 30-day analytics map counts installs per invocation; sum them.
        downloads_recent: doc
            .analytics
            .and_then(|a| a.install)
            .and_then(|i| i.last_30_days)
            .map(|m| m.values().sum::<u64>()),
        deprecated: flag(doc.deprecated, "deprecated").or_else(|| flag(doc.disabled, "disabled")),
        ..Default::default()
    })
}

/// A Homebrew formula document.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Formula {
    name: Option<String>,
    versions: Option<FormulaVersions>,
    desc: Option<String>,
    homepage: Option<String>,
    license: Option<String>,
    analytics: Option<Analytics>,
    deprecated: Option<bool>,
    disabled: Option<bool>,
}

/// The formula's current versions.
#[derive(Default, Deserialize)]
#[serde(default)]
struct FormulaVersions {
    stable: Option<String>,
}

/// The formula's install analytics.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Analytics {
    install: Option<InstallCounts>,
}

/// Install counts per window, each keyed by the install invocation.
#[derive(Default, Deserialize)]
#[serde(default)]
struct InstallCounts {
    #[serde(rename = "30d")]
    last_30_days: Option<HashMap<String, u64>>,
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
