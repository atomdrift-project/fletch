//! Homebrew: registry metadata.

use filefacts::Registry;
use serde::Deserialize;
use std::collections::HashMap;

use crate::ecosystem::{Coordinates, fetch_json, non_empty};
use crate::fetch::{BlobCache, Fetch};
use crate::registry::RegistryError;

/// The namespaces that name homebrew-core, the repository formulae.brew.sh
/// describes, for both `pkg:brew` and `pkg:homebrew`. Any other namespace is a
/// third-party tap, whose formula of the same name is a different package.
const CORE_NAMESPACES: &[&str] = &["homebrew", "homebrew-core", "homebrew/core", "core"];

/// Look up the formula `c` names in homebrew-core: its stable version,
/// description, license, deprecation, and 30-day install count. Homebrew
/// records no publish date.
pub(crate) fn lookup(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let name = c.bare_name(CORE_NAMESPACES)?;
    let doc: Formula = fetch_json(
        &format!("https://formulae.brew.sh/api/formula/{name}.json"),
        net,
        cache,
    )?;

    Ok(Registry {
        ecosystem: "homebrew".into(),
        name: doc.name.unwrap_or_else(|| c.name().to_string()),
        version: c
            .target(doc.versions.and_then(|v| v.stable).as_deref())
            .to_string(),
        description: doc.desc,
        homepage: doc.homepage,
        license: doc.license,
        // The 30-day analytics map counts installs per invocation; sum them.
        downloads_recent: doc
            .analytics
            .and_then(|a| a.install)
            .and_then(|i| i.last_30_days)
            .map(|m| m.values().sum::<u64>()),
        deprecated: doc.deprecated.unwrap_or_default().then(|| {
            doc.deprecation_reason
                .unwrap_or_else(|| "deprecated".into())
        }),
        // A disabled formula can no longer be installed.
        version_removed: doc.disabled,
        ..Default::default()
    })
}

/// A Homebrew formula document.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Formula {
    name: Option<String>,
    versions: Option<FormulaVersions>,
    #[serde(deserialize_with = "non_empty")]
    desc: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    homepage: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    license: Option<String>,
    analytics: Option<Analytics>,
    deprecated: Option<bool>,
    #[serde(deserialize_with = "non_empty")]
    deprecation_reason: Option<String>,
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
    use crate::fetch::Fixtures;
    use filefacts::RefLocator;

    const WGET: &str = "https://formulae.brew.sh/api/formula/wget.json";

    fn lookup(purl: &str, net: &Fixtures) -> Result<Registry, RegistryError> {
        crate::registry::lookup(&RefLocator::Purl(purl.into()), net, &BlobCache::disabled())
    }

    fn wget(deprecated: bool, disabled: bool) -> Fixtures {
        let doc = serde_json::json!({
            "name": "wget", "desc": "Internet file retriever",
            "homepage": "https://www.gnu.org/software/wget/", "license": "GPL-3.0-or-later",
            "versions": {"stable": "1.25.0"},
            "deprecated": deprecated, "deprecation_reason": if deprecated { "repo_archived" } else { "" },
            "disabled": disabled,
            "analytics": {"install": {"30d": {"wget": 20_568u64, "wget --HEAD": 26u64}}}
        })
        .to_string();
        Fixtures::default().with(WGET, doc.as_bytes())
    }

    #[test]
    fn homebrew_formula_normalizes() {
        let r = lookup("pkg:brew/wget", &wget(false, false)).expect("registry");
        assert_eq!(r.ecosystem, "homebrew");
        assert_eq!(r.version, "1.25.0");
        assert_eq!(r.license.as_deref(), Some("GPL-3.0-or-later"));
        assert_eq!(r.downloads_recent, Some(20_594));
        assert_eq!(r.deprecated, None);
        assert_eq!(r.version_removed, Some(false));
    }

    #[test]
    fn both_type_spellings_and_every_core_namespace_route_here() {
        let net = wget(false, false);
        for purl in [
            "pkg:brew/wget",
            "pkg:homebrew/wget",
            "pkg:homebrew/homebrew/core/wget",
            "pkg:brew/homebrew-core/wget",
            "pkg:brew/core/wget",
        ] {
            assert_eq!(
                lookup(purl, &net).map(|r| r.ecosystem),
                Ok("homebrew".to_string()),
                "{purl}"
            );
        }
        for purl in ["pkg:brew/evil-tap/wget", "pkg:homebrew/evil/tap/wget"] {
            assert_eq!(
                lookup(purl, &net),
                Err(RegistryError::OffRegistry),
                "{purl}"
            );
        }
    }

    #[test]
    fn a_deprecation_carries_its_reason_and_a_disabled_formula_is_removed() {
        let r = lookup("pkg:brew/wget", &wget(true, true)).expect("registry");
        assert_eq!(r.deprecated.as_deref(), Some("repo_archived"));
        assert_eq!(r.version_removed, Some(true));
    }

    #[test]
    fn a_requested_version_is_the_records_version() {
        let r = lookup("pkg:brew/wget@1.21.0", &wget(false, false)).expect("registry");
        assert_eq!(r.version, "1.21.0");
        assert_eq!(r.published_at, None);
    }
}
