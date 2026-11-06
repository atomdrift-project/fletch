//! Homebrew: registry metadata.

use filefacts::{Ecosystem, Registry};
use serde::Deserialize;
use std::collections::HashMap;

use crate::ecosystem::{Coordinates, DEPRECATED, fetch_json, non_empty};
use crate::fetch::{BlobCache, Fetch};
use crate::registry::RegistryError;

/// The namespaces that name homebrew-core, the repository formulae.brew.sh
/// describes, for both `pkg:brew` and `pkg:homebrew`. Any other namespace is a
/// third-party tap, whose formula of the same name is a different package.
const CORE_NAMESPACES: &[&str] = &["homebrew", "homebrew-core", "homebrew/core", "core"];

/// Look up the formula `c` names in homebrew-core: its stable version,
/// description, license, deprecation or disabling, and 30-day install count.
/// Homebrew records no publish date.
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

    let mut record = c.record(
        Ecosystem::Homebrew,
        doc.name.unwrap_or_else(|| c.name().to_string()),
        doc.versions.and_then(|v| v.stable),
    );
    record.description = doc.desc;
    record.homepage = doc.homepage;
    record.license = doc.license;
    // The 30-day analytics map counts installs per invocation; sum them.
    record.downloads_recent = doc
        .analytics
        .and_then(|a| a.install)
        .and_then(|i| i.last_30_days)
        .map(|m| m.values().fold(0u64, |sum, &n| sum.saturating_add(n)));
    // A deprecated formula still installs; a disabled one no longer does.
    // Both are the formula's standing, not one release's removal.
    record.deprecated = match (doc.disabled, doc.deprecated) {
        (Some(true), _) => Some(doc.disable_reason.map_or_else(
            || "disabled".to_string(),
            |reason| format!("disabled: {reason}"),
        )),
        (_, Some(true)) => Some(
            doc.deprecation_reason
                .unwrap_or_else(|| DEPRECATED.to_string()),
        ),
        _ => None,
    };
    Ok(record)
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
    #[serde(deserialize_with = "non_empty")]
    disable_reason: Option<String>,
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
    use crate::ecosystem::look;
    use crate::fetch::Fixtures;

    const WGET: &str = "https://formulae.brew.sh/api/formula/wget.json";

    fn wget(deprecated: bool, disabled: bool) -> Fixtures {
        let doc = serde_json::json!({
            "name": "wget", "desc": "Internet file retriever",
            "homepage": "https://www.gnu.org/software/wget/", "license": "GPL-3.0-or-later",
            "versions": {"stable": "1.25.0"},
            "deprecated": deprecated, "deprecation_reason": if deprecated { "repo_archived" } else { "" },
            "disabled": disabled, "disable_reason": if disabled { "unmaintained" } else { "" },
            "analytics": {"install": {"30d": {"wget": 20_568u64, "wget --HEAD": 26u64}}}
        })
        .to_string();
        Fixtures::default().with(WGET, doc.as_bytes())
    }

    #[test]
    fn homebrew_formula_normalizes() {
        let r = look("pkg:brew/wget", &wget(false, false)).expect("registry");
        assert_eq!(r.ecosystem, Ecosystem::Homebrew);
        assert_eq!(r.version, "1.25.0");
        assert_eq!(r.license.as_deref(), Some("GPL-3.0-or-later"));
        assert_eq!(r.downloads_recent, Some(20_594));
        assert_eq!(r.deprecated, None);
        assert_eq!(r.version_removed, None);
        assert_eq!(r.latest_version.as_deref(), Some("1.25.0"));
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
                look(purl, &net).map(|r| r.ecosystem),
                Ok(Ecosystem::Homebrew),
                "{purl}"
            );
        }
        for purl in ["pkg:brew/evil-tap/wget", "pkg:homebrew/evil/tap/wget"] {
            assert_eq!(look(purl, &net), Err(RegistryError::OffRegistry), "{purl}");
        }
    }

    #[test]
    fn a_deprecation_or_disabling_carries_its_reason_and_removes_no_release() {
        let r = look("pkg:brew/wget", &wget(true, false)).expect("registry");
        assert_eq!(r.deprecated.as_deref(), Some("repo_archived"));
        assert_eq!(r.version_removed, None);
        let r = look("pkg:brew/wget", &wget(true, true)).expect("registry");
        assert_eq!(r.deprecated.as_deref(), Some("disabled: unmaintained"));
        assert_eq!(
            r.version_removed, None,
            "a formula's standing, not a release's"
        );
    }

    #[test]
    fn hostile_install_counts_saturate() {
        let doc = serde_json::json!({"name": "wget", "analytics": {"install": {"30d":
            {"wget": u64::MAX, "wget --HEAD": u64::MAX}}}});
        let net = Fixtures::default().with(WGET, doc.to_string().as_bytes());
        let r = look("pkg:brew/wget", &net).expect("registry");
        assert_eq!(r.downloads_recent, Some(u64::MAX));
    }

    #[test]
    fn a_requested_version_is_the_records_version() {
        let r = look("pkg:brew/wget@1.21.0", &wget(false, false)).expect("registry");
        assert_eq!(r.version, "1.21.0");
        assert_eq!(r.latest_version.as_deref(), Some("1.25.0"));
        assert_eq!(r.published_at, None);
    }
}
