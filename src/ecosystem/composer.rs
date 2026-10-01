//! Composer / Packagist: registry metadata and artifact resolution.

use filefacts::Registry;
use serde::Deserialize;
use serde::de::IgnoredAny;
use std::collections::BTreeMap;

use crate::ecosystem::{fetch_json, lenient, null_default, parse_rfc3339_secs};
use crate::fetch::{BlobCache, Fetch, percent_decode};
use crate::registry::RegistryError;

/// Composer's download URL lives in Packagist's per-package metadata, not a
/// derivable path. Fetch the v2 metadata, find the matching version, and return
/// its `dist.url` (the exact artifact Composer would install). `name` is
/// `vendor/package`.
pub(crate) fn resolve_composer(name: &str, version: &str, net: &dyn Fetch) -> Option<String> {
    let api = format!("https://repo.packagist.org/p2/{name}.json");
    let resp = net.get(&api).ok()?;
    let json: serde_json::Value = serde_json::from_slice(&resp.bytes).ok()?;
    let versions = json.get("packages")?.get(name)?.as_array()?;
    let want = version.trim_start_matches('v');
    versions
        .iter()
        .find(|v| {
            v.get("version")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|s| s.trim_start_matches('v') == want)
        })
        .and_then(|v| v.get("dist")?.get("url")?.as_str())
        .map(String::from)
}

/// Composer/Packagist: the package endpoint carries lifetime downloads and a
/// favers (stars) count alongside the per-version time, authors, and license.
pub(crate) fn composer(
    path: &str,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let doc: PackageDocument = fetch_json(
        &format!("https://packagist.org/packages/{path}.json"),
        net,
        cache,
    )?;
    let pkg = &doc.package;

    let versions = pkg.versions.as_ref();
    let latest = versions.and_then(composer_latest);
    let requested = version.map(percent_decode);
    let ver = match requested.as_deref() {
        Some(want) => {
            let want = want.trim_start_matches('v');
            versions.and_then(|vs| {
                vs.iter()
                    .find(|(k, _)| k.trim_start_matches('v') == want)
                    .map(|(_, v)| v)
            })
        }
        None => latest,
    };
    let version_of = |v: &PackageVersion| v.version.clone();

    Ok(Registry {
        ecosystem: "composer".into(),
        name: path.to_string(),
        version: ver.and_then(version_of).or(requested).unwrap_or_default(),
        latest_version: latest.and_then(version_of),
        published_at: ver
            .and_then(|v| v.time.as_deref())
            .and_then(parse_rfc3339_secs),
        author: ver
            .and_then(|v| v.authors.first())
            .and_then(|a| a.name.clone()),
        description: pkg.description.clone(),
        repository: pkg.repository.clone(),
        license: ver.and_then(|v| v.license.first()).cloned(),
        downloads_total: pkg.downloads.as_ref().and_then(|d| d.total),
        downloads_recent: pkg.downloads.as_ref().and_then(|d| d.monthly),
        rating_count: pkg.favers,
        maintainers: pkg.maintainers.as_ref().map(|m| m.len() as u32),
        ..Default::default()
    })
}

/// Packagist's latest release: the highest stable `version_normalized`, which
/// Packagist pads to four numeric parts (`2.10.0.0` beats `2.9.1.0`), else the
/// highest pre-release (`3.0.0.0-beta1`). Branches (`dev-main`,
/// `1.x-dev` → `1.9999999.9999999.9999999-dev`) never count. The `versions`
/// map is keyed by version string, and its key order says nothing about
/// recency.
fn composer_latest(versions: &BTreeMap<String, PackageVersion>) -> Option<&PackageVersion> {
    versions
        .values()
        .filter_map(|v| {
            let norm = v
                .version_normalized
                .as_deref()
                .or(v.version.as_deref())?
                .trim_start_matches('v');
            let (numbers, suffix) = norm
                .split_once('-')
                .map_or((norm, None), |(n, s)| (n, Some(s)));
            if suffix.is_some_and(|s| s.contains("dev")) {
                return None;
            }
            let numbers: Vec<u64> = numbers
                .split('.')
                .map(|n| n.parse().ok())
                .collect::<Option<_>>()?;
            Some(((suffix.is_none(), numbers), v))
        })
        .max_by(|(a, _), (b, _)| a.cmp(b))
        .map(|(_, v)| v)
}

/// The Packagist package document (`/packages/{vendor}/{name}.json`).
#[derive(Deserialize)]
struct PackageDocument {
    package: Package,
}

/// The package-level facts and every version Packagist knows.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Package {
    /// Keyed by version string. PHP encodes an empty map as `[]`.
    #[serde(deserialize_with = "lenient")]
    versions: Option<BTreeMap<String, PackageVersion>>,
    description: Option<String>,
    repository: Option<String>,
    downloads: Option<Downloads>,
    favers: Option<u64>,
    maintainers: Option<Vec<IgnoredAny>>,
}

/// One version's composer metadata, as Packagist lists it.
#[derive(Default, Deserialize)]
#[serde(default)]
struct PackageVersion {
    version: Option<String>,
    version_normalized: Option<String>,
    time: Option<String>,
    #[serde(deserialize_with = "null_default")]
    authors: Vec<Author>,
    #[serde(deserialize_with = "null_default")]
    license: Vec<String>,
}

/// One entry of a version's `authors`.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Author {
    name: Option<String>,
}

/// The package's download counters.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Downloads {
    total: Option<u64>,
    monthly: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::test_cache;

    use crate::fetch::Fixtures;

    #[test]
    fn resolve_composer_via_packagist_dist_url() {
        let api = "https://repo.packagist.org/p2/monolog/monolog.json";
        let body = br#"{"packages":{"monolog/monolog":[
            {"version":"3.0.0","dist":{"type":"zip","url":"https://api.github.com/repos/Seldaek/monolog/zipball/abc"}},
            {"version":"2.9.1","dist":{"type":"zip","url":"https://api.github.com/repos/Seldaek/monolog/zipball/old"}}
        ]}}"#;
        let net = Fixtures::default().with(api, body);
        assert_eq!(
            resolve_composer("monolog/monolog", "3.0.0", &net),
            Some("https://api.github.com/repos/Seldaek/monolog/zipball/abc".to_string())
        );
        // Unknown version → no match.
        assert_eq!(resolve_composer("monolog/monolog", "9.9.9", &net), None);
    }

    #[test]
    fn composers_latest_is_the_highest_stable_release() {
        // As map keys these sort `1.0.0` < `10.0.0` < `11…` < `9.0.0` <
        // `dev-main`, an order that says nothing about recency.
        let doc = serde_json::json!({"package": {"versions": {
            "dev-main": {"version": "dev-main", "version_normalized": "9999999-dev"},
            "1.0.0": {"version": "1.0.0", "version_normalized": "1.0.0.0", "time": "2012-01-01T00:00:00+00:00"},
            "9.0.0": {"version": "9.0.0", "version_normalized": "9.0.0.0", "time": "2020-01-01T00:00:00+00:00"},
            "10.0.0": {"version": "10.0.0", "version_normalized": "10.0.0.0", "time": "2021-01-01T00:00:00+00:00"},
            "11.0.0-beta1": {"version": "11.0.0-beta1", "version_normalized": "11.0.0.0-beta1"}
        }}})
        .to_string();
        let net = Fixtures::default().with(
            "https://packagist.org/packages/acme/lib.json",
            doc.as_bytes(),
        );
        let cache = test_cache("composer");

        let r = composer("acme/lib", None, &net, &cache).expect("record");
        assert_eq!(r.version, "10.0.0");
        assert_eq!(r.latest_version.as_deref(), Some("10.0.0"));
        assert_eq!(r.published_at, Some(1_609_459_200)); // 2021-01-01

        // A requested version the package lacks keeps its own name, undated.
        let gone = composer("acme/lib", Some("v3.0.0"), &net, &cache).expect("record");
        assert_eq!(gone.version, "v3.0.0");
        assert_eq!(gone.published_at, None);
        assert_eq!(gone.latest_version.as_deref(), Some("10.0.0"));
    }
}
