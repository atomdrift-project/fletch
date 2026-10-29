//! Composer / Packagist: registry metadata and artifact resolution.

use filefacts::Registry;
use serde::Deserialize;
use serde::de::IgnoredAny;
use std::collections::BTreeMap;

use crate::ecosystem::{Coordinates, fetch_json, for_version, lenient, non_empty, unix_secs};
use crate::fetch::{BlobCache, Fetch};
use crate::purl::encode_component;
use crate::registry::RegistryError;

/// The `dist.url` of `name`'s release `version` — the exact archive Composer
/// would install — from Packagist's v2 release list, which, unlike the package
/// document, carries every release's dist. `name` is the percent-encoded
/// `vendor/package` and `version` the percent-encoded version, as a PURL
/// spells them; a leading `v` on either side of the comparison is ignored.
pub(crate) fn resolve_composer(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Option<String> {
    let (name, version) = (c.path(), c.encoded_version()?);
    let url = format!("https://repo.packagist.org/p2/{name}.json");
    let mut doc: ReleaseList = fetch_json(&url, net, &for_version(cache, Some(version)))
        .inspect_err(|error| tracing::debug!(url, %error, "Packagist release list unavailable"))
        .ok()?;
    let want = version.trim_start_matches('v');
    let dist = doc
        .packages
        .remove(name)
        .unwrap_or_default()
        .into_iter()
        .find(|v| {
            v.version
                .as_deref()
                .is_some_and(|s| encode_component(s.trim_start_matches('v')) == want)
        })
        .and_then(|v| v.dist)
        .and_then(|d| d.url);
    if dist.is_none() {
        tracing::debug!(
            package = %name.escape_debug(),
            version = %version.escape_debug(),
            "Packagist lists no dist for this release"
        );
    }
    dist
}

/// Packagist's package document: lifetime downloads alongside every
/// version's time, authors, and license. A Composer package is always
/// `vendor/package`.
pub(crate) fn lookup(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let (vendor, package) = c.pair()?;
    let doc: PackageDocument = fetch_json(
        &format!("https://packagist.org/packages/{vendor}/{package}.json"),
        net,
        cache,
    )?;
    let pkg = &doc.package;
    let versions = pkg.versions.as_ref();
    let latest = versions.and_then(composer_latest);
    let release = match c.version() {
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
    if release.is_none() {
        tracing::debug!(
            package = %c.full_name().escape_debug(),
            version = ?c.version(),
            "Packagist lists no such release; leaving it undated"
        );
    }
    let latest_version = latest.and_then(|v| v.version.as_deref());

    Ok(Registry {
        ecosystem: "composer".into(),
        name: c.full_name(),
        version: release
            .and_then(|v| v.version.as_deref())
            .unwrap_or_else(|| c.target(latest_version))
            .to_string(),
        latest_version: latest_version.map(str::to_string),
        published_at: release.and_then(|v| v.time.as_deref()).and_then(unix_secs),
        author: release
            .and_then(|v| v.authors.as_ref()?.first())
            .and_then(|a| a.name.clone()),
        description: pkg.description.clone(),
        repository: pkg.repository.clone(),
        license: release.and_then(|v| v.license.as_ref()?.first()).cloned(),
        downloads_total: pkg.downloads.as_ref().and_then(|d| d.total),
        downloads_recent: pkg.downloads.as_ref().and_then(|d| d.monthly),
        maintainers: pkg
            .maintainers
            .as_ref()
            .and_then(|m| u32::try_from(m.len()).ok()),
        ..Default::default()
    })
}

/// Packagist's latest release: the highest stable `version_normalized`, which
/// Packagist pads to four numeric parts (`2.10.0.0` beats `2.9.1.0`), else the
/// highest pre-release (`3.0.0.0-beta1`). Branches (`dev-main`,
/// `1.x-dev` → `1.9999999.9999999.9999999-dev`) never count. The `versions`
/// map is keyed by version string, and its key order says nothing about
/// recency.
fn composer_latest(versions: &BTreeMap<String, Release>) -> Option<&Release> {
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
    versions: Option<BTreeMap<String, Release>>,
    #[serde(deserialize_with = "non_empty")]
    description: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    repository: Option<String>,
    downloads: Option<Downloads>,
    maintainers: Option<Vec<IgnoredAny>>,
}

/// The v2 release list (`repo.packagist.org/p2/{vendor}/{name}.json`): each
/// package's releases, keyed by package name.
#[derive(Default, Deserialize)]
#[serde(default)]
struct ReleaseList {
    packages: BTreeMap<String, Vec<Release>>,
}

/// One release's composer metadata, as both Packagist documents list it. The
/// v2 list is minified — a field equal to the previous release's is omitted,
/// and one the release drops reads `"__unset"` — so every field but `version`
/// tolerates any shape.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Release {
    version: Option<String>,
    #[serde(deserialize_with = "lenient")]
    version_normalized: Option<String>,
    #[serde(deserialize_with = "lenient")]
    time: Option<String>,
    #[serde(deserialize_with = "lenient")]
    authors: Option<Vec<Author>>,
    #[serde(deserialize_with = "lenient")]
    license: Option<Vec<String>>,
    #[serde(deserialize_with = "lenient")]
    dist: Option<Dist>,
}

/// One entry of a release's `authors`.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Author {
    #[serde(deserialize_with = "non_empty")]
    name: Option<String>,
}

/// A release's installable archive.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Dist {
    #[serde(deserialize_with = "non_empty")]
    url: Option<String>,
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
    use crate::ecosystem::coordinates;
    use crate::fetch::Fixtures;
    use filefacts::RefLocator;

    const MONOLOG: &str = "https://repo.packagist.org/p2/monolog/monolog.json";

    #[test]
    fn resolve_composer_via_packagist_dist_url() {
        let body = br#"{"minified":"composer/2.0","packages":{"monolog/monolog":[
            {"version":"3.0.0","license":["MIT"],"dist":{"type":"zip","url":"https://api.github.com/repos/Seldaek/monolog/zipball/abc"}},
            {"version":"2.9.1","license":"__unset","dist":{"type":"zip","url":"https://api.github.com/repos/Seldaek/monolog/zipball/old"}}
        ]}}"#;
        let net = Fixtures::default().with(MONOLOG, body);
        let cache = BlobCache::disabled();
        assert_eq!(
            resolve_composer(
                &coordinates("pkg:composer/monolog/monolog@3.0.0"),
                &net,
                &cache
            ),
            Some("https://api.github.com/repos/Seldaek/monolog/zipball/abc".to_string())
        );
        assert_eq!(
            resolve_composer(
                &coordinates("pkg:composer/monolog/monolog@v2.9.1"),
                &net,
                &cache
            ),
            Some("https://api.github.com/repos/Seldaek/monolog/zipball/old".to_string()),
            "a minified `__unset` field costs the field, not the list"
        );
        // Unknown version → no match.
        assert_eq!(
            resolve_composer(
                &coordinates("pkg:composer/monolog/monolog@9.9.9"),
                &net,
                &cache
            ),
            None
        );
    }

    #[test]
    fn the_release_list_is_read_through_the_cache() {
        let body = br#"{"packages":{"monolog/monolog":[
            {"version":"3.0.0","dist":{"url":"https://example.test/abc.zip"}}
        ]}}"#;
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = BlobCache::with_dir(dir.path());
        let warm = Fixtures::default().with(MONOLOG, body);
        let url = Some("https://example.test/abc.zip".to_string());
        assert_eq!(
            resolve_composer(
                &coordinates("pkg:composer/monolog/monolog@3.0.0"),
                &warm,
                &cache
            ),
            url
        );
        // The registry is gone; the cached list still answers.
        assert_eq!(
            resolve_composer(
                &coordinates("pkg:composer/monolog/monolog@3.0.0"),
                &Fixtures::default(),
                &cache
            ),
            url
        );
    }

    #[test]
    fn composers_latest_is_the_highest_stable_release() {
        // As map keys these sort `1.0.0` < `10.0.0` < `11…` < `9.0.0` <
        // `dev-main`, an order that says nothing about recency.
        let doc = serde_json::json!({"package": {"favers": 4242, "versions": {
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
        let look = |purl: &str| {
            crate::registry::lookup(&RefLocator::Purl(purl.into()), &net, &BlobCache::disabled())
        };

        let r = look("pkg:composer/acme/lib").expect("record");
        assert_eq!(r.name, "acme/lib");
        assert_eq!(r.version, "10.0.0");
        assert_eq!(r.latest_version.as_deref(), Some("10.0.0"));
        assert_eq!(r.published_at, Some(1_609_459_200)); // 2021-01-01
        // Favers are stars with no rating behind them.
        assert_eq!(r.rating_count, None);

        // A requested version the package lacks keeps its own name, undated.
        let gone = look("pkg:composer/acme/lib@v3.0.0").expect("record");
        assert_eq!(gone.version, "v3.0.0");
        assert_eq!(gone.published_at, None);
        assert_eq!(gone.latest_version.as_deref(), Some("10.0.0"));

        // A package is exactly `vendor/package`.
        assert_eq!(
            look("pkg:composer/acme/lib/extra"),
            Err(RegistryError::UnsafeCoordinate)
        );
    }
}
