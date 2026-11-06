//! Composer / Packagist: registry metadata and artifact resolution.

use filefacts::{Ecosystem, Registry};
use serde::Deserialize;
use serde::de::IgnoredAny;
use std::collections::BTreeMap;

use crate::ecosystem::{
    Coordinates, count, fetch_json, for_version, lenient, listed, non_empty, set_timeline,
    unix_secs,
};
use crate::fetch::{BlobCache, Fetch};
use crate::registry::RegistryError;

/// The `dist.url` of the release `c` names — the exact archive Composer would
/// install — from Packagist's v2 release list, which, unlike the package
/// document, carries every release's dist. The release is matched by its
/// decoded version, a leading `v` on either side ignored. A package is
/// exactly `vendor/package`, as the registry lookup requires.
pub(crate) fn resolve_composer(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<String, RegistryError> {
    c.pair()?;
    let (name, version) = (c.path(), c.version().ok_or(RegistryError::NoRecord)?);
    let url = format!("https://repo.packagist.org/p2/{name}.json");
    let mut doc: ReleaseList = fetch_json(&url, net, &for_version(cache, Some(version)))
        .inspect_err(|error| tracing::debug!(url, %error, "Packagist release list unavailable"))?;
    let want = version.trim_start_matches('v');
    let dist = doc
        .packages
        .remove(name)
        .unwrap_or_default()
        .into_iter()
        .find(|v| {
            v.version
                .as_deref()
                .is_some_and(|s| s.trim_start_matches('v') == want)
        })
        .and_then(|v| v.dist)
        .and_then(|d| d.url);
    dist.ok_or_else(|| {
        tracing::debug!(
            package = %name.escape_debug(),
            version = %version.escape_debug(),
            "Packagist lists no dist for this release"
        );
        RegistryError::NoRecord
    })
}

/// Packagist's package document: lifetime downloads alongside every
/// version's time (the release timeline), authors, and license. A Composer
/// package is always `vendor/package`.
pub(crate) fn lookup(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let (vendor, package) = c.pair()?;
    let pkg = fetch_json::<PackageDocument>(
        &format!("https://packagist.org/packages/{vendor}/{package}.json"),
        net,
        cache,
    )?
    .package;
    let versions = pkg.versions.as_ref();
    // The latest release is the highest stable `version_normalized`, else the
    // highest pre-release; the map's key order says nothing about recency.
    let latest = versions.and_then(|vs| {
        vs.values()
            .filter_map(|v| Some((release_order(v)?, v)))
            .max_by(|(a, _), (b, _)| a.cmp(b))
            .map(|(_, v)| v)
    });
    let release = match c.version() {
        Some(want) => {
            let bare = want.trim_start_matches('v');
            let found = versions.and_then(|vs| {
                vs.iter()
                    .find(|(k, _)| k.trim_start_matches('v') == bare)
                    .map(|(_, v)| v)
            });
            listed(found, &c.full_name(), want)
        }
        None => latest,
    };

    let mut record = c.record(
        Ecosystem::Composer,
        c.full_name(),
        latest.and_then(|v| v.version.clone()),
    );
    // The release in Packagist's own spelling (`v1.0.0` for `1.0.0`).
    if let Some(version) = release.and_then(|v| v.version.as_deref()) {
        record.version = version.to_string();
    }
    record.published_at = release.and_then(|v| v.time.as_deref()).and_then(unix_secs);
    record.author = release
        .and_then(|v| v.authors.as_ref()?.first())
        .and_then(|a| a.name.clone());
    record.description = pkg.description;
    record.repository = pkg.repository;
    record.license = release.and_then(|v| v.license.as_ref()?.first()).cloned();
    record.downloads_total = pkg.downloads.as_ref().and_then(|d| d.total);
    record.downloads_recent = pkg.downloads.as_ref().and_then(|d| d.monthly);
    record.favorites = pkg.favers;
    record.maintainers = pkg.maintainers.as_ref().map(|m| count(m.len()));
    // Branches are not releases, so their times are no part of the timeline.
    set_timeline(
        &mut record,
        versions
            .into_iter()
            .flat_map(BTreeMap::values)
            .filter(|v| release_order(v).is_some())
            .filter_map(|v| v.time.as_deref().and_then(unix_secs)),
    );
    Ok(record)
}

/// A release's place in Packagist's order: stable above pre-release, then by
/// its `version_normalized` numbers, which Packagist pads to four parts
/// (`2.10.0.0` beats `2.9.1.0`). `None` for a branch (`dev-main`, `1.x-dev` →
/// `1.9999999.9999999.9999999-dev`), or a version that does not normalize to
/// numbers.
fn release_order(v: &Release) -> Option<(bool, Vec<u64>)> {
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
    Some((suffix.is_none(), numbers))
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
    favers: Option<u64>,
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
    use crate::ecosystem::{coordinates, look};
    use crate::fetch::Fixtures;

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
            )
            .ok(),
            Some("https://api.github.com/repos/Seldaek/monolog/zipball/abc".to_string())
        );
        assert_eq!(
            resolve_composer(
                &coordinates("pkg:composer/monolog/monolog@v2.9.1"),
                &net,
                &cache
            )
            .ok(),
            Some("https://api.github.com/repos/Seldaek/monolog/zipball/old".to_string()),
            "a minified `__unset` field costs the field, not the list"
        );
        // Unknown version → no match.
        assert_eq!(
            resolve_composer(
                &coordinates("pkg:composer/monolog/monolog@9.9.9"),
                &net,
                &cache
            )
            .ok(),
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
            )
            .ok(),
            url
        );
        // The registry is gone; the cached list still answers.
        assert_eq!(
            resolve_composer(
                &coordinates("pkg:composer/monolog/monolog@3.0.0"),
                &Fixtures::default(),
                &cache
            )
            .ok(),
            url
        );
    }

    #[test]
    fn composers_latest_is_the_highest_stable_release() {
        // As map keys these sort `1.0.0` < `10.0.0` < `11…` < `9.0.0` <
        // `dev-main`, an order that says nothing about recency.
        let doc = serde_json::json!({"package": {"favers": 4242, "versions": {
            "dev-main": {"version": "dev-main", "version_normalized": "9999999-dev", "time": "2022-01-01T00:00:00+00:00"},
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
        let look = |purl: &str| look(purl, &net);

        let r = look("pkg:composer/acme/lib").expect("record");
        assert_eq!(r.name, "acme/lib");
        assert_eq!(r.version, "10.0.0");
        assert_eq!(r.latest_version.as_deref(), Some("10.0.0"));
        assert_eq!(r.published_at, Some(1_609_459_200)); // 2021-01-01
        // The dated releases are the timeline; the branch is not a release.
        assert_eq!(r.release_count, Some(3));
        assert_eq!(r.first_published_at, Some(1_325_376_000)); // 2012-01-01
        assert_eq!(r.previous_published_at, Some(1_577_836_800)); // 2020-01-01
        // Favers are favorites with no rating behind them.
        assert_eq!(r.favorites, Some(4242));
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

    #[test]
    fn the_resolver_takes_only_vendor_and_package() {
        let body = br#"{"packages":{"a/b/c":[{"version":"1.0.0","dist":{"url":"https://example.test/x.zip"}}]}}"#;
        let net = Fixtures::default().with("https://repo.packagist.org/p2/a/b/c.json", body);
        assert_eq!(
            resolve_composer(
                &coordinates("pkg:composer/a/b/c@1.0.0"),
                &net,
                &BlobCache::disabled()
            ),
            Err(RegistryError::UnsafeCoordinate)
        );
    }
}
