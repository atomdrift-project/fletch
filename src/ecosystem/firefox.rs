//! Firefox Add-ons (AMO): registry metadata and artifact resolution.

use filefacts::{Ecosystem, Registry};
use serde::Deserialize;

use crate::ecosystem::{
    Coordinates, Localized, count, fetch_json, five_star, flag, immutable_or_fresh, null_default,
    optional, set_timeline, unix_secs,
};
use crate::fetch::{BlobCache, Fetch};
use crate::registry::RegistryError;

/// The AMO v5 add-on API root: `/<slug>/` is the add-on's listing,
/// `/<slug>/versions/<version>/` one release's document.
const AMO_API: &str = "https://addons.mozilla.org/api/v5/addons/addon";

/// Resolve a Firefox Add-ons slug to the XPI AMO serves, as `(version, url)`.
/// A requested version goes through the immutable per-version endpoint, so an
/// old pin can never be silently replaced by the latest release. Without a
/// version, the add-on's `current_version` supplies both the concrete version
/// and file. A namespace names an add-on outside AMO, refused as the
/// registry lookup refuses it.
pub(crate) fn resolve_firefox(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<(String, String), RegistryError> {
    let slug = c.bare_name(&[])?;
    let version = c.encoded_version();
    let api = match version {
        Some(v) => format!("{AMO_API}/{slug}/versions/{v}/"),
        None => format!("{AMO_API}/{slug}/"),
    };
    let resolve = |cache: &BlobCache| {
        let release = match version {
            Some(_) => fetch_json::<AddonVersion>(&api, net, cache).map(Some),
            None => fetch_json::<Addon>(&api, net, cache).map(|addon| addon.current_version),
        }
        .inspect_err(|error| tracing::debug!(url = api, %error, "AMO release unresolved"))?
        .ok_or(RegistryError::NoRecord)?;
        let resolved = release.version.ok_or(RegistryError::NoRecord)?;
        // A surprising answer must not substitute another release for the
        // requested one.
        if version.is_some_and(|want| want != resolved) {
            tracing::debug!(
                url = api,
                got = %resolved.escape_debug(),
                "AMO release refused: the document describes another release"
            );
            return Err(RegistryError::NoRecord);
        }
        let Some(url) = release.file.and_then(|file| file.url) else {
            tracing::debug!(url = api, "AMO release unresolved: no file URL");
            return Err(RegistryError::NoRecord);
        };
        Ok((resolved, url))
    };
    match version {
        Some(_) => immutable_or_fresh(cache, resolve),
        None => resolve(&cache.with_meta_ttl(cache.meta_ttl_unpinned())),
    }
}

/// Look up the add-on `c` names: its listing (localized name and summary,
/// rating, installs, current release) and the first page of its releases for
/// the timeline. A requested version other than the current one is dated from
/// its own release document, or left undated when AMO does not list it.
pub(crate) fn lookup(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let slug = c.bare_name(&[])?;
    let doc: Addon = fetch_json(&format!("{AMO_API}/{slug}/"), net, cache)?;
    let current = doc.current_version.unwrap_or_default();
    let (license, published_at) = match (c.version(), c.encoded_version()) {
        (Some(want), Some(v)) if current.version.as_deref() != Some(want) => {
            let url = format!("{AMO_API}/{slug}/versions/{v}/");
            let release = optional(fetch_json::<AddonVersion>(&url, net, cache), &url)
                .filter(|release| release.version.as_deref() == Some(want))
                .unwrap_or_default();
            let published_at = release.reviewed.as_deref().and_then(unix_secs);
            if published_at.is_none() {
                tracing::debug!(url, "requested release undated on AMO");
            }
            (release.license, published_at)
        }
        // `reviewed` (the release's approval) is when it reached users.
        _ => (
            current.license,
            current
                .reviewed
                .as_deref()
                .or(doc.last_updated.as_deref())
                .and_then(unix_secs),
        ),
    };
    let ratings = doc.ratings.unwrap_or_default();

    let mut record = c.record(
        Ecosystem::Firefox,
        doc.slug.unwrap_or_else(|| c.name().to_string()),
        current.version,
    );
    record.published_at = published_at;
    // `created` is the add-on's first listing.
    record.first_published_at = doc.created.as_deref().and_then(unix_secs);
    record.maintainers = Some(count(doc.authors.len()));
    record.author = doc
        .authors
        .into_iter()
        .next()
        .and_then(|author| author.name);
    record.title = doc.name.as_ref().and_then(Localized::text);
    record.description = doc.summary.as_ref().and_then(Localized::text);
    record.homepage = doc
        .homepage
        .and_then(|h| h.url)
        .as_ref()
        .and_then(Localized::text);
    record.license = license
        .and_then(|l| l.name)
        .as_ref()
        .and_then(Localized::text);
    // `average_daily_users` is the install base, the reach a lifetime
    // download count stands for elsewhere; `weekly_downloads` is recent.
    record.downloads_total = doc.average_daily_users;
    record.downloads_recent = doc.weekly_downloads;
    record.rating = ratings.average.and_then(|r| five_star(r, 5.0));
    record.rating_count = ratings.count;
    // Mozilla disables an add-on it has taken down; a developer disables
    // one to withdraw it. Both are the add-on's standing, not one release's.
    record.security_hold = match doc.status.as_deref() {
        Some("disabled") => Some(true),
        Some("public") => Some(false),
        _ => None,
    };
    record.deprecated = flag(doc.is_disabled, "disabled by its developer");

    // The newest page of releases gives the timeline; `count` is how many
    // AMO lists in all.
    let url = format!("{AMO_API}/{slug}/versions/?page_size=50");
    if let Some(page) = optional(fetch_json::<AddonVersions>(&url, net, cache), &url) {
        record.release_count = page.count;
        set_timeline(
            &mut record,
            page.results
                .iter()
                .filter_map(|v| v.reviewed.as_deref().or(v.created.as_deref()))
                .filter_map(unix_secs),
        );
    }
    Ok(record)
}

/// An AMO add-on document: the listing plus its current release.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Addon {
    slug: Option<String>,
    status: Option<String>,
    current_version: Option<AddonVersion>,
    last_updated: Option<String>,
    created: Option<String>,
    #[serde(deserialize_with = "null_default")]
    authors: Vec<AddonAuthor>,
    name: Option<Localized>,
    summary: Option<Localized>,
    homepage: Option<AddonHomepage>,
    average_daily_users: Option<u64>,
    weekly_downloads: Option<u64>,
    ratings: Option<AddonRatings>,
    is_disabled: Option<bool>,
}

/// One release of an add-on: the add-on's `current_version`, or a
/// per-version document.
#[derive(Default, Deserialize)]
#[serde(default)]
struct AddonVersion {
    version: Option<String>,
    reviewed: Option<String>,
    license: Option<AddonLicense>,
    file: Option<AddonFile>,
}

/// The XPI a release ships.
#[derive(Default, Deserialize)]
#[serde(default)]
struct AddonFile {
    url: Option<String>,
}

/// The license a release ships under.
#[derive(Default, Deserialize)]
#[serde(default)]
struct AddonLicense {
    name: Option<Localized>,
}

/// One author of an add-on.
#[derive(Default, Deserialize)]
#[serde(default)]
struct AddonAuthor {
    name: Option<String>,
}

/// An add-on's homepage link.
#[derive(Default, Deserialize)]
#[serde(default)]
struct AddonHomepage {
    url: Option<Localized>,
}

/// An add-on's rating summary.
#[derive(Default, Deserialize)]
#[serde(default)]
struct AddonRatings {
    average: Option<f64>,
    count: Option<u64>,
}

/// One page of an add-on's releases, with the total AMO lists.
#[derive(Default, Deserialize)]
#[serde(default)]
struct AddonVersions {
    count: Option<u32>,
    #[serde(deserialize_with = "null_default")]
    results: Vec<ListedVersion>,
}

/// One release on a page of releases.
#[derive(Default, Deserialize)]
#[serde(default)]
struct ListedVersion {
    reviewed: Option<String>,
    created: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::{coordinates, look};
    use crate::fetch::Fixtures;

    const ADDON: &str = "https://addons.mozilla.org/api/v5/addons/addon/ublock-origin/";
    const VERSIONS: &str =
        "https://addons.mozilla.org/api/v5/addons/addon/ublock-origin/versions/?page_size=50";

    fn addon() -> String {
        serde_json::json!({
            "slug": "ublock-origin", "status": "public",
            "name": {"en-US": "uBlock Origin"}, "summary": {"en-US": "An efficient blocker"},
            "homepage": {"url": {"en-US": "https://github.com/gorhill/uBlock"}},
            "authors": [{"name": "Raymond Hill"}, {"name": "co-author"}],
            "created": "2015-04-25T07:26:22Z",
            "ratings": {"average": 4.7997, "count": 21_850u64},
            "weekly_downloads": 123_456u64, "average_daily_users": 8_000_000u64,
            "is_disabled": false,
            "current_version": {"version": "1.66.4", "reviewed": "2021-04-23T10:00:00Z",
                                "license": {"name": {"en-US": "GPL-3.0-only"}}}
        })
        .to_string()
    }

    fn versions() -> String {
        serde_json::json!({
            "count": 151,
            "results": [
                {"version": "1.66.4", "reviewed": "2021-04-23T10:00:00Z"},
                {"version": "1.66.3", "reviewed": "2021-04-20T10:00:00Z"},
                {"version": "1.66.2", "reviewed": "2021-03-01T10:00:00Z"}
            ]
        })
        .to_string()
    }

    fn net() -> Fixtures {
        Fixtures::default()
            .with(ADDON, addon().as_bytes())
            .with(VERSIONS, versions().as_bytes())
    }

    #[test]
    fn firefox_amo_normalizes() {
        let r = look("pkg:firefox/ublock-origin", &net()).expect("registry");
        assert_eq!(r.ecosystem, Ecosystem::Firefox);
        assert_eq!(r.title.as_deref(), Some("uBlock Origin"));
        assert_eq!(r.version, "1.66.4");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(
            r.homepage.as_deref(),
            Some("https://github.com/gorhill/uBlock")
        );
        assert_eq!(r.license.as_deref(), Some("GPL-3.0-only"));
        assert_eq!(r.rating, Some(4.7997));
        assert_eq!(r.rating_count, Some(21_850));
        assert_eq!(r.first_published_at, unix_secs("2015-04-25T07:26:22Z"));
        assert_eq!(r.downloads_total, Some(8_000_000));
        assert_eq!(r.maintainers, Some(2));
        assert_eq!(r.previous_published_at, unix_secs("2021-04-20T10:00:00Z"));
        assert_eq!(r.security_hold, Some(false));
        assert_eq!(r.version_removed, None, "AMO flags add-ons, not releases");
        assert_eq!(r.deprecated, None);
        assert_eq!(r.latest_version.as_deref(), Some("1.66.4"));
    }

    #[test]
    fn the_release_count_is_amos_total_not_the_page() {
        let r = look("pkg:firefox/ublock-origin", &net()).expect("registry");
        assert_eq!(r.release_count, Some(151));
        assert_eq!(r.release_times.len(), 3);
        assert_eq!(r.first_published_at, unix_secs("2015-04-25T07:26:22Z"));
    }

    #[test]
    fn a_missing_timeline_leaves_the_listing_intact() {
        let net = Fixtures::default()
            .with(ADDON, addon().as_bytes())
            .refusing(VERSIONS, 503);
        let r = look("pkg:firefox/ublock-origin", &net).expect("registry");
        assert_eq!(r.version, "1.66.4");
        assert_eq!(r.release_count, None);
    }

    #[test]
    fn a_requested_release_is_dated_from_its_own_document_or_not_at_all() {
        let old = serde_json::json!({
            "version": "1.60.0", "reviewed": "2024-09-26T14:47:20Z",
            "license": {"name": {"en-US": "MPL-2.0"}}
        })
        .to_string();
        let net = net()
            .with(&format!("{ADDON}versions/1.60.0/"), old.as_bytes())
            .refusing(&format!("{ADDON}versions/9.9.9/"), 404);

        let r = look("pkg:firefox/ublock-origin@1.60.0", &net).expect("registry");
        assert_eq!(r.version, "1.60.0");
        assert_eq!(r.published_at, unix_secs("2024-09-26T14:47:20Z"));
        assert_eq!(r.license.as_deref(), Some("MPL-2.0"));

        let r = look("pkg:firefox/ublock-origin@9.9.9", &net).expect("registry");
        assert_eq!(r.version, "9.9.9");
        assert_eq!(r.published_at, None);
        assert_eq!(r.license, None);

        let r = look("pkg:firefox/ublock-origin@1.66.4", &net).expect("registry");
        assert_eq!(r.published_at, Some(1_619_172_000));
    }

    #[test]
    fn a_takedown_is_a_hold_and_a_withdrawal_a_deprecation() {
        let net = |status: &str, is_disabled: bool| {
            let doc = serde_json::json!({"status": status, "is_disabled": is_disabled});
            Fixtures::default().with(
                "https://addons.mozilla.org/api/v5/addons/addon/gone/",
                doc.to_string().as_bytes(),
            )
        };
        let r = look("pkg:firefox/gone", &net("disabled", false)).expect("registry");
        assert_eq!(r.security_hold, Some(true));
        assert_eq!(r.deprecated, None);
        assert_eq!(r.version_removed, None);

        // A developer's withdrawal is the add-on's standing, not a removed
        // release.
        let r = look("pkg:firefox/gone", &net("public", true)).expect("registry");
        assert_eq!(r.security_hold, Some(false));
        assert_eq!(r.deprecated.as_deref(), Some("disabled by its developer"));
        assert_eq!(r.version_removed, None);
    }

    #[test]
    fn the_resolver_refuses_what_the_lookup_refuses() {
        let cache = BlobCache::disabled();
        let c = coordinates("pkg:firefox/evil/ublock-origin@1.66.4");
        assert_eq!(
            look("pkg:firefox/evil/ublock-origin", &net()),
            Err(RegistryError::OffRegistry)
        );
        let release = serde_json::json!({"version": "1.66.4",
            "file": {"url": "https://addons.mozilla.org/x.xpi"}})
        .to_string();
        let net = net().with(&format!("{ADDON}versions/1.66.4/"), release.as_bytes());
        assert_eq!(
            resolve_firefox(&c, &net, &cache),
            Err(RegistryError::OffRegistry)
        );
        assert!(
            resolve_firefox(
                &coordinates("pkg:firefox/ublock-origin@1.66.4"),
                &net,
                &cache
            )
            .is_ok()
        );
    }
}
