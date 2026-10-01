//! Firefox Add-ons (AMO): registry metadata and artifact resolution.

use filefacts::Registry;
use serde_json::Value;

use crate::ecosystem::{deprecation_flag, json_meta, localized, parse_ts};
use crate::fetch::{BlobCache, Fetch, META_TTL_IMMUTABLE, cached_metadata, meta_ttl_unpinned};

/// Resolve a Firefox Add-ons slug to the XPI AMO serves. A requested version
/// goes through the immutable per-version endpoint, so an old pin can never be
/// silently replaced by the latest release. Without a version, the add-on
/// document's `current_version` supplies both the concrete version and file.
pub(crate) fn resolve_firefox(
    path: &str,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Option<(String, String)> {
    let slug = path.rsplit('/').next().unwrap_or(path);
    if slug.is_empty() {
        return None;
    }
    let (api, ttl) = match version {
        Some(v) => (
            format!("https://addons.mozilla.org/api/v5/addons/addon/{slug}/versions/{v}/"),
            META_TTL_IMMUTABLE,
        ),
        None => (
            format!("https://addons.mozilla.org/api/v5/addons/addon/{slug}/"),
            meta_ttl_unpinned(),
        ),
    };
    let bytes = cached_metadata(&api, net, &cache.with_meta_ttl(ttl))?;
    let json: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let release = if version.is_some() {
        &json
    } else {
        json.get("current_version")?
    };
    let resolved_version = release.get("version")?.as_str()?.to_string();
    // Defensive equality check: a malformed or surprising API response must
    // not substitute another release for an explicitly requested version.
    if version.is_some_and(|want| want != resolved_version) {
        return None;
    }
    let url = release.pointer("/file/url")?.as_str()?.to_string();
    Some((resolved_version, url))
}

/// Firefox Add-ons (addons.mozilla.org v5): the same marketplace shape as the
/// Chrome and VS Code stores — localized name/summary, rating, weekly installs,
/// and the current version with its review date.
pub(crate) fn firefox(slug: &str, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    let doc = json_meta(
        &format!("https://addons.mozilla.org/api/v5/addons/addon/{slug}/"),
        net,
        cache,
    )?;

    let mut p = Registry {
        ecosystem: "firefox".into(),
        name: doc
            .get("slug")
            .and_then(Value::as_str)
            .unwrap_or(slug)
            .to_string(),
        version: doc
            .pointer("/current_version/version")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        // `reviewed` (the current version's approval) is the supply-chain recency.
        published_at: doc
            .pointer("/current_version/reviewed")
            .and_then(Value::as_str)
            .or_else(|| doc.get("last_updated").and_then(Value::as_str))
            .and_then(parse_ts),
        // `created` is the add-on's first listing — the package-age signal.
        first_published_at: doc
            .get("created")
            .and_then(Value::as_str)
            .and_then(parse_ts),
        author: doc
            .pointer("/authors/0/name")
            .and_then(Value::as_str)
            .map(str::to_string),
        // The author set is the custody signal AMO exposes.
        maintainers: doc
            .get("authors")
            .and_then(Value::as_array)
            .map(|a| a.len() as u32),
        title: doc.get("name").and_then(localized),
        description: doc.get("summary").and_then(localized),
        homepage: doc.pointer("/homepage/url").and_then(localized),
        license: doc
            .pointer("/current_version/license/name")
            .and_then(localized),
        // `average_daily_users` is the install base (a lifetime-reach analogue);
        // `weekly_downloads` stays the recent-window figure.
        downloads_total: doc.get("average_daily_users").and_then(Value::as_u64),
        downloads_recent: doc.get("weekly_downloads").and_then(Value::as_u64),
        rating: doc
            .pointer("/ratings/average")
            .and_then(Value::as_f64)
            .map(|f| f as f32),
        rating_count: doc.pointer("/ratings/count").and_then(Value::as_u64),
        deprecated: deprecation_flag(&doc, "is_disabled", "disabled"),
        ..Default::default()
    };

    // One extra GET to the versions endpoint yields the release timeline (each
    // version's `reviewed` approval time) for the cadence metrics. Best-effort:
    // a failure leaves the package-age signal (from `created`) intact.
    if let Some(versions) = json_meta(
        &format!("https://addons.mozilla.org/api/v5/addons/addon/{slug}/versions/?page_size=50"),
        net,
        cache,
    )
    .and_then(|d| d.get("results").and_then(Value::as_array).cloned())
    {
        let mut times: Vec<u64> = versions
            .iter()
            .filter_map(|v| {
                v.get("reviewed")
                    .or_else(|| v.get("created"))
                    .and_then(Value::as_str)
                    .and_then(parse_ts)
            })
            .collect();
        times.sort_unstable();
        if !times.is_empty() {
            p.release_count = Some(times.len() as u32);
            if let Some(this) = p.published_at {
                p.previous_published_at = times.iter().copied().filter(|&t| t < this).max();
            }
            p.release_times = times;
        }
    }

    Some(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::test_cache;

    use crate::ecosystem::parse_rfc3339_secs;

    use crate::fetch::Fixtures;

    #[test]
    fn firefox_amo_normalizes() {
        let doc = serde_json::json!({
            "slug": "ublock-origin",
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
        .to_string();
        // The versions endpoint (one extra GET) supplies the release timeline.
        let versions = serde_json::json!({
            "results": [
                {"version": "1.66.4", "reviewed": "2021-04-23T10:00:00Z"},
                {"version": "1.66.3", "reviewed": "2021-04-20T10:00:00Z"},
                {"version": "1.66.2", "reviewed": "2021-03-01T10:00:00Z"}
            ]
        })
        .to_string();
        let net = Fixtures::default()
            .with(
                "https://addons.mozilla.org/api/v5/addons/addon/ublock-origin/",
                doc.as_bytes(),
            )
            .with(
                "https://addons.mozilla.org/api/v5/addons/addon/ublock-origin/versions/?page_size=50",
                versions.as_bytes(),
            );
        let r = firefox("ublock-origin", &net, &test_cache("firefox")).expect("registry");
        assert_eq!(r.ecosystem, "firefox");
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
        // New: first-listing date, install base, author count, release timeline.
        assert!(r.first_published_at.is_some()); // `created`
        assert_eq!(r.downloads_total, Some(8_000_000)); // average_daily_users
        assert_eq!(r.maintainers, Some(2)); // two authors
        assert_eq!(r.release_count, Some(3));
        assert_eq!(
            r.previous_published_at,
            parse_rfc3339_secs("2021-04-20T10:00:00Z")
        );
    }
}
