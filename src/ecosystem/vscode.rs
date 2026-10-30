//! The VS Code Marketplace and Open VSX: registry metadata and artifact
//! resolution. Both stores address an extension as `publisher/name` and know
//! it by the id `publisher.name`.

use filefacts::{Ecosystem, Registry};
use serde::Deserialize;
use std::collections::BTreeMap;

use crate::ecosystem::{
    Coordinates, decode, fetch_json, five_star, flag, for_version, non_empty, null_default,
    set_timeline, unix_secs,
};
use crate::fetch::{BlobCache, Fetch, cached_post};
use crate::purl::encode_component;
use crate::registry::RegistryError;

/// The Open VSX API root: `/<namespace>/<name>` is the latest release's
/// document, `/<namespace>/<name>/<version>` that version's.
const OPEN_VSX_API: &str = "https://open-vsx.org/api";

/// The Marketplace's JSON-RPC query endpoint; it has no GET form.
const MARKETPLACE_QUERY: &str =
    "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery";

/// The `.vsix` Open VSX serves for the extension `purl` names: the
/// `files.download` URL its API publishes for the requested version, or for
/// the latest release when none is requested.
pub(crate) fn resolve_openvsx(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<String, RegistryError> {
    let (namespace, name) = c.pair()?;
    let url = match c.encoded_version() {
        Some(v) => format!("{OPEN_VSX_API}/{namespace}/{name}/{v}"),
        None => format!("{OPEN_VSX_API}/{namespace}/{name}"),
    };
    let doc: OpenVsxExtension = fetch_json(&url, net, &for_version(cache, c.version()))
        .inspect_err(|error| tracing::debug!(url, %error, "Open VSX artifact unresolved"))?;
    // A surprising answer must not substitute another release for the
    // requested one.
    if let Some(want) = c.version()
        && doc.version.as_deref() != Some(want)
    {
        tracing::debug!(
            url,
            want = %want.escape_debug(),
            got = ?doc.version,
            "Open VSX artifact refused: the document describes another release"
        );
        return Err(RegistryError::NoRecord);
    }
    doc.files.and_then(|files| files.download).ok_or_else(|| {
        tracing::debug!(url, "Open VSX artifact unresolved: no download URL");
        RegistryError::NoRecord
    })
}

/// The `.vsix` the VS Code Marketplace serves for the extension `purl` names,
/// at the gallery's deterministic URL. An unpinned reference takes the latest
/// version from the Marketplace query first.
pub(crate) fn resolve_vscode(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<String, RegistryError> {
    let (publisher, name) = c.pair()?;
    // The publisher becomes a label of the gallery's hostname, so it must be a
    // publisher ID as `vsce` enforces it (`^[a-z0-9][a-z0-9-]*$`, any case),
    // which is also one hostname label of at most 63 bytes.
    let is_label = publisher.len() <= 63
        && publisher.starts_with(|ch: char| ch.is_ascii_alphanumeric())
        && publisher
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-');
    if !is_label {
        tracing::debug!(
            publisher = %publisher.escape_debug(),
            "VS Code artifact refused: publisher is not a hostname label"
        );
        return Err(RegistryError::UnsafeCoordinate);
    }
    let version = match c.encoded_version() {
        Some(v) => v.to_string(),
        None => {
            let id = extension_id(c);
            let ext = marketplace_extension(&id, net, &for_version(cache, None)).inspect_err(
                |error| {
                    tracing::debug!(%id, %error, "VS Code artifact unresolved");
                },
            )?;
            let Some(latest) = ext.versions.into_iter().next().and_then(|v| v.version) else {
                tracing::debug!(%id, "VS Code artifact unresolved: no version listed");
                return Err(RegistryError::NoRecord);
            };
            // The registry's version goes into a URL path: encoded, it can
            // only ever be one segment.
            encode_component(&latest)
        }
    };
    Ok(format!(
        "https://{publisher}.gallery.vsassets.io/_apis/public/gallery/publisher/{publisher}/extension/{name}/{version}/assetbyname/Microsoft.VisualStudio.Services.VSIXPackage"
    ))
}

/// Look up the extension `c` names on Open VSX: one document per release, with
/// the extension's rating, downloads, and publisher beside it. A requested
/// version the store does not list is read from the latest release's
/// document, and only its package-wide facts are kept.
pub(crate) fn open_vsx(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let (namespace, name) = c.pair()?;
    let latest_url = format!("{OPEN_VSX_API}/{namespace}/{name}");
    let doc: OpenVsxExtension = match c.encoded_version() {
        Some(v) => match fetch_json(&format!("{latest_url}/{v}"), net, cache) {
            Err(RegistryError::NotFound) => {
                tracing::debug!(
                    url = latest_url,
                    "requested version not on Open VSX; reading the extension's latest document"
                );
                fetch_json(&latest_url, net, cache)?
            }
            doc => doc?,
        },
        None => fetch_json(&latest_url, net, cache)?,
    };
    let version = c.target(doc.version.as_deref()).to_string();
    // A release's own facts (its time, publisher, license) belong on the
    // record only when the document is that release.
    let this_release = doc.version.as_deref() == Some(version.as_str());
    let publisher = doc
        .published_by
        .and_then(|user| user.login_name)
        .filter(|_| this_release);

    let mut registry = Registry::new(Ecosystem::Openvsx, extension_id(c));
    registry.version = version;
    registry.published_at = doc
        .timestamp
        .as_deref()
        .and_then(unix_secs)
        .filter(|_| this_release);
    registry.author = publisher.clone();
    registry.publisher = publisher;
    // Whether the release was published by a verified member of the
    // namespace, rather than by anyone with an account.
    registry.publisher_verified = doc.verified.filter(|_| this_release);
    registry.title = doc.display_name;
    registry.description = doc.description;
    registry.homepage = doc.homepage;
    registry.repository = doc.repository;
    registry.license = doc.license.filter(|_| this_release);
    registry.downloads_total = doc.download_count;
    registry.rating = doc.average_rating.and_then(|r| five_star(r, 5.0));
    registry.rating_count = doc.review_count;
    registry.deprecated = flag(doc.deprecated, "deprecated");
    Ok(registry)
}

/// Look up the extension `c` names on the VS Code Marketplace: one query
/// returns the extension with its install count, rating, publisher, and every
/// version it has published, which dates the requested (or latest) release
/// and the release timeline.
pub(crate) fn marketplace(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    c.pair()?;
    let id = extension_id(c);
    let ext = marketplace_extension(&id, net, cache)?;

    // A version is listed once per target platform, minutes apart; it was
    // released when its first build was.
    let mut releases: BTreeMap<&str, u64> = BTreeMap::new();
    for v in &ext.versions {
        if let (Some(version), Some(time)) = (
            v.version.as_deref(),
            v.last_updated.as_deref().and_then(unix_secs),
        ) {
            releases
                .entry(version)
                .and_modify(|t| *t = (*t).min(time))
                .or_insert(time);
        }
    }
    // The newest version is listed first.
    let version = c.target(ext.versions.first().and_then(|v| v.version.as_deref()));
    let published_at = releases.get(version).copied();
    if published_at.is_none() {
        tracing::debug!(%id, version = %version.escape_debug(), "release not listed on the Marketplace; undated");
    }
    let stat = |name: &str| {
        ext.statistics
            .iter()
            .find(|s| s.statistic_name.as_deref() == Some(name))
            .and_then(|s| s.value)
    };
    let publisher = ext.publisher.unwrap_or_default();

    let mut record = Registry::new(Ecosystem::Vscode, id);
    record.version = version.to_string();
    record.published_at = published_at;
    // `publishedDate` is the extension's first listing.
    record.first_published_at = ext.published_date.as_deref().and_then(unix_secs);
    record.author = publisher.display_name;
    // The publisher account, and whether the Marketplace verified its
    // domain: an unverified publisher is one anyone could have registered.
    record.publisher = publisher.publisher_name;
    record.publisher_verified = publisher.is_domain_verified;
    record.title = ext.display_name;
    record.description = ext.short_description;
    record.downloads_total = stat("install").and_then(whole);
    record.rating = stat("averagerating").and_then(|r| five_star(r, 5.0));
    record.rating_count = stat("ratingcount").and_then(whole);
    set_timeline(&mut record, releases.into_values());
    Ok(record)
}

/// The id both stores know an extension by: `publisher.name`, decoded.
fn extension_id(c: &Coordinates<'_>) -> String {
    format!("{}.{}", c.namespace().concat(), c.name())
}

/// The Marketplace's record of the extension `id`, with every version it
/// lists.
fn marketplace_extension(
    id: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<MarketplaceExtension, RegistryError> {
    // Built with the JSON writer, never `format!`: the id comes from a scanned
    // coordinate, and a `"` in it would otherwise close the string and let it
    // restructure the query, answering with another extension's record.
    // filterType 7 is the exact `publisher.name`; flags 257 are
    // IncludeVersions (0x1) | IncludeStatistics (0x100). Files and asset URIs
    // repeat per version and platform and are left out: they would make the
    // answer for a busy extension tens of megabytes.
    let body = serde_json::json!({
        "filters": [{"criteria": [{"filterType": 7, "value": id}]}],
        "flags": 257,
    })
    .to_string();
    let headers = [
        ("Content-Type", "application/json"),
        ("Accept", "application/json;api-version=3.0-preview.1"),
    ];
    let bytes = cached_post(MARKETPLACE_QUERY, body.as_bytes(), &headers, net, cache)?;
    let doc: ExtensionQuery = decode(MARKETPLACE_QUERY, &bytes)?;
    doc.results
        .into_iter()
        .next()
        .and_then(|result| result.extensions.into_iter().next())
        .ok_or_else(|| {
            tracing::debug!(id = %id.escape_debug(), "the Marketplace has no such extension");
            RegistryError::NotFound
        })
}

/// A non-negative whole count from a statistic the Marketplace sends as a
/// float; `None` for a negative or non-finite one.
fn whole(value: f64) -> Option<u64> {
    (value.is_finite() && value >= 0.0).then_some(value as u64)
}

/// An Open VSX extension document: one release of the extension, with the
/// extension's own figures.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct OpenVsxExtension {
    version: Option<String>,
    timestamp: Option<String>,
    published_by: Option<OpenVsxUser>,
    verified: Option<bool>,
    files: Option<OpenVsxFiles>,
    #[serde(deserialize_with = "non_empty")]
    display_name: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    description: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    homepage: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    repository: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    license: Option<String>,
    download_count: Option<u64>,
    average_rating: Option<f64>,
    review_count: Option<u64>,
    deprecated: Option<bool>,
}

/// The Open VSX account that published a release.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct OpenVsxUser {
    #[serde(deserialize_with = "non_empty")]
    login_name: Option<String>,
}

/// The files of an Open VSX release.
#[derive(Default, Deserialize)]
#[serde(default)]
struct OpenVsxFiles {
    download: Option<String>,
}

/// The Marketplace's `extensionquery` answer: one result set per filter.
#[derive(Default, Deserialize)]
#[serde(default)]
struct ExtensionQuery {
    #[serde(deserialize_with = "null_default")]
    results: Vec<QueryResult>,
}

/// The extensions one query filter matched.
#[derive(Default, Deserialize)]
#[serde(default)]
struct QueryResult {
    #[serde(deserialize_with = "null_default")]
    extensions: Vec<MarketplaceExtension>,
}

/// A Marketplace extension with its versions and statistics.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct MarketplaceExtension {
    #[serde(deserialize_with = "non_empty")]
    display_name: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    short_description: Option<String>,
    publisher: Option<MarketplacePublisher>,
    published_date: Option<String>,
    #[serde(deserialize_with = "null_default")]
    versions: Vec<MarketplaceVersion>,
    #[serde(deserialize_with = "null_default")]
    statistics: Vec<Statistic>,
}

/// The Marketplace publisher account behind an extension.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct MarketplacePublisher {
    #[serde(deserialize_with = "non_empty")]
    display_name: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    publisher_name: Option<String>,
    is_domain_verified: Option<bool>,
}

/// One published build of a Marketplace extension: a version for one target
/// platform.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct MarketplaceVersion {
    version: Option<String>,
    last_updated: Option<String>,
}

/// One `{statisticName, value}` pair of an extension's statistics.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Statistic {
    statistic_name: Option<String>,
    value: Option<f64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fetch::{FetchError, Fetched, Fixtures, Method, Request};
    use filefacts::RefLocator;
    use serde_json::Value;

    fn lookup(purl: &str, net: &Fixtures) -> Result<Registry, RegistryError> {
        crate::registry::lookup(&RefLocator::Purl(purl.into()), net, &BlobCache::disabled())
    }

    fn marketplace_answer() -> String {
        serde_json::json!({
            "results": [{"extensions": [{
                "displayName": "Language Support for Java",
                "shortDescription": "Java tooling",
                "publisher": {"displayName": "Red Hat", "publisherName": "redhat", "isDomainVerified": true},
                "publishedDate": "2017-01-01T00:00:00Z",
                "lastUpdated": "2026-06-23T09:30:32.957Z",
                "versions": [
                    {"version": "1.55.0", "targetPlatform": "linux-x64", "lastUpdated": "2026-06-23T09:30:32.957Z"},
                    {"version": "1.55.0", "targetPlatform": "win32-x64", "lastUpdated": "2026-06-23T09:20:00Z"},
                    {"version": "1.54.0", "lastUpdated": "2026-06-20T09:30:32.957Z"},
                    {"version": "1.53.0", "lastUpdated": "2026-05-01T09:30:32.957Z"}
                ],
                "statistics": [
                    {"statisticName": "install", "value": 55_043_274.0},
                    {"statisticName": "averagerating", "value": 3.315},
                    {"statisticName": "ratingcount", "value": 184.0}
                ]
            }]}]
        })
        .to_string()
    }

    fn marketplace_net(answer: &str) -> Fixtures {
        // Fixtures key on URL; the POST body is ignored.
        Fixtures::default().with(MARKETPLACE_QUERY, answer.as_bytes())
    }

    #[test]
    fn vscode_marketplace_query_normalizes() {
        let r = lookup(
            "pkg:vscode-extension/redhat/java",
            &marketplace_net(&marketplace_answer()),
        )
        .expect("registry");
        assert_eq!(r.ecosystem, Ecosystem::Vscode);
        assert_eq!(r.name, "redhat.java");
        assert_eq!(r.version, "1.55.0");
        assert_eq!(r.title.as_deref(), Some("Language Support for Java"));
        assert_eq!(r.author.as_deref(), Some("Red Hat"));
        assert_eq!(r.downloads_total, Some(55_043_274));
        assert_eq!(r.rating, Some(3.315));
        assert_eq!(r.rating_count, Some(184));
        // The release is dated by its first platform build.
        assert_eq!(r.published_at, unix_secs("2026-06-23T09:20:00Z"));
        assert_eq!(r.publisher.as_deref(), Some("redhat"));
        assert_eq!(r.publisher_verified, Some(true));
        assert_eq!(r.first_published_at, unix_secs("2017-01-01T00:00:00Z"));
        assert_eq!(
            r.previous_published_at,
            unix_secs("2026-06-20T09:30:32.957Z")
        );
    }

    #[test]
    fn a_version_built_for_many_platforms_is_one_release() {
        let r = lookup(
            "pkg:vscode-extension/redhat/java",
            &marketplace_net(&marketplace_answer()),
        )
        .expect("registry");
        assert_eq!(r.release_count, Some(3));
        assert_eq!(r.release_times.len(), 3);
    }

    #[test]
    fn the_marketplace_dates_the_requested_version_or_nothing() {
        let net = marketplace_net(&marketplace_answer());
        let r = lookup("pkg:vscode-extension/redhat/java@1.54.0", &net).expect("registry");
        assert_eq!(r.version, "1.54.0");
        assert_eq!(r.published_at, unix_secs("2026-06-20T09:30:32.957Z"));
        assert_eq!(
            r.previous_published_at,
            unix_secs("2026-05-01T09:30:32.957Z")
        );

        let r = lookup("pkg:vscode-extension/redhat/java@9.9.9", &net).expect("registry");
        assert_eq!(r.version, "9.9.9");
        assert_eq!(r.published_at, None);
        // Package-wide facts still hold.
        assert_eq!(r.first_published_at, unix_secs("2017-01-01T00:00:00Z"));
    }

    #[test]
    fn negative_or_off_scale_statistics_are_unknown() {
        let answer = serde_json::json!({
            "results": [{"extensions": [{
                "versions": [{"version": "1.0.0", "lastUpdated": "2026-06-23T09:30:32Z"}],
                "statistics": [
                    {"statisticName": "install", "value": -5.0},
                    {"statisticName": "averagerating", "value": 7.5},
                    {"statisticName": "ratingcount", "value": -1.0}
                ]
            }]}]
        })
        .to_string();
        let r = lookup("pkg:vscode-extension/a/b", &marketplace_net(&answer)).expect("registry");
        assert_eq!(r.downloads_total, None);
        assert_eq!(r.rating, None);
        assert_eq!(r.rating_count, None);
    }

    #[test]
    fn an_empty_answer_is_not_found() {
        let answer = r#"{"results": [{"extensions": []}]}"#;
        assert_eq!(
            lookup("pkg:vscode-extension/a/b", &marketplace_net(answer)),
            Err(RegistryError::NotFound)
        );
    }

    #[test]
    fn an_extension_is_exactly_publisher_and_name() {
        let net = marketplace_net(&marketplace_answer());
        for purl in [
            "pkg:vscode-extension/a/b/c",
            "pkg:vscode-extension/a/b/c?repository_url=https://open-vsx.org",
        ] {
            assert_eq!(
                lookup(purl, &net),
                Err(RegistryError::UnsafeCoordinate),
                "{purl}"
            );
        }
    }

    fn open_vsx_doc(version: &str, timestamp: &str) -> String {
        serde_json::json!({
            "namespace": "redhat", "name": "java", "version": version,
            "timestamp": timestamp,
            "displayName": "Language Support for Java", "description": "Java tooling",
            "averageRating": 5.0, "reviewCount": 16, "downloadCount": 33_978_555u64,
            "publishedBy": {"loginName": "rhdevelopers-ci"}, "verified": true,
            "license": "EPL-2.0", "deprecated": false,
            "files": {"download": format!("https://open-vsx.org/api/redhat/java/{version}/file/redhat.java-{version}.vsix")}
        })
        .to_string()
    }

    const OPEN_VSX: &str = "?repository_url=https://open-vsx.org";

    #[test]
    fn openvsx_api_normalizes() {
        let net = Fixtures::default().with(
            "https://open-vsx.org/api/redhat/java",
            open_vsx_doc("1.55.0", "2026-06-23T09:16:36.442135Z").as_bytes(),
        );
        let r =
            lookup(&format!("pkg:vscode-extension/redhat/java{OPEN_VSX}"), &net).expect("registry");
        assert_eq!(r.ecosystem, Ecosystem::Openvsx);
        assert_eq!(r.name, "redhat.java");
        assert_eq!(r.version, "1.55.0");
        assert_eq!(r.published_at, Some(1_782_206_196));
        assert_eq!(r.author.as_deref(), Some("rhdevelopers-ci"));
        assert_eq!(r.publisher_verified, Some(true));
        assert_eq!(r.rating, Some(5.0));
        assert_eq!(r.rating_count, Some(16));
        assert_eq!(r.downloads_total, Some(33_978_555));
        assert_eq!(r.deprecated, None);
    }

    #[test]
    fn open_vsx_dates_the_requested_version_or_nothing() {
        let net = Fixtures::default()
            .with(
                "https://open-vsx.org/api/redhat/java/1.54.0",
                open_vsx_doc("1.54.0", "2026-06-20T00:00:00Z").as_bytes(),
            )
            .refusing("https://open-vsx.org/api/redhat/java/9.9.9", 404)
            .with(
                "https://open-vsx.org/api/redhat/java",
                open_vsx_doc("1.55.0", "2026-06-23T00:00:00Z").as_bytes(),
            );
        let r = lookup(
            &format!("pkg:vscode-extension/redhat/java@1.54.0{OPEN_VSX}"),
            &net,
        )
        .expect("registry");
        assert_eq!(r.version, "1.54.0");
        assert_eq!(r.published_at, unix_secs("2026-06-20T00:00:00Z"));

        // Unlisted: the record is still that version, undated, and carries
        // none of the latest release's own facts.
        let r = lookup(
            &format!("pkg:vscode-extension/redhat/java@9.9.9{OPEN_VSX}"),
            &net,
        )
        .expect("registry");
        assert_eq!(r.version, "9.9.9");
        assert_eq!(r.published_at, None);
        assert_eq!(r.publisher, None);
        assert_eq!(r.license, None);
        assert_eq!(r.downloads_total, Some(33_978_555));
    }

    #[test]
    fn a_deprecated_open_vsx_extension_says_so() {
        let doc = serde_json::json!({"version": "1.0.0", "deprecated": true}).to_string();
        let net = Fixtures::default().with("https://open-vsx.org/api/a/b", doc.as_bytes());
        let r = lookup(&format!("pkg:vscode-extension/a/b{OPEN_VSX}"), &net).expect("registry");
        assert_eq!(r.deprecated.as_deref(), Some("deprecated"));
    }

    #[test]
    fn open_vsx_artifacts_come_from_the_requested_release() {
        let purl = crate::ecosystem::coordinates;
        let cache = BlobCache::disabled();
        let net = Fixtures::default()
            .with(
                "https://open-vsx.org/api/redhat/java",
                open_vsx_doc("1.55.0", "2026-06-23T00:00:00Z").as_bytes(),
            )
            .with(
                "https://open-vsx.org/api/redhat/java/1.54.0",
                open_vsx_doc("1.54.0", "2026-06-20T00:00:00Z").as_bytes(),
            )
            // An answer for another release than the one asked for.
            .with(
                "https://open-vsx.org/api/redhat/java/1.53.0",
                open_vsx_doc("1.55.0", "2026-06-23T00:00:00Z").as_bytes(),
            );
        assert_eq!(
            resolve_openvsx(&purl("pkg:vscode-extension/redhat/java"), &net, &cache)
                .ok()
                .as_deref(),
            Some("https://open-vsx.org/api/redhat/java/1.55.0/file/redhat.java-1.55.0.vsix")
        );
        assert_eq!(
            resolve_openvsx(
                &purl("pkg:vscode-extension/redhat/java@1.54.0"),
                &net,
                &cache
            )
            .ok()
            .as_deref(),
            Some("https://open-vsx.org/api/redhat/java/1.54.0/file/redhat.java-1.54.0.vsix")
        );
        assert_eq!(
            resolve_openvsx(
                &purl("pkg:vscode-extension/redhat/java@1.53.0"),
                &net,
                &cache
            )
            .ok(),
            None
        );
        assert_eq!(
            resolve_openvsx(&purl("pkg:vscode-extension/redhat/x/java"), &net, &cache).ok(),
            None
        );
    }

    #[test]
    fn marketplace_artifacts_resolve_the_latest_through_the_query() {
        let purl = crate::ecosystem::coordinates;
        let cache = BlobCache::disabled();
        let net = marketplace_net(&marketplace_answer());
        assert_eq!(
            resolve_vscode(&purl("pkg:vscode/redhat/java"), &net, &cache)
                .ok()
                .as_deref(),
            Some(
                "https://redhat.gallery.vsassets.io/_apis/public/gallery/publisher/redhat/extension/java/1.55.0/assetbyname/Microsoft.VisualStudio.Services.VSIXPackage"
            )
        );
        // A registry version that would add a path segment stays one segment.
        let answer = r#"{"results":[{"extensions":[{"versions":[{"version":"1.0/../x"}]}]}]}"#;
        assert!(
            resolve_vscode(
                &purl("pkg:vscode/redhat/java"),
                &marketplace_net(answer),
                &cache
            )
            .ok()
            .is_some_and(|url| url.contains("/1.0%2F..%2Fx/"))
        );
    }

    #[test]
    fn the_query_body_cannot_be_restructured_by_a_crafted_id() {
        /// Captures the POST body so the emitted request can be inspected.
        #[derive(Default, Debug)]
        struct CaptureBody(std::sync::Mutex<Vec<u8>>);
        impl Fetch for CaptureBody {
            fn send(&self, request: &Request<'_>) -> Result<Fetched, FetchError> {
                if let Method::Post(body) = request.method
                    && let Ok(mut seen) = self.0.lock()
                {
                    *seen = body.to_vec();
                }
                Err(FetchError::Refused("captured".into()))
            }
        }

        // An id crafted to close the JSON string literal and graft on
        // sibling keys.
        let crafted = r#"evil","flags":9999,"junk":"x.pkg"#;
        let net = CaptureBody::default();
        assert!(marketplace_extension(crafted, &net, &BlobCache::disabled()).is_err());

        let body = net.0.lock().expect("lock").clone();
        let doc: Value = serde_json::from_slice(&body).expect("body must still be valid JSON");
        assert_eq!(
            doc.pointer("/filters/0/criteria/0/value")
                .and_then(Value::as_str),
            Some(crafted),
            "the whole id must remain a single JSON string: {body:?}"
        );
        assert_eq!(doc.get("flags"), Some(&Value::from(257)));
        assert_eq!(doc.get("junk"), None);
    }
}
