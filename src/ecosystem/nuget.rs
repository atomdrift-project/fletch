//! NuGet: registry metadata and artifact resolution.

use filefacts::Registry;
use serde::Deserialize;
use serde::de::{DeserializeOwned, IgnoredAny};
use std::io::{Cursor, Read};

use crate::ecosystem::{decode, fetch_json, lenient, null_default, parse_rfc3339_secs};
use crate::fetch::{BlobCache, Fetch, cached_metadata, cached_metadata_status};
use crate::registry::RegistryError;

/// The gzip-compressed V3 registration base — per-version `catalogEntry`
/// documents (publish time, listing, license, deprecation), keyed by lowercased
/// package id under `{base}/{id}/index.json`.
const NUGET_REGISTRATION: &str = "https://api.nuget.org/v3/registration5-gz-semver2";

/// Ceiling on a decompressed registration document, a gzip-bomb guard. Real
/// indexes are KBs to low MBs even for packages with thousands of versions.
const NUGET_DECOMP_CAP: u64 = 64 * 1024 * 1024;

/// NuGet has no single metadata document, so three sources compose the record.
/// The uncompressed **search** API gives the package-level facts — version,
/// downloads, custody, links, deprecation, vulnerabilities — but no per-version
/// detail. The per-version **`.nuspec`** (a plain flatcontainer GET) adds the
/// source provenance the search API omits: the `<repository>` URL+commit and
/// the SPDX license. The gzip **registration index** then supplies publish time
/// (this version's, and the whole timeline behind age/cadence) and listing
/// state. Each is best-effort: the record degrades to whatever resolved.
pub(crate) fn nuget(
    path: &str,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let id = path.to_lowercase();
    let doc: SearchResults = fetch_json(
        &format!(
            "https://azuresearch-usnc.nuget.org/query?q=packageid:{id}&prerelease=true&semVerLevel=2.0.0"
        ),
        net,
        cache,
    )?;
    // An exact `packageid:` query with no hit is NuGet saying there is no such
    // package.
    let Some(d) = doc.data.first() else {
        return Err(RegistryError::NotFound);
    };
    let latest = d.version.as_deref();
    // Honor a requested version only if the registry lists it; the search-API
    // metadata below is the latest release's regardless (it exposes no
    // per-version doc), but the `.nuspec` we fetch afterward *is* per-version.
    let version = version
        .filter(|v| d.versions.iter().any(|e| e.version.as_deref() == Some(*v)))
        .or(latest)
        .unwrap_or_default()
        .to_string();

    let mut reg = Registry {
        ecosystem: "nuget".into(),
        name: d.id.as_deref().unwrap_or(path).to_string(),
        version: version.clone(),
        latest_version: latest.map(str::to_string),
        author: d.authors.as_ref().and_then(Authors::first),
        description: d.description.clone(),
        homepage: d
            .project_url
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        downloads_total: d.total_downloads,
        // `deprecation` is an object with a `message`/`reasons` when the package
        // is deprecated, absent otherwise — presence is the signal.
        deprecated: d.deprecation.as_ref().map(nuget_deprecation),
        // `owners` is the curated custody set (distinct from free-text
        // `authors`); its size is the maintainer count. Absent → unknown.
        maintainers: d.owners.as_ref().map(|o| o.len() as u32),
        // The search doc carries advisories for the queried package inline.
        vulnerability_count: d.vulnerabilities.as_ref().map(|v| v.len() as u32),
        ..Default::default()
    };

    // Enrich from the per-version `.nuspec`. Best-effort: the search-derived
    // record stands on its own if the manifest is missing or unparseable.
    // Flatcontainer names the manifest `{id}.nuspec` (only the `.nupkg` carries
    // the version); the version lives in the path segment. Both are lowercased.
    if let Some(bytes) = cached_metadata(
        &format!(
            "https://api.nuget.org/v3-flatcontainer/{id}/{v}/{id}.nuspec",
            v = version.to_lowercase()
        ),
        net,
        cache,
    ) && let Ok(text) = std::str::from_utf8(&bytes)
    {
        nuget_nuspec(text, &mut reg);
    }

    // Enrich from the registration index — the per-version `catalogEntry` the
    // search API omits: publish time (this version's, and the whole timeline
    // that drives cadence), listing state, and license/deprecation fallbacks.
    nuget_registration(&id, &version, &mut reg, net, cache);

    Ok(reg)
}

/// A NuGet `deprecation` object → a reason string: its `message`, else
/// `deprecated`. Shared by the search doc and the registration `catalogEntry`,
/// which carry the same `{message, reasons, alternatePackage}` shape.
fn nuget_deprecation(deprecation: &Deprecation) -> String {
    deprecation
        .message
        .clone()
        .unwrap_or_else(|| "deprecated".to_string())
}

/// Fetch a NuGet registration document and decode it, gunzipping first when
/// the bytes are gzip. The `-gz-` registration resources are stored compressed
/// and served with `Content-Encoding: gzip`, which this client (built without
/// reqwest's `gzip` feature) hands back raw; the magic-byte check also tolerates
/// a proxy that already decoded them. Decompression is capped against a bomb.
fn nuget_gz_json<T: DeserializeOwned>(
    url: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<T, RegistryError> {
    let bytes = cached_metadata_status(url, &[], net, cache)?;
    if bytes.starts_with(&[0x1f, 0x8b]) {
        let mut out = Vec::new();
        flate2::read::MultiGzDecoder::new(Cursor::new(&bytes))
            .take(NUGET_DECOMP_CAP)
            .read_to_end(&mut out)
            .map_err(|e| RegistryError::Malformed {
                url: url.to_string(),
                reason: e.to_string(),
            })?;
        decode(url, &out)
    } else {
        decode(url, &bytes)
    }
}

/// Fold the registration index into `reg`. The index is paged: each page either
/// inlines its `items` or names a separate gzip document by `@id`. Every leaf's
/// `catalogEntry` carries a `published` time — the full set is the release
/// timeline (cadence, package age), and the entry matching `want` supplies this
/// version's publish time, listing state, and license/deprecation fallbacks.
/// Best-effort: a decode or parse failure leaves these fields unknown. (An
/// unlisted version has its `published` zeroed to 1900, which the RFC-3339 parse
/// rejects as pre-epoch, so it neither dates the version nor skews the timeline.)
fn nuget_registration(
    id: &str,
    want: &str,
    reg: &mut Registry,
    net: &dyn Fetch,
    cache: &BlobCache,
) {
    let Ok(index) = nuget_gz_json::<RegistrationIndex>(
        &format!("{NUGET_REGISTRATION}/{id}/index.json"),
        net,
        cache,
    ) else {
        return;
    };
    let mut times: Vec<u64> = Vec::new();
    for page in &index.items {
        // Inline items, or a page document to fetch and scan in their place.
        let fetched;
        let items = if let Some(items) = &page.items {
            items
        } else if let Some(url) = &page.id {
            fetched = nuget_gz_json::<RegistrationPage>(url, net, cache).ok();
            match fetched.as_ref().and_then(|d| d.items.as_ref()) {
                Some(items) => items,
                None => continue,
            }
        } else {
            continue;
        };
        for ce in items.iter().filter_map(|leaf| leaf.catalog_entry.as_ref()) {
            let published = ce.published.as_deref().and_then(parse_rfc3339_secs);
            if let Some(t) = published {
                times.push(t);
            }
            if ce.version.as_deref() == Some(want) {
                reg.published_at = published;
                // `listed:false` hides a version without removing it — NuGet's
                // analogue of a yank, and a real custody signal.
                reg.version_removed = ce.listed.map(|l| !l);
                if reg.license.is_none() {
                    reg.license = ce
                        .license_expression
                        .as_deref()
                        .filter(|s| !s.is_empty())
                        .map(str::to_string);
                }
                if reg.deprecated.is_none() {
                    reg.deprecated = ce.deprecation.as_ref().map(nuget_deprecation);
                }
            }
        }
    }
    if times.is_empty() {
        return;
    }
    times.sort_unstable();
    reg.release_count = Some(times.len() as u32);
    reg.first_published_at = times.first().copied();
    if let Some(this) = reg.published_at {
        reg.previous_published_at = times.iter().copied().filter(|&t| t < this).max();
    }
    reg.release_times = times;
}

/// Fold `.nuspec` `<metadata>` provenance into `reg`: the `<repository>`
/// URL+commit (the artifact→source pin) and a `<license type="expression">`
/// SPDX string. Namespace-agnostic (nuspec schemas vary by tooling version);
/// matches on local tag names. Leaves fields untouched when the element is
/// absent, so a manifest without a `<repository>` doesn't erase search facts.
fn nuget_nuspec(text: &str, reg: &mut Registry) {
    let Ok(dom) = roxmltree::Document::parse(text) else {
        return;
    };
    for node in dom.descendants().filter(roxmltree::Node::is_element) {
        match node.tag_name().name() {
            "repository" => {
                if let Some(url) = node.attribute("url").filter(|s| !s.is_empty()) {
                    reg.repository = Some(url.to_string());
                }
                if let Some(commit) = node.attribute("commit").filter(|s| !s.is_empty()) {
                    reg.repository_commit = Some(commit.to_string());
                }
            }
            // A license *expression* is an SPDX id; a `type="file"` license only
            // names a bundled file, so keep it out of the SPDX-shaped field.
            "license" if node.attribute("type") == Some("expression") => {
                if let Some(expr) = node.text().map(str::trim).filter(|s| !s.is_empty()) {
                    reg.license = Some(expr.to_string());
                }
            }
            _ => {}
        }
    }
}

/// The search API's answer to an exact `packageid:` query.
#[derive(Deserialize)]
struct SearchResults {
    data: Vec<SearchHit>,
}

/// One package in the search results: the latest release's package-level facts.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct SearchHit {
    id: Option<String>,
    version: Option<String>,
    #[serde(deserialize_with = "null_default")]
    versions: Vec<SearchVersion>,
    authors: Option<Authors>,
    description: Option<String>,
    project_url: Option<String>,
    total_downloads: Option<u64>,
    deprecation: Option<Deprecation>,
    /// A list of accounts, or a bare string the record does not count.
    #[serde(deserialize_with = "lenient")]
    owners: Option<Vec<IgnoredAny>>,
    vulnerabilities: Option<Vec<IgnoredAny>>,
}

/// One version a search hit lists.
#[derive(Default, Deserialize)]
#[serde(default)]
struct SearchVersion {
    version: Option<String>,
}

/// A search hit's `authors`: a list of names, or one string.
#[derive(Deserialize)]
#[serde(untagged)]
enum Authors {
    List(Vec<String>),
    One(String),
}

impl Authors {
    /// The first-listed author.
    fn first(&self) -> Option<String> {
        match self {
            Self::List(names) => names.first().cloned(),
            Self::One(name) => Some(name.clone()),
        }
    }
}

/// A `deprecation` object, from a search hit or a registration `catalogEntry`.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Deprecation {
    message: Option<String>,
}

/// The registration index: its pages, inline or by reference.
#[derive(Default, Deserialize)]
#[serde(default)]
struct RegistrationIndex {
    #[serde(deserialize_with = "null_default")]
    items: Vec<RegistrationPage>,
}

/// A registration page, in the index or fetched by `@id`: its leaves, when inline.
#[derive(Default, Deserialize)]
#[serde(default)]
struct RegistrationPage {
    items: Option<Vec<RegistrationLeaf>>,
    #[serde(rename = "@id")]
    id: Option<String>,
}

/// One version's leaf on a registration page.
#[derive(Default, Deserialize)]
#[serde(default)]
struct RegistrationLeaf {
    #[serde(rename = "catalogEntry")]
    catalog_entry: Option<CatalogEntry>,
}

/// A version's catalog entry: its publish time, listing state, and license.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct CatalogEntry {
    version: Option<String>,
    published: Option<String>,
    listed: Option<bool>,
    license_expression: Option<String>,
    deprecation: Option<Deprecation>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::test_cache;

    use crate::ecosystem::parse_rfc3339_secs;

    use crate::fetch::Fixtures;

    #[test]
    fn nuget_search_normalizes() {
        let doc = serde_json::json!({"data": [{
            "id": "Newtonsoft.Json", "version": "13.0.3",
            "description": "Json.NET", "authors": ["James Newton-King"],
            "owners": ["dotnetfoundation", "jamesnk"],
            "projectUrl": "https://www.newtonsoft.com/json",
            "totalDownloads": 8_537_565_389u64,
            "vulnerabilities": [],
            "versions": [{"version": "13.0.3"}, {"version": "13.0.2"}]
        }]})
        .to_string();
        let net = Fixtures::default().with(
            "https://azuresearch-usnc.nuget.org/query?q=packageid:newtonsoft.json&prerelease=true&semVerLevel=2.0.0",
            doc.as_bytes(),
        );
        let r = nuget("Newtonsoft.Json", None, &net, &test_cache("nuget")).expect("registry");
        assert_eq!(r.ecosystem, "nuget");
        assert_eq!(r.name, "Newtonsoft.Json");
        assert_eq!(r.version, "13.0.3");
        assert_eq!(r.author.as_deref(), Some("James Newton-King"));
        assert_eq!(r.downloads_total, Some(8_537_565_389));
        assert_eq!(r.maintainers, Some(2)); // owners are the custody set
        assert_eq!(r.vulnerability_count, Some(0));
        assert_eq!(r.deprecated, None);
        assert_eq!(r.published_at, None); // search API carries no publish time
        // No nuspec fixture registered → source provenance stays unknown, and
        // the search-derived record still stands.
        assert_eq!(r.repository, None);
        assert_eq!(r.repository_commit, None);
    }

    #[test]
    fn nuget_nuspec_adds_source_provenance() {
        let search = serde_json::json!({"data": [{
            "id": "LlamaLibrary", "version": "24.525.2252.26",
            "authors": ["nt153133"],
            "deprecation": {"message": "use the successor package"},
            "versions": [{"version": "24.525.2252.26"}]
        }]})
        .to_string();
        let nuspec = r#"<?xml version="1.0" encoding="utf-8"?>
            <package xmlns="http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd">
              <metadata>
                <id>LlamaLibrary</id>
                <version>24.525.2252.26</version>
                <license type="expression">MIT</license>
                <repository type="git"
                  url="https://github.com/nt153133/__LlamaLibrary.git"
                  commit="60e89979455a504418a0d102a733fab0d2a8f756" />
              </metadata>
            </package>"#;
        let net = Fixtures::default()
            .with(
                "https://azuresearch-usnc.nuget.org/query?q=packageid:llamalibrary&prerelease=true&semVerLevel=2.0.0",
                search.as_bytes(),
            )
            .with(
                "https://api.nuget.org/v3-flatcontainer/llamalibrary/24.525.2252.26/llamalibrary.nuspec",
                nuspec.as_bytes(),
            );
        let r = nuget(
            "LlamaLibrary",
            Some("24.525.2252.26"),
            &net,
            &test_cache("nuget_nuspec"),
        )
        .expect("registry");
        assert_eq!(
            r.repository.as_deref(),
            Some("https://github.com/nt153133/__LlamaLibrary.git")
        );
        assert_eq!(
            r.repository_commit.as_deref(),
            Some("60e89979455a504418a0d102a733fab0d2a8f756")
        );
        assert_eq!(r.license.as_deref(), Some("MIT"));
        assert_eq!(r.deprecated.as_deref(), Some("use the successor package"));
    }

    /// Gzip a JSON string the way NuGet serves the `-gz-` registration blobs.
    fn gzip(text: &str) -> Vec<u8> {
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(text.as_bytes()).expect("gzip");
        enc.finish().expect("gzip finish")
    }

    #[test]
    fn nuget_registration_supplies_dates_and_timeline() {
        let search = serde_json::json!({"data": [{
            "id": "Sample.Pkg", "version": "2.0.0",
            "versions": [{"version": "1.0.0"}, {"version": "2.0.0"}]
        }]})
        .to_string();
        // A paged index: one page inline, a second addressed by `@id`. The
        // decoder must gunzip the index *and* follow the page link.
        let page2_url = "https://api.nuget.org/v3/registration5-gz-semver2/sample.pkg/page/2.json";
        let index = serde_json::json!({"count": 2, "items": [
            {"items": [
                {"catalogEntry": {"version": "1.0.0",
                    "published": "2020-01-01T00:00:00+00:00", "listed": true}}
            ]},
            {"@id": page2_url}
        ]})
        .to_string();
        let page2 = serde_json::json!({"items": [
            {"catalogEntry": {"version": "2.0.0",
                "published": "2021-06-15T12:30:00+00:00", "listed": true,
                "licenseExpression": "Apache-2.0"}}
        ]})
        .to_string();
        let net = Fixtures::default()
            .with(
                "https://azuresearch-usnc.nuget.org/query?q=packageid:sample.pkg&prerelease=true&semVerLevel=2.0.0",
                search.as_bytes(),
            )
            .with(
                "https://api.nuget.org/v3/registration5-gz-semver2/sample.pkg/index.json",
                &gzip(&index),
            )
            .with(page2_url, &gzip(&page2));
        let r =
            nuget("Sample.Pkg", Some("2.0.0"), &net, &test_cache("nuget_reg")).expect("registry");
        assert_eq!(r.version, "2.0.0");
        assert_eq!(
            r.published_at,
            parse_rfc3339_secs("2021-06-15T12:30:00+00:00")
        );
        assert_eq!(
            r.first_published_at,
            parse_rfc3339_secs("2020-01-01T00:00:00+00:00")
        );
        assert_eq!(
            r.previous_published_at,
            parse_rfc3339_secs("2020-01-01T00:00:00+00:00")
        );
        assert_eq!(r.release_count, Some(2));
        assert_eq!(r.version_removed, Some(false));
        // No nuspec fixture → license falls back to the catalogEntry expression.
        assert_eq!(r.license.as_deref(), Some("Apache-2.0"));
    }

    #[test]
    fn nuget_registration_unlisted_version_has_no_publish_time() {
        let search = serde_json::json!({"data": [{
            "id": "Hidden.Pkg", "version": "1.0.0",
            "versions": [{"version": "1.0.0"}]
        }]})
        .to_string();
        // NuGet zeroes an unlisted release's `published` to 1900 — a pre-epoch
        // date the RFC-3339 parse rejects, so the version dates to "unknown"
        // rather than 1900, and it drops out of the release timeline entirely.
        let index = serde_json::json!({"count": 1, "items": [
            {"items": [
                {"catalogEntry": {"version": "1.0.0",
                    "published": "1900-01-01T00:00:00+00:00", "listed": false}}
            ]}
        ]})
        .to_string();
        let net = Fixtures::default()
            .with(
                "https://azuresearch-usnc.nuget.org/query?q=packageid:hidden.pkg&prerelease=true&semVerLevel=2.0.0",
                search.as_bytes(),
            )
            .with(
                "https://api.nuget.org/v3/registration5-gz-semver2/hidden.pkg/index.json",
                &gzip(&index),
            );
        let r = nuget(
            "Hidden.Pkg",
            Some("1.0.0"),
            &net,
            &test_cache("nuget_unlisted"),
        )
        .expect("registry");
        assert_eq!(r.published_at, None);
        assert_eq!(r.version_removed, Some(true)); // unlisted → the yank analogue
        assert_eq!(r.release_count, None); // no real publish times to count
    }
}
