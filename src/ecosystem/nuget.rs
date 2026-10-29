//! NuGet: registry metadata.

use filefacts::{Ecosystem, Registry};
use serde::Deserialize;
use serde::de::{DeserializeOwned, IgnoredAny};
use std::io::{Cursor, Read};

use crate::ecosystem::{
    Coordinates, decode, fetch_json, lenient, non_empty, null_default, optional, set_timeline,
    unix_secs,
};
use crate::fetch::{BlobCache, Fetch, cached_metadata_status};
use crate::purl::encode_component;
use crate::registry::RegistryError;

/// The gzip-compressed V3 registration base — per-version `catalogEntry`
/// documents (publish time, listing, license, deprecation), keyed by lowercased
/// package id under `{base}/{id}/index.json`.
const NUGET_REGISTRATION: &str = "https://api.nuget.org/v3/registration5-gz-semver2";

/// Ceiling on a decompressed registration document, a gzip-bomb guard. Real
/// indexes are KBs to low MBs even for packages with thousands of versions.
const NUGET_DECOMP_CAP: u64 = 64 * 1024 * 1024;

/// NuGet has no single metadata document, so three sources compose the record.
/// The uncompressed **search** API gives the package-level facts — latest
/// version, downloads, custody, links, deprecation, vulnerabilities — but
/// lists only the listed versions and no per-version detail. The per-version
/// **`.nuspec`** (a plain flatcontainer GET) adds the source provenance the
/// search API omits: the `<repository>` URL+commit and the SPDX license. The
/// gzip **registration index** then supplies publish time (this version's,
/// and the whole timeline behind age/cadence) and listing state, unlisted
/// versions included. The `.nuspec` and the registration are matched to the
/// version itself, whether or not search lists it, and each is best-effort:
/// the record degrades to whatever resolved.
pub(crate) fn lookup(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let id = c.bare_name(&[])?.to_lowercase();
    let doc: SearchResults = fetch_json(
        &format!(
            "https://azuresearch-usnc.nuget.org/query?q=packageid:{id}&prerelease=true&semVerLevel=2.0.0"
        ),
        net,
        cache,
    )?;
    // An exact `packageid:` query with no hit is NuGet saying there is no such
    // package. Only the hit that *is* that package counts: search is a
    // ranking, and another package's record must not stand in for this one.
    let Some(hit) = doc.data.iter().find(|hit| {
        hit.id
            .as_deref()
            .is_some_and(|found| found.eq_ignore_ascii_case(c.name()))
    }) else {
        tracing::debug!(
            package = %c.name().escape_debug(),
            "NuGet search has no hit for exactly this package"
        );
        return Err(RegistryError::NotFound);
    };
    let latest = hit.version.as_deref();
    // A requested version is the record's version, in NuGet's spelling when
    // search lists it. Search omits unlisted versions, so one it lacks is
    // still read from the registration below.
    let version = match c.version() {
        Some(want) => hit
            .versions
            .iter()
            .filter_map(|e| e.version.as_deref())
            .find(|v| nuget_version_key(v) == nuget_version_key(want))
            .unwrap_or_else(|| {
                tracing::debug!(
                    package = %c.name().escape_debug(),
                    version = %want.escape_debug(),
                    "NuGet search does not list this version; reading the registration"
                );
                want
            }),
        None => latest.unwrap_or_default(),
    };

    let mut reg = Registry::new(
        Ecosystem::Nuget,
        hit.id.clone().unwrap_or_else(|| c.name().to_string()),
    );
    reg.version = version.to_string();
    reg.latest_version = latest.map(str::to_string);
    reg.author = hit.authors.as_ref().and_then(Authors::first);
    reg.description = hit.description.clone();
    reg.homepage = hit.project_url.clone();
    reg.downloads_total = hit.total_downloads;
    // `deprecation` is an object with a `message`/`reasons` when the package
    // is deprecated, absent otherwise — presence is the signal.
    reg.deprecated = hit.deprecation.as_ref().map(Deprecation::reason);
    // `owners` is the curated custody set (distinct from free-text
    // `authors`); its size is the maintainer count. Absent → unknown.
    reg.maintainers = hit
        .owners
        .as_ref()
        .and_then(|o| u32::try_from(o.len()).ok());
    // The search doc carries advisories for the queried package inline.
    reg.vulnerability_count = hit
        .vulnerabilities
        .as_ref()
        .and_then(|v| u32::try_from(v.len()).ok());

    // Flatcontainer names the manifest `{id}.nuspec` (only the `.nupkg`
    // carries the version); the version lives in the path segment, normalized.
    let url = format!(
        "https://api.nuget.org/v3-flatcontainer/{id}/{v}/{id}.nuspec",
        v = encode_component(&nuget_version_key(version))
    );
    if let Some(bytes) = optional(
        cached_metadata_status(&url, &[], net, cache).map_err(RegistryError::from),
        &url,
    ) {
        nuget_nuspec(&url, &bytes, &mut reg);
    }
    nuget_registration(&id, version, &mut reg, net, cache);
    Ok(reg)
}

/// A version as NuGet tells versions apart: case-insensitively, and without
/// SemVer build metadata, which nuget.org drops when it normalizes a version
/// (`1.0.0-Beta+abc` and `1.0.0-beta` are one release). Flat-container URLs
/// spell versions this way.
fn nuget_version_key(version: &str) -> String {
    version
        .split('+')
        .next()
        .unwrap_or(version)
        .to_ascii_lowercase()
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
/// Best-effort: a document that does not resolve leaves these fields unknown.
/// (An unlisted version has its `published` zeroed to 1900, which the RFC-3339
/// parse rejects as pre-epoch, so it neither dates the version nor skews the
/// timeline.)
fn nuget_registration(
    id: &str,
    want: &str,
    reg: &mut Registry,
    net: &dyn Fetch,
    cache: &BlobCache,
) {
    let url = format!("{NUGET_REGISTRATION}/{id}/index.json");
    let Some(index) = optional(nuget_gz_json::<RegistrationIndex>(&url, net, cache), &url) else {
        return;
    };
    let want = nuget_version_key(want);
    let mut times = Vec::new();
    let mut found = false;
    for page in &index.items {
        // Inline items, or a page document to fetch and read in their place.
        let fetched;
        let items = match (&page.items, &page.id) {
            (Some(items), _) => items,
            (None, Some(url)) => {
                fetched = optional(nuget_gz_json::<RegistrationPage>(url, net, cache), url);
                match fetched.as_ref().and_then(|d| d.items.as_ref()) {
                    Some(items) => items,
                    None => continue,
                }
            }
            (None, None) => continue,
        };
        for ce in items.iter().filter_map(|leaf| leaf.catalog_entry.as_ref()) {
            let published = ce.published.as_deref().and_then(unix_secs);
            times.extend(published);
            if ce
                .version
                .as_deref()
                .is_some_and(|v| nuget_version_key(v) == want)
            {
                found = true;
                reg.published_at = published;
                // `listed:false` hides a version without removing it — NuGet's
                // analogue of a yank, and a real custody signal.
                reg.version_removed = ce.listed.map(|l| !l);
                reg.license = reg.license.take().or_else(|| ce.license_expression.clone());
                reg.deprecated = reg
                    .deprecated
                    .take()
                    .or_else(|| ce.deprecation.as_ref().map(Deprecation::reason));
            }
        }
    }
    if !found {
        tracing::debug!(
            package = %id.escape_debug(),
            version = %want.escape_debug(),
            "NuGet registration does not list this version; leaving it undated"
        );
    }
    set_timeline(reg, times);
}

/// Fold `.nuspec` `<metadata>` provenance into `reg`: the `<repository>`
/// URL+commit (the artifact→source pin) and a `<license type="expression">`
/// SPDX string. Namespace-agnostic (nuspec schemas vary by tooling version);
/// matches on local tag names. Leaves fields untouched when the element is
/// absent, so a manifest without a `<repository>` doesn't erase search facts.
fn nuget_nuspec(url: &str, bytes: &[u8], reg: &mut Registry) {
    let dom = match std::str::from_utf8(bytes).map(roxmltree::Document::parse) {
        Ok(Ok(dom)) => dom,
        Ok(Err(error)) => {
            tracing::debug!(url, %error, "NuGet manifest is not XML; skipping it");
            return;
        }
        Err(error) => {
            tracing::debug!(url, %error, "NuGet manifest is not UTF-8; skipping it");
            return;
        }
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
    #[serde(deserialize_with = "non_empty")]
    description: Option<String>,
    #[serde(deserialize_with = "non_empty")]
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
    #[serde(deserialize_with = "non_empty")]
    message: Option<String>,
}

impl Deprecation {
    /// The deprecation's `message`, else `deprecated`.
    fn reason(&self) -> String {
        self.message
            .clone()
            .unwrap_or_else(|| "deprecated".to_string())
    }
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
    #[serde(deserialize_with = "non_empty")]
    license_expression: Option<String>,
    deprecation: Option<Deprecation>,
}

#[cfg(test)]
mod tests {
    use crate::ecosystem::unix_secs;
    use crate::fetch::{BlobCache, Fixtures};
    use crate::registry::{RegistryError, lookup};
    use filefacts::{Ecosystem, RefLocator, Registry};

    fn search_url(id: &str) -> String {
        format!(
            "https://azuresearch-usnc.nuget.org/query?q=packageid:{id}&prerelease=true&semVerLevel=2.0.0"
        )
    }

    fn registration_url(id: &str) -> String {
        format!("https://api.nuget.org/v3/registration5-gz-semver2/{id}/index.json")
    }

    fn look(net: &Fixtures, purl: &str) -> Result<Registry, RegistryError> {
        lookup(&RefLocator::Purl(purl.into()), net, &BlobCache::disabled())
    }

    /// Gzip a JSON string the way NuGet serves the `-gz-` registration blobs.
    fn gzip(text: &str) -> Vec<u8> {
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(text.as_bytes()).expect("gzip");
        enc.finish().expect("gzip finish")
    }

    #[test]
    fn only_the_requested_package_answers_a_search() {
        let url = search_url("newtonsoft.json");
        let doc = serde_json::json!({"data": [
            {"id": "Newtonsoft.Json.Evil", "version": "99.0.0", "totalDownloads": 1u64},
            {"id": "Newtonsoft.Json", "version": "13.0.3", "totalDownloads": 7u64}
        ]})
        .to_string();
        let net = Fixtures::default().with(&url, doc.as_bytes());
        let r = look(&net, "pkg:nuget/Newtonsoft.Json").expect("registry");
        assert_eq!(r.version, "13.0.3");
        assert_eq!(r.downloads_total, Some(7));

        let other =
            serde_json::json!({"data": [{"id": "Newtonsoft.Json.Evil", "version": "99.0.0"}]})
                .to_string();
        let net = Fixtures::default().with(&url, other.as_bytes());
        assert_eq!(
            look(&net, "pkg:nuget/Newtonsoft.Json").err(),
            Some(RegistryError::NotFound)
        );
    }

    #[test]
    fn nuget_search_normalizes() {
        let doc = serde_json::json!({"data": [{
            "id": "Newtonsoft.Json", "version": "13.0.3",
            "description": "Json.NET", "authors": ["James Newton-King"],
            "owners": ["dotnetfoundation", "jamesnk"],
            "projectUrl": "",
            "totalDownloads": 8_537_565_389u64,
            "vulnerabilities": [],
            "versions": [{"version": "13.0.3"}, {"version": "13.0.2"}]
        }]})
        .to_string();
        let net = Fixtures::default().with(&search_url("newtonsoft.json"), doc.as_bytes());
        let r = look(&net, "pkg:nuget/Newtonsoft.Json").expect("registry");
        assert_eq!(r.ecosystem, Ecosystem::Nuget);
        assert_eq!(r.name, "Newtonsoft.Json");
        assert_eq!(r.version, "13.0.3");
        assert_eq!(r.author.as_deref(), Some("James Newton-King"));
        assert_eq!(r.homepage, None, "an empty projectUrl is unknown");
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

    /// A PURL percent-encodes the `+` of build metadata, and NuGet tells
    /// versions apart without it or letter case: the encoded request is the
    /// release NuGet lists, and its manifest is filed under the normalized
    /// version.
    #[test]
    fn nuget_matches_a_requested_version_as_nuget_does() {
        let search = serde_json::json!({"data": [{
            "id": "Sample.Pkg", "version": "2.0.0",
            "versions": [{"version": "1.0.0-beta+build.7"}, {"version": "2.0.0"}]
        }]})
        .to_string();
        let nuspec =
            r#"<package><metadata><license type="expression">MIT</license></metadata></package>"#;
        let net = Fixtures::default()
            .with(&search_url("sample.pkg"), search.as_bytes())
            .with(
                "https://api.nuget.org/v3-flatcontainer/sample.pkg/1.0.0-beta/sample.pkg.nuspec",
                nuspec.as_bytes(),
            );
        let r = look(&net, "pkg:nuget/Sample.Pkg@1.0.0-Beta%2Bbuild.7").expect("registry");
        assert_eq!(r.version, "1.0.0-beta+build.7", "the release asked for");
        assert_eq!(r.latest_version.as_deref(), Some("2.0.0"));
        assert_eq!(r.license.as_deref(), Some("MIT"), "its own manifest");
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
            .with(&search_url("llamalibrary"), search.as_bytes())
            .with(
                "https://api.nuget.org/v3-flatcontainer/llamalibrary/24.525.2252.26/llamalibrary.nuspec",
                nuspec.as_bytes(),
            );
        let r = look(&net, "pkg:nuget/LlamaLibrary@24.525.2252.26").expect("registry");
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
            .with(&search_url("sample.pkg"), search.as_bytes())
            .with(&registration_url("sample.pkg"), &gzip(&index))
            .with(page2_url, &gzip(&page2));
        let r = look(&net, "pkg:nuget/Sample.Pkg@2.0.0").expect("registry");
        assert_eq!(r.version, "2.0.0");
        assert_eq!(r.published_at, unix_secs("2021-06-15T12:30:00+00:00"));
        assert_eq!(r.first_published_at, unix_secs("2020-01-01T00:00:00+00:00"));
        assert_eq!(
            r.previous_published_at,
            unix_secs("2020-01-01T00:00:00+00:00")
        );
        assert_eq!(r.release_count, Some(2));
        assert_eq!(r.version_removed, Some(false));
        // No nuspec fixture → license falls back to the catalogEntry expression.
        assert_eq!(r.license.as_deref(), Some("Apache-2.0"));
    }

    #[test]
    fn an_unlisted_version_is_itself_removed_and_undated() {
        // Search lists only listed versions, so the unlisted 1.0.0 is absent
        // from it and known only to the registration, which zeroes its
        // `published` to 1900 — a pre-epoch date the RFC-3339 parse rejects,
        // so the version dates to "unknown" rather than 1900, and it drops out
        // of the release timeline.
        let search = serde_json::json!({"data": [{
            "id": "Hidden.Pkg", "version": "2.0.0",
            "versions": [{"version": "2.0.0"}]
        }]})
        .to_string();
        let index = serde_json::json!({"count": 1, "items": [
            {"items": [
                {"catalogEntry": {"version": "1.0.0",
                    "published": "1900-01-01T00:00:00+00:00", "listed": false}},
                {"catalogEntry": {"version": "2.0.0",
                    "published": "2021-06-15T12:30:00+00:00", "listed": true}}
            ]}
        ]})
        .to_string();
        let net = Fixtures::default()
            .with(&search_url("hidden.pkg"), search.as_bytes())
            .with(&registration_url("hidden.pkg"), &gzip(&index));
        let r = look(&net, "pkg:nuget/Hidden.Pkg@1.0.0").expect("registry");
        assert_eq!(r.version, "1.0.0", "the version asked for, not the latest");
        assert_eq!(r.latest_version.as_deref(), Some("2.0.0"));
        assert_eq!(r.published_at, None);
        assert_eq!(r.version_removed, Some(true)); // unlisted → the yank analogue
        assert_eq!(r.release_count, Some(1)); // only the listed release is dated
    }

    #[test]
    fn a_version_nuget_does_not_know_stays_undated() {
        let search = serde_json::json!({"data": [{
            "id": "n", "version": "1.0.0", "versions": [{"version": "1.0.0"}]
        }]})
        .to_string();
        let net = Fixtures::default().with(&search_url("n"), search.as_bytes());
        let r = look(&net, "pkg:nuget/n@9.9.9").expect("registry");
        assert_eq!(r.version, "9.9.9");
        assert_eq!(r.published_at, None);
        assert_eq!(r.version_removed, None);
    }
}
