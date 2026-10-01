//! CRAN: registry metadata and artifact resolution.

use filefacts::Registry;
use serde::Deserialize;
use std::collections::HashMap;

use crate::ecosystem::{fetch_json, null_default, parse_ts, strip_email};
use crate::fetch::{BlobCache, Fetch, percent_decode};
use crate::registry::RegistryError;

/// CRAN: crandb's all-versions document carries every release's DESCRIPTION
/// (title, license, maintainer, `Date/Publication`), a timeline dating each
/// one, and which is latest.
pub(crate) fn cran(
    name: &str,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let doc: Package = fetch_json(&format!("https://crandb.r-pkg.org/{name}/all"), net, cache)?;
    let requested = version.map(percent_decode);
    let target = requested
        .as_deref()
        .or(doc.latest.as_deref())
        .unwrap_or_default();

    // Only the release's own entry dates it — releases older than the
    // `Date/Publication` field are dated by the timeline — and a version
    // crandb does not list stays undated. The package-level facts come from
    // the release, else from the latest.
    let mut versions = doc.versions;
    let release = versions.remove(target);
    let published_at = release
        .as_ref()
        .and_then(|r| r.date_publication.as_deref())
        .or_else(|| doc.timeline.get(target).map(String::as_str))
        .and_then(parse_ts);
    let desc = release
        .or_else(|| doc.latest.as_deref().and_then(|v| versions.remove(v)))
        .unwrap_or_default();

    Ok(Registry {
        ecosystem: "cran".into(),
        name: desc.package.unwrap_or_else(|| name.to_string()),
        version: target.to_string(),
        published_at,
        latest_version: doc.latest,
        author: desc.maintainer.as_deref().map(strip_email),
        description: desc.title,
        // CRAN crowds several URLs into one field, separated by commas or
        // whitespace; keep the first.
        homepage: desc
            .url
            .as_deref()
            .and_then(|urls| {
                urls.split(|c: char| c == ',' || c.is_whitespace())
                    .find(|u| !u.is_empty())
            })
            .map(str::to_string),
        license: desc.license,
        ..Default::default()
    })
}

/// crandb's all-versions document for a package.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Package {
    latest: Option<String>,
    #[serde(deserialize_with = "null_default")]
    versions: HashMap<String, DescriptionFile>,
    #[serde(deserialize_with = "null_default")]
    timeline: HashMap<String, String>,
}

/// One release's DESCRIPTION fields, as crandb serves them.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct DescriptionFile {
    package: Option<String>,
    #[serde(rename = "Date/Publication")]
    date_publication: Option<String>,
    maintainer: Option<String>,
    title: Option<String>,
    #[serde(rename = "URL")]
    url: Option<String>,
    license: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::test_cache;

    use crate::fetch::Fixtures;

    #[test]
    fn cran_crandb_normalizes() {
        let doc = serde_json::json!({
            "name": "jsonlite", "latest": "2.0.0",
            "versions": {
                "2.0.0": {
                    "Package": "jsonlite", "Version": "2.0.0",
                    "Title": "A Simple and Robust JSON Parser", "License": "MIT + file LICENSE",
                    "Maintainer": "Jeroen Ooms <jeroenooms@gmail.com>",
                    "URL": "https://jeroen.r-universe.dev/jsonlite,\nhttps://arxiv.org/abs/1403.2805",
                    "Date/Publication": "2021-04-23 10:00:00 UTC"
                },
                "0.9.0": {"Package": "jsonlite", "Version": "0.9.0", "Title": "A JSON parser"}
            },
            "timeline": {"0.9.0": "2013-12-03T00:00:00+00:00", "2.0.0": "2021-04-23T10:00:00+00:00"}
        })
        .to_string();
        let net = Fixtures::default().with("https://crandb.r-pkg.org/jsonlite/all", doc.as_bytes());
        let cache = test_cache("cran");
        let r = cran("jsonlite", None, &net, &cache).expect("registry");
        assert_eq!(r.ecosystem, "cran");
        assert_eq!(r.version, "2.0.0");
        assert_eq!(r.latest_version.as_deref(), Some("2.0.0"));
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(r.author.as_deref(), Some("Jeroen Ooms"));
        assert_eq!(
            r.homepage.as_deref(),
            Some("https://jeroen.r-universe.dev/jsonlite")
        );

        // A release asked for is that release, not the latest; one from
        // before `Date/Publication` existed is dated by the timeline.
        let r = cran("jsonlite", Some("0.9.0"), &net, &cache).expect("registry");
        assert_eq!(r.version, "0.9.0");
        assert_eq!(r.description.as_deref(), Some("A JSON parser"));
        assert_eq!(r.published_at, Some(1_386_028_800));
        assert_eq!(r.latest_version.as_deref(), Some("2.0.0"));

        // One crandb does not list is still the package, undated.
        let r = cran("jsonlite", Some("9.9.9"), &net, &cache).expect("registry");
        assert_eq!(r.version, "9.9.9");
        assert_eq!(r.published_at, None);
        assert_eq!(
            r.description.as_deref(),
            Some("A Simple and Robust JSON Parser")
        );
    }
}
