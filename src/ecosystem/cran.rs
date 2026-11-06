//! CRAN: registry metadata.

use filefacts::{Ecosystem, Registry};
use serde::Deserialize;
use std::collections::HashMap;

use crate::ecosystem::{
    Coordinates, fetch_json, listed, non_empty, null_default, set_timeline, strip_email, unix_secs,
};
use crate::fetch::{BlobCache, Fetch};
use crate::registry::RegistryError;

/// crandb's all-versions document: every release's DESCRIPTION (title,
/// license, maintainer, `Date/Publication`), a timeline dating each one, and
/// which is latest.
pub(crate) fn lookup(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let name = c.encoded_name();
    let doc: Package = fetch_json(&format!("https://crandb.r-pkg.org/{name}/all"), net, cache)?;
    let target = c.target(doc.latest.as_deref());

    // Only the release's own entry dates it — releases older than the
    // `Date/Publication` field are dated by the timeline — and a version
    // crandb does not list stays undated. The package-level facts come from
    // the release, else from the latest.
    let mut versions = doc.versions;
    let release = listed(versions.remove(target), c.name(), target);
    let published_at = release
        .as_ref()
        .and_then(|r| r.date_publication.as_deref())
        .or_else(|| doc.timeline.get(target).map(String::as_str))
        .and_then(unix_secs);
    let desc = release
        .or_else(|| doc.latest.as_deref().and_then(|v| versions.remove(v)))
        .unwrap_or_default();

    let mut record = c.record(
        Ecosystem::Cran,
        desc.package.unwrap_or_else(|| c.name().to_string()),
        doc.latest.clone(),
    );
    record.published_at = published_at;
    record.author = desc.maintainer.as_deref().map(strip_email);
    record.description = desc.title;
    // CRAN crowds several URLs into one field, separated by commas or
    // whitespace; keep the first.
    record.homepage = desc
        .url
        .as_deref()
        .and_then(|urls| {
            urls.split(|c: char| c == ',' || c.is_whitespace())
                .find(|u| !u.is_empty())
        })
        .map(str::to_string);
    record.license = desc.license;
    set_timeline(
        &mut record,
        doc.timeline.values().filter_map(|t| unix_secs(t)),
    );
    Ok(record)
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
    #[serde(deserialize_with = "non_empty")]
    package: Option<String>,
    #[serde(rename = "Date/Publication")]
    date_publication: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    maintainer: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    title: Option<String>,
    #[serde(rename = "URL", deserialize_with = "non_empty")]
    url: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    license: Option<String>,
}

#[cfg(test)]
mod tests {
    use crate::ecosystem::look;
    use crate::fetch::Fixtures;
    use filefacts::Ecosystem;

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
                "0.9.0": {"Package": "jsonlite", "Version": "0.9.0", "Title": "A JSON parser",
                          "License": "", "URL": " "}
            },
            "timeline": {"0.9.0": "2013-12-03T00:00:00+00:00", "2.0.0": "2021-04-23T10:00:00+00:00"}
        })
        .to_string();
        let net = Fixtures::default().with("https://crandb.r-pkg.org/jsonlite/all", doc.as_bytes());
        let look = |purl: &str| look(purl, &net);
        let r = look("pkg:cran/jsonlite").expect("registry");
        assert_eq!(r.ecosystem, Ecosystem::Cran);
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
        let r = look("pkg:cran/jsonlite@0.9.0").expect("registry");
        assert_eq!(r.version, "0.9.0");
        assert_eq!(r.description.as_deref(), Some("A JSON parser"));
        assert_eq!(r.published_at, Some(1_386_028_800));
        assert_eq!(r.latest_version.as_deref(), Some("2.0.0"));
        assert_eq!(r.license, None, "an empty license is unknown");
        assert_eq!(r.homepage, None, "an empty URL is unknown");
        // The timeline dates every release.
        assert_eq!(r.release_count, Some(2));
        assert_eq!(r.first_published_at, Some(1_386_028_800));
        assert_eq!(r.previous_published_at, None, "the first release");

        // One crandb does not list is still the package, undated.
        let r = look("pkg:cran/jsonlite@9.9.9").expect("registry");
        assert_eq!(r.version, "9.9.9");
        assert_eq!(r.published_at, None);
        assert_eq!(
            r.description.as_deref(),
            Some("A Simple and Robust JSON Parser")
        );
    }
}
