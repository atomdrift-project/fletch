//! CRAN: registry metadata and artifact resolution.

use filefacts::Registry;
use serde::Deserialize;

use crate::ecosystem::{fetch_json, parse_ts, strip_email};
use crate::fetch::{BlobCache, Fetch};
use crate::registry::RegistryError;

/// CRAN: the crandb mirror serves one JSON document per package with the
/// description, license, maintainer, and the `Date/Publication` of the release.
pub(crate) fn cran(
    name: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let doc: DescriptionFile = fetch_json(&format!("https://crandb.r-pkg.org/{name}"), net, cache)?;

    Ok(Registry {
        ecosystem: "cran".into(),
        name: doc.package.unwrap_or_else(|| name.to_string()),
        version: doc.version.unwrap_or_default(),
        published_at: doc.date_publication.as_deref().and_then(parse_ts),
        author: doc.maintainer.as_deref().map(strip_email),
        description: doc.title,
        // CRAN crowds several URLs into one field; keep the first.
        homepage: doc
            .url
            .as_deref()
            .and_then(|urls| urls.lines().map(str::trim).find(|l| !l.is_empty()))
            .map(str::to_string),
        license: doc.license,
        ..Default::default()
    })
}

/// A package's DESCRIPTION fields, as crandb serves them.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct DescriptionFile {
    package: Option<String>,
    version: Option<String>,
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
            "Package": "jsonlite", "Version": "2.0.0",
            "Title": "A Simple and Robust JSON Parser", "License": "MIT + file LICENSE",
            "Maintainer": "Jeroen Ooms <jeroenooms@gmail.com>",
            "URL": "https://jeroen.r-universe.dev/jsonlite\nhttps://arxiv.org/abs/1403.2805",
            "Date/Publication": "2021-04-23 10:00:00 UTC"
        })
        .to_string();
        let net = Fixtures::default().with("https://crandb.r-pkg.org/jsonlite", doc.as_bytes());
        let r = cran("jsonlite", &net, &test_cache("cran")).expect("registry");
        assert_eq!(r.ecosystem, "cran");
        assert_eq!(r.version, "2.0.0");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(r.author.as_deref(), Some("Jeroen Ooms"));
        assert_eq!(
            r.homepage.as_deref(),
            Some("https://jeroen.r-universe.dev/jsonlite")
        );
    }
}
