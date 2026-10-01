//! Conda-forge: registry metadata and artifact resolution.

use filefacts::Registry;
use serde::Deserialize;

use crate::ecosystem::{fetch_json, null_default, parse_ts};
use crate::fetch::{BlobCache, Fetch, percent_decode};
use crate::registry::RegistryError;

/// conda (Anaconda.org, conda-forge channel): the package doc lists every file
/// with its upload time and downloads; the channel has no per-version record, so
/// the earliest upload of the matching version is its publish time.
pub(crate) fn conda(
    name: &str,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let doc: Package = fetch_json(
        &format!("https://api.anaconda.org/package/conda-forge/{name}"),
        net,
        cache,
    )?;
    let latest = doc.latest_version.as_deref();
    let requested = version.map(percent_decode);
    let version = requested.as_deref().or(latest).unwrap_or_default();
    // A version with no files gets no date; the package's `created_at` is its
    // first upload, not this version's.
    let published_at = doc
        .files
        .iter()
        .filter(|f| f.version.as_deref() == Some(version))
        .filter_map(|f| f.upload_time.as_deref().and_then(parse_ts))
        .min();

    Ok(Registry {
        ecosystem: "conda".into(),
        name: name.to_string(),
        version: version.to_string(),
        published_at,
        first_published_at: doc.created_at.as_deref().and_then(parse_ts),
        latest_version: latest.map(str::to_string),
        description: doc.summary,
        homepage: doc.home,
        repository: doc.source_git_url.or(doc.dev_url),
        license: doc.license,
        downloads_total: doc.ndownloads,
        ..Default::default()
    })
}

/// The parts of an Anaconda.org package document the registry record reads.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Package {
    latest_version: Option<String>,
    #[serde(deserialize_with = "null_default")]
    files: Vec<PackageFile>,
    created_at: Option<String>,
    summary: Option<String>,
    home: Option<String>,
    source_git_url: Option<String>,
    dev_url: Option<String>,
    license: Option<String>,
    ndownloads: Option<u64>,
}

/// One uploaded file: the version it builds and when it was uploaded.
#[derive(Default, Deserialize)]
#[serde(default)]
struct PackageFile {
    version: Option<String>,
    upload_time: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::test_cache;

    use crate::fetch::Fixtures;

    #[test]
    fn conda_anaconda_normalizes() {
        let doc = serde_json::json!({
            "latest_version": "1.9.3", "summary": "Scientific computing",
            "license": "BSD-3-Clause", "home": "https://numpy.org",
            "dev_url": "https://github.com/numpy/numpy", "source_git_url": null,
            "ndownloads": 138_106_777u64,
            "files": [{"version": "1.9.3", "upload_time": "2021-04-23T10:00:00.000Z"}]
        })
        .to_string();
        let net = Fixtures::default().with(
            "https://api.anaconda.org/package/conda-forge/numpy",
            doc.as_bytes(),
        );
        let r = conda("numpy", None, &net, &test_cache("conda")).expect("registry");
        assert_eq!(r.ecosystem, "conda");
        assert_eq!(r.version, "1.9.3");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(
            r.repository.as_deref(),
            Some("https://github.com/numpy/numpy")
        );
        assert_eq!(r.downloads_total, Some(138_106_777));
    }
}
