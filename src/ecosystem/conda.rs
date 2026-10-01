//! Conda-forge: registry metadata and artifact resolution.

use filefacts::Registry;
use serde_json::Value;

use crate::ecosystem::{json_meta, parse_ts};
use crate::fetch::{BlobCache, Fetch, percent_decode};

/// conda (Anaconda.org, conda-forge channel): the package doc lists every file
/// with its upload time and downloads; the channel has no per-version record, so
/// the earliest upload of the matching version is its publish time.
pub(crate) fn conda(
    name: &str,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Option<Registry> {
    let doc = json_meta(
        &format!("https://api.anaconda.org/package/conda-forge/{name}"),
        net,
        cache,
    )?;
    let latest = doc.get("latest_version").and_then(Value::as_str);
    let requested = version.map(percent_decode);
    let version = requested.as_deref().or(latest).unwrap_or_default();
    // A version with no files gets no date; the package's `created_at` is its
    // first upload, not this version's.
    let published_at = doc.get("files").and_then(Value::as_array).and_then(|fs| {
        fs.iter()
            .filter(|f| f.get("version").and_then(Value::as_str) == Some(version))
            .filter_map(|f| {
                f.get("upload_time")
                    .and_then(Value::as_str)
                    .and_then(parse_ts)
            })
            .min()
    });

    Some(Registry {
        ecosystem: "conda".into(),
        name: name.to_string(),
        version: version.to_string(),
        published_at,
        first_published_at: doc
            .get("created_at")
            .and_then(Value::as_str)
            .and_then(parse_ts),
        latest_version: latest.map(str::to_string),
        description: doc
            .get("summary")
            .and_then(Value::as_str)
            .map(str::to_string),
        homepage: doc.get("home").and_then(Value::as_str).map(str::to_string),
        repository: doc
            .get("source_git_url")
            .and_then(Value::as_str)
            .or_else(|| doc.get("dev_url").and_then(Value::as_str))
            .map(str::to_string),
        license: doc
            .get("license")
            .and_then(Value::as_str)
            .map(str::to_string),
        downloads_total: doc.get("ndownloads").and_then(Value::as_u64),
        ..Default::default()
    })
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
