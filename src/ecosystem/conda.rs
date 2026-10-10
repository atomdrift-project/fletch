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
    channel: Option<&str>,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let owner = anaconda_owner(channel)?;
    let doc: Package = fetch_json(
        &format!("https://api.anaconda.org/package/{owner}/{name}"),
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

/// The anaconda.org account that publishes a PURL's `channel`: conda-forge
/// when none is named, Anaconda's own for its default channel, else the named
/// channel — every other channel is some user's account, and conda-forge's
/// record for a same-named package says nothing about that user's build. A
/// channel given as a URL or path is not one anaconda.org can answer for.
fn anaconda_owner(channel: Option<&str>) -> Result<&str, RegistryError> {
    match channel {
        None | Some("conda-forge") => Ok("conda-forge"),
        Some("main" | "defaults" | "anaconda" | "pkgs/main") => Ok("anaconda"),
        Some(owner)
            if !owner.is_empty()
                && owner
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
                && !owner.starts_with('.') =>
        {
            Ok(owner)
        }
        Some(_) => Err(RegistryError::OffRegistry),
    }
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
        let r = conda("numpy", None, None, &net, &test_cache("conda")).expect("registry");
        assert_eq!(r.ecosystem, "conda");
        assert_eq!(r.version, "1.9.3");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(
            r.repository.as_deref(),
            Some("https://github.com/numpy/numpy")
        );
        assert_eq!(r.downloads_total, Some(138_106_777));
    }

    #[test]
    fn a_channel_reads_its_own_owners_record() {
        assert_eq!(anaconda_owner(None), Ok("conda-forge"));
        assert_eq!(anaconda_owner(Some("main")), Ok("anaconda"));
        assert_eq!(anaconda_owner(Some("some-user")), Ok("some-user"));
        for hostile in ["https://evil.test/c", "../x", "a/b", ".hidden", ""] {
            assert_eq!(
                anaconda_owner(Some(hostile)),
                Err(RegistryError::OffRegistry),
                "{hostile}"
            );
        }
    }
}
