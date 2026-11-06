//! Conda (Anaconda.org channels): registry metadata.

use filefacts::{Ecosystem, Registry};
use serde::Deserialize;
use std::collections::BTreeMap;

use crate::ecosystem::{
    Coordinates, fetch_json, listed, non_empty, null_default, set_timeline, unix_secs,
};
use crate::fetch::{BlobCache, Fetch};
use crate::registry::RegistryError;

/// Anaconda.org's package document for the PURL's `channel` (conda-forge by
/// default): every file with its upload time, and lifetime downloads. A
/// channel has no per-version record, so the earliest upload of a version is
/// its publish time, and those times are the release timeline.
pub(crate) fn lookup(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let name = c.encoded_name();
    let owner = anaconda_owner(c.purl().qualifier("channel"))?;
    let doc: Package = fetch_json(
        &format!("https://api.anaconda.org/package/{owner}/{name}"),
        net,
        cache,
    )?;
    // One file per build; a version was released with its first upload.
    let mut released: BTreeMap<&str, u64> = BTreeMap::new();
    for file in &doc.files {
        if let (Some(version), Some(at)) = (
            file.version.as_deref(),
            file.upload_time.as_deref().and_then(unix_secs),
        ) {
            released
                .entry(version)
                .and_modify(|first| *first = (*first).min(at))
                .or_insert(at);
        }
    }

    let mut record = c.record(Ecosystem::Conda, c.name(), doc.latest_version);
    // A version with no files gets no date; the package's `created_at` is its
    // first upload, not this version's.
    record.published_at = listed(
        released.get(record.version.as_str()).copied(),
        c.name(),
        &record.version,
    );
    record.first_published_at = doc.created_at.as_deref().and_then(unix_secs);
    record.description = doc.summary;
    record.homepage = doc.home;
    record.repository = doc.source_git_url.or(doc.dev_url);
    record.license = doc.license;
    record.downloads_total = doc.ndownloads;
    set_timeline(&mut record, released.into_values());
    Ok(record)
}

/// The parts of an Anaconda.org package document the registry record reads.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Package {
    latest_version: Option<String>,
    #[serde(deserialize_with = "null_default")]
    files: Vec<PackageFile>,
    created_at: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    summary: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    home: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    source_git_url: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    dev_url: Option<String>,
    #[serde(deserialize_with = "non_empty")]
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
        Some(other) => {
            tracing::debug!(
                channel = %other.escape_debug(),
                "conda lookup refused: channel is not an anaconda.org account"
            );
            Err(RegistryError::OffRegistry)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::look;
    use crate::fetch::Fixtures;

    #[test]
    fn conda_anaconda_normalizes() {
        let doc = serde_json::json!({
            "latest_version": "1.9.3", "summary": "Scientific computing",
            "license": "BSD-3-Clause", "home": "https://numpy.org",
            "dev_url": "https://github.com/numpy/numpy", "source_git_url": "",
            "ndownloads": 138_106_777u64,
            "files": [{"version": "1.9.3", "upload_time": "2021-04-23T10:00:00.000Z"},
                      {"version": "1.9.3", "upload_time": "2021-04-23T11:00:00.000Z"},
                      {"version": "1.9.2", "upload_time": "2021-01-01T00:00:00.000Z"}]
        })
        .to_string();
        let net = Fixtures::default()
            .with(
                "https://api.anaconda.org/package/conda-forge/numpy",
                doc.as_bytes(),
            )
            .with(
                "https://api.anaconda.org/package/anaconda/numpy",
                br#"{"latest_version": "1.0.0"}"#,
            );
        let look = |purl: &str| look(purl, &net);
        let r = look("pkg:conda/numpy").expect("registry");
        assert_eq!(r.ecosystem, Ecosystem::Conda);
        assert_eq!(r.version, "1.9.3");
        assert_eq!(r.published_at, Some(1_619_172_000));
        // One release per version, dated by its first upload.
        assert_eq!(r.release_count, Some(2));
        assert_eq!(r.previous_published_at, Some(1_609_459_200)); // 2021-01-01
        assert_eq!(
            r.repository.as_deref(),
            Some("https://github.com/numpy/numpy"),
            "an empty source_git_url falls back to dev_url"
        );
        assert_eq!(r.downloads_total, Some(138_106_777));

        // The channel qualifier picks the account whose record is read.
        let r = look("pkg:conda/numpy?channel=main").expect("registry");
        assert_eq!(r.version, "1.0.0");
        assert_eq!(
            look("pkg:conda/numpy?channel=https://evil.test/c"),
            Err(RegistryError::OffRegistry)
        );
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
