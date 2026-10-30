//! crates.io (Cargo): registry metadata, and artifact resolution for crates.io
//! and for alternative registries named by `repository_url`.

use filefacts::{Ecosystem, Registry};
use serde::Deserialize;

use crate::ecosystem::{Coordinates, fetch_json, null_default, set_timeline, unix_secs};
use crate::fetch::{
    ArtifactCandidate, ArtifactKind, BlobCache, Fetch, artifact_candidate, cached_metadata_status,
    deterministic_artifacts, file_name_matches, is_crates_io, is_web_scheme, percent_decode,
    purl_checksums,
};
use crate::registry::RegistryError;

/// The `.crate` for `purl`. crates.io's download URL is computable; an
/// alternative registry's comes from its index `config.json` `dl` template,
/// filled with the PURL's `sha256` checksum or, failing that, the index
/// record's. Empty when the registry, its template, or the version is
/// unknown; an error when the registry cannot be read.
pub(crate) fn cargo_artifacts(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Vec<ArtifactCandidate>, RegistryError> {
    let (purl, name, version) = (c.purl(), c.path(), c.encoded_version());
    let Some(repository) = purl.qualifier("repository_url") else {
        return Ok(deterministic_artifacts(purl, ArtifactKind::Crate));
    };
    if is_crates_io(repository) {
        return Ok(deterministic_artifacts(purl, ArtifactKind::Crate));
    }
    let repository = repository.trim_end_matches('/');
    let repository = repository.strip_prefix("sparse+").unwrap_or(repository);
    if !is_web_scheme(repository) {
        tracing::debug!(
            repository = %repository.escape_debug(),
            "cargo artifacts unresolved: repository_url is not a web URL"
        );
        return Ok(Vec::new());
    }
    let Some(version) = version.map(percent_decode) else {
        tracing::debug!(
            repository = %repository.escape_debug(),
            "cargo artifacts unresolved: an alternative registry needs a version"
        );
        return Ok(Vec::new());
    };
    let config_url = format!("{repository}/config.json");
    let config: IndexConfig = fetch_json(
        &config_url,
        net,
        &cache.with_meta_ttl(cache.meta_ttl_pinned()),
    )
    .inspect_err(|error| {
        tracing::debug!(url = %config_url, %error, "cargo artifacts unresolved: no readable index config");
    })?;
    let mut checksums = purl_checksums(purl);
    if !checksums.contains_key("sha256") {
        // The index's checksum enriches the candidate, unless the download
        // URL cannot be built without it.
        match cargo_index_checksum(repository, name, &version, net, cache) {
            Ok(Some(checksum)) => {
                checksums.insert("sha256".into(), checksum);
            }
            Err(error) if config.dl.contains("{sha256-checksum}") => return Err(error),
            Ok(None) | Err(_) => {}
        }
    }
    let Some(url) = cargo_download_url(
        &config.dl,
        name,
        &version,
        checksums.get("sha256").map(String::as_str),
    ) else {
        tracing::debug!(
            url = %config_url,
            template = %config.dl.escape_debug(),
            "cargo artifacts unresolved: the download template does not expand to a web URL"
        );
        return Ok(Vec::new());
    };
    let mut candidate = artifact_candidate(url, ArtifactKind::Crate);
    candidate.checksums = checksums;
    candidate
        .qualifiers
        .insert("repository_url".into(), repository.to_string());
    candidate.preferred = file_name_matches(purl, &candidate.file_name);
    Ok(vec![candidate])
}

/// The `cksum` the registry's index records for `name` `version`: the sparse
/// index file holds one JSON record per line, one line per version. A line
/// that is not such a record is skipped; an index without the crate has no
/// checksum, and one that cannot be read is an error.
fn cargo_index_checksum(
    repository: &str,
    name: &str,
    version: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Option<String>, RegistryError> {
    let lower = name.to_ascii_lowercase();
    let Some(prefix) = cargo_registry_prefix(&lower) else {
        return Ok(None);
    };
    let index_url = format!("{repository}/{prefix}/{lower}");
    let bytes = match cached_metadata_status(
        &index_url,
        &[],
        net,
        &cache.with_meta_ttl(cache.meta_ttl_pinned()),
    )
    .map_err(RegistryError::from)
    {
        Ok(bytes) => bytes,
        Err(RegistryError::NotFound) => return Ok(None),
        Err(error) => {
            tracing::debug!(url = %index_url, %error, "cargo index unreadable");
            return Err(error);
        }
    };
    let checksum = String::from_utf8_lossy(&bytes)
        .lines()
        .filter_map(|line| serde_json::from_str::<IndexEntry>(line).ok())
        .find(|entry| entry.vers == version)
        .map(|entry| entry.cksum);
    if checksum.is_none() {
        tracing::debug!(url = %index_url, version = %version.escape_debug(), "cargo index has no record of the version");
    }
    Ok(checksum)
}

/// Expand a registry's `dl` template for `name` `version`. A template with no
/// `{…}` marker is a base the standard `/{crate}/{version}/download` path is
/// appended to. `None` when the result is not a web URL, or the template
/// wants a `{sha256-checksum}` and there is no hex digest to give it: the
/// digest is never invented, and nothing but hex may enter the path.
fn cargo_download_url(
    template: &str,
    name: &str,
    version: &str,
    sha256: Option<&str>,
) -> Option<String> {
    let sha256 = sha256.filter(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_hexdigit()));
    if template.contains("{sha256-checksum}") && sha256.is_none() {
        return None;
    }
    let prefix = cargo_registry_prefix(name)?;
    let lowerprefix = cargo_registry_prefix(&name.to_ascii_lowercase())?;
    let url = if template.contains('{') {
        template
            .replace("{crate}", name)
            .replace("{version}", version)
            .replace("{prefix}", &prefix)
            .replace("{lowerprefix}", &lowerprefix)
            .replace("{sha256-checksum}", sha256.unwrap_or_default())
    } else {
        format!(
            "{}/{name}/{version}/download",
            template.trim_end_matches('/')
        )
    };
    is_web_scheme(&url).then_some(url)
}

/// The index directory a crate name lives under: `1`, `2`, `3/{first}`, or
/// `{first two}/{next two}` by length. `None` for an empty name.
fn cargo_registry_prefix(name: &str) -> Option<String> {
    let characters: Vec<char> = name.chars().collect();
    Some(match characters.as_slice() {
        [] => return None,
        [_] => "1".to_string(),
        [_, _] => "2".to_string(),
        [first, _, _] => format!("3/{first}"),
        [a, b, c, d, ..] => format!("{a}{b}/{c}{d}"),
    })
}

/// An alternative registry's index `config.json`, as far as downloads go.
#[derive(Deserialize)]
struct IndexConfig {
    dl: String,
}

/// One version's record in a sparse index file.
#[derive(Deserialize)]
struct IndexEntry {
    vers: String,
    cksum: String,
}

/// Look up the crate `c` names on crates.io. The crate document carries
/// popularity and links, and lists every version with its own publish time
/// and yank flag.
pub(crate) fn lookup(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let doc: CrateResponse = fetch_json(
        &format!("https://crates.io/api/v1/crates/{}", c.encoded_name()),
        net,
        cache,
    )?;
    let krate = &doc.krate;

    // A crate with no stable release has a `null` max stable version; its
    // newest pre-release is then the latest there is.
    let latest = krate
        .max_stable_version
        .as_deref()
        .or(krate.max_version.as_deref());
    let version = c.target(latest);
    let ver = doc
        .versions
        .iter()
        .find(|v| v.num.as_deref() == Some(version));

    let mut p = Registry::new(Ecosystem::Crates, c.name().to_string());
    p.version = version.to_string();
    // A version the list lacks has no date of its own; the crate's
    // `created_at` is its first release, not this one.
    p.published_at = ver
        .and_then(|v| v.created_at.as_deref())
        .and_then(unix_secs);
    p.first_published_at = krate.created_at.as_deref().and_then(unix_secs);
    p.latest_version = latest.map(str::to_string);
    p.description = krate.description.clone();
    p.homepage = krate.homepage.clone();
    p.repository = krate.repository.clone();
    p.license = ver.and_then(|v| v.license.clone());
    p.downloads_total = krate.downloads;
    p.downloads_recent = krate.recent_downloads;
    p.version_removed = ver.and_then(|v| v.yanked);
    set_timeline(
        &mut p,
        doc.versions
            .iter()
            .filter_map(|v| v.created_at.as_deref().and_then(unix_secs)),
    );
    Ok(p)
}

/// The crates.io `/api/v1/crates/{name}` response, as far as the record reads it.
#[derive(Deserialize)]
struct CrateResponse {
    #[serde(rename = "crate")]
    krate: Crate,
    #[serde(default, deserialize_with = "null_default")]
    versions: Vec<CrateVersion>,
}

/// The crate-level facts: latest versions, popularity, and links.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Crate {
    max_stable_version: Option<String>,
    max_version: Option<String>,
    created_at: Option<String>,
    description: Option<String>,
    homepage: Option<String>,
    repository: Option<String>,
    downloads: Option<u64>,
    recent_downloads: Option<u64>,
}

/// One published version of the crate.
#[derive(Default, Deserialize)]
#[serde(default)]
struct CrateVersion {
    num: Option<String>,
    created_at: Option<String>,
    license: Option<String>,
    yanked: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::fetch::Fixtures;
    use filefacts::RefLocator;

    #[test]
    fn the_crate_document_normalizes() {
        let doc = serde_json::json!({
            "crate": {
                "max_stable_version": "1.1.0", "max_version": "2.0.0-rc.1",
                "created_at": "2015-01-01T00:00:00Z", "description": "codec",
                "repository": "https://github.test/c", "downloads": 100u64,
                "recent_downloads": 10u64
            },
            "versions": [
                {"num": "2.0.0-rc.1", "created_at": "2024-02-01T00:00:00Z", "yanked": false},
                {"num": "1.1.0", "created_at": "2024-01-01T00:00:00Z", "license": "MIT", "yanked": false},
                {"num": "1.0.0", "created_at": "2015-01-01T00:00:00Z", "yanked": true}
            ]
        })
        .to_string();
        let net = Fixtures::default().with("https://crates.io/api/v1/crates/c", doc.as_bytes());
        let cache = BlobCache::disabled();
        let look = |purl: &str| {
            crate::registry::lookup(&RefLocator::Purl(purl.into()), &net, &cache).expect("record")
        };

        let latest = look("pkg:cargo/c");
        assert_eq!(latest.ecosystem, Ecosystem::Crates);
        assert_eq!(latest.name, "c");
        assert_eq!(latest.version, "1.1.0", "the latest stable release");
        assert_eq!(latest.latest_version.as_deref(), Some("1.1.0"));
        assert_eq!(latest.license.as_deref(), Some("MIT"));
        assert_eq!(latest.published_at, Some(1_704_067_200)); // 2024-01-01
        assert_eq!(latest.version_removed, Some(false));
        assert_eq!(latest.release_count, Some(3));
        assert_eq!(latest.first_published_at, Some(1_420_070_400)); // 2015-01-01
        assert_eq!(latest.previous_published_at, Some(1_420_070_400));
        assert_eq!(latest.downloads_total, Some(100));
        assert_eq!(latest.downloads_recent, Some(10));

        let requested = look("pkg:cargo/c@2.0.0-rc.1");
        assert_eq!(requested.version, "2.0.0-rc.1");
        assert_eq!(requested.published_at, Some(1_706_745_600)); // 2024-02-01

        let yanked = look("pkg:cargo/c@1.0.0");
        assert_eq!(yanked.version_removed, Some(true));
        assert_eq!(yanked.deprecated, None, "a yank is not a deprecation");

        let unlisted = look("pkg:cargo/c@9.9.9");
        assert_eq!(unlisted.version, "9.9.9");
        assert_eq!(unlisted.published_at, None);
        assert_eq!(unlisted.version_removed, None);
        assert_eq!(unlisted.license, None);
    }

    #[test]
    fn download_templates_expand_or_refuse() {
        let sha = "ab12";
        assert_eq!(
            cargo_download_url(
                "https://dl.test/{crate}/{version}/download",
                "Serde",
                "1.0.0",
                None
            )
            .as_deref(),
            Some("https://dl.test/Serde/1.0.0/download")
        );
        assert_eq!(
            cargo_download_url(
                "https://dl.test/{prefix}/{lowerprefix}/{crate}",
                "Serde",
                "1.0.0",
                None
            )
            .as_deref(),
            Some("https://dl.test/Se/rd/se/rd/Serde")
        );
        assert_eq!(
            cargo_download_url("https://dl.test/api/", "serde", "1.0.0", None).as_deref(),
            Some("https://dl.test/api/serde/1.0.0/download"),
            "a marker-less template is a base"
        );
        let checksummed = "https://dl.test/{crate}/{sha256-checksum}.crate";
        assert_eq!(
            cargo_download_url(checksummed, "serde", "1.0.0", Some(sha)).as_deref(),
            Some("https://dl.test/serde/ab12.crate")
        );
        assert_eq!(
            cargo_download_url(checksummed, "serde", "1.0.0", None),
            None,
            "the digest is never invented"
        );
        assert_eq!(
            cargo_download_url(checksummed, "serde", "1.0.0", Some("../../x")),
            None,
            "a digest that is not hex never enters the path"
        );
        assert_eq!(
            cargo_download_url("file:///{crate}", "serde", "1.0.0", None),
            None
        );
    }

    #[test]
    fn index_prefixes_follow_the_name_length() {
        assert_eq!(cargo_registry_prefix(""), None);
        assert_eq!(cargo_registry_prefix("a").as_deref(), Some("1"));
        assert_eq!(cargo_registry_prefix("ab").as_deref(), Some("2"));
        assert_eq!(cargo_registry_prefix("abc").as_deref(), Some("3/a"));
        assert_eq!(cargo_registry_prefix("serde").as_deref(), Some("se/rd"));
    }

    #[test]
    fn the_index_checksum_is_the_requested_versions() {
        let index = b"{\"name\":\"foo\",\"vers\":\"0.9.0\",\"cksum\":\"aa\"}\nnot json\n{\"name\":\"foo\",\"vers\":\"1.0.0\",\"cksum\":\"bb\"}\n";
        let net = Fixtures::default().with("https://reg.test/index/3/f/foo", index);
        let cache = BlobCache::disabled();
        let checksum = |name, version| {
            cargo_index_checksum("https://reg.test/index", name, version, &net, &cache)
                .expect("index read")
        };
        assert_eq!(checksum("Foo", "1.0.0").as_deref(), Some("bb"));
        assert_eq!(checksum("foo", "0.9.0").as_deref(), Some("aa"));
        assert_eq!(checksum("foo", "2.0.0"), None);
    }
}
