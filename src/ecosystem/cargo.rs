//! Crates.io (Cargo): registry metadata and artifact resolution.

use filefacts::Registry;
use serde::Deserialize;

use crate::ecosystem::{fetch_json, null_default, parse_rfc3339_secs, present};
use crate::fetch::{
    ArtifactCandidate, BlobCache, Fetch, artifact_candidate, cached_metadata,
    deterministic_artifacts, file_name_matches, is_web_scheme, meta_ttl_pinned, percent_decode,
    purl_checksums,
};
use crate::purl::Purl;
use crate::registry::RegistryError;

pub(crate) fn cargo_artifacts(
    purl: &Purl,
    name: &str,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Vec<ArtifactCandidate> {
    let Some(repository) = purl.qualifier("repository_url") else {
        return deterministic_artifacts(purl, "crate");
    };
    let repository = repository.trim_end_matches('/');
    if matches!(repository, "https://crates.io" | "https://index.crates.io") {
        return deterministic_artifacts(purl, "crate");
    }
    let repository = repository.strip_prefix("sparse+").unwrap_or(repository);
    if !is_web_scheme(repository) {
        return Vec::new();
    }
    let Some(version) = version.map(percent_decode) else {
        return Vec::new();
    };
    let config_url = format!("{repository}/config.json");
    let Some(download) = cached_metadata(&config_url, net, &cache.with_meta_ttl(meta_ttl_pinned()))
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|config| config.get("dl")?.as_str().map(str::to_string))
    else {
        return Vec::new();
    };
    let mut checksums = purl_checksums(purl);
    if !checksums.contains_key("sha256")
        && let Some(checksum) = cargo_index_checksum(repository, name, &version, net, cache)
    {
        checksums.insert("sha256".into(), checksum);
    }
    let url = cargo_download_url(
        &download,
        name,
        &version,
        checksums.get("sha256").map(String::as_str),
    );
    let Some(url) = url else {
        return Vec::new();
    };
    let mut candidate = artifact_candidate(url, "crate");
    candidate.checksums = checksums;
    candidate
        .qualifiers
        .insert("repository_url".into(), repository.to_string());
    candidate.preferred = file_name_matches(purl, &candidate.file_name);
    vec![candidate]
}

fn cargo_index_checksum(
    repository: &str,
    name: &str,
    version: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Option<String> {
    let lower = name.to_ascii_lowercase();
    let prefix = cargo_registry_prefix(&lower)?;
    let index_url = format!("{repository}/{prefix}/{lower}");
    let bytes = cached_metadata(&index_url, net, &cache.with_meta_ttl(meta_ttl_pinned()))?;
    std::str::from_utf8(&bytes)
        .ok()?
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find_map(|entry| {
            (entry.get("vers")?.as_str()? == version)
                .then(|| entry.get("cksum")?.as_str().map(str::to_string))
                .flatten()
        })
}

fn cargo_download_url(
    template: &str,
    name: &str,
    version: &str,
    sha256: Option<&str>,
) -> Option<String> {
    if template.contains("{sha256-checksum}") && sha256.is_none() {
        // This template cannot be expanded without either an explicit PURL
        // checksum or the crate's index record. Never invent the digest.
        return None;
    }
    let prefix = cargo_registry_prefix(name)?;
    let lowerprefix = cargo_registry_prefix(&name.to_ascii_lowercase())?;
    let has_markers = template.contains('{');
    let expanded = template
        .replace("{crate}", name)
        .replace("{version}", version)
        .replace("{prefix}", &prefix)
        .replace("{lowerprefix}", &lowerprefix)
        .replace("{sha256-checksum}", sha256.unwrap_or_default());
    let url = if has_markers {
        expanded
    } else {
        format!(
            "{}/{name}/{version}/download",
            expanded.trim_end_matches('/')
        )
    };
    is_web_scheme(&url).then_some(url)
}

fn cargo_registry_prefix(name: &str) -> Option<String> {
    let characters: Vec<char> = name.chars().collect();
    Some(match characters.len() {
        0 => return None,
        1 => "1".to_string(),
        2 => "2".to_string(),
        3 => format!("3/{}", characters[0]),
        _ => format!(
            "{}{}/{}{}",
            characters[0], characters[1], characters[2], characters[3]
        ),
    })
}

/// crates.io: the per-crate API returns custody-free but rich popularity and
/// links; the matching version object carries its own publish time.
pub(crate) fn crates(
    path: &str,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let doc: CrateResponse = fetch_json(
        &format!("https://crates.io/api/v1/crates/{path}"),
        net,
        cache,
    )?;
    let krate = &doc.krate;

    let latest = krate
        .max_stable_version
        .as_ref()
        .unwrap_or(&krate.max_version)
        .as_deref();
    let requested = version.map(percent_decode);
    let version = requested.as_deref().or(latest).unwrap_or_default();
    let ver = doc
        .versions
        .iter()
        .find(|v| v.num.as_deref() == Some(version));

    Ok(Registry {
        ecosystem: "crates".into(),
        name: path.to_string(),
        version: version.to_string(),
        // A version the list lacks has no date of its own; the crate's
        // `created_at` is its first release, not this one.
        published_at: ver
            .and_then(|v| v.created_at.as_deref())
            .and_then(parse_rfc3339_secs),
        first_published_at: krate.created_at.as_deref().and_then(parse_rfc3339_secs),
        latest_version: latest.map(str::to_string),
        author: None,
        title: None,
        description: krate.description.clone(),
        homepage: krate.homepage.clone(),
        repository: krate.repository.clone(),
        license: ver.and_then(|v| v.license.clone()),
        downloads_total: krate.downloads,
        downloads_recent: krate.recent_downloads,
        deprecated: ver
            .and_then(|v| v.yanked)
            .and_then(|y| y.then(|| "yanked".to_string())),
        ..Default::default()
    })
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
    /// `null` for a crate with no stable release, and that `null` is the
    /// answer: `max_version` stands in only when the key is absent.
    #[serde(deserialize_with = "present")]
    max_stable_version: Option<Option<String>>,
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
