//! Crates.io (Cargo): registry metadata and artifact resolution.

use filefacts::Registry;
use serde_json::Value;

use crate::ecosystem::{json_meta, parse_rfc3339_secs};
use crate::fetch::{
    ArtifactCandidate, BlobCache, Fetch, artifact_candidate, cached_metadata,
    deterministic_artifacts, file_name_matches, is_web_scheme, meta_ttl_pinned, percent_decode,
    purl_checksums,
};
use crate::purl::Purl;

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
) -> Option<Registry> {
    let doc = json_meta(
        &format!("https://crates.io/api/v1/crates/{path}"),
        net,
        cache,
    )?;
    let krate = doc.get("crate")?;

    let latest = krate
        .get("max_stable_version")
        .or_else(|| krate.get("max_version"))
        .and_then(Value::as_str);
    let requested = version.map(percent_decode);
    let version = requested.as_deref().or(latest).unwrap_or_default();
    let ver = doc
        .get("versions")
        .and_then(Value::as_array)
        .and_then(|vs| {
            vs.iter()
                .find(|v| v.get("num").and_then(Value::as_str) == Some(version))
        });

    Some(Registry {
        ecosystem: "crates".into(),
        name: path.to_string(),
        version: version.to_string(),
        // A version the list lacks has no date of its own; the crate's
        // `created_at` is its first release, not this one.
        published_at: ver
            .and_then(|v| v.get("created_at"))
            .and_then(Value::as_str)
            .and_then(parse_rfc3339_secs),
        first_published_at: krate
            .get("created_at")
            .and_then(Value::as_str)
            .and_then(parse_rfc3339_secs),
        latest_version: latest.map(str::to_string),
        author: None,
        title: None,
        description: krate
            .get("description")
            .and_then(Value::as_str)
            .map(str::to_string),
        homepage: krate
            .get("homepage")
            .and_then(Value::as_str)
            .map(str::to_string),
        repository: krate
            .get("repository")
            .and_then(Value::as_str)
            .map(str::to_string),
        license: ver
            .and_then(|v| v.get("license"))
            .and_then(Value::as_str)
            .map(str::to_string),
        downloads_total: krate.get("downloads").and_then(Value::as_u64),
        downloads_recent: krate.get("recent_downloads").and_then(Value::as_u64),
        deprecated: ver
            .and_then(|v| v.get("yanked"))
            .and_then(Value::as_bool)
            .and_then(|y| y.then(|| "yanked".to_string())),
        ..Default::default()
    })
}
