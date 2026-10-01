//! RubyGems: registry metadata and artifact resolution.

use filefacts::Registry;
use serde::Deserialize;
use std::collections::BTreeMap;

use crate::ecosystem::{fetch_json, null_default, parse_rfc3339_secs};
use crate::fetch::{
    ArtifactCandidate, BlobCache, Fetch, cached_metadata, meta_ttl_pinned, meta_ttl_unpinned,
    percent_decode, repository_base, safe_filename_part,
};
use crate::purl::Purl;
use crate::registry::RegistryError;

pub(crate) fn gem_artifacts(
    name: &str,
    requested_version: Option<&str>,
    purl: &Purl,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Vec<ArtifactCandidate> {
    let Some(repository) = repository_base(purl, "https://rubygems.org") else {
        return Vec::new();
    };
    let api = format!("{repository}/api/v1/versions/{name}.json");
    let ttl = if requested_version.is_some() {
        meta_ttl_pinned()
    } else {
        meta_ttl_unpinned()
    };
    let entries = cached_metadata(&api, net, &cache.with_meta_ttl(ttl))
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default();
    let requested = requested_version.map(percent_decode);
    let resolved =
        requested.or_else(|| entries.first()?.get("number")?.as_str().map(str::to_string));
    let Some(version) = resolved else {
        return Vec::new();
    };
    let mut candidates: Vec<_> = entries
        .iter()
        .filter(|entry| {
            entry.get("number").and_then(serde_json::Value::as_str) == Some(version.as_str())
        })
        .filter(|entry| {
            entry
                .get("platform")
                .and_then(serde_json::Value::as_str)
                .is_none_or(safe_filename_part)
        })
        .map(|entry| gem_candidate(&repository, name, &version, entry))
        .collect();
    if candidates.is_empty() {
        return Vec::new();
    }
    candidates.sort_by(|left, right| left.file_name.cmp(&right.file_name));
    let explicit_platform = purl.qualifier("platform");
    let wanted = explicit_platform.unwrap_or("ruby");
    let mut preferred = candidates.iter().position(|candidate| {
        candidate
            .qualifiers
            .get("platform")
            .is_some_and(|platform| platform == wanted)
    });
    if let Some(file_name) = purl.qualifier("file_name") {
        preferred = candidates
            .iter()
            .position(|candidate| candidate.file_name == file_name);
    }
    for (index, candidate) in candidates.iter_mut().enumerate() {
        candidate.preferred = Some(index) == preferred;
    }
    candidates.sort_by_key(|candidate| !candidate.preferred);
    candidates
}

fn gem_candidate(
    repository: &str,
    name: &str,
    version: &str,
    entry: &serde_json::Value,
) -> ArtifactCandidate {
    let platform = entry
        .get("platform")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("ruby");
    let mut candidate = gem_candidate_for_platform(repository, name, version, platform);
    if let Some(sha256) = entry.get("sha").and_then(serde_json::Value::as_str)
        && !sha256.is_empty()
    {
        candidate
            .checksums
            .insert("sha256".into(), sha256.to_string());
    }
    for key in ["ruby_version", "rubygems_version"] {
        if let Some(value) = entry.get(key).and_then(serde_json::Value::as_str) {
            candidate.attributes.insert(key.into(), value.to_string());
        }
    }
    candidate
}

fn gem_candidate_for_platform(
    repository: &str,
    name: &str,
    version: &str,
    platform: &str,
) -> ArtifactCandidate {
    let suffix = if platform == "ruby" {
        String::new()
    } else {
        format!("-{platform}")
    };
    let file_name = format!("{name}-{version}{suffix}.gem");
    let mut qualifiers = BTreeMap::new();
    qualifiers.insert("platform".into(), platform.to_string());
    let mut attributes = BTreeMap::new();
    attributes.insert("kind".into(), "gem".into());
    attributes.insert("version".into(), version.to_string());
    ArtifactCandidate {
        release_purl: None,
        artifact_purl: None,
        url: format!("{repository}/downloads/{file_name}"),
        file_name,
        qualifiers,
        attributes,
        checksums: BTreeMap::new(),
        preferred: false,
    }
}

/// RubyGems: a clean JSON API. The package endpoint carries downloads, author,
/// and links; the per-version publish date comes from the versions endpoint.
pub(crate) fn gem(
    name: &str,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let doc: GemInfo = fetch_json(
        &format!("https://rubygems.org/api/v1/gems/{name}.json"),
        net,
        cache,
    )?;
    let resolved = version
        .map(percent_decode)
        .or_else(|| doc.version.clone())
        .unwrap_or_default();

    // The gem endpoint omits dates; the versions list carries `created_at` per
    // release. A version the list lacks gets no date rather than the newest's.
    let published_at = fetch_json::<Vec<GemVersion>>(
        &format!("https://rubygems.org/api/v1/versions/{name}.json"),
        net,
        cache,
    )
    .ok()
    .and_then(|vs| {
        vs.iter()
            .find(|v| v.number.as_deref() == Some(resolved.as_str()))?
            .created_at
            .as_deref()
            .and_then(parse_rfc3339_secs)
    });

    Ok(Registry {
        ecosystem: "gem".into(),
        name: name.to_string(),
        version: resolved,
        published_at,
        author: doc.authors,
        description: doc.info,
        homepage: doc.homepage_uri,
        repository: doc.source_code_uri,
        license: doc.licenses.into_iter().next(),
        downloads_total: doc.downloads,
        downloads_recent: doc.version_downloads,
        ..Default::default()
    })
}

/// The RubyGems gem document (`/api/v1/gems/{name}.json`): latest version and downloads.
#[derive(Default, Deserialize)]
#[serde(default)]
struct GemInfo {
    version: Option<String>,
    authors: Option<String>,
    info: Option<String>,
    homepage_uri: Option<String>,
    source_code_uri: Option<String>,
    #[serde(deserialize_with = "null_default")]
    licenses: Vec<String>,
    downloads: Option<u64>,
    version_downloads: Option<u64>,
}

/// One release in the RubyGems versions list (`/api/v1/versions/{name}.json`).
#[derive(Default, Deserialize)]
#[serde(default)]
struct GemVersion {
    number: Option<String>,
    created_at: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::fetch::{BlobCache, Fixtures};

    #[test]
    fn gem_api_normalizes() {
        let gem_doc = serde_json::json!({
            "name": "rails", "version": "8.1.3", "downloads": 756_666_563u64,
            "version_downloads": 7_420_432u64, "authors": "David Heinemeier Hansson",
            "info": "Full-stack web framework", "licenses": ["MIT"],
            "homepage_uri": "https://rubyonrails.org",
            "source_code_uri": "https://github.com/rails/rails"
        })
        .to_string();
        let versions = serde_json::json!([
            {"number": "8.1.3", "created_at": "2021-04-23T10:00:00.000Z"},
            {"number": "8.1.2", "created_at": "2021-01-01T00:00:00.000Z"}
        ])
        .to_string();
        let net = Fixtures::default()
            .with(
                "https://rubygems.org/api/v1/gems/rails.json",
                gem_doc.as_bytes(),
            )
            .with(
                "https://rubygems.org/api/v1/versions/rails.json",
                versions.as_bytes(),
            );
        let cache = BlobCache::disabled();
        let r = gem("rails", None, &net, &cache).expect("registry");
        assert_eq!(r.ecosystem, "gem");
        assert_eq!(r.version, "8.1.3");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(r.author.as_deref(), Some("David Heinemeier Hansson"));
        assert_eq!(r.license.as_deref(), Some("MIT"));
        assert_eq!(r.downloads_total, Some(756_666_563));
    }
}
