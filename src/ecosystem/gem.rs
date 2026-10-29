//! RubyGems: registry metadata and artifact resolution. The gem document
//! carries the package's facts; the versions document dates every release
//! and lists each platform's build, which is what the artifact resolver
//! reads.

use filefacts::{Ecosystem, Registry};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};

use crate::ecosystem::{
    Coordinates, fetch_json, for_version, non_empty, null_default, optional, set_timeline,
    unix_secs,
};
use crate::fetch::{
    ArtifactCandidate, ArtifactKind, BlobCache, Fetch, artifact_candidate, repository_base,
    safe_filename_part,
};
use crate::registry::RegistryError;

/// One `.gem` per platform built for `purl`'s release (the newest listed
/// when unversioned). The `file_name` qualifier picks one exactly; else the
/// `platform` qualifier's build, else the pure-Ruby one, is preferred and
/// sorted first. A platform that could restructure the download URL is
/// dropped.
pub(crate) fn gem_artifacts(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Vec<ArtifactCandidate> {
    let (name, requested_version, purl) = (c.path(), c.encoded_version(), c.purl());
    let Some(repository) = repository_base(purl, "https://rubygems.org") else {
        tracing::debug!(
            purl = %purl.to_string().escape_debug(),
            "gem artifacts unresolved: repository_url is not a web URL"
        );
        return Vec::new();
    };
    let api = format!("{repository}/api/v1/versions/{name}.json");
    let builds: Vec<GemVersion> = match fetch_json(
        &api,
        net,
        &for_version(cache, requested_version),
    ) {
        Ok(builds) => builds,
        Err(error) => {
            tracing::debug!(url = %api, %error, "gem artifacts unresolved: versions unreadable");
            return Vec::new();
        }
    };
    let Some(version) = purl.version().or_else(|| builds.first()?.number.as_deref()) else {
        tracing::debug!(url = %api, "gem artifacts unresolved: no version listed");
        return Vec::new();
    };
    let mut candidates: Vec<_> = builds
        .iter()
        .filter(|build| build.number.as_deref() == Some(version))
        .filter(|build| {
            let safe = build.platform.as_deref().is_none_or(safe_filename_part);
            if !safe {
                tracing::debug!(
                    url = %api,
                    platform = ?build.platform,
                    "gem build skipped: platform is not a file-name part"
                );
            }
            safe
        })
        .map(|build| gem_candidate(&repository, name, version, build))
        .collect();
    candidates.sort_by(|left, right| left.file_name.cmp(&right.file_name));
    let preferred = match purl.qualifier("file_name") {
        Some(file_name) => candidates.iter().position(|c| c.file_name == file_name),
        None => {
            let wanted = purl.qualifier("platform").unwrap_or("ruby");
            candidates
                .iter()
                .position(|c| c.qualifiers.get("platform").is_some_and(|p| p == wanted))
        }
    };
    for (index, candidate) in candidates.iter_mut().enumerate() {
        candidate.preferred = Some(index) == preferred;
    }
    candidates.sort_by_key(|candidate| !candidate.preferred);
    candidates
}

/// The candidate for one platform's build of `name` `version`.
fn gem_candidate(
    repository: &str,
    name: &str,
    version: &str,
    build: &GemVersion,
) -> ArtifactCandidate {
    let platform = build.platform.as_deref().unwrap_or("ruby");
    let suffix = if platform == "ruby" {
        String::new()
    } else {
        format!("-{platform}")
    };
    let file_name = format!("{name}-{version}{suffix}.gem");
    let mut qualifiers = BTreeMap::new();
    qualifiers.insert("platform".into(), platform.to_string());
    let mut attributes = BTreeMap::new();
    for (key, value) in [
        ("ruby_version", &build.ruby_version),
        ("rubygems_version", &build.rubygems_version),
    ] {
        if let Some(value) = value {
            attributes.insert(key.into(), value.clone());
        }
    }
    let mut checksums = BTreeMap::new();
    if let Some(sha256) = &build.sha {
        checksums.insert("sha256".into(), sha256.clone());
    }
    let url = format!("{repository}/downloads/{file_name}");
    ArtifactCandidate {
        file_name,
        version: Some(version.to_string()),
        qualifiers,
        attributes,
        checksums,
        preferred: false,
        ..artifact_candidate(url, ArtifactKind::Gem)
    }
}

/// Look up the gem `c` names on RubyGems. The gem document carries the latest
/// version, downloads, author, and links; the versions document dates each
/// release, so it gives the target's publish time and the release timeline.
pub(crate) fn lookup(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let name = c.encoded_name();
    let doc: GemInfo = fetch_json(
        &format!("https://rubygems.org/api/v1/gems/{name}.json"),
        net,
        cache,
    )?;
    let version = c.target(doc.version.as_deref());

    // One entry per platform build; a release is dated by its first build.
    let versions = format!("https://rubygems.org/api/v1/versions/{name}.json");
    let mut released: HashMap<&str, u64> = HashMap::new();
    let builds: Vec<GemVersion> =
        optional(fetch_json(&versions, net, cache), &versions).unwrap_or_default();
    for build in &builds {
        let (Some(number), Some(at)) = (
            build.number.as_deref(),
            build.created_at.as_deref().and_then(unix_secs),
        ) else {
            continue;
        };
        released
            .entry(number)
            .and_modify(|first| *first = (*first).min(at))
            .or_insert(at);
    }

    let mut p = Registry::new(Ecosystem::Gem, c.name().to_string());
    p.version = version.to_string();
    // A version the list lacks gets no date rather than the newest's.
    p.published_at = released.get(version).copied();
    p.latest_version = doc.version.clone();
    p.author = doc.authors;
    p.description = doc.info;
    p.homepage = doc.homepage_uri;
    p.repository = doc.source_code_uri;
    p.license = doc.licenses.into_iter().next();
    p.downloads_total = doc.downloads;
    set_timeline(&mut p, released.into_values());
    Ok(p)
}

/// The RubyGems gem document (`/api/v1/gems/{name}.json`): latest version,
/// downloads, and links.
#[derive(Default, Deserialize)]
#[serde(default)]
struct GemInfo {
    #[serde(deserialize_with = "non_empty")]
    version: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    authors: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    info: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    homepage_uri: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    source_code_uri: Option<String>,
    #[serde(deserialize_with = "null_default")]
    licenses: Vec<String>,
    downloads: Option<u64>,
}

/// One platform build of a release in the RubyGems versions document
/// (`/api/v1/versions/{name}.json`), newest release first.
#[derive(Default, Deserialize)]
#[serde(default)]
struct GemVersion {
    number: Option<String>,
    created_at: Option<String>,
    platform: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    sha: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    ruby_version: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    rubygems_version: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::coordinates;

    use crate::fetch::Fixtures;
    use filefacts::RefLocator;

    fn rails() -> Fixtures {
        let gem_doc = serde_json::json!({
            "name": "rails", "version": "8.1.3", "downloads": 756_666_563u64,
            "version_downloads": 7_420_432u64, "authors": "David Heinemeier Hansson",
            "info": "Full-stack web framework", "licenses": ["MIT"],
            "homepage_uri": "https://rubyonrails.org",
            "source_code_uri": "https://github.com/rails/rails"
        })
        .to_string();
        let versions = serde_json::json!([
            {"number": "8.1.3", "platform": "ruby", "created_at": "2021-04-23T10:00:00.000Z", "sha": "aa"},
            {"number": "8.1.3", "platform": "x86_64-linux", "created_at": "2021-04-23T11:00:00.000Z"},
            {"number": "8.1.3", "platform": "../evil", "created_at": "2021-04-23T11:00:00.000Z"},
            {"number": "8.1.2", "platform": "ruby", "created_at": "2021-01-01T00:00:00.000Z"}
        ])
        .to_string();
        Fixtures::default()
            .with(
                "https://rubygems.org/api/v1/gems/rails.json",
                gem_doc.as_bytes(),
            )
            .with(
                "https://rubygems.org/api/v1/versions/rails.json",
                versions.as_bytes(),
            )
    }

    #[test]
    fn gem_api_normalizes() {
        let net = rails();
        let r = crate::registry::lookup(
            &RefLocator::Purl("pkg:gem/rails".into()),
            &net,
            &BlobCache::disabled(),
        )
        .expect("registry");
        assert_eq!(r.ecosystem, Ecosystem::Gem);
        assert_eq!(r.version, "8.1.3");
        assert_eq!(r.latest_version.as_deref(), Some("8.1.3"));
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(r.author.as_deref(), Some("David Heinemeier Hansson"));
        assert_eq!(r.license.as_deref(), Some("MIT"));
        assert_eq!(r.downloads_total, Some(756_666_563));
        // `version_downloads` counts this version's lifetime, not a recent window.
        assert_eq!(r.downloads_recent, None);
        // Two releases, each dated by its first build.
        assert_eq!(r.release_count, Some(2));
        assert_eq!(r.first_published_at, Some(1_609_459_200)); // 2021-01-01
        assert_eq!(r.previous_published_at, Some(1_609_459_200));
    }

    #[test]
    fn the_artifact_resolver_reads_the_versions_document() {
        let net = rails();
        let builds = gem_artifacts(
            &coordinates("pkg:gem/rails?platform=x86_64-linux"),
            &net,
            &BlobCache::disabled(),
        );
        assert_eq!(builds.len(), 2, "the unsafe platform is dropped");
        assert!(builds[0].preferred);
        assert_eq!(
            builds[0].url,
            "https://rubygems.org/downloads/rails-8.1.3-x86_64-linux.gem"
        );
        assert_eq!(
            builds[1].checksums.get("sha256").map(String::as_str),
            Some("aa")
        );
    }
}
