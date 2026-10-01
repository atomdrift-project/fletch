//! PyPI: registry metadata and artifact resolution.

use filefacts::Registry;
use serde::Deserialize;
use serde::de::IgnoredAny;
use std::collections::{BTreeMap, HashMap};

use crate::ecosystem::{email_domain, fetch_json, null_default, parse_rfc3339_secs};
use crate::fetch::{
    ArtifactCandidate, BlobCache, Fetch, META_TTL_IMMUTABLE, cached_metadata, file_name_from_url,
    meta_ttl_unpinned, percent_decode, repository_base,
};
use crate::purl::Purl;
use crate::registry::RegistryError;

pub(crate) fn pypi_artifacts(
    name: &str,
    version: Option<&str>,
    purl: &Purl,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Vec<ArtifactCandidate> {
    let Some(repository) = repository_base(purl, "https://pypi.org") else {
        return Vec::new();
    };
    let api = version.map_or_else(
        || format!("{repository}/pypi/{name}/json"),
        |value| format!("{repository}/pypi/{name}/{value}/json"),
    );
    let ttl = if version.is_some() {
        META_TTL_IMMUTABLE
    } else {
        meta_ttl_unpinned()
    };
    let Some(doc) = cached_metadata(&api, net, &cache.with_meta_ttl(ttl))
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
    else {
        return Vec::new();
    };
    let resolved_version = version
        .map(percent_decode)
        .or_else(|| doc.pointer("/info/version")?.as_str().map(str::to_string))
        .unwrap_or_default();
    let Some(urls) = doc.get("urls").and_then(serde_json::Value::as_array) else {
        return Vec::new();
    };
    let mut candidates: Vec<_> = urls
        .iter()
        .filter_map(|file| pypi_candidate(file, name, &resolved_version))
        .collect();
    let exact = purl.qualifier("file_name");
    let kind = purl.qualifier("kind");
    candidates.sort_by_key(|candidate| {
        (
            pypi_rank(candidate, exact, kind),
            candidate.file_name.clone(),
        )
    });
    let preferred = if let Some(file_name) = exact {
        candidates
            .iter()
            .position(|candidate| candidate.file_name == file_name)
    } else {
        (!candidates.is_empty()).then_some(0)
    };
    for (index, candidate) in candidates.iter_mut().enumerate() {
        candidate.preferred = Some(index) == preferred;
    }
    candidates
}

fn pypi_candidate(
    file: &serde_json::Value,
    name: &str,
    version: &str,
) -> Option<ArtifactCandidate> {
    let url = file.get("url")?.as_str()?.to_string();
    let file_name = file
        .get("filename")
        .and_then(serde_json::Value::as_str)
        .map_or_else(|| file_name_from_url(&url), str::to_string);
    let package_type = file
        .get("packagetype")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("distribution");
    let kind = match package_type {
        "bdist_wheel" => "wheel",
        "sdist" => "sdist",
        other => other,
    };
    let mut qualifiers = BTreeMap::new();
    qualifiers.insert("file_name".into(), file_name.clone());
    let mut attributes = BTreeMap::new();
    attributes.insert("kind".into(), kind.to_string());
    attributes.insert("version".into(), version.to_string());
    if kind == "wheel" {
        attributes.extend(wheel_attributes(&file_name, name, version));
    }
    for key in ["python_version", "requires_python"] {
        if let Some(value) = file.get(key).and_then(serde_json::Value::as_str) {
            attributes.insert(key.to_string(), value.to_string());
        }
    }
    if file
        .get("yanked")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        attributes.insert("yanked".into(), "true".into());
    }
    if let Some(reason) = file
        .get("yanked_reason")
        .and_then(serde_json::Value::as_str)
    {
        attributes.insert("yanked_reason".into(), reason.to_string());
    }
    let checksums = file
        .get("digests")
        .and_then(serde_json::Value::as_object)
        .map(|digests| {
            digests
                .iter()
                .filter_map(|(algorithm, value)| {
                    value.as_str().map(|digest| {
                        (
                            algorithm.to_ascii_lowercase().replace('_', "-"),
                            digest.to_string(),
                        )
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Some(ArtifactCandidate {
        release_purl: None,
        artifact_purl: None,
        url,
        file_name,
        qualifiers,
        attributes,
        checksums,
        preferred: false,
    })
}

fn wheel_attributes(file_name: &str, name: &str, version: &str) -> BTreeMap<String, String> {
    let mut attributes = BTreeMap::new();
    let Some(stem) = file_name.strip_suffix(".whl") else {
        return attributes;
    };

    // Wheel filenames are `{distribution}-{version}(-{build})?-{python}-{abi}-{platform}`.
    // Distribution punctuation is normalized to underscores, so remove the
    // known coordinate prefix before deciding whether the optional build tag
    // exists. Counting every `-` in the full filename misclassifies legacy
    // distributions containing a hyphen as a build tag.
    let distribution = name
        .chars()
        .map(|ch| match ch {
            '-' | '.' => '_',
            other => other.to_ascii_lowercase(),
        })
        .collect::<String>();
    let version = version.replace('-', "_");
    let prefix = format!("{distribution}-{version}-");
    let suffix = stem
        .get(..prefix.len())
        .filter(|actual| actual.eq_ignore_ascii_case(&prefix))
        .and_then(|_| stem.get(prefix.len()..))
        .unwrap_or(stem);
    let parts: Vec<&str> = suffix.split('-').collect();
    if parts.len() < 3 {
        return attributes;
    }
    let tag = parts.len() - 3;
    attributes.insert("python".into(), parts[tag].to_string());
    attributes.insert("abi".into(), parts[tag + 1].to_string());
    attributes.insert("platform".into(), parts[tag + 2].to_string());
    if parts.len() == 4 {
        attributes.insert("build".into(), parts[0].to_string());
    }
    attributes
}

fn pypi_rank(
    candidate: &ArtifactCandidate,
    exact: Option<&str>,
    requested_kind: Option<&str>,
) -> u8 {
    if let Some(file_name) = exact {
        return u8::from(candidate.file_name != file_name);
    }
    let kind = candidate.attributes.get("kind").map(String::as_str);
    let natural = if kind == Some("wheel") {
        let python = candidate.attributes.get("python").map(String::as_str);
        let abi = candidate.attributes.get("abi").map(String::as_str);
        let platform = candidate.attributes.get("platform").map(String::as_str);
        if python == Some("py3") && abi == Some("none") && platform == Some("any") {
            0
        } else if abi == Some("none") && platform == Some("any") {
            1
        } else {
            3
        }
    } else if kind == Some("sdist") {
        2
    } else {
        4
    };
    let requested = if requested_kind.is_some_and(|requested| kind != Some(requested)) {
        10 + natural
    } else {
        natural
    };
    requested
        + if candidate.attributes.contains_key("yanked") {
            20
        } else {
            0
        }
}

/// PyPI: the package-level JSON API carries the `info` block, the full
/// `releases` timeline (every version's files and upload times), `ownership`
/// (the owning accounts), and the latest release's known `vulnerabilities`.
/// The requested version's own publish time and yank status come from its
/// `releases` entry, and its vulnerabilities from the per-version endpoint when
/// it is not the latest; identity text falls back to the latest release's
/// `info`.
pub(crate) fn pypi(
    path: &str,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let doc: Project = fetch_json(&format!("https://pypi.org/pypi/{path}/json"), net, cache)?;
    let Some(info) = &doc.info else {
        return Err(RegistryError::NoRecord);
    };
    let releases = doc.releases.as_ref();

    // Target version: the one requested, else the registry's latest. A PURL
    // percent-encodes what PyPI spells literally (`1.0%2Blocal`).
    let latest = info.version.as_deref();
    let requested = version.map(percent_decode);
    let target = requested.as_deref().or(latest).unwrap_or_default();
    let target_is_latest = Some(target) == latest;
    let vulnerability_count = |v: &Option<Vec<IgnoredAny>>| v.as_ref().map(|v| v.len() as u32);

    // The earliest upload across a version's files is its publish time. The
    // target version's files come from `releases`; `urls` lists the latest
    // version's files, so it stands in only when the target *is* latest. A
    // requested version the timeline lacks gets no publish time or yank status
    // rather than latest's.
    let publish_time = |files: &[DistFile]| {
        files
            .iter()
            .filter_map(|f| f.upload_time_iso_8601.as_deref())
            .filter_map(parse_rfc3339_secs)
            .min()
    };
    let target_files = releases
        .and_then(|r| r.get(target))
        .or_else(|| target_is_latest.then_some(doc.urls.as_ref()).flatten());
    let published_at = target_files.map(Vec::as_slice).and_then(publish_time);
    // Per-version yank status (a specific version can be yanked while latest is
    // not), with the per-version reason where the file records carry one.
    let yanked_reason = target_files.and_then(|fs| {
        fs.iter().any(|f| f.yanked.unwrap_or(false)).then(|| {
            fs.iter()
                .find_map(|f| f.yanked_reason.as_deref())
                .unwrap_or("yanked")
                .to_string()
        })
    });

    let mut p = Registry {
        ecosystem: "pypi".into(),
        name: path.to_string(),
        version: target.to_string(),
        published_at,
        latest_version: latest.map(str::to_string),
        author: info
            .author
            .as_deref()
            .filter(|s| !s.is_empty())
            .or_else(|| info.maintainer.as_deref().filter(|s| !s.is_empty()))
            .map(str::to_string),
        description: info.summary.clone(),
        homepage: info
            .home_page
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        license: info
            .license
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        deprecated: yanked_reason,
        // The package document's `vulnerabilities` are the latest release's;
        // any other listed version's come from its own endpoint.
        vulnerability_count: if target_is_latest {
            vulnerability_count(&doc.vulnerabilities)
        } else if let (Some(v), Some(_)) = (version, target_files) {
            fetch_json::<Release>(
                &format!("https://pypi.org/pypi/{path}/{v}/json"),
                net,
                cache,
            )
            .ok()
            .and_then(|release| vulnerability_count(&release.vulnerabilities))
        } else {
            None
        },
        ..Default::default()
    };

    // Release timeline: one publish time per version (the earliest of its files).
    if let Some(rel) = releases {
        let mut times: Vec<u64> = rel.values().filter_map(|fs| publish_time(fs)).collect();
        times.sort_unstable();
        p.release_count = Some(times.len() as u32);
        p.first_published_at = times.first().copied();
        if let Some(this) = p.published_at {
            p.previous_published_at = times.iter().copied().filter(|&t| t < this).max();
        }
        p.release_times = times;
    }

    // Custody: the owning account (PyPI exposes roles, not a per-version
    // publisher), and the email domain from the package's author/maintainer.
    p.publisher = doc
        .ownership
        .as_ref()
        .and_then(|o| {
            o.roles
                .iter()
                .find(|r| r.role.as_deref() == Some("Owner"))
                .or_else(|| o.roles.first())
        })
        .and_then(|r| r.user.clone());
    p.publisher_email_domain = info
        .author_email
        .as_deref()
        .filter(|s| !s.is_empty())
        .or(info.maintainer_email.as_deref())
        .and_then(email_domain);

    Ok(p)
}

/// The parts of a PyPI project document (`/pypi/{name}/json`) the record reads.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Project {
    info: Option<ProjectInfo>,
    releases: Option<HashMap<String, Vec<DistFile>>>,
    urls: Option<Vec<DistFile>>,
    vulnerabilities: Option<Vec<IgnoredAny>>,
    ownership: Option<Ownership>,
}

/// The project's `info` block: the latest release's metadata.
#[derive(Default, Deserialize)]
#[serde(default)]
struct ProjectInfo {
    version: Option<String>,
    author: Option<String>,
    maintainer: Option<String>,
    summary: Option<String>,
    home_page: Option<String>,
    license: Option<String>,
    author_email: Option<String>,
    maintainer_email: Option<String>,
}

/// One uploaded file of a release, as `releases` and `urls` list it.
#[derive(Default, Deserialize)]
#[serde(default)]
struct DistFile {
    upload_time_iso_8601: Option<String>,
    yanked: Option<bool>,
    yanked_reason: Option<String>,
}

/// The project's owning accounts.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Ownership {
    #[serde(deserialize_with = "null_default")]
    roles: Vec<Role>,
}

/// One account's role on the project (`Owner`, `Maintainer`).
#[derive(Default, Deserialize)]
#[serde(default)]
struct Role {
    role: Option<String>,
    user: Option<String>,
}

/// The parts of a PyPI release document (`/pypi/{name}/{version}/json`) the record reads.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Release {
    vulnerabilities: Option<Vec<IgnoredAny>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::test_cache;

    use crate::fetch::{BlobCache, Fixtures};

    #[test]
    fn pypi_releases_yield_cadence_and_custody() {
        let doc = serde_json::json!({
            "info": {
                "version": "0.3.0",
                "summary": "a tool",
                "author_email": "Huw <huw@evil.example>",
                "license": "MIT"
            },
            "ownership": {"organization": null, "roles": [{"role": "Owner", "user": "hoo29"}]},
            "vulnerabilities": [{"id": "PYSEC-1"}],
            "urls": [
                {"packagetype": "sdist", "upload_time_iso_8601": "2021-04-23T10:00:00Z", "yanked": false}
            ],
            "releases": {
                "0.1.0": [{"upload_time_iso_8601": "2021-01-01T00:00:00Z", "yanked": false}],
                "0.2.0": [{"upload_time_iso_8601": "2021-04-22T10:00:00Z", "yanked": false}],
                "0.3.0": [{"upload_time_iso_8601": "2021-04-23T10:00:00Z", "yanked": false}]
            }
        })
        .to_string();
        let net = Fixtures::default().with("https://pypi.org/pypi/widget/json", doc.as_bytes());
        let cache = BlobCache::disabled();
        let p = pypi("widget", Some("0.3.0"), &net, &cache).expect("provenance");

        assert_eq!(p.ecosystem, "pypi");
        assert_eq!(p.version, "0.3.0");
        assert_eq!(p.published_at, Some(1_619_172_000)); // 2021-04-23
        assert_eq!(p.latest_version.as_deref(), Some("0.3.0"));
        // Cadence from the full `releases` timeline.
        assert_eq!(p.release_count, Some(3));
        assert_eq!(p.first_published_at, Some(1_609_459_200)); // 2021-01-01
        assert_eq!(p.previous_published_at, Some(1_619_085_600)); // 2021-04-22
        // Custody: the owning account, and the domain from the author email
        // (the `Name <user@domain>` form is parsed cleanly).
        assert_eq!(p.publisher.as_deref(), Some("hoo29"));
        assert_eq!(p.publisher_email_domain.as_deref(), Some("evil.example"));
        assert_eq!(p.vulnerability_count, Some(1));
        // PyPI exposes no per-version publisher account or unpacked size.
        assert_eq!(p.publisher_in_maintainers, None);
        assert_eq!(p.unpacked_size, None);
    }

    #[test]
    fn a_version_pypi_does_not_list_gets_none_of_latests_facts() {
        let doc = serde_json::json!({
            "info": {"version": "2.0.0"},
            "vulnerabilities": [],
            "urls": [{"upload_time_iso_8601": "2024-01-01T00:00:00Z", "yanked": true, "yanked_reason": "malware"}],
            "releases": {
                "1.0+local": [{"upload_time_iso_8601": "2021-01-01T00:00:00Z", "yanked": false}],
                "2.0.0": [{"upload_time_iso_8601": "2024-01-01T00:00:00Z", "yanked": true, "yanked_reason": "malware"}]
            }
        })
        .to_string();
        let old_release =
            serde_json::json!({"vulnerabilities": [{"id": "A"}, {"id": "B"}]}).to_string();
        let net = Fixtures::default()
            .with("https://pypi.org/pypi/w/json", doc.as_bytes())
            .with(
                "https://pypi.org/pypi/w/1.0%2Blocal/json",
                old_release.as_bytes(),
            );
        let cache = test_cache("pypi-miss");

        // Unlisted: latest's date, yank and vulnerabilities must not transfer.
        let gone = pypi("w", Some("9.9.9"), &net, &cache).expect("record");
        assert_eq!(gone.version, "9.9.9");
        assert_eq!(gone.published_at, None);
        assert_eq!(gone.deprecated, None);
        assert_eq!(gone.vulnerability_count, None);

        // A PURL's encoded `+` still finds the listed `1.0+local`, and an older
        // release's vulnerabilities come from its own endpoint, not latest's.
        let old = pypi("w", Some("1.0%2Blocal"), &net, &cache).expect("record");
        assert_eq!(old.version, "1.0+local");
        assert_eq!(old.published_at, Some(1_609_459_200)); // 2021-01-01
        assert_eq!(old.deprecated, None);
        assert_eq!(old.vulnerability_count, Some(2));
    }
}
