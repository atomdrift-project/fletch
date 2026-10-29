//! PyPI: registry metadata and artifact resolution, both read from the JSON
//! API's project and release documents.

use filefacts::{Ecosystem, Registry};
use serde::Deserialize;
use serde::de::IgnoredAny;
use std::collections::{BTreeMap, HashMap};

use crate::ecosystem::{
    Coordinates, email_domain, fetch_json, for_version, lenient, non_empty, null_default, optional,
    set_timeline, unix_secs,
};
use crate::fetch::{
    ArtifactCandidate, ArtifactKind, BlobCache, Fetch, artifact_candidate, file_name_from_url,
    repository_base,
};
use crate::registry::RegistryError;

/// The files PyPI publishes for `purl`'s release (the latest when
/// unversioned), each a candidate carrying its kind, wheel tags, Python
/// constraints, yank status, and registry digests. A `file_name` qualifier
/// selects one exactly; otherwise [`pypi_rank`] orders them and the first is
/// preferred. Empty when the document is unreadable.
pub(crate) fn pypi_artifacts(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Vec<ArtifactCandidate> {
    let (name, version, purl) = (c.path(), c.encoded_version(), c.purl());
    let Some(repository) = repository_base(purl, "https://pypi.org") else {
        tracing::debug!(
            purl = %purl.to_string().escape_debug(),
            "pypi artifacts unresolved: repository_url is not a web URL"
        );
        return Vec::new();
    };
    let api = version.map_or_else(
        || format!("{repository}/pypi/{name}/json"),
        |value| format!("{repository}/pypi/{name}/{value}/json"),
    );
    // A release's files are fixed once uploaded, but their `yanked` flags are
    // not, so a pinned release revalidates on the pinned window.
    let doc: Project = match fetch_json(&api, net, &for_version(cache, version)) {
        Ok(doc) => doc,
        Err(error) => {
            tracing::debug!(url = %api, %error, "pypi artifacts unresolved: document unreadable");
            return Vec::new();
        }
    };
    let Some(resolved) = purl
        .version()
        .or_else(|| doc.info.as_ref()?.version.as_deref())
    else {
        tracing::debug!(url = %api, "pypi artifacts unresolved: no version named");
        return Vec::new();
    };
    let mut candidates: Vec<_> = doc
        .urls
        .iter()
        .filter_map(|file| pypi_candidate(file, purl.name(), resolved))
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

/// One uploaded file as an artifact candidate; `None` for a file record with
/// no URL.
fn pypi_candidate(file: &DistFile, name: &str, version: &str) -> Option<ArtifactCandidate> {
    let url = file.url.clone()?;
    let file_name = file
        .filename
        .clone()
        .unwrap_or_else(|| file_name_from_url(&url));
    let kind = match file.packagetype.as_deref() {
        Some("bdist_wheel") => ArtifactKind::Wheel,
        Some("sdist") => ArtifactKind::Sdist,
        _ => ArtifactKind::Other,
    };
    let mut qualifiers = BTreeMap::new();
    qualifiers.insert("file_name".into(), file_name.clone());
    let mut attributes = BTreeMap::new();
    if kind == ArtifactKind::Wheel {
        attributes.extend(wheel_attributes(&file_name, name, version));
    }
    for (key, value) in [
        ("python_version", &file.python_version),
        ("requires_python", &file.requires_python),
        ("yanked_reason", &file.yanked_reason),
    ] {
        if let Some(value) = value {
            attributes.insert(key.to_string(), value.clone());
        }
    }
    let checksums = file
        .digests
        .iter()
        .flatten()
        .map(|(algorithm, digest)| {
            (
                algorithm.to_ascii_lowercase().replace('_', "-"),
                digest.clone(),
            )
        })
        .collect();
    Some(ArtifactCandidate {
        file_name,
        version: Some(version.to_string()),
        yanked: file.yanked == Some(true),
        qualifiers,
        attributes,
        checksums,
        preferred: false,
        ..artifact_candidate(url, kind)
    })
}

/// A wheel's compatibility tags (`python`, `abi`, `platform`, and `build`
/// when present) from its file name; empty for a name that is not a wheel's.
fn wheel_attributes(file_name: &str, name: &str, version: &str) -> BTreeMap<String, String> {
    let mut attributes = BTreeMap::new();
    let Some(stem) = file_name.strip_suffix(".whl") else {
        return attributes;
    };

    // Wheel filenames are `{distribution}-{version}(-{build})?-{python}-{abi}-{platform}`.
    // Distribution punctuation is normalized to underscores, so remove the
    // known coordinate prefix before deciding whether the optional build tag
    // exists: counting every `-` in the full filename would read a hyphen
    // kept in a distribution's name as a build tag.
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
    // `[build-]python-abi-platform`.
    let parts: Vec<&str> = suffix.split('-').collect();
    let [.., python, abi, platform] = parts.as_slice() else {
        return attributes;
    };
    attributes.insert("python".into(), (*python).to_string());
    attributes.insert("abi".into(), (*abi).to_string());
    attributes.insert("platform".into(), (*platform).to_string());
    if let [build, _, _, _] = parts.as_slice() {
        attributes.insert("build".into(), (*build).to_string());
    }
    attributes
}

/// A candidate's preference, lowest first: the exact `file_name` asked for;
/// else a pure-Python wheel, another universal wheel, the sdist, a platform
/// wheel, then anything else — a requested `kind` ahead of the rest, and a
/// yanked file behind every live one.
fn pypi_rank(
    candidate: &ArtifactCandidate,
    exact: Option<&str>,
    requested_kind: Option<&str>,
) -> u8 {
    if let Some(file_name) = exact {
        return u8::from(candidate.file_name != file_name);
    }
    let kind = candidate.kind;
    let natural = if kind == ArtifactKind::Wheel {
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
    } else if kind == ArtifactKind::Sdist {
        2
    } else {
        4
    };
    let requested = if requested_kind.is_some_and(|requested| kind.as_str() != requested) {
        10 + natural
    } else {
        natural
    };
    requested + if candidate.yanked { 20 } else { 0 }
}

/// Look up the package `c` names on PyPI. The project document carries the
/// `info` block (the latest release's metadata), the full `releases`
/// timeline (every version's files and upload times), `ownership`, and the
/// latest release's known `vulnerabilities`. The requested version's publish
/// time and yank status come from its own `releases` entry, and its
/// vulnerabilities from the per-version document when it is not the latest.
pub(crate) fn lookup(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let name = c.encoded_name();
    let doc: Project = fetch_json(&format!("https://pypi.org/pypi/{name}/json"), net, cache)?;
    let Some(info) = &doc.info else {
        return Err(RegistryError::NoRecord);
    };
    let latest = info.version.as_deref();
    let target = c.target(latest);
    let target_is_latest = Some(target) == latest;
    let vulnerability_count =
        |v: &Option<Vec<IgnoredAny>>| v.as_ref().and_then(|v| u32::try_from(v.len()).ok());

    // `urls` lists the latest release's files, so it stands in for the
    // target's `releases` entry only when the target is the latest. A
    // requested version the timeline lacks gets no date or yank status
    // rather than the latest's.
    let target_files = doc
        .releases
        .get(target)
        .or_else(|| target_is_latest.then_some(&doc.urls))
        .filter(|files| !files.is_empty());
    // PyPI yanks a release by yanking its files; a release whose every file
    // is yanked is removed.
    let version_removed = target_files.map(|files| files.iter().all(|f| f.yanked == Some(true)));
    if version_removed == Some(true) {
        tracing::debug!(
            package = %c.name().escape_debug(),
            version = %target.escape_debug(),
            reason = ?target_files.into_iter().flatten().find_map(|f| f.yanked_reason.as_deref()),
            "pypi release is yanked"
        );
    }

    let mut p = Registry::new(Ecosystem::Pypi, c.name().to_string());
    p.version = target.to_string();
    p.published_at = target_files.and_then(|files| publish_time(files));
    p.latest_version = latest.map(str::to_string);
    p.author = info.author.clone().or_else(|| info.maintainer.clone());
    p.description = info.summary.clone();
    p.homepage = info.home_page.clone();
    p.license = info.license.clone();
    p.version_removed = version_removed;
    // The project document's `vulnerabilities` are the latest release's;
    // any other listed version's come from its own document.
    p.vulnerability_count = match (target_is_latest, c.encoded_version(), target_files) {
        (true, _, _) => vulnerability_count(&doc.vulnerabilities),
        (false, Some(v), Some(_)) => {
            let url = format!("https://pypi.org/pypi/{name}/{v}/json");
            optional(fetch_json::<Project>(&url, net, cache), &url)
                .and_then(|release| vulnerability_count(&release.vulnerabilities))
        }
        _ => None,
    };
    // Custody: the owning account (PyPI exposes roles, not a per-version
    // publisher), and the email domain from the author or maintainer.
    p.publisher = doc.ownership.as_ref().and_then(|o| {
        o.roles
            .iter()
            .find(|r| r.role.as_deref() == Some("Owner"))
            .or_else(|| o.roles.first())?
            .user
            .clone()
    });
    p.publisher_email_domain = info
        .author_email
        .as_deref()
        .or(info.maintainer_email.as_deref())
        .and_then(email_domain);
    set_timeline(
        &mut p,
        doc.releases
            .values()
            .filter_map(|files| publish_time(files)),
    );
    Ok(p)
}

/// A release's publish time: the earliest upload among its files.
fn publish_time(files: &[DistFile]) -> Option<u64> {
    files
        .iter()
        .filter_map(|f| f.upload_time_iso_8601.as_deref())
        .filter_map(unix_secs)
        .min()
}

/// The parts of a PyPI project document (`/pypi/{name}/json`) or release
/// document (`/pypi/{name}/{version}/json`) the record and the artifact
/// resolver read. A release document has no `releases` or `ownership`.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Project {
    info: Option<ProjectInfo>,
    #[serde(deserialize_with = "null_default")]
    releases: HashMap<String, Vec<DistFile>>,
    #[serde(deserialize_with = "null_default")]
    urls: Vec<DistFile>,
    vulnerabilities: Option<Vec<IgnoredAny>>,
    ownership: Option<Ownership>,
}

/// The `info` block: the described release's metadata.
#[derive(Default, Deserialize)]
#[serde(default)]
struct ProjectInfo {
    #[serde(deserialize_with = "non_empty")]
    version: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    author: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    maintainer: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    summary: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    home_page: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    license: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    author_email: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    maintainer_email: Option<String>,
}

/// One uploaded file of a release, as `releases` and `urls` list it.
#[derive(Default, Deserialize)]
#[serde(default)]
struct DistFile {
    #[serde(deserialize_with = "non_empty")]
    url: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    filename: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    packagetype: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    python_version: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    requires_python: Option<String>,
    #[serde(deserialize_with = "lenient")]
    digests: Option<BTreeMap<String, String>>,
    upload_time_iso_8601: Option<String>,
    yanked: Option<bool>,
    #[serde(deserialize_with = "non_empty")]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::coordinates;

    use crate::fetch::Fixtures;
    use filefacts::RefLocator;

    fn look(purl: &str, net: &Fixtures) -> Result<Registry, RegistryError> {
        crate::registry::lookup(&RefLocator::Purl(purl.into()), net, &BlobCache::disabled())
    }

    #[test]
    fn pypi_releases_yield_cadence_and_custody() {
        let doc = serde_json::json!({
            "info": {
                "version": "0.3.0",
                "summary": "a tool",
                "author": "",
                "maintainer": "Mae",
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
        let p = look("pkg:pypi/widget@0.3.0", &net).expect("provenance");

        assert_eq!(p.ecosystem, Ecosystem::Pypi);
        assert_eq!(p.version, "0.3.0");
        assert_eq!(p.published_at, Some(1_619_172_000)); // 2021-04-23
        assert_eq!(p.latest_version.as_deref(), Some("0.3.0"));
        // A blank author falls back to the maintainer.
        assert_eq!(p.author.as_deref(), Some("Mae"));
        // Cadence from the full `releases` timeline.
        assert_eq!(p.release_count, Some(3));
        assert_eq!(p.first_published_at, Some(1_609_459_200)); // 2021-01-01
        assert_eq!(p.previous_published_at, Some(1_619_085_600)); // 2021-04-22
        // Custody: the owning account, and the domain from the author email
        // (the `Name <user@domain>` form is parsed cleanly).
        assert_eq!(p.publisher.as_deref(), Some("hoo29"));
        assert_eq!(p.publisher_email_domain.as_deref(), Some("evil.example"));
        assert_eq!(p.vulnerability_count, Some(1));
        assert_eq!(p.version_removed, Some(false));
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

        // Unlisted: latest's date, yank and vulnerabilities must not transfer.
        let gone = look("pkg:pypi/w@9.9.9", &net).expect("record");
        assert_eq!(gone.version, "9.9.9");
        assert_eq!(gone.published_at, None);
        assert_eq!(gone.version_removed, None);
        assert_eq!(gone.deprecated, None);
        assert_eq!(gone.vulnerability_count, None);

        // A PURL's encoded `+` still finds the listed `1.0+local`, and an older
        // release's vulnerabilities come from its own endpoint, not latest's.
        let old = look("pkg:pypi/w@1.0%2Blocal", &net).expect("record");
        assert_eq!(old.version, "1.0+local");
        assert_eq!(old.published_at, Some(1_609_459_200)); // 2021-01-01
        assert_eq!(old.version_removed, Some(false));
        assert_eq!(old.deprecated, None);
        assert_eq!(old.vulnerability_count, Some(2));
    }

    #[test]
    fn a_yanked_release_is_removed_not_deprecated() {
        let doc = serde_json::json!({
            "info": {"version": "2.0.0"},
            "releases": {
                "1.0.0": [
                    {"upload_time_iso_8601": "2021-01-01T00:00:00Z", "yanked": true, "yanked_reason": "broken"},
                    {"upload_time_iso_8601": "2021-01-01T00:00:00Z", "yanked": false}
                ],
                "2.0.0": [
                    {"upload_time_iso_8601": "2024-01-01T00:00:00Z", "yanked": true, "yanked_reason": "malware"},
                    {"upload_time_iso_8601": "2024-01-01T00:00:00Z", "yanked": true}
                ]
            }
        })
        .to_string();
        let net = Fixtures::default()
            .with("https://pypi.org/pypi/w/json", doc.as_bytes())
            .refusing("https://pypi.org/pypi/w/1.0.0/json", 404);
        let yanked = look("pkg:pypi/w", &net).expect("record");
        assert_eq!(yanked.version, "2.0.0");
        assert_eq!(yanked.version_removed, Some(true));
        assert_eq!(yanked.deprecated, None, "a yank is not a deprecation");
        // One live file keeps the release installable.
        let partly = look("pkg:pypi/w@1.0.0", &net).expect("record");
        assert_eq!(partly.version_removed, Some(false));
        assert_eq!(partly.deprecated, None);
    }

    #[test]
    fn the_artifact_resolver_reads_the_release_document() {
        let doc = serde_json::json!({
            "info": {"version": "1.0.0"},
            "urls": [
                {"url": "https://files.example/w-1.0.0.tar.gz", "filename": "w-1.0.0.tar.gz",
                 "packagetype": "sdist", "digests": {"sha256": "aa", "blake2b_256": "bb"},
                 "requires_python": null},
                {"url": "https://files.example/w-1.0.0-py3-none-any.whl",
                 "filename": "w-1.0.0-py3-none-any.whl", "packagetype": "bdist_wheel",
                 "python_version": "py3", "requires_python": ">=3.8", "yanked": false},
                {"filename": "no-url.whl"}
            ]
        })
        .to_string();
        let net = Fixtures::default().with("https://pypi.org/pypi/w/1.0.0/json", doc.as_bytes());
        let files = pypi_artifacts(
            &coordinates("pkg:pypi/w@1.0.0"),
            &net,
            &BlobCache::disabled(),
        );
        assert_eq!(files.len(), 2, "a file record with no URL is no candidate");
        assert!(files[0].preferred);
        assert_eq!(files[0].file_name, "w-1.0.0-py3-none-any.whl");
        assert_eq!(
            files[0].attributes.get("platform").map(String::as_str),
            Some("any")
        );
        assert_eq!(
            files[0]
                .attributes
                .get("requires_python")
                .map(String::as_str),
            Some(">=3.8")
        );
        assert_eq!(
            files[1].checksums.get("blake2b-256").map(String::as_str),
            Some("bb")
        );
        assert_eq!(files[1].attributes.get("requires_python"), None);
    }
}
