//! Artifact candidates for a release and the policy that picks one.

use crate::fetch::is_false;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::fetch::coordinate::percent_decode;
use crate::purl::Purl;

/// One concrete archive published for a package coordinate.
///
/// `qualifiers` contains the PURL selectors that identify this exact artifact
/// (for example PyPI's `file_name` or RubyGems' `platform`). `attributes`
/// contains ecosystem metadata that describes compatibility but is not itself
/// a registered PURL qualifier (`python`, `abi`, npm `cpu`, and similar).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactCandidate {
    /// Canonical release-level PURL shared by sibling artifacts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_purl: Option<String>,
    /// Canonical PURL including selectors for this exact published artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_purl: Option<String>,
    /// Direct URL for this archive.
    pub url: String,
    /// Archive basename as published by the registry.
    pub file_name: String,
    /// Exact PURL qualifier values that select this candidate.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub qualifiers: BTreeMap<String, String>,
    /// Ecosystem-specific file type and compatibility tags.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, String>,
    /// Registry-provided or PURL-declared content digests, keyed by the
    /// standard lowercase algorithm name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub checksums: BTreeMap<String, String>,
    /// Whether the legacy single-URL API would choose this candidate.
    #[serde(default, skip_serializing_if = "is_false")]
    pub preferred: bool,
}

/// All concrete archives a registry publishes for one PURL release.
///
/// This additive API preserves [`resolve`](crate::fetch::resolve)'s single-URL contract while letting
/// scanners enumerate platform, ABI, and file-format variants. Exactly one
/// candidate is normally marked [`ArtifactCandidate::preferred`]; no candidate
/// is preferred when an explicit selector names an artifact the registry did
/// not return.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactMatrix {
    /// The requested locator, retained for correlation with the caller's input.
    pub locator: String,
    /// Concrete artifact variants in deterministic preference order.
    pub candidates: Vec<ArtifactCandidate>,
}

impl ArtifactMatrix {
    /// The candidate selected by the backward-compatible single-URL policy.
    #[must_use]
    pub fn preferred(&self) -> Option<&ArtifactCandidate> {
        self.candidates.iter().find(|candidate| candidate.preferred)
    }

    /// Select one compatible artifact for an explicit target and policy.
    /// Enumeration itself remains target-neutral.
    #[must_use]
    pub fn select(
        &self,
        target: &ArtifactTarget,
        policy: &SelectionPolicy,
    ) -> Option<&ArtifactCandidate> {
        let exact = crate::purl::Purl::parse(&self.locator)
            .ok()
            .is_some_and(|purl| {
                purl.qualifiers().keys().any(|key| {
                    matches!(
                        key.as_str(),
                        "file_name" | "platform" | "download_url" | "kind"
                    )
                })
            });
        self.candidates
            .iter()
            .filter(|candidate| !exact || candidate.preferred)
            .filter_map(|candidate| {
                candidate_score(candidate, target, policy).map(|score| (score, candidate))
            })
            .min_by(|(left_score, left), (right_score, right)| {
                left_score
                    .cmp(right_score)
                    .then_with(|| left.file_name.cmp(&right.file_name))
            })
            .map(|(_, candidate)| candidate)
    }
}

/// Compatibility information supplied by a caller selecting an artifact.
///
/// Python and Ruby publish ecosystem-specific compatibility tags, so callers
/// pass the tags their runtime accepts rather than Fletch guessing from a host
/// triple. Empty tag lists mean “portable artifacts only.”
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactTarget {
    /// Operating system (`linux`, `darwin`, `win32`, ...).
    pub os: Option<String>,
    /// CPU architecture (`x64`, `arm64`, `x86_64`, ...).
    pub arch: Option<String>,
    /// C library where relevant (`glibc`, `musl`).
    pub libc: Option<String>,
    /// Accepted Python interpreter tags, best first (`cp313`, `py3`, ...).
    #[serde(default)]
    pub python_tags: Vec<String>,
    /// Accepted Python ABI tags (`cp313`, `abi3`, `none`, ...).
    #[serde(default)]
    pub abi_tags: Vec<String>,
    /// Accepted Python platform tags (`manylinux_2_17_x86_64`, ...).
    #[serde(default)]
    pub python_platform_tags: Vec<String>,
    /// Concrete Python runtime version used for `Requires-Python` checks.
    pub python_version: Option<String>,
    /// Concrete Node.js runtime version used for npm `engines.node` checks.
    pub node_version: Option<String>,
    /// Accepted RubyGems platform strings (`x86_64-linux`, ...).
    #[serde(default)]
    pub gem_platforms: Vec<String>,
}

/// Policy choices kept separate from registry enumeration and host identity.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectionPolicy {
    /// Permit a yanked/withdrawn artifact when no healthy candidate exists.
    pub allow_yanked: bool,
    /// Prefer source distributions over compatible binaries.
    pub prefer_source: bool,
}

fn candidate_score(
    candidate: &ArtifactCandidate,
    target: &ArtifactTarget,
    policy: &SelectionPolicy,
) -> Option<u16> {
    if candidate.attributes.contains_key("checksum_mismatch") {
        return None;
    }
    if !policy.allow_yanked && candidate.attributes.contains_key("yanked") {
        return None;
    }
    if let Some(constraint) = candidate.attributes.get("requires_python")
        && let Some(version) = target.python_version.as_deref()
    {
        let specifiers = constraint.parse::<pep440_rs::VersionSpecifiers>().ok()?;
        let version = version.parse::<pep440_rs::Version>().ok()?;
        if !specifiers.contains(&version) {
            return None;
        }
    }
    if let Some(constraint) = candidate.attributes.get("node")
        && let Some(version) = target.node_version.as_deref()
    {
        let range = node_semver::Range::parse(constraint).ok()?;
        let version = node_semver::Version::parse(version).ok()?;
        if !range.satisfies(&version) {
            return None;
        }
    }
    for (attribute, requested) in [
        ("os", target.os.as_deref()),
        ("cpu", target.arch.as_deref()),
        ("libc", target.libc.as_deref()),
    ] {
        if let Some(constraint) = candidate.attributes.get(attribute)
            && !runtime_constraint_matches(constraint, requested)
        {
            return None;
        }
    }

    let kind = candidate.attributes.get("kind").map(String::as_str);
    let natural = match kind {
        Some("wheel") => {
            let python = candidate.attributes.get("python").map(String::as_str)?;
            let abi = candidate.attributes.get("abi").map(String::as_str)?;
            let platform = candidate.attributes.get("platform").map(String::as_str)?;
            if !compressed_tag_matches(python, &target.python_tags, python.starts_with("py"))
                || !compressed_tag_matches(abi, &target.abi_tags, abi == "none")
                || !compressed_tag_matches(
                    platform,
                    &target.python_platform_tags,
                    platform == "any",
                )
            {
                return None;
            }
            if policy.prefer_source { 4 } else { 0 }
        }
        Some("sdist") => {
            if policy.prefer_source {
                0
            } else {
                1
            }
        }
        Some("gem") => {
            let platform = candidate
                .qualifiers
                .get("platform")
                .map_or("ruby", String::as_str);
            if platform != "ruby" && !target.gem_platforms.iter().any(|tag| tag == platform) {
                return None;
            }
            u16::from(platform != "ruby")
        }
        _ => 0,
    };
    Some(natural + 100 * u16::from(candidate.attributes.contains_key("yanked")))
}

fn compressed_tag_matches(actual: &str, accepted: &[String], targetless_compatible: bool) -> bool {
    if accepted.is_empty() {
        return targetless_compatible;
    }
    actual
        .split('.')
        .any(|tag| accepted.iter().any(|accepted| accepted == tag))
}

fn runtime_constraint_matches(constraint: &str, requested: Option<&str>) -> bool {
    let Some(requested) = requested else {
        return constraint
            .split(',')
            .map(str::trim)
            .all(|value| value.starts_with('!'));
    };
    if constraint.split(',').map(str::trim).any(|value| {
        value
            .strip_prefix('!')
            .is_some_and(|denied| runtime_value_matches(denied, requested))
    }) {
        return false;
    }
    let mut allowed = constraint
        .split(',')
        .map(str::trim)
        .filter(|value| !value.starts_with('!'));
    allowed.clone().next().is_none() || allowed.any(|value| runtime_value_matches(value, requested))
}

fn runtime_value_matches(candidate: &str, requested: &str) -> bool {
    candidate == requested
        || matches!(
            (candidate, requested),
            ("x86_64" | "amd64" | "x64", "x86_64" | "amd64" | "x64")
                | ("aarch64" | "arm64", "aarch64" | "arm64")
                | ("windows" | "win32", "windows" | "win32")
        )
}

pub(crate) fn artifact_candidate(url: String, kind: &str) -> ArtifactCandidate {
    let file_name = file_name_from_url(&url);
    let mut attributes = BTreeMap::new();
    attributes.insert("kind".to_string(), kind.to_string());
    ArtifactCandidate {
        release_purl: None,
        artifact_purl: None,
        url,
        file_name,
        qualifiers: BTreeMap::new(),
        attributes,
        checksums: BTreeMap::new(),
        preferred: true,
    }
}

pub(crate) fn file_name_from_url(url: &str) -> String {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    percent_decode(path.rsplit('/').next().unwrap_or_default())
}

pub(crate) fn file_name_matches(purl: &Purl, actual: &str) -> bool {
    purl.qualifier("file_name")
        .is_none_or(|wanted| wanted == actual)
}

pub(crate) fn maybe_selected_artifact_url(
    purl: &Purl,
    url: String,
    honor_file_name: bool,
) -> Option<String> {
    (!honor_file_name || file_name_matches(purl, &file_name_from_url(&url))).then_some(url)
}

pub(crate) fn purl_checksums(purl: &Purl) -> BTreeMap<String, String> {
    purl.qualifier("checksum")
        .map(|value| {
            value
                .split(',')
                .filter_map(|checksum| {
                    let (algorithm, digest) = checksum.split_once(':')?;
                    (!algorithm.is_empty() && !digest.is_empty()).then(|| {
                        (
                            algorithm.to_ascii_lowercase().replace('_', "-"),
                            digest.to_ascii_lowercase(),
                        )
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn apply_common_candidate_qualifiers(purl: &Purl, candidates: &mut [ArtifactCandidate]) {
    let declared = purl_checksums(purl);
    for candidate in candidates {
        for key in ["repository_url", "vcs_url", "download_url"] {
            if let Some(value) = purl.qualifier(key) {
                candidate.qualifiers.insert(key.into(), value.into());
            }
        }
        if let Some(file_name) = purl.qualifier("file_name")
            && candidate.file_name == file_name
        {
            candidate
                .qualifiers
                .entry("file_name".into())
                .or_insert_with(|| file_name.into());
        }
        for (algorithm, digest) in &declared {
            if candidate
                .checksums
                .get(algorithm)
                .is_some_and(|published| !published.eq_ignore_ascii_case(digest))
            {
                candidate.preferred = false;
                candidate
                    .attributes
                    .insert("checksum_mismatch".into(), "true".into());
            }
            candidate
                .checksums
                .entry(algorithm.clone())
                .or_insert_with(|| digest.clone());
        }
    }
}

pub(crate) fn attach_candidate_identities(release: &str, candidates: &mut [ArtifactCandidate]) {
    for candidate in candidates {
        let version = candidate.attributes.get("version").map(String::as_str);
        let release_purl = crate::purl::release_identity_at(release, version);
        candidate.release_purl.clone_from(&release_purl);
        let mut selectors = candidate.qualifiers.clone();
        if !candidate.checksums.is_empty() {
            selectors.insert(
                "checksum".into(),
                candidate
                    .checksums
                    .iter()
                    .map(|(algorithm, digest)| format!("{algorithm}:{digest}"))
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        candidate.artifact_purl = release_purl
            .as_deref()
            .and_then(|release| crate::purl::artifact_identity(release, &selectors));
    }
}
