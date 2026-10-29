//! Artifact candidates for a release, and the common PURL selectors applied
//! to them.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::fetch::coordinate::percent_decode;
use crate::purl::Purl;

/// The file format of one published artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ArtifactKind {
    /// An archive named directly: a `download_url` qualifier or a URL locator.
    Download,
    /// An npm package tarball.
    Tgz,
    /// A Python wheel.
    Wheel,
    /// A Python source distribution.
    Sdist,
    /// A RubyGems package.
    Gem,
    /// A Go module zip.
    Zip,
    /// A Cargo crate.
    Crate,
    /// A Terraform provider zip.
    Provider,
    /// Another registry-published format (a Python egg or Windows installer).
    Other,
}

impl ArtifactKind {
    /// The kind's name, as it is serialized and as a `kind` qualifier spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Download => "download",
            Self::Tgz => "tgz",
            Self::Wheel => "wheel",
            Self::Sdist => "sdist",
            Self::Gem => "gem",
            Self::Zip => "zip",
            Self::Crate => "crate",
            Self::Provider => "provider",
            Self::Other => "other",
        }
    }
}

/// One concrete archive published for a package coordinate.
///
/// `qualifiers` holds the PURL selectors that identify this exact artifact
/// (PyPI's `file_name`, RubyGems' `platform`). `attributes` holds free-form
/// ecosystem tags that describe compatibility but are not registered PURL
/// qualifiers (`python`, `abi`, npm `cpu`, and similar); nothing in fletch
/// decides on them.
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
    /// The archive's format.
    pub kind: ArtifactKind,
    /// The release this archive belongs to, when the registry named it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The path inside the archive the PURL addresses (a Go package within
    /// its module zip), which is context and never another artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subpath: Option<String>,
    /// Whether the registry withdrew this archive (a PyPI yank).
    #[serde(default, skip_serializing_if = "is_false")]
    pub yanked: bool,
    /// Whether a checksum the PURL declares disagrees with the one the
    /// registry publishes, which makes this candidate unfit to prefer.
    #[serde(default, skip_serializing_if = "is_false")]
    pub checksum_mismatch: bool,
    /// Exact PURL qualifier values that select this candidate.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub qualifiers: BTreeMap<String, String>,
    /// Free-form ecosystem compatibility tags.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, String>,
    /// Registry-provided or PURL-declared content digests, keyed by the
    /// standard lowercase algorithm name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub checksums: BTreeMap<String, String>,
    /// Whether this is the artifact a fetch of the PURL retrieves.
    #[serde(default, skip_serializing_if = "is_false")]
    pub preferred: bool,
}

/// All concrete archives a registry publishes for one PURL release.
///
/// At most one candidate is [`ArtifactCandidate::preferred`]: the one a fetch
/// of the PURL retrieves. None is when an explicit selector names an artifact
/// the registry did not return, or no candidate is fit to fetch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactMatrix {
    /// The requested locator, canonicalized: a PURL in its canonical form, or
    /// the URL as written.
    pub locator: String,
    /// Concrete artifact variants in deterministic preference order.
    pub candidates: Vec<ArtifactCandidate>,
}

impl ArtifactMatrix {
    /// The candidate a fetch of the locator retrieves.
    #[must_use]
    pub fn preferred(&self) -> Option<&ArtifactCandidate> {
        self.candidates.iter().find(|candidate| candidate.preferred)
    }
}

/// `skip_serializing_if` helper for a default-`false` flag.
fn is_false(b: &bool) -> bool {
    !*b
}

/// A preferred candidate for `url`, its file name taken from the URL.
pub(crate) fn artifact_candidate(url: String, kind: ArtifactKind) -> ArtifactCandidate {
    let file_name = file_name_from_url(&url);
    ArtifactCandidate {
        release_purl: None,
        artifact_purl: None,
        url,
        file_name,
        kind,
        version: None,
        subpath: None,
        yanked: false,
        checksum_mismatch: false,
        qualifiers: BTreeMap::new(),
        attributes: BTreeMap::new(),
        checksums: BTreeMap::new(),
        preferred: true,
    }
}

/// The decoded last path segment of `url`, ignoring its query and fragment.
pub(crate) fn file_name_from_url(url: &str) -> String {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    percent_decode(path.rsplit('/').next().unwrap_or_default())
}

/// Whether `actual` satisfies the PURL's `file_name` selector, which names one
/// exact artifact; a PURL without one accepts any.
pub(crate) fn file_name_matches(purl: &Purl, actual: &str) -> bool {
    purl.qualifier("file_name")
        .is_none_or(|wanted| wanted == actual)
}

/// The PURL's `checksum` qualifier as `algorithm → lowercase hex digest`.
/// Algorithm names are lowercased with `_` spelled `-`; malformed entries are
/// skipped.
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

/// Apply the PURL's common qualifiers to each candidate: carry its repository
/// and download qualifiers, record a matching `file_name` selector, and merge
/// its declared checksums. A declared checksum that disagrees with a
/// published one marks the candidate [`checksum_mismatch`] and never
/// preferred.
///
/// [`checksum_mismatch`]: ArtifactCandidate::checksum_mismatch
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
                tracing::debug!(
                    url = %candidate.url,
                    algorithm = %algorithm,
                    "declared checksum disagrees with the registry's; candidate not preferred"
                );
                candidate.preferred = false;
                candidate.checksum_mismatch = true;
            }
            candidate
                .checksums
                .entry(algorithm.clone())
                .or_insert_with(|| digest.clone());
        }
    }
}

/// Give each candidate its release PURL (`release` at the candidate's own
/// version) and its artifact PURL (the release plus the selectors and
/// checksums that pick this exact archive).
pub(crate) fn attach_candidate_identities(release: &Purl, candidates: &mut [ArtifactCandidate]) {
    for candidate in candidates {
        let release_purl = match candidate.version.as_deref() {
            None => Some(release.identity()),
            Some(version) => release
                .release(version)
                .inspect_err(|error| tracing::debug!(%error, version, "no release identity"))
                .ok(),
        };
        candidate.release_purl = release_purl.as_ref().map(Purl::to_string);
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
        candidate.artifact_purl = release_purl.and_then(|release| {
            release
                .artifact(&selectors)
                .inspect_err(|error| tracing::debug!(%error, "no artifact identity"))
                .ok()
                .map(|artifact| artifact.to_string())
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn purl(raw: &str) -> Purl {
        Purl::parse(raw).unwrap()
    }

    #[test]
    fn a_declared_checksum_conflict_is_typed_and_never_preferred() {
        let mut candidates = [artifact_candidate(
            "https://x/demo-1.0.tar.gz".into(),
            ArtifactKind::Sdist,
        )];
        candidates[0]
            .checksums
            .insert("sha256".into(), "aaaa".into());
        apply_common_candidate_qualifiers(
            &purl("pkg:pypi/demo@1.0?checksum=sha256:bbbb"),
            &mut candidates,
        );
        assert!(candidates[0].checksum_mismatch);
        assert!(!candidates[0].preferred);
        assert!(candidates[0].attributes.is_empty());

        let mut agreeing = [artifact_candidate(
            "https://x/demo-1.0.tar.gz".into(),
            ArtifactKind::Sdist,
        )];
        agreeing[0].checksums.insert("sha256".into(), "AAAA".into());
        apply_common_candidate_qualifiers(
            &purl("pkg:pypi/demo@1.0?checksum=sha256:aaaa"),
            &mut agreeing,
        );
        assert!(!agreeing[0].checksum_mismatch);
        assert!(agreeing[0].preferred);
    }

    #[test]
    fn typed_flags_serialize_only_when_set() {
        let candidate = artifact_candidate("https://x/pkg-1.0.0.tgz".into(), ArtifactKind::Tgz);
        let json = serde_json::to_value(&candidate).unwrap();
        assert_eq!(json["kind"], "tgz");
        assert!(json.get("yanked").is_none());
        assert!(json.get("checksum_mismatch").is_none());
        assert!(json.get("version").is_none());
        let back: ArtifactCandidate = serde_json::from_value(json).unwrap();
        assert_eq!(back, candidate);
        for kind in [
            ArtifactKind::Download,
            ArtifactKind::Wheel,
            ArtifactKind::Other,
        ] {
            assert_eq!(
                serde_json::to_value(kind).unwrap(),
                serde_json::json!(kind.as_str())
            );
        }
    }

    #[test]
    fn identities_use_the_candidates_own_version() {
        let mut candidates = [artifact_candidate(
            "https://x/pkg-2.0.0.tgz".into(),
            ArtifactKind::Tgz,
        )];
        candidates[0].version = Some("2.0.0".into());
        attach_candidate_identities(&purl("pkg:npm/pkg"), &mut candidates);
        assert_eq!(
            candidates[0].release_purl.as_deref(),
            Some("pkg:npm/pkg@2.0.0")
        );
    }

    #[test]
    fn file_names_come_from_the_decoded_last_segment() {
        assert_eq!(
            file_name_from_url("https://x/a/b%2Bc.whl?sig=1#frag"),
            "b+c.whl"
        );
        assert!(file_name_matches(&purl("pkg:npm/a@1"), "anything"));
        assert!(!file_name_matches(
            &purl("pkg:npm/a@1?file_name=x.tgz"),
            "y.tgz"
        ));
    }
}
