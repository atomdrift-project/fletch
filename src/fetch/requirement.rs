//! Declared version requirements: resolved against the registry to the
//! release a package manager would install, or against a lockfile's pins.
//! Neither ever substitutes a guessed latest release.

use filefacts::{RefLocator, Reference};

use super::BlobCache;
use super::cache::cached_metadata_status;
use super::coordinate::{repository_base, safe_coordinate};
use super::record::Unresolved;
use super::resolve::{ResolveError, on_crates_io, parse, rules};
use super::transport::{Fetch, FetchError};
use crate::ecosystem::npm::npm_registry_name;
use crate::purl::Purl;

/// The grammar an ecosystem writes `version_requirement` in, and the registry
/// document that lists its releases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Grammar {
    /// npm semver ranges; text that is not one is a dist-tag (`latest`, `next`).
    Npm,
    /// Cargo semver requirements, against crates.io.
    Cargo,
    /// PEP 440 version specifiers.
    Pep440,
}

/// A parsed version requirement.
enum Range {
    Npm(node_semver::Range),
    Cargo(semver::VersionReq),
    /// PEP 440 admits a pre-release only when a specifier names one.
    Pep440 {
        specifiers: pep440_rs::VersionSpecifiers,
        prereleases: bool,
    },
}

/// One release a registry document lists.
struct Release {
    version: String,
    yanked: bool,
    /// The release's sha256, when the registry publishes one.
    checksum: Option<String>,
}

impl Grammar {
    fn parse(self, requirement: &str) -> Option<Range> {
        match self {
            Self::Npm => node_semver::Range::parse(requirement).ok().map(Range::Npm),
            Self::Cargo => requirement.parse().ok().map(Range::Cargo),
            Self::Pep440 => requirement
                .parse::<pep440_rs::VersionSpecifiers>()
                .ok()
                .map(|specifiers| Range::Pep440 {
                    prereleases: specifiers.iter().any(|s| s.version().any_prerelease()),
                    specifiers,
                }),
        }
    }

    /// The registry document listing `name`'s releases.
    fn document(self, purl: &Purl, name: &str) -> Option<String> {
        match self {
            Self::Npm => repository_base(purl, "https://registry.npmjs.org")
                .map(|repository| format!("{repository}/{}", npm_registry_name(name))),
            Self::Cargo => {
                on_crates_io(purl).then(|| format!("https://crates.io/api/v1/crates/{name}"))
            }
            Self::Pep440 => repository_base(purl, "https://pypi.org")
                .map(|repository| format!("{repository}/pypi/{name}/json")),
        }
    }

    /// The releases `doc` lists. A PyPI release is yanked when every one of
    /// its files is.
    fn releases(self, doc: &serde_json::Value) -> Vec<Release> {
        let unchecked = |version: &String| Release {
            version: version.clone(),
            yanked: false,
            checksum: None,
        };
        let yanked = |file: &serde_json::Value| {
            file.get("yanked").and_then(serde_json::Value::as_bool) == Some(true)
        };
        match self {
            Self::Npm => doc
                .get("versions")
                .and_then(serde_json::Value::as_object)
                .map(|versions| versions.keys().map(unchecked).collect())
                .unwrap_or_default(),
            Self::Cargo => doc
                .get("versions")
                .and_then(serde_json::Value::as_array)
                .map(|rows| {
                    rows.iter()
                        .filter_map(|row| {
                            Some(Release {
                                version: row.get("num")?.as_str()?.to_owned(),
                                yanked: yanked(row),
                                checksum: row
                                    .get("checksum")
                                    .and_then(serde_json::Value::as_str)
                                    .map(str::to_owned),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default(),
            Self::Pep440 => doc
                .get("releases")
                .and_then(serde_json::Value::as_object)
                .map(|releases| {
                    releases
                        .iter()
                        .map(|(version, files)| Release {
                            yanked: !files
                                .as_array()
                                .is_some_and(|files| files.iter().any(|f| !yanked(f))),
                            ..unchecked(version)
                        })
                        .collect()
                })
                .unwrap_or_default(),
        }
    }
}

impl Range {
    /// Whether `version` satisfies the requirement.
    fn matches(&self, version: &str) -> bool {
        match self {
            Self::Npm(range) => {
                node_semver::Version::parse(version).is_ok_and(|v| range.satisfies(&v))
            }
            Self::Cargo(req) => version
                .parse::<semver::Version>()
                .is_ok_and(|v| req.matches(&v)),
            Self::Pep440 {
                specifiers,
                prereleases,
            } => version
                .parse::<pep440_rs::Version>()
                .is_ok_and(|v| specifiers.contains(&v) && (*prereleases || !v.any_prerelease())),
        }
    }

    /// The highest release that satisfies the requirement and is not yanked.
    fn best<'a>(&self, releases: &'a [Release]) -> Option<&'a Release> {
        let admitted = releases
            .iter()
            .filter(|r| !r.yanked && self.matches(&r.version));
        match self {
            Self::Npm(_) => admitted.max_by_key(|r| node_semver::Version::parse(&r.version).ok()),
            Self::Cargo(_) => admitted.max_by_key(|r| r.version.parse::<semver::Version>().ok()),
            Self::Pep440 { .. } => {
                admitted.max_by_key(|r| r.version.parse::<pep440_rs::Version>().ok())
            }
        }
    }
}

/// Resolve a declared `version_requirement` to the exact release the
/// registry names for it: the declaration at that version without the
/// requirement, keeping its other qualifiers and subpath, plus the registry's
/// checksum when it offers one the declaration didn't. `Ok(None)` when no
/// requirement is declared.
pub(super) fn resolve_requirement(
    purl: &Purl,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Option<Purl>, ResolveError> {
    let Some(requirement) = purl.qualifier("version_requirement") else {
        return Ok(None);
    };
    let refused = |why: Unresolved, reason: &'static str| {
        tracing::debug!(
            locator = %purl,
            r#type = purl.typ(),
            branch = "requirement",
            requirement,
            reason,
            unresolved = ?why,
            "version requirement unresolved"
        );
        ResolveError::from(why)
    };
    if purl.version().is_some() {
        return Err(refused(
            Unresolved::Unsupported,
            "declares both a version and a requirement",
        ));
    }
    if purl.qualifier("registry").is_some() {
        return Err(refused(Unresolved::Unsupported, "names a private registry"));
    }
    let Some(grammar) = rules(purl.typ()).requirement else {
        return Err(refused(
            Unresolved::Unsupported,
            "no requirement grammar for this type",
        ));
    };
    let name = purl.encoded_path();
    if !safe_coordinate(&name) {
        return Err(refused(Unresolved::UnsafeCoordinate, "unsafe package name"));
    }
    let range = grammar.parse(requirement);
    if range.is_none() && grammar != Grammar::Npm {
        return Err(refused(
            Unresolved::Unsupported,
            "requirement does not parse",
        ));
    }
    let Some(url) = grammar.document(purl, &name) else {
        return Err(refused(
            Unresolved::Unsupported,
            "no public registry document",
        ));
    };
    let ttl = cache.with_meta_ttl(cache.meta_ttl_unpinned());
    let doc = match cached_metadata_status(&url, &[], net, &ttl) {
        Ok(bytes) => serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|e| {
            tracing::debug!(url, error = %e, "registry document does not parse");
            refused(Unresolved::NoRelease, "registry document does not parse")
        })?,
        Err(FetchError::Status(404 | 410)) => {
            return Err(refused(
                Unresolved::NoRelease,
                "registry has no such package",
            ));
        }
        Err(e) => {
            tracing::debug!(url, error = %e, "registry unreachable resolving a requirement");
            return Err(ResolveError::Failed(e));
        }
    };
    let (version, checksum) = match range {
        Some(range) => {
            let releases = grammar.releases(&doc);
            let release = range
                .best(&releases)
                .ok_or_else(|| refused(Unresolved::NoRelease, "no release satisfies it"))?;
            (release.version.clone(), release.checksum.clone())
        }
        // An npm requirement that is not a range is a dist-tag.
        None => (
            doc.get("dist-tags")
                .and_then(|tags| tags.get(requirement))
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| refused(Unresolved::NoRelease, "no such dist-tag"))?
                .to_owned(),
            None,
        ),
    };
    let mut exact = purl
        .with_qualifier("version_requirement", None)
        .and_then(|declared| declared.with_version(&version))
        .ok_or_else(|| refused(Unresolved::NoRelease, "registry named an unusable version"))?;
    if let Some(checksum) =
        checksum.filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        && exact.qualifier("checksum").is_none()
        && let Some(pinned) = exact.with_qualifier("checksum", Some(&format!("sha256:{checksum}")))
    {
        exact = pinned;
    }
    tracing::debug!(locator = %purl, resolved = %exact, "version requirement resolved");
    Ok(Some(exact))
}

/// Refine a manifest requirement to the exact release the registry names for
/// it, before registry-age or reputation gating. The declaration's source,
/// role and evidence stay attached to the exact target. A reference without
/// a requirement comes back as it is.
///
/// # Errors
///
/// Why no release could be named: [`ResolveError::Unresolved`] when there is
/// none to name, [`ResolveError::Failed`] when the registry could not be read.
pub fn resolve_declared_reference(
    reference: &Reference,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Reference, ResolveError> {
    let RefLocator::Purl(raw) = &reference.locator else {
        return Ok(reference.clone());
    };
    let purl = parse(raw)?;
    let mut exact = reference.clone();
    if let Some(resolved) = resolve_requirement(&purl, net, cache)? {
        exact.locator = RefLocator::Purl(resolved.to_string());
    }
    Ok(exact)
}

/// Prefer the unique lock pin that satisfies a manifest dependency's
/// requirement. The caller supplies only the applicable package or workspace
/// lock, not an archive-wide union. No match, or several, leaves the
/// reference as declared rather than guessing.
#[must_use]
pub fn prefer_lock_pin(reference: &Reference, lock: &[Reference]) -> Reference {
    lock_pin(reference, lock).unwrap_or_else(|| reference.clone())
}

/// [`prefer_lock_pin`]'s match: the declaration carrying the one satisfying
/// pin's locator and hashes.
fn lock_pin(reference: &Reference, lock: &[Reference]) -> Option<Reference> {
    let RefLocator::Purl(raw) = &reference.locator else {
        return None;
    };
    let purl = Purl::parse(raw).ok()?;
    let requirement = purl.qualifier("version_requirement")?;
    if purl.version().is_some() || purl.qualifier("registry").is_some() {
        return None;
    }
    let range = rules(purl.typ()).requirement?.parse(requirement)?;
    let path = purl.encoded_path();
    let mut satisfying = lock.iter().filter(|pin| {
        let RefLocator::Purl(p) = &pin.locator else {
            return false;
        };
        Purl::parse(p).is_ok_and(|pin| {
            pin.typ() == purl.typ()
                && pin.encoded_path() == path
                && pin.qualifier("repository_url") == purl.qualifier("repository_url")
                && pin.version().is_some_and(|version| range.matches(version))
        })
    });
    let only = satisfying.next()?;
    if satisfying.next().is_some() {
        tracing::debug!(
            locator = raw,
            requirement,
            "several lock pins satisfy the requirement; none preferred"
        );
        return None;
    }
    let mut resolved = reference.clone();
    resolved.locator = only.locator.clone();
    resolved.pinned_hash.clone_from(&only.pinned_hash);
    resolved.content_sha256.clone_from(&only.content_sha256);
    Some(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fetch::Fixtures;
    use crate::fetch::record::tests::dep;

    fn purl(raw: &str) -> Purl {
        Purl::parse(raw).unwrap()
    }

    fn resolved(raw: &str, net: &dyn Fetch) -> Result<Option<String>, ResolveError> {
        resolve_requirement(&purl(raw), net, &BlobCache::disabled())
            .map(|exact| exact.map(|p| p.to_string()))
    }

    #[test]
    fn cargo_requirement_selects_compatible_non_yanked_release() {
        let net = Fixtures::default().with(
            "https://crates.io/api/v1/crates/codec",
            br#"{"versions":[{"num":"2.0.0","yanked":false},{"num":"1.9.0","yanked":true},{"num":"1.4.2","yanked":false}]}"#,
        );
        assert_eq!(
            resolved("pkg:cargo/codec?version_requirement=%5E1.2", &net),
            Ok(Some("pkg:cargo/codec@1.4.2".into()))
        );
        assert_eq!(
            resolved("pkg:cargo/codec?version_requirement=%3E%3D9", &net),
            Err(Unresolved::NoRelease.into())
        );
    }

    #[test]
    fn a_resolved_requirement_keeps_the_declared_subpath() {
        let net = Fixtures::default().with(
            "https://crates.io/api/v1/crates/codec",
            br#"{"versions":[{"num":"1.4.2","yanked":false}]}"#,
        );
        assert_eq!(
            resolved("pkg:cargo/codec?version_requirement=%5E1.2#src/lib", &net),
            Ok(Some("pkg:cargo/codec@1.4.2#src/lib".into()))
        );
    }

    #[test]
    fn a_registry_checksum_is_pinned_onto_the_release() {
        let digest = "ab".repeat(32);
        let body = format!(r#"{{"versions":[{{"num":"1.4.2","checksum":"{digest}"}}]}}"#);
        let net =
            Fixtures::default().with("https://crates.io/api/v1/crates/codec", body.as_bytes());
        assert_eq!(
            resolved("pkg:cargo/codec?version_requirement=%5E1", &net),
            Ok(Some(format!(
                "pkg:cargo/codec@1.4.2?checksum=sha256:{digest}"
            )))
        );
    }

    #[test]
    fn python_requirement_does_not_pick_incompatible_latest() {
        let net = Fixtures::default().with(
            "https://pypi.org/pypi/codec/json",
            br#"{"info":{"version":"9.0"},"releases":{"1.2":[{"yanked":false}],"1.9":[{"yanked":true}],"9.0":[{"yanked":false}]}}"#,
        );
        assert_eq!(
            resolved("pkg:pypi/codec?version_requirement=%3E%3D1%2C%3C2", &net),
            Ok(Some("pkg:pypi/codec@1.2".into()))
        );
    }

    /// PEP 440 admits a pre-release only when a specifier names one; the
    /// registry and the lockfile paths apply the same rule.
    #[test]
    fn a_python_prerelease_is_admitted_only_when_named() {
        let net = Fixtures::default().with(
            "https://pypi.org/pypi/codec/json",
            br#"{"releases":{"1.0.0":[{}],"2.0.0rc1":[{}]}}"#,
        );
        assert_eq!(
            resolved("pkg:pypi/codec?version_requirement=%3D%3D2.0.0rc1", &net),
            Ok(Some("pkg:pypi/codec@2.0.0rc1".into()))
        );
        assert_eq!(
            resolved("pkg:pypi/codec?version_requirement=%3E%3D1", &net),
            Ok(Some("pkg:pypi/codec@1.0.0".into()))
        );

        let declared = |requirement: &str| {
            dep(
                RefLocator::Purl(format!("pkg:pypi/codec?version_requirement={requirement}")),
                None,
            )
        };
        let rc = dep(RefLocator::Purl("pkg:pypi/codec@2.0.0rc1".into()), None);
        let named = declared("%3D%3D2.0.0rc1");
        assert_eq!(
            prefer_lock_pin(&named, std::slice::from_ref(&rc)).locator,
            rc.locator
        );
        let unnamed = declared("%3E%3D1");
        assert_eq!(
            prefer_lock_pin(&unnamed, std::slice::from_ref(&rc)),
            unnamed
        );
    }

    #[test]
    fn npm_requirement_selects_compatible_release_and_honors_dist_tag() {
        let packument = br#"{
            "dist-tags": {"latest": "4.0.50", "next": "5.0.0-beta.1"},
            "versions": {"3.0.39": {}, "3.9.0": {}, "4.0.50": {}, "5.0.0-beta.1": {}}
        }"#;
        let net = Fixtures::default().with("https://registry.npmjs.org/@ai-sdk/groq", packument);
        // A manifest's ^3 range must not drift to the registry's newer major.
        assert_eq!(
            resolved("pkg:npm/%40ai-sdk/groq?version_requirement=%5E3.0.39", &net),
            Ok(Some("pkg:npm/%40ai-sdk/groq@3.9.0".into()))
        );
        // A non-range requirement remains a dist-tag lookup.
        assert_eq!(
            resolved("pkg:npm/%40ai-sdk/groq?version_requirement=next", &net),
            Ok(Some("pkg:npm/%40ai-sdk/groq@5.0.0-beta.1".into()))
        );
    }

    /// An outage, an unsafe name and an unsupported ecosystem each say so,
    /// rather than all reading as "no release".
    #[test]
    fn a_requirement_failure_says_why() {
        let offline = Fixtures::default();
        assert!(matches!(
            resolved("pkg:cargo/codec?version_requirement=%5E1", &offline),
            Err(ResolveError::Failed(_))
        ));
        let gone = Fixtures::default().refusing("https://crates.io/api/v1/crates/codec", 404);
        assert_eq!(
            resolved("pkg:cargo/codec?version_requirement=%5E1", &gone),
            Err(Unresolved::NoRelease.into())
        );
        assert_eq!(
            resolved(
                "pkg:cargo/foo%2F..%2Fbar?version_requirement=%5E1",
                &offline
            ),
            Err(Unresolved::UnsafeCoordinate.into())
        );
        assert_eq!(
            resolved("pkg:alpm/arch/bash?version_requirement=%3E%3D5", &offline),
            Err(Unresolved::Unsupported.into())
        );
        assert_eq!(
            resolved(
                "pkg:cargo/codec?version_requirement=%5E1&repository_url=https:%2F%2Fcargo.example.test",
                &offline
            ),
            Err(Unresolved::Unsupported.into())
        );
        assert_eq!(resolved("pkg:cargo/codec@1.0.0", &offline), Ok(None));
    }

    #[test]
    fn a_declared_reference_resolves_or_says_why() {
        let net = Fixtures::default().with(
            "https://crates.io/api/v1/crates/codec",
            br#"{"versions":[{"num":"1.4.2"}]}"#,
        );
        let declared = dep(
            RefLocator::Purl("pkg:cargo/codec?version_requirement=%5E1".into()),
            None,
        );
        let exact = resolve_declared_reference(&declared, &net, &BlobCache::disabled()).unwrap();
        assert_eq!(
            exact.locator,
            RefLocator::Purl("pkg:cargo/codec@1.4.2".into())
        );
        assert_eq!(exact.source, declared.source);
        assert!(matches!(
            resolve_declared_reference(&declared, &Fixtures::default(), &BlobCache::disabled()),
            Err(ResolveError::Failed(_))
        ));
    }

    #[test]
    fn compatible_lock_pin_preserves_build_role_and_rejects_ambiguity() {
        let mut declaration = dep(
            RefLocator::Purl("pkg:cargo/codec?version_requirement=%5E1.2".into()),
            None,
        );
        declaration.source = "Cargo.toml:build-dependencies.aliased".into();
        declaration.evidence = "aliased = { package = codec, version = 1.2 }".into();
        let pin = dep(RefLocator::Purl("pkg:cargo/codec@1.4.2".into()), None);
        let exact = prefer_lock_pin(&declaration, std::slice::from_ref(&pin));
        assert_eq!(exact.locator, pin.locator);
        assert_eq!(exact.source, declaration.source);
        assert_eq!(exact.evidence, declaration.evidence);
        let incompatible = dep(RefLocator::Purl("pkg:cargo/codec@2.0.0".into()), None);
        assert_eq!(prefer_lock_pin(&declaration, &[incompatible]), declaration);
        let second = dep(RefLocator::Purl("pkg:cargo/codec@1.3.0".into()), None);
        assert_eq!(prefer_lock_pin(&declaration, &[pin, second]), declaration);
    }

    #[test]
    fn an_npm_lock_pin_satisfies_its_range() {
        let declaration = dep(
            RefLocator::Purl("pkg:npm/left-pad?version_requirement=%5E1.1".into()),
            None,
        );
        let pin = dep(RefLocator::Purl("pkg:npm/left-pad@1.3.0".into()), None);
        assert_eq!(
            prefer_lock_pin(&declaration, std::slice::from_ref(&pin)).locator,
            pin.locator
        );
    }
}
