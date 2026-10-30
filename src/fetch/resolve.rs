//! Resolution: a locator to its artifact's URL, and a PURL to every artifact
//! its registry publishes, through one per-ecosystem table, [`rules`].

use filefacts::RefLocator;

use super::BlobCache;
use super::coordinate::{
    is_crates_io, is_web_scheme, repository_base, safe_filename_part, url_host_is,
};
use super::record::Unresolved;
use super::requirement::{Grammar, resolve_requirement};
use super::select::{
    ArtifactCandidate, ArtifactKind, ArtifactMatrix, apply_common_candidate_qualifiers,
    artifact_candidate, attach_candidate_identities, file_name_from_url, file_name_matches,
};
use super::transport::{Fetch, FetchError};
use crate::ecosystem::Coordinates;
use crate::ecosystem::arch::{resolve_arch_current, resolve_aur};
use crate::ecosystem::cargo::cargo_artifacts;
use crate::ecosystem::comfyui::resolve_comfyui;
use crate::ecosystem::composer::resolve_composer;
use crate::ecosystem::container::resolve_oci_ref;
use crate::ecosystem::dify::resolve_dify;
use crate::ecosystem::firefox::resolve_firefox;
use crate::ecosystem::gem::gem_artifacts;
use crate::ecosystem::golang::{golang_artifacts, goproxy_escape};
use crate::ecosystem::npm::{npm_artifacts, npm_version_is_concrete};
use crate::ecosystem::pypi::pypi_artifacts;
use crate::ecosystem::terraform::terraform_artifact;
use crate::ecosystem::vscode::{resolve_openvsx, resolve_vscode};
use crate::purl::Purl;
use crate::registry::RegistryError;

/// Why a reference resolved to no fetchable artifact.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum ResolveError {
    /// There is nothing to fetch, for this reason.
    #[error("unresolved: {0:?}")]
    Unresolved(Unresolved),
    /// A registry read the resolution needed failed — the registry was
    /// unreachable or refused — so a later attempt may succeed.
    #[error("registry read failed: {0}")]
    Failed(FetchError),
}

impl From<Unresolved> for ResolveError {
    fn from(why: Unresolved) -> Self {
        Self::Unresolved(why)
    }
}

impl From<RegistryError> for ResolveError {
    /// A registry that could not be read is a failure a later attempt may
    /// overcome; one that answered without a usable release named none.
    fn from(error: RegistryError) -> Self {
        match error {
            RegistryError::Unavailable(error) => Self::Failed(error),
            RegistryError::InvalidPurl(_) => Unresolved::InvalidPurl.into(),
            RegistryError::UnsafeCoordinate => Unresolved::UnsafeCoordinate.into(),
            RegistryError::NotAPackage
            | RegistryError::Unsupported(_)
            | RegistryError::OffRegistry => Unresolved::Unsupported.into(),
            RegistryError::NotFound | RegistryError::Malformed { .. } | RegistryError::NoRecord => {
                Unresolved::NoRelease.into()
            }
        }
    }
}

/// An artifact URL computed from coordinates alone.
type DeriveFn = fn(&Coordinates<'_>) -> Option<String>;
/// The registry's listing of every artifact one release publishes.
type ListFn =
    fn(&Coordinates<'_>, &dyn Fetch, &BlobCache) -> Result<Vec<ArtifactCandidate>, RegistryError>;
/// A registry API naming the artifact URL, and the release it chose when the
/// coordinates pin none.
type ApiFn =
    fn(&Coordinates<'_>, &dyn Fetch, &BlobCache) -> Result<(Option<String>, String), ResolveError>;

/// How fletch reaches one ecosystem's artifacts.
enum Artifact {
    /// A container image, pulled by the OCI puller from its `oci://` URL.
    Oci,
    /// An artifact URL `derive`d from the coordinates, and the registry's
    /// listing, which decides instead whenever `listed` says the coordinates
    /// alone cannot (no version, a tag, a case-sensitive proxy, a URL only
    /// the registry knows).
    Derived {
        derive: Option<DeriveFn>,
        list: Option<ListFn>,
        listed: fn(&Coordinates<'_>) -> bool,
    },
    /// Only the registry's API names the artifact.
    Api(ApiFn),
    /// No artifact source.
    Unsupported,
}

/// One ecosystem's resolution rules.
pub(super) struct Rules {
    /// The grammar of a `version_requirement` fletch resolves against the
    /// registry; `None` when it resolves none.
    pub(super) requirement: Option<Grammar>,
    artifact: Artifact,
}

/// The single per-ecosystem table: every resolver dispatches on a PURL type
/// here, and nowhere else.
pub(super) fn rules(typ: &str) -> Rules {
    let derived = |derive: DeriveFn| Artifact::Derived {
        derive: Some(derive),
        list: None,
        listed: |_| false,
    };
    let (requirement, artifact) = match typ {
        "oci" | "docker" => (None, Artifact::Oci),
        "npm" => (
            Some(Grammar::Npm),
            Artifact::Derived {
                derive: Some(npm_url),
                list: Some(|c, net, cache| npm_artifacts(c, net, cache)),
                listed: |c| {
                    c.encoded_version()
                        .is_none_or(|v| !npm_version_is_concrete(v))
                },
            },
        ),
        "pypi" => (
            Some(Grammar::Pep440),
            Artifact::Derived {
                derive: None,
                list: Some(|c, net, cache| pypi_artifacts(c, net, cache)),
                listed: |_| true,
            },
        ),
        "cargo" => (
            Some(Grammar::Cargo),
            Artifact::Derived {
                derive: Some(crate_url),
                list: Some(|c, net, cache| cargo_artifacts(c, net, cache)),
                listed: |c| !on_crates_io(c.purl()),
            },
        ),
        "gem" => (
            None,
            Artifact::Derived {
                derive: Some(gem_url),
                list: Some(|c, net, cache| gem_artifacts(c, net, cache)),
                listed: |c| c.encoded_version().is_none(),
            },
        ),
        // The proxy is case-sensitive and a PURL may not be: the listing asks
        // it which spelling it serves.
        "golang" => (
            None,
            Artifact::Derived {
                derive: Some(golang_url),
                list: Some(|c, net, cache| golang_artifacts(c, net, cache)),
                listed: |_| true,
            },
        ),
        // The zip's URL and sha256 exist only in the registry's download API.
        "terraform" => (
            None,
            Artifact::Derived {
                derive: None,
                list: Some(|c, net, cache| terraform_artifact(c, net, cache).map(|a| vec![a])),
                listed: |_| true,
            },
        ),
        "github" => (
            None,
            derived(|c| {
                Some(format!(
                    "https://codeload.github.com/{}/tar.gz/{}",
                    c.path(),
                    c.encoded_version().unwrap_or("HEAD")
                ))
            }),
        ),
        // NuGet's flat-container coordinates and filenames are lowercase,
        // even when the package id and version in the PURL are not.
        "nuget" => (
            None,
            derived(|c| {
                let (id, version) = (c.path().to_lowercase(), c.encoded_version()?.to_lowercase());
                Some(format!(
                    "https://api.nuget.org/v3-flatcontainer/{id}/{version}/{id}.{version}.nupkg"
                ))
            }),
        ),
        "maven" => (None, derived(maven_url)),
        // `chrome-extension` is the ratified purl-spec spelling of the type.
        // The CRX download service redirects to the current packed extension;
        // the id is the last path segment (a slug may precede it).
        "chrome" | "chrome-extension" => (
            None,
            derived(|c| {
                let id = c.path().rsplit('/').next().unwrap_or(c.path());
                Some(format!(
                    "https://clients2.google.com/service/update2/crx?response=redirect&prodversion=120&acceptformat=crx2,crx3&x=id%3D{id}%26installsource%3Dondemand%26uc"
                ))
            }),
        ),
        "clawhub" => (None, derived(clawhub_url)),
        // Open VSX and the VS Code Marketplace publish the exact `.vsix` URL
        // (and the latest version) only through their APIs; the ratified
        // `vscode-extension` type covers both, Open VSX named by its
        // `repository_url`.
        "openvsx" => (
            None,
            Artifact::Api(|c, net, cache| unrefined(resolve_openvsx(c, net, cache))),
        ),
        "vscode" | "vscode-extension" => (None, Artifact::Api(vscode)),
        // AMO, the ComfyUI Registry and the Dify Marketplace name their
        // artifact only through their APIs (a publisher-keyed CDN path, a
        // download key embedding the marketplace's own checksum); unpinned,
        // the current release is chosen and refined into the locator.
        "firefox" => (
            None,
            Artifact::Api(|c, net, cache| refined(resolve_firefox(c, net, cache))),
        ),
        "comfyui" => (
            None,
            Artifact::Api(|c, net, cache| refined(resolve_comfyui(c, net, cache))),
        ),
        "dify" => (
            None,
            Artifact::Api(|c, net, cache| refined(resolve_dify(c, net, cache))),
        ),
        "aur" => (None, Artifact::Api(aur)),
        "alpm" => (None, Artifact::Api(alpm)),
        "composer" => (None, Artifact::Api(composer)),
        _ => (None, Artifact::Unsupported),
    };
    Rules {
        requirement,
        artifact,
    }
}

/// An API answer that names the release it chose and its artifact URL.
fn refined(
    named: Result<(String, String), RegistryError>,
) -> Result<(Option<String>, String), ResolveError> {
    Ok(named.map(|(version, url)| (Some(version), url))?)
}

/// An API answer that names only the artifact URL.
fn unrefined(url: Result<String, RegistryError>) -> Result<(Option<String>, String), ResolveError> {
    Ok((None, url?))
}

/// Whether a Cargo PURL names crates.io, explicitly or by default. A named
/// alternate registry is never redirected to crates.io.
pub(super) fn on_crates_io(purl: &Purl) -> bool {
    purl.qualifier("repository_url").is_none_or(is_crates_io)
}

fn npm_url(c: &Coordinates<'_>) -> Option<String> {
    let version = c.encoded_version()?;
    let name = c.path().replace("%40", "@");
    let base = name.rsplit('/').next().unwrap_or(&name);
    let repository = repository_base(c.purl(), "https://registry.npmjs.org")?;
    Some(format!("{repository}/{name}/-/{base}-{version}.tgz"))
}

/// Alternate Cargo registries publish their download template in their
/// index's `config.json`, so only the listing resolves those.
fn crate_url(c: &Coordinates<'_>) -> Option<String> {
    let version = c.encoded_version()?;
    on_crates_io(c.purl()).then(|| {
        format!(
            "https://static.crates.io/crates/{path}/{path}-{version}.crate",
            path = c.path()
        )
    })
}

/// The Go module proxy's zip; module path and version are case-encoded per
/// the GOPROXY protocol.
fn golang_url(c: &Coordinates<'_>) -> Option<String> {
    let version = c.encoded_version()?;
    let repository = repository_base(c.purl(), "https://proxy.golang.org")?;
    Some(format!(
        "{repository}/{}/@v/{}.zip",
        goproxy_escape(c.path()),
        goproxy_escape(version)
    ))
}

fn gem_url(c: &Coordinates<'_>) -> Option<String> {
    let version = c.encoded_version()?;
    let repository = repository_base(c.purl(), "https://rubygems.org")?;
    let suffix = match c.purl().qualifier("platform") {
        None | Some("ruby") => String::new(),
        Some(value) if safe_filename_part(value) => format!("-{value}"),
        Some(_) => return None,
    };
    Some(format!(
        "{repository}/downloads/{}-{version}{suffix}.gem",
        c.path()
    ))
}

/// Maven Central lays the dotted group id out as path segments. `type` and
/// `classifier` select a non-default artifact; otherwise the main JAR.
fn maven_url(c: &Coordinates<'_>) -> Option<String> {
    let version = c.encoded_version()?;
    let (group, artifact) = c.path().split_once('/')?;
    let extension = match c.purl().qualifier("type") {
        Some(v) if safe_filename_part(v) => v,
        Some(_) => return None,
        None => "jar",
    };
    let classifier = match c.purl().qualifier("classifier") {
        Some(v) if safe_filename_part(v) => format!("-{v}"),
        Some(_) => return None,
        None => String::new(),
    };
    Some(format!(
        "https://repo1.maven.org/maven2/{}/{artifact}/{version}/{artifact}-{version}{classifier}.{extension}",
        group.replace('.', "/")
    ))
}

/// ClawHub's download API takes the slug, plus the owner handle when the
/// PURL carries one (slugs are not unique across publishers).
#[expect(
    clippy::unnecessary_wraps,
    reason = "shaped to fit the resolution table"
)]
fn clawhub_url(c: &Coordinates<'_>) -> Option<String> {
    let (owner, slug) = c.path().split_once('/').unwrap_or(("", c.path()));
    let mut url = format!("https://clawhub.ai/api/v1/download?slug={slug}");
    if !owner.is_empty() {
        url.push_str("&ownerHandle=");
        url.push_str(owner);
    }
    if let Some(v) = c.encoded_version() {
        url.push_str("&version=");
        url.push_str(v);
    }
    Some(url)
}

fn vscode(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<(Option<String>, String), ResolveError> {
    if c.purl()
        .qualifier("repository_url")
        .is_some_and(|url| url_host_is(url, "open-vsx.org"))
    {
        return unrefined(resolve_openvsx(c, net, cache));
    }
    unrefined(resolve_vscode(c, net, cache))
}

/// The AUR serves one artifact per package: the current PKGBUILD-tree
/// snapshot, addressed by *pkgbase*, which the RPC names exactly. Snapshots
/// track HEAD only, so a pinned version cannot select an older release.
#[expect(
    clippy::unnecessary_wraps,
    reason = "shaped to fit the resolution table"
)]
fn aur(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<(Option<String>, String), ResolveError> {
    let name = c.path().rsplit('/').next().unwrap_or(c.path());
    Ok((None, resolve_aur(name, net, cache)))
}

/// `pkg:alpm`: an AUR package (`aur/<name>`, or the spec's `arch/<name>` with
/// the AUR as its `repository_url`), or an official Arch package, fetched
/// only at its current release since the mirrors keep no history.
fn alpm(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<(Option<String>, String), ResolveError> {
    if c.path().starts_with("aur/")
        || c.purl()
            .qualifier("repository_url")
            .is_some_and(|url| url_host_is(url, "aur.archlinux.org"))
    {
        return aur(c, net, cache);
    }
    match (c.path().strip_prefix("arch/"), c.encoded_version()) {
        (Some(name), None) => unrefined(resolve_arch_current(name, net, cache)),
        _ => Err(Unresolved::Unsupported.into()),
    }
}

fn composer(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<(Option<String>, String), ResolveError> {
    if c.encoded_version().is_none() {
        return Err(Unresolved::Unsupported.into());
    }
    unrefined(resolve_composer(c, net, cache))
}

/// Where a PURL's artifact is: the refined PURL its bytes are filed under,
/// the URL to fetch, and the archive's file name.
struct Located {
    purl: Purl,
    url: String,
    file_name: String,
}

impl Located {
    fn at(purl: Purl, url: String) -> Self {
        Self {
            file_name: file_name_from_url(&url),
            purl,
            url,
        }
    }
}

/// A registry to consult while resolving; `None` resolves offline, from the
/// coordinates alone.
type Online<'a> = Option<(&'a dyn Fetch, &'a BlobCache)>;

/// Parse a PURL locator, logging why one does not parse.
pub(super) fn parse(raw: &str) -> Result<Purl, Unresolved> {
    Purl::parse(raw).map_err(|e| {
        tracing::debug!(locator = raw, error = %e, "locator is not a valid PURL");
        Unresolved::InvalidPurl
    })
}

/// Log why `purl` resolved to nothing on the `branch` resolution took, and
/// say so.
fn refused(
    purl: &Purl,
    branch: &'static str,
    why: Unresolved,
    reason: &'static str,
) -> ResolveError {
    tracing::debug!(
        locator = %purl,
        r#type = purl.typ(),
        branch,
        reason,
        unresolved = ?why,
        "resolution refused"
    );
    why.into()
}

/// `error` from the `branch` resolution took for `purl`, logged: a refusal
/// with `reason`, or the registry failure that left the question open.
fn logged(
    purl: &Purl,
    branch: &'static str,
    error: ResolveError,
    reason: &'static str,
) -> ResolveError {
    match error {
        ResolveError::Unresolved(why) => refused(purl, branch, why, reason),
        ResolveError::Failed(error) => {
            tracing::debug!(
                locator = %purl,
                r#type = purl.typ(),
                branch,
                %error,
                "resolution failed: the registry could not be read"
            );
            ResolveError::Failed(error)
        }
    }
}

/// Resolve `purl` to its artifact. Online, a declared requirement is first
/// resolved to its release. A `download_url` qualifier is an exact artifact
/// selector and wins over the ecosystem's own source; a `vers` range names no
/// one release. The `file_name` selector is checked here, once, for every
/// source.
fn locate(purl: &Purl, online: Online<'_>) -> Result<Located, ResolveError> {
    if let Some((net, cache)) = online
        && let Some(exact) = resolve_requirement(purl, net, cache)?
    {
        return locate(&exact, online);
    }
    let located = if let Some(url) = purl.qualifier("download_url") {
        if !is_web_scheme(url) {
            return Err(refused(
                purl,
                "download_url",
                Unresolved::Unsupported,
                "download_url is not a web URL",
            ));
        }
        Located::at(purl.clone(), url.to_owned())
    } else if purl.qualifier("vers").is_some() {
        return Err(refused(
            purl,
            "vers",
            Unresolved::Unsupported,
            "a vers range names no one release",
        ));
    } else {
        // Its one refusal is an unsafe coordinate.
        let coordinates = Coordinates::new(purl).ok().ok_or_else(|| {
            refused(
                purl,
                "coordinates",
                Unresolved::UnsafeCoordinate,
                "coordinate would restructure a registry URL",
            )
        })?;
        locate_artifact(&coordinates, online)?
    };
    if !file_name_matches(purl, &located.file_name) {
        return Err(refused(
            purl,
            "file_name",
            Unresolved::Unsupported,
            "file_name selects an artifact this source does not serve",
        ));
    }
    tracing::debug!(
        locator = %located.purl,
        url = %located.url,
        online = online.is_some(),
        "resolved"
    );
    Ok(located)
}

/// [`locate`] through the ecosystem's [`rules`].
fn locate_artifact(c: &Coordinates<'_>, online: Online<'_>) -> Result<Located, ResolveError> {
    let purl = c.purl();
    match (rules(purl.typ()).artifact, online) {
        (Artifact::Oci, _) => resolve_oci_ref(purl)
            .map(|url| Located::at(purl.clone(), url))
            .ok_or(ResolveError::Unresolved(Unresolved::UnsafeCoordinate)),
        (
            Artifact::Derived {
                list: Some(list),
                listed,
                ..
            },
            Some((net, cache)),
        ) if listed(c) => listed_artifact(c, list, net, cache),
        (
            Artifact::Derived {
                derive: Some(derive),
                ..
            },
            _,
        ) => derive(c)
            .map(|url| Located::at(purl.clone(), url))
            .ok_or_else(|| {
                refused(
                    purl,
                    "derived",
                    Unresolved::Unsupported,
                    "coordinates name no artifact",
                )
            }),
        (Artifact::Api(api), Some((net, cache))) => {
            let (named, url) = api(c, net, cache)
                .map_err(|error| logged(purl, "api", error, "registry API named no artifact"))?;
            let refined = match (c.encoded_version(), named) {
                (None, Some(version)) => purl.with_version(&version).ok_or_else(|| {
                    refused(
                        purl,
                        "api",
                        Unresolved::NoRelease,
                        "registry named an unusable version",
                    )
                })?,
                _ => purl.clone(),
            };
            Ok(Located::at(refined, url))
        }
        _ => Err(refused(
            purl,
            "unsupported",
            Unresolved::Unsupported,
            "no artifact source",
        )),
    }
}

/// The registry listing's preferred artifact, filed under its artifact PURL:
/// the release it belongs to plus the selectors and checksum that pick it.
fn listed_artifact(
    c: &Coordinates<'_>,
    list: ListFn,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Located, ResolveError> {
    let purl = c.purl();
    let Some(candidate) = listing(purl, listed(c, list, net, cache)?)
        .into_iter()
        .find(|candidate| candidate.preferred)
    else {
        return Err(refused(
            purl,
            "listing",
            Unresolved::NoRelease,
            "registry listed no artifact to prefer",
        ));
    };
    let exact = match candidate.artifact_purl {
        Some(artifact) => Purl::parse(&artifact).ok(),
        // The release form drops `checksum`, so a registry answer that spoils
        // the artifact identity (a malformed digest) must not trade a pinned
        // PURL for an unpinned one and pass unverified.
        None if purl.qualifier("checksum").is_some() => Some(purl.clone()),
        None => Some(
            candidate
                .release_purl
                .and_then(|release| Purl::parse(&release).ok())
                .unwrap_or_else(|| purl.clone()),
        ),
    };
    let exact = exact.ok_or_else(|| {
        refused(
            purl,
            "listing",
            Unresolved::NoRelease,
            "registry artifact identity does not parse",
        )
    })?;
    tracing::debug!(locator = %exact, url = %candidate.url, "registry listing chose the artifact");
    Ok(Located {
        purl: exact,
        url: candidate.url,
        file_name: candidate.file_name,
    })
}

/// The registry's listing for `c`. A registry that answered without the
/// release lists nothing; only one that could not be read is an error.
fn listed(
    c: &Coordinates<'_>,
    list: ListFn,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Vec<ArtifactCandidate>, ResolveError> {
    match list(c, net, cache).map_err(ResolveError::from) {
        Ok(candidates) => Ok(candidates),
        Err(ResolveError::Unresolved(why)) => {
            tracing::debug!(locator = %c.purl(), unresolved = ?why, "registry listed nothing");
            Ok(Vec::new())
        }
        Err(error) => Err(logged(
            c.purl(),
            "listing",
            error,
            "registry listing failed",
        )),
    }
}

/// `candidates` with the PURL's common qualifiers applied and their release
/// and artifact identities attached.
fn listing(purl: &Purl, mut candidates: Vec<ArtifactCandidate>) -> Vec<ArtifactCandidate> {
    apply_common_candidate_qualifiers(purl, &mut candidates);
    attach_candidate_identities(purl, &mut candidates);
    candidates
}

/// Resolve a locator to a fetchable URL from its coordinates alone, never
/// asking a registry: `None` for a type whose artifact only its registry can
/// name, or a reference that names none.
///
/// A URL locator is verbatim text out of a scanned file, so it may name a
/// *destination* but never pick a *transport*: [`fetch_ref`](super::fetch_ref)
/// routes an `oci://` target to the container puller, which is reached only
/// from a `pkg:oci` coordinate. Plain `http` still resolves and is refused at
/// connect, which records the more informative outcome.
#[must_use]
pub fn resolve(locator: &RefLocator) -> Option<String> {
    match locator {
        RefLocator::Url(url) => is_web_scheme(url).then(|| url.clone()),
        RefLocator::Purl(raw) => locate(&Purl::parse(raw).ok()?, None)
            .ok()
            .map(|located| located.url),
        // An intra-artifact file reference is resolved against the bundle's
        // other files by a consumer, never fetched; nor is a locator kind
        // this fletch predates.
        _ => None,
    }
}

/// What a fetch retrieves for a reference.
pub(super) struct Target {
    /// The PURL the bytes are filed under, refined from the reference's own
    /// (a version chosen, an artifact selected); `None` for a URL locator.
    pub(super) purl: Option<Purl>,
    /// The canonical locator the bytes are filed and cached under.
    pub(super) locator: String,
    /// The URL to retrieve.
    pub(super) url: String,
}

/// Resolve a reference's locator to what a fetch retrieves, asking the
/// registry where the coordinates alone cannot name the artifact.
pub(super) fn target(
    locator: &RefLocator,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Target, ResolveError> {
    match locator {
        RefLocator::Url(url) if is_web_scheme(url) => Ok(Target {
            purl: None,
            locator: url.clone(),
            url: url.clone(),
        }),
        RefLocator::Purl(raw) => {
            let purl = parse(raw)?;
            let Located { purl, url, .. } = locate(&purl, Some((net, cache)))?;
            Ok(Target {
                locator: purl.to_string(),
                purl: Some(purl),
                url,
            })
        }
        _ => Err(Unresolved::Unsupported.into()),
    }
}

/// Resolve every concrete artifact variant published for `locator`, asking
/// the registry: npm, PyPI, RubyGems, Go modules, Cargo crates and Terraform
/// providers list theirs. The matrix keeps every variant it found, the one a
/// fetch retrieves marked [`ArtifactCandidate::preferred`].
///
/// A declared `version_requirement` is resolved to its release first. The
/// common `download_url`, `file_name`, `repository_url` and `checksum`
/// qualifiers are honored; a `vers` range yields no candidate until its
/// caller picks a release. Compatibility tags that are not PURL selectors
/// (Python wheel tags, npm os/cpu/libc/Node constraints) are
/// [`ArtifactCandidate::attributes`].
pub fn resolve_artifacts(
    locator: &RefLocator,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<ArtifactMatrix, ResolveError> {
    match locator {
        RefLocator::Url(url) if is_web_scheme(url) => Ok(ArtifactMatrix {
            locator: url.clone(),
            candidates: vec![artifact_candidate(url.clone(), ArtifactKind::Download)],
        }),
        RefLocator::Purl(raw) => {
            let purl = parse(raw)?;
            Ok(ArtifactMatrix {
                candidates: purl_artifacts(&purl, net, cache)?,
                locator: purl.to_string(),
            })
        }
        _ => Err(Unresolved::Unsupported.into()),
    }
}

/// [`resolve_artifacts`] for a PURL.
fn purl_artifacts(
    purl: &Purl,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Vec<ArtifactCandidate>, ResolveError> {
    if let Some(exact) = resolve_requirement(purl, net, cache)? {
        return purl_artifacts(&exact, net, cache);
    }
    let candidates = if let Some(url) = purl.qualifier("download_url") {
        if !is_web_scheme(url) {
            return Err(refused(
                purl,
                "download_url",
                Unresolved::Unsupported,
                "download_url is not a web URL",
            ));
        }
        let mut candidate = artifact_candidate(url.to_owned(), ArtifactKind::Download);
        candidate.preferred = file_name_matches(purl, &candidate.file_name);
        vec![candidate]
    } else if purl.qualifier("vers").is_some() {
        Vec::new()
    } else {
        // Its one refusal is an unsafe coordinate.
        let coordinates = Coordinates::new(purl).ok().ok_or_else(|| {
            refused(
                purl,
                "coordinates",
                Unresolved::UnsafeCoordinate,
                "coordinate would restructure a registry URL",
            )
        })?;
        match rules(purl.typ()).artifact {
            Artifact::Derived {
                list: Some(list), ..
            } => listed(&coordinates, list, net, cache)?,
            _ => {
                return Err(refused(
                    purl,
                    "unsupported",
                    Unresolved::Unsupported,
                    "no registry listing",
                ));
            }
        }
    };
    Ok(listing(purl, candidates))
}

/// The artifact a PURL's coordinates name, offered as the one candidate of a
/// listing, `preferred` only when it satisfies the PURL's `file_name`.
pub(crate) fn deterministic_artifacts(purl: &Purl, kind: ArtifactKind) -> Vec<ArtifactCandidate> {
    let url = Coordinates::new(purl)
        .ok()
        .and_then(|c| match rules(purl.typ()).artifact {
            Artifact::Derived {
                derive: Some(derive),
                ..
            } => derive(&c),
            _ => None,
        });
    let Some(url) = url else {
        return Vec::new();
    };
    let mut candidate = artifact_candidate(url, kind);
    candidate.subpath = purl.subpath_string();
    candidate.preferred = file_name_matches(purl, &candidate.file_name);
    vec![candidate]
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::fetch::record::tests::dep;
    use crate::fetch::{Fixtures, Outcome, fetch_ref, sha256_hex};

    /// `raw` resolved online to `(locator, url)`, or `None`.
    pub(in crate::fetch) fn resolved(
        raw: &str,
        net: &dyn Fetch,
        cache: &BlobCache,
    ) -> Option<(String, String)> {
        target(&RefLocator::Purl(raw.into()), net, cache)
            .ok()
            .map(|target| (target.locator, target.url))
    }

    fn offline(raw: &str) -> Option<String> {
        resolve(&RefLocator::Purl(raw.into()))
    }

    fn matrix(raw: &str, net: &dyn Fetch) -> ArtifactMatrix {
        resolve_artifacts(&RefLocator::Purl(raw.into()), net, &BlobCache::disabled())
            .expect("matrix")
    }

    #[test]
    fn resolve_gem_to_rubygems_download() {
        assert_eq!(
            offline("pkg:gem/rails@7.0.4").as_deref(),
            Some("https://rubygems.org/downloads/rails-7.0.4.gem")
        );
        assert_eq!(offline("pkg:gem/rails"), None);
        assert_eq!(
            offline("pkg:gem/nokogiri@1.19.4?platform=x86_64-linux-gnu").as_deref(),
            Some("https://rubygems.org/downloads/nokogiri-1.19.4-x86_64-linux-gnu.gem")
        );
    }

    #[test]
    fn resolves_npm_scoped_and_unscoped() {
        assert_eq!(
            offline("pkg:npm/left-pad@1.3.0").as_deref(),
            Some("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz")
        );
        assert_eq!(
            offline("pkg:npm/%40scope/util@2.1.0").as_deref(),
            Some("https://registry.npmjs.org/@scope/util/-/util-2.1.0.tgz")
        );
        assert_eq!(offline("pkg:pypi/requests@2.0"), None);
    }

    #[test]
    fn resolve_cargo_crate_to_static_crates_io() {
        assert_eq!(
            offline("pkg:cargo/serde@1.0.0").as_deref(),
            Some("https://static.crates.io/crates/serde/serde-1.0.0.crate")
        );
        // No version → no fetchable artifact.
        assert_eq!(offline("pkg:cargo/serde"), None);
    }

    #[test]
    fn resolve_nuget_and_maven_artifacts() {
        assert_eq!(
            offline("pkg:nuget/Newtonsoft.Json@13.0.3").as_deref(),
            Some(
                "https://api.nuget.org/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg"
            )
        );
        assert_eq!(
            offline("pkg:maven/com.google.guava/guava@32.1.3-jre").as_deref(),
            Some(
                "https://repo1.maven.org/maven2/com/google/guava/guava/32.1.3-jre/guava-32.1.3-jre.jar"
            )
        );
        assert_eq!(
            offline("pkg:maven/org.example/tool@1.2.0?classifier=sources&type=zip").as_deref(),
            Some("https://repo1.maven.org/maven2/org/example/tool/1.2.0/tool-1.2.0-sources.zip")
        );
        assert_eq!(
            offline("pkg:maven/org.example/tool@1.2.0?classifier=..%2Fsecret"),
            None
        );
    }

    #[test]
    fn resolve_clawhub_download_url() {
        assert_eq!(
            offline("pkg:clawhub/owner/cool-skill@1.0.2").as_deref(),
            Some(
                "https://clawhub.ai/api/v1/download?slug=cool-skill&ownerHandle=owner&version=1.0.2"
            )
        );
        // A bare slug (no owner, no version) still resolves.
        assert_eq!(
            offline("pkg:clawhub/coolskill").as_deref(),
            Some("https://clawhub.ai/api/v1/download?slug=coolskill")
        );
    }

    #[test]
    fn resolve_oci_to_pseudo_url() {
        // Tag from the qualifier, repository from the percent-encoded
        // repository_url.
        assert_eq!(
            offline("pkg:oci/nginx?repository_url=docker.io%2Flibrary%2Fnginx&tag=1.25").as_deref(),
            Some("oci://docker.io/library/nginx:1.25")
        );
        // A sha256 digest is the version and wins over any tag.
        assert_eq!(
            offline("pkg:oci/img@sha256:244fd47e07d10?repository_url=ghcr.io%2Fowner%2Fimg&tag=v1")
                .as_deref(),
            Some("oci://ghcr.io/owner/img@sha256:244fd47e07d10")
        );
        // No qualifier, no version: Docker Hub's implied coordinates, latest.
        assert_eq!(
            offline("pkg:oci/nginx").as_deref(),
            Some("oci://docker.io/library/nginx:latest")
        );
        // `pkg:docker` with a namespace and a tag in the version slot.
        assert_eq!(
            offline("pkg:docker/smartentry/debian@dc437cc87d10").as_deref(),
            Some("oci://docker.io/smartentry/debian:dc437cc87d10")
        );
    }

    #[test]
    fn a_url_locator_cannot_select_the_container_puller() {
        // `oci://` reaches the OCI puller, which runs outside this module's
        // SSRF-guarded client. It must only ever come from a `pkg:oci`
        // coordinate, never from a URL a scanned file supplied.
        for url in [
            "oci://docker.io/library/nginx:latest",
            "OCI://docker.io/library/nginx:latest",
            "file:///etc/passwd",
            "ftp://example.com/x.tgz",
        ] {
            assert_eq!(resolve(&RefLocator::Url(url.to_string())), None, "{url}");
        }
        // The web schemes still resolve — `http` so it can be refused at
        // connect with the more specific reason.
        for url in ["https://example.com/x.tgz", "HTTPS://example.com/x.tgz"] {
            assert_eq!(
                resolve(&RefLocator::Url(url.to_string())),
                Some(url.to_string())
            );
        }
    }

    #[test]
    fn crafted_coordinates_never_reach_a_url() {
        // Each of these restructures the endpoint it is interpolated into:
        // climbing out of the intended path, or truncating it into a query or
        // fragment.
        for purl in [
            "pkg:npm/../../../evil@1.0.0",
            "pkg:cargo/serde@../../../evil",
            "pkg:golang/github.com/a/../../../../evil@v1.0.0",
            "pkg:maven/com.example/lib@1.0/../../../../evil",
            // A `#` before any `?` is not stripped as a qualifier, so it does
            // reach the interpolation and would truncate the path.
            "pkg:gem/rails#frag@1.0",
            "pkg:nuget/pkg@1.0\\..\\..\\evil",
            "pkg:github/owner/repo@a b",
            "pkg:cargo/foo%2F..%2Fbar@1.0.0",
            "pkg:npm/foo%2Fbar@1.0.0",
            "pkg:gem/foo%2Fbar@1.0.0",
        ] {
            assert_eq!(offline(purl), None, "{purl} must not resolve to a URL");
        }
        // The guard must not reject the punctuation real coordinates carry.
        for purl in [
            "pkg:npm/%40babel/core@7.24.0",
            "pkg:golang/github.com/BurntSushi/toml@v1.4.0",
            "pkg:maven/com.google.guava/guava@32.1.3-jre",
            "pkg:cargo/serde@1.0.0",
            "pkg:github/owner/repo@v1.0.0+build.1",
        ] {
            assert!(offline(purl).is_some(), "{purl} must still resolve");
        }
    }

    /// The `file_name` selector names one exact artifact, so every source —
    /// a derived URL of any ecosystem, a `download_url`, a listing — is held
    /// to it, offline and online alike.
    #[test]
    fn every_source_honors_the_file_name_selector() {
        for purl in [
            "pkg:cargo/serde@1.0.0",
            "pkg:nuget/newtonsoft.json@13.0.3",
            "pkg:maven/com.google.guava/guava@32.1.3-jre",
            "pkg:github/owner/repo@v1.0.0",
            "pkg:chrome/abcdefghijklmnopabcdefghijklmnop",
            "pkg:clawhub/owner/cool-skill@1.0.2",
            "pkg:cargo/serde@1.0.0?download_url=https:%2F%2Fmirror.test%2Fserde.crate",
        ] {
            assert!(offline(purl).is_some(), "{purl}");
            let wrong = if purl.contains('?') {
                format!("{purl}&file_name=other.bin")
            } else {
                format!("{purl}?file_name=other.bin")
            };
            assert_eq!(offline(&wrong), None, "{wrong}");
            assert_eq!(
                resolved(&wrong, &Fixtures::default(), &BlobCache::disabled()),
                None,
                "{wrong}"
            );
        }
        assert_eq!(
            offline("pkg:cargo/serde@1.0.0?file_name=serde-1.0.0.crate").as_deref(),
            Some("https://static.crates.io/crates/serde/serde-1.0.0.crate")
        );
    }

    #[test]
    fn deterministic_ecosystems_honor_common_artifact_selectors() {
        let go = "pkg:golang/google.golang.org/genproto@v1.2.3#googleapis/api/annotations";
        assert_eq!(
            offline(go).as_deref(),
            Some("https://proxy.golang.org/google.golang.org/genproto/@v/v1.2.3.zip")
        );
        let go_matrix = matrix(go, &Fixtures::default());
        assert_eq!(
            go_matrix
                .preferred()
                .and_then(|candidate| candidate.subpath.as_deref()),
            Some("googleapis/api/annotations")
        );

        let unmatched = matrix(
            "pkg:cargo/serde@1.0.0?file_name=another.crate",
            &Fixtures::default(),
        );
        assert_eq!(unmatched.candidates.len(), 1);
        assert_eq!(unmatched.candidates[0].file_name, "serde-1.0.0.crate");
        assert!(unmatched.preferred().is_none());

        let override_purl = "pkg:npm/native-addon?download_url=https:%2F%2Fmirror.test%2Fnative.tgz&file_name=native.tgz";
        assert_eq!(
            resolved(override_purl, &Fixtures::default(), &BlobCache::disabled()),
            Some((
                Purl::parse(override_purl).unwrap().to_string(),
                "https://mirror.test/native.tgz".into()
            ))
        );
        let wrong_file = "pkg:npm/native-addon?download_url=https:%2F%2Fmirror.test%2Fnative.tgz&file_name=other.tgz";
        assert_eq!(
            resolved(wrong_file, &Fixtures::default(), &BlobCache::disabled()),
            None
        );
        let override_matrix = matrix(wrong_file, &Fixtures::default());
        assert_eq!(override_matrix.candidates.len(), 1);
        assert_eq!(override_matrix.candidates[0].kind, ArtifactKind::Download);
        assert!(override_matrix.preferred().is_none());
    }

    #[test]
    fn alternate_repositories_and_ranges_do_not_fall_back_to_public_defaults() {
        let npm_repo = "https://npm.example.test";
        let npm_doc = br#"{"versions":{"1.2.3":{"dist":{"tarball":"https://cdn.example.test/pkg-1.2.3.tgz"}}}}"#;
        let pypi_api = "https://python.example.test/pypi/widget/1.0/json";
        let pypi_doc = br#"{"urls":[{"packagetype":"sdist","filename":"widget-1.0.tar.gz","url":"https://python.example.test/files/widget-1.0.tar.gz"}]}"#;
        let gem_api = "https://gems.example.test/api/v1/versions/widget.json";
        let gem_doc = br#"[{"number":"1.0","platform":"ruby"}]"#;
        let cargo_config = "https://cargo.example.test/index/config.json";
        let cargo_doc = br#"{"dl":"https://cargo.example.test/files/{lowerprefix}/{crate}/{version}/{crate}.crate"}"#;
        let net = Fixtures::default()
            .with(&format!("{npm_repo}/pkg"), npm_doc)
            .with(pypi_api, pypi_doc)
            .with(gem_api, gem_doc)
            .with(cargo_config, cargo_doc);

        for (purl, expected) in [
            (
                "pkg:npm/pkg@1.2.3?repository_url=https:%2F%2Fnpm.example.test",
                "https://cdn.example.test/pkg-1.2.3.tgz",
            ),
            (
                "pkg:pypi/widget@1.0?repository_url=https:%2F%2Fpython.example.test",
                "https://python.example.test/files/widget-1.0.tar.gz",
            ),
            (
                "pkg:gem/widget@1.0?repository_url=https:%2F%2Fgems.example.test",
                "https://gems.example.test/downloads/widget-1.0.gem",
            ),
            (
                "pkg:cargo/serde@1.0.0?repository_url=https:%2F%2Fcargo.example.test%2Findex",
                "https://cargo.example.test/files/se/rd/serde/1.0.0/serde.crate",
            ),
        ] {
            assert_eq!(
                matrix(purl, &net)
                    .preferred()
                    .map(|candidate| candidate.url.as_str()),
                Some(expected),
                "repository for {purl}"
            );
        }

        assert_eq!(
            offline("pkg:golang/example.com/Mod@v1.0.0?repository_url=https:%2F%2Fgo.example.test")
                .as_deref(),
            Some("https://go.example.test/example.com/!mod/@v/v1.0.0.zip")
        );
        assert_eq!(
            offline("pkg:cargo/serde@1.0.0?repository_url=https:%2F%2Fcargo.example.test%2Findex"),
            None
        );

        let range = "pkg:npm/pkg?vers=vers:npm%2F%3E%3D1.0.0";
        assert!(matrix(range, &net).candidates.is_empty());
        assert_eq!(resolved(range, &net, &BlobCache::disabled()), None);
    }

    /// The matrix reports the locator canonicalized, whichever form the
    /// caller wrote and whether or not a requirement was resolved first.
    #[test]
    fn a_matrix_locator_is_always_canonical() {
        let net = Fixtures::default().with(
            "https://crates.io/api/v1/crates/serde",
            br#"{"versions":[{"num":"1.0.0"}]}"#,
        );
        for raw in [
            "pkg:cargo/serde@1.0.0?file_name=serde-1.0.0.crate&checksum=sha256:ab",
            "pkg:cargo/serde?version_requirement=%5E1&checksum=sha256:ab",
        ] {
            assert_ne!(Purl::parse(raw).unwrap().to_string(), raw);
            assert_eq!(
                matrix(raw, &net).locator,
                Purl::parse(raw).unwrap().to_string(),
                "{raw}"
            );
        }
    }

    #[test]
    fn a_requirement_resolves_to_its_release_artifact() {
        let net = Fixtures::default().with(
            "https://crates.io/api/v1/crates/codec",
            br#"{"versions":[{"num":"2.0.0","yanked":false},{"num":"1.4.2","yanked":false}]}"#,
        );
        let (exact, url) = resolved(
            "pkg:cargo/codec?version_requirement=%5E1.2",
            &net,
            &BlobCache::disabled(),
        )
        .unwrap();
        assert_eq!(exact, "pkg:cargo/codec@1.4.2");
        assert!(url.ends_with("codec-1.4.2.crate"));
    }

    /// A candidate the listing rejected (its registry digest contradicts the
    /// declared checksum) is never fetched by another path.
    #[test]
    fn a_listing_rejection_is_final() {
        let pypi = br#"{"urls":[{"packagetype":"sdist","filename":"demo-1.0.tar.gz","url":"https://x/demo.tar.gz","digests":{"sha256":"aaaaaaaa"}}]}"#;
        let npm = br#"{"dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"dist":{"tarball":"https://x/pkg-1.0.0.tgz","shasum":"aaaaaaaa"}}}}"#;
        let net = Fixtures::default()
            .with("https://pypi.org/pypi/demo/1.0/json", pypi)
            .with("https://registry.npmjs.org/pkg", npm);
        for raw in [
            "pkg:pypi/demo@1.0?checksum=sha256:bbbbbbbb",
            "pkg:npm/pkg?checksum=sha1:bbbbbbbb",
            "pkg:npm/pkg@latest?checksum=sha1:bbbbbbbb",
        ] {
            let listed = matrix(raw, &net);
            assert!(
                listed.candidates.iter().all(|c| c.checksum_mismatch),
                "{raw}"
            );
            assert!(listed.preferred().is_none(), "{raw}");
            let rec = fetch_ref(
                &dep(RefLocator::Purl(raw.into()), None),
                &net,
                &BlobCache::disabled(),
            );
            assert_eq!(
                rec.outcome,
                Outcome::Unresolved(Unresolved::NoRelease),
                "{raw}"
            );
        }
    }

    #[test]
    fn registry_candidate_refines_locator_and_verifies_its_checksum() {
        let artifact = "https://files.pythonhosted.org/demo-1.0.tar.gz";
        let bytes = b"artifact bytes";
        let digest = sha256_hex(bytes);
        let body = format!(
            r#"{{"urls":[{{"packagetype":"sdist","filename":"demo-1.0.tar.gz","url":"{artifact}","digests":{{"sha256":"{digest}"}}}}]}}"#
        );
        let net = Fixtures::default()
            .with("https://pypi.org/pypi/demo/1.0/json", body.as_bytes())
            .with(artifact, bytes);
        let record = fetch_ref(
            &dep(RefLocator::Purl("pkg:pypi/demo@1.0".into()), None),
            &net,
            &BlobCache::disabled(),
        );
        assert_eq!(record.outcome, Outcome::Ok);
        assert!(
            record
                .locator
                .contains(&format!("checksum=sha256:{digest}"))
        );
        assert!(record.locator.contains("file_name=demo-1.0.tar.gz"));

        let substituted = Fixtures::default()
            .with("https://pypi.org/pypi/demo/1.0/json", body.as_bytes())
            .with(artifact, b"other bytes");
        let record = fetch_ref(
            &dep(RefLocator::Purl("pkg:pypi/demo@1.0".into()), None),
            &substituted,
            &BlobCache::disabled(),
        );
        assert_eq!(record.outcome, Outcome::PinMismatch);
    }

    #[test]
    fn every_purl_candidate_carries_release_and_artifact_identity() {
        let body = br#"{"urls":[{"packagetype":"sdist","filename":"demo-1.0.tar.gz","url":"https://x/demo.tar.gz"}]}"#;
        let net = Fixtures::default().with("https://pypi.org/pypi/demo/1.0/json", body);
        let listed = matrix("pkg:pypi/demo@1.0", &net);
        let candidate = &listed.candidates[0];
        assert_eq!(candidate.release_purl.as_deref(), Some("pkg:pypi/demo@1.0"));
        assert_eq!(
            candidate.artifact_purl.as_deref(),
            Some("pkg:pypi/demo@1.0?file_name=demo-1.0.tar.gz")
        );
    }

    /// The same rule the digest list follows, one level up: a manifest pin in
    /// an algorithm fletch cannot compute must not erase a `checksum` the
    /// registry refined into the locator that did confirm the bytes.
    #[test]
    fn an_uncomputable_manifest_pin_does_not_erase_a_verified_checksum() {
        let artifact = "https://files.pythonhosted.org/demo-1.0.tar.gz";
        let bytes = b"artifact bytes";
        let body = format!(
            r#"{{"urls":[{{"packagetype":"sdist","filename":"demo-1.0.tar.gz","url":"{artifact}","digests":{{"sha256":"{}"}}}}]}}"#,
            sha256_hex(bytes)
        );
        let net = Fixtures::default()
            .with("https://pypi.org/pypi/demo/1.0/json", body.as_bytes())
            .with(artifact, bytes);
        let record = fetch_ref(
            &dep(
                RefLocator::Purl("pkg:pypi/demo@1.0".into()),
                Some(filefacts::PinnedHash {
                    algo: filefacts::HashAlgo::GoModH1,
                    value: "NIvaJDMOsjHA8n1jAhLSgzrAzy1Hgr+hNrb57e+94F0=".into(),
                }),
            ),
            &net,
            &BlobCache::disabled(),
        );
        assert_eq!(record.outcome, Outcome::Ok);
    }

    #[test]
    fn crates_io_is_recognized_by_either_address() {
        let cargo = |qualifier: &str| {
            on_crates_io(&Purl::parse(&format!("pkg:cargo/serde@1.0.0{qualifier}")).unwrap())
        };
        assert!(cargo(""));
        assert!(cargo("?repository_url=https:%2F%2Fcrates.io%2F"));
        assert!(cargo("?repository_url=https:%2F%2Findex.crates.io"));
        assert!(cargo(
            "?repository_url=sparse%2Bhttps:%2F%2Findex.crates.io%2F"
        ));
        assert!(!cargo("?repository_url=https:%2F%2Fcrates.io.evil.test"));
        assert!(!cargo("?repository_url=https:%2F%2Fevil.test%2Fcrates.io"));
    }

    #[test]
    fn an_unreachable_registry_is_a_failure_not_a_missing_release() {
        let unreachable = Fixtures::default();
        let cache = BlobCache::disabled();
        let resolved =
            |raw: &str, net: &Fixtures| target(&RefLocator::Purl(raw.into()), net, &cache);
        // Listings, then registry APIs.
        for raw in [
            "pkg:npm/left-pad",
            "pkg:pypi/requests@2.31.0",
            "pkg:gem/rails",
            "pkg:terraform/hashicorp/aws",
            "pkg:cargo/serde@1.0.0?repository_url=https:%2F%2Fcargo.example.test%2Findex",
            "pkg:firefox/ublock-origin",
            "pkg:comfyui/node@1.0",
            "pkg:dify/org/plugin",
            "pkg:composer/monolog/monolog@3.0.0",
            "pkg:vscode/redhat/java",
            "pkg:openvsx/redhat/java",
            "pkg:alpm/arch/bash",
        ] {
            assert!(
                matches!(resolved(raw, &unreachable), Err(ResolveError::Failed(_))),
                "{raw}"
            );
        }
        assert!(matches!(
            resolve_artifacts(
                &RefLocator::Purl("pkg:npm/left-pad".into()),
                &unreachable,
                &cache
            ),
            Err(ResolveError::Failed(_))
        ));
        // A registry that answers without the package named no release.
        let absent = Fixtures::default().refusing("https://registry.npmjs.org/left-pad", 404);
        assert_eq!(
            resolved("pkg:npm/left-pad", &absent).err(),
            Some(ResolveError::Unresolved(Unresolved::NoRelease))
        );
    }

    #[test]
    fn an_alternate_cargo_index_is_needed_only_when_the_template_wants_its_checksum() {
        let config = "https://cargo.example.test/index/config.json";
        let purl = "pkg:cargo/serde@1.0.0?repository_url=https:%2F%2Fcargo.example.test%2Findex";
        let net = Fixtures::default().with(
            config,
            br#"{"dl":"https://cargo.example.test/files/{crate}/{version}/{sha256-checksum}"}"#,
        );
        assert!(matches!(
            target(&RefLocator::Purl(purl.into()), &net, &BlobCache::disabled()),
            Err(ResolveError::Failed(_))
        ));
    }
}
