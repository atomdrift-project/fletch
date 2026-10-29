//! Look up and normalize a package's registry metadata.
//!
//! [`fetch`](crate::fetch) retrieves the *artifact*; this module retrieves the
//! registry's *metadata about* the artifact — publish date, author, downloads,
//! rating, deprecation — and reduces every ecosystem's bespoke JSON to one
//! common [`filefacts::Registry`] shape (which filefacts can re-parse from a
//! serialized `*.registry.json` document into trait-matchable facts). A
//! consumer then applies uniform policy — age gating, reputation heuristics —
//! without knowing whether the source was npm, PyPI, crates.io, Packagist, or
//! the AUR.
//!
//! The lookup is small (a JSON document, not a tarball) and cached, so it is the
//! cheap thing to do *first*: learn a dependency's age before deciding whether
//! the expensive fetch and analysis of its bytes is worth it.

use std::sync::{Arc, PoisonError};

use crate::distro;
use crate::ecosystem::{
    Coordinates, arch, cargo, chrome, clawhub, clojars, comfyui, composer, conda, container, cpan,
    cran, dify, fedora, firefox, for_version, gem, github, golang, hex, homebrew, huggingface,
    jetbrains, jsr, maven, npm, nuget, pub_dev, pypi, snap, terraform, vscode, wordpress,
};
use crate::fetch::{BlobCache, Fetch, FetchError, RecordedSource, is_http_url, url_host_is};
use crate::purl::{Purl, PurlError};
use filefacts::{RefLocator, Registry};

/// Why a registry lookup produced no record.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum RegistryError {
    /// The locator is a URL or a path, not a package URL.
    #[error("not a package URL")]
    NotAPackage,
    /// The package URL does not parse.
    #[error(transparent)]
    InvalidPurl(#[from] PurlError),
    /// A coordinate that could restructure the registry URL it fills, which
    /// no registry name does (see `safe_coordinate`).
    #[error("coordinate is not a registry name")]
    UnsafeCoordinate,
    /// fletch has no registry lookup for this package type.
    #[error("no registry lookup for type `{0}`")]
    Unsupported(String),
    /// The registry answered that it has no such package (404 or 410).
    #[error("not in the registry")]
    NotFound,
    /// The registry could not be reached, or refused the request.
    #[error("registry unavailable: {0}")]
    Unavailable(FetchError),
    /// The registry's answer was not the document fletch reads: a schema
    /// change upstream, or not JSON at all.
    #[error("unreadable registry document {url}: {reason}")]
    Malformed {
        /// The document that could not be read.
        url: String,
        /// What was wrong with it, as the decoder put it.
        reason: String,
    },
    /// The registry answered, but with nothing fletch could read as a record.
    #[error("no usable record in the registry's answer")]
    NoRecord,
    /// The PURL's bytes come from somewhere other than the registry the lookup
    /// reads (a `download_url`, a `repository_url` other than that registry,
    /// or a namespace naming another repository), so that registry's record
    /// would describe another artifact.
    #[error("package is not served by the registry fletch reads")]
    OffRegistry,
}

impl From<FetchError> for RegistryError {
    /// A registry that answers 404 or 410 has no such package; any other
    /// failure leaves the question open.
    fn from(error: FetchError) -> Self {
        match error {
            FetchError::Status(404 | 410) => Self::NotFound,
            error => Self::Unavailable(error),
        }
    }
}

/// Look up and normalize the registry metadata for a dependency `locator`.
///
/// Dispatches on the PURL type, fetches the metadata document through the
/// blob cache (one round-trip per package per cache window, free on a hit),
/// and maps it to [`Registry`]. The returned record leaves
/// [`Registry::age_days`] unset; the caller stamps it with
/// [`Registry::with_age`] from its own clock. The error says why there is no
/// record, so the caller can decide what an absent answer means.
pub fn lookup(
    locator: &RefLocator,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let started = std::time::Instant::now();
    let result = resolve(locator, net, cache);
    let raw = crate::fetch::locator_str(locator);
    match &result {
        Ok(record) => tracing::debug!(
            locator = %raw.escape_debug(),
            ecosystem = %record.ecosystem,
            version = %record.version,
            "registry record"
        ),
        Err(error) => tracing::debug!(
            locator = %raw.escape_debug(),
            %error,
            "no registry record"
        ),
    }
    crate::metrics::registry(raw, &result, started.elapsed());
    result
}

/// [`lookup`], also returning the raw provider documents the lookup consumed:
/// the `(url, bytes)` of every metadata response it read, from the warm cache
/// or a fresh fetch, in read order — the primary registry document first. A
/// consumer that archives provenance keeps these beside the normalized record
/// as its re-parsing backup. On an error, the sources are whatever was read
/// before the lookup gave up (often none).
pub fn lookup_recorded(
    locator: &RefLocator,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> (Result<Registry, RegistryError>, Vec<RecordedSource>) {
    let (recording, sink) = cache.recording();
    let record = lookup(locator, net, &recording);
    drop(recording);
    // A lookup that panicked mid-read poisons the sink; what it recorded
    // before then is still the provenance of whatever it returned.
    let sources = match Arc::try_unwrap(sink) {
        Ok(mutex) => mutex.into_inner().unwrap_or_else(PoisonError::into_inner),
        Err(shared) => std::mem::take(&mut *shared.lock().unwrap_or_else(PoisonError::into_inner)),
    };
    (record, sources)
}

/// [`lookup`]'s work: parse and vet the coordinate, refuse off-registry
/// bytes, then dispatch under the TTL the version warrants.
fn resolve(
    locator: &RefLocator,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let RefLocator::Purl(raw) = locator else {
        return Err(RegistryError::NotAPackage);
    };
    let purl = Purl::parse(raw)?;
    let c = Coordinates::new(&purl)?;
    // The fetcher honours these qualifiers, so without this a file could name
    // `pkg:npm/lodash@4.17.21?repository_url=https://evil.test` and have
    // evil.test's bytes judged by lodash's age and popularity.
    if off_registry(&purl) {
        tracing::debug!(
            purl = %raw.escape_debug(),
            "registry lookup refused: the PURL's bytes are not the public registry's"
        );
        return Err(RegistryError::OffRegistry);
    }
    let (first, staged) = for_version(cache, c.version()).staged();
    let record = dispatch(&c, net, &first);
    // The one fact a months-old copy can't hold is a version published after
    // it was cached. In an ecosystem whose package document dates every
    // version it lists, an undated pinned record means the copy didn't list
    // it, so re-read the document under the versionless TTL before concluding
    // so. A hijacked account's new release is exactly this case, and its
    // publish time, publisher and install hooks are what would flag it.
    if c.version().is_some()
        && DATES_EVERY_VERSION.contains(&purl.typ())
        && record.as_ref().is_ok_and(|r| r.published_at.is_none())
    {
        tracing::debug!(
            purl = %raw.escape_debug(),
            "pinned version undated in the cached document; re-reading it fresh"
        );
        return dispatch(&c, net, &for_version(cache, None));
    }
    cache.commit(staged);
    record
}

/// Ecosystems whose package document carries a publish time for every version
/// it lists — so a requested version with none is one the document lacks.
const DATES_EVERY_VERSION: &[&str] = &[
    "npm",
    "cargo",
    "pypi",
    "composer",
    "gem",
    "hex",
    "pub",
    "conda",
    "jsr",
    "cran",
    "terraform",
];

/// Whether `purl` names bytes the registry lookup does not read: any
/// `download_url`, or a `repository_url` that is not the type's public
/// registry ([`repository_is_public`]).
fn off_registry(purl: &Purl) -> bool {
    purl.qualifier("download_url").is_some()
        || purl
            .qualifier("repository_url")
            .is_some_and(|url| !repository_is_public(purl.typ(), url))
}

/// Whether `url`, a `repository_url` qualifier on a PURL of type `typ`, names
/// the public registry fletch reads that type's metadata from.
///
/// Deny by default: a type absent from the table has no public repository URL
/// fletch recognizes, so any `repository_url` on it names somewhere else. For
/// the rest, the URL must be absolute `http`/`https` and its host exactly one
/// of the type's registry hosts; the path is not consulted, since each of
/// these hosts serves one registry. A Cargo `sparse+` prefix is the same
/// registry over the sparse protocol, so `sparse+https://index.crates.io/`
/// is public. An OCI `repository_url` is a `host/path` reference rather than
/// a URL; it is public when its host is Docker Hub or Quay, the registries
/// whose metadata fletch reads.
pub(crate) fn repository_is_public(typ: &str, url: &str) -> bool {
    if matches!(typ, "oci" | "docker") {
        return container::public_repository(url);
    }
    let hosts: &[&str] = match typ {
        "npm" => &["registry.npmjs.org"],
        "pypi" => &["pypi.org", "files.pythonhosted.org"],
        "cargo" => &["crates.io", "index.crates.io", "static.crates.io"],
        "gem" => &["rubygems.org"],
        "golang" => &["proxy.golang.org"],
        "maven" => &["repo.maven.apache.org", "repo1.maven.org"],
        "nuget" => &["api.nuget.org", "www.nuget.org", "nuget.org"],
        "composer" => &["repo.packagist.org", "packagist.org"],
        "hex" => &["hex.pm", "repo.hex.pm"],
        "pub" => &["pub.dev"],
        "conda" => &["conda.anaconda.org", "anaconda.org"],
        "cran" => &["cran.r-project.org", "cloud.r-project.org"],
        "clojars" => &["clojars.org", "repo.clojars.org"],
        "jsr" => &["jsr.io"],
        "terraform" => &["registry.terraform.io"],
        "huggingface" => &["huggingface.co"],
        "alpm" => &["archlinux.org", "aur.archlinux.org"],
        "vscode-extension" => &["marketplace.visualstudio.com", "open-vsx.org"],
        _ => &[],
    };
    let url = if typ == "cargo" {
        url.strip_prefix("sparse+").unwrap_or(url)
    } else {
        url
    };
    is_http_url(url) && hosts.iter().any(|host| url_host_is(url, host))
}

/// One registry lookup: dispatch on the PURL type to its backend. The OS
/// types carry the distribution in their one namespace segment
/// (`pkg:deb/debian/curl`); any other vendor (a PPA, a derivative, a
/// third-party repo) names its own repository, whose package of the same
/// name the official record does not describe.
fn dispatch(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let typ = c.purl().typ();
    let vendor = match c.namespace() {
        [vendor] => Some(vendor.as_str()),
        _ => None,
    };
    match (typ, vendor) {
        ("npm", _) => npm::lookup(c, net, cache),
        ("cargo", _) => cargo::lookup(c, net, cache),
        ("pypi", _) => pypi::lookup(c, net, cache),
        ("composer", _) => composer::lookup(c, net, cache),
        ("gem", _) => gem::lookup(c, net, cache),
        ("golang", _) => golang::lookup(c, net, cache),
        ("github", _) => github::lookup(c, net, cache),
        ("nuget", _) => nuget::lookup(c, net, cache),
        ("maven", _) => maven::lookup(c, net, cache),
        ("huggingface", _) => huggingface::lookup(c, net, cache),
        ("hex", _) => hex::lookup(c, net, cache),
        ("cran", _) => cran::lookup(c, net, cache),
        ("cpan", _) => cpan::lookup(c, net, cache),
        ("pub", _) => pub_dev::lookup(c, net, cache),
        ("conda", _) => conda::lookup(c, net, cache),
        ("clojars", _) => clojars::lookup(c, net, cache),
        ("jsr", _) => jsr::lookup(c, net, cache),
        ("terraform", _) => terraform::lookup(c, net, cache),
        ("alpm", Some("aur")) => arch::user(c, net, cache),
        ("alpm", Some(repo)) if arch::REPOSITORIES.contains(&repo) => arch::official(c, net, cache),
        ("deb", Some("debian")) => at_requested(c, distro::debian(c.name(), net, cache)),
        ("deb", Some("ubuntu")) => at_requested(c, distro::ubuntu(c.name(), net, cache)),
        ("rpm", Some("fedora")) => fedora::lookup(c, net, cache),
        ("rpm", Some("opensuse")) => at_requested(c, distro::opensuse(c.name(), net, cache)),
        ("rpm", Some("rpmfusion")) => at_requested(c, distro::rpmfusion(c.name(), net, cache)),
        ("apk", Some("alpine")) => at_requested(c, distro::alpine(c.name(), net, cache)),
        ("apk", Some("wolfi")) => at_requested(c, distro::wolfi(c.name(), net, cache)),
        ("alpm" | "deb" | "rpm" | "apk", _) => {
            tracing::debug!(
                purl_type = typ,
                namespace = %c.namespace().join("/").escape_debug(),
                "registry lookup refused: not an official repository"
            );
            Err(RegistryError::OffRegistry)
        }
        ("netbsd", _) => c
            .bare_name(&[])
            .and_then(|_| at_requested(c, distro::netbsd(c.name(), net, cache))),
        ("freebsd", _) => c
            .bare_name(&[])
            .and_then(|_| at_requested(c, distro::freebsd(c.name(), net, cache))),
        ("openbsd", _) => c
            .bare_name(&[])
            .and_then(|_| at_requested(c, distro::openbsd(c.name(), net, cache))),
        ("brew" | "homebrew", _) => homebrew::lookup(c, net, cache),
        ("snap", _) => snap::lookup(c, net, cache),
        ("wordpress", _) => wordpress::lookup(c, net, cache),
        ("clawhub", _) => clawhub::lookup(c, net, cache),
        ("comfyui", _) => comfyui::lookup(c, net, cache),
        ("dify", _) => dify::lookup(c, net, cache),
        // `pkg:docker` is the pre-ratification spelling of `pkg:oci`: the
        // same repositories, so it routes identically.
        ("oci" | "docker", _) => container::lookup(c, net, cache),
        ("firefox", _) => firefox::lookup(c, net, cache),
        ("jetbrains", _) => jetbrains::lookup(c, net, cache),
        ("chrome-extension", _) => chrome::lookup(c, net, cache),
        // One ratified type covers both editor marketplaces; a
        // `repository_url` on Open VSX names that store.
        ("vscode-extension", _)
            if c.purl()
                .qualifier("repository_url")
                .is_some_and(|url| url_host_is(url, "open-vsx.org")) =>
        {
            vscode::open_vsx(c, net, cache)
        }
        ("vscode-extension", _) => vscode::marketplace(c, net, cache),
        (other, _) => Err(RegistryError::Unsupported(other.to_string())),
    }
}

/// A distro index lists only each package's current build, which becomes the
/// record's `latest_version`. A requested version other than that build is
/// still the version the record describes — undated, since the index does not
/// say when it was built.
fn at_requested(
    c: &Coordinates<'_>,
    record: Result<Registry, RegistryError>,
) -> Result<Registry, RegistryError> {
    let mut record = record?;
    record.latest_version = Some(record.version.clone());
    if let Some(requested) = c.version()
        && requested != record.version
    {
        tracing::debug!(
            requested = %requested.escape_debug(),
            current = %record.version,
            "requested build is not the index's current one; leaving it undated"
        );
        record.version = requested.to_string();
        record.published_at = None;
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use filefacts::Ecosystem;

    use crate::fetch::{BlobCache, Fixtures};

    #[test]
    fn lookup_recorded_returns_record_and_raw_documents() {
        let packument = serde_json::json!({
            "dist-tags": {"latest": "1.3.0"},
            "versions": {"1.3.0": {"license": "MIT"}},
            "time": {"1.3.0": "2021-04-23T10:00:00.000Z"},
            "maintainers": [{"name": "una"}],
        })
        .to_string();
        let net = Fixtures::default().with_headers(
            "https://registry.npmjs.org/left-pad",
            packument.as_bytes(),
            &[("Content-Type", "application/json")],
        );
        // Disabled cache: every read is a fresh fetch through the recorder.
        let (record, sources) = lookup_recorded(
            &RefLocator::Purl("pkg:npm/left-pad@1.3.0".into()),
            &net,
            &BlobCache::disabled(),
        );

        let record = record.expect("record");
        assert_eq!(record.ecosystem, Ecosystem::Npm);
        assert_eq!(record.name, "left-pad");

        // The raw packument is captured verbatim, with its transport facts — the
        // downloads endpoint isn't in the fixtures, so it fails and isn't recorded.
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].url, "https://registry.npmjs.org/left-pad");
        assert_eq!(sources[0].status, 200);
        assert_eq!(sources[0].content_type.as_deref(), Some("application/json"));
        let bytes = sources[0].bytes.as_deref().expect("kept: no source limit");
        assert_eq!(sources[0].size, bytes.len() as u64);
        let body: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        assert_eq!(body["dist-tags"]["latest"], "1.3.0");

        // Past the cache's source limit the document is still named, with
        // its size, but its bytes are not copied.
        let (_, sources) = lookup_recorded(
            &RefLocator::Purl("pkg:npm/left-pad@1.3.0".into()),
            &net,
            &BlobCache::disabled().with_source_limit(16),
        );
        assert_eq!(sources[0].url, "https://registry.npmjs.org/left-pad");
        assert_eq!(sources[0].size, bytes.len() as u64);
        assert_eq!(sources[0].bytes, None);
    }

    #[test]
    fn pinned_metadata_outlives_unpinned_and_honours_the_override() {
        // A pinned coordinate cannot come back holding different bytes on any
        // registry we support, so its packument is held for months; a versionless
        // lookup resolves through mutable dist-tags and keeps a tight bound.
        let cache = BlobCache::disabled();
        assert!(cache.meta_ttl_pinned() > cache.meta_ttl_unpinned());
        assert!(cache.meta_ttl_pinned() >= std::time::Duration::from_secs(30 * 86_400));

        // An explicit operator override still wins on both tiers, so asking for
        // tight revalidation is never silently ignored.
        let minute = std::time::Duration::from_secs(60);
        let cache = cache.with_registry_ttl(Some(minute));
        assert_eq!(cache.meta_ttl_pinned(), minute);
        assert_eq!(cache.meta_ttl_unpinned(), minute);
    }

    #[test]
    fn an_unsupported_or_unreachable_locator_has_no_record() {
        let net = Fixtures::default();
        let cache = BlobCache::disabled();
        assert!(
            lookup(
                &RefLocator::Url("https://x.test/a.tgz".into()),
                &net,
                &cache
            )
            .is_err()
        );
        assert!(
            lookup(
                &RefLocator::Purl("pkg:gem/rails@7.0.0".into()),
                &net,
                &cache
            )
            .is_err()
        );
    }

    #[test]
    fn a_lookup_says_why_it_has_no_record() {
        let url = "https://pypi.org/pypi/w/json";
        let why = |net: &Fixtures, raw: &str| {
            lookup(&RefLocator::Purl(raw.into()), net, &BlobCache::disabled()).err()
        };
        let none = Fixtures::default();
        assert_eq!(
            lookup(
                &RefLocator::Url("https://example.test/x".into()),
                &none,
                &BlobCache::disabled()
            )
            .err(),
            Some(RegistryError::NotAPackage)
        );
        assert_eq!(
            why(&none, "not a purl"),
            Some(RegistryError::InvalidPurl(PurlError::Syntax("no scheme")))
        );
        assert_eq!(
            why(&none, "pkg:pypi/w@..%2F..%2Fx"),
            Some(RegistryError::UnsafeCoordinate)
        );
        assert_eq!(
            why(&none, "pkg:swift/github.com/apple/swift-nio@1.0.0"),
            Some(RegistryError::Unsupported("swift".into()))
        );
        // What the registry said, or failed to say.
        assert_eq!(
            why(&Fixtures::default().refusing(url, 404), "pkg:pypi/w"),
            Some(RegistryError::NotFound)
        );
        assert_eq!(
            why(&Fixtures::default().refusing(url, 503), "pkg:pypi/w"),
            Some(RegistryError::Unavailable(FetchError::Status(503)))
        );
        assert!(matches!(
            why(&none, "pkg:pypi/w"),
            Some(RegistryError::Unavailable(FetchError::Transport(_)))
        ));
        assert_eq!(
            why(&Fixtures::default().with(url, b"{}"), "pkg:pypi/w"),
            Some(RegistryError::NoRecord)
        );
    }

    #[test]
    fn a_subpath_does_not_hide_the_package_from_its_registry() {
        // A Go module addressed with a subpath is still that module: the
        // subpath never reaches the coordinate the URL is built from.
        let doc = br#"{"Version":"v0.0.0-20240101","Time":"2024-01-01T00:00:00Z"}"#;
        let net = Fixtures::default().with(
            "https://proxy.golang.org/google.golang.org/genproto/@latest",
            doc,
        );
        let locator =
            RefLocator::Purl("pkg:golang/google.golang.org/genproto#googleapis/api".into());
        let record = lookup(&locator, &net, &BlobCache::disabled()).expect("record");
        assert_eq!(record.version, "v0.0.0-20240101");
    }

    #[test]
    fn only_the_repository_qualifier_routes_alpm_to_the_aur() {
        // Both stores answer for `pacman`; which one the lookup asks decides
        // the record. A qualifier that merely mentions the AUR host is not a
        // route there, so an official package goes to the official repository.
        let arch =
            br#"{"results":[{"pkgname":"pacman","repo":"core","pkgver":"7.1.0","pkgrel":"2"}]}"#;
        let aur = br#"{"results":[{"Name":"pacman","Version":"6.0-1"}]}"#;
        let net = Fixtures::default()
            .with(
                "https://archlinux.org/packages/search/json/?name=pacman",
                arch,
            )
            .with(
                "https://aur.archlinux.org/rpc/v5/info?arg%5B%5D=pacman",
                aur,
            );
        let lookup = |purl: &str| {
            lookup(&RefLocator::Purl(purl.into()), &net, &BlobCache::disabled())
                .ok()
                .map(|r| r.ecosystem)
        };
        assert_eq!(
            lookup("pkg:alpm/core/pacman?foo=aur.archlinux.org"),
            Some(Ecosystem::Arch)
        );
        assert_eq!(
            lookup("pkg:alpm/arch/pacman?repository_url=https://aur.archlinux.org"),
            Some(Ecosystem::Aur)
        );
    }

    #[test]
    fn a_namespaced_docker_image_is_not_the_official_one() {
        // `pkg:docker/myorg/nginx` is Docker Hub's `myorg/nginx`. Looked up as
        // `library/nginx`, it would inherit the official image's pulls and stars.
        let doc = serde_json::json!({"name": "nginx", "namespace": "myorg", "pull_count": 3u64})
            .to_string();
        let net = Fixtures::default().with(
            "https://hub.docker.com/v2/repositories/myorg/nginx",
            doc.as_bytes(),
        );
        let locator = RefLocator::Purl("pkg:docker/myorg/nginx".into());
        let r = lookup(&locator, &net, &BlobCache::disabled()).expect("registry");
        assert_eq!(r.author.as_deref(), Some("myorg"));
        assert_eq!(r.downloads_total, Some(3));
        // A bare name is still the official image.
        assert_eq!(
            crate::ecosystem::container::oci_repository("nginx", None).as_deref(),
            Ok("docker.io/library/nginx")
        );
    }

    #[test]
    fn an_unlisted_version_is_undated_in_every_backend() {
        // Each registry knows the package and its latest release, but not
        // version 9.9.9, which must stay undated rather than borrow the newest
        // release's date or the package's own creation.
        let docs = [
            (
                "https://crates.io/api/v1/crates/c",
                serde_json::json!({"crate": {"max_version": "1.0.0", "created_at": "2015-01-01T00:00:00Z"},
                    "versions": [{"num": "1.0.0", "created_at": "2024-01-01T00:00:00Z"}]}),
            ),
            (
                "https://rubygems.org/api/v1/gems/g.json",
                serde_json::json!({"version": "1.0.0"}),
            ),
            (
                "https://rubygems.org/api/v1/versions/g.json",
                serde_json::json!([{"number": "1.0.0", "created_at": "2024-01-01T00:00:00Z"}]),
            ),
            (
                "https://hex.pm/api/packages/h",
                serde_json::json!({"latest_version": "1.0.0", "inserted_at": "2015-01-01T00:00:00Z",
                    "releases": [{"version": "1.0.0", "inserted_at": "2024-01-01T00:00:00Z"}]}),
            ),
            (
                "https://pub.dev/api/packages/p",
                serde_json::json!({"latest": {"version": "1.0.0", "published": "2024-01-01T00:00:00Z"},
                    "versions": [{"version": "1.0.0", "published": "2024-01-01T00:00:00Z"}]}),
            ),
            (
                "https://api.anaconda.org/package/conda-forge/k",
                serde_json::json!({"latest_version": "1.0.0", "created_at": "2015-01-01T00:00:00Z",
                    "files": [{"version": "1.0.0", "upload_time": "2024-01-01T00:00:00Z"}]}),
            ),
            (
                "https://api.jsr.io/scopes/s/packages/j",
                serde_json::json!({"latestVersion": "1.0.0"}),
            ),
            (
                "https://azuresearch-usnc.nuget.org/query?q=packageid:n&prerelease=true&semVerLevel=2.0.0",
                serde_json::json!({"data": [{"id": "n", "version": "1.0.0",
                    "versions": [{"version": "1.0.0"}]}]}),
            ),
        ];
        let net = docs
            .iter()
            .fold(Fixtures::default(), |net, (url, doc)| {
                net.with(url, doc.to_string().as_bytes())
            })
            .refusing("https://api.jsr.io/scopes/s/packages/j/versions/9.9.9", 404);
        let cache = BlobCache::disabled();
        let first_release = Some(1_420_070_400); // 2015-01-01

        let records = [
            "pkg:cargo/c",
            "pkg:gem/g",
            "pkg:hex/h",
            "pkg:pub/p",
            "pkg:conda/k",
            "pkg:jsr/%40s/j",
            "pkg:nuget/n",
        ]
        .map(|purl| lookup(&RefLocator::Purl(format!("{purl}@9.9.9")), &net, &cache));
        for r in records {
            let r = r.expect("the package itself resolves");
            assert_eq!(r.version, "9.9.9", "{}", r.ecosystem);
            assert_eq!(r.published_at, None, "{}", r.ecosystem);
            // Where a backend has the package's birth date, it lands in the
            // field that means that.
            if matches!(r.ecosystem.as_str(), "crates" | "hex" | "conda") {
                assert_eq!(r.first_published_at, first_release, "{}", r.ecosystem);
            }
        }
    }

    #[test]
    fn a_package_with_no_stable_release_still_has_a_latest() {
        // Each registry sends `null` for the stable release and names the
        // newest pre-release beside it, which is then the latest.
        let docs = [
            (
                "https://crates.io/api/v1/crates/c",
                serde_json::json!({"crate": {"max_stable_version": null, "max_version": "0.1.0-rc.1"}}),
            ),
            (
                "https://hex.pm/api/packages/h",
                serde_json::json!({"latest_stable_version": null, "latest_version": "0.1.0-rc.1"}),
            ),
            (
                "https://clojars.org/api/artifacts/k",
                serde_json::json!({"jar_name": "k", "latest_release": null, "latest_version": "0.1.0-SNAPSHOT"}),
            ),
        ];
        let net = docs.iter().fold(Fixtures::default(), |net, (url, doc)| {
            net.with(url, doc.to_string().as_bytes())
        });
        let cache = BlobCache::disabled();
        let version = |purl: &str| {
            lookup(&RefLocator::Purl(purl.into()), &net, &cache)
                .expect("the package resolves")
                .version
        };
        assert_eq!(version("pkg:cargo/c"), "0.1.0-rc.1");
        assert_eq!(version("pkg:hex/h"), "0.1.0-rc.1");
        assert_eq!(version("pkg:clojars/k"), "0.1.0-SNAPSHOT");
    }

    #[test]
    fn off_registry_bytes_never_borrow_the_public_record() {
        // No fixtures: an off-registry PURL must be refused before any read.
        let (net, cache) = (Fixtures::default(), BlobCache::disabled());
        let look = |purl: &str| lookup(&RefLocator::Purl(purl.into()), &net, &cache);
        for purl in [
            "pkg:npm/lodash@4.17.21?repository_url=https://evil.test",
            "pkg:npm/lodash@4.17.21?download_url=https://evil.test/x.tgz",
            "pkg:pypi/requests@2.31.0?repository_url=https://evil.test/simple",
            "pkg:cargo/serde@1.0.0?repository_url=https://evil.test",
            "pkg:gem/rails@7.0.0?repository_url=https://evil.test",
            "pkg:golang/github.com/a/b@v1.0.0?repository_url=https://evil.test",
        ] {
            assert_eq!(look(purl), Err(RegistryError::OffRegistry), "{purl}");
        }
        assert_ne!(
            look("pkg:npm/lodash@4.17.21?repository_url=https://registry.npmjs.org"),
            Err(RegistryError::OffRegistry),
            "the public registry named explicitly is still the public registry"
        );
    }

    #[test]
    fn a_foreign_vendor_never_borrows_the_official_record() {
        // No fixtures: each must be refused before any read.
        let (net, cache) = (Fixtures::default(), BlobCache::disabled());
        let look = |purl: &str| lookup(&RefLocator::Purl(purl.into()), &net, &cache);
        for purl in [
            "pkg:deb/attacker-ppa/curl",
            "pkg:rpm/evilrepo/openssl",
            "pkg:apk/evil/musl",
            "pkg:alpm/evil/pacman",
            "pkg:homebrew/evil-tap/wget",
            "pkg:snap/evil/firefox",
            "pkg:deb/debian/nested/curl",
        ] {
            assert_eq!(look(purl), Err(RegistryError::OffRegistry), "{purl}");
        }
        assert_eq!(
            look("pkg:jsr/%40%40%40std/path"),
            Err(RegistryError::NoRecord)
        );
    }

    #[test]
    fn a_cpan_author_namespace_must_be_the_releasing_author() {
        let doc = br#"{"distribution":"URI-PackageURL","author":"GDT","version":"2.0"}"#;
        let net = Fixtures::default().with(
            "https://fastapi.metacpan.org/v1/release/URI-PackageURL",
            doc,
        );
        let cache = BlobCache::disabled();
        let look = |purl: &str| lookup(&RefLocator::Purl(purl.into()), &net, &cache);
        assert_eq!(
            look("pkg:cpan/GDT/URI-PackageURL").map(|r| r.author),
            Ok(Some("GDT".to_string()))
        );
        assert_eq!(
            look("pkg:cpan/EVIL/URI-PackageURL"),
            Err(RegistryError::OffRegistry)
        );
        assert!(
            look("pkg:cpan/URI-PackageURL").is_ok(),
            "no namespace, no claim"
        );
    }

    #[test]
    fn alpm_namespace_routes_aur_vs_official() {
        // Both `pkg:alpm/aur/<name>` and the vendor-plus-qualifier spelling
        // `pkg:alpm/arch/<name>?repository_url=…aur.archlinux.org` → AUR RPC;
        // an official repository namespace → archlinux.org.
        let aur_rpc = serde_json::json!({
            "resultcount": 1,
            "results": [{"Name": "yay", "Version": "12.0.0-1", "Maintainer": "jverify",
                         "LastModified": 1_619_172_000u64, "OutOfDate": serde_json::Value::Null}]
        })
        .to_string();
        let arch_json = serde_json::json!({"results": [{
            "pkgname": "pacman", "repo": "core", "pkgver": "7.1.0", "pkgrel": "2", "packager": "eworm",
            "last_update": "2021-04-23T10:00:00Z"
        }]})
        .to_string();
        let net = Fixtures::default()
            .with(
                "https://aur.archlinux.org/rpc/v5/info?arg%5B%5D=yay",
                aur_rpc.as_bytes(),
            )
            .with(
                "https://archlinux.org/packages/search/json/?name=pacman",
                arch_json.as_bytes(),
            );
        let cache = BlobCache::disabled();
        let from_aur = lookup(&RefLocator::Purl("pkg:alpm/aur/yay".into()), &net, &cache)
            .expect("aur registry");
        assert_eq!(from_aur.ecosystem, Ecosystem::Aur);
        // Spec-compliant form: arch vendor in the namespace, AUR named in a
        // repository_url qualifier — still routes to the AUR RPC.
        let from_spec = lookup(
            &RefLocator::Purl("pkg:alpm/arch/yay?repository_url=https://aur.archlinux.org".into()),
            &net,
            &cache,
        )
        .expect("aur spec registry");
        assert_eq!(from_spec.ecosystem, Ecosystem::Aur);
        let from_official = lookup(
            &RefLocator::Purl("pkg:alpm/core/pacman".into()),
            &net,
            &cache,
        )
        .expect("arch registry");
        assert_eq!(from_official.ecosystem, Ecosystem::Arch);
    }

    /// A backend that records each URL asked for and refuses it: routing,
    /// observed without a network.
    #[derive(Default)]
    struct Recorder(std::sync::Mutex<Vec<String>>);

    impl Fetch for Recorder {
        fn send(
            &self,
            request: &crate::fetch::Request<'_>,
        ) -> Result<crate::fetch::Fetched, FetchError> {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(request.url.to_string());
            Err(FetchError::Refused("recorder".into()))
        }
    }

    /// The first URL a lookup of `purl` asks for.
    fn first_url(purl: &str) -> Option<String> {
        let net = Recorder::default();
        let _refused = lookup(&RefLocator::Purl(purl.into()), &net, &BlobCache::disabled());
        net.0
            .into_inner()
            .unwrap_or_else(PoisonError::into_inner)
            .into_iter()
            .next()
    }

    #[test]
    fn legacy_spellings_route_like_their_canonical_form() {
        let chrome = "pkg:chrome/aapbdbdomjkkjkaonfhkkikfgjllcleb";
        for (legacy, canonical) in [
            ("pkg:arch/pacman", "pkg:alpm/arch/pacman"),
            ("pkg:aur/yay", "pkg:alpm/aur/yay"),
            ("pkg:debian/curl", "pkg:deb/debian/curl"),
            ("pkg:ubuntu/curl", "pkg:deb/ubuntu/curl"),
            ("pkg:fedora/curl", "pkg:rpm/fedora/curl"),
            ("pkg:opensuse/curl", "pkg:rpm/opensuse/curl"),
            ("pkg:rpmfusion/ffmpeg", "pkg:rpm/rpmfusion/ffmpeg"),
            ("pkg:alpine/curl", "pkg:apk/alpine/curl"),
            ("pkg:wolfi/curl", "pkg:apk/wolfi/curl"),
            (
                chrome,
                "pkg:chrome-extension/aapbdbdomjkkjkaonfhkkikfgjllcleb",
            ),
            (
                "pkg:openvsx/redhat/java",
                "pkg:vscode-extension/redhat/java?repository_url=https://open-vsx.org",
            ),
            ("pkg:vscode/redhat/java", "pkg:vscode-extension/redhat/java"),
            ("pkg:homebrew/wget", "pkg:brew/wget"),
            ("pkg:docker/nginx", "pkg:oci/nginx"),
        ] {
            let routed = first_url(canonical);
            assert!(routed.is_some(), "{canonical} reaches a registry");
            assert_eq!(first_url(legacy), routed, "{legacy}");
        }
        assert!(
            first_url("pkg:vscode-extension/redhat/java?repository_url=https://open-vsx.org")
                .is_some_and(|url| url_host_is(&url, "open-vsx.org"))
        );
        assert!(
            first_url(
                "pkg:vscode-extension/redhat/java?repository_url=https://evil.test/open-vsx.org"
            )
            .is_none(),
            "a path naming the store is not the store"
        );
    }

    #[test]
    fn only_a_public_registry_host_is_public() {
        for (typ, url) in [
            ("npm", "https://registry.npmjs.org"),
            ("npm", "HTTPS://Registry.NPMJS.org/"),
            ("pypi", "https://pypi.org/simple"),
            ("cargo", "https://index.crates.io/"),
            ("cargo", "sparse+https://index.crates.io/"),
            ("cargo", "https://crates.io"),
            ("maven", "https://repo1.maven.org/maven2"),
            ("vscode-extension", "https://open-vsx.org"),
            ("oci", "docker.io/library/nginx"),
            ("docker", "quay.io/org/img"),
        ] {
            assert!(repository_is_public(typ, url), "{typ} {url}");
        }
        for (typ, url) in [
            ("npm", "https://evil.test"),
            ("npm", "https://evil.test/registry.npmjs.org"),
            ("npm", "https://registry.npmjs.org.evil.test"),
            ("npm", "registry.npmjs.org"),
            ("npm", "ftp://registry.npmjs.org"),
            ("cargo", "sparse+https://evil.test/index.crates.io"),
            ("pypi", "https://registry.npmjs.org"),
            ("nuget", "https://evil.test/v3/index.json"),
            ("composer", "https://evil.test"),
            ("deb", "https://deb.debian.org/debian"),
            ("snap", "https://snapcraft.io"),
            ("swift", "https://github.com"),
            ("oci", "ghcr.io/owner/img"),
            ("oci", "https://docker.io/library/nginx"),
        ] {
            assert!(!repository_is_public(typ, url), "{typ} {url}");
        }
    }

    #[test]
    fn any_foreign_repository_is_off_registry() {
        // Every type denies a repository it does not recognize.
        let (net, cache) = (Fixtures::default(), BlobCache::disabled());
        for purl in [
            "pkg:maven/org.example/lib@1.0?repository_url=https://evil.test/maven2",
            "pkg:nuget/Newtonsoft.Json@13.0.1?repository_url=https://evil.test/v3/index.json",
            "pkg:composer/acme/lib@1.0?repository_url=https://evil.test",
            "pkg:vscode-extension/redhat/java?repository_url=https://evil.test",
            "pkg:hex/plug@1.0?repository_url=https://evil.test",
            "pkg:snap/firefox?repository_url=https://evil.test",
            "pkg:alpm/arch/pacman?repository_url=https://evil.test/aur.archlinux.org",
        ] {
            assert_eq!(
                lookup(&RefLocator::Purl(purl.into()), &net, &cache),
                Err(RegistryError::OffRegistry),
                "{purl}"
            );
        }
    }

    #[test]
    fn recorded_sources_survive_and_are_ordered() {
        let doc = br#"{"Version":"v1.0.0","Time":"2024-01-01T00:00:00Z"}"#;
        let url = "https://proxy.golang.org/example.com/m/@latest";
        let net = Fixtures::default().with(url, doc);
        let (record, sources) = lookup_recorded(
            &RefLocator::Purl("pkg:golang/example.com/m".into()),
            &net,
            &BlobCache::disabled(),
        );
        assert_eq!(record.map(|r| r.version), Ok("v1.0.0".to_string()));
        assert_eq!(sources.first().map(|s| s.url.as_str()), Some(url));
        let (record, sources) = lookup_recorded(
            &RefLocator::Url("https://example.test/x".into()),
            &net,
            &BlobCache::disabled(),
        );
        assert_eq!(record, Err(RegistryError::NotAPackage));
        assert!(sources.is_empty());
    }
}
