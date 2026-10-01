//! Look up and normalize a package's registry metadata.
//!
//! [`fetch`](crate::fetch) retrieves the *artifact*; this module retrieves the
//! registry's *metadata about* the artifact — publish date, author, downloads,
//! rating, deprecation — and reduces every ecosystem's bespoke JSON to one
//! common [`filefacts::Registry`] shape (which filefacts can re-parse from a
//! serialized `*.registry.json` document into trait-matchable facts). A consumer
//! (scan) then applies uniform policy — age gating, reputation heuristics —
//! without knowing whether the source was npm, PyPI, crates.io, Packagist, or
//! the AUR.
//!
//! The lookup is small (a JSON document, not a tarball) and cached, so it is the
//! cheap thing to do *first*: learn a dependency's age before deciding whether
//! the expensive fetch-and-scan of its bytes is worth it.

use crate::distro;
use crate::ecosystem::arch::{arch, aur};
use crate::ecosystem::cargo::crates;
use crate::ecosystem::chrome::chrome;
use crate::ecosystem::clawhub::clawhub;
use crate::ecosystem::clojars::clojars;
use crate::ecosystem::comfyui::comfyui;
use crate::ecosystem::composer::composer;
use crate::ecosystem::conda::conda;
use crate::ecosystem::container::oci_meta;
use crate::ecosystem::cpan::cpan;
use crate::ecosystem::cran::cran;
use crate::ecosystem::dify::dify;
use crate::ecosystem::fedora::fedora;
use crate::ecosystem::firefox::firefox;
use crate::ecosystem::gem::gem;
use crate::ecosystem::github::github;
use crate::ecosystem::golang::golang;
use crate::ecosystem::hex::hex_pm;
use crate::ecosystem::homebrew::homebrew;
use crate::ecosystem::huggingface::huggingface;
use crate::ecosystem::jetbrains::jetbrains;
use crate::ecosystem::jsr::jsr;
use crate::ecosystem::last_seg;
use crate::ecosystem::maven::maven;
use crate::ecosystem::npm::npm;
use crate::ecosystem::nuget::nuget;
use crate::ecosystem::pub_dev::pub_dev;
use crate::ecosystem::pypi::pypi;
use crate::ecosystem::snap::snap;
use crate::ecosystem::terraform::terraform;
use crate::ecosystem::vscode::{openvsx, vscode};
use crate::ecosystem::wordpress::wordpress;
use crate::fetch::{BlobCache, Fetch, RecordedSource, safe_coordinate};

use crate::fetch::FetchError;
use crate::purl::{Purl, PurlError};
use filefacts::{RefLocator, Registry};

/// Why a registry lookup produced no record.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
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
/// Dispatches on the PURL ecosystem, fetches the metadata document through the
/// blob cache (one round-trip per package per cache window, free on a hit), and
/// maps it to [`Registry`]. The returned record leaves [`Registry::age_days`]
/// unset; the caller stamps it with [`Registry::with_age`] from its own clock.
/// The error says why there is no record, so the caller can decide what an
/// absent answer means (scan fails open and fetches).
pub fn try_registry(
    locator: &RefLocator,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let started = std::time::Instant::now();
    let result = look_up(locator, net, cache);
    let named = match locator {
        RefLocator::Purl(s) | RefLocator::Url(s) | RefLocator::Path(s) => s,
    };
    crate::metrics::registry(named, &result, started.elapsed());
    result
}

/// [`try_registry`]'s work.
fn look_up(
    locator: &RefLocator,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let RefLocator::Purl(raw) = locator else {
        return Err(RegistryError::NotAPackage);
    };
    let purl = Purl::parse(raw)?;
    let (path, version) = (purl.encoded_path(), purl.encoded_version());
    // Every backend `format!`s these into a registry endpoint, so vet them
    // once here — see [`crate::fetch::safe_coordinate`].
    if !safe_coordinate(&path) || version.as_deref().is_some_and(|v| !safe_coordinate(v)) {
        return Err(RegistryError::UnsafeCoordinate);
    }
    let version = version.as_deref();
    // Package documents are mutable, but what they say about a published
    // version is not (see the metadata TTL notes in `fetch`), so a versioned
    // lookup trusts its cached copy for months while a versionless one,
    // tracking a moving `latest`, revalidates hourly. Selected here, the one
    // place that knows the PURL's version-ness, and carried on the cache
    // rather than threaded through every ecosystem fn.
    let ttl = if version.is_some() {
        cache.meta_ttl_pinned()
    } else {
        cache.meta_ttl_unpinned()
    };
    let (first, staged) = cache.with_meta_ttl(ttl).staged();
    let record = lookup(&purl, &path, version, net, &first);
    // The one fact a months-old copy can't hold is a version published after
    // it was cached. In an ecosystem whose package document dates every
    // version it lists, an undated pinned record means the copy didn't list
    // it, so re-read the document under the versionless TTL before concluding
    // so. A hijacked account's new release is exactly this case, and its
    // publish time, publisher and install hooks are what would flag it.
    if version.is_some()
        && DATES_EVERY_VERSION.contains(&purl.typ())
        && record.as_ref().is_ok_and(|r| r.published_at.is_none())
    {
        let fresh = cache.with_meta_ttl(cache.meta_ttl_unpinned());
        return lookup(&purl, &path, version, net, &fresh);
    }
    cache.commit(staged);
    record
}

/// [`try_registry`], for a caller that only needs the record.
#[must_use]
pub fn registry(locator: &RefLocator, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    try_registry(locator, net, cache).ok()
}

/// Ecosystems whose package document carries a publish time for every version
/// it lists — so a requested version with none is one the document lacks.
const DATES_EVERY_VERSION: &[&str] = &[
    "npm", "cargo", "pypi", "composer", "gem", "hex", "pub", "conda", "jsr", "cran",
];

/// One registry lookup: dispatch on the PURL type to its backend.
fn lookup(
    purl: &Purl,
    path: &str,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let repository_url = purl.qualifier("repository_url");
    match purl.typ() {
        "npm" => npm(path, version, net, cache),
        "cargo" => crates(path, version, net, cache),
        "pypi" => pypi(path, version, net, cache),
        "composer" => composer(path, version, net, cache),
        "gem" => gem(path, version, net, cache),
        "golang" => golang(path, version, net, cache),
        // A `pkg:github/<owner>/<repo>` source: the repo *is* the upstream. Its
        // metadata is the closest thing to a registry record.
        "github" => github(path, net, cache),
        // Language registries with a clean JSON API: one GET mapped onto the
        // common shape.
        "nuget" => nuget(path, version, net, cache),
        "maven" => maven(path, version, net, cache),
        // Hugging Face model repos: `owner/model` (or a canonical bare `model`),
        // the attacker-reachable half of the ML supply chain forager mirrors.
        "huggingface" => huggingface(path, version, net, cache),
        "hex" => hex_pm(path, version, net, cache),
        "cran" => cran(last_seg(path), version, net, cache),
        "cpan" => cpan(last_seg(path), net, cache),
        "pub" => pub_dev(last_seg(path), version, net, cache),
        "conda" => conda(last_seg(path), version, net, cache),
        "clojars" => clojars(path, net, cache),
        // JSR ships through npm-compatible mirrors, but its own API carries the
        // richer record (score, repo, per-version dates).
        "jsr" => jsr(path, version, net, cache),
        // Terraform providers: `pkg:terraform/<namespace>/<type>` on
        // registry.terraform.io, whose addresses the PURL already lowercases.
        "terraform" => terraform(path, version, net, cache),
        // OS package registries each get their own PURL type so a scan can name
        // `pkg:fedora/curl` vs `pkg:arch/pacman` directly. The package name is
        // the last path segment (any vendor namespace is dropped).
        "arch" => arch(last_seg(path), net, cache),
        "fedora" => fedora(last_seg(path), net, cache),
        // The AUR is the user-contributed, attacker-reachable half of Arch. Three
        // spellings reach it: the bare `pkg:aur/<name>` legacy type; the
        // spec-compliant `pkg:alpm/arch/<name>?repository_url=https://aur.archlinux.org`,
        // which keeps the `arch` vendor in the namespace (where the spec puts the
        // vendor) and names the AUR in a qualifier; and the older `pkg:alpm/aur/<name>`,
        // which put `aur` in the namespace slot. All route to the AUR RPC; any other
        // alpm namespace is an official repo. Normalization folds the spec form
        // into the `aur` namespace; a repository URL it doesn't fold is read
        // from the qualifier.
        "aur" => aur(last_seg(path), net, cache),
        "alpm" if repository_url.is_some_and(|url| url.contains("aur.archlinux.org")) => {
            aur(last_seg(path), net, cache)
        }
        "alpm" => match path.split_once('/') {
            Some(("aur", name)) => aur(name, net, cache),
            Some((_, name)) => arch(name, net, cache),
            None => arch(path, net, cache),
        },
        // Distro registries with no JSON API: each metadata lookup fetches a
        // compressed index/catalog and scans it. See [`crate::distro`].
        "alpine" => distro::alpine(last_seg(path), net, cache),
        "wolfi" => distro::wolfi(last_seg(path), net, cache),
        "debian" => distro::debian(last_seg(path), net, cache),
        "ubuntu" => distro::ubuntu(last_seg(path), net, cache),
        "opensuse" => distro::opensuse(last_seg(path), net, cache),
        "rpmfusion" => distro::rpmfusion(last_seg(path), net, cache),
        "netbsd" => distro::netbsd(last_seg(path), net, cache),
        "freebsd" => distro::freebsd(last_seg(path), net, cache),
        "openbsd" => distro::openbsd(last_seg(path), net, cache),
        // Package managers and app stores.
        "homebrew" => homebrew(last_seg(path), net, cache),
        "snap" => snap(last_seg(path), net, cache),
        "wordpress" => wordpress(last_seg(path), net, cache),
        // Agent-skill registry: `pkg:clawhub/[owner/]slug`.
        "clawhub" => clawhub(path, net, cache),
        // Plugin registries of ML apps: a ComfyUI custom node
        // (`pkg:comfyui/<node_id>`) and a Dify Marketplace plugin
        // (`pkg:dify/<org>/<name>`).
        "comfyui" => comfyui(path, version, net, cache),
        "dify" => dify(path, version, net, cache),
        // Container images: `pkg:oci/<name>?repository_url=<host%2Fpath>`,
        // the ratified registry-agnostic type (`pkg:docker` is its legacy
        // spelling — same repositories, so it routes identically). The
        // registry host picks the metadata API.
        "oci" | "docker" => oci_meta(repository_url, path, net, cache),
        // Browser-extension / plugin marketplaces — the same listing shape as
        // the Chrome and VS Code stores (rating, downloads, recency).
        "firefox" => firefox(last_seg(path), net, cache),
        "jetbrains" => jetbrains(last_seg(path), net, cache),
        // Browser extensions: `pkg:chrome/<extension-id>`. The store's risk
        // signals (reach, rating, recency, the developer's own description of
        // what it harvests) live on the listing, not in a manifest.
        // `chrome-extension` is the ratified purl-spec spelling of the same type.
        "chrome" | "chrome-extension" => chrome(last_seg(path), net, cache),
        // VS Code / editor extensions: `pkg:openvsx/<namespace>/<name>`. Open
        // VSX exposes a clean JSON API, so no scraping — the same marketplace
        // shape (rating, downloads, publisher, recency) as the Chrome store.
        // `vscode-extension` is the ratified type and covers both stores; Open
        // VSX is flagged by the `repository_url` qualifier. The parsed PURL is
        // normalized, so a legacy `pkg:openvsx/<pub>/<ext>` (which carries the
        // store in its type) arrives here with that qualifier too.
        "openvsx" => openvsx(path, version, net, cache),
        "vscode-extension" if repository_url.is_some_and(|url| url.contains("open-vsx.org")) => {
            openvsx(path, version, net, cache)
        }
        // The Microsoft VS Code Marketplace: `pkg:vscode/<publisher>/<name>`.
        // Its data lives behind a JSON-RPC `POST` query — same marketplace shape
        // as Open VSX, just a different transport.
        "vscode" | "vscode-extension" => vscode(path, net, cache),
        // Spec-form aliases (purl-spec / common practice) for the same registries,
        // so a PURL generated per spec fetches identically to our legacy spelling.
        // The OS types carry the distro in the namespace (`pkg:deb/debian/curl`).
        "deb" => match path.split_once('/') {
            Some(("ubuntu", name)) => distro::ubuntu(last_seg(name), net, cache),
            Some((_, name)) => distro::debian(last_seg(name), net, cache),
            None => distro::debian(path, net, cache),
        },
        "rpm" => match path.split_once('/') {
            Some(("opensuse", name)) => distro::opensuse(last_seg(name), net, cache),
            Some(("rpmfusion", name)) => distro::rpmfusion(last_seg(name), net, cache),
            Some((_, name)) => fedora(last_seg(name), net, cache),
            None => fedora(path, net, cache),
        },
        "apk" => match path.split_once('/') {
            Some(("wolfi", name)) => distro::wolfi(last_seg(name), net, cache),
            Some((_, name)) => distro::alpine(last_seg(name), net, cache),
            None => distro::alpine(path, net, cache),
        },
        other => Err(RegistryError::Unsupported(other.to_string())),
    }
}

/// Like [`try_registry`], but also returns the raw provider documents the
/// lookup consumed: the `(url, bytes)` of every metadata response it read, from
/// the warm cache or a fresh fetch. A consumer that archives provenance (scan's
/// `--upload`) keeps these as the re-parsing backup beside the normalized
/// record, without re-deriving which endpoints an ecosystem needs. On an error
/// `sources` is whatever was read before the lookup gave up (often empty).
/// Order matches read order — the primary registry document first.
pub fn try_registry_with_sources(
    locator: &RefLocator,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> (Result<Registry, RegistryError>, Vec<RecordedSource>) {
    let (recording, sink) = cache.recording();
    let record = try_registry(locator, net, &recording);
    let sources = sink
        .lock()
        .map(|mut s| std::mem::take(&mut *s))
        .unwrap_or_default();
    (record, sources)
}

/// [`try_registry_with_sources`], for a caller that only needs the record.
#[must_use]
pub fn registry_with_sources(
    locator: &RefLocator,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> (Option<Registry>, Vec<RecordedSource>) {
    let (record, sources) = try_registry_with_sources(locator, net, cache);
    (record.ok(), sources)
}

/// Split a PURL into `(type, name-path, version?)`: the normalized type and
/// the percent-encoded coordinates (a scope is `%40`) the registry lookup keys
/// on. Public so a consumer (the CLI's `purl` probe, cross-tool consistency
/// checks against hopper's generator) can see exactly those coordinates.
#[must_use]
pub fn parse_purl(purl: &str) -> Option<(String, String, Option<String>)> {
    let purl = Purl::parse(purl).ok()?;
    Some((
        purl.typ().to_string(),
        purl.encoded_path(),
        purl.encoded_version(),
    ))
}

// --- HTML scraping helpers --------------------------------------------------

// --- JSON shaping helpers ---------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::test_cache;

    use crate::fetch::{BlobCache, Fixtures};

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
    fn unsupported_locator_is_none() {
        let net = Fixtures::default();
        let cache = BlobCache::disabled();
        assert!(
            registry(
                &RefLocator::Url("https://x.test/a.tgz".into()),
                &net,
                &cache
            )
            .is_none()
        );
        assert!(
            registry(
                &RefLocator::Purl("pkg:gem/rails@7.0.0".into()),
                &net,
                &cache
            )
            .is_none()
        );
    }

    #[test]
    fn a_lookup_says_why_it_has_no_record() {
        let url = "https://pypi.org/pypi/w/json";
        let lookup = |net: &Fixtures, raw: &str| {
            try_registry(&RefLocator::Purl(raw.into()), net, &test_cache("why")).err()
        };
        let none = Fixtures::default();
        assert_eq!(
            try_registry(
                &RefLocator::Url("https://example.test/x".into()),
                &none,
                &test_cache("why")
            )
            .err(),
            Some(RegistryError::NotAPackage)
        );
        assert_eq!(
            lookup(&none, "not a purl"),
            Some(RegistryError::InvalidPurl(PurlError::Syntax))
        );
        assert_eq!(
            lookup(&none, "pkg:pypi/w@..%2F..%2Fx"),
            Some(RegistryError::UnsafeCoordinate)
        );
        assert_eq!(
            lookup(&none, "pkg:swift/github.com/apple/swift-nio@1.0.0"),
            Some(RegistryError::Unsupported("swift".into()))
        );
        // What the registry said, or failed to say.
        assert_eq!(
            lookup(&Fixtures::default().refusing(url, 404), "pkg:pypi/w"),
            Some(RegistryError::NotFound)
        );
        assert_eq!(
            lookup(&Fixtures::default().refusing(url, 503), "pkg:pypi/w"),
            Some(RegistryError::Unavailable(FetchError::Status(503)))
        );
        assert!(matches!(
            lookup(&none, "pkg:pypi/w"),
            Some(RegistryError::Unavailable(FetchError::Transport(_)))
        ));
        assert_eq!(
            lookup(&Fixtures::default().with(url, b"{}"), "pkg:pypi/w"),
            Some(RegistryError::NoRecord)
        );
    }

    #[test]
    fn a_subpath_does_not_hide_the_package_from_its_registry() {
        // A Go module addressed with a subpath is still that module. The old
        // splitter left `#…` in the coordinate, which the URL vetting then
        // refused, so no lookup happened at all.
        let doc = br#"{"Version":"v0.0.0-20240101","Time":"2024-01-01T00:00:00Z"}"#;
        let net = Fixtures::default().with(
            "https://proxy.golang.org/google.golang.org/genproto/@latest",
            doc,
        );
        let locator =
            RefLocator::Purl("pkg:golang/google.golang.org/genproto#googleapis/api".into());
        let record = registry(&locator, &net, &test_cache("go-subpath")).expect("record");
        assert_eq!(record.version, "v0.0.0-20240101");
    }

    #[test]
    fn only_the_repository_qualifier_routes_alpm_to_the_aur() {
        // Both stores answer for `pacman`; which one the lookup asks decides
        // the record. A qualifier that merely mentions the AUR host is not a
        // route there, so an official package goes to the official repository.
        let arch = br#"{"results":[{"pkgname":"pacman","pkgver":"7.1.0","pkgrel":"2"}]}"#;
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
            registry(&RefLocator::Purl(purl.into()), &net, &test_cache("alpm")).map(|r| r.ecosystem)
        };
        assert_eq!(
            lookup("pkg:alpm/core/pacman?foo=aur.archlinux.org").as_deref(),
            Some("arch")
        );
        assert_eq!(
            lookup("pkg:alpm/arch/pacman?repository_url=https://aur.archlinux.org").as_deref(),
            Some("aur")
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
        let r = registry(&locator, &net, &test_cache("oci-ns")).expect("registry");
        assert_eq!(r.author.as_deref(), Some("myorg"));
        assert_eq!(r.downloads_total, Some(3));
        // A bare name is still the official image.
        assert_eq!(
            crate::ecosystem::container::oci_repository("nginx", None),
            "docker.io/library/nginx"
        );
    }

    #[test]
    fn an_unlisted_version_is_undated_in_every_backend() {
        // Each registry knows the package and its latest release, but not
        // version 9.9.9. Every backend used to date it from something else: the
        // newest release, or the package's own creation.
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
        ];
        let net = docs
            .iter()
            .fold(Fixtures::default(), |net, (url, doc)| {
                net.with(url, doc.to_string().as_bytes())
            })
            .refusing("https://api.jsr.io/scopes/s/packages/j/versions/9.9.9", 404);
        let cache = test_cache("unlisted");
        let first_release = Some(1_420_070_400); // 2015-01-01

        let records = [
            "pkg:cargo/c",
            "pkg:gem/g",
            "pkg:hex/h",
            "pkg:pub/p",
            "pkg:conda/k",
            "pkg:jsr/%40s/j",
        ]
        .map(|purl| registry(&RefLocator::Purl(format!("{purl}@9.9.9")), &net, &cache));
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
        // newest pre-release beside it; that `null` used to blank the version.
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
        let cache = test_cache("prerelease");
        let version = |purl: &str| {
            registry(&RefLocator::Purl(purl.into()), &net, &cache)
                .expect("the package resolves")
                .version
        };
        assert_eq!(version("pkg:cargo/c"), "0.1.0-rc.1");
        assert_eq!(version("pkg:hex/h"), "0.1.0-rc.1");
        assert_eq!(version("pkg:clojars/k"), "0.1.0-SNAPSHOT");
    }

    #[test]
    fn huggingface_model_normalizes() {
        // No version in the locator → the record carries the current commit sha;
        // `downloads` maps to the 30-day recent count and `likes` to rating_count.
        let doc = serde_json::json!({
            "id": "microsoft/resnet-50", "author": "microsoft", "sha": "abc123def",
            "createdAt": "2022-03-16T10:00:00.000Z", "lastModified": "2023-04-23T10:00:00.000Z",
            "downloads": 1_234_567u64, "likes": 89u64, "license": "apache-2.0"
        })
        .to_string();
        let net = Fixtures::default().with(
            "https://huggingface.co/api/models/microsoft/resnet-50",
            doc.as_bytes(),
        );
        let r = registry(
            &RefLocator::Purl("pkg:huggingface/microsoft/resnet-50".into()),
            &net,
            &test_cache("huggingface"),
        )
        .expect("huggingface registry");
        assert_eq!(r.ecosystem, "huggingface");
        assert_eq!(r.name, "microsoft/resnet-50");
        assert_eq!(r.version, "abc123def");
        assert_eq!(r.author.as_deref(), Some("microsoft"));
        assert_eq!(r.license.as_deref(), Some("apache-2.0"));
        assert_eq!(r.downloads_recent, Some(1_234_567));
        assert_eq!(r.rating_count, Some(89));
        assert_eq!(r.first_published_at, Some(1_647_424_800)); // createdAt
    }

    #[test]
    fn alpm_namespace_routes_aur_vs_official() {
        // Both the legacy `pkg:alpm/aur/<name>` and the spec-compliant
        // `pkg:alpm/arch/<name>?repository_url=…aur.archlinux.org` → AUR RPC; any
        // other namespace → official repos.
        let aur_rpc = serde_json::json!({
            "resultcount": 1,
            "results": [{"Name": "yay", "Version": "12.0.0-1", "Maintainer": "jverify",
                         "LastModified": 1_619_172_000u64, "OutOfDate": serde_json::Value::Null}]
        })
        .to_string();
        let arch_json = serde_json::json!({"results": [{
            "pkgname": "pacman", "pkgver": "7.1.0", "pkgrel": "2", "packager": "eworm",
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
        let cache = test_cache("alpm");
        let from_aur = registry(&RefLocator::Purl("pkg:alpm/aur/yay".into()), &net, &cache)
            .expect("aur registry");
        assert_eq!(from_aur.ecosystem, "aur");
        // Spec-compliant form: arch vendor in the namespace, AUR named in a
        // repository_url qualifier — still routes to the AUR RPC.
        let from_spec = registry(
            &RefLocator::Purl("pkg:alpm/arch/yay?repository_url=https://aur.archlinux.org".into()),
            &net,
            &cache,
        )
        .expect("aur spec registry");
        assert_eq!(from_spec.ecosystem, "aur");
        let from_official = registry(
            &RefLocator::Purl("pkg:alpm/core/pacman".into()),
            &net,
            &cache,
        )
        .expect("arch registry");
        assert_eq!(from_official.ecosystem, "arch");
    }

    #[test]
    fn parse_purl_tolerates_misplaced_version() {
        // Spec order: `@version` before `?qualifiers`.
        assert_eq!(
            parse_purl("pkg:alpm/arch/yay@1.0-1?repository_url=https://aur.archlinux.org"),
            Some(("alpm".into(), "aur/yay".into(), Some("1.0-1".into())))
        );
        // The non-spec `?qualifiers@version` ordering older hopper exports
        // emitted: the trailing version is still recovered.
        assert_eq!(
            parse_purl("pkg:alpm/arch/yay?repository_url=https://aur.archlinux.org@1.0-1"),
            Some(("alpm".into(), "aur/yay".into(), Some("1.0-1".into())))
        );
        // A qualifier value containing `@` (URL userinfo) is not a version.
        assert_eq!(
            parse_purl("pkg:alpm/arch/yay?repository_url=https://user@example.com/repo"),
            Some(("alpm".into(), "arch/yay".into(), None))
        );
    }

    #[test]
    fn parse_purl_canonicalizes_a_versionless_literal_npm_scope() {
        assert_eq!(
            parse_purl("pkg:npm/@scope/name"),
            Some(("npm".into(), "%40scope/name".into(), None))
        );
    }

    #[test]
    fn registry_parser_rejects_type_prohibited_namespaces() {
        for invalid in [
            "pkg:pypi/namespace/name@1",
            "pkg:gem/namespace/name@1",
            "pkg:cargo/namespace/name@1",
        ] {
            assert_eq!(parse_purl(invalid), None, "{invalid}");
        }
    }
}
