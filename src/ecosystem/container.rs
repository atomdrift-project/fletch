//! Container images (Docker Hub, Quay, and OCI references): registry metadata
//! and artifact resolution.

use filefacts::{Ecosystem, Registry};
use serde::Deserialize;

use crate::ecosystem::{
    Coordinates, fetch_json, last_seg, non_empty, null_default, optional, unix_secs,
};
use crate::fetch::{BlobCache, Fetch, safe_coordinate};
use crate::purl::Purl;
use crate::registry::RegistryError;

/// Resolve a `pkg:oci` (or `pkg:docker`) purl to the `oci://` pseudo-URL the
/// OCI puller consumes: `oci://<repo>[@sha256:…|:tag]`, the repository as
/// [`oci_repository`] names it. A `sha256:…` version is the content-addressed
/// digest and wins over any mutable `tag` qualifier; a `pkg:docker` version
/// slot may carry a plain tag; with neither, `latest`.
///
/// `None` for a repository off the reference grammar, which names nothing
/// the puller may contact.
pub(crate) fn resolve_oci_ref(purl: &Purl) -> Option<String> {
    let repo = oci_repository(&purl.encoded_path(), purl.qualifier("repository_url")).ok()?;
    let version = purl.encoded_version();
    Some(match (version.as_deref(), purl.qualifier("tag")) {
        (Some(d), _) if d.starts_with("sha256:") => format!("oci://{repo}@{d}"),
        (Some(t), _) | (None, Some(t)) => format!("oci://{repo}:{t}"),
        (None, None) => format!("oci://{repo}:latest"),
    })
}

/// The registry-qualified repository a `pkg:oci`/`pkg:docker` name denotes:
/// its decoded `repository_url` qualifier when present, otherwise Docker
/// Hub's implied coordinates. A host-less name lives on Docker Hub, and only
/// a single-segment one under `library/` — `myorg/nginx` is
/// `docker.io/myorg/nginx`, not the official `library/nginx`. Shared by the
/// fetcher and the registry lookup so the bytes and the reputation always
/// describe the same repository.
///
/// The result always satisfies the OCI reference grammar
/// ([`split_reference`]); anything else is
/// [`RegistryError::UnsafeCoordinate`], so no registry URL is ever built
/// from it.
pub(crate) fn oci_repository(
    name: &str,
    repository_url: Option<&str>,
) -> Result<String, RegistryError> {
    let repo = match repository_url.filter(|u| !u.is_empty()) {
        Some(url) => url.to_string(),
        None => match name.split_once('/') {
            Some((first, _)) if first.contains(['.', ':']) => name.to_string(),
            Some(_) => format!("docker.io/{name}"),
            None => format!("docker.io/library/{name}"),
        },
    };
    if split_reference(&repo).is_none() {
        tracing::debug!(
            repository = %repo.escape_debug(),
            "container reference refused: not a registry-qualified OCI repository"
        );
        return Err(RegistryError::UnsafeCoordinate);
    }
    Ok(repo)
}

/// Whether an OCI `repository_url` names a valid repository on Docker Hub or
/// Quay, the registries whose metadata fletch reads.
pub(crate) fn public_repository(repository: &str) -> bool {
    split_reference(repository).is_some_and(|(host, _)| MetadataApi::of(host).is_some())
}

/// `host/path` split at its first `/` when both halves keep the OCI
/// distribution reference grammar: the host dot-separated
/// `[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?` labels with an optional `:port`,
/// and the path `/`-separated `[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*`
/// components, each also a [`safe_coordinate`]. Nothing that passes can
/// restructure a URL it is spliced into.
fn split_reference(reference: &str) -> Option<(&str, &str)> {
    let (host, path) = reference.split_once('/')?;
    (valid_host(host)
        && path
            .split('/')
            .all(|component| valid_component(component) && safe_coordinate(component)))
    .then_some((host, path))
}

/// A registry host: DNS labels, optionally followed by a decimal `:port`.
fn valid_host(host: &str) -> bool {
    let (name, port) = match host.split_once(':') {
        Some((name, port)) => (name, Some(port)),
        None => (host, None),
    };
    let label = |l: &str| {
        !l.is_empty()
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    };
    name.split('.').all(label)
        && port.is_none_or(|p| p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u16>().is_ok())
}

/// A repository path component: lowercase alphanumeric runs joined by one
/// `.`, one `_`, `__`, or a run of `-`.
fn valid_component(component: &str) -> bool {
    let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let bytes = component.as_bytes();
    let (Some(&first), Some(&last)) = (bytes.first(), bytes.last()) else {
        return false;
    };
    alnum(first)
        && alnum(last)
        && component
            .split(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
            .all(|sep| matches!(sep, "" | "." | "_" | "__") || sep.bytes().all(|b| b == b'-'))
}

/// The anonymous metadata API a registry host offers, if any.
enum MetadataApi {
    DockerHub,
    Quay,
}

impl MetadataApi {
    /// Docker Hub under each of its host spellings, or Quay. Host names are
    /// case-insensitive.
    fn of(host: &str) -> Option<Self> {
        let is = |name: &str| host.eq_ignore_ascii_case(name);
        if ["docker.io", "index.docker.io", "registry-1.docker.io"]
            .into_iter()
            .any(is)
        {
            Some(Self::DockerHub)
        } else if is("quay.io") {
            Some(Self::Quay)
        } else {
            None
        }
    }
}

/// Container-image metadata for the repository [`oci_repository`] names; its
/// host picks the metadata API. Docker Hub and Quay expose anonymous
/// repository JSON; any other registry (ghcr.io needs a token dance for a thin
/// manifest) has none fletch reads, so it is [`RegistryError::OffRegistry`].
///
/// Both APIs describe the repository, not a release: a requested digest or tag
/// is the record's version, and the repository's last push does not date it.
pub(crate) fn lookup(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let repo = oci_repository(c.path(), c.purl().qualifier("repository_url"))?;
    let (host, image) = split_reference(&repo).ok_or(RegistryError::UnsafeCoordinate)?;
    let mut record = match MetadataApi::of(host) {
        Some(MetadataApi::DockerHub) => docker_hub(image, net, cache)?,
        Some(MetadataApi::Quay) => quay(image, c.version().is_none(), net, cache)?,
        None => {
            tracing::debug!(
                host = %host.escape_debug(),
                "registry lookup refused: no anonymous metadata API for this container registry"
            );
            return Err(RegistryError::OffRegistry);
        }
    };
    if let Some(version) = c.version() {
        record.version = version.to_string();
        record.published_at = None;
    }
    Ok(record)
}

/// Docker Hub repository metadata: anonymous JSON with pulls, the publishing
/// namespace, and registration/update times.
fn docker_hub(image: &str, net: &dyn Fetch, cache: &BlobCache) -> Result<Registry, RegistryError> {
    let doc: HubRepository = fetch_json(
        &format!("https://hub.docker.com/v2/repositories/{image}"),
        net,
        cache,
    )?;
    let mut registry = Registry::new(
        Ecosystem::Oci,
        doc.name.unwrap_or_else(|| last_seg(image).to_string()),
    );
    registry.published_at = doc.last_updated.as_deref().and_then(unix_secs);
    registry.first_published_at = doc.date_registered.as_deref().and_then(unix_secs);
    registry.author = doc.namespace.or(doc.user);
    registry.description = doc.description;
    registry.downloads_total = doc.pull_count;
    registry.favorites = doc.star_count;
    Ok(registry)
}

/// The parts of a Docker Hub repository document the registry record reads.
#[derive(Default, Deserialize)]
#[serde(default)]
struct HubRepository {
    #[serde(deserialize_with = "non_empty")]
    name: Option<String>,
    last_updated: Option<String>,
    date_registered: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    namespace: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    user: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    description: Option<String>,
    pull_count: Option<u64>,
    star_count: Option<u64>,
}

/// Quay repository metadata: anonymous JSON with the description, the owning
/// namespace, and (asked for with `includeStats`) the last ~90 days of daily
/// pulls. The repository document carries no time; when `dated`, its newest
/// active tag — tags list newest first — says when it was last pushed.
fn quay(
    image: &str,
    dated: bool,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let doc: QuayRepository = fetch_json(
        &format!("https://quay.io/api/v1/repository/{image}?includeStats=true"),
        net,
        cache,
    )?;
    let last_push = if dated {
        let url =
            format!("https://quay.io/api/v1/repository/{image}/tag/?limit=1&onlyActiveTags=true");
        optional(fetch_json::<QuayTags>(&url, net, cache), &url)
            .and_then(|t| t.tags.into_iter().next()?.start_ts)
    } else {
        None
    };
    let mut registry = Registry::new(
        Ecosystem::Oci,
        doc.name.unwrap_or_else(|| last_seg(image).to_string()),
    );
    registry.published_at = last_push;
    registry.author = doc.namespace;
    registry.description = doc.description;
    registry.downloads_recent = doc
        .stats
        .map(|days| days.iter().filter_map(|d| d.count).sum());
    Ok(registry)
}

/// The parts of a Quay repository document the registry record reads.
#[derive(Default, Deserialize)]
#[serde(default)]
struct QuayRepository {
    #[serde(deserialize_with = "non_empty")]
    name: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    namespace: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    description: Option<String>,
    stats: Option<Vec<QuayDay>>,
}

/// One day of a Quay repository's pull counts.
#[derive(Default, Deserialize)]
#[serde(default)]
struct QuayDay {
    count: Option<u64>,
}

/// A page of a Quay repository's tags.
#[derive(Default, Deserialize)]
#[serde(default)]
struct QuayTags {
    #[serde(deserialize_with = "null_default")]
    tags: Vec<QuayTag>,
}

/// One tag: when it started pointing at its manifest, in Unix seconds.
#[derive(Default, Deserialize)]
#[serde(default)]
struct QuayTag {
    start_ts: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use filefacts::RefLocator;

    use crate::fetch::Fixtures;

    fn look(purl: &str, net: &Fixtures) -> Result<Registry, RegistryError> {
        crate::registry::lookup(&RefLocator::Purl(purl.into()), net, &BlobCache::disabled())
    }

    #[test]
    fn oci_docker_hub_normalizes() {
        let doc = serde_json::json!({
            "name": "nginx", "namespace": "library",
            "description": "Official build of Nginx.",
            "star_count": 20_000u64, "pull_count": 1_000_000_000u64,
            "last_updated": "2026-06-01T10:00:00.123456Z",
            "date_registered": "2014-06-05T19:14:13Z"
        })
        .to_string();
        let net = Fixtures::default().with(
            "https://hub.docker.com/v2/repositories/library/nginx",
            doc.as_bytes(),
        );
        // Through the purl-facing entry so the percent-encoded qualifier is
        // exercised end-to-end.
        let r = look(
            "pkg:oci/nginx?repository_url=docker.io%2Flibrary%2Fnginx",
            &net,
        )
        .expect("registry");
        assert_eq!(r.ecosystem, Ecosystem::Oci);
        assert_eq!(r.name, "nginx");
        assert_eq!(r.author.as_deref(), Some("library"));
        assert_eq!(r.downloads_total, Some(1_000_000_000));
        // Stars are favorites, not ratings: nothing stands behind a `rating`.
        assert_eq!(r.favorites, Some(20_000));
        assert_eq!(r.rating_count, None);
        assert_eq!(r.version, "");
        assert!(r.published_at.is_some());
        assert!(r.first_published_at.is_some());
    }

    #[test]
    fn every_docker_hub_host_reads_the_one_hub_api() {
        let doc = serde_json::json!({"name": "nginx", "namespace": "library"}).to_string();
        let net = Fixtures::default().with(
            "https://hub.docker.com/v2/repositories/library/nginx",
            doc.as_bytes(),
        );
        for host in ["docker.io", "index.docker.io", "registry-1.docker.io"] {
            let purl = format!("pkg:oci/nginx?repository_url={host}%2Flibrary%2Fnginx");
            assert_eq!(
                look(&purl, &net).map(|r| r.author),
                Ok(Some("library".to_string())),
                "{host}"
            );
        }
    }

    #[test]
    fn a_pinned_image_is_the_version_asked_for_and_undated() {
        // The repository's last push dates the newest image, not the pinned one.
        let doc = serde_json::json!({"name": "nginx", "last_updated": "2026-06-01T10:00:00Z"})
            .to_string();
        let net = Fixtures::default().with(
            "https://hub.docker.com/v2/repositories/library/nginx",
            doc.as_bytes(),
        );
        let r = look("pkg:oci/nginx@sha256:abc123", &net).expect("registry");
        assert_eq!(r.version, "sha256:abc123");
        assert_eq!(r.published_at, None);
    }

    #[test]
    fn oci_quay_normalizes() {
        let repo = serde_json::json!({
            "namespace": "prometheus", "name": "node-exporter", "kind": "image",
            "description": "Prometheus exporter for machine metrics",
            "stats": [{"date": "2026-09-29", "count": 20}, {"date": "2026-09-30", "count": 22}]
        })
        .to_string();
        let tags = serde_json::json!({
            "tags": [{"name": "master", "start_ts": 1_790_343_232u64}],
            "page": 1, "has_additional": true
        })
        .to_string();
        let repo_url =
            "https://quay.io/api/v1/repository/prometheus/node-exporter?includeStats=true";
        let tags_url = "https://quay.io/api/v1/repository/prometheus/node-exporter/tag/?limit=1&onlyActiveTags=true";
        let purl = "pkg:oci/node-exporter?repository_url=quay.io%2Fprometheus%2Fnode-exporter";
        let net = Fixtures::default()
            .with(repo_url, repo.as_bytes())
            .with(tags_url, tags.as_bytes());
        let r = look(purl, &net).expect("registry");
        assert_eq!(r.name, "node-exporter");
        assert_eq!(r.author.as_deref(), Some("prometheus"));
        assert_eq!(r.published_at, Some(1_790_343_232));
        assert_eq!(r.downloads_recent, Some(42));

        // The tag page is an enrichment: without it the record stands, undated.
        let net = Fixtures::default()
            .with(repo_url, repo.as_bytes())
            .refusing(tags_url, 503);
        let r = look(purl, &net).expect("registry");
        assert_eq!(r.author.as_deref(), Some("prometheus"));
        assert_eq!(r.published_at, None);
    }

    /// An organisation's repository has no `namespace` user behind it, and
    /// Docker Hub can send `null` there; the publishing `user` is then who.
    #[test]
    fn oci_docker_hub_falls_back_to_the_user() {
        let doc = serde_json::json!({"name": "app", "namespace": null, "user": "acme"}).to_string();
        let net = Fixtures::default().with(
            "https://hub.docker.com/v2/repositories/acme/app",
            doc.as_bytes(),
        );
        let r = look("pkg:docker/acme/app", &net).expect("registry");
        assert_eq!(r.author.as_deref(), Some("acme"));
    }

    #[test]
    fn oci_unknown_registry_is_off_registry() {
        // ghcr has no anonymous metadata API; the lookup is refused without
        // touching the network, whether the host rides the qualifier or the name.
        let net = Fixtures::default();
        assert_eq!(
            look("pkg:oci/img?repository_url=ghcr.io%2Fowner%2Fimg", &net),
            Err(RegistryError::OffRegistry)
        );
        assert_eq!(
            look("pkg:docker/ghcr.io/owner/img", &net),
            Err(RegistryError::OffRegistry)
        );
    }

    #[test]
    fn a_repository_off_the_reference_grammar_is_never_spliced() {
        // No fixtures: each must be refused before any read.
        let net = Fixtures::default();
        for repository_url in [
            "docker.io%2Flibrary%2F..%2F..%2Fusers%2Fx",
            "docker.io%2Flibrary%2Fnginx%3Fpage%3D2",
            "docker.io%2Flibrary%2Fnginx%23x",
            "docker.io%2FLibrary%2Fnginx",
            "docker.io%2F%2Fnginx",
            "docker.io",
            "quay.io%2Fa%2Fb%5Cc",
        ] {
            let purl = format!("pkg:oci/nginx?repository_url={repository_url}");
            assert_eq!(look(&purl, &net), Err(RegistryError::OffRegistry), "{purl}");
        }
        // A name off the grammar, with no qualifier to stand in for it.
        assert_eq!(
            look("pkg:docker/MyOrg/nginx", &net),
            Err(RegistryError::UnsafeCoordinate)
        );
        assert_eq!(
            oci_repository("x", Some("docker.io/library/../etc")),
            Err(RegistryError::UnsafeCoordinate)
        );
    }

    #[test]
    fn the_reference_grammar_holds_hosts_and_components() {
        for good in [
            "docker.io/library/nginx",
            "quay.io/prometheus/node-exporter",
            "QUAY.IO/a/b",
            "localhost:5000/a/b",
            "registry.example.com/a.b/c_d/e__f/g---h",
        ] {
            assert!(split_reference(good).is_some(), "{good}");
        }
        for bad in [
            "docker.io/a/b.",
            "docker.io/a/.b",
            "docker.io/a/b..c",
            "docker.io/a/b___c",
            "docker.io/a/b-.c",
            "-docker.io/a",
            "docker..io/a",
            "docker.io:/a",
            "docker.io:99999/a",
            "docker.io:+80/a",
            "docker_io/a",
            "docker.io/a/b c",
            "docker.io/a/é",
        ] {
            assert!(split_reference(bad).is_none(), "{bad}");
        }
        assert!(public_repository("index.docker.io/library/nginx"));
        assert!(public_repository("quay.io/a/b"));
        assert!(!public_repository("ghcr.io/a/b"));
        assert!(!public_repository("docker.io.evil.test/a/b"));
        assert!(!public_repository("docker.io/../b"));
    }

    #[test]
    fn a_reference_resolves_to_the_puller_pseudo_url() {
        let oci = |purl: &str| resolve_oci_ref(&Purl::parse(purl).expect("purl"));
        assert_eq!(
            oci("pkg:oci/nginx").as_deref(),
            Some("oci://docker.io/library/nginx:latest")
        );
        assert_eq!(
            oci("pkg:oci/nginx?repository_url=quay.io%2Fa%2Fnginx&tag=1.25").as_deref(),
            Some("oci://quay.io/a/nginx:1.25")
        );
        assert_eq!(
            oci("pkg:docker/myorg/nginx@sha256:abc").as_deref(),
            Some("oci://docker.io/myorg/nginx@sha256:abc")
        );
        assert_eq!(oci("pkg:oci/nginx?repository_url=quay.io%2F..%2Fx"), None);
    }
}
