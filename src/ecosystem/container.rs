//! Container images (Docker Hub, Quay, and OCI references): registry metadata and artifact resolution.

use filefacts::Registry;
use serde::Deserialize;

use crate::ecosystem::{fetch_json, last_seg, null_default, parse_ts};
use crate::fetch::{BlobCache, Fetch};
use crate::purl::Purl;
use crate::registry::RegistryError;

/// Resolve a `pkg:oci` (or legacy `pkg:docker`) purl body to the `oci://`
/// pseudo-URL the OCI puller consumes: `oci://<repo>[@sha256:…|:tag]`. The
/// repository path rides the purl's percent-encoded `repository_url`
/// qualifier; without one, Docker Hub's implied coordinates apply. A
/// `sha256:…` version is the content-addressed digest and wins over any
/// mutable `tag` qualifier; with neither, `latest` — matching what forager's
/// crane path pulls for a bare reference.
pub(crate) fn resolve_oci_ref(purl: &Purl) -> String {
    let repo = oci_repository(&purl.encoded_path(), purl.qualifier("repository_url"));
    let version = purl.encoded_version();
    match (version.as_deref(), purl.qualifier("tag")) {
        (Some(d), _) if d.starts_with("sha256:") => format!("oci://{repo}@{d}"),
        // A legacy pkg:docker version slot may carry a plain tag.
        (Some(t), _) | (None, Some(t)) => format!("oci://{repo}:{t}"),
        (None, None) => format!("oci://{repo}:latest"),
    }
}

/// The registry-qualified repository a `pkg:oci`/`pkg:docker` name denotes:
/// its (decoded) `repository_url` qualifier when present;
/// otherwise Docker Hub's implied coordinates. A host-less name lives on
/// Docker Hub, and only a single-segment one under `library/` — `myorg/nginx`
/// is `docker.io/myorg/nginx`, not the official `library/nginx`. Shared by the
/// fetcher and the registry lookup so the bytes and the reputation always
/// describe the same repository.
pub(crate) fn oci_repository(name: &str, repository_url: Option<&str>) -> String {
    if let Some(url) = repository_url.filter(|u| !u.is_empty()) {
        return url.to_string();
    }
    match name.split_once('/') {
        Some((first, _)) if first.contains('.') || first.contains(':') => name.to_string(),
        Some(_) => format!("docker.io/{name}"),
        None => format!("docker.io/library/{name}"),
    }
}

/// Container-image metadata. The purl carries the registry-qualified
/// repository path on its percent-encoded `repository_url` qualifier
/// (`pkg:oci/nginx?repository_url=docker.io%2Flibrary%2Fnginx`); the host
/// picks the metadata API. Docker Hub and Quay expose anonymous repository
/// JSON; ghcr.io does not (a token dance for a thin manifest), so its refs
/// resolve no record and the caller fails open like any unreachable registry.
pub(crate) fn oci_meta(
    repository_url: Option<&str>,
    path: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let repo = oci_repository(path, repository_url);
    let (host, image) = repo.split_once('/').ok_or(RegistryError::NoRecord)?;
    match host {
        "docker.io" => docker_hub(image, net, cache),
        "quay.io" => quay(image, net, cache),
        _ => Err(RegistryError::NoRecord),
    }
}

/// Docker Hub repository metadata: anonymous JSON with pulls, stars, the
/// publishing namespace, and registration/update times.
fn docker_hub(image: &str, net: &dyn Fetch, cache: &BlobCache) -> Result<Registry, RegistryError> {
    let doc: HubRepository = fetch_json(
        &format!("https://hub.docker.com/v2/repositories/{image}"),
        net,
        cache,
    )?;
    Ok(Registry {
        ecosystem: "oci".into(),
        name: doc.name.unwrap_or_else(|| last_seg(image).to_string()),
        published_at: doc.last_updated.as_deref().and_then(parse_ts),
        first_published_at: doc.date_registered.as_deref().and_then(parse_ts),
        author: doc.namespace.or(doc.user),
        description: doc.description.filter(|d| !d.is_empty()),
        downloads_total: doc.pull_count,
        rating_count: doc.star_count,
        ..Default::default()
    })
}

/// The parts of a Docker Hub repository document the registry record reads.
#[derive(Default, Deserialize)]
#[serde(default)]
struct HubRepository {
    name: Option<String>,
    last_updated: Option<String>,
    date_registered: Option<String>,
    namespace: Option<String>,
    user: Option<String>,
    description: Option<String>,
    pull_count: Option<u64>,
    star_count: Option<u64>,
}

/// Quay repository metadata: anonymous JSON with the description, the owning
/// namespace, and (asked for with `includeStats`) the last ~90 days of daily
/// pulls. The repository document carries no time; its newest active tag —
/// tags list newest first — says when it was last pushed.
fn quay(image: &str, net: &dyn Fetch, cache: &BlobCache) -> Result<Registry, RegistryError> {
    let doc: QuayRepository = fetch_json(
        &format!("https://quay.io/api/v1/repository/{image}?includeStats=true"),
        net,
        cache,
    )?;
    let last_push = fetch_json::<QuayTags>(
        &format!("https://quay.io/api/v1/repository/{image}/tag/?limit=1&onlyActiveTags=true"),
        net,
        cache,
    )
    .ok()
    .and_then(|t| t.tags.into_iter().next()?.start_ts);
    Ok(Registry {
        ecosystem: "oci".into(),
        name: doc.name.unwrap_or_else(|| last_seg(image).to_string()),
        published_at: last_push,
        author: doc.namespace,
        description: doc.description.filter(|d| !d.is_empty()),
        downloads_recent: doc
            .stats
            .map(|days| days.iter().filter_map(|d| d.count).sum()),
        ..Default::default()
    })
}

/// The parts of a Quay repository document the registry record reads.
#[derive(Default, Deserialize)]
#[serde(default)]
struct QuayRepository {
    name: Option<String>,
    namespace: Option<String>,
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
    use crate::ecosystem::test_cache;
    use filefacts::RefLocator;

    use crate::fetch::Fixtures;

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
        let r = crate::registry(
            &RefLocator::Purl("pkg:oci/nginx?repository_url=docker.io%2Flibrary%2Fnginx".into()),
            &net,
            &test_cache("oci"),
        )
        .expect("registry");
        assert_eq!(r.ecosystem, "oci");
        assert_eq!(r.name, "nginx");
        assert_eq!(r.author.as_deref(), Some("library"));
        assert_eq!(r.downloads_total, Some(1_000_000_000));
        assert_eq!(r.rating_count, Some(20_000));
        assert!(r.published_at.is_some());
        assert!(r.first_published_at.is_some());
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
        let net = Fixtures::default()
            .with(
                "https://quay.io/api/v1/repository/prometheus/node-exporter?includeStats=true",
                repo.as_bytes(),
            )
            .with(
                "https://quay.io/api/v1/repository/prometheus/node-exporter/tag/?limit=1&onlyActiveTags=true",
                tags.as_bytes(),
            );
        let r = super::oci_meta(
            Some("quay.io/prometheus/node-exporter"),
            "node-exporter",
            &net,
            &test_cache("oci-quay"),
        )
        .expect("registry");
        assert_eq!(r.name, "node-exporter");
        assert_eq!(r.author.as_deref(), Some("prometheus"));
        assert_eq!(r.published_at, Some(1_790_343_232));
        assert_eq!(r.downloads_recent, Some(42));
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
        let r = super::oci_meta(None, "acme/app", &net, &test_cache("oci-user")).expect("registry");
        assert_eq!(r.author.as_deref(), Some("acme"));
    }

    #[test]
    fn oci_unknown_registry_resolves_no_record() {
        // ghcr has no anonymous metadata API; the lookup fails open (None)
        // without touching the network.
        let net = Fixtures::default();
        assert!(
            crate::registry(
                &RefLocator::Purl("pkg:oci/img?repository_url=ghcr.io%2Fowner%2Fimg".into()),
                &net,
                &test_cache("oci-ghcr"),
            )
            .is_none()
        );
    }
}
