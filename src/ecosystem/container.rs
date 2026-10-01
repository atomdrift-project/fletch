//! Container images (Docker Hub, Quay, and OCI references): registry metadata and artifact resolution.

use filefacts::Registry;
use serde_json::Value;

use crate::ecosystem::{json_meta, last_seg, parse_ts};
use crate::fetch::{BlobCache, Fetch};
use crate::purl::Purl;

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
) -> Option<Registry> {
    let repo = oci_repository(path, repository_url);
    let (host, image) = repo.split_once('/')?;
    match host {
        "docker.io" => docker_hub(image, net, cache),
        "quay.io" => quay(image, net, cache),
        _ => None,
    }
}

/// Docker Hub repository metadata: anonymous JSON with pulls, stars, the
/// publishing namespace, and registration/update times.
fn docker_hub(image: &str, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    let doc = json_meta(
        &format!("https://hub.docker.com/v2/repositories/{image}"),
        net,
        cache,
    )?;
    Some(Registry {
        ecosystem: "oci".into(),
        name: doc
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or(last_seg(image))
            .to_string(),
        published_at: doc
            .get("last_updated")
            .and_then(Value::as_str)
            .and_then(parse_ts),
        first_published_at: doc
            .get("date_registered")
            .and_then(Value::as_str)
            .and_then(parse_ts),
        author: doc
            .get("namespace")
            .or_else(|| doc.get("user"))
            .and_then(Value::as_str)
            .map(str::to_string),
        description: doc
            .get("description")
            .and_then(Value::as_str)
            .filter(|d| !d.is_empty())
            .map(str::to_string),
        downloads_total: doc.get("pull_count").and_then(Value::as_u64),
        rating_count: doc.get("star_count").and_then(Value::as_u64),
        ..Default::default()
    })
}

/// Quay repository metadata: anonymous JSON with the description, the owning
/// namespace, and a Unix-seconds last-modified time.
fn quay(image: &str, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    let doc = json_meta(
        &format!("https://quay.io/api/v1/repository/{image}"),
        net,
        cache,
    )?;
    Some(Registry {
        ecosystem: "oci".into(),
        name: doc
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or(last_seg(image))
            .to_string(),
        published_at: doc.get("last_modified").and_then(Value::as_u64),
        author: doc
            .get("namespace")
            .and_then(Value::as_str)
            .map(str::to_string),
        description: doc
            .get("description")
            .and_then(Value::as_str)
            .filter(|d| !d.is_empty())
            .map(str::to_string),
        rating_count: doc.get("popularity").and_then(Value::as_u64),
        ..Default::default()
    })
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
