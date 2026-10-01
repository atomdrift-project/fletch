//! ComfyUI custom nodes: registry metadata and artifact resolution.

use filefacts::Registry;
use serde::Deserialize;

use crate::ecosystem::{fetch_json, parse_ts};
use crate::fetch::{
    BlobCache, Fetch, META_TTL_IMMUTABLE, cached_metadata, is_web_scheme, percent_decode,
    safe_coordinate,
};
use crate::registry::RegistryError;

/// Resolve a ComfyUI Registry node id to `(version, archive URL)`. The CDN path
/// is keyed by publisher rather than node id, and the archive is a `.zip` or a
/// `.tar.gz` as uploaded, so only the install endpoint names it. With
/// `?version=` it answers that one release; without, the current one.
pub(crate) fn resolve_comfyui(
    path: &str,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Option<(String, String)> {
    // A node id is one global segment: the registry has no namespace.
    if path.is_empty()
        || path.contains('/')
        || !safe_coordinate(path)
        || version.is_some_and(|v| !safe_coordinate(v))
    {
        return None;
    }
    let base = format!("https://api.comfy.org/nodes/{path}/install");
    let (api, ttl) = match version {
        Some(v) => (format!("{base}?version={v}"), META_TTL_IMMUTABLE),
        None => (base, cache.meta_ttl_unpinned()),
    };
    let bytes = cached_metadata(&api, net, &cache.with_meta_ttl(ttl))?;
    let doc: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let resolved = doc.get("version")?.as_str()?;
    // As with AMO: a surprising response must not substitute another release,
    // or another node, for the one requested.
    if version.is_some_and(|want| percent_decode(want) != resolved)
        || doc.get("node_id").and_then(serde_json::Value::as_str) != Some(&percent_decode(path))
    {
        return None;
    }
    let url = doc.get("downloadUrl")?.as_str()?;
    is_web_scheme(url).then(|| (resolved.to_string(), url.to_string()))
}

/// ComfyUI Registry: the node document is the listing (publisher, repository,
/// downloads, first listing) plus its latest release. It carries no other
/// release, so a pinned older version gets no publish time.
pub(crate) fn comfyui(
    id: &str,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    if id.contains('/') {
        return Err(RegistryError::NoRecord);
    }
    let doc: Node = fetch_json(&format!("https://api.comfy.org/nodes/{id}"), net, cache)?;
    let latest = doc.latest_version;
    let latest_version = latest
        .as_ref()
        .and_then(|l| l.version.clone())
        .filter(|s| !s.is_empty());
    let version = version
        .map(percent_decode)
        .or_else(|| latest_version.clone())
        .unwrap_or_default();
    Ok(Registry {
        ecosystem: "comfyui".into(),
        name: doc
            .id
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| percent_decode(id)),
        published_at: latest
            .filter(|_| latest_version.as_deref() == Some(version.as_str()))
            .and_then(|l| l.created_at)
            .as_deref()
            .and_then(parse_ts),
        first_published_at: doc.created_at.as_deref().and_then(parse_ts),
        version,
        latest_version,
        title: doc.name.filter(|s| !s.is_empty()),
        description: doc.description.filter(|s| !s.is_empty()),
        repository: doc.repository.filter(|s| !s.is_empty()),
        publisher: doc.publisher.and_then(|p| p.id).filter(|s| !s.is_empty()),
        downloads_total: doc.downloads,
        // A banned or deleted node still answers; its status says which.
        deprecated: doc
            .status
            .filter(|s| !s.is_empty())
            .filter(|s| s != "NodeStatusActive"),
        ..Default::default()
    })
}

/// A ComfyUI Registry node document: the listing plus its latest release.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Node {
    id: Option<String>,
    name: Option<String>,
    description: Option<String>,
    repository: Option<String>,
    created_at: Option<String>,
    downloads: Option<u64>,
    status: Option<String>,
    publisher: Option<NodePublisher>,
    latest_version: Option<NodeVersion>,
}

/// The publisher a node is listed under.
#[derive(Default, Deserialize)]
#[serde(default)]
struct NodePublisher {
    id: Option<String>,
}

/// A node's latest release.
#[derive(Default, Deserialize)]
#[serde(default)]
struct NodeVersion {
    version: Option<String>,
    #[serde(rename = "createdAt")]
    created_at: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::test_cache;
    use crate::registry;
    use filefacts::RefLocator;

    use crate::fetch::Fixtures;

    #[test]
    fn comfyui_node_normalizes() {
        let doc = serde_json::json!({
            "id": "comfyui-loopstrip", "name": "Loop Strip",
            "description": "Character animation nodes for ComfyUI.",
            "repository": "https://github.com/serhiiyashyn-sf/comfyui-loopstrip",
            "downloads": 353u64, "status": "NodeStatusActive",
            "created_at": "2026-04-16T09:28:21.273039Z",
            "publisher": {"id": "serhiiyashyn-sf"},
            "latest_version": {"version": "1.3.1", "createdAt": "2026-04-21T23:53:06.619755Z"}
        })
        .to_string();
        let net = Fixtures::default().with(
            "https://api.comfy.org/nodes/comfyui-loopstrip",
            doc.as_bytes(),
        );
        let locator = RefLocator::Purl("pkg:comfyui/comfyui-loopstrip@1.3.1".into());
        let r = registry(&locator, &net, &test_cache("comfyui")).expect("registry");
        assert_eq!(r.ecosystem, "comfyui");
        assert_eq!(r.name, "comfyui-loopstrip");
        assert_eq!(r.version, "1.3.1");
        assert_eq!(r.latest_version.as_deref(), Some("1.3.1"));
        assert_eq!(r.published_at, Some(1_776_815_586)); // 2026-04-21T23:53:06Z
        assert_eq!(r.first_published_at, Some(1_776_331_701)); // 2026-04-16T09:28:21Z
        assert_eq!(r.title.as_deref(), Some("Loop Strip"));
        assert_eq!(r.publisher.as_deref(), Some("serhiiyashyn-sf"));
        assert_eq!(r.downloads_total, Some(353));
        assert_eq!(r.deprecated, None);

        // An older pin has no publish time in the node document.
        let r = comfyui(
            "comfyui-loopstrip",
            Some("1.3.0"),
            &net,
            &test_cache("comfyui"),
        )
        .expect("registry");
        assert_eq!(r.version, "1.3.0");
        assert_eq!(r.published_at, None);
    }
}
