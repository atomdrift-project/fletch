//! ComfyUI custom nodes: registry metadata and artifact resolution.

use filefacts::Registry;
use serde_json::Value;

use crate::ecosystem::{json_meta, nonempty, parse_ts};
use crate::fetch::{
    BlobCache, Fetch, META_TTL_IMMUTABLE, cached_metadata, is_web_scheme, meta_ttl_unpinned,
    percent_decode, safe_coordinate,
};

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
        None => (base, meta_ttl_unpinned()),
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
) -> Option<Registry> {
    if id.contains('/') {
        return None;
    }
    let doc = json_meta(&format!("https://api.comfy.org/nodes/{id}"), net, cache)?;
    let latest = doc.get("latest_version");
    let latest_version = nonempty(latest.and_then(|l| l.get("version")));
    let version = version
        .map(percent_decode)
        .or_else(|| latest_version.clone())
        .unwrap_or_default();
    Some(Registry {
        ecosystem: "comfyui".into(),
        name: nonempty(doc.get("id")).unwrap_or_else(|| percent_decode(id)),
        published_at: latest
            .filter(|_| latest_version.as_deref() == Some(version.as_str()))
            .and_then(|l| l.get("createdAt")?.as_str())
            .and_then(parse_ts),
        first_published_at: doc
            .get("created_at")
            .and_then(Value::as_str)
            .and_then(parse_ts),
        version,
        latest_version,
        title: nonempty(doc.get("name")),
        description: nonempty(doc.get("description")),
        repository: nonempty(doc.get("repository")),
        publisher: nonempty(doc.pointer("/publisher/id")),
        downloads_total: doc.get("downloads").and_then(Value::as_u64),
        // A banned or deleted node still answers; its status says which.
        deprecated: nonempty(doc.get("status")).filter(|s| s != "NodeStatusActive"),
        ..Default::default()
    })
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
