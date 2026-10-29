//! ComfyUI custom nodes: registry metadata and artifact resolution.

use filefacts::Registry;
use serde::Deserialize;

use crate::ecosystem::{
    Coordinates, fetch_json, immutable_or_fresh, non_empty, optional, unix_secs,
};
use crate::fetch::{BlobCache, Fetch, is_web_scheme, percent_decode, safe_coordinate};
use crate::registry::RegistryError;

/// The status the registry gives a node in good standing; a banned or deleted
/// node still answers, under another status.
const ACTIVE: &str = "NodeStatusActive";

/// Resolve a ComfyUI Registry node id to `(version, archive URL)`. The CDN path
/// is keyed by publisher rather than node id, and the archive is a `.zip` or a
/// `.tar.gz` as uploaded, so only the install endpoint names it. With
/// `?version=` it answers that one release; without, the current one. The
/// answer must name the node and the release asked for, or nothing resolves.
pub(crate) fn resolve_comfyui(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Option<(String, String)> {
    let (path, version) = (c.path(), c.encoded_version());
    // A node id is one global segment: the registry has no namespace.
    if path.is_empty()
        || path.contains('/')
        || !safe_coordinate(path)
        || version.is_some_and(|v| !safe_coordinate(v))
    {
        tracing::debug!(
            path = %path.escape_debug(),
            "comfyui artifact refused: not a node id"
        );
        return None;
    }
    let base = format!("https://api.comfy.org/nodes/{path}/install");
    let api = match version {
        Some(v) => format!("{base}?version={v}"),
        None => base,
    };
    let node_id = percent_decode(path);
    let wanted = version.map(percent_decode);
    let resolve = |cache: &BlobCache| {
        let install: Install = optional(fetch_json(&api, net, cache), &api)?;
        let (Some(resolved), Some(url)) = (install.version, install.download_url) else {
            tracing::debug!(
                url = %api,
                "comfyui artifact unresolved: the install answer lacks a version or URL"
            );
            return None;
        };
        if wanted.as_ref().is_some_and(|want| *want != resolved)
            || install.node_id.as_deref() != Some(node_id.as_str())
            || !is_web_scheme(&url)
        {
            tracing::debug!(
                url = %api,
                resolved = %resolved.escape_debug(),
                "comfyui artifact refused: the answer is not the node and release asked for"
            );
            return None;
        }
        Some((resolved, url))
    };
    match version {
        Some(_) => immutable_or_fresh(cache, resolve),
        None => resolve(&cache.with_meta_ttl(cache.meta_ttl_unpinned())),
    }
}

/// The install endpoint's answer: one release of one node and its archive.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Install {
    #[serde(rename = "node_id")]
    node_id: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    version: Option<String>,
    download_url: Option<String>,
}

/// ComfyUI Registry: the node document is the listing (publisher, repository,
/// downloads, first listing, standing) plus its latest release. It carries no
/// other release, so a pinned older version gets no publish time. A node the
/// registry banned or deleted is a security hold.
pub(crate) fn lookup(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let id = c.bare_name(&[])?;
    let doc: Node = fetch_json(&format!("https://api.comfy.org/nodes/{id}"), net, cache)?;
    let latest = doc.latest_version.unwrap_or_default();
    let version = c.target(latest.version.as_deref()).to_string();
    let security_hold = doc.status.as_deref().map(|status| status != ACTIVE);
    if let Some(status) = doc.status.as_deref().filter(|s| *s != ACTIVE) {
        tracing::debug!(
            node = %c.name().escape_debug(),
            status = %status.escape_debug(),
            "comfyui node is not active: security hold"
        );
    }
    Ok(Registry {
        ecosystem: "comfyui".into(),
        name: doc.id.unwrap_or_else(|| c.name().to_string()),
        published_at: latest
            .created_at
            .as_deref()
            .filter(|_| latest.version.as_deref() == Some(version.as_str()))
            .and_then(unix_secs),
        first_published_at: doc.created_at.as_deref().and_then(unix_secs),
        version,
        latest_version: latest.version,
        title: doc.name,
        description: doc.description,
        repository: doc.repository,
        publisher: doc.publisher.and_then(|p| p.id),
        downloads_total: doc.downloads,
        security_hold,
        ..Default::default()
    })
}

/// A ComfyUI Registry node document: the listing plus its latest release.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Node {
    #[serde(deserialize_with = "non_empty")]
    id: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    name: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    description: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    repository: Option<String>,
    created_at: Option<String>,
    downloads: Option<u64>,
    #[serde(deserialize_with = "non_empty")]
    status: Option<String>,
    publisher: Option<NodePublisher>,
    latest_version: Option<NodeVersion>,
}

/// The publisher a node is listed under.
#[derive(Default, Deserialize)]
#[serde(default)]
struct NodePublisher {
    #[serde(deserialize_with = "non_empty")]
    id: Option<String>,
}

/// A node's latest release.
#[derive(Default, Deserialize)]
#[serde(default)]
struct NodeVersion {
    #[serde(deserialize_with = "non_empty")]
    version: Option<String>,
    #[serde(rename = "createdAt")]
    created_at: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::coordinates;
    use filefacts::RefLocator;
    use std::sync::Mutex;

    use crate::fetch::{FetchError, Fetched, Fixtures, Request};

    /// A registry whose answers change between reads: each request takes the
    /// next of `answers`, and every URL asked is kept in order.
    struct Sequence {
        answers: Mutex<Vec<Fixtures>>,
        asked: Mutex<Vec<String>>,
    }

    impl Fetch for Sequence {
        fn send(&self, request: &Request<'_>) -> Result<Fetched, FetchError> {
            if let Ok(mut asked) = self.asked.lock() {
                asked.push(request.url.to_string());
            }
            let next = self
                .answers
                .lock()
                .ok()
                .filter(|a| !a.is_empty())
                .map(|mut a| a.remove(0));
            next.unwrap_or_default().send(request)
        }
    }

    fn install(version: &str) -> Fixtures {
        let doc = serde_json::json!({"version": version, "node_id": "n",
                                     "downloadUrl": "https://cdn.comfy.org/n.zip"})
        .to_string();
        Fixtures::default().with(
            "https://api.comfy.org/nodes/n/install?version=1.0",
            doc.as_bytes(),
        )
    }

    #[test]
    fn a_placeholder_for_an_unpublished_version_is_not_pinned_forever() {
        // The first read — the one that trusts a cached copy of any age —
        // answers with another release, as a placeholder cached before 1.0
        // existed would. The resolver then asks the network once more, and
        // the release published since resolves.
        let net = Sequence {
            answers: Mutex::new(vec![install("0.9"), install("1.0")]),
            asked: Mutex::new(Vec::new()),
        };
        assert_eq!(
            resolve_comfyui(
                &coordinates("pkg:comfyui/n@1.0"),
                &net,
                &BlobCache::disabled()
            ),
            Some(("1.0".to_string(), "https://cdn.comfy.org/n.zip".to_string()))
        );
        assert_eq!(
            net.asked.lock().map(|a| a.len()).ok(),
            Some(2),
            "one re-read, straight from the network"
        );
    }

    #[test]
    fn an_install_answer_for_another_node_or_release_is_refused() {
        let cache = BlobCache::disabled();
        assert_eq!(
            resolve_comfyui(&coordinates("pkg:comfyui/n@1.0"), &install("0.9"), &cache),
            None
        );
        let other = serde_json::json!({"version": "1.0", "node_id": "evil",
                                       "downloadUrl": "https://cdn.comfy.org/n.zip"})
        .to_string();
        let net = Fixtures::default().with(
            "https://api.comfy.org/nodes/n/install?version=1.0",
            other.as_bytes(),
        );
        assert_eq!(
            resolve_comfyui(&coordinates("pkg:comfyui/n@1.0"), &net, &cache),
            None
        );
    }

    fn loopstrip(status: &str) -> Fixtures {
        let doc = serde_json::json!({
            "id": "comfyui-loopstrip", "name": "Loop Strip",
            "description": "Character animation nodes for ComfyUI.",
            "repository": "https://github.com/serhiiyashyn-sf/comfyui-loopstrip",
            "downloads": 353u64, "status": status,
            "created_at": "2026-04-16T09:28:21.273039Z",
            "publisher": {"id": "serhiiyashyn-sf"},
            "latest_version": {"version": "1.3.1", "createdAt": "2026-04-21T23:53:06.619755Z"}
        })
        .to_string();
        Fixtures::default().with(
            "https://api.comfy.org/nodes/comfyui-loopstrip",
            doc.as_bytes(),
        )
    }

    fn look(purl: &str, net: &Fixtures) -> Result<Registry, RegistryError> {
        crate::registry::lookup(&RefLocator::Purl(purl.into()), net, &BlobCache::disabled())
    }

    #[test]
    fn comfyui_node_normalizes() {
        let net = loopstrip(ACTIVE);
        let r = look("pkg:comfyui/comfyui-loopstrip@1.3.1", &net).expect("registry");
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
        assert_eq!(r.security_hold, Some(false));

        // An older pin has no publish time in the node document.
        let r = look("pkg:comfyui/comfyui-loopstrip@1.3.0", &net).expect("registry");
        assert_eq!(r.version, "1.3.0");
        assert_eq!(r.published_at, None);
    }

    #[test]
    fn a_banned_or_deleted_node_is_a_security_hold_not_a_deprecation() {
        for status in ["NodeStatusBanned", "NodeStatusDeleted"] {
            let r = look("pkg:comfyui/comfyui-loopstrip", &loopstrip(status)).expect("registry");
            assert_eq!(r.security_hold, Some(true), "{status}");
            assert_eq!(r.deprecated, None, "{status}");
        }
    }

    #[test]
    fn a_namespaced_node_names_no_registry_node() {
        assert_eq!(
            look("pkg:comfyui/pub/comfyui-loopstrip", &Fixtures::default()),
            Err(RegistryError::OffRegistry)
        );
    }
}
