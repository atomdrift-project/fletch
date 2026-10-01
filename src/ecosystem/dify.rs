//! The Dify Marketplace: registry metadata and artifact resolution.

use filefacts::Registry;
use serde::Deserialize;
use std::time::Duration;

use crate::ecosystem::{Localized, fetch_json, parse_ts};
use crate::fetch::{
    BlobCache, Fetch, META_TTL_IMMUTABLE, cached_metadata, percent_decode, safe_coordinate,
};
use crate::registry::RegistryError;

/// Resolve a Dify Marketplace plugin (`<org>/<name>`) to `(version, .difypkg
/// URL)`. The download endpoint is keyed by the release's unique identifier,
/// `<org>/<name>:<version>@<checksum>`, whose checksum is Dify's own (not the
/// package's sha256), so it is read from the per-version document — or, for an
/// unpinned plugin, from the plugin document's current release.
pub(crate) fn resolve_dify(
    path: &str,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Option<(String, String)> {
    let (org, name) = path.split_once('/')?;
    if org.is_empty()
        || name.is_empty()
        || name.contains('/')
        || !safe_coordinate(path)
        || version.is_some_and(|v| !safe_coordinate(v))
    {
        return None;
    }
    let base = format!("https://marketplace.dify.ai/api/v1/plugins/{org}/{name}");
    let json = |url: &str, ttl: Duration| {
        cached_metadata(url, net, &cache.with_meta_ttl(ttl))
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
    };
    let text = |doc: &serde_json::Value, pointer: &str| {
        doc.pointer(pointer)
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
    };
    let (resolved, identifier) = match version {
        Some(v) => {
            let doc = json(&format!("{base}/{v}"), META_TTL_IMMUTABLE)?;
            (
                text(&doc, "/data/version/version")?,
                text(&doc, "/data/version/unique_identifier")?,
            )
        }
        None => {
            let doc = json(&base, cache.meta_ttl_unpinned())?;
            (
                text(&doc, "/data/plugin/latest_version")?,
                text(&doc, "/data/plugin/latest_package_identifier")?,
            )
        }
    };
    if version.is_some_and(|want| percent_decode(want) != resolved) {
        return None;
    }
    // Held to its documented shape, so a surprising response can't point the
    // download at another plugin's (or another release's) package.
    let checksum = identifier.strip_prefix(&format!("{}:{resolved}@", percent_decode(path)))?;
    if checksum.is_empty() || !checksum.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some((
        resolved,
        format!(
            "https://marketplace.dify.ai/api/v1/plugins/download?unique_identifier={}",
            crate::purl::encode_component(&identifier)
        ),
    ))
}

/// Dify Marketplace: the plugin document is the listing (installs, publisher
/// org, repository, verification) plus its latest release. As with ComfyUI, a
/// pinned older version gets no publish time.
pub(crate) fn dify(
    path: &str,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let (org, name) = path.split_once('/').ok_or(RegistryError::NoRecord)?;
    if name.contains('/') {
        return Err(RegistryError::NoRecord);
    }
    let doc: PluginDocument = fetch_json(
        &format!("https://marketplace.dify.ai/api/v1/plugins/{org}/{name}"),
        net,
        cache,
    )?;
    let plugin = doc.data.plugin;
    let latest_version = plugin.latest_version.filter(|s| !s.is_empty());
    let version = version
        .map(percent_decode)
        .or_else(|| latest_version.clone())
        .unwrap_or_default();
    Ok(Registry {
        ecosystem: "dify".into(),
        name: plugin
            .plugin_id
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| percent_decode(path)),
        published_at: plugin
            .version_updated_at
            .as_deref()
            .filter(|_| latest_version.as_deref() == Some(version.as_str()))
            .and_then(parse_ts),
        first_published_at: plugin.created_at.as_deref().and_then(parse_ts),
        version,
        latest_version,
        // Localized as `{ "en_US": … }`, underscore where AMO has a hyphen.
        title: plugin
            .label
            .and_then(|l| l.translation("en_US").or_else(|| l.text())),
        description: plugin
            .brief
            .and_then(|b| b.translation("en_US").or_else(|| b.text())),
        repository: plugin.repository.filter(|s| !s.is_empty()),
        publisher: Some(percent_decode(org)),
        downloads_total: plugin.install_count,
        // Dify's own and its partners' plugins are vetted; `community` is
        // anyone's.
        publisher_verified: plugin
            .verification
            .and_then(|v| v.authorized_category)
            .map(|c| matches!(c.as_str(), "langgenius" | "partner")),
        deprecated: plugin
            .deprecated_reason
            .filter(|s| !s.is_empty())
            .or_else(|| {
                plugin
                    .status
                    .filter(|s| !s.is_empty())
                    .filter(|s| s != "active")
            }),
        ..Default::default()
    })
}

/// A Dify Marketplace plugin document: the listing under `data.plugin`.
#[derive(Deserialize)]
struct PluginDocument {
    data: PluginData,
}

/// The `data` envelope of a plugin document.
#[derive(Deserialize)]
struct PluginData {
    plugin: Plugin,
}

/// A Dify plugin listing with its latest release.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Plugin {
    plugin_id: Option<String>,
    latest_version: Option<String>,
    version_updated_at: Option<String>,
    created_at: Option<String>,
    label: Option<Localized>,
    brief: Option<Localized>,
    repository: Option<String>,
    install_count: Option<u64>,
    verification: Option<Verification>,
    deprecated_reason: Option<String>,
    status: Option<String>,
}

/// Dify's vetting of a plugin.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Verification {
    authorized_category: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::test_cache;
    use crate::registry;
    use filefacts::RefLocator;

    use crate::fetch::Fixtures;

    #[test]
    fn dify_plugin_normalizes() {
        let doc = serde_json::json!({"code": 0, "data": {"plugin": {
            "plugin_id": "fr3on/eval-loop", "org": "fr3on", "name": "eval-loop",
            "label": {"en_US": "Eval Loop"}, "brief": {"en_US": "Evaluates Q&A."},
            "repository": "https://github.com/fr3on/eval-loop",
            "install_count": 9u64, "status": "active", "deprecated_reason": "",
            "verification": {"authorized_category": "community"},
            "created_at": "2026-09-26T01:46:12.196377Z",
            "version_updated_at": "2026-09-26T01:46:15.993933Z",
            "latest_version": "0.1.1"
        }}})
        .to_string();
        let net = Fixtures::default().with(
            "https://marketplace.dify.ai/api/v1/plugins/fr3on/eval-loop",
            doc.as_bytes(),
        );
        let locator = RefLocator::Purl("pkg:dify/fr3on/eval-loop".into());
        let r = registry(&locator, &net, &test_cache("dify")).expect("registry");
        assert_eq!(r.ecosystem, "dify");
        assert_eq!(r.name, "fr3on/eval-loop");
        assert_eq!(r.version, "0.1.1");
        assert_eq!(r.published_at, Some(1_790_387_175)); // 2026-09-26T01:46:15Z
        assert_eq!(r.first_published_at, Some(1_790_387_172));
        assert_eq!(r.title.as_deref(), Some("Eval Loop"));
        assert_eq!(r.description.as_deref(), Some("Evaluates Q&A."));
        assert_eq!(r.publisher.as_deref(), Some("fr3on"));
        assert_eq!(r.publisher_verified, Some(false));
        assert_eq!(r.downloads_total, Some(9));
        assert_eq!(r.deprecated, None);
        assert!(dify("eval-loop", None, &net, &test_cache("dify")).is_err());
    }
}
