//! The JetBrains Marketplace: registry metadata.

use filefacts::{Ecosystem, Registry};
use serde::Deserialize;

use crate::ecosystem::{
    Coordinates, fetch_json, five_star, non_empty, null_default, optional, secs_from_millis,
};
use crate::fetch::{BlobCache, Fetch};
use crate::registry::RegistryError;

/// The Marketplace API root.
const API: &str = "https://plugins.jetbrains.com/api";

/// Look up the plugin `c` names: its numeric id, or an `xmlId` resolved
/// through search; then its listing and the update this record describes —
/// the requested version's, or the latest. A requested version the
/// Marketplace does not list is left undated.
pub(crate) fn lookup(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let path = c.bare_name(&[])?;
    let id = if path.bytes().all(|b| b.is_ascii_digit()) {
        path.to_string()
    } else {
        let search: PluginSearch = fetch_json(
            &format!("{API}/searchPlugins?search={path}&max=20"),
            net,
            cache,
        )?;
        let Some(hit) = search
            .plugins
            .iter()
            .find(|p| p.xml_id.as_deref() == Some(c.name()))
        else {
            tracing::debug!(xml_id = %c.name().escape_debug(), "no JetBrains plugin has this xmlId");
            return Err(RegistryError::NotFound);
        };
        hit.id.to_string()
    };
    let doc: Plugin = fetch_json(&format!("{API}/plugins/{id}"), net, cache)?;
    let url = match c.encoded_version() {
        Some(v) => format!("{API}/plugins/{id}/updates?version={v}"),
        None => format!("{API}/plugins/{id}/updates?size=1"),
    };
    let update = optional(fetch_json::<Vec<PluginUpdate>>(&url, net, cache), &url)
        .unwrap_or_default()
        .into_iter()
        .find(|u| c.version().is_none_or(|v| u.version.as_deref() == Some(v)));
    if update.is_none() {
        tracing::debug!(url, "no JetBrains update for this release; undated");
    }
    let update = update.unwrap_or_default();
    let urls = doc.urls.unwrap_or_default();

    let mut registry = Registry::new(
        Ecosystem::Jetbrains,
        doc.xml_id.unwrap_or_else(|| c.name().to_string()),
    );
    registry.version = c.target(update.version.as_deref()).to_string();
    registry.published_at = update
        .cdate
        .and_then(|cdate| match cdate {
            Millis::Text(s) => s.parse().ok(),
            Millis::Number(n) => Some(n),
        })
        .and_then(secs_from_millis);
    registry.author = doc.vendor.and_then(|vendor| match vendor {
        Vendor::Name(name) => Some(name),
        Vendor::Object { name } => name,
    });
    registry.title = doc.name;
    registry.description = doc.preview;
    registry.homepage = urls.url;
    registry.repository = urls.source_code_url;
    registry.downloads_total = doc.downloads;
    registry.rating = doc.rating.and_then(|r| five_star(r, 5.0));
    Ok(registry)
}

/// The Marketplace's plugin search results.
#[derive(Deserialize)]
struct PluginSearch {
    #[serde(default, deserialize_with = "null_default")]
    plugins: Vec<SearchHit>,
}

/// One plugin in the search results.
#[derive(Deserialize)]
struct SearchHit {
    id: u64,
    #[serde(rename = "xmlId")]
    xml_id: Option<String>,
}

/// A JetBrains Marketplace plugin listing.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Plugin {
    xml_id: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    name: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    preview: Option<String>,
    vendor: Option<Vendor>,
    urls: Option<PluginUrls>,
    downloads: Option<u64>,
    rating: Option<f64>,
}

/// A plugin's `vendor`: an object with a `name` in the live API, or a bare
/// name.
#[derive(Deserialize)]
#[serde(untagged)]
enum Vendor {
    Name(String),
    Object { name: Option<String> },
}

/// A plugin's links.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct PluginUrls {
    #[serde(deserialize_with = "non_empty")]
    url: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    source_code_url: Option<String>,
}

/// One released update of a plugin.
#[derive(Default, Deserialize)]
#[serde(default)]
struct PluginUpdate {
    version: Option<String>,
    cdate: Option<Millis>,
}

/// An epoch-milliseconds time, which JetBrains sends as a string or a number.
#[derive(Deserialize)]
#[serde(untagged)]
enum Millis {
    Text(String),
    Number(f64),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fetch::Fixtures;
    use filefacts::RefLocator;

    const PLUGIN: &str = "https://plugins.jetbrains.com/api/plugins/22407";

    fn lookup(purl: &str, net: &Fixtures) -> Result<Registry, RegistryError> {
        crate::registry::lookup(&RefLocator::Purl(purl.into()), net, &BlobCache::disabled())
    }

    fn net(updates_url: &str, updates: &serde_json::Value) -> Fixtures {
        let plugin = serde_json::json!({
            "id": 22407, "xmlId": "com.jetbrains.rust", "name": "Rust",
            "preview": "Rust support", "vendor": "JetBrains s.r.o.",
            "downloads": 1_964_675u64, "rating": 2.78,
            "urls": {"url": "", "sourceCodeUrl": "https://github.com/intellij-rust/intellij-rust"}
        });
        Fixtures::default()
            .with(PLUGIN, plugin.to_string().as_bytes())
            .with(updates_url, updates.to_string().as_bytes())
    }

    #[test]
    fn jetbrains_plugin_normalizes() {
        let updates = serde_json::json!([{"version": "262.8117.29", "cdate": "1619172000000"}]);
        let net = net(&format!("{PLUGIN}/updates?size=1"), &updates);
        let r = lookup("pkg:jetbrains/22407", &net).expect("registry");
        assert_eq!(r.ecosystem, Ecosystem::Jetbrains);
        assert_eq!(r.name, "com.jetbrains.rust");
        assert_eq!(r.version, "262.8117.29");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(r.author.as_deref(), Some("JetBrains s.r.o."));
        assert_eq!(r.homepage, None);
        assert_eq!(
            r.repository.as_deref(),
            Some("https://github.com/intellij-rust/intellij-rust")
        );
        assert_eq!(r.downloads_total, Some(1_964_675));
        assert_eq!(r.rating, Some(2.78));
    }

    #[test]
    fn the_requested_update_is_dated_or_nothing() {
        let updates = serde_json::json!([{"version": "232.10056", "cdate": 1_695_898_009_000u64}]);
        let net = net(&format!("{PLUGIN}/updates?version=232.10056"), &updates)
            .with(&format!("{PLUGIN}/updates?version=9.9.9"), b"[]");
        let r = lookup("pkg:jetbrains/22407@232.10056", &net).expect("registry");
        assert_eq!(r.version, "232.10056");
        assert_eq!(r.published_at, Some(1_695_898_009));

        let r = lookup("pkg:jetbrains/22407@9.9.9", &net).expect("registry");
        assert_eq!(r.version, "9.9.9");
        assert_eq!(r.published_at, None);
    }

    #[test]
    fn a_negative_or_unreachable_update_time_is_unknown() {
        let updates = serde_json::json!([{"version": "1.0", "cdate": "-1000"}]);
        let r = lookup(
            "pkg:jetbrains/22407",
            &net(&format!("{PLUGIN}/updates?size=1"), &updates),
        )
        .expect("registry");
        assert_eq!(r.published_at, None);

        // The listing stands without its updates.
        let net = net(&format!("{PLUGIN}/updates?size=1"), &updates)
            .refusing(&format!("{PLUGIN}/updates?size=1"), 503);
        let r = lookup("pkg:jetbrains/22407", &net).expect("registry");
        assert_eq!(r.version, "");
        assert_eq!(r.published_at, None);
        assert_eq!(r.title.as_deref(), Some("Rust"));
    }

    #[test]
    fn an_xml_id_resolves_through_search() {
        let search = serde_json::json!({"plugins": [
            {"id": 1, "xmlId": "com.jetbrains.rust.fake"},
            {"id": 22407, "xmlId": "com.jetbrains.rust"}
        ]});
        let updates = serde_json::json!([]);
        let net = net(&format!("{PLUGIN}/updates?size=1"), &updates).with(
            "https://plugins.jetbrains.com/api/searchPlugins?search=com.jetbrains.rust&max=20",
            search.to_string().as_bytes(),
        );
        let r = lookup("pkg:jetbrains/com.jetbrains.rust", &net).expect("registry");
        assert_eq!(r.title.as_deref(), Some("Rust"));
        let missing = Fixtures::default().with(
            "https://plugins.jetbrains.com/api/searchPlugins?search=nope&max=20",
            br#"{"plugins": []}"#,
        );
        assert_eq!(
            lookup("pkg:jetbrains/nope", &missing),
            Err(RegistryError::NotFound)
        );
    }
}
