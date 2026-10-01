//! The JetBrains Marketplace: registry metadata and artifact resolution.

use filefacts::Registry;
use serde::Deserialize;

use crate::ecosystem::fetch_json;
use crate::fetch::{BlobCache, Fetch};
use crate::registry::RegistryError;

/// JetBrains Marketplace: resolve the plugin id (numeric, or an `xmlId` via
/// search), then read its listing plus latest update — the same marketplace
/// shape as the editor stores (rating, downloads, the update's publish date).
pub(crate) fn jetbrains(
    path: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    // A numeric path is the plugin id directly; otherwise resolve the xmlId.
    let id = if !path.is_empty() && path.bytes().all(|b| b.is_ascii_digit()) {
        path.to_string()
    } else {
        let search: PluginSearch = fetch_json(
            &format!("https://plugins.jetbrains.com/api/searchPlugins?search={path}&max=20"),
            net,
            cache,
        )?;
        search
            .plugins
            .iter()
            .find(|p| p.xml_id.as_deref() == Some(path))
            .ok_or(RegistryError::NotFound)?
            .id
            .to_string()
    };
    let doc: Plugin = fetch_json(
        &format!("https://plugins.jetbrains.com/api/plugins/{id}"),
        net,
        cache,
    )?;
    // The latest update carries the released version and its publish time.
    let updates = fetch_json::<Vec<PluginUpdate>>(
        &format!("https://plugins.jetbrains.com/api/plugins/{id}/updates?size=1"),
        net,
        cache,
    )
    .ok();
    let update = updates.as_ref().and_then(|u| u.first());
    let urls = doc.urls.unwrap_or_default();

    Ok(Registry {
        ecosystem: "jetbrains".into(),
        name: doc.xml_id.unwrap_or_else(|| path.to_string()),
        version: update.and_then(|u| u.version.clone()).unwrap_or_default(),
        // Unix millis, a JSON string or number as JetBrains emits it.
        published_at: update
            .and_then(|u| u.cdate.as_ref())
            .and_then(|cdate| match cdate {
                Millis::Text(s) => s.parse::<u64>().ok(),
                Millis::Number(n) => Some(*n),
            })
            .map(|ms| ms / 1000),
        // `vendor` is an object (`{name, …}`) in the live API; a bare name is
        // read too.
        author: doc.vendor.and_then(|vendor| match vendor {
            Vendor::Name(name) => Some(name),
            Vendor::Object { name } => name,
        }),
        title: doc.name,
        description: doc.preview,
        homepage: urls.url.filter(|s| !s.is_empty()),
        repository: urls.source_code_url.filter(|s| !s.is_empty()),
        downloads_total: doc.downloads,
        rating: doc.rating.map(|f| f as f32),
        ..Default::default()
    })
}

/// The Marketplace's plugin search results.
#[derive(Deserialize)]
struct PluginSearch {
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
    name: Option<String>,
    preview: Option<String>,
    vendor: Option<Vendor>,
    urls: Option<PluginUrls>,
    downloads: Option<u64>,
    rating: Option<f64>,
}

/// A plugin's `vendor`: a bare name, or an object with a `name`.
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
    url: Option<String>,
    source_code_url: Option<String>,
}

/// One released update of a plugin.
#[derive(Default, Deserialize)]
#[serde(default)]
struct PluginUpdate {
    version: Option<String>,
    cdate: Option<Millis>,
}

/// A Unix-millis timestamp, which JetBrains sends as a string or a number.
#[derive(Deserialize)]
#[serde(untagged)]
enum Millis {
    Text(String),
    Number(u64),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::test_cache;

    use crate::fetch::Fixtures;

    #[test]
    fn jetbrains_plugin_normalizes() {
        let plugin = serde_json::json!({
            "id": 22407, "xmlId": "com.jetbrains.rust", "name": "Rust",
            "preview": "Rust support", "vendor": "JetBrains s.r.o.",
            "downloads": 1_964_675u64, "rating": 2.78,
            "urls": {"url": "", "sourceCodeUrl": "https://github.com/intellij-rust/intellij-rust"}
        })
        .to_string();
        let updates = serde_json::json!([
            {"version": "262.8117.29", "cdate": "1619172000000"}
        ])
        .to_string();
        let net = Fixtures::default()
            .with(
                "https://plugins.jetbrains.com/api/plugins/22407",
                plugin.as_bytes(),
            )
            .with(
                "https://plugins.jetbrains.com/api/plugins/22407/updates?size=1",
                updates.as_bytes(),
            );
        let r = jetbrains("22407", &net, &test_cache("jetbrains")).expect("registry");
        assert_eq!(r.ecosystem, "jetbrains");
        assert_eq!(r.name, "com.jetbrains.rust");
        assert_eq!(r.version, "262.8117.29");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(r.author.as_deref(), Some("JetBrains s.r.o."));
        assert_eq!(
            r.repository.as_deref(),
            Some("https://github.com/intellij-rust/intellij-rust")
        );
        assert_eq!(r.downloads_total, Some(1_964_675));
    }
}
