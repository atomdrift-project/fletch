//! The JetBrains Marketplace: registry metadata.

use filefacts::{Ecosystem, Registry};
use serde::Deserialize;

use crate::ecosystem::{
    Coordinates, Person, fetch_json, five_star, lenient, non_empty, null_default, optional,
    secs_from_millis,
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
        let Some(id) = search
            .plugins
            .iter()
            .filter(|p| p.xml_id.as_deref() == Some(c.name()))
            .find_map(|p| p.id)
        else {
            tracing::debug!(xml_id = %c.name().escape_debug(), "no JetBrains plugin has this xmlId");
            return Err(RegistryError::NotFound);
        };
        id.to_string()
    };
    let doc: Plugin = fetch_json(&format!("{API}/plugins/{id}"), net, cache)?;
    let url = match c.encoded_version() {
        Some(v) => format!("{API}/plugins/{id}/updates?version={v}"),
        None => format!("{API}/plugins/{id}/updates?size=1"),
    };
    let update = optional(fetch_json::<Vec<PluginUpdate>>(&url, net, cache), &url)
        .unwrap_or_default()
        .into_iter()
        .find(|u| c.version().is_none_or(|v| u.version.as_deref() == Some(v)))
        .unwrap_or_else(|| {
            tracing::debug!(url, "no JetBrains update for this release; undated");
            PluginUpdate::default()
        });
    let urls = doc.urls.unwrap_or_default();

    // Only the versionless query asks for the latest update.
    let latest = update.version.filter(|_| c.version().is_none());
    let mut record = c.record(
        Ecosystem::Jetbrains,
        doc.xml_id.unwrap_or_else(|| c.name().to_string()),
        latest,
    );
    record.published_at = update
        .cdate
        .and_then(|cdate| match cdate {
            Millis::Text(s) => s.parse().ok(),
            Millis::Number(n) => Some(n),
        })
        .and_then(secs_from_millis);
    record.author = doc
        .vendor
        .as_ref()
        .and_then(Person::name)
        .map(str::to_string);
    record.title = doc.name;
    record.description = doc.preview;
    record.homepage = urls.url;
    record.repository = urls.source_code_url;
    record.downloads_total = doc.downloads;
    record.rating = doc.rating.and_then(|r| five_star(r, 5.0));
    Ok(record)
}

/// The Marketplace's plugin search results.
#[derive(Deserialize)]
struct PluginSearch {
    #[serde(default, deserialize_with = "null_default")]
    plugins: Vec<SearchHit>,
}

/// One plugin in the search results. A hit without a numeric id costs that
/// hit, never the search.
#[derive(Default, Deserialize)]
#[serde(default)]
struct SearchHit {
    #[serde(deserialize_with = "lenient")]
    id: Option<u64>,
    #[serde(rename = "xmlId", deserialize_with = "lenient")]
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
    /// An object with a `name` in the live API, or a bare name.
    #[serde(deserialize_with = "lenient")]
    vendor: Option<Person>,
    urls: Option<PluginUrls>,
    downloads: Option<u64>,
    rating: Option<f64>,
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
    use crate::ecosystem::look;
    use crate::fetch::Fixtures;

    const PLUGIN: &str = "https://plugins.jetbrains.com/api/plugins/22407";

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
        let r = look("pkg:jetbrains/22407", &net).expect("registry");
        assert_eq!(r.ecosystem, Ecosystem::Jetbrains);
        assert_eq!(r.name, "com.jetbrains.rust");
        assert_eq!(r.version, "262.8117.29");
        assert_eq!(r.latest_version.as_deref(), Some("262.8117.29"));
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
        let r = look("pkg:jetbrains/22407@232.10056", &net).expect("registry");
        assert_eq!(r.version, "232.10056");
        assert_eq!(r.published_at, Some(1_695_898_009));

        let r = look("pkg:jetbrains/22407@9.9.9", &net).expect("registry");
        assert_eq!(r.version, "9.9.9");
        assert_eq!(r.published_at, None);
    }

    #[test]
    fn a_negative_or_unreachable_update_time_is_unknown() {
        let updates = serde_json::json!([{"version": "1.0", "cdate": "-1000"}]);
        let r = look(
            "pkg:jetbrains/22407",
            &net(&format!("{PLUGIN}/updates?size=1"), &updates),
        )
        .expect("registry");
        assert_eq!(r.published_at, None);

        // The listing stands without its updates.
        let net = net(&format!("{PLUGIN}/updates?size=1"), &updates)
            .refusing(&format!("{PLUGIN}/updates?size=1"), 503);
        let r = look("pkg:jetbrains/22407", &net).expect("registry");
        assert_eq!(r.version, "");
        assert_eq!(r.published_at, None);
        assert_eq!(r.title.as_deref(), Some("Rust"));
    }

    #[test]
    fn an_xml_id_resolves_through_search() {
        // A malformed hit costs that hit, not the search.
        let search = serde_json::json!({"plugins": [
            {"id": "not-a-number", "xmlId": "com.jetbrains.rust"},
            {"id": 1, "xmlId": "com.jetbrains.rust.fake"},
            {"xmlId": null},
            {"id": 22407, "xmlId": "com.jetbrains.rust"}
        ]});
        let updates = serde_json::json!([]);
        let net = net(&format!("{PLUGIN}/updates?size=1"), &updates).with(
            "https://plugins.jetbrains.com/api/searchPlugins?search=com.jetbrains.rust&max=20",
            search.to_string().as_bytes(),
        );
        let r = look("pkg:jetbrains/com.jetbrains.rust", &net).expect("registry");
        assert_eq!(r.title.as_deref(), Some("Rust"));
        let missing = Fixtures::default().with(
            "https://plugins.jetbrains.com/api/searchPlugins?search=nope&max=20",
            br#"{"plugins": []}"#,
        );
        assert_eq!(
            look("pkg:jetbrains/nope", &missing),
            Err(RegistryError::NotFound)
        );
    }
}
