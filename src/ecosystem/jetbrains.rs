//! The JetBrains Marketplace: registry metadata and artifact resolution.

use filefacts::Registry;
use serde_json::Value;

use crate::ecosystem::json_meta;
use crate::fetch::{BlobCache, Fetch};

/// JetBrains Marketplace: resolve the plugin id (numeric, or an `xmlId` via
/// search), then read its listing plus latest update — the same marketplace
/// shape as the editor stores (rating, downloads, the update's publish date).
pub(crate) fn jetbrains(path: &str, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    // A numeric path is the plugin id directly; otherwise resolve the xmlId.
    let id = if !path.is_empty() && path.bytes().all(|b| b.is_ascii_digit()) {
        path.to_string()
    } else {
        let search = json_meta(
            &format!("https://plugins.jetbrains.com/api/searchPlugins?search={path}&max=20"),
            net,
            cache,
        )?;
        search
            .get("plugins")
            .and_then(Value::as_array)?
            .iter()
            .find(|p| p.get("xmlId").and_then(Value::as_str) == Some(path))
            .and_then(|p| p.get("id"))
            .and_then(Value::as_u64)?
            .to_string()
    };
    let doc = json_meta(
        &format!("https://plugins.jetbrains.com/api/plugins/{id}"),
        net,
        cache,
    )?;
    // The latest update carries the released version and its publish time.
    let updates = json_meta(
        &format!("https://plugins.jetbrains.com/api/plugins/{id}/updates?size=1"),
        net,
        cache,
    );
    let update = updates
        .as_ref()
        .and_then(|u| u.as_array())
        .and_then(|a| a.first());

    Some(Registry {
        ecosystem: "jetbrains".into(),
        name: doc
            .get("xmlId")
            .and_then(Value::as_str)
            .unwrap_or(path)
            .to_string(),
        version: update
            .and_then(|u| u.get("version"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        published_at: update.and_then(|u| u.get("cdate")).and_then(parse_millis),
        // `vendor` is a bare string here, an object in search results.
        author: doc.get("vendor").and_then(|v| {
            v.as_str()
                .map(str::to_string)
                .or_else(|| v.get("name").and_then(Value::as_str).map(str::to_string))
        }),
        title: doc.get("name").and_then(Value::as_str).map(str::to_string),
        description: doc
            .get("preview")
            .and_then(Value::as_str)
            .map(str::to_string),
        homepage: doc
            .pointer("/urls/url")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        repository: doc
            .pointer("/urls/sourceCodeUrl")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        downloads_total: doc.get("downloads").and_then(Value::as_u64),
        rating: doc.get("rating").and_then(Value::as_f64).map(|f| f as f32),
        ..Default::default()
    })
}

/// Unix-millis (a JSON string or number, as JetBrains emits) → Unix seconds.
fn parse_millis(v: &Value) -> Option<u64> {
    let ms = match v {
        Value::String(s) => s.parse::<u64>().ok()?,
        Value::Number(n) => n.as_u64()?,
        _ => return None,
    };
    Some(ms / 1000)
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
