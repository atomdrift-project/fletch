//! WordPress plugins: registry metadata and artifact resolution.

use filefacts::Registry;
use serde::Deserialize;

use crate::ecosystem::{fetch_json, parse_rfc3339_secs};
use crate::fetch::{BlobCache, Fetch};
use crate::registry::RegistryError;

/// WordPress plugin directory: the info API carries installs, rating (0–100),
/// the author (as an HTML anchor), and the last-updated date.
pub(crate) fn wordpress(
    slug: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let doc: PluginInfo = fetch_json(
        &format!("https://api.wordpress.org/plugins/info/1.0/{slug}.json"),
        net,
        cache,
    )?;

    Ok(Registry {
        ecosystem: "wordpress".into(),
        name: doc.slug.unwrap_or_else(|| slug.to_string()),
        version: doc.version.unwrap_or_default(),
        // `last_updated` is `2026-04-23 10:34pm GMT`; keep the date.
        published_at: doc
            .last_updated
            .as_deref()
            .and_then(|s| parse_rfc3339_secs(&format!("{}T00:00:00Z", s.get(..10)?))),
        author: doc.author.as_deref().map(strip_html),
        title: doc.name,
        homepage: doc.homepage.filter(|s| !s.is_empty()),
        downloads_total: doc.downloaded,
        // The directory reports rating as a 0–100 percentage; scale to 5 stars.
        rating: doc.rating.map(|r| (r / 20.0) as f32),
        rating_count: doc.num_ratings,
        ..Default::default()
    })
}

/// A WordPress plugin-directory info document.
#[derive(Default, Deserialize)]
#[serde(default)]
struct PluginInfo {
    slug: Option<String>,
    version: Option<String>,
    last_updated: Option<String>,
    author: Option<String>,
    name: Option<String>,
    homepage: Option<String>,
    downloaded: Option<u64>,
    rating: Option<f64>,
    num_ratings: Option<u64>,
}

/// Drop HTML tags from a one-line field (WordPress wraps the author in an `<a>`).
fn strip_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::test_cache;

    use crate::fetch::Fixtures;

    #[test]
    fn wordpress_plugin_normalizes() {
        let doc = serde_json::json!({
            "name": "Akismet Anti-spam", "slug": "akismet", "version": "5.7",
            "author": "<a href=\"https://profiles.wordpress.org/automattic/\">Automattic</a>",
            "homepage": "https://akismet.com/", "last_updated": "2021-04-23 10:34pm GMT",
            "downloaded": 395_330_422u64, "rating": 94, "num_ratings": 1184
        })
        .to_string();
        let net = Fixtures::default().with(
            "https://api.wordpress.org/plugins/info/1.0/akismet.json",
            doc.as_bytes(),
        );
        let r = wordpress("akismet", &net, &test_cache("wordpress")).expect("registry");
        assert_eq!(r.ecosystem, "wordpress");
        assert_eq!(r.version, "5.7");
        assert_eq!(r.author.as_deref(), Some("Automattic"));
        assert_eq!(r.published_at, Some(1_619_136_000)); // date floored to UTC midnight
        assert_eq!(r.downloads_total, Some(395_330_422));
        assert_eq!(r.rating, Some(4.7));
        assert_eq!(r.rating_count, Some(1184));
    }
}
