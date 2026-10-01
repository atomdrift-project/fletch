//! WordPress plugins: registry metadata and artifact resolution.

use filefacts::Registry;
use serde_json::Value;

use crate::ecosystem::{json_meta, parse_rfc3339_secs};
use crate::fetch::{BlobCache, Fetch};

/// WordPress plugin directory: the info API carries installs, rating (0–100),
/// the author (as an HTML anchor), and the last-updated date.
pub(crate) fn wordpress(slug: &str, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    let doc = json_meta(
        &format!("https://api.wordpress.org/plugins/info/1.0/{slug}.json"),
        net,
        cache,
    )?;

    Some(Registry {
        ecosystem: "wordpress".into(),
        name: doc
            .get("slug")
            .and_then(Value::as_str)
            .unwrap_or(slug)
            .to_string(),
        version: doc
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        // `last_updated` is `2026-04-23 10:34pm GMT`; keep the date.
        published_at: doc
            .get("last_updated")
            .and_then(Value::as_str)
            .and_then(|s| parse_rfc3339_secs(&format!("{}T00:00:00Z", s.get(..10)?))),
        author: doc.get("author").and_then(Value::as_str).map(strip_html),
        title: doc.get("name").and_then(Value::as_str).map(str::to_string),
        homepage: doc
            .get("homepage")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        downloads_total: doc.get("downloaded").and_then(Value::as_u64),
        // The directory reports rating as a 0–100 percentage; scale to 5 stars.
        rating: doc
            .get("rating")
            .and_then(Value::as_f64)
            .map(|r| (r / 20.0) as f32),
        rating_count: doc.get("num_ratings").and_then(Value::as_u64),
        ..Default::default()
    })
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
