//! WordPress plugins: registry metadata.

use filefacts::{Ecosystem, Registry};
use serde::Deserialize;

use crate::ecosystem::{
    Coordinates, civil_secs, decode_entities, fetch_json, five_star, non_empty, release_time,
    strip_html,
};
use crate::fetch::{BlobCache, Fetch};
use crate::registry::RegistryError;

/// Look up the plugin `c` names in the plugin directory: installs, rating, the
/// author, when the plugin was added, and when its current version was
/// published. A requested version other than the current one is left undated.
pub(crate) fn lookup(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let slug = c.bare_name(&[])?;
    let doc: PluginInfo = fetch_json(
        &format!("https://api.wordpress.org/plugins/info/1.0/{slug}.json"),
        net,
        cache,
    )?;
    let mut record = c.record(
        Ecosystem::Wordpress,
        doc.slug.unwrap_or_else(|| c.name().to_string()),
        doc.version,
    );
    // `last_updated` dates the current version only.
    record.published_at = release_time(
        &record,
        record.latest_version.as_deref(),
        doc.last_updated.as_deref().and_then(utc_date),
    );
    record.first_published_at = doc.added.as_deref().and_then(utc_date);
    // The directory wraps the author in an `<a>`, and escapes text as HTML.
    record.author = doc
        .author
        .as_deref()
        .map(strip_html)
        .filter(|a| !a.is_empty());
    record.title = doc.name.as_deref().map(decode_entities);
    record.homepage = doc.homepage;
    record.downloads_total = doc.downloaded;
    // The directory reports rating as a 0–100 percentage.
    record.rating = doc.rating.and_then(|r| five_star(r, 100.0));
    record.rating_count = doc.num_ratings;
    Ok(record)
}

/// Unix seconds at UTC midnight of the date a directory timestamp starts with
/// (`2026-04-23` of `2026-04-23 10:34pm GMT`, or a bare `2005-10-20`): the
/// day is what it dates, in UTC. `None` unless that is a real `YYYY-MM-DD`.
fn utc_date(timestamp: &str) -> Option<u64> {
    let date = timestamp
        .split_once(' ')
        .map_or(timestamp, |(date, _)| date);
    let mut fields = date.split('-').map(|field| {
        field
            .bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| field.parse().ok())?
    });
    let (year, month, day) = (fields.next()??, fields.next()??, fields.next()??);
    if fields.next().is_some() {
        return None;
    }
    civil_secs(year, month, day)
}

/// A WordPress plugin-directory info document.
#[derive(Default, Deserialize)]
#[serde(default)]
struct PluginInfo {
    #[serde(deserialize_with = "non_empty")]
    slug: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    version: Option<String>,
    last_updated: Option<String>,
    added: Option<String>,
    author: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    name: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    homepage: Option<String>,
    downloaded: Option<u64>,
    rating: Option<f64>,
    num_ratings: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::look;
    use crate::fetch::Fixtures;

    const AKISMET: &str = "https://api.wordpress.org/plugins/info/1.0/akismet.json";

    /// The record for `purl` when the directory answers `doc` for akismet.
    fn answering(purl: &str, doc: &serde_json::Value) -> Result<Registry, RegistryError> {
        let net = Fixtures::default().with(AKISMET, doc.to_string().as_bytes());
        look(purl, &net)
    }

    fn akismet(last_updated: &str) -> serde_json::Value {
        serde_json::json!({
            "name": "Akismet Anti-spam", "slug": "akismet", "version": "5.7",
            "author": "<a href=\"https://profiles.wordpress.org/automattic/\">Automattic</a>",
            "homepage": "https://akismet.com/", "last_updated": last_updated,
            "added": "2005-10-20",
            "downloaded": 395_330_422u64, "rating": 94, "num_ratings": 1184
        })
    }

    #[test]
    fn wordpress_plugin_normalizes() {
        let r = answering("pkg:wordpress/akismet", &akismet("2021-04-23 10:34pm GMT"))
            .expect("registry");
        assert_eq!(r.ecosystem, Ecosystem::Wordpress);
        assert_eq!(r.version, "5.7");
        assert_eq!(r.author.as_deref(), Some("Automattic"));
        assert_eq!(r.published_at, Some(1_619_136_000)); // date floored to UTC midnight
        assert_eq!(r.first_published_at, Some(1_129_766_400)); // 2005-10-20
        assert_eq!(r.downloads_total, Some(395_330_422));
        assert_eq!(r.rating, Some(4.7));
        assert_eq!(r.rating_count, Some(1184));
    }

    #[test]
    fn an_impossible_or_malformed_date_is_unknown() {
        for bad in [
            "2021-02-31 10:34pm GMT",
            "2021-13-01 10:34pm GMT",
            "+021-04-23 10:34pm GMT",
            "2021-04-234 10:34pm GMT",
            "2021-04 10:34pm GMT",
            "garbage",
        ] {
            let r = answering("pkg:wordpress/akismet", &akismet(bad)).expect("registry");
            assert_eq!(r.published_at, None, "{bad}");
        }
    }

    #[test]
    fn an_off_scale_rating_is_unknown() {
        let mut doc = akismet("2021-04-23 10:34pm GMT");
        doc["rating"] = serde_json::json!(140);
        assert_eq!(
            answering("pkg:wordpress/akismet", &doc)
                .expect("registry")
                .rating,
            None
        );
    }

    #[test]
    fn only_the_current_version_is_dated() {
        let doc = akismet("2021-04-23 10:34pm GMT");
        let r = answering("pkg:wordpress/akismet@5.7", &doc).expect("registry");
        assert_eq!(r.published_at, Some(1_619_136_000));
        let r = answering("pkg:wordpress/akismet@4.0", &doc).expect("registry");
        assert_eq!(r.version, "4.0");
        assert_eq!(r.latest_version.as_deref(), Some("5.7"));
        assert_eq!(r.published_at, None);
    }

    #[test]
    fn escaped_directory_text_is_decoded() {
        let mut doc = akismet("2021-04-23 10:34pm GMT");
        doc["name"] = serde_json::json!("Spam &amp; Abuse &#8211; Filter");
        doc["author"] = serde_json::json!("<a href=\"x\">Smith &amp; Sons &lt;dev&gt;</a>");
        let r = answering("pkg:wordpress/akismet", &doc).expect("registry");
        assert_eq!(r.title.as_deref(), Some("Spam & Abuse \u{2013} Filter"));
        assert_eq!(r.author.as_deref(), Some("Smith & Sons <dev>"));
    }
}
