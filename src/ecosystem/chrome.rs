//! The Chrome Web Store: registry metadata and artifact resolution.

use filefacts::Registry;

use crate::ecosystem::days_from_civil;
use crate::fetch::{BlobCache, Fetch, cached_metadata_status};
use crate::registry::RegistryError;

/// Chrome Web Store: the listing has no JSON API, so scrape the public detail
/// page. The signals that matter for an extension — what it claims to do (the
/// developer's own description), how far it reaches (user count), how it's
/// rated, and when it last changed — are all rendered into the HTML. Best-effort
/// by design: a field that moves in the markup degrades to "unknown", never a
/// wrong value.
pub(crate) fn chrome(
    id: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let url = format!("https://chromewebstore.google.com/detail/{id}");
    let bytes = cached_metadata_status(&url, &[], net, cache)?;
    let html = std::str::from_utf8(&bytes).map_err(|e| RegistryError::Malformed {
        url: url.clone(),
        reason: e.to_string(),
    })?;

    // og:title carries the listing name with a `- Chrome Web Store` suffix.
    let title = meta_content(html, "og:title")
        .map(|t| t.trim_end_matches(" - Chrome Web Store").trim().to_string());

    Ok(Registry {
        ecosystem: "chrome".into(),
        name: id.to_string(),
        version: String::new(),
        // "Updated <Month D, YYYY>" is the listing's last-change date.
        published_at: text_after(html, "Updated").and_then(|s| parse_month_day_year(&s)),
        author: text_after(html, "Offered by"),
        title,
        description: meta_content(html, "og:description"),
        homepage: Some(url),
        // "N,NNN users" — the store's reach figure, a downloads analogue.
        downloads_total: before(html, " users").and_then(parse_grouped_u64),
        // "X out of 5 stars" / "N ratings".
        rating: before(html, " out of 5 stars").and_then(|s| s.parse::<f32>().ok()),
        rating_count: before(html, " ratings").and_then(parse_grouped_u64),
        ..Default::default()
    })
}

/// Extract a `<meta property="og:NAME" content="VALUE">` value.
fn meta_content(html: &str, property: &str) -> Option<String> {
    let anchor = format!("property=\"{property}\" content=\"");
    let start = html.find(&anchor)? + anchor.len();
    let rest = &html[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// The first non-empty text run *after* `marker`, skipping any intervening
/// tags — for label/value pairs the markup splits across elements, like
/// `Updated</div><div>June 9, 2026</div>` → `June 9, 2026`.
fn text_after(html: &str, marker: &str) -> Option<String> {
    let start = html.find(marker)? + marker.len();
    let mut in_tag = false;
    let mut out = String::new();
    for c in html[start..].chars().take(400) {
        match c {
            '<' => {
                if !out.trim().is_empty() {
                    break;
                }
                in_tag = true;
            }
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    let trimmed = out.trim().to_string();
    (!trimmed.is_empty()).then_some(trimmed)
}

/// The token immediately *before* `marker` — for `N users`, `4.9 out of 5
/// stars`, `122 ratings`: walk back over the value characters.
fn before<'a>(html: &'a str, marker: &str) -> Option<&'a str> {
    let head = &html[..html.find(marker)?];
    // Every character in the run is ASCII, so the count is also its byte
    // width — which makes the split point a valid `str` boundary.
    let width = head
        .chars()
        .rev()
        .take_while(|&c| c.is_ascii_digit() || matches!(c, '.' | ','))
        .count();
    Some(&head[head.len() - width..]).filter(|s| !s.is_empty())
}

/// Parse a thousands-grouped count like `40,000` to `u64`.
fn parse_grouped_u64(s: &str) -> Option<u64> {
    s.replace(',', "").parse().ok()
}

/// Parse a US-style `Month D, YYYY` (`June 9, 2026`) to Unix seconds at UTC
/// midnight. `None` on anything unrecognized.
fn parse_month_day_year(s: &str) -> Option<u64> {
    let s = s.trim();
    let (month_name, rest) = s.split_once(' ')?;
    let month = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ]
    .iter()
    .position(|m| m.eq_ignore_ascii_case(month_name))? as i64
        + 1;
    let (day, year) = rest.split_once(',')?;
    let day: i64 = day.trim().parse().ok()?;
    let year: i64 = year.trim().parse().ok()?;
    u64::try_from(days_from_civil(year, month, day) * 86_400).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::fetch::{BlobCache, Fixtures};

    #[test]
    fn month_day_year_parses() {
        // 1970-01-01 is the epoch; June 9, 2026 is 20613 days later.
        assert_eq!(parse_month_day_year("January 1, 1970"), Some(0));
        assert_eq!(parse_month_day_year("June 9, 2026"), Some(1_780_963_200));
        assert_eq!(parse_month_day_year("not a date"), None);
    }

    #[test]
    fn html_scrape_helpers() {
        let html = r#"<meta property="og:title" content="社媒助手 - Chrome Web Store">
            <span>40,000 users</span><div>4.9 out of 5 stars</div>
            <div class="x">Updated</div><div>June 9, 2026</div>"#;
        assert_eq!(
            meta_content(html, "og:title").as_deref(),
            Some("社媒助手 - Chrome Web Store")
        );
        assert_eq!(
            before(html, " users").and_then(parse_grouped_u64),
            Some(40_000)
        );
        assert_eq!(
            before(html, " out of 5 stars").and_then(|s| s.parse::<f32>().ok()),
            Some(4.9)
        );
        // The value is split across tags after the marker.
        assert_eq!(text_after(html, "Updated").as_deref(), Some("June 9, 2026"));
    }

    #[test]
    fn chrome_listing_normalizes() {
        let id = "dbichmdlbjdeplpkhcejgkakobjbjalc";
        let html = r#"<meta property="og:title" content="社媒助手 - 数据采集工具 - Chrome Web Store">
               <meta property="og:description" content="小红书、抖音等社媒平台数据采集工具，批量导出数据">
               <span>40,000 users</span><div>4.9 out of 5 stars</div><div>122 ratings</div>
               <div>Updated</div><div>June 9, 2026</div>"#.to_string();
        let net = Fixtures::default().with(
            &format!("https://chromewebstore.google.com/detail/{id}"),
            html.as_bytes(),
        );
        let cache = BlobCache::disabled();
        let r = chrome(id, &net, &cache).expect("registry");
        assert_eq!(r.ecosystem, "chrome");
        assert_eq!(r.title.as_deref(), Some("社媒助手 - 数据采集工具"));
        assert_eq!(r.downloads_total, Some(40_000));
        assert_eq!(r.rating, Some(4.9));
        assert_eq!(r.rating_count, Some(122));
        assert_eq!(r.published_at, Some(1_780_963_200));
        assert!(r.description.is_some_and(|d| d.contains("数据采集")));
    }
}
