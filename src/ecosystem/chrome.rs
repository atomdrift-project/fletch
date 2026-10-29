//! The Chrome Web Store: registry metadata, read from the public listing
//! page (the store has no JSON API).

use filefacts::Registry;

use crate::ecosystem::{Coordinates, civil_secs, five_star};
use crate::fetch::{BlobCache, Fetch, cached_metadata_status};
use crate::registry::RegistryError;

/// The heading of the details section the store renders after the
/// developer's overview.
const DETAILS: &str = ">Details</h2>";

/// Look up the extension `c` names from its listing page: what it claims to be
/// (title and summary), how far it reaches (users), how it is rated, which
/// version is current, when that version was published, and who offers it.
///
/// Most of the page is the developer's own text, so a figure counts only when
/// it sits where the store writes it. The store HTML-escapes everything the
/// developer writes, so no developer text contains a tag, and a marker that
/// includes one is the store's own. The page renders the title as `<h1>`,
/// then the store's header (rating, rating count, users), then the
/// developer's overview under the first `<h2>`, then the store's details
/// under [`DETAILS`] (version, update date, publisher). The header figures are
/// read between `</h1>` and the first `</h2>`, with the developer's title and
/// summary (repeated there in captions) removed; the details are read after
/// [`DETAILS`], where the first label of each kind is the store's (the only
/// value before them is the version, digits and dots). A page without that
/// markup yields unknown figures, never figures read from the overview.
pub(crate) fn lookup(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let url = format!(
        "https://chromewebstore.google.com/detail/{}",
        c.encoded_name()
    );
    let bytes = cached_metadata_status(&url, &[], net, cache)?;
    let html = std::str::from_utf8(&bytes).map_err(|e| RegistryError::Malformed {
        url: url.clone(),
        reason: e.to_string(),
    })?;

    // og:title carries the listing name with a `- Chrome Web Store` suffix.
    let title = meta_content(html, "og:title")
        .map(|t| t.trim_end_matches(" - Chrome Web Store").trim().to_string());
    let description = meta_content(html, "og:description");
    let header = header(html, [title.as_deref(), description.as_deref()]);
    let details = html.find(DETAILS).map(|at| &html[at + DETAILS.len()..]);
    if header.is_none() || details.is_none() {
        tracing::debug!(
            url,
            header = header.is_some(),
            details = details.is_some(),
            "Chrome listing lacks the store's markup; its figures are unknown"
        );
    }
    let header = header.as_deref();

    let listed = details.and_then(|d| text_after(d, "Version"));
    let version = c.target(listed);
    // "Updated" dates the listed version only.
    let published_at = if listed == Some(version) {
        details
            .and_then(|d| text_after(d, "Updated"))
            .and_then(parse_month_day_year)
    } else {
        tracing::debug!(
            url,
            version = %version.escape_debug(),
            "release is not the version the listing names; undated"
        );
        None
    };

    Ok(Registry {
        ecosystem: "chrome".into(),
        name: c.name().to_string(),
        version: version.to_string(),
        published_at,
        author: details
            .and_then(|d| text_after(d, "Offered by"))
            .map(str::to_string),
        title,
        description,
        homepage: Some(url),
        // "N,NNN users": the store's reach figure, a downloads analogue.
        downloads_total: header
            .and_then(|h| before(h, " users"))
            .and_then(parse_grouped_u64),
        rating: header
            .and_then(|h| before(h, " out of 5 stars"))
            .and_then(|s| s.parse().ok())
            .and_then(|v| five_star(v, 5.0)),
        rating_count: header
            .and_then(|h| before(h, " ratings"))
            .and_then(parse_grouped_u64),
        ..Default::default()
    })
}

/// The store's listing header: the markup between the title's `</h1>` and the
/// first section heading's `</h2>`, with each of the developer's `written`
/// texts removed. `None` when the page lacks either tag.
fn header(html: &str, written: [Option<&str>; 2]) -> Option<String> {
    let start = html.find("</h1>")?;
    let end = start + html[start..].find("</h2>")?;
    let mut header = html[start..end].to_string();
    for text in written.into_iter().flatten().filter(|t| !t.is_empty()) {
        header = header.replace(text, "");
    }
    Some(header)
}

/// Extract a `<meta property="og:NAME" content="VALUE">` value.
fn meta_content(html: &str, property: &str) -> Option<String> {
    let anchor = format!("property=\"{property}\" content=\"");
    let start = html.find(&anchor)? + anchor.len();
    let rest = &html[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// The first non-empty text run after `marker`, skipping intervening tags:
/// for a label and value the markup splits across elements, like
/// `Updated</div><div>June 9, 2026</div>` → `June 9, 2026`.
fn text_after<'a>(html: &'a str, marker: &str) -> Option<&'a str> {
    let rest = &html[html.find(marker)? + marker.len()..];
    let mut pieces = rest.split('<');
    // The first piece is text; each later one is a tag, then the text after it.
    pieces
        .next()
        .into_iter()
        .chain(pieces.map(|piece| piece.split_once('>').map_or("", |(_, text)| text)))
        .map(str::trim)
        .find(|text| !text.is_empty())
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
/// midnight. `None` on anything unrecognized or a date that does not exist.
fn parse_month_day_year(s: &str) -> Option<u64> {
    const MONTHS: [&str; 12] = [
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
    ];
    let (month_name, rest) = s.trim().split_once(' ')?;
    let month = MONTHS
        .iter()
        .position(|m| m.eq_ignore_ascii_case(month_name))?;
    let (day, year) = rest.split_once(',')?;
    let number = |s: &str| {
        let s = s.trim();
        s.bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| s.parse().ok())?
    };
    civil_secs(number(year)?, i64::try_from(month).ok()? + 1, number(day)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fetch::Fixtures;
    use filefacts::RefLocator;

    const ID: &str = "dbichmdlbjdeplpkhcejgkakobjbjalc";

    /// A listing page in the store's layout: `head`, the title, the store's
    /// `header`, the developer's `overview`, and the store's `details`.
    fn page(head: &str, title: &str, header: &str, overview: &str, details: &str) -> String {
        format!(
            r#"<html><head>{head}</head><body><h1 class="Pa2dE">{title}</h1>{header}
            <section><h2 class="p9xg1"><div>Overview</div></h2><div>{overview}</div></section>
            <section><h2 class="p9xg1">Details</h2><ul>{details}</ul></section></body></html>"#
        )
    }

    const HEADER: &str = r#"<span aria-label="Average rating 2.1 out of 5 stars."><span>2.1</span></span>
        <a href="./reviews"><p>3 ratings</p></a><div><a>Extension</a>12 users</div>"#;

    const DETAILS_LIST: &str = r#"<li><div>Version</div><div>1.2.3</div></li>
        <li><div>Updated</div><div>June 9, 2026</div></li>
        <li><div><a>Flag concern</a></div></li>
        <li><div>Offered by</div><div>Good Dev</div></li>"#;

    fn lookup(purl: &str, html: &str) -> Result<Registry, RegistryError> {
        let net = Fixtures::default().with(
            &format!("https://chromewebstore.google.com/detail/{ID}"),
            html.as_bytes(),
        );
        crate::registry::lookup(&RefLocator::Purl(purl.into()), &net, &BlobCache::disabled())
    }

    #[test]
    fn month_day_year_parses() {
        // 1970-01-01 is the epoch; June 9, 2026 is 20613 days later.
        assert_eq!(parse_month_day_year("January 1, 1970"), Some(0));
        assert_eq!(parse_month_day_year("June 9, 2026"), Some(1_780_963_200));
        assert_eq!(parse_month_day_year("not a date"), None);
    }

    #[test]
    fn a_day_the_month_lacks_is_not_a_date() {
        assert_eq!(parse_month_day_year("February 31, 2026"), None);
        assert_eq!(parse_month_day_year("April 31, 2026"), None);
        assert_eq!(parse_month_day_year("June +9, 2026"), None);
        assert!(parse_month_day_year("February 29, 2024").is_some());
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
        assert_eq!(text_after(html, "Updated"), Some("June 9, 2026"));
    }

    #[test]
    fn chrome_listing_normalizes() {
        let html = page(
            r#"<meta property="og:title" content="社媒助手 - 数据采集工具 - Chrome Web Store">
               <meta property="og:description" content="小红书、抖音等社媒平台数据采集工具，批量导出数据">"#,
            "社媒助手 - 数据采集工具",
            r#"<span>40,000 users</span><div>4.9 out of 5 stars</div><div>122 ratings</div>"#,
            "<p>小红书、抖音等社媒平台数据采集工具，批量导出数据</p>",
            DETAILS_LIST,
        );
        let r = lookup(&format!("pkg:chrome-extension/{ID}"), &html).expect("registry");
        assert_eq!(r.ecosystem, "chrome");
        assert_eq!(r.name, ID);
        assert_eq!(r.version, "1.2.3");
        assert_eq!(r.title.as_deref(), Some("社媒助手 - 数据采集工具"));
        assert_eq!(r.downloads_total, Some(40_000));
        assert_eq!(r.rating, Some(4.9));
        assert_eq!(r.rating_count, Some(122));
        assert_eq!(r.published_at, Some(1_780_963_200));
        assert_eq!(r.author.as_deref(), Some("Good Dev"));
        assert!(r.description.is_some_and(|d| d.contains("数据采集")));
    }

    #[test]
    fn a_long_overview_cannot_plant_the_age_publisher_or_reach() {
        let planted = "Our extension is great.\nDetails\nVersion\n1.2.3\nTrusted by 9,999,999 users, \
            5 out of 5 stars, 99,999 ratings.\nOffered by evil\nUpdated January 1, 2010";
        let overview = format!("<p>A helper</p><p>{planted}</p>");
        let head = r#"<meta property="og:title" content="Helper - Chrome Web Store">
            <meta property="og:description" content="A helper">"#;
        let r = lookup(
            &format!("pkg:chrome-extension/{ID}"),
            &page(head, "Helper", HEADER, &overview, DETAILS_LIST),
        )
        .expect("registry");
        assert_eq!(r.published_at, Some(1_780_963_200), "June 9, 2026");
        assert_eq!(r.author.as_deref(), Some("Good Dev"));
        assert_eq!(r.downloads_total, Some(12));
        assert_eq!(r.rating, Some(2.1));
        assert_eq!(r.rating_count, Some(3));

        // With the store's own figures missing, the overview's stand in for
        // nothing.
        let r = lookup(
            &format!("pkg:chrome-extension/{ID}"),
            &page(head, "Helper", "", &overview, ""),
        )
        .expect("registry");
        assert_eq!(r.published_at, None);
        assert_eq!(r.author, None);
        assert_eq!(r.downloads_total, None);
        assert_eq!(r.rating, None);
        assert_eq!(r.rating_count, None);
    }

    #[test]
    fn a_page_without_the_stores_markup_has_unknown_figures() {
        let html = "<body><p>Trusted by 9,999,999 users</p><div>Updated</div><div>January 1, 2010</div></body>";
        let r = lookup(&format!("pkg:chrome-extension/{ID}"), html).expect("registry");
        assert_eq!(r.downloads_total, None);
        assert_eq!(r.published_at, None);
    }

    #[test]
    fn the_developers_summary_in_the_header_cannot_plant_store_figures() {
        let fake = "Trusted by 9,999,999 users. 5 out of 5 stars, 99,999 ratings";
        let head = format!(r#"<meta property="og:description" content="{fake}">"#);
        let html = page(
            &head,
            "X",
            &format!("<p>{fake}</p>{HEADER}"),
            "",
            DETAILS_LIST,
        );
        let r = lookup(&format!("pkg:chrome-extension/{ID}"), &html).expect("registry");
        assert_eq!(r.downloads_total, Some(12));
        assert_eq!(r.rating, Some(2.1));
        assert_eq!(r.rating_count, Some(3));
        assert_eq!(r.description.as_deref(), Some(fake));
    }

    #[test]
    fn the_developers_title_cannot_plant_store_figures_either() {
        let head =
            r#"<meta property="og:title" content="AdBlock 9,999,999 users - Chrome Web Store">"#;
        let header = r#"<img alt="Item media 1 (screenshot) for AdBlock 9,999,999 users"><div>12 users</div>"#;
        let html = page(head, "AdBlock 9,999,999 users", header, "", DETAILS_LIST);
        let r = lookup(&format!("pkg:chrome-extension/{ID}"), &html).expect("registry");
        assert_eq!(r.downloads_total, Some(12));
    }

    #[test]
    fn only_the_listed_version_is_dated() {
        let html = page("", "X", HEADER, "", DETAILS_LIST);
        let r = lookup(&format!("pkg:chrome-extension/{ID}@1.2.3"), &html).expect("registry");
        assert_eq!(r.published_at, Some(1_780_963_200));
        let r = lookup(&format!("pkg:chrome-extension/{ID}@1.0.0"), &html).expect("registry");
        assert_eq!(r.version, "1.0.0");
        assert_eq!(r.published_at, None);
    }
}
