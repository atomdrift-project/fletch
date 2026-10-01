//! What fletch knows about each package ecosystem. Each module holds both
//! halves for its registry, side by side: reading registry metadata into a
//! [`Registry`](filefacts::Registry) record and resolving artifact downloads.
//! This module holds the document helpers they share.

pub(crate) mod arch;
pub(crate) mod cargo;
pub(crate) mod chrome;
pub(crate) mod clawhub;
pub(crate) mod clojars;
pub(crate) mod comfyui;
pub(crate) mod composer;
pub(crate) mod conda;
pub(crate) mod container;
pub(crate) mod cpan;
pub(crate) mod cran;
pub(crate) mod dify;
pub(crate) mod fedora;
pub(crate) mod firefox;
pub(crate) mod gem;
pub(crate) mod github;
pub(crate) mod golang;
pub(crate) mod hex;
pub(crate) mod homebrew;
pub(crate) mod huggingface;
pub(crate) mod jetbrains;
pub(crate) mod jsr;
pub(crate) mod maven;
pub(crate) mod npm;
pub(crate) mod nuget;
pub(crate) mod pub_dev;
pub(crate) mod pypi;
pub(crate) mod snap;
pub(crate) mod terraform;
pub(crate) mod vscode;
pub(crate) mod wordpress;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use std::collections::BTreeMap;

use crate::fetch::{BlobCache, Fetch, cached_metadata_status};
use crate::registry::RegistryError;

/// The domain half of an email address (`a@b.com` → `b.com`), lowercased.
/// `None` when there is no `@` or the domain is empty. Tolerates the
/// `Display Name <user@domain>` form PyPI uses by keeping only the leading run
/// of valid domain characters after the `@` (so a trailing `>` or comment is
/// dropped). A freemail/disposable domain behind a sensitive package is a weak
/// custody signal; the local-part is dropped so no per-user identifier is kept.
fn email_domain(email: &str) -> Option<String> {
    let after = email.rsplit_once('@')?.1;
    let domain: String = after
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-')
        .collect::<String>()
        .to_ascii_lowercase();
    (!domain.is_empty()).then_some(domain)
}

/// Fetch the registry document at `url` through the metadata cache and decode
/// it as `T`, the shape the backend reads.
fn fetch_json<T: DeserializeOwned>(
    url: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<T, RegistryError> {
    decode(url, &cached_metadata_status(url, &[], net, cache)?)
}

/// Decode a registry document, naming it when it is not the shape expected —
/// a schema change upstream is then a precise error instead of a silent gap.
fn decode<T: DeserializeOwned>(url: &str, bytes: &[u8]) -> Result<T, RegistryError> {
    serde_json::from_slice(bytes).map_err(|e| RegistryError::Malformed {
        url: url.to_string(),
        reason: e.to_string(),
    })
}

/// A field that is `T` when the registry sends one, else `None`: for fields a
/// registry sends in more than one shape (npm's `license` is a string, an
/// object, or an array of them), so that variety costs the field and never the
/// document. Use with `#[serde(default, deserialize_with = "lenient")]`.
fn lenient<'de, D: Deserializer<'de>, T: DeserializeOwned>(d: D) -> Result<Option<T>, D::Error> {
    Ok(T::deserialize(Value::deserialize(d)?).ok())
}

/// A field read as its default when the registry sends `null` — registries
/// say "nothing here" that way, which serde accepts only for an `Option`. Use
/// with `#[serde(default, deserialize_with = "null_default")]`.
fn null_default<'de, D: Deserializer<'de>, T: Deserialize<'de> + Default>(
    d: D,
) -> Result<T, D::Error> {
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

/// A localized marketplace string: a bare string, or a `{ locale: text }` map
/// (AMO keys it `en-US`, Dify `en_US`).
#[derive(Deserialize)]
#[serde(untagged)]
enum Localized {
    Text(String),
    Translations(BTreeMap<String, Option<String>>),
}

impl Localized {
    /// The non-empty translation for exactly `locale`; `None` for a bare string.
    fn translation(&self, locale: &str) -> Option<String> {
        let Self::Translations(map) = self else {
            return None;
        };
        map.get(locale)?
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    }

    /// The text to show: a non-empty bare string, else the `en-US` translation,
    /// else the first non-empty one in locale order.
    fn text(&self) -> Option<String> {
        match self {
            Self::Text(s) => (!s.is_empty()).then(|| s.clone()),
            Self::Translations(map) => self
                .translation("en-US")
                .or_else(|| map.values().flatten().find(|s| !s.is_empty()).cloned()),
        }
    }
}

/// A boolean flag the registry sets → its `label` when set, else `None`.
fn flag(set: Option<bool>, label: &str) -> Option<String> {
    set.and_then(|f| f.then(|| label.to_string()))
}

/// The final path segment — the bare package name, dropping any vendor/namespace
/// prefix an OS-package locator carries (`pkg:aur/foo`, `pkg:alpm/arch/foo`).
pub(crate) fn last_seg(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// `Name <email>` → `Name`; a bare name is returned unchanged. Shared with
/// [`crate::distro`], whose index formats spell a maintainer the same way.
pub(crate) fn strip_email(s: &str) -> String {
    s.split('<').next().unwrap_or(s).trim().to_string()
}

/// Parse a registry timestamp: RFC 3339, or that core followed by a space and
/// a zone — a UTC word (`… UTC`, `… GMT`, as crandb appends) or a numeric
/// offset (`… +0000`, pkgsrc's `BUILD_DATE`). Any other trailing text (`PST`,
/// a 12-hour clock) can't be placed on the timeline, so it is `None` rather
/// than a guess hours off.
pub(crate) fn parse_ts(s: &str) -> Option<u64> {
    parse_rfc3339_secs(s).or_else(|| {
        let (core, zone) = s.trim_end().rsplit_once(' ')?;
        match zone {
            "UTC" | "GMT" | "Z" => parse_rfc3339_secs(core),
            _ if zone.starts_with(['+', '-']) => parse_rfc3339_secs(&format!("{core}{zone}")),
            _ => None,
        }
    })
}

/// Parse an RFC 3339 / ISO 8601 timestamp to Unix seconds, covering the shapes
/// registries emit: `2021-04-23T10:00:00.000Z`, `…+00:00`, `…+0000`, fractional
/// seconds of any width, space or `T` separator, no zone meaning UTC. `None` on
/// anything else, including an impossible date or time (`2021-13-45`, `25:00`)
/// or trailing text — an unparseable date becomes "age unknown", never a
/// wrong age.
fn parse_rfc3339_secs(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    // A fixed-width field of digits only: `str::parse` would also take a sign.
    let n = |a: usize, z: usize| -> Option<i64> {
        b.get(a..z)?.iter().try_fold(0i64, |acc, &d| {
            d.is_ascii_digit().then(|| acc * 10 + i64::from(d - b'0'))
        })
    };
    let separators = b.get(4) == Some(&b'-')
        && b.get(7) == Some(&b'-')
        && matches!(b.get(10), Some(b'T' | b't' | b' '))
        && b.get(13) == Some(&b':')
        && b.get(16) == Some(&b':');
    if !separators {
        return None;
    }
    let (year, month, day) = (n(0, 4)?, n(5, 7)?, n(8, 10)?);
    let (hour, min, sec) = (n(11, 13)?, n(14, 16)?, n(17, 19)?);
    // A leap second (`:60`) is legal RFC 3339.
    if !(1..=12).contains(&month)
        || !(1..=days_in_month(year, month)).contains(&day)
        || hour > 23
        || min > 59
        || sec > 60
    {
        return None;
    }

    let mut i = 19;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let digits = i;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        if i == digits {
            return None;
        }
    }
    let offset = match b.get(i) {
        None => 0,
        Some(b'Z' | b'z') if i + 1 == b.len() => 0,
        Some(&sign @ (b'+' | b'-')) => {
            let oh = n(i + 1, i + 3)?;
            // `+05:30`, `+0530`, or an hour-only `+05`.
            let (om, end) = match b.get(i + 3) {
                None => (0, i + 3),
                Some(b':') => (n(i + 4, i + 6)?, i + 6),
                Some(_) => (n(i + 3, i + 5)?, i + 5),
            };
            if end != b.len() || oh > 23 || om > 59 {
                return None;
            }
            let secs = oh * 3600 + om * 60;
            if sign == b'+' { secs } else { -secs }
        }
        _ => return None,
    };
    let days = days_from_civil(year, month, day);
    u64::try_from(days * 86400 + hour * 3600 + min * 60 + sec - offset).ok()
}

/// Days in `month` (1-based) of the proleptic-Gregorian `year`.
fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 for a proleptic-Gregorian civil date (Howard
/// Hinnant's algorithm). Valid for any year in range.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

#[cfg(test)]
/// Build a fresh temp-dir blob cache keyed by a per-test name, purging any
/// entry a prior run left behind so a changed fixture is never masked by a
/// stale cached response.
pub(crate) fn test_cache(_name: &str) -> BlobCache {
    // Hermetic: an inert cache so every lookup goes straight to the fixture,
    // with no shared on-disk state across tests or runs.
    BlobCache::disabled()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_shapes_parse_to_unix_seconds() {
        // 2021-04-23T10:00:00Z == 1619172000.
        assert_eq!(
            parse_rfc3339_secs("2021-04-23T10:00:00Z"),
            Some(1_619_172_000)
        );
        assert_eq!(
            parse_rfc3339_secs("2021-04-23T10:00:00.000Z"),
            Some(1_619_172_000)
        );
        assert_eq!(
            parse_rfc3339_secs("2021-04-23T10:00:00.123456Z"),
            Some(1_619_172_000)
        );
        // +02:00 offset is two hours earlier in UTC.
        assert_eq!(
            parse_rfc3339_secs("2021-04-23T12:00:00+02:00"),
            Some(1_619_172_000)
        );
        assert_eq!(
            parse_rfc3339_secs("2021-04-23 10:00:00"),
            Some(1_619_172_000)
        );
        // The Unix epoch itself.
        assert_eq!(parse_rfc3339_secs("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339_secs("garbage"), None);
        assert_eq!(
            parse_rfc3339_secs("2021-04-23T12:00:00+0200"),
            Some(1_619_172_000)
        );
        assert_eq!(
            parse_rfc3339_secs("2021-04-23T12:00:00+02"),
            Some(1_619_172_000)
        );
    }

    #[test]
    fn impossible_or_malformed_timestamps_are_unknown_not_wrong() {
        for bad in [
            "2021-13-01T00:00:00Z",     // month 13
            "2021-02-29T00:00:00Z",     // not a leap year
            "2021-04-31T00:00:00Z",     // April has 30 days
            "2021-04-23T24:00:00Z",     // hour 24
            "2021-13-45T99:99:99Z",     // every field out of range
            "2021x04y23T10:00:00Z",     // wrong separators
            "+021-04-23T10:00:00Z",     // a sign is not a digit
            "2021-04-23T10:00:00Zjunk", // trailing text
            "2021-04-23T10:00:00+05:30junk",
            "2021-04-23T10:00:00.Z", // a dot with no fraction
        ] {
            assert_eq!(parse_rfc3339_secs(bad), None, "{bad}");
        }
        assert!(
            parse_rfc3339_secs("2024-02-29T00:00:00Z").is_some(),
            "2024 is a leap year"
        );
        assert!(
            parse_rfc3339_secs("2016-12-31T23:59:60Z").is_some(),
            "leap second"
        );
    }

    #[test]
    fn a_trailing_zone_is_honoured_or_refused_never_assumed() {
        let utc = parse_rfc3339_secs("2021-04-23T10:00:00Z");
        assert_eq!(parse_ts("2021-04-23 10:00:00 UTC"), utc);
        assert_eq!(parse_ts("2021-04-23 10:00:00 GMT"), utc);
        assert_eq!(parse_ts("2021-04-23 10:00:00 +0000"), utc);
        // A non-UTC offset moves the instant instead of being dropped.
        assert_eq!(
            parse_ts("2021-04-23 15:30:00 +0530"),
            utc,
            "15:30 at +05:30 is 10:00 UTC"
        );
        // A zone abbreviation can't be placed, so it is unknown, not UTC.
        assert_eq!(parse_ts("2021-04-23 10:00:00 PST"), None);
    }
}
