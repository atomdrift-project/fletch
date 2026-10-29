//! What fletch knows about each package ecosystem. Every module reads its
//! registry's metadata into a [`Registry`](filefacts::Registry) record through
//! a `lookup` entry point; the modules for registries fletch downloads from
//! also resolve artifact URLs. This module holds the coordinates and the
//! document helpers they share.

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

use filefacts::Registry;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use std::collections::BTreeMap;

use crate::fetch::{
    BlobCache, Fetch, META_TTL_IMMUTABLE, cached_metadata_status, safe_purl_coordinates,
};
use crate::purl::Purl;
use crate::registry::RegistryError;

/// A package coordinate vetted once for every registry backend and artifact
/// resolver: the percent-encoded path and version are safe to interpolate
/// into a registry URL ([`safe_purl_coordinates`]). Backends build URLs from
/// the encoded forms and name records with the decoded ones, so none decodes
/// for itself.
#[derive(Debug)]
pub(crate) struct Coordinates<'a> {
    purl: &'a Purl,
    path: String,
    version: Option<String>,
}

/// Test coordinates for `raw`, a PURL with safe coordinates.
#[cfg(test)]
pub(crate) fn coordinates(raw: &str) -> Coordinates<'static> {
    let purl = Box::leak(Box::new(Purl::parse(raw).expect("purl")));
    Coordinates::new(purl).expect("safe coordinates")
}

impl<'a> Coordinates<'a> {
    /// Vet `purl`'s coordinates; [`RegistryError::UnsafeCoordinate`] when its
    /// path or version could restructure the URL it fills.
    pub(crate) fn new(purl: &'a Purl) -> Result<Self, RegistryError> {
        let path = purl.encoded_path();
        let version = purl.encoded_version();
        if !safe_purl_coordinates(purl.typ(), &path, version.as_deref()) {
            tracing::debug!(
                purl = %purl.to_string().escape_debug(),
                "refused: coordinate could restructure a registry URL"
            );
            return Err(RegistryError::UnsafeCoordinate);
        }
        Ok(Self {
            purl,
            path,
            version,
        })
    }

    /// The parsed PURL, for its type and qualifiers.
    pub(crate) fn purl(&self) -> &Purl {
        self.purl
    }

    /// The namespace and name as one `/`-joined path of percent-encoded
    /// segments (`%40scope/name`): the form a registry URL is built from.
    pub(crate) fn path(&self) -> &str {
        &self.path
    }

    /// The name, percent-encoded: the last segment of [`path`](Self::path).
    pub(crate) fn encoded_name(&self) -> &str {
        last_seg(&self.path)
    }

    /// The decoded name.
    pub(crate) fn name(&self) -> &str {
        self.purl.name()
    }

    /// The decoded namespace segments.
    pub(crate) fn namespace(&self) -> &[String] {
        self.purl.namespace()
    }

    /// The decoded namespace and name, `/`-joined (`@scope/name`): how a
    /// registry names the package in its own documents.
    pub(crate) fn full_name(&self) -> String {
        let mut segments = self.namespace().to_vec();
        segments.push(self.name().to_string());
        segments.join("/")
    }

    /// The requested version, decoded.
    pub(crate) fn version(&self) -> Option<&str> {
        self.purl.version()
    }

    /// The requested version, percent-encoded.
    pub(crate) fn encoded_version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    /// The release a record describes: the requested version, else the
    /// registry's `latest`, else empty — the record's documented "no version".
    pub(crate) fn target<'b>(&'b self, latest: Option<&'b str>) -> &'b str {
        self.version().or(latest).unwrap_or_default()
    }

    /// The encoded `(namespace, name)` of a registry that addresses packages
    /// as exactly `owner/name`.
    pub(crate) fn pair(&self) -> Result<(&str, &str), RegistryError> {
        split_pair(&self.path)
    }

    /// The encoded name for a backend that reads one repository: the name
    /// itself when there is no namespace, or when the namespace is one of
    /// `own`, that repository's own spellings. Any other namespace — a
    /// third-party tap, PPA, or vendor — names a package elsewhere, and the
    /// backend's record of the same name would lend it a reputation it never
    /// earned.
    pub(crate) fn bare_name(&self, own: &[&str]) -> Result<&str, RegistryError> {
        let namespace = self.namespace().join("/");
        if namespace.is_empty() || own.iter().any(|o| o.eq_ignore_ascii_case(&namespace)) {
            return Ok(self.encoded_name());
        }
        tracing::debug!(
            purl_type = self.purl.typ(),
            namespace = %namespace.escape_debug(),
            "registry lookup refused: namespace names another repository"
        );
        Err(RegistryError::OffRegistry)
    }
}

/// `owner/name` split at its one `/`, both halves non-empty. Anything longer
/// could reach another endpoint of a registry that addresses packages by
/// pair, so it is refused as [`RegistryError::UnsafeCoordinate`].
pub(crate) fn split_pair(path: &str) -> Result<(&str, &str), RegistryError> {
    match path.split_once('/') {
        Some((owner, name)) if !owner.is_empty() && !name.is_empty() && !name.contains('/') => {
            Ok((owner, name))
        }
        _ => {
            tracing::debug!(
                path = %path.escape_debug(),
                "registry lookup refused: coordinate is not owner/name"
            );
            Err(RegistryError::UnsafeCoordinate)
        }
    }
}

/// `cache` with the metadata TTL a lookup for `version` warrants. What a
/// package document says about a published version does not change, so a
/// versioned lookup trusts a cached copy for the long pinned window; a
/// versionless one tracks a moving `latest` and revalidates on the short one.
pub(crate) fn for_version(cache: &BlobCache, version: Option<&str>) -> BlobCache {
    cache.with_meta_ttl(if version.is_some() {
        cache.meta_ttl_pinned()
    } else {
        cache.meta_ttl_unpinned()
    })
}

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
    serde_json::from_slice(bytes).map_err(|e| {
        tracing::debug!(url, error = %e, "registry document is not the expected shape");
        RegistryError::Malformed {
            url: url.to_string(),
            reason: e.to_string(),
        }
    })
}

/// A best-effort enrichment's value, or `None` with the reason logged: the
/// record stands without it, but the gap is never silent.
fn optional<T>(result: Result<T, RegistryError>, url: &str) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(error) => {
            tracing::debug!(url, %error, "registry enrichment skipped");
            None
        }
    }
}

/// A field that is `T` when the registry sends one, else `None`: for fields a
/// registry sends in more than one shape (npm's `license` is a string, an
/// object, or an array of them), so that variety costs the field and never the
/// document. Use with `#[serde(default, deserialize_with = "lenient")]`.
fn lenient<'de, D: Deserializer<'de>, T: DeserializeOwned>(d: D) -> Result<Option<T>, D::Error> {
    Ok(T::deserialize(Value::deserialize(d)?).ok())
}

/// A text field that is `None` when absent, not a string, or blank —
/// registries send `""` for "nothing here" as often as they omit the field.
/// Use with `#[serde(default, deserialize_with = "non_empty")]`.
fn non_empty<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Ok(lenient::<D, String>(d)?.filter(|s| !s.trim().is_empty()))
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

/// A marketplace rating on a `0..=max` scale, as stars out of five. `None`
/// for a value off its scale, so every record's `rating` reads the same way.
fn five_star(value: f64, max: f64) -> Option<f32> {
    (value.is_finite() && (0.0..=max).contains(&value)).then(|| (value * 5.0 / max) as f32)
}

/// Resolve through a per-version document that, once published, never
/// changes: `resolve` reads it trusting a cached copy of any age, and if what
/// it reads does not check out, once more straight from the network. Without
/// the second read, a wrong answer cached before the release existed (a `200`
/// placeholder for a version not yet published) would be served forever —
/// and the real release, published later under that version, never resolved.
fn immutable_or_fresh<T>(
    cache: &BlobCache,
    resolve: impl Fn(&BlobCache) -> Option<T>,
) -> Option<T> {
    resolve(&cache.with_meta_ttl(META_TTL_IMMUTABLE))
        .or_else(|| resolve(&cache.with_meta_ttl(std::time::Duration::ZERO)))
}

/// The final `/`-separated segment of `path`; all of `path` when it has none.
fn last_seg(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// `Name <email>` → `Name`; a bare name is returned unchanged. Shared with
/// [`crate::distro`], whose index formats spell a maintainer the same way.
pub(crate) fn strip_email(s: &str) -> String {
    s.split('<').next().unwrap_or(s).trim().to_string()
}

/// The text of a one-line HTML fragment, its tags dropped and the rest
/// trimmed (WordPress wraps an author in an `<a>`).
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

/// Record a package's release timeline from every release's publish time, in
/// any order: the release count (unless the registry reported its own total),
/// the first release (unless the registry dated the package's creation), the
/// release just before this record's [`published_at`](Registry::published_at),
/// and the raw times [`Registry::with_age`] derives the burst counts from. An
/// empty timeline leaves the record untouched: unknown, not zero releases.
fn set_timeline(record: &mut Registry, times: impl IntoIterator<Item = u64>) {
    let mut times: Vec<u64> = times.into_iter().collect();
    if times.is_empty() {
        return;
    }
    times.sort_unstable();
    record.release_count = record.release_count.or(u32::try_from(times.len()).ok());
    record.first_published_at = record.first_published_at.or(times.first().copied());
    if let Some(this) = record.published_at {
        let earlier = times.partition_point(|&t| t < this);
        record.previous_published_at = earlier.checked_sub(1).map(|i| times[i]);
    }
    record.release_times = times;
}

/// Unix seconds from an epoch-milliseconds figure, which some registries send
/// as a float. `None` for a negative, non-finite, or out-of-range value, never
/// the epoch.
fn secs_from_millis(ms: f64) -> Option<u64> {
    (ms.is_finite() && (0.0..1.0e18).contains(&ms)).then(|| (ms / 1000.0) as u64)
}

/// Parse a registry timestamp to Unix seconds. The shapes registries emit:
/// RFC 3339 / ISO 8601 (`2021-04-23T10:00:00.000Z`, `…+00:00`, `…+0000`,
/// `…+05`, fractional seconds of any width, a space or `T` separator, no zone
/// meaning UTC), optionally followed by a space and a zone — a UTC word
/// (`… UTC`, `… GMT`, as crandb appends) or a numeric offset (`… +0000`,
/// pkgsrc's `BUILD_DATE`). `None` on anything else: an impossible date or
/// time (`2021-13-45`, `25:00`), trailing text, or a zone abbreviation such
/// as `PST` that can't be placed — an unparseable date becomes "age unknown",
/// never a wrong age.
pub(crate) fn unix_secs(s: &str) -> Option<u64> {
    rfc3339_secs(s).or_else(|| {
        let (core, zone) = s.trim_end().rsplit_once(' ')?;
        match zone {
            "UTC" | "GMT" | "Z" => rfc3339_secs(core),
            _ if zone.starts_with(['+', '-']) => rfc3339_secs(&format!("{core}{zone}")),
            _ => None,
        }
    })
}

/// [`unix_secs`] for exactly one RFC 3339 / ISO 8601 timestamp.
fn rfc3339_secs(s: &str) -> Option<u64> {
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
    if hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    let midnight = i64::try_from(civil_secs(year, month, day)?).ok()?;

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
    u64::try_from(midnight + hour * 3600 + min * 60 + sec - offset).ok()
}

/// Unix seconds at UTC midnight of a proleptic-Gregorian civil date. `None`
/// for a month or day that does not exist (`2021-02-29`, `2021-04-31`) or a
/// date before the epoch.
fn civil_secs(year: i64, month: i64, day: i64) -> Option<u64> {
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        _ => return None,
    };
    if !(1..=days_in_month).contains(&day) {
        return None;
    }
    // Days since 1970-01-01 (Howard Hinnant's `days_from_civil`).
    let y = if month <= 2 { year - 1 } else { year };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    u64::try_from((era * 146_097 + doe - 719_468).checked_mul(86_400)?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use filefacts::Ecosystem;

    #[test]
    fn rfc3339_shapes_parse_to_unix_seconds() {
        // 2021-04-23T10:00:00Z == 1619172000.
        for shape in [
            "2021-04-23T10:00:00Z",
            "2021-04-23T10:00:00.000Z",
            "2021-04-23T10:00:00.123456Z",
            "2021-04-23T12:00:00+02:00",
            "2021-04-23 10:00:00",
            "2021-04-23T12:00:00+0200",
            "2021-04-23T12:00:00+02",
        ] {
            assert_eq!(unix_secs(shape), Some(1_619_172_000), "{shape}");
        }
        assert_eq!(unix_secs("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(unix_secs("garbage"), None);
    }

    #[test]
    fn impossible_or_malformed_timestamps_are_unknown_not_wrong() {
        for bad in [
            "2021-13-01T00:00:00Z",     // month 13
            "2021-00-01T00:00:00Z",     // month 0
            "2021-02-29T00:00:00Z",     // not a leap year
            "2021-04-31T00:00:00Z",     // April has 30 days
            "2021-04-23T24:00:00Z",     // hour 24
            "2021-13-45T99:99:99Z",     // every field out of range
            "2021x04y23T10:00:00Z",     // wrong separators
            "+021-04-23T10:00:00Z",     // a sign is not a digit
            "2021-04-23T10:00:00Zjunk", // trailing text
            "2021-04-23T10:00:00+05:30junk",
            "2021-04-23T10:00:00.Z", // a dot with no fraction
            "1969-12-31T00:00:00Z",  // before the epoch
        ] {
            assert_eq!(unix_secs(bad), None, "{bad}");
        }
        assert!(
            unix_secs("2024-02-29T00:00:00Z").is_some(),
            "2024 is a leap year"
        );
        assert!(unix_secs("2016-12-31T23:59:60Z").is_some(), "leap second");
    }

    #[test]
    fn a_trailing_zone_is_honoured_or_refused_never_assumed() {
        let utc = unix_secs("2021-04-23T10:00:00Z");
        assert_eq!(unix_secs("2021-04-23 10:00:00 UTC"), utc);
        assert_eq!(unix_secs("2021-04-23 10:00:00 GMT"), utc);
        assert_eq!(unix_secs("2021-04-23 10:00:00 +0000"), utc);
        // A non-UTC offset moves the instant instead of being dropped.
        assert_eq!(
            unix_secs("2021-04-23 15:30:00 +0530"),
            utc,
            "15:30 at +05:30 is 10:00 UTC"
        );
        // A zone abbreviation can't be placed, so it is unknown, not UTC.
        assert_eq!(unix_secs("2021-04-23 10:00:00 PST"), None);
    }

    #[test]
    fn civil_dates_are_validated() {
        assert_eq!(civil_secs(2021, 4, 23), Some(1_619_136_000));
        assert_eq!(civil_secs(2024, 2, 29), Some(1_709_164_800));
        for (y, m, d) in [
            (2021, 2, 29),
            (2021, 2, 31),
            (2021, 4, 31),
            (2021, 13, 1),
            (2021, 1, 0),
        ] {
            assert_eq!(civil_secs(y, m, d), None, "{y}-{m}-{d}");
        }
    }

    #[test]
    fn millisecond_times_never_become_the_epoch() {
        assert_eq!(secs_from_millis(1_619_172_000_123.0), Some(1_619_172_000));
        assert_eq!(secs_from_millis(-1.0), None);
        assert_eq!(secs_from_millis(f64::NAN), None);
        assert_eq!(secs_from_millis(f64::INFINITY), None);
    }

    #[test]
    fn a_timeline_dates_the_first_and_previous_release() {
        let unknown = || Registry::new(Ecosystem::Npm, "pkg");
        let mut record = unknown();
        record.published_at = Some(30);
        set_timeline(&mut record, [40, 10, 30, 20]);
        assert_eq!(record.release_count, Some(4));
        assert_eq!(record.first_published_at, Some(10));
        assert_eq!(record.previous_published_at, Some(20));
        assert_eq!(record.release_times, vec![10, 20, 30, 40]);

        // The registry's own total and creation date win; the first release
        // has no predecessor; an empty timeline is unknown.
        let mut record = unknown();
        record.published_at = Some(10);
        record.first_published_at = Some(5);
        record.release_count = Some(99);
        set_timeline(&mut record, [10, 20]);
        assert_eq!(record.release_count, Some(99));
        assert_eq!(record.first_published_at, Some(5));
        assert_eq!(record.previous_published_at, None);
        let mut record = unknown();
        set_timeline(&mut record, []);
        assert_eq!(record, unknown());
    }

    #[test]
    fn ratings_land_on_five_stars_or_nowhere() {
        assert_eq!(five_star(80.0, 100.0), Some(4.0));
        assert_eq!(five_star(4.5, 5.0), Some(4.5));
        assert_eq!(five_star(101.0, 100.0), None);
        assert_eq!(five_star(-1.0, 5.0), None);
        assert_eq!(five_star(f64::NAN, 5.0), None);
    }

    #[test]
    fn a_pair_is_exactly_owner_and_name() {
        assert_eq!(split_pair("a/b"), Ok(("a", "b")));
        for bad in ["a", "a/", "/b", "a/b/c", ""] {
            assert_eq!(
                split_pair(bad),
                Err(RegistryError::UnsafeCoordinate),
                "{bad}"
            );
        }
    }

    #[test]
    fn coordinates_carry_both_spellings() {
        let purl = Purl::parse("pkg:npm/%40scope/na%2Bme@1.0.0%2Bbuild").expect("purl");
        let c = Coordinates::new(&purl).expect("safe");
        assert_eq!(c.path(), "%40scope/na%2Bme");
        assert_eq!(c.encoded_name(), "na%2Bme");
        assert_eq!(c.name(), "na+me");
        assert_eq!(c.full_name(), "@scope/na+me");
        assert_eq!(c.version(), Some("1.0.0+build"));
        assert_eq!(c.encoded_version(), Some("1.0.0%2Bbuild"));
        assert_eq!(c.target(Some("2.0.0")), "1.0.0+build");
        assert_eq!(c.bare_name(&[]), Err(RegistryError::OffRegistry));
        assert_eq!(c.bare_name(&["@SCOPE"]), Ok("na%2Bme"));

        let purl = Purl::parse("pkg:pypi/w@..%2F..%2Fx").expect("purl");
        assert_eq!(
            Coordinates::new(&purl).err(),
            Some(RegistryError::UnsafeCoordinate)
        );
    }
}
