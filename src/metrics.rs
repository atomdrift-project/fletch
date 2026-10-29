//! Operational events for a deployment to count. Each fetch, registry lookup,
//! metadata read, and registry back-off emits one `tracing` event on the
//! [`TARGET`] target, its kind in the `event` field and its facts in fields
//! whose names are stable — so a subscriber can aggregate cache hit rates,
//! outcomes by ecosystem, throttling, bytes and latency without parsing log
//! text. Back-offs are `info`, the rest `debug`: with the target disabled, an
//! event costs one level check.
//!
//! | `event` | fields |
//! |---|---|
//! | `fetch` | `ecosystem`, `outcome`, `detail`, `status`, `served`, `bytes`, `elapsed_ms` |
//! | `registry` | `ecosystem`, `result`, `status`, `elapsed_ms` |
//! | `metadata` | `host`, `served`, `bytes` |
//! | `backoff` | `host`, `status`, `delay_ms` |
//!
//! `ecosystem` is the PURL type of the locator when it is one this crate
//! knows, `other` for any other PURL, `oci` for a container reference, and
//! `url` for anything else: a bounded set, whatever the scanned input says.
//! `host` is the URL's host alone, never its userinfo.
//!
//! `outcome` is a [`FetchRecord`] outcome in snake case; `detail` its reason,
//! for an unresolved reference (`no_release`, …) or a failure (`status`,
//! `timeout`, …). `served` is `network`, `cache`, `stale_cache`, or — for a
//! metadata read that got nothing — `failed`. `result` is `ok` or a
//! [`RegistryError`] kind in snake case. `status` is present when the server
//! answered with one.

use std::time::Duration;

use filefacts::Registry;

use crate::fetch::{FetchError, FetchRecord, Outcome, Served, Unresolved};
use crate::purl::{Purl, known_type};
use crate::registry::RegistryError;

/// The `tracing` target every metric event is emitted on.
pub const TARGET: &str = "fletch::metrics";

/// One reference fetched (or not), as its record says.
pub(crate) fn fetch(rec: &FetchRecord, elapsed: Duration) {
    let (outcome, detail) = match &rec.outcome {
        Outcome::Ok => ("ok", None),
        Outcome::PinMismatch => ("pin_mismatch", None),
        Outcome::UnverifiablePin => ("unverifiable_pin", None),
        Outcome::Unresolved(why) => (
            "unresolved",
            Some(match why {
                Unresolved::InvalidPurl => "invalid_purl",
                Unresolved::UnsafeCoordinate => "unsafe_coordinate",
                Unresolved::NoRelease => "no_release",
                Unresolved::Unsupported => "unsupported",
            }),
        ),
        Outcome::Skipped => ("skipped", None),
        Outcome::BudgetExceeded => ("budget_exceeded", None),
        Outcome::Failed(error) => (
            "failed",
            Some(match error {
                FetchError::Refused(_) => "refused",
                FetchError::Status(_) => "status",
                FetchError::TooLarge => "too_large",
                FetchError::Timeout => "timeout",
                FetchError::Transport(_) => "transport",
                FetchError::Io(_) => "io",
                FetchError::Internal(_) => "internal",
            }),
        ),
    };
    tracing::debug!(
        target: TARGET,
        event = "fetch",
        ecosystem = ecosystem(&rec.locator),
        outcome,
        detail,
        status = rec.status,
        served = rec.served.map(served_label),
        bytes = rec.size,
        elapsed_ms = millis(elapsed),
    );
}

/// One registry lookup for `locator`, and how it ended.
pub(crate) fn registry(locator: &str, result: &Result<Registry, RegistryError>, elapsed: Duration) {
    let (result, status) = match result {
        Ok(_) => ("ok", None),
        Err(RegistryError::NotAPackage) => ("not_a_package", None),
        Err(RegistryError::InvalidPurl(_)) => ("invalid_purl", None),
        Err(RegistryError::UnsafeCoordinate) => ("unsafe_coordinate", None),
        Err(RegistryError::Unsupported(_)) => ("unsupported", None),
        Err(RegistryError::NotFound) => ("not_found", None),
        Err(RegistryError::Unavailable(FetchError::Status(status))) => {
            ("unavailable", Some(*status))
        }
        Err(RegistryError::Unavailable(_)) => ("unavailable", None),
        Err(RegistryError::Malformed { .. }) => ("malformed", None),
        Err(RegistryError::NoRecord) => ("no_record", None),
        Err(RegistryError::OffRegistry) => ("off_registry", None),
    };
    tracing::debug!(
        target: TARGET,
        event = "registry",
        ecosystem = ecosystem(locator),
        result,
        status,
        elapsed_ms = millis(elapsed),
    );
}

/// One registry metadata document read through the cache: from where
/// (`None` when nothing came back), and how large.
pub(crate) fn metadata(url: &str, served: Option<Served>, bytes: Option<usize>) {
    tracing::debug!(
        target: TARGET,
        event = "metadata",
        host = host(url).as_deref().unwrap_or_default(),
        served = served.map_or("failed", served_label),
        bytes,
    );
}

fn served_label(served: Served) -> &'static str {
    match served {
        Served::Network => "network",
        Served::Cache => "cache",
        Served::StaleCache => "stale_cache",
    }
}

/// A registry asked to be left alone for `delay`.
pub(crate) fn backoff(host: &str, status: u16, delay: Duration) {
    tracing::info!(
        target: TARGET,
        event = "backoff",
        host,
        status,
        delay_ms = millis(delay),
    );
}

/// The ecosystem label of a locator: its canonical PURL type when this crate
/// knows the type, `other` for any other PURL, `oci` for a container
/// reference, else `url`.
fn ecosystem(locator: &str) -> &'static str {
    match Purl::parse(locator) {
        Ok(purl) => known_type(purl.typ()).unwrap_or("other"),
        Err(_) if locator.starts_with("oci://") => "oci",
        Err(_)
            if locator
                .get(..4)
                .is_some_and(|scheme| scheme.eq_ignore_ascii_case("pkg:")) =>
        {
            "other"
        }
        Err(_) => "url",
    }
}

/// The lowercase host of `url`, without any userinfo or port.
fn host(url: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()?
        .host_str()
        .map(str::to_ascii_lowercase)
}

fn millis(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::{ecosystem, host};

    /// The label is the canonical type, whatever the locator's case or type
    /// spelling, and a type an input invents never becomes a label value.
    #[test]
    fn ecosystem_labels_are_canonical_and_bounded() {
        for (locator, label) in [
            ("pkg:npm/a@1", "npm"),
            ("PKG:NPM/a@1", "npm"),
            ("pkg:debian/curl", "deb"),
            ("pkg:homebrew/wget", "brew"),
            ("pkg:swift/github.com/x/y@1", "swift"),
            ("pkg:attacker-chosen-1234/x", "other"),
            ("pkg:npm/", "other"),
            ("oci://ghcr.io/a/b:1", "oci"),
            ("https://example.com/x.tgz", "url"),
            ("", "url"),
        ] {
            assert_eq!(ecosystem(locator), label, "{locator}");
        }
    }

    #[test]
    fn host_never_carries_userinfo() {
        assert_eq!(
            host("https://user:token@Registry.Example:8443/x?y#z").as_deref(),
            Some("registry.example")
        );
        assert_eq!(host("not a url"), None);
    }
}
