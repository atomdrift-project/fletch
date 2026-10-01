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
//! `outcome` is a [`FetchRecord`] outcome in snake case; `detail` its reason,
//! for an unresolved reference (`no_release`, …) or a failure (`status`,
//! `timeout`, …). `served` is `network`, `cache`, `stale_cache`, or — for a
//! metadata read that got nothing — `failed`. `result` is `ok` or a
//! [`RegistryError`] kind in snake case. `status` is present when the server
//! answered with one.

use std::time::Duration;

use filefacts::Registry;

use crate::fetch::{FetchError, FetchRecord, Outcome, Served, Unresolved};
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
        served = rec.served.map(|served| match served {
            Served::Network => "network",
            Served::Cache => "cache",
            Served::StaleCache => "stale_cache",
        }),
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

/// One registry metadata document read through the cache: from where, and
/// how large (`None` when nothing came back).
pub(crate) fn metadata(url: &str, served: &str, bytes: Option<usize>) {
    tracing::debug!(
        target: TARGET,
        event = "metadata",
        host = url
            .split_once("://")
            .map_or("", |(_, rest)| rest.split(['/', '?', '#']).next().unwrap_or("")),
        served,
        bytes,
    );
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

/// The ecosystem a locator names: a PURL's type, `oci` for a container
/// reference, else `url`.
fn ecosystem(locator: &str) -> &str {
    match locator.strip_prefix("pkg:") {
        Some(rest) => rest.split('/').next().unwrap_or(rest),
        None if locator.starts_with("oci://") => "oci",
        None => "url",
    }
}

fn millis(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
}
