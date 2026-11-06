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

use crate::fetch::{FetchError, FetchRecord, Outcome, Served};
use crate::purl::{Purl, known_type};
use crate::registry::RegistryError;

/// The `tracing` target every metric event is emitted on.
pub const TARGET: &str = "fletch::metrics";

/// One reference fetched (or not), as its record says.
pub(crate) fn fetch(rec: &FetchRecord, elapsed: Duration) {
    let detail = match &rec.outcome {
        Outcome::Unresolved(why) => Some(why.label()),
        Outcome::Failed(error) => Some(error.label()),
        _ => None,
    };
    tracing::debug!(
        target: TARGET,
        event = "fetch",
        ecosystem = ecosystem(&rec.locator),
        outcome = rec.outcome.label(),
        detail,
        status = rec.status,
        served = rec.served.map(Served::label),
        bytes = rec.size,
        elapsed_ms = millis(elapsed),
    );
}

/// One registry lookup for `locator`, and how it ended.
pub(crate) fn registry(locator: &str, result: &Result<Registry, RegistryError>, elapsed: Duration) {
    let (result, status) = match result {
        Ok(_) => ("ok", None),
        Err(error @ RegistryError::Unavailable(FetchError::Status(status))) => {
            (error.label(), Some(*status))
        }
        Err(error) => (error.label(), None),
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
        served = served.map_or("failed", Served::label),
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

    /// A label is the name a stored record serializes the value under, so
    /// metrics and records never spell one outcome two ways.
    #[test]
    fn labels_are_the_serialized_names() {
        use crate::fetch::{FetchError, Outcome, Served, Unresolved};
        let name = |value: serde_json::Value| match value {
            serde_json::Value::String(name) => name,
            serde_json::Value::Object(map) => map.into_iter().next().map(|(k, _)| k).unwrap(),
            other => panic!("unexpected {other}"),
        };
        let errors = [
            FetchError::Refused(String::new()),
            FetchError::Status(404),
            FetchError::TooLarge,
            FetchError::Timeout,
            FetchError::Transport(String::new()),
            FetchError::Io(String::new()),
            FetchError::Internal(String::new()),
        ];
        for error in errors {
            assert_eq!(error.label(), name(serde_json::to_value(&error).unwrap()));
        }
        let unresolved = [
            Unresolved::InvalidPurl,
            Unresolved::UnsafeCoordinate,
            Unresolved::NoRelease,
            Unresolved::Unsupported,
        ];
        for why in unresolved {
            assert_eq!(why.label(), name(serde_json::to_value(why).unwrap()));
        }
        for served in [Served::Network, Served::Cache, Served::StaleCache] {
            assert_eq!(served.label(), name(serde_json::to_value(served).unwrap()));
        }
        for outcome in [
            Outcome::Ok,
            Outcome::PinMismatch,
            Outcome::UnverifiablePin,
            Outcome::Unresolved(Unresolved::NoRelease),
            Outcome::Skipped,
            Outcome::BudgetExceeded,
            Outcome::Failed(FetchError::Timeout),
        ] {
            assert_eq!(
                outcome.label(),
                name(serde_json::to_value(&outcome).unwrap())
            );
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
