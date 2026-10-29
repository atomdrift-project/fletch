//! Best-effort, non-blocking reclamation of the blob cache.
//!
//! A sweep deletes the cache's least recently used entries until it is
//! within its budget: 30 days, 10 GiB and 262 144 entries by default,
//! overridden by `FLETCH_CACHE_TTL_DAYS`, `FLETCH_CACHE_MAX_BYTES` and
//! `FLETCH_CACHE_MAX_ENTRIES` (read once per process). It runs on a detached
//! thread that dies with the process; a `.last-sweep` marker in the cache
//! keeps it to about once a day, and a process that writes a budget's worth of
//! entries sweeps sooner.
//!
//! The sweep only touches a cache directory owned by this user and writable
//! by no one else. That ownership check is Unix-only: on other platforms the
//! cache relies on the per-user location of the OS cache directory.

pub use crate::fetch::cache::sweep::{Budget, spawn, spawn_periodic};

use crate::fetch::cache::sweep::Limits;

/// Sweep the blob cache on a detached thread and return at once. An
/// interrupted sweep is re-attempted on a later run.
pub fn cleanup() {
    spawn(vec![refs_budget()]);
}

/// The budget of the blob cache under the OS cache directory
/// (`…/fletch/refs`), for [`spawn`] or [`spawn_periodic`]. When there is no
/// OS cache directory there is nothing to sweep, and the sweep does nothing.
#[must_use]
pub fn refs_budget() -> Budget {
    Budget::new(crate::fetch::refs_dir(), Limits::from_env())
}
