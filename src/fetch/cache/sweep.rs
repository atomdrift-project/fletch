//! Best-effort, non-blocking reclamation of the blob cache.
//!
//! A *sweep* deletes the oldest entries until the cache is within an age,
//! count and size budget. It runs on a detached thread that dies with the
//! process: no daemon, no async runtime, no persistent index.
//!
//! The count ceiling is the one that usually binds a cache of small entries: a
//! byte budget alone lets a directory reach millions of files, which every
//! filesystem tool handles badly and which makes the sweep meant to fix it
//! progressively more expensive.
//!
//! Three properties keep it cheap and safe:
//! - A `.last-sweep` marker gates the walk, so the common case is a single
//!   `stat`, never a scan of a large directory. The marker records whether the
//!   sweep it names *finished*: a detached thread dies with its process, and a
//!   sweep cut short that way must not book itself as a full day's work, or a
//!   cache too large to sweep in one short run would never be swept at all.
//! - The root and every shard pass the cache's trust check
//!   ([`disk::trust_root`]) before anything is written or deleted there: in a
//!   directory others can write, an entry swapped for a symlink between listing
//!   and deleting would aim the deletion anywhere this user can reach.
//! - Filesystem errors never reach the caller: reclaiming disk must not disturb
//!   the program it runs alongside. On Unix, unlinking a file another thread
//!   has open leaves that reader's descriptor valid, so a concurrent reader
//!   never sees a torn file.
//!
//! The 30-day retention is well above the blob cache's 7-day pinned TTL, so
//! serving a stale entry when the source is unreachable keeps working.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::{Duration, SystemTime};

use super::disk::{self, MARKER, Trusted};

/// Default retention window, in days. Override with `FLETCH_CACHE_TTL_DAYS`.
const DEFAULT_TTL_DAYS: u64 = 30;
/// Default byte ceiling: 10 GiB, for fetched package artifacts. Override with
/// `FLETCH_CACHE_MAX_BYTES`.
const DEFAULT_MAX_BYTES: u64 = 10 * 1024 * 1024 * 1024;
/// Default entry ceiling. A worker scanning at volume reads a registry
/// document for nearly every package it meets, so this is sized for a server,
/// not a desktop; the byte ceiling still bounds a smaller machine. Spread over
/// the cache's 256 shards it is about a thousand entries each. Override with
/// `FLETCH_CACHE_MAX_ENTRIES`.
const DEFAULT_MAX_ENTRIES: usize = 1 << 18;
/// Re-walk a cache at most this often; cheaper runs just read the marker.
const SWEEP_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
/// Re-walk this soon after a sweep that never reported finishing. A sweep in
/// another process still running after this long can be joined by a second,
/// which costs a redundant walk but nothing else: each deletes what it decided
/// was oldest, and a failed delete is ignored.
const RETRY_INTERVAL: Duration = Duration::from_secs(60 * 60);
/// Marker contents: a sweep is in flight, or died with its process.
const MARK_STARTED: &[u8] = b"s";
/// Marker contents: the sweep that wrote it ran to completion.
const MARK_DONE: &[u8] = b"d";
/// The most of the marker ever read: one byte past the longest state.
const MAX_MARKER_BYTES: u64 = 2;

/// How large a blob cache may grow: the limits a sweep enforces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Limits {
    /// Delete entries last used longer ago than this.
    pub(crate) max_age: Duration,
    /// Then delete the oldest until the total is at or below this.
    pub(crate) max_bytes: u64,
    /// Likewise for the entry count. Usually the binding ceiling.
    pub(crate) max_entries: usize,
}

impl Limits {
    /// The defaults, overridden by `FLETCH_CACHE_TTL_DAYS`,
    /// `FLETCH_CACHE_MAX_BYTES` and `FLETCH_CACHE_MAX_ENTRIES`. Read once per
    /// process; an unset, unparsable or zero value keeps the default.
    pub(crate) fn from_env() -> Self {
        static LIMITS: OnceLock<Limits> = OnceLock::new();
        *LIMITS.get_or_init(|| {
            let days = positive("FLETCH_CACHE_TTL_DAYS").unwrap_or(DEFAULT_TTL_DAYS);
            let limits = Self {
                // Saturating, so an absurd value cannot overflow.
                max_age: Duration::from_secs(days.saturating_mul(24 * 60 * 60)),
                max_bytes: positive("FLETCH_CACHE_MAX_BYTES").unwrap_or(DEFAULT_MAX_BYTES),
                max_entries: positive("FLETCH_CACHE_MAX_ENTRIES").unwrap_or(DEFAULT_MAX_ENTRIES),
            };
            tracing::debug!(target: "cache_sweep", ?limits, "blob cache limits");
            limits
        })
    }
}

/// The positive number `var` holds, if it holds one.
fn positive<T: std::str::FromStr + PartialOrd + Default>(var: &str) -> Option<T> {
    let value = std::env::var(var).ok()?;
    let parsed = value.trim().parse::<T>().ok().filter(|n| *n > T::default());
    if parsed.is_none() {
        tracing::warn!(target: "cache_sweep", var, value, "ignoring invalid cache limit");
    }
    parsed
}

/// A blob cache and the limits a sweep holds it to. Build one with
/// [`refs_budget`](crate::cache_sweep::refs_budget).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Budget {
    /// `None` when there is no cache to sweep (no OS cache directory).
    root: Option<PathBuf>,
    limits: Limits,
}

impl Budget {
    pub(crate) fn new(root: Option<PathBuf>, limits: Limits) -> Self {
        Self { root, limits }
    }
}

/// Sweep `budgets` on a detached thread and return at once. The thread dies
/// with the process; an interrupted sweep leaves the marker unfinished, so
/// the next run retries it within the hour. A cache already being swept by
/// this process is skipped.
pub fn spawn(budgets: Vec<Budget>) {
    start(budgets, false);
}

/// Sweep `budgets` now and every `interval` thereafter on one detached thread,
/// for the life of the process — for a daemon, where a startup-only sweep
/// would never fire again. The daily marker keeps each wake cheap whatever
/// the `interval`, and a wake that finds a cache already being swept skips it.
pub fn spawn_periodic(budgets: Vec<Budget>, interval: Duration) {
    let budgets: Vec<Budget> = budgets.into_iter().filter(|b| b.root.is_some()).collect();
    if budgets.is_empty() {
        return;
    }
    let spawned = std::thread::Builder::new()
        .name("fletch-cache-sweep".into())
        .spawn(move || {
            loop {
                for budget in &budgets {
                    if let Some(claim) = Claim::take(budget, false) {
                        sweep(budget, claim, false);
                    }
                }
                std::thread::sleep(interval);
            }
        });
    if let Err(error) = spawned {
        tracing::warn!(target: "cache_sweep", %error, "cannot start the periodic cache sweep");
    }
}

/// Claim each budget's cache and sweep the claimed ones on a detached thread.
fn start(budgets: Vec<Budget>, force: bool) {
    let claimed: Vec<(Budget, Claim)> = budgets
        .into_iter()
        .filter_map(|budget| Claim::take(&budget, force).map(|claim| (budget, claim)))
        .collect();
    if claimed.is_empty() {
        return;
    }
    // A thread the OS refuses drops the closure, and with it the claims.
    let spawned = std::thread::Builder::new()
        .name("fletch-cache-sweep".into())
        .spawn(move || {
            for (budget, claim) in claimed {
                sweep(&budget, claim, force);
            }
        });
    if let Err(error) = spawned {
        tracing::warn!(target: "cache_sweep", %error, "cannot start a cache sweep");
    }
}

/// Sweep `budget`'s cache under `claim`, then again for every forced sweep
/// asked for while it ran.
fn sweep(budget: &Budget, mut claim: Claim, mut force: bool) {
    let Some(root) = &budget.root else {
        return;
    };
    loop {
        run(root, &budget.limits, force);
        if !claim.rerun() {
            return;
        }
        force = true;
    }
}

/// Caches this process is sweeping, by root, each with whether a forced sweep
/// was asked for while it ran.
static ACTIVE: Mutex<BTreeMap<PathBuf, bool>> = Mutex::new(BTreeMap::new());

/// This process's claim on sweeping one cache: one sweep per cache at a time.
/// Released when dropped, so a panicking sweep cannot wedge the cache.
#[derive(Debug)]
struct Claim {
    root: PathBuf,
    released: bool,
}

impl Claim {
    /// The claim on `budget`'s cache, unless it is already being swept — in
    /// which case a `force`d request is queued for that sweep to run again.
    fn take(budget: &Budget, force: bool) -> Option<Self> {
        let root = budget.root.as_ref()?;
        let mut active = ACTIVE.lock().unwrap_or_else(PoisonError::into_inner);
        let claimed = match active.get_mut(root) {
            Some(rerun) => {
                *rerun |= force;
                false
            }
            None => {
                active.insert(root.clone(), false);
                true
            }
        };
        drop(active);
        if !claimed {
            tracing::debug!(
                target: "cache_sweep",
                root = %root.display(),
                queued = force,
                "cache sweep already running"
            );
            return None;
        }
        Some(Self {
            root: root.clone(),
            released: false,
        })
    }

    /// Whether a forced sweep was asked for since the last call, clearing the
    /// request; if not, the claim is released.
    fn rerun(&mut self) -> bool {
        let mut active = ACTIVE.lock().unwrap_or_else(PoisonError::into_inner);
        let rerun = active.get_mut(&self.root).is_some_and(std::mem::take);
        if !rerun {
            active.remove(&self.root);
            self.released = true;
        }
        drop(active);
        rerun
    }
}

impl Drop for Claim {
    fn drop(&mut self) {
        if !self.released {
            ACTIVE
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&self.root);
        }
    }
}

/// Entries written to each cache by this process since it last triggered a
/// sweep of that cache.
static WRITES: Mutex<BTreeMap<PathBuf, usize>> = Mutex::new(BTreeMap::new());

/// Record one entry written to the blob cache at `dir`, sweeping it once this
/// process has written `limits.max_entries` there.
///
/// The marker gates sweeps on elapsed *time*, which a bulk fetch defeats: it
/// can write far past the ceiling between two daily sweeps, all within one
/// process whose startup sweep found nothing to do. Counting writes closes
/// that gap without a second timer.
pub(crate) fn note_write(dir: &Path, limits: Limits) {
    let mut writes = WRITES.lock().unwrap_or_else(PoisonError::into_inner);
    let count = writes.entry(dir.to_path_buf()).or_insert(0);
    *count += 1;
    let reached = *count >= limits.max_entries;
    if reached {
        *count = 0;
    }
    drop(writes);
    if !reached {
        return;
    }
    if !disk::is_blob_cache(dir) {
        tracing::warn!(
            target: "cache_sweep",
            root = %dir.display(),
            "not sweeping a cache directory that holds other files"
        );
        return;
    }
    tracing::debug!(
        target: "cache_sweep",
        root = %dir.display(),
        writes = limits.max_entries,
        "write count reached the entry ceiling; sweeping"
    );
    start(vec![Budget::new(Some(dir.to_path_buf()), limits)], true);
}

/// An entry considered for eviction: its files (a blob and its sidecar share
/// one), and the size and newest mtime read once and reused by both passes.
#[derive(Debug)]
struct Entry {
    paths: Vec<PathBuf>,
    modified: SystemTime,
    bytes: u64,
}

fn run(root: &Path, limits: &Limits, force: bool) {
    if !root.is_dir() || (!force && !due(root)) {
        return;
    }
    // Trust first: a refused root is left exactly as found, marker and all.
    let trusted = match disk::trust_root(root) {
        Ok(trusted) => trusted,
        Err(why) => {
            tracing::warn!(target: "cache_sweep", root = %root.display(), %why, "not sweeping");
            return;
        }
    };
    // Mark the start (mtime = now) so a racing process sees a fresh marker
    // and skips.
    let marker = root.join(MARKER);
    mark(&marker, MARK_STARTED);

    let mut entries = collect(root, trusted);
    let now = SystemTime::now();
    let mut freed = 0u64;
    let mut removed = 0usize;

    // Age pass: drop anything past the retention window outright.
    entries.retain(|e| {
        if now.duration_since(e.modified).unwrap_or_default() > limits.max_age && remove(e) {
            freed = freed.saturating_add(e.bytes);
            removed += 1;
            false
        } else {
            true
        }
    });

    // Count/size pass: over either ceiling, evict oldest first until under 90%
    // of both. Stopping at 90% rather than exactly at the cap keeps a cache
    // sitting at the ceiling from re-triggering a sweep on the very next write.
    // Divide before multiplying so a `u64::MAX`/`usize::MAX` ceiling can't
    // overflow the target.
    let mut count = entries.len();
    let mut total = entries
        .iter()
        .fold(0, |sum: u64, e| sum.saturating_add(e.bytes));
    if total > limits.max_bytes || count > limits.max_entries {
        entries.sort_by_key(|e| e.modified); // oldest first
        let byte_target = limits.max_bytes / 10 * 9;
        let count_target = limits.max_entries / 10 * 9;
        for e in &entries {
            if total <= byte_target && count <= count_target {
                break;
            }
            if remove(e) {
                total = total.saturating_sub(e.bytes);
                count -= 1;
                freed = freed.saturating_add(e.bytes);
                removed += 1;
            }
        }
    }

    // Record completion, so the next run waits a full interval rather than
    // retrying. Not reached if this thread dies with its process mid-sweep.
    mark(&marker, MARK_DONE);
    tracing::debug!(
        target: "cache_sweep",
        root = %root.display(),
        removed,
        freed_bytes = freed,
        kept = count,
        kept_bytes = total,
        "swept cache"
    );
}

/// True unless this root was swept recently: within [`SWEEP_INTERVAL`] for a
/// sweep that finished, or [`RETRY_INTERVAL`] for one that died with its
/// process. A missing or unreadable marker counts as due, so a never-swept
/// cache is handled on the first run.
fn due(root: &Path) -> bool {
    let marker = root.join(MARKER);
    let Ok(started) = fs::metadata(&marker).and_then(|m| m.modified()) else {
        return true;
    };
    let Ok(elapsed) = started.elapsed() else {
        return true; // marker dated in the future (clock skew): sweep now
    };
    let interval = match read_marker(&marker).as_deref() {
        Some(MARK_DONE) => SWEEP_INTERVAL,
        _ => RETRY_INTERVAL,
    };
    elapsed >= interval
}

/// The marker's state, read only from a regular file and only as far as a
/// state is long: a marker swapped for a symlink to `/dev/zero` must not
/// exhaust memory, nor a FIFO stall the sweep.
fn read_marker(marker: &Path) -> Option<Vec<u8>> {
    if !fs::symlink_metadata(marker).ok()?.is_file() {
        return None;
    }
    let mut state = Vec::new();
    fs::File::open(marker)
        .ok()?
        .take(MAX_MARKER_BYTES)
        .read_to_end(&mut state)
        .ok()?;
    Some(state)
}

/// Record `state` in the marker, replacing whatever is there rather than
/// writing through it: a symlink planted in its place would otherwise aim the
/// write at any file this user can reach.
fn mark(marker: &Path, state: &[u8]) {
    let _ = fs::remove_file(marker);
    let written = disk::create_private(marker).and_then(|mut file| file.write_all(state));
    if let Err(error) = written {
        tracing::debug!(
            target: "cache_sweep",
            marker = %marker.display(),
            %error,
            "cannot write the sweep marker"
        );
    }
}

/// Every entry in the cache at `root`: those in its shards, each shard first
/// held to the root's trust, and any left at the top by a flatter layout.
fn collect(root: &Path, trusted: Trusted) -> Vec<Entry> {
    let mut entries = Vec::new();
    for shard in gather(root, &mut entries) {
        // Checked just before descending, narrowing the window for a shard
        // swapped for a symlink since it was listed.
        match trusted.admit(&shard) {
            Ok(()) => {
                gather(&shard, &mut entries);
            }
            Err(why) => tracing::warn!(
                target: "cache_sweep",
                shard = %shard.display(),
                %why,
                "not sweeping shard"
            ),
        }
    }
    entries
}

/// Append the entries among `dir`'s files to `out`, grouping the files of one
/// entry so a blob and its sidecar are evicted together, never split into an
/// orphan the reader cannot use. Returns `dir`'s shard directories; any other
/// directory is not the cache's and is left alone, as is the marker.
fn gather(dir: &Path, out: &mut Vec<Entry>) -> Vec<PathBuf> {
    let Ok(listing) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut shards = Vec::new();
    let mut entries: HashMap<PathBuf, Entry> = HashMap::new();
    for item in listing.flatten() {
        let name = item.file_name();
        let path = item.path();
        // `file_type` and `symlink_metadata` do not follow symlinks, so a
        // planted link is an entry to delete, never a tree to walk.
        let Ok(kind) = item.file_type() else {
            continue;
        };
        if kind.is_dir() {
            if disk::is_shard_name(&name) {
                shards.push(path);
            }
            continue;
        }
        if name == MARKER {
            continue;
        }
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        let Ok(modified) = meta.modified() else {
            continue;
        };
        // An entry lives or dies by its newest file, which the reader touches
        // on access.
        entries
            .entry(disk::entry_stem(&path))
            .and_modify(|entry| {
                entry.paths.push(path.clone());
                entry.bytes = entry.bytes.saturating_add(meta.len());
                entry.modified = entry.modified.max(modified);
            })
            .or_insert_with(|| Entry {
                paths: vec![path.clone()],
                modified,
                bytes: meta.len(),
            });
    }
    out.extend(entries.into_values());
    shards
}

/// Delete every file of `e`, each attempted even when another fails; `true`
/// when all are gone.
fn remove(e: &Entry) -> bool {
    e.paths.iter().fold(true, |all, path| {
        let removed = fs::remove_file(path);
        if let Err(error) = &removed {
            tracing::debug!(
                target: "cache_sweep",
                path = %path.display(),
                %error,
                "cannot evict cache file"
            );
        }
        removed.is_ok() && all
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_aged(path: &Path, bytes: usize, age: Duration) {
        let mut f = fs::File::create(path).unwrap();
        f.write_all(&vec![b'x'; bytes]).unwrap();
        f.set_modified(SystemTime::now() - age).unwrap();
    }

    fn day(n: u64) -> Duration {
        Duration::from_secs(n * 24 * 60 * 60)
    }

    /// Limits that keep 30 days and are otherwise unbounded.
    fn generous() -> Limits {
        Limits {
            max_age: day(30),
            max_bytes: u64::MAX,
            max_entries: usize::MAX,
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_planted_marker_symlink_is_replaced_not_written_through() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let victim = elsewhere.path().join("victim");
        fs::write(&victim, b"keep").unwrap();
        std::os::unix::fs::symlink(&victim, dir.path().join(MARKER)).unwrap();
        run(dir.path(), &generous(), true);
        assert_eq!(fs::read(&victim).unwrap(), b"keep", "victim untouched");
        let marker = fs::symlink_metadata(dir.path().join(MARKER)).unwrap();
        assert!(marker.is_file(), "the symlink was replaced by a marker");
        assert_eq!(
            read_marker(&dir.path().join(MARKER)).as_deref(),
            Some(MARK_DONE)
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_owned_root_is_made_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        run(dir.path(), &generous(), true);
        let mode = fs::metadata(dir.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
    }

    /// A root others can write is left exactly as found: nothing deleted,
    /// and no marker written into it before it was refused.
    #[cfg(unix)]
    #[test]
    fn a_root_others_can_write_is_never_touched() {
        use std::os::unix::fs::PermissionsExt;
        for mode in [0o777, 0o775, 0o770] {
            let dir = tempfile::tempdir().unwrap();
            write_aged(&dir.path().join("old.zst"), 10, day(40));
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(mode)).unwrap();
            run(dir.path(), &generous(), true);
            assert!(
                dir.path().join("old.zst").exists(),
                "{mode:o}: nothing deleted"
            );
            assert!(
                !dir.path().join(MARKER).exists(),
                "{mode:o}: no marker written"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_shard_others_can_write_is_never_swept() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        for shard in ["ab", "cd"] {
            fs::create_dir(dir.path().join(shard)).unwrap();
            write_aged(&dir.path().join(shard).join("k.zst"), 10, day(40));
        }
        fs::set_permissions(dir.path().join("cd"), fs::Permissions::from_mode(0o770)).unwrap();
        run(dir.path(), &generous(), true);
        assert!(
            !dir.path().join("ab/k.zst").exists(),
            "a trusted shard is swept"
        );
        assert!(dir.path().join("cd/k.zst").exists(), "a loose one is not");
    }

    #[test]
    fn age_pass_removes_only_old() {
        let dir = tempfile::tempdir().unwrap();
        write_aged(&dir.path().join("old.zst"), 10, day(40));
        write_aged(&dir.path().join("fresh.zst"), 10, day(1));
        run(dir.path(), &generous(), false);
        assert!(!dir.path().join("old.zst").exists(), "40-day entry evicted");
        assert!(dir.path().join("fresh.zst").exists(), "1-day entry kept");
    }

    #[test]
    fn size_pass_evicts_oldest_first() {
        let dir = tempfile::tempdir().unwrap();
        for (i, age) in [5u64, 4, 3, 2, 1].into_iter().enumerate() {
            write_aged(&dir.path().join(format!("e{i}.zst")), 400, day(age));
        }
        let limits = Limits {
            max_bytes: 1000,
            ..generous()
        };
        run(dir.path(), &limits, false);
        for gone in ["e0.zst", "e1.zst", "e2.zst"] {
            assert!(!dir.path().join(gone).exists(), "{gone}: oldest evicted");
        }
        for kept in ["e3.zst", "e4.zst"] {
            assert!(dir.path().join(kept).exists(), "{kept}: newest kept");
        }
    }

    /// A blob and its sidecar are one entry: the oldest pair goes whole, and
    /// the cut never falls between the two files of a pair.
    #[test]
    fn a_blob_and_its_sidecar_are_evicted_together() {
        let dir = tempfile::tempdir().unwrap();
        // Three pairs; the cut is reached after the oldest pair's blob alone
        // would have satisfied it, were files counted one by one.
        for (key, age) in [("a", 3u64), ("b", 2), ("c", 1)] {
            write_aged(&dir.path().join(format!("{key}.zst")), 300, day(age));
            write_aged(
                &dir.path().join(format!("{key}.json")),
                10,
                day(age) - Duration::from_secs(60),
            );
        }
        let limits = Limits {
            max_bytes: 700,
            ..generous()
        };
        run(dir.path(), &limits, false);
        for name in ["a.zst", "a.json"] {
            assert!(
                !dir.path().join(name).exists(),
                "{name}: the oldest pair goes whole"
            );
        }
        for name in ["b.zst", "b.json", "c.zst", "c.json"] {
            assert!(dir.path().join(name).exists(), "{name} kept");
        }
    }

    /// The cache keeps entries in shard directories; the sweep finds them
    /// there, reclaims what a flat layout left at the top, and leaves alone a
    /// directory that is not a shard.
    #[test]
    fn a_sharded_cache_is_swept_and_its_flat_leftovers_reclaimed() {
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path();
        for sub in ["ab", "cd", "notes"] {
            fs::create_dir_all(dir.join(sub)).unwrap();
        }
        for name in ["ab/ab1.zst", "ab/ab1.json", "flat.zst", "flat.json"] {
            write_aged(&dir.join(name), 10, day(40));
        }
        for name in ["cd/cd1.zst", "cd/cd1.json", "recent.zst", "notes/old.txt"] {
            write_aged(&dir.join(name), 10, day(1));
        }
        write_aged(&dir.join("notes/older.txt"), 10, day(40));
        run(dir, &generous(), true);
        for gone in ["ab/ab1.zst", "ab/ab1.json", "flat.zst", "flat.json"] {
            assert!(!dir.join(gone).exists(), "{gone} is past retention");
        }
        for kept in ["cd/cd1.zst", "cd/cd1.json", "recent.zst", "notes/older.txt"] {
            assert!(
                dir.join(kept).exists(),
                "{kept} is recent or not the cache's"
            );
        }
    }

    #[test]
    fn count_pass_evicts_oldest_to_ninety_percent() {
        let dir = tempfile::tempdir().unwrap();
        // Thirteen tiny entries, oldest first; cap 10 → 90% = 9, so the four
        // oldest go. The byte ceiling is inert, isolating the count pass.
        for i in 0..13u64 {
            write_aged(&dir.path().join(format!("e{i:02}.zst")), 1, day(20 - i));
        }
        let limits = Limits {
            max_age: day(3650),
            max_entries: 10,
            ..generous()
        };
        run(dir.path(), &limits, false);
        let kept = fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name() != MARKER)
            .count();
        assert_eq!(kept, 9, "evicted down to 90% of the cap");
        assert!(!dir.path().join("e00.zst").exists(), "oldest evicted");
        assert!(!dir.path().join("e03.zst").exists());
        assert!(dir.path().join("e04.zst").exists(), "newest kept");
    }

    #[test]
    fn unfinished_marker_retries_within_the_hour() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join(MARKER);
        let two_hours = Duration::from_secs(2 * 60 * 60);
        let backdate = |contents: &[u8]| {
            fs::write(&marker, contents).unwrap();
            fs::File::options()
                .write(true)
                .open(&marker)
                .unwrap()
                .set_modified(SystemTime::now() - two_hours)
                .unwrap();
        };

        backdate(MARK_DONE);
        assert!(!due(dir.path()), "completed sweep gates for SWEEP_INTERVAL");

        // A sweep that died mid-walk is retried instead: without this, a cache
        // too large to sweep inside one short-lived process is never swept.
        backdate(MARK_STARTED);
        assert!(
            due(dir.path()),
            "unfinished sweep is due again after RETRY_INTERVAL"
        );
    }

    #[test]
    fn marker_gates_and_survives() {
        let dir = tempfile::tempdir().unwrap();
        assert!(due(dir.path()), "no marker ⇒ due");
        run(dir.path(), &generous(), false);
        assert!(dir.path().join(MARKER).exists(), "sweep writes the marker");
        assert!(!due(dir.path()), "fresh marker ⇒ not due");
    }

    /// One sweep per cache at a time; a forced request that arrives while one
    /// runs is queued for it rather than dropped; other caches are separate.
    #[test]
    fn a_forced_sweep_during_another_is_queued_not_lost() {
        let dir = tempfile::tempdir().unwrap();
        let budget = |sub: &str| Budget::new(Some(dir.path().join(sub)), generous());
        let (a, b) = (budget("a"), budget("b"));

        let mut first = Claim::take(&a, false).expect("an idle cache is claimed");
        assert!(
            Claim::take(&b, false).is_some(),
            "another cache is separate"
        );
        assert!(Claim::take(&a, false).is_none(), "one sweep per cache");
        assert!(!first.rerun(), "nothing queued: the claim is released");

        let mut second = Claim::take(&a, false).expect("released");
        assert!(Claim::take(&a, true).is_none());
        assert!(second.rerun(), "the forced request is run, not dropped");
        assert!(!second.rerun());
        drop(second);
        assert!(Claim::take(&a, false).is_some(), "released for good");
    }

    #[test]
    fn a_dropped_claim_releases_its_cache() {
        let dir = tempfile::tempdir().unwrap();
        let budget = Budget::new(Some(dir.path().to_path_buf()), generous());
        drop(Claim::take(&budget, false));
        assert!(Claim::take(&budget, false).is_some());
    }
}
