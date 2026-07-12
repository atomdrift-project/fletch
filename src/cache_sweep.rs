//! Best-effort, non-blocking cache reclamation.
//!
//! A cache here is a directory of entries, each carrying an mtime. A *sweep*
//! deletes the oldest entries until the directory is within a time and size
//! budget. The whole thing runs on one detached thread that dies with the
//! process — no daemon, no async runtime, no persistent index.
//!
//! Two properties keep it cheap and safe:
//! - A once-a-day `.last-sweep` marker gates the walk, so the common case is a
//!   single `stat`, never a scan of a large directory.
//! - Every filesystem error is ignored: reclaiming disk must never disturb the
//!   program it runs alongside. Cache entries are written once and never
//!   rewritten, and on Unix unlinking a file another thread has open leaves that
//!   reader's descriptor valid, so a concurrent reader never sees a torn file.
//!
//! This is a verbatim copy of stng's `cache_sweep` mechanism (fletch does not
//! link stng, so a little copying beats a dependency edge); only the budget
//! helper — [`refs_budget`] — is fletch-specific. The 30-day retention is
//! deliberately well above the blob cache's 7-day pinned TTL, so the
//! stale-on-unreachable fallback in [`crate::fetch`] keeps working.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

/// Default retention window: entries older than this are dropped.
const DEFAULT_TTL_DAYS: u64 = 30;
/// Default aggregate ceiling for a generic budget: 2 GiB.
const DEFAULT_MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Default ceiling for fletch's blob cache: 10 GiB. Fetched package artifacts
/// are far larger than the derived caches elsewhere, so this tier gets more
/// headroom. Override with `FLETCH_CACHE_MAX_BYTES`.
const FLETCH_DEFAULT_MAX_BYTES: u64 = 10 * 1024 * 1024 * 1024;
/// Re-walk a cache at most this often; cheaper runs just read the marker.
const SWEEP_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
/// Marker file whose mtime records the last sweep, written in the primary root.
const MARKER: &str = ".last-sweep";

/// A cache directory and how deep its entries live below it.
#[derive(Debug)]
pub struct Root {
    /// Directory to sweep.
    pub path: PathBuf,
    /// `1` = direct children are entries (files or dirs); `2` = grandchildren
    /// are entries and each child is a container to descend into.
    pub depth: u8,
}

/// One component's caches and the budget they must collectively stay within.
#[derive(Debug)]
pub struct Budget {
    /// Component name, for a debug log line.
    pub label: &'static str,
    /// One or more directories sharing the `max_bytes` ceiling. The first is
    /// the *primary* root and holds the sweep marker.
    pub roots: Vec<Root>,
    /// Delete entries older than this.
    pub max_age: Duration,
    /// After the age pass, delete oldest entries until the total across all
    /// roots is at or below this.
    pub max_bytes: u64,
}

/// One sweep in flight per process; a second [`spawn`] is a no-op until it ends.
static RUNNING: AtomicBool = AtomicBool::new(false);

/// Clears [`RUNNING`] on drop, so a panic inside the sweep can never wedge every
/// future [`spawn`] into a permanent no-op.
struct RunningGuard;

impl Drop for RunningGuard {
    fn drop(&mut self) {
        RUNNING.store(false, Ordering::Release);
    }
}

/// Sweep the blob cache on a detached thread and return immediately. Call once
/// at startup; the thread is reaped when the process exits and an interrupted
/// sweep is re-attempted on a later run.
pub fn cleanup() {
    spawn(vec![refs_budget()]);
}

/// fletch's budget: the blob cache under `…/fletch/refs`. Empty when no OS cache
/// directory is available (the sweep then no-ops).
#[must_use]
pub fn refs_budget() -> Budget {
    let roots = crate::fetch::refs_dir()
        .map(|path| Root { path, depth: 1 })
        .into_iter()
        .collect();
    Budget {
        label: "fletch",
        roots,
        max_age: max_age_from_env("FLETCH_CACHE_TTL_DAYS"),
        max_bytes: max_bytes_from_env_or("FLETCH_CACHE_MAX_BYTES", FLETCH_DEFAULT_MAX_BYTES),
    }
}

/// Sweep `budgets` on a detached thread and return immediately. The thread is
/// reaped when the process exits; a partial sweep simply resumes next run.
pub fn spawn(mut budgets: Vec<Budget>) {
    budgets.retain(|b| !b.roots.is_empty());
    if budgets.is_empty() {
        return;
    }
    if RUNNING.swap(true, Ordering::AcqRel) {
        return; // a sweep is already running
    }
    // `Builder::spawn` returns an error (rather than panicking) if the OS
    // refuses the thread; reset the guard so a later call can retry.
    let started = std::thread::Builder::new()
        .name("fletch-cache-sweep".into())
        .spawn(move || {
            let _guard = RunningGuard;
            run_all(&budgets);
        });
    if started.is_err() {
        RUNNING.store(false, Ordering::Release);
    }
}

/// Sweep `budgets` now and every `interval` thereafter, on one detached thread,
/// for the life of the process. For daemons whose process never exits, so a
/// startup-only sweep would never fire again. The daily marker keeps each wake
/// cheap regardless of `interval`.
pub fn spawn_periodic(mut budgets: Vec<Budget>, interval: Duration) {
    budgets.retain(|b| !b.roots.is_empty());
    if budgets.is_empty() {
        return;
    }
    let _ = std::thread::Builder::new()
        .name("fletch-cache-sweep".into())
        .spawn(move || {
            loop {
                run_all(&budgets);
                std::thread::sleep(interval);
            }
        });
}

/// Retention window from `var` (in days), or the 30-day default. `saturating_mul`
/// so an absurd env value can't overflow into a panic (debug) or wrap (release).
#[must_use]
pub fn max_age_from_env(var: &str) -> Duration {
    let days = std::env::var(var)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&d| d > 0)
        .unwrap_or(DEFAULT_TTL_DAYS);
    Duration::from_secs(days.saturating_mul(24 * 60 * 60))
}

/// Byte ceiling from `var`, or the 2 GiB default.
#[must_use]
pub fn max_bytes_from_env(var: &str) -> u64 {
    max_bytes_from_env_or(var, DEFAULT_MAX_BYTES)
}

/// Byte ceiling from `var`, or `default` when unset or invalid.
#[must_use]
pub fn max_bytes_from_env_or(var: &str, default: u64) -> u64 {
    std::env::var(var)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&b| b > 0)
        .unwrap_or(default)
}

fn run_all(budgets: &[Budget]) {
    for b in budgets {
        run(b);
    }
}

/// An entry considered for eviction: its path, whether it is a directory, and
/// the size and mtime read once and reused by both passes.
struct Entry {
    path: PathBuf,
    is_dir: bool,
    modified: SystemTime,
    bytes: u64,
}

fn run(b: &Budget) {
    let Some(primary) = b.roots.first() else {
        return;
    };
    if !due(&primary.path) {
        return;
    }
    // Mark the start (mtime = now) so a racing process sees a fresh marker and
    // skips. Best-effort; if the directory doesn't exist yet, there's nothing
    // to sweep anyway.
    let _ = fs::write(primary.path.join(MARKER), b"");

    let mut entries = Vec::new();
    for r in &b.roots {
        collect(&r.path, r.depth, &mut entries);
    }

    let now = SystemTime::now();
    let mut freed = 0u64;
    let mut removed = 0usize;

    // Age pass: drop anything past the retention window outright.
    entries.retain(|e| {
        if now.duration_since(e.modified).unwrap_or_default() > b.max_age && remove(e) {
            freed += e.bytes;
            removed += 1;
            false
        } else {
            true
        }
    });

    // Size pass: if still over budget, evict oldest first to 90% of the cap.
    let mut total: u64 = entries.iter().map(|e| e.bytes).sum();
    if total > b.max_bytes {
        entries.sort_by_key(|e| e.modified); // oldest first
        let target = b.max_bytes / 10 * 9;
        for e in &entries {
            if total <= target {
                break;
            }
            if remove(e) {
                total = total.saturating_sub(e.bytes);
                freed += e.bytes;
                removed += 1;
            }
        }
    }

    if removed > 0 {
        tracing::debug!(
            target: "cache_sweep",
            component = b.label,
            removed,
            freed_bytes = freed,
            "swept cache"
        );
    }
}

/// True unless this root was swept within [`SWEEP_INTERVAL`]. A missing or
/// unreadable marker counts as due, so a never-swept cache is handled on the
/// first run.
fn due(root: &Path) -> bool {
    match fs::metadata(root.join(MARKER)).and_then(|m| m.modified()) {
        Ok(t) => t.elapsed().map(|e| e >= SWEEP_INTERVAL).unwrap_or(true),
        Err(_) => true,
    }
}

/// Gather the cache entries at `depth` below `root` into `out`. At `depth <= 1`
/// each child is an entry; deeper, each directory child is descended into.
fn collect(root: &Path, depth: u8, out: &mut Vec<Entry>) {
    let Ok(rd) = fs::read_dir(root) else {
        return;
    };
    for e in rd.flatten() {
        let Ok(ft) = e.file_type() else {
            continue;
        };
        let path = e.path();
        if depth <= 1 {
            if path.file_name().is_some_and(|n| n == MARKER) {
                continue; // never evict our own marker
            }
            if let Some(entry) = stat_entry(path, ft.is_dir()) {
                out.push(entry);
            }
        } else if ft.is_dir() {
            collect(&path, depth - 1, out);
        }
    }
}

fn stat_entry(path: PathBuf, is_dir: bool) -> Option<Entry> {
    let meta = fs::metadata(&path).ok()?;
    let modified = meta.modified().ok()?;
    let bytes = if is_dir { dir_size(&path) } else { meta.len() };
    Some(Entry {
        path,
        is_dir,
        modified,
        bytes,
    })
}

/// Recursive byte size of a directory entry. Recursion is gated on `file_type()`
/// (which does NOT follow symlinks), so a symlink loop can't cause a
/// stack-overflow abort and a symlink to a large tree can't inflate the total.
fn dir_size(dir: &Path) -> u64 {
    let Ok(rd) = fs::read_dir(dir) else {
        return 0;
    };
    let mut total = 0;
    for e in rd.flatten() {
        let Ok(ft) = e.file_type() else {
            continue;
        };
        if ft.is_dir() {
            total += dir_size(&e.path());
        } else if ft.is_file() {
            total += e.metadata().map(|m| m.len()).unwrap_or(0);
        }
    }
    total
}

fn remove(e: &Entry) -> bool {
    let r = if e.is_dir {
        fs::remove_dir_all(&e.path)
    } else {
        fs::remove_file(&e.path)
    };
    r.is_ok()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::io::Write;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("fletch-sweep-{}-{}", std::process::id(), name));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_aged(path: &Path, bytes: usize, age: Duration) {
        let mut f = fs::File::create(path).unwrap();
        f.write_all(&vec![b'x'; bytes]).unwrap();
        f.set_modified(SystemTime::now() - age).unwrap();
    }

    fn day(n: u64) -> Duration {
        Duration::from_secs(n * 24 * 60 * 60)
    }

    #[cfg(unix)]
    #[test]
    fn dir_size_does_not_follow_symlink_loops() {
        let dir = scratch("symloop");
        let sub = dir.join("sub");
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join("a.zst"), b"1234567890").unwrap(); // 10 bytes
        std::os::unix::fs::symlink(&dir, sub.join("loop")).unwrap();
        assert_eq!(dir_size(&dir), 10, "the symlink is neither followed nor counted");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn age_pass_removes_only_old() {
        let dir = scratch("age");
        write_aged(&dir.join("old.zst"), 10, day(40));
        write_aged(&dir.join("fresh.zst"), 10, day(1));
        run(&Budget {
            label: "test",
            roots: vec![Root {
                path: dir.clone(),
                depth: 1,
            }],
            max_age: day(30),
            max_bytes: u64::MAX,
        });
        assert!(!dir.join("old.zst").exists(), "40-day entry evicted");
        assert!(dir.join("fresh.zst").exists(), "1-day entry kept");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn size_pass_evicts_oldest_first() {
        let dir = scratch("size");
        for (i, age) in [5u64, 4, 3, 2, 1].into_iter().enumerate() {
            write_aged(&dir.join(format!("e{i}.zst")), 400, day(age));
        }
        run(&Budget {
            label: "test",
            roots: vec![Root {
                path: dir.clone(),
                depth: 1,
            }],
            max_age: day(3650),
            max_bytes: 1000,
        });
        assert!(!dir.join("e0.zst").exists(), "oldest evicted");
        assert!(!dir.join("e1.zst").exists());
        assert!(!dir.join("e2.zst").exists());
        assert!(dir.join("e3.zst").exists(), "newest kept");
        assert!(dir.join("e4.zst").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn marker_gates_and_survives() {
        let dir = scratch("gate");
        assert!(due(&dir), "no marker ⇒ due");
        run(&Budget {
            label: "test",
            roots: vec![Root {
                path: dir.clone(),
                depth: 1,
            }],
            max_age: day(30),
            max_bytes: u64::MAX,
        });
        assert!(dir.join(MARKER).exists(), "sweep writes the marker");
        assert!(!due(&dir), "fresh marker ⇒ not due");
        let _ = fs::remove_dir_all(&dir);
    }
}
