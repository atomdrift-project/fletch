//! The blob cache's on-disk layout and the trust its directories must earn.
//!
//! The layout, in one place for the reader, the writer and the sweep:
//!
//! ```text
//! <root>/.last-sweep           sweep marker
//! <root>/<ab>/                 shard: the first two hex digits of the key
//! <root>/<ab>/<key>.zst        the body, zstd-compressed
//! <root>/<ab>/<key>.json       its provenance sidecar
//! <root>/<ab>/<key>.part.…     a spool, while a fetch is written out
//! <root>/<ab>/<key>.tmp.…      a write in progress, renamed into place
//! ```
//!
//! A blob and its sidecar share a stem and are one entry: the sweep evicts
//! them together.
//!
//! Trust: a cache directory is used only when it is a real directory owned by
//! this process's user and writable by no one else (`mode & 0o022 == 0`); one
//! that others can merely read is made owner-only (`0o700`). Anything else is
//! refused, by the reader, the writer and the sweep alike, through
//! [`trust_root`] and [`Trusted::admit`]. A directory others can write lets
//! them plant entries that would be served as fetched bytes, or swap an entry
//! for a symlink between the sweep listing and deleting it.
//!
//! Ownership and modes are Unix concepts: on other platforms these checks
//! reduce to "is a directory", and the cache relies on the platform's
//! per-user cache location for its privacy.

use std::cell::Cell;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// The sweep marker, in the cache root.
pub(crate) const MARKER: &str = ".last-sweep";

/// The prefix of the throwaway file that learns which user this process's
/// files belong to (see [`trust_root`]).
const PROBE_PREFIX: &str = ".probe.";

/// Extension of an entry's compressed body.
const BLOB_EXT: &str = "zst";

/// Extension of an entry's provenance sidecar.
const META_EXT: &str = "json";

/// The shard directory name for `key`: its first two hex digits.
pub(crate) fn shard_name(key: &str) -> &str {
    key.get(..2).unwrap_or("00")
}

/// The file name of `key`'s body.
pub(crate) fn blob_name(key: &str) -> String {
    format!("{key}.{BLOB_EXT}")
}

/// The file name of `key`'s sidecar.
pub(crate) fn meta_name(key: &str) -> String {
    format!("{key}.{META_EXT}")
}

/// The entry a cache file belongs to: its path less the last extension, so
/// `<key>.zst` and `<key>.json` group as one.
pub(crate) fn entry_stem(path: &Path) -> PathBuf {
    path.with_extension("")
}

/// Whether `name` is a shard directory's: two lowercase hex digits.
pub(crate) fn is_shard_name(name: &OsStr) -> bool {
    name.to_str().is_some_and(|n| n.len() == 2 && is_hex(n))
}

fn is_hex(s: &str) -> bool {
    s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Whether `dir` holds nothing but a blob cache's own names — shards, entries
/// left at the top by a flatter layout (`<64 hex>.…`), the sweep marker and a
/// trust probe — so a write-triggered sweep never reaches files that happen to
/// share a directory a caller passed to
/// [`BlobCache::with_dir`](crate::fetch::BlobCache::with_dir).
pub(crate) fn is_blob_cache(dir: &Path) -> bool {
    let Ok(entries) = fs::read_dir(dir) else {
        return false;
    };
    entries.flatten().all(|e| {
        let name = e.file_name();
        let Some(name) = name.to_str() else {
            return false;
        };
        // Finder drops a `.DS_Store` into any directory it has shown.
        matches!(name, MARKER | ".DS_Store")
            || name.starts_with(PROBE_PREFIX)
            || is_shard_name(OsStr::new(name))
            || name.get(..64).is_some_and(is_hex)
    })
}

/// A name no other process or call can predict: the pid, a sequence number
/// and a random tag. The keys a cache names files after are hashes of
/// attacker-chosen locators and the pid is public, so without the tag anyone
/// sharing a directory could plant the path first.
pub(crate) fn unique_suffix() -> String {
    use std::hash::{BuildHasher, RandomState};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    format!(
        "{}.{seq}.{:016x}",
        std::process::id(),
        RandomState::new().hash_one(seq)
    )
}

/// Why a cache directory is not used.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Distrust {
    /// It cannot be inspected (or, for a root, does not exist).
    #[error("cannot be inspected: {0}")]
    Unreadable(io::Error),
    /// It is something other than a directory — a symlink, for a shard.
    #[error("not a directory")]
    NotADirectory,
    /// Another user owns it.
    #[error("owned by another user")]
    ForeignOwner,
    /// Someone else can write in it.
    #[error("writable by group or others")]
    Writable,
    /// This user cannot write in it.
    #[error("not writable: {0}")]
    ReadOnly(io::Error),
}

/// A cache root that passed [`trust_root`], carrying the owner every
/// directory beneath it must share.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Trusted {
    #[cfg(unix)]
    uid: u32,
}

/// Hold the existing directory `root` to the cache's trust rule (see the
/// module docs), making it owner-only when others can read it. The root may be reached through a symlink (a relocated
/// `~/.cache`); the directories beneath it may not.
///
/// std cannot name this process's user, so it is learned as the owner of a
/// throwaway file created in `root` — which also proves the directory is
/// writable, as a cache must be. Only a root no one else can write is probed.
pub(crate) fn trust_root(root: &Path) -> Result<Trusted, Distrust> {
    let meta = fs::metadata(root).map_err(Distrust::Unreadable)?;
    if !meta.is_dir() {
        return Err(Distrust::NotADirectory);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.mode() & 0o022 != 0 {
            return Err(Distrust::Writable);
        }
        let probe = root.join(format!("{PROBE_PREFIX}{}", unique_suffix()));
        let owner = create_private(&probe)
            .and_then(|file| file.metadata())
            .map(|m| m.uid());
        let _ = fs::remove_file(&probe);
        let trusted = Trusted {
            uid: owner.map_err(Distrust::ReadOnly)?,
        };
        hold(root, &meta, trusted.uid)?;
        Ok(trusted)
    }
    #[cfg(not(unix))]
    Ok(Trusted {})
}

impl Trusted {
    /// Hold `dir`, a directory inside the trusted root, to the same rule. It
    /// must be a directory itself, not a symlink to one.
    pub(crate) fn admit(self, dir: &Path) -> Result<(), Distrust> {
        let meta = fs::symlink_metadata(dir).map_err(Distrust::Unreadable)?;
        #[cfg(unix)]
        return hold(dir, &meta, self.uid);
        #[cfg(not(unix))]
        return if meta.is_dir() {
            Ok(())
        } else {
            Err(Distrust::NotADirectory)
        };
    }
}

/// The trust rule for one directory whose metadata is `meta`.
#[cfg(unix)]
fn hold(dir: &Path, meta: &fs::Metadata, uid: u32) -> Result<(), Distrust> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !meta.is_dir() {
        return Err(Distrust::NotADirectory);
    }
    if meta.uid() != uid {
        return Err(Distrust::ForeignOwner);
    }
    let mode = meta.mode();
    if mode & 0o022 != 0 {
        return Err(Distrust::Writable);
    }
    if mode & 0o077 != 0 {
        // Readable by others is a privacy leak, not a trust failure: the
        // cache records what was scanned. Nobody else can have written here.
        match fs::set_permissions(dir, fs::Permissions::from_mode(0o700)) {
            Ok(()) => tracing::debug!(
                target: "cache",
                dir = %dir.display(),
                mode = format_args!("{:o}", mode & 0o777),
                "made cache directory owner-only"
            ),
            Err(error) => tracing::warn!(
                target: "cache",
                dir = %dir.display(),
                %error,
                "cannot make cache directory owner-only"
            ),
        }
    }
    Ok(())
}

/// Create `dir` and any missing parents, owner-only on Unix. Directories that
/// already exist are left as they are; [`trust_root`] and [`Trusted::admit`]
/// judge those.
pub(crate) fn create_private_dir(dir: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir)
}

/// Create the new file `path` for writing, owner-only on Unix. `create_new`
/// fails on any existing path, a symlink included, rather than writing
/// through it.
pub(crate) fn create_private(path: &Path) -> io::Result<fs::File> {
    let mut options = fs::File::options();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}

/// Write `path` through a fresh temporary file, with `write`, and rename it
/// into place.
///
/// Two properties a plain `fs::write` does not have. The rename is atomic, so
/// a concurrent reader sees either the whole old file or the whole new one,
/// never a torn prefix. And both steps replace a *name* rather than writing
/// through one: `create_new` fails on an existing path instead of following
/// it, and `rename` unlinks whatever the destination was. So an entry planted
/// as a symlink is destroyed rather than followed into an arbitrary file.
pub(crate) fn write_replacing(
    path: &Path,
    write: impl FnOnce(&mut fs::File) -> io::Result<()>,
) -> io::Result<()> {
    let tmp = path.with_extension(format!("tmp.{}", unique_suffix()));
    let landed = create_private(&tmp)
        .and_then(|mut file| write(&mut file))
        .and_then(|()| fs::rename(&tmp, path));
    if landed.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    landed
}

/// A reader that tallies the bytes passing through it into `count`, which
/// outlives the reader — so a caller can still learn how far a consumer got
/// after handing the reader away or seeing it fail.
#[derive(Debug)]
pub(crate) struct Counted<'a, R> {
    inner: R,
    count: &'a Cell<u64>,
}

impl<'a, R> Counted<'a, R> {
    pub(crate) fn new(inner: R, count: &'a Cell<u64>) -> Self {
        Self { inner, count }
    }
}

impl<R: Read> Read for Counted<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.count.set(self.count.get().saturating_add(n as u64));
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_directory_of_cache_names_is_a_blob_cache() {
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path();
        fs::create_dir_all(dir.join("ab")).unwrap();
        fs::write(dir.join(MARKER), b"d").unwrap();
        fs::write(dir.join(blob_name(&"a".repeat(64))), b"x").unwrap();
        fs::write(dir.join(format!("{PROBE_PREFIX}1.2.3")), b"").unwrap();
        assert!(is_blob_cache(dir));
        fs::write(dir.join(".DS_Store"), b"x").unwrap();
        assert!(is_blob_cache(dir), "Finder's droppings don't disqualify it");
        fs::write(dir.join("thesis.tex"), b"x").unwrap();
        assert!(!is_blob_cache(dir), "a stranger's file disqualifies it");
    }

    #[test]
    fn a_blob_and_its_sidecar_share_an_entry() {
        let key = "ab12";
        assert_eq!(shard_name(key), "ab");
        assert_eq!(shard_name("a"), "00");
        assert_eq!(
            entry_stem(Path::new(&blob_name(key))),
            entry_stem(Path::new(&meta_name(key)))
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_files_are_owner_only_and_never_written_through() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        fs::write(&victim, b"keep").unwrap();
        let link = dir.path().join("planted");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        assert!(
            create_private(&link).is_err(),
            "a planted symlink is refused"
        );
        assert_eq!(fs::read(&victim).unwrap(), b"keep");

        let fresh = dir.path().join("fresh");
        create_private(&fresh).unwrap();
        let mode = fs::metadata(&fresh).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        let shard = dir.path().join("a/b");
        create_private_dir(&shard).unwrap();
        let mode = fs::metadata(&shard).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn a_readable_directory_is_made_private_and_a_writable_one_refused() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let set = |p: &Path, m| fs::set_permissions(p, fs::Permissions::from_mode(m)).unwrap();
        let root = tempfile::tempdir().unwrap();
        let root = root.path();

        set(root, 0o755);
        let trusted = trust_root(root).expect("an owned, readable root is trusted");
        assert_eq!(mode(root), 0o700, "and made owner-only");
        assert!(
            fs::read_dir(root).unwrap().next().is_none(),
            "the probe is gone"
        );

        let shard = root.join("ab");
        fs::create_dir(&shard).unwrap();
        set(&shard, 0o750);
        assert!(trusted.admit(&shard).is_ok());
        assert_eq!(mode(&shard), 0o700);

        for loose in [0o770, 0o775, 0o777, 0o757] {
            set(&shard, loose);
            assert!(trusted.admit(&shard).is_err(), "{loose:o} is refused");
            set(root, loose);
            assert!(trust_root(root).is_err(), "{loose:o} root is refused");
            set(root, 0o700);
        }

        set(&shard, 0o700);
        let elsewhere = tempfile::tempdir().unwrap();
        fs::remove_dir(&shard).unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), &shard).unwrap();
        assert!(
            trusted.admit(&shard).is_err(),
            "a symlinked shard is refused"
        );
    }

    #[test]
    fn a_replaced_file_is_never_written_through() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("entry.zst");
        write_replacing(&path, |f| io::Write::write_all(f, b"one")).unwrap();
        write_replacing(&path, |f| io::Write::write_all(f, b"two")).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"two");
        let failed = write_replacing(&path, |_| Err(io::Error::other("disk full")));
        assert!(failed.is_err());
        assert_eq!(
            fs::read(&path).unwrap(),
            b"two",
            "a failed write keeps the old"
        );
        assert_eq!(
            fs::read_dir(dir.path()).unwrap().count(),
            1,
            "no temporary is left"
        );
    }

    #[test]
    fn unique_suffixes_are_unguessable() {
        let (a, b) = (unique_suffix(), unique_suffix());
        assert_ne!(a, b);
        let tag = |s: &str| s.rsplit('.').next().unwrap().to_string();
        assert_eq!(tag(&a).len(), 16, "a 64-bit random tag ends the name");
        assert_ne!(tag(&a), tag(&b));
    }
}
