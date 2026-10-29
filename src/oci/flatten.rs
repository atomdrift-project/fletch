//! The flatten half of an export: merge an image's layer tars, read from disk,
//! into one xz-compressed rootfs tar, the way a container runtime would lay
//! them down.

use std::cell::Cell;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::{BufReader, Read, Write};
use std::ops::Bound;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::fetch::FetchError;
use crate::fetch::cache::Counted;

/// Bound on flattening and recompressing the layers: the CPU-bound half of an
/// export, which the pull's own deadline does not cover. Checked per tar
/// entry.
const FLATTEN_DEADLINE: Duration = Duration::from_secs(30 * 60);

/// Longest entry or link name a layer may carry: Linux's `PATH_MAX`. Names are
/// attacker-sized (a GNU or PAX long name is bounded only by the layer), and
/// every name is held in memory while its layer is flattened.
const MAX_PATH: usize = 4096;

/// How a layer blob is encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Encoding {
    /// A plain tar.
    Tar,
    /// A gzip-compressed tar (any number of members, as Go reads it).
    Gzip,
    /// A zstd-compressed tar.
    Zstd,
}

/// One layer blob on disk.
#[derive(Debug, Clone, Copy)]
pub(super) struct Layer<'a> {
    pub(super) path: &'a Path,
    pub(super) encoding: Encoding,
}

/// Flatten `layers` (base → top order, as the manifest lists them) into one
/// xz-compressed rootfs tar written to `out`, which is returned. `cap` bounds
/// both the layers' expanded size, together, and the tar written.
///
/// Semantics follow go-containerregistry's `mutate.Extract` (`crane export`):
/// walk layers *top-down*, the highest layer's copy of a path wins, and a
/// `.wh.<name>` whiteout tombstones that path (and, for a directory,
/// everything under it) in the layers below. Within one layer the *last* copy
/// of a path wins, as it does when containerd or Docker extract the layer;
/// `mutate.Extract` keeps the first, which would let a layer show this scanner
/// a benign file while the runtime installs the one after it. Each layer ends
/// where Go's `archive/tar` ends it ([`check_end`]), and entries that tar
/// readers parse differently are refused outright ([`vet_entry`]).
///
/// Two deliberate divergences. The OCI image-spec's opaque-whiteout marker
/// (`.wh..wh..opq`, hiding a directory's lower-layer *contents* while keeping
/// the directory) is honored per spec. And an entry beneath a symlink already
/// emitted (`a -> /etc`, then `a/passwd`) is dropped: where a runtime would
/// follow the link, an extractor of the output would write outside its root.
///
/// The output is for analysis only and must never be extracted to disk:
/// symlink targets are kept as the image has them (`/etc/…`, `../…`), as are
/// device nodes and setuid bits.
pub(super) fn flatten<W: Write>(layers: &[Layer<'_>], out: W, cap: u64) -> Result<W, FetchError> {
    let deadline = Instant::now() + FLATTEN_DEADLINE;
    let mut builder = tar::Builder::new(LimitWriter {
        w: xz2::write::XzEncoder::new(out, 6),
        limit: cap,
        written: 0,
    });
    // Paths already emitted (exact-match dedup: a higher layer's file shadows
    // the same path below, never its siblings).
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    // What higher layers, and symlinks already emitted, hide.
    let mut shadows = Shadows::default();
    let mut expanded = 0u64;

    for (depth, layer) in layers.iter().rev().enumerate() {
        let plan = plan(layer, cap.saturating_sub(expanded), deadline)?;
        expanded = expanded.saturating_add(plan.size);
        let emitted = emit(
            layer,
            &plan,
            &mut builder,
            &mut seen,
            &mut shadows,
            deadline,
        )?;
        tracing::debug!(
            target: "oci",
            layer = layers.len() - depth - 1,
            bytes = plan.size,
            entries = plan.last.len(),
            emitted,
            "layer flattened"
        );
        // A layer's markers constrain the layers *below* it, never its own
        // entries, so they apply only now.
        for path in &plan.tombstones {
            shadows.tombstones.insert(path);
        }
        for path in &plan.opaque {
            shadows.beneath.insert(path);
        }
    }

    let limit = builder.into_inner().map_err(output)?;
    limit.w.finish().map_err(output)
}

/// A failure to write the output: over its cap, or the disk's.
#[expect(
    clippy::needless_pass_by_value,
    reason = "used as `map_err(output)`, which hands over the error by value"
)]
fn output(e: std::io::Error) -> FetchError {
    if e.kind() == std::io::ErrorKind::FileTooLarge {
        FetchError::TooLarge
    } else {
        FetchError::Io(format!("write flattened image: {e}"))
    }
}

/// What the first pass over a layer learns.
#[derive(Debug, Default)]
struct Plan {
    /// Each path's last entry in this layer — the one emitted — and whether
    /// it is something other than a directory.
    last: HashMap<Vec<u8>, (usize, bool)>,
    /// Paths this layer's `.wh.` markers tombstone in the layers below.
    tombstones: Vec<Vec<u8>>,
    /// Directories whose lower-layer contents this layer hides: opaque
    /// markers, and paths whose last entry here is a file, link or device —
    /// which replaces a lower layer's directory outright when a runtime
    /// applies the layer.
    opaque: Vec<Vec<u8>>,
    /// The layer's expanded size: as far as the second pass may read.
    size: u64,
}

/// The first pass over `layer`: [`Plan`] it, refusing it when it expands past
/// `budget` bytes. Tar reading is forward-only, so each pass decodes the blob
/// afresh from disk.
fn plan(layer: &Layer<'_>, budget: u64, deadline: Instant) -> Result<Plan, FetchError> {
    let read = Cell::new(0);
    let planned = decoded(layer, budget, &read).and_then(|body| plan_entries(body, deadline));
    // Checked first: a decoder stopped by the budget mid-stream looks like a
    // truncated (or, at a block boundary, a complete) archive.
    if read.get() > budget {
        return Err(FetchError::TooLarge);
    }
    Ok(Plan {
        size: read.get(),
        ..planned?
    })
}

fn plan_entries(body: impl Read, deadline: Instant) -> Result<Plan, FetchError> {
    let mut plan = Plan::default();
    let mut archive = tar::Archive::new(body);
    for (i, entry) in archive.entries().map_err(malformed)?.enumerate() {
        if Instant::now() >= deadline {
            return Err(FetchError::Timeout);
        }
        let mut entry = entry.map_err(malformed)?;
        vet_entry(&mut entry)?;
        let path = clean_path(&entry.path_bytes());
        let (dir, base) = split_dir_base(&path);
        if base == b".wh..wh..opq" {
            plan.opaque.push(dir.to_vec());
        } else if let Some(target) = base.strip_prefix(b".wh.") {
            plan.tombstones.push(join_dir(dir, target));
        }
        let replacing =
            !base.starts_with(b".wh.") && replaces_directory(entry.header().entry_type());
        plan.last.insert(path, (i, replacing));
    }
    check_end(archive.into_inner())?;
    let replaced: Vec<Vec<u8>> = plan
        .last
        .iter()
        .filter(|(path, (_, replacing))| *replacing && !path.is_empty())
        .map(|(path, _)| path.clone())
        .collect();
    plan.opaque.extend(replaced);
    Ok(plan)
}

/// Where a layer ends, held to Go's `archive/tar`, which containerd and Docker
/// extract layers with. Both readers stop at the first all-zero block; Go
/// then reads one more and refuses the layer unless it is absent or zero too.
/// `rest` is the layer after that first zero block. Nothing past the end
/// marker is ever read as entries: an entry hidden there is one the runtime
/// never installs, so letting it shadow one before the marker would show the
/// scanner a different file from the one that runs.
fn check_end(rest: impl Read) -> Result<(), FetchError> {
    let mut block = Vec::with_capacity(512);
    rest.take(512).read_to_end(&mut block).map_err(malformed)?;
    if block.is_empty() || (block.len() == 512 && block.iter().all(|&b| b == 0)) {
        Ok(())
    } else {
        Err(FetchError::Refused(
            "layer tar has data after a lone end-of-archive block".into(),
        ))
    }
}

/// The second pass over `layer`: append to `builder` each entry that is the
/// last copy of its path here and that nothing above hides. Returns how many
/// entries were appended.
fn emit<W: Write>(
    layer: &Layer<'_>,
    plan: &Plan,
    builder: &mut tar::Builder<W>,
    seen: &mut HashSet<Vec<u8>>,
    shadows: &mut Shadows,
    deadline: Instant,
) -> Result<usize, FetchError> {
    let read = Cell::new(0);
    let mut archive = tar::Archive::new(decoded(layer, plan.size, &read)?);
    let mut emitted = 0;
    for (i, entry) in archive.entries().map_err(malformed)?.enumerate() {
        if Instant::now() >= deadline {
            return Err(FetchError::Timeout);
        }
        let mut entry = entry.map_err(malformed)?;
        let path = clean_path(&entry.path_bytes());
        // An entry that cleans away to nothing names the archive root itself
        // (`./`, `.`, `/`, `..`). It carries no content, and `tar::Builder`
        // refuses an empty path outright — so emitting it would abort the
        // export. `./` opens virtually every layer any real builder produces,
        // so this is the common case, not the adversarial one.
        if path.is_empty() {
            continue;
        }
        let (_, base) = split_dir_base(&path);
        if base.starts_with(b".wh.")
            || plan.last.get(&path).map(|&(last, _)| last) != Some(i)
            || seen.contains(&path)
            || shadows.hides(&path)
        {
            continue;
        }
        if let Some(kind) = append_entry(builder, &mut entry, &path)? {
            emitted += 1;
            if kind.is_symlink() {
                shadows.beneath.insert(&path);
            }
        }
        seen.insert(path);
    }
    Ok(emitted)
}

/// `layer`'s tar, decoded as it is read from disk, read no further than one
/// byte past `limit` and tallied into `count`.
fn decoded<'c>(
    layer: &Layer<'_>,
    limit: u64,
    count: &'c Cell<u64>,
) -> Result<Counted<'c, std::io::Take<Box<dyn Read>>>, FetchError> {
    let file = std::fs::File::open(layer.path)
        .map(BufReader::new)
        .map_err(|e| FetchError::Io(format!("open layer: {e}")))?;
    let body: Box<dyn Read> = match layer.encoding {
        Encoding::Tar => Box::new(file),
        Encoding::Gzip => Box::new(flate2::bufread::MultiGzDecoder::new(file)),
        Encoding::Zstd => {
            Box::new(zstd::stream::read::Decoder::with_buffer(file).map_err(malformed)?)
        }
    };
    Ok(Counted::new(body.take(limit.saturating_add(1)), count))
}

/// A layer that does not read as a tar. Its digest was verified, so this is
/// the image's fault, not the network's.
#[expect(
    clippy::needless_pass_by_value,
    reason = "used as `map_err(malformed)`, which hands over the error by value"
)]
fn malformed(e: std::io::Error) -> FetchError {
    FetchError::Refused(format!("malformed layer tar: {e}"))
}

/// Refuse an entry that tar readers disagree on, so the rootfs analyzed is the
/// one a container runtime extracts. tar-rs takes the *first* of a repeated PAX
/// `path`/`linkpath`/`size` record where Go (containerd) takes the last, and
/// treats an empty one as set where Go ignores it; a GNU long name with an
/// embedded NUL is cut at the NUL by Go but not by tar-rs. Each lets one layer
/// read as two different file sets. Names past [`MAX_PATH`] are refused too.
fn vet_entry<R: Read>(entry: &mut tar::Entry<'_, R>) -> Result<(), FetchError> {
    let refuse = |why: &str| {
        Err(FetchError::Refused(format!(
            "ambiguous layer tar entry: {why}"
        )))
    };
    for name in [Some(entry.path_bytes()), entry.link_name_bytes()]
        .into_iter()
        .flatten()
    {
        if name.len() > MAX_PATH {
            return refuse("name longer than PATH_MAX");
        }
        if name.contains(&0) {
            return refuse("NUL in name");
        }
    }
    let Some(pax) = entry.pax_extensions().map_err(malformed)? else {
        return Ok(());
    };
    let mut keys: HashSet<&[u8]> = HashSet::new();
    for ext in pax {
        let ext = ext.map_err(malformed)?;
        let key = ext.key_bytes();
        if matches!(key, b"path" | b"linkpath" | b"size")
            && (ext.value_bytes().is_empty() || !keys.insert(key))
        {
            return refuse("empty or repeated PAX record");
        }
    }
    Ok(())
}

/// Copy one tar entry (path, link target, body) into the output under a
/// header built afresh, regenerating long-name/long-link extensions so paths
/// the source encoded via PAX/GNU records survive the transplant. Returns the
/// kind appended, or `None` for an entry dropped.
///
/// Never the source header itself: its size field need not frame the body
/// tar-rs yields (a PAX `size`, a GNU sparse map, a link with a nonzero size),
/// and copying it would let a layer's bytes parse as forged entries of the
/// output. So only the file types a rootfs holds are kept, sparse and
/// contiguous files become regular ones of their real size, and metadata
/// records (PAX globals, GNU volume and multivolume headers) and unknown types
/// are dropped.
///
/// The entry *name* is the cleaned path. A symlink's *target* is copied
/// verbatim, deliberately: absolute and `..`-relative targets are how a real
/// rootfs is built (`usr/sbin/x -> ../bin/y`, `/etc/alternatives/…`), so
/// rewriting them would misrepresent the filesystem being analyzed. A hard
/// link's target is another way of naming an entry *in the archive*, so it is
/// cleaned exactly as names are: it then matches the entry it links to, and
/// cannot point an extractor outside the root (`../../etc/passwd`). One that
/// cleans to the root names no file, and is dropped like a root entry.
fn append_entry<W: Write, R: Read>(
    builder: &mut tar::Builder<W>,
    entry: &mut tar::Entry<'_, R>,
    path: &[u8],
) -> Result<Option<tar::EntryType>, FetchError> {
    use tar::EntryType as T;
    let src = entry.header();
    let kind = match src.entry_type() {
        T::Regular | T::Continuous | T::GNUSparse => T::Regular,
        kind @ (T::Directory | T::Symlink | T::Link | T::Char | T::Block | T::Fifo) => kind,
        _ => return Ok(None),
    };
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(kind);
    header.set_size(0);
    header.set_mode(src.mode().unwrap_or(0o644) & 0o7777);
    header.set_uid(src.uid().unwrap_or(0));
    header.set_gid(src.gid().unwrap_or(0));
    header.set_mtime(src.mtime().unwrap_or(0));
    if let Ok(Some(name)) = src.username() {
        let _ = header.set_username(name);
    }
    if let Ok(Some(name)) = src.groupname() {
        let _ = header.set_groupname(name);
    }
    if matches!(kind, T::Char | T::Block)
        && let (Ok(Some(major)), Ok(Some(minor))) = (src.device_major(), src.device_minor())
    {
        let _ = header.set_device_major(major);
        let _ = header.set_device_minor(minor);
    }
    let written = if kind.is_symlink() || kind.is_hard_link() {
        let mut target = entry
            .link_name_bytes()
            .ok_or_else(|| FetchError::Refused("link entry without target".into()))?
            .into_owned();
        if kind.is_hard_link() {
            target = clean_path(&target);
            if target.is_empty() {
                return Ok(None);
            }
        }
        builder.append_link(&mut header, bytes_path(path), bytes_path(&target))
    } else if kind == T::Regular {
        header.set_size(entry.size());
        builder.append_data(&mut header, bytes_path(path), entry)
    } else {
        builder.append_data(&mut header, bytes_path(path), std::io::empty())
    };
    written.map_err(output)?;
    Ok(Some(kind))
}

/// `path::Clean`-alike over raw tar path bytes, as `path.Clean("/"+name)`
/// with the leading `/` dropped: resolve `.` and `..` segments and collapse
/// separators, so every layer spelling of one file (`./etc/passwd`,
/// `/etc/passwd`, `etc/passwd`, `foo/../etc/passwd`) keys the same entry.
///
/// Resolving `..` is load-bearing twice over, because layer entry names are
/// attacker-controlled. First, availability: `tar::Builder` refuses to write
/// a name containing `..`, so one such entry would abort the analysis of the
/// whole image — a one-byte way for a hostile image to opt out of being
/// scanned. Anchored at the root, `../../etc/cron.d/x` is `etc/cron.d/x` and
/// the image flattens. Second, shadowing: the cleaned path is the key for
/// `seen` and for whiteout matching, so an unresolved `a/../b` would compare
/// unequal to `b` and slip past a tombstone meant to hide it.
fn clean_path(raw: &[u8]) -> Vec<u8> {
    let mut out: Vec<&[u8]> = Vec::new();
    for segment in raw.split(|&b| b == b'/') {
        match segment {
            // Empty (a leading, trailing, or doubled `/`) and `.` are no-ops.
            b"" | b"." => {}
            // Anchored at the root, so a `..` above it has nothing to pop.
            b".." => {
                out.pop();
            }
            name => out.push(name),
        }
    }
    out.join(&b'/')
}

/// Split a cleaned path into (directory, basename); the directory is empty
/// for a root-level name.
fn split_dir_base(path: &[u8]) -> (&[u8], &[u8]) {
    match path.iter().rposition(|&b| b == b'/') {
        Some(i) => (&path[..i], &path[i + 1..]),
        None => (b"", path),
    }
}

fn join_dir(dir: &[u8], base: &[u8]) -> Vec<u8> {
    if dir.is_empty() {
        return base.to_vec();
    }
    [dir, b"/", base].concat()
}

/// Whether an entry kind is something [`append_entry`] emits other than a
/// directory — what replaces a lower layer's directory at the same path.
fn replaces_directory(kind: tar::EntryType) -> bool {
    use tar::EntryType as T;
    matches!(
        kind,
        T::Regular
            | T::Continuous
            | T::GNUSparse
            | T::Symlink
            | T::Link
            | T::Char
            | T::Block
            | T::Fifo
    )
}

/// What is hidden from the entries still to be emitted.
#[derive(Debug, Default)]
struct Shadows {
    /// Paths a higher layer's `.wh.` marker tombstoned: hidden, with
    /// everything beneath them.
    tombstones: Subtrees,
    /// Directories made opaque or replaced by a higher layer, and symlinks
    /// already emitted: everything strictly beneath them is hidden, the path
    /// itself kept.
    beneath: Subtrees,
}

impl Shadows {
    fn hides(&self, path: &[u8]) -> bool {
        self.tombstones.covers(path, true) || self.beneath.covers(path, false)
    }
}

/// A set of subtrees, each kept as its root's path plus a trailing `/` (the
/// archive root as the empty key), with no key a prefix of another: adding a
/// subtree already covered changes nothing, and adding one drops those it
/// covers. In such a set, ordered, the only key that can be an ancestor of a
/// path is the greatest key not above it — any key between the two would
/// itself extend the ancestor — so a lookup is one ordered probe, whatever
/// the name's depth.
#[derive(Debug, Default)]
struct Subtrees(BTreeSet<Vec<u8>>);

impl Subtrees {
    fn key(path: &[u8]) -> Vec<u8> {
        if path.is_empty() {
            Vec::new()
        } else {
            [path, b"/"].concat()
        }
    }

    /// The stored key that is `key` or one of its ancestors, if any.
    fn covering(&self, key: &[u8]) -> Option<&[u8]> {
        self.0
            .range::<[u8], _>((Bound::Unbounded, Bound::Included(key)))
            .next_back()
            .map(Vec::as_slice)
            .filter(|stored| key.starts_with(stored))
    }

    fn insert(&mut self, path: &[u8]) {
        let key = Self::key(path);
        if self.covering(&key).is_some() {
            return;
        }
        let covered: Vec<Vec<u8>> = self
            .0
            .range::<[u8], _>((Bound::Included(key.as_slice()), Bound::Unbounded))
            .take_while(|stored| stored.starts_with(&key))
            .cloned()
            .collect();
        for stored in covered {
            self.0.remove(&stored);
        }
        self.0.insert(key);
    }

    /// Whether `path` lies beneath one of the subtrees' roots — or, when
    /// `inclusive`, is one.
    fn covers(&self, path: &[u8], inclusive: bool) -> bool {
        let key = Self::key(path);
        self.covering(&key)
            .is_some_and(|stored| inclusive || stored.len() < key.len())
    }
}

/// Borrow a raw tar entry name as a `Path`.
///
/// Unix `OsStr` is arbitrary bytes, so this is a zero-copy view. Windows has no
/// equivalent — its `OsStr` is WTF-8 over UTF-16 code units, not bytes — so
/// there the name is borrowed only when it is valid UTF-8, which OCI layer
/// entry names are in practice. A non-UTF-8 name has no Windows path
/// representation at all; it yields an empty path rather than a lossily
/// mangled one, so the caller's `append_*` fails loudly instead of writing an
/// entry under a corrupted name.
#[cfg(unix)]
fn bytes_path(b: &[u8]) -> &Path {
    use std::os::unix::ffi::OsStrExt;
    Path::new(std::ffi::OsStr::from_bytes(b))
}

#[cfg(not(unix))]
fn bytes_path(b: &[u8]) -> &Path {
    Path::new(std::str::from_utf8(b).unwrap_or(""))
}

/// Forward writes until more than `limit` bytes pass, then fail: the bound on
/// the uncompressed tar fed to xz.
struct LimitWriter<W: Write> {
    w: W,
    limit: u64,
    written: u64,
}

impl<W: Write> Write for LimitWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.written + buf.len() as u64 > self.limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::FileTooLarge,
                "container image exceeds size cap",
            ));
        }
        let n = self.w.write(buf)?;
        self.written += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.w.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci::MAX_EXPORT_BYTES;
    use crate::oci::tests::{entries_of, hostile_layer, layer};

    /// Flatten `layers`, each a blob encoded as `encoding`, under `cap`.
    fn flatten_encoded(
        layers: &[Vec<u8>],
        encoding: Encoding,
        cap: u64,
    ) -> Result<Vec<u8>, FetchError> {
        let dir = tempfile::tempdir().unwrap();
        let paths: Vec<_> = layers
            .iter()
            .enumerate()
            .map(|(i, bytes)| {
                let path = dir.path().join(i.to_string());
                std::fs::write(&path, bytes).unwrap();
                path
            })
            .collect();
        let layers: Vec<Layer<'_>> = paths.iter().map(|path| Layer { path, encoding }).collect();
        flatten(&layers, Vec::new(), cap)
    }

    /// Flatten plain layer tars.
    fn flat(layers: &[Vec<u8>]) -> Result<Vec<u8>, FetchError> {
        flatten_encoded(layers, Encoding::Tar, MAX_EXPORT_BYTES)
    }

    #[test]
    fn top_layer_overrides_and_whiteout_deletes() {
        let base = layer(&[
            ("etc/passwd", "base"),
            ("data/old.txt", "old"),
            ("data/keep.txt", "keep"),
        ]);
        let top = layer(&[("etc/passwd", "top"), ("data/.wh.old.txt", "")]);
        let got = entries_of(&flat(&[base, top]).unwrap());

        // Top layer's entries come first (the top-down walk), the override
        // wins, the whiteout target and marker are both absent.
        assert_eq!(
            got,
            vec![
                ("etc/passwd".into(), "top".into()),
                ("data/keep.txt".into(), "keep".into()),
            ]
        );
    }

    #[test]
    fn opaque_dir_hides_lower_contents_recursively() {
        let base = layer(&[
            ("cfg/old.conf", "old"),
            ("cfg/sub/x", "x"),
            ("root.txt", "r"),
        ]);
        let top = layer(&[("cfg/.wh..wh..opq", ""), ("cfg/new.conf", "new")]);
        let got = entries_of(&flat(&[base, top]).unwrap());
        assert_eq!(
            got,
            vec![
                ("cfg/new.conf".into(), "new".into()),
                ("root.txt".into(), "r".into()),
            ]
        );
    }

    #[test]
    fn whiteout_of_a_directory_hides_its_subtree() {
        let base = layer(&[("bin/tool", "t"), ("bin/sub/y", "y"), ("lib/z", "z")]);
        let top = layer(&[(".wh.bin", "")]);
        let got = entries_of(&flat(&[base, top]).unwrap());
        assert_eq!(got, vec![("lib/z".into(), "z".into())]);
    }

    #[test]
    fn path_spellings_key_the_same_file() {
        // `./etc/passwd` and `etc/passwd` are the same path; the top layer's
        // spelling must still shadow the base.
        let base = layer(&[("etc/passwd", "base")]);
        let top = layer(&[("./etc/passwd", "top")]);
        let got = entries_of(&flat(&[base, top]).unwrap());
        assert_eq!(got, vec![("etc/passwd".into(), "top".into())]);
    }

    #[test]
    fn layers_are_capped_in_aggregate_not_individually() {
        // Each layer is comfortably under the cap; together they are over it.
        // A small download can expand to the cap per layer, so the ceiling
        // has to be on the sum.
        let one = layer(&[("f", &"x".repeat(1000))]);
        let size = one.len() as u64;
        let cap = size * 2 + size / 2;
        assert!(flatten_encoded(&[one.clone(), one.clone()], Encoding::Tar, cap).is_ok());
        assert_eq!(
            flatten_encoded(&[one.clone(), one.clone(), one], Encoding::Tar, cap),
            Err(FetchError::TooLarge)
        );
    }

    #[test]
    fn a_compressed_layer_is_decoded_from_disk_under_the_cap() {
        let tar = layer(&[("etc/motd", "hello"), ("big", &"\0".repeat(64 << 10))]);
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        gz.write_all(&tar).unwrap();
        let gz = gz.finish().unwrap();
        let zst = zstd::encode_all(tar.as_slice(), 3).unwrap();
        for (blob, encoding) in [(gz, Encoding::Gzip), (zst, Encoding::Zstd)] {
            assert!(blob.len() < tar.len() / 8, "a small download");
            let got = entries_of(
                &flatten_encoded(std::slice::from_ref(&blob), encoding, MAX_EXPORT_BYTES).unwrap(),
            );
            assert_eq!(got[0], ("etc/motd".into(), "hello".into()), "{encoding:?}");
            // Expanding past the cap is refused, not truncated into a tar
            // that would parse as something else.
            assert_eq!(
                flatten_encoded(&[blob], encoding, 32 << 10),
                Err(FetchError::TooLarge),
                "{encoding:?}"
            );
        }
    }

    #[test]
    fn root_entry_does_not_abort_the_export() {
        // Virtually every layer built by `docker build`/buildkit opens with a
        // `./` entry for the archive root. It cleans to the empty path, which
        // `tar::Builder` rejects outright ("paths in archives must have at
        // least one component") — so failing to skip it fails the export of
        // almost every real image, not just a crafted one.
        let base = layer(&[("./", ""), ("etc/passwd", "root:x:0:0")]);
        let got = entries_of(&flat(&[base]).expect("root entry must not abort"));
        assert_eq!(got, vec![("etc/passwd".into(), "root:x:0:0".into())]);
    }

    #[test]
    fn rootish_names_are_skipped_not_fatal() {
        // The same hazard reached deliberately: every spelling that cleans away
        // to nothing must be dropped, never turned into a failed export.
        let evil = hostile_layer(&[("..", "x"), ("/", "y"), (".", "z"), ("keep", "k")]);
        let got = entries_of(&flat(&[evil]).expect("must not abort"));
        assert_eq!(got, vec![("keep".into(), "k".into())]);
    }

    #[test]
    fn traversal_names_are_anchored_at_the_root() {
        // Layer entry names are attacker-controlled. Left unresolved,
        // `tar::Builder` rejects the `..` and fails the whole export, so a
        // single crafted name would let an image opt out of being analyzed.
        let evil = hostile_layer(&[
            ("../../../../etc/cron.d/x", "pwn"),
            ("a/b/../../../etc/shadow", "pwn2"),
        ]);
        let got = entries_of(&flat(&[evil]).unwrap());
        assert_eq!(
            got,
            vec![
                ("etc/cron.d/x".into(), "pwn".into()),
                ("etc/shadow".into(), "pwn2".into()),
            ]
        );
    }

    /// A raw 512-byte header block for a link `path` → `target`.
    fn link(path: &str, kind: tar::EntryType, target: &str) -> Vec<u8> {
        let mut h = tar::Header::new_gnu();
        h.set_size(0);
        h.set_mode(0o644);
        h.set_entry_type(kind);
        h.as_old_mut().name[..path.len()].copy_from_slice(path.as_bytes());
        h.as_old_mut().linkname[..target.len()].copy_from_slice(target.as_bytes());
        h.set_cksum();
        h.as_bytes().to_vec()
    }

    /// The (path, link target) of every link in a flattened image.
    fn links_of(tar_xz: &[u8]) -> Vec<(String, String)> {
        let mut raw = Vec::new();
        xz2::read::XzDecoder::new(tar_xz)
            .read_to_end(&mut raw)
            .unwrap();
        tar::Archive::new(raw.as_slice())
            .entries()
            .unwrap()
            .filter_map(|e| {
                let e = e.unwrap();
                let target = e.link_name().unwrap()?.display().to_string();
                Some((e.path().unwrap().display().to_string(), target))
            })
            .collect()
    }

    /// Hard links name another entry of the archive, so their targets are
    /// cleaned as entry names are — matching the cleaned name of what they
    /// link to, and anchored at the root. Symlink targets describe the image's
    /// filesystem and are kept as written.
    #[test]
    fn hard_link_targets_are_cleaned_like_names() {
        let mut layer = hostile_layer(&[("./usr/bin/a", "A")]);
        layer.truncate(layer.len() - 1024); // reopen past the end-of-archive
        for entry in [
            link("usr/bin/b", tar::EntryType::Link, "./usr/bin/a"),
            link("x", tar::EntryType::Link, "../../../etc/passwd"),
            link("root", tar::EntryType::Link, "../"),
            link("usr/sbin/y", tar::EntryType::Symlink, "../bin/a"),
        ] {
            layer.extend_from_slice(&entry);
        }
        layer.extend_from_slice(&[0u8; 1024]);
        assert_eq!(
            links_of(&flat(&[layer]).unwrap()),
            vec![
                ("usr/bin/b".into(), "usr/bin/a".into()),
                ("x".into(), "etc/passwd".into()),
                ("usr/sbin/y".into(), "../bin/a".into()),
            ]
        );
    }

    /// `a -> /etc` then `a/passwd`: an extractor of the output would follow
    /// the link out of its root, so nothing beneath an emitted symlink is
    /// emitted — in its own layer or any below.
    #[test]
    fn entries_beneath_an_emitted_symlink_are_dropped() {
        let mut top = hostile_layer(&[]);
        top.truncate(top.len() - 1024);
        top.extend_from_slice(&link("a", tar::EntryType::Symlink, "/etc"));
        top.extend_from_slice(&hostile_layer(&[("a/passwd", "root::0:0"), ("ab", "kept")]));
        let base = layer(&[("a/shadow", "x")]);
        let got = entries_of(&flat(&[base, top]).unwrap());
        assert_eq!(
            got,
            vec![("a".into(), String::new()), ("ab".into(), "kept".into())]
        );
    }

    #[test]
    fn traversal_spelling_cannot_evade_a_whiteout() {
        // The cleaned path is the shadowing key, so an unresolved `a/../secret`
        // would compare unequal to the tombstoned `secret` and survive.
        let base = hostile_layer(&[("dir/../secret", "leaked"), ("keep", "k")]);
        let top = layer(&[(".wh.secret", "")]);
        let got = entries_of(&flat(&[base, top]).unwrap());
        assert_eq!(got, vec![("keep".into(), "k".into())]);
    }

    #[test]
    fn markers_only_constrain_lower_layers() {
        // A whiteout and a fresh file for the same path in ONE layer: the
        // layer's own file must survive (markers apply strictly below).
        let base = layer(&[("app/a", "old")]);
        let top = layer(&[("app/.wh.a", ""), ("app/a", "new")]);
        let got = entries_of(&flat(&[base, top]).unwrap());
        assert_eq!(got, vec![("app/a".into(), "new".into())]);
    }

    /// The runtime reads a layer up to its end-of-archive marker and no
    /// further, so an entry hidden past the marker must not shadow the one
    /// before it that actually runs.
    #[test]
    fn entries_after_the_end_of_archive_are_never_read() {
        let mut evil = layer(&[("usr/bin/sshd", "evil")]);
        evil.extend_from_slice(&layer(&[("usr/bin/sshd", "benign"), ("decoy", "d")]));
        let got = entries_of(&flat(&[evil]).unwrap());
        assert_eq!(got, vec![("usr/bin/sshd".into(), "evil".into())]);
    }

    /// Go refuses a lone zero block followed by data, so the runtime never
    /// installs such a layer; neither reading of it is the one that runs.
    #[test]
    fn a_lone_end_block_followed_by_data_is_refused() {
        let mut odd = hostile_layer(&[("a", "1")]);
        odd.truncate(odd.len() - 512);
        odd.extend_from_slice(&hostile_layer(&[("b", "2")]));
        assert!(matches!(flat(&[odd]), Err(FetchError::Refused(_))));
        // A layer that simply ends after one zero block, or none, is fine.
        let mut short = hostile_layer(&[("a", "1")]);
        short.truncate(short.len() - 512);
        assert!(flat(&[short.clone()]).is_ok());
        short.truncate(short.len() - 512);
        assert!(flat(&[short]).is_ok());
    }

    /// A raw 512-byte header block: `name`, `kind`, and a declared `size`.
    fn raw_header(name: &str, kind: tar::EntryType, size: u64) -> Vec<u8> {
        let mut h = tar::Header::new_ustar();
        h.set_size(size);
        h.set_mode(0o644);
        h.set_entry_type(kind);
        h.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
        h.set_cksum();
        h.as_bytes().to_vec()
    }

    /// A layer of one PAX extension block carrying `records`, then the entry
    /// `name` whose ustar header declares size 0 and whose body is `body`.
    fn pax_layer(records: &str, name: &str, body: &[u8]) -> Vec<u8> {
        let mut out = raw_header("pax", tar::EntryType::XHeader, records.len() as u64);
        out.extend_from_slice(records.as_bytes());
        out.resize(out.len().div_ceil(512) * 512, 0);
        out.extend_from_slice(&raw_header(name, tar::EntryType::Regular, 0));
        out.extend_from_slice(body);
        out.resize(out.len().div_ceil(512) * 512, 0);
        out.extend_from_slice(&[0u8; 1024]);
        out
    }

    #[test]
    fn a_pax_size_cannot_forge_entries_in_the_output() {
        // The body tar-rs reads (PAX `size=512`) is itself a header block. A
        // copied header would still say 0 bytes, so a reader of the output
        // would parse the body as an entry that never existed in the image.
        let forged = raw_header("etc/forged", tar::EntryType::Regular, 0);
        let layer = pax_layer("12 size=512\n", "f", &forged);
        let got = entries_of(&flat(&[layer]).unwrap());
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].0, "f");
        assert_eq!(got[0].1.len(), 512);
    }

    #[test]
    fn ambiguous_pax_records_are_refused() {
        // Go keeps the last `path`, tar-rs the first: two readings of one layer.
        for records in ["12 path=abc\n12 path=xyz\n", "8 path=\n"] {
            let layer = pax_layer(records, "f", b"");
            assert!(
                matches!(flat(&[layer]), Err(FetchError::Refused(_))),
                "{records:?} must be refused"
            );
        }
    }

    #[test]
    fn overlong_names_are_refused() {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(0);
        h.set_mode(0o644);
        b.append_data(&mut h, "a/".repeat(MAX_PATH / 2 + 1), std::io::empty())
            .unwrap();
        let layer = b.into_inner().unwrap();
        assert!(matches!(flat(&[layer]), Err(FetchError::Refused(_))));
    }

    #[test]
    fn the_last_copy_of_a_path_in_a_layer_wins() {
        // containerd and Docker extract a layer in order, so the later copy is
        // the one that runs; showing the first would hide it.
        let layer = layer(&[("usr/bin/sshd", "benign"), ("usr/bin/sshd", "evil")]);
        let got = entries_of(&flat(&[layer]).unwrap());
        assert_eq!(got, vec![("usr/bin/sshd".into(), "evil".into())]);
    }

    /// A layer holding one symlink `path` → `target`.
    fn symlink_layer(path: &str, target: &str) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_size(0);
        h.set_mode(0o777);
        b.append_link(&mut h, path, target).unwrap();
        b.into_inner().unwrap()
    }

    #[test]
    fn a_directory_replaced_by_a_file_hides_what_was_beneath_it() {
        // A runtime applying the top layer removes the `etc` directory to put
        // a file there, so `etc/cron.d/evil` from below never reaches the
        // container — and must not reach the analysis as if it did.
        let base = layer(&[("etc/cron.d/evil", "x"), ("etcetera", "kept")]);
        let top = layer(&[("etc", "now a file")]);
        let got = entries_of(&flat(&[base, top]).unwrap());
        assert_eq!(
            got,
            vec![
                ("etc".into(), "now a file".into()),
                ("etcetera".into(), "kept".into())
            ]
        );

        // Likewise a symlink in the directory's place.
        let base = layer(&[("opt/app/bin", "x")]);
        let top = symlink_layer("opt", "/srv");
        let got = entries_of(&flat(&[base, top]).unwrap());
        assert_eq!(got, vec![("opt".into(), String::new())]);
    }

    #[test]
    fn a_directory_over_a_directory_still_merges() {
        let base = layer(&[("etc/passwd", "base")]);
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Directory);
        h.set_size(0);
        h.set_mode(0o755);
        b.append_data(&mut h, "etc", std::io::empty()).unwrap();
        let top = b.into_inner().unwrap();
        let got = entries_of(&flat(&[base, top]).unwrap());
        assert!(
            got.contains(&("etc/passwd".into(), "base".into())),
            "{got:?}"
        );
    }

    #[test]
    fn shadows_test_each_ancestor_exactly() {
        let mut shadows = Shadows::default();
        shadows.tombstones.insert(b"a/b");
        shadows.beneath.insert(b"x");
        assert!(shadows.hides(b"a/b"), "the tombstoned path");
        assert!(shadows.hides(b"a/b/c/d"), "beneath it");
        assert!(!shadows.hides(b"a/bc"), "a sibling sharing its prefix");
        assert!(!shadows.hides(b"a"), "its parent");
        assert!(!shadows.hides(b"x"), "an opaque directory itself survives");
        assert!(shadows.hides(b"x/y"), "what is beneath it does not");
        let deep = "d/".repeat(2000) + "f";
        assert!(!shadows.hides(deep.as_bytes()));
        shadows.beneath.insert(b"");
        assert!(shadows.hides(b"anything"), "a root opaque hides everything");
    }

    /// The ordered probe finds an ancestor past siblings that sort between
    /// it and the path (`-` sorts before `/`), and a subtree added over
    /// narrower ones subsumes them.
    #[test]
    fn subtrees_find_an_ancestor_past_sorted_siblings() {
        let mut set = Subtrees::default();
        set.insert(b"a");
        set.insert(b"a/b-x");
        set.insert(b"a/b.y");
        assert!(set.covers(b"a/b/c", false));
        assert!(set.covers(b"a", true) && !set.covers(b"a", false));
        assert!(!set.covers(b"a-b/c", true));

        let mut set = Subtrees::default();
        set.insert(b"p/q/r");
        set.insert(b"p/q-s");
        set.insert(b"p");
        assert_eq!(set.0.len(), 1, "the narrower subtrees are subsumed");
        assert!(set.covers(b"p/z", false));
        set.insert(b"p/q");
        assert_eq!(set.0.len(), 1, "a covered subtree adds nothing");
    }

    #[test]
    fn a_root_opaque_marker_hides_every_lower_layer() {
        let base = layer(&[("etc/passwd", "base")]);
        let top = layer(&[(".wh..wh..opq", ""), ("new", "n")]);
        let got = entries_of(&flat(&[base, top]).unwrap());
        assert_eq!(got, vec![("new".into(), "n".into())]);
    }
}
