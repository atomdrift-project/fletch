//! The flatten half of an export: merge an image's layer tars, read from disk,
//! into one xz-compressed rootfs tar, the way a container runtime would lay
//! them down.

use std::borrow::Cow;
use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::io::{BufReader, Read, Write};
use std::path::Path;
use std::rc::Rc;
use std::time::{Duration, Instant};

use crate::fetch::FetchError;
use crate::fetch::cache::Counted;

/// Bound on flattening and recompressing the layers: the CPU-bound half of an
/// export, which the pull's own deadline does not cover. Checked per tar
/// entry.
const FLATTEN_DEADLINE: Duration = Duration::from_mins(30);

/// Longest entry or link name a layer may carry, or path an entry may land at
/// once its symlinks are followed: Linux's `PATH_MAX`. Names are
/// attacker-sized (a GNU or PAX long name is bounded only by the layer).
const MAX_PATH: usize = 4096;

/// Most tar entries an image's layers may hold together, with the directories
/// the flatten creates to hold them. Every entry's name is kept in memory
/// while the image is flattened, and an entry can cost as
/// little as one 512-byte header, so the expanded-size cap alone would admit
/// millions. A large real image holds a few hundred thousand files.
const MAX_ENTRIES: usize = 1 << 20;

/// Most bytes of entry names and symlink targets an image's layers may hold
/// together: the memory the flatten's model of the root may take for them,
/// against a crafted image of long names.
const MAX_NAME_BYTES: usize = 128 << 20;

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
/// The output is the root an overlay runtime builds: Docker's overlay2 and
/// containerd's overlayfs snapshotter, the defaults. Each unpacks a layer
/// entry by entry into a directory of its own, resolving the entry's parent
/// directories through the symlinks *that layer* has laid down so far — a
/// layer holding `a -> /etc` and then `a/passwd` writes `/etc/passwd` — and
/// overlayfs then stacks the layers: an upper directory merges with a lower
/// one and hides a lower non-directory, symlinks included. Keyed on the names
/// as written, the scanner would see the benign `/etc/passwd` the runtime
/// replaces. So a first pass applies every entry, base layer first, to a
/// model of the root ([`Tree`]); the second writes the entries that survive,
/// under the paths they resolved to, top layer first. Within a layer the
/// last copy of a path wins, as on extraction. A `.wh.<name>` whiteout
/// removes that path, and the OCI image-spec's opaque marker (`.wh..wh..opq`)
/// a directory's contents, as far as the layers *below* put them there. Each
/// layer ends where Go's `archive/tar` ends it ([`check_end`]), and entries
/// that tar readers parse differently are refused outright ([`vet_entry`]).
///
/// Runtimes that unpack onto the merged root instead (vfs, native, btrfs,
/// zfs, devmapper) also follow lower layers' symlinks, sending an upper
/// `bin/sh` through a lower `bin -> usr/bin`. Following them here would let
/// an upper layer replace, or white out, a lower file the default runtimes
/// keep; not following them shows those runtimes' files too, an upper
/// layer's at the path it names rather than the one they reach — a superset.
///
/// The output is for analysis only and must never be extracted to disk:
/// symlink targets are kept as the image has them (`/etc/…`, `../…`), as are
/// device nodes and setuid bits.
pub(super) fn flatten<W: Write>(layers: &[Layer<'_>], out: W, cap: u64) -> Result<W, FetchError> {
    let deadline = Instant::now() + FLATTEN_DEADLINE;
    let mut tree = Tree::new();
    let mut sizes = Vec::with_capacity(layers.len());
    let mut expanded = 0u64;
    for (n, layer) in layers.iter().enumerate() {
        let budget = cap.saturating_sub(expanded);
        let size = model(layer, n, budget, &mut tree, deadline)?;
        expanded = expanded.saturating_add(size);
        sizes.push(size);
    }

    // xz preset 1: on a real rootfs it compresses some 9x faster than the
    // default 6 in a tenth of the memory, for output about a fifth larger.
    // At preset 6 compression is most of an export, and a large image runs
    // into the flatten deadline.
    let mut builder = tar::Builder::new(LimitWriter {
        w: xz2::write::XzEncoder::new(out, 1),
        limit: cap,
        written: 0,
    });
    let survivors = tree.survivors(layers.len());
    for (n, ((layer, &size), keep)) in layers.iter().zip(&sizes).zip(&survivors).enumerate().rev() {
        let emitted = emit(layer, size, keep, &mut tree, &mut builder, deadline)?;
        tracing::debug!(
            target: "oci",
            layer = n,
            bytes = size,
            surviving = keep.len(),
            emitted,
            "layer flattened"
        );
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

/// The entries, and bytes of their names, the image's layers have held so
/// far, against [`MAX_ENTRIES`] and [`MAX_NAME_BYTES`].
#[derive(Debug, Default)]
struct Names {
    entries: usize,
    bytes: usize,
}

impl Names {
    /// Count an entry, or a directory the [`Tree`] creates implicitly, named
    /// `name`.
    fn admit(&mut self, name: &[u8]) -> Result<(), FetchError> {
        self.entries = self.entries.saturating_add(1);
        self.hold(name)
    }

    /// Count `name`'s bytes, also held: an entry's, or a symlink's target.
    fn hold(&mut self, name: &[u8]) -> Result<(), FetchError> {
        self.bytes = self.bytes.saturating_add(name.len());
        if self.entries > MAX_ENTRIES || self.bytes > MAX_NAME_BYTES {
            tracing::debug!(
                target: "oci",
                entries = self.entries,
                name_bytes = self.bytes,
                "image holds too many entries to flatten"
            );
            return Err(FetchError::TooLarge);
        }
        Ok(())
    }
}

/// The first pass over `layer`, the `n`th from the base: apply its entries to
/// `tree`, refusing it when it expands past `budget` bytes. Returns its
/// expanded size: as far as the second pass may read. Tar reading is
/// forward-only, so each pass decodes the blob afresh from disk.
fn model(
    layer: &Layer<'_>,
    n: usize,
    budget: u64,
    tree: &mut Tree,
    deadline: Instant,
) -> Result<u64, FetchError> {
    let read = Cell::new(0);
    let applied =
        decoded(layer, budget, &read).and_then(|body| apply_layer(body, n, tree, deadline));
    // Checked first: a decoder stopped by the budget mid-stream looks like a
    // truncated (or, at a block boundary, a complete) archive.
    if read.get() > budget {
        return Err(FetchError::TooLarge);
    }
    let entries = applied?;
    tracing::debug!(
        target: "oci",
        layer = n,
        bytes = read.get(),
        entries,
        nodes = tree.nodes.len(),
        "layer applied"
    );
    Ok(read.get())
}

/// Apply each entry of layer `n`'s tar `body` to `tree`; returns how many it
/// holds.
fn apply_layer(
    body: impl Read,
    n: usize,
    tree: &mut Tree,
    deadline: Instant,
) -> Result<usize, FetchError> {
    let mut archive = tar::Archive::new(body);
    let mut entries = 0;
    for (i, entry) in archive.entries().map_err(malformed)?.enumerate() {
        if Instant::now() >= deadline {
            return Err(FetchError::Timeout);
        }
        let mut entry = entry.map_err(malformed)?;
        vet_entry(&mut entry)?;
        let path = clean_path(&entry.path_bytes());
        tree.names.admit(&path)?;
        apply(tree, &entry, &path, (n, i))?;
        entries = i + 1;
    }
    check_end(archive.into_inner())?;
    Ok(entries)
}

/// Apply `entry`, cleaned to `path` and found at `origin` (layer, index), to
/// `tree` as a runtime applies it to the root.
fn apply<R: Read>(
    tree: &mut Tree,
    entry: &tar::Entry<'_, R>,
    path: &[u8],
    origin: (usize, usize),
) -> Result<(), FetchError> {
    use tar::EntryType as T;
    let layer = origin.0;
    // `./` and its kin name the root itself, which a runtime leaves be.
    if path.is_empty() {
        return Ok(());
    }
    let (dir, base) = split_dir_base(path);
    // Never `None`: missing parents are made.
    let Some(dir) = tree.resolve(dir, layer, true)? else {
        return Ok(());
    };
    if base == b".wh..wh..opq" {
        tree.clear(dir, layer, false);
        return Ok(());
    }
    if let Some(name) = base.strip_prefix(b".wh.") {
        if let Some(node) = tree.child(dir, name) {
            tree.clear(node, layer, true);
        }
        return Ok(());
    }
    let Some(kind) = output_kind(entry_kind(entry)) else {
        // Metadata, or a type no rootfs holds: nothing a runtime installs.
        return Ok(());
    };
    match kind {
        T::Directory => {
            tree.put(dir, base, Kind::Dir, origin)?;
        }
        T::Symlink => {
            let target = link_target(entry)?;
            tree.names.hold(&target)?;
            tree.put(dir, base, Kind::Symlink(Rc::from(&*target)), origin)?;
        }
        // The runtime removes what is at the path, then links what the
        // target names: its parents resolved as an entry's are, its last
        // component not followed, nothing created on the way.
        T::Link => {
            let target = clean_path(&link_target(entry)?);
            let node = tree.put(dir, base, Kind::Link(None), origin)?;
            let (target_dir, target_base) = split_dir_base(&target);
            let linked = tree
                .resolve(target_dir, layer, false)?
                .and_then(|dir| tree.child(dir, target_base));
            tree.nodes[node].kind = Kind::Link(linked);
        }
        _ => {
            tree.put(dir, base, Kind::File, origin)?;
        }
    }
    Ok(())
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

/// The second pass over `layer`, `size` bytes expanded: append to `builder`
/// each entry `keep` maps to its surviving node, under that node's path.
/// Returns how many entries were appended.
fn emit<W: Write>(
    layer: &Layer<'_>,
    size: u64,
    keep: &HashMap<usize, usize>,
    tree: &mut Tree,
    builder: &mut tar::Builder<W>,
    deadline: Instant,
) -> Result<usize, FetchError> {
    if keep.is_empty() {
        return Ok(0);
    }
    let read = Cell::new(0);
    let mut archive = tar::Archive::new(decoded(layer, size, &read)?);
    let (mut emitted, mut pending) = (0, keep.len());
    for (i, entry) in archive.entries().map_err(malformed)?.enumerate() {
        if pending == 0 {
            break;
        }
        if Instant::now() >= deadline {
            return Err(FetchError::Timeout);
        }
        let mut entry = entry.map_err(malformed)?;
        let Some(&node) = keep.get(&i) else {
            continue;
        };
        pending = pending.saturating_sub(1);
        let path = tree.path(node);
        // A hard link names another entry of the output, so it is written
        // only once the node it linked has been: never to one a later entry
        // replaced or a whiteout removed, nor to a lower layer's (not yet
        // written), nor to nothing.
        let link = match tree.nodes[node].kind {
            Kind::Link(target) => match target.filter(|&t| tree.nodes[t].written) {
                Some(target) => Some(tree.path(target)),
                None => {
                    tracing::debug!(
                        target: "oci",
                        path = %String::from_utf8_lossy(&path),
                        "hard link to an entry not written; dropped"
                    );
                    continue;
                }
            },
            _ => None,
        };
        if append_entry(builder, &mut entry, &path, link.as_deref())? {
            tree.nodes[node].written = true;
            emitted += 1;
        }
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
/// one a container runtime extracts. Each disagreement lets one layer read as
/// two different file sets:
///
/// - tar-rs takes the *first* of a repeated PAX `path`/`linkpath`/`size`
///   record where Go (containerd) takes the last, and treats an empty one as
///   set where Go ignores it.
/// - A GNU long name with an embedded NUL is cut at the NUL by Go but not by
///   tar-rs.
/// - Go gives a link, device, FIFO or directory no body whatever its size
///   says; tar-rs skips `size` bytes, which could hold entries only the
///   runtime installs.
/// - Go applies a PAX or GNU long-name header whatever the block's magic;
///   tar-rs only behind a ustar or GNU magic, and hands any other one over as
///   an entry, so the name it carries reaches only the runtime.
/// - Go renames a PAX-format GNU sparse file to its `GNU.sparse.name` and reads
///   its body as a sparse map; tar-rs knows neither.
/// - Go joins the ustar `prefix` to the name behind the ustar magic alone, and
///   reads a STAR header's shorter prefix; tar-rs needs the version too, and
///   always reads 155 bytes ([`prefixes`]).
///
/// Names past [`MAX_PATH`] are refused too.
fn vet_entry<R: Read>(entry: &mut tar::Entry<'_, R>) -> Result<(), FetchError> {
    use tar::EntryType as T;
    let refuse = |why: &str| {
        Err(FetchError::Refused(format!(
            "ambiguous layer tar entry: {why}"
        )))
    };
    let kind = entry_kind(entry);
    if matches!(
        kind,
        T::Link | T::Symlink | T::Char | T::Block | T::Directory | T::Fifo
    ) && entry.size() != 0
    {
        return refuse("body on an entry Go reads as header-only");
    }
    if matches!(kind, T::XHeader | T::GNULongName | T::GNULongLink) {
        return refuse("extension header without a ustar or GNU magic");
    }
    let (go, rs) = prefixes(entry.header().as_bytes());
    if go != rs {
        return refuse("ustar prefix read two ways");
    }
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
        if key.starts_with(b"GNU.sparse.") {
            return refuse("PAX-format GNU sparse file");
        }
    }
    Ok(())
}

/// An entry's type as Go's `archive/tar` reads it: a pre-POSIX regular file
/// (type `\0`) whose name ends in `/` is a directory, which tar-rs alone
/// would take for a file replacing whatever lies beneath it.
fn entry_kind<R: Read>(entry: &tar::Entry<'_, R>) -> tar::EntryType {
    let header = entry.header();
    if header.as_old().linkflag[0] == 0 && entry.path_bytes().ends_with(b"/") {
        tar::EntryType::Directory
    } else {
        header.entry_type()
    }
}

/// A link entry's target, as the image wrote it.
fn link_target<'e, R: Read>(entry: &'e tar::Entry<'_, R>) -> Result<Cow<'e, [u8]>, FetchError> {
    entry
        .link_name_bytes()
        .ok_or_else(|| FetchError::Refused("link entry without target".into()))
}

/// The ustar `prefix` field of header block `raw` as `(Go, tar-rs)` join it to
/// the name, each empty when it joins none. Go reads one behind the
/// `ustar\0` magic whatever the version, and 131 bytes of it (the rest is
/// timestamps) when the block ends in STAR's `tar\0` trailer; tar-rs reads one
/// only behind the `00` version too, and always 155 bytes.
fn prefixes(raw: &[u8; 512]) -> (&[u8], &[u8]) {
    fn field(b: &[u8]) -> &[u8] {
        b.iter().position(|&c| c == 0).map_or(b, |end| &b[..end])
    }
    if raw[257..263] != *b"ustar\0" {
        return (b"", b"");
    }
    let go = if raw[508..512] == *b"tar\0" {
        field(&raw[345..476])
    } else {
        field(&raw[345..500])
    };
    let rs = if raw[263..265] == *b"00" {
        field(&raw[345..500])
    } else {
        b""
    };
    (go, rs)
}

/// Copy one tar entry (path, link target, body) into the output under a
/// header built afresh, regenerating long-name/long-link extensions so paths
/// the source encoded via PAX/GNU records survive the transplant. Returns
/// whether it was appended.
///
/// Never the source header itself: its size field need not frame the body
/// tar-rs yields (a PAX `size`, a GNU sparse map, a link with a nonzero size),
/// and copying it would let a layer's bytes parse as forged entries of the
/// output. So only the file types a rootfs holds are kept, sparse and
/// contiguous files become regular ones of their real size, and metadata
/// records (PAX globals, GNU volume and multivolume headers) and unknown types
/// are dropped.
///
/// The entry is written as `path`, where it landed in the root. A symlink's
/// *target* is copied verbatim, deliberately: absolute and `..`-relative
/// targets are how a real rootfs is built (`usr/sbin/x -> ../bin/y`,
/// `/etc/alternatives/…`), so rewriting them would misrepresent the
/// filesystem being analyzed. A hard link's target names another entry *of
/// the output*, so it is `link`, that entry's path; without one the link is
/// dropped.
fn append_entry<W: Write, R: Read>(
    builder: &mut tar::Builder<W>,
    entry: &mut tar::Entry<'_, R>,
    path: &[u8],
    link: Option<&[u8]>,
) -> Result<bool, FetchError> {
    use tar::EntryType as T;
    let Some(kind) = output_kind(entry_kind(entry)) else {
        return Ok(false);
    };
    // Decided before any PAX record is written, which would otherwise
    // attach to the entry after.
    let link = match (kind.is_hard_link(), link) {
        (false, _) => None,
        (true, Some(link)) => Some(link),
        (true, None) => return Ok(false),
    };
    // Extended attributes (file capabilities ride in `security.capability`,
    // as telling as a setuid bit) and owner names longer than a header holds
    // travel as PAX records ahead of the entry.
    let mut pax = Vec::new();
    if let Some(extensions) = entry.pax_extensions().map_err(malformed)? {
        for ext in extensions {
            let ext = ext.map_err(malformed)?;
            let key = ext.key_bytes();
            if key.starts_with(b"SCHILY.xattr.") || matches!(key, b"uname" | b"gname") {
                pax_record(&mut pax, key, ext.value_bytes());
            }
        }
    }
    let src = entry.header();
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(kind);
    header.set_size(0);
    header.set_mode(src.mode().unwrap_or(0o644) & 0o7777);
    header.set_uid(src.uid().unwrap_or(0));
    header.set_gid(src.gid().unwrap_or(0));
    header.set_mtime(src.mtime().unwrap_or(0));
    // The source's header fields are the same width as the output's, so
    // these fit; a longer name came as a PAX record, kept above.
    if let Ok(Some(name)) = src.username() {
        header.set_username(name).map_err(output)?;
    }
    if let Ok(Some(name)) = src.groupname() {
        header.set_groupname(name).map_err(output)?;
    }
    if matches!(kind, T::Char | T::Block)
        && let (Ok(Some(major)), Ok(Some(minor))) = (src.device_major(), src.device_minor())
    {
        header.set_device_major(major).map_err(output)?;
        header.set_device_minor(minor).map_err(output)?;
    }
    if !pax.is_empty() {
        let mut extension = tar::Header::new_ustar();
        extension.set_entry_type(T::XHeader);
        extension.set_mode(0o644);
        extension.set_size(pax.len() as u64);
        builder
            .append_data(&mut extension, "PaxHeaders/entry", pax.as_slice())
            .map_err(output)?;
    }
    let written = if let Some(link) = link {
        builder.append_link(&mut header, bytes_path(path), bytes_path(link))
    } else if kind.is_symlink() {
        let target = link_target(entry)?;
        builder.append_link(&mut header, bytes_path(path), bytes_path(&target))
    } else if kind == T::Regular {
        header.set_size(entry.size());
        builder.append_data(&mut header, bytes_path(path), entry)
    } else {
        builder.append_data(&mut header, bytes_path(path), std::io::empty())
    };
    written.map_err(output)?;
    Ok(true)
}

/// Append one PAX extended-header record, `"<len> <key>=<value>\n"`, to
/// `out`; `len` counts the whole record, its own digits included.
fn pax_record(out: &mut Vec<u8>, key: &[u8], value: &[u8]) {
    let rest = key.len() + value.len() + 3; // ' ', '=', '\n'
    let mut len = rest + 1;
    while len != rest + len.to_string().len() {
        len = rest + len.to_string().len();
    }
    out.extend_from_slice(format!("{len} ").as_bytes());
    out.extend_from_slice(key);
    out.push(b'=');
    out.extend_from_slice(value);
    out.push(b'\n');
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
/// the image flattens. Second, fidelity: a runtime cleans a name so before it
/// resolves any symlink in it, so the model must walk the same path; walking
/// `a/../b` through a symlinked `a` would land somewhere else.
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

/// The kind [`append_entry`] writes an entry of `kind` as — only the file
/// types a rootfs holds, sparse and contiguous files as regular ones — or
/// `None` for one it drops.
fn output_kind(kind: tar::EntryType) -> Option<tar::EntryType> {
    use tar::EntryType as T;
    match kind {
        T::Regular | T::Continuous | T::GNUSparse => Some(T::Regular),
        T::Directory | T::Symlink | T::Link | T::Char | T::Block | T::Fifo => Some(kind),
        _ => None,
    }
}

/// Most symlinks one path lookup may pass through: Linux's `MAXSYMLINKS`.
const MAX_HOPS: usize = 40;

/// Most bytes of symlink targets the flatten may follow, together. Each hop
/// re-walks its target, so without a bound a short chain of long targets
/// would multiply the cost of every entry beneath it by 40 × `PATH_MAX`; a
/// real image follows a few short targets per redirected entry.
const MAX_FOLLOWED_BYTES: usize = MAX_NAME_BYTES;

/// The [`Tree`] node of the root directory.
const ROOT: usize = 0;

/// What a [`Node`] is.
#[derive(Debug)]
enum Kind {
    Dir,
    Symlink(Rc<[u8]>),
    /// A hard link to the node its target named when it was applied, if any.
    Link(Option<usize>),
    /// A regular file, device or FIFO.
    File,
}

/// One file of the modeled root.
#[derive(Debug)]
struct Node {
    parent: usize,
    name: Rc<[u8]>,
    /// Bytes of its path from the root, held to [`MAX_PATH`].
    len: usize,
    kind: Kind,
    /// The entry it came from, as (layer, index in the layer); `None` for a
    /// directory created only to hold what is beneath it, which is never
    /// written.
    origin: Option<(usize, usize)>,
    children: HashMap<Rc<[u8]>, usize>,
    /// The last layer whose markers walked everything beneath it.
    cleared: Option<usize>,
    /// Whether it was written to the output: what a hard link may name.
    written: bool,
}

/// The root a runtime builds from the layers, as an arena of [`Node`]s. Each
/// node has a fixed place, so a lookup costs one probe per component of the
/// path, whatever its depth; replacing a node detaches it and its subtree
/// from its parent, leaving them as garbage the entry caps bound.
#[derive(Debug)]
struct Tree {
    nodes: Vec<Node>,
    /// The names the layers have laid down, against [`MAX_ENTRIES`] and
    /// [`MAX_NAME_BYTES`].
    names: Names,
    /// Bytes of symlink targets followed, against [`MAX_FOLLOWED_BYTES`].
    followed: usize,
}

impl Tree {
    fn new() -> Self {
        let root = Node {
            parent: ROOT,
            name: Rc::from(&b""[..]),
            len: 0,
            kind: Kind::Dir,
            origin: None,
            children: HashMap::new(),
            cleared: None,
            written: false,
        };
        Self {
            nodes: vec![root],
            names: Names::default(),
            followed: 0,
        }
    }

    fn child(&self, dir: usize, name: &[u8]) -> Option<usize> {
        self.nodes[dir].children.get(name).copied()
    }

    /// The directory an overlay runtime reaches walking `dir` (a cleaned
    /// path) from the root for an entry of layer `layer`. It unpacks each
    /// layer into a directory of its own, so only that layer's symlinks are
    /// followed — an absolute target restarting at the root and `..`
    /// stopping there, as continuity's `RootPath` does — and a lower layer's
    /// are not there to follow. With `make`, a missing component is created,
    /// as a runtime creates a missing parent, and a lower layer's symlink or
    /// file in the way is shadowed by a directory, as overlayfs shows an
    /// upper directory over a lower non-directory (a file of the layer's own
    /// in the way makes the runtime refuse the layer, so the image never
    /// runs); the directories created count against the tree's [`Names`].
    /// Without `make`, either ends the walk at nothing. A symlink loop, or a
    /// chain of more than [`MAX_HOPS`], refuses the image: the runtime fails
    /// to apply the layer.
    fn resolve(
        &mut self,
        dir: &[u8],
        layer: usize,
        make: bool,
    ) -> Result<Option<usize>, FetchError> {
        let mut at = ROOT;
        let mut hops = 0usize;
        // The paths being walked, innermost symlink target last, each with
        // the offset of its next component.
        let mut walks: Vec<(Rc<[u8]>, usize)> = vec![(Rc::from(dir), 0)];
        while let Some((path, offset)) = walks.last_mut() {
            if *offset >= path.len() {
                walks.pop();
                continue;
            }
            // A handle of its own, so `walks` can grow while `name` borrows it.
            let (path, start) = (Rc::clone(path), *offset);
            let end = path[start..]
                .iter()
                .position(|&b| b == b'/')
                .map_or(path.len(), |len| start + len);
            *offset = end + 1;
            let name = &path[start..end];
            match name {
                b"" | b"." => continue,
                b".." => {
                    at = self.nodes[at].parent;
                    continue;
                }
                _ => {}
            }
            let child = self.child(at, name);
            if let Some(node) = child
                && matches!(self.nodes[node].kind, Kind::Dir)
            {
                at = node;
                continue;
            }
            if let Some(node) = child
                && self.nodes[node]
                    .origin
                    .is_some_and(|(from, _)| from == layer)
                && let Kind::Symlink(target) = &self.nodes[node].kind
            {
                let target = Rc::clone(target);
                hops += 1;
                self.followed = self.followed.saturating_add(target.len());
                if hops > MAX_HOPS {
                    return Err(FetchError::Refused(format!(
                        "layer entry path passes a symlink loop or more than {MAX_HOPS} symlinks"
                    )));
                }
                if self.followed > MAX_FOLLOWED_BYTES {
                    tracing::debug!(
                        target: "oci",
                        followed = self.followed,
                        "image follows too many bytes of symlink targets"
                    );
                    return Err(FetchError::TooLarge);
                }
                if target.starts_with(b"/") {
                    at = ROOT;
                }
                walks.push((target, 0));
                continue;
            }
            if !make {
                return Ok(None);
            }
            if let Some(node) = child {
                self.detach(node);
            }
            self.names.admit(name)?;
            at = self.add(at, name, Kind::Dir, None)?;
        }
        Ok(Some(at))
    }

    /// Put a node of `kind` from entry `origin` at `name` in `dir`, as a
    /// runtime does: a directory onto a directory merges with it (the new
    /// entry's metadata wins); anything else replaces what is there, a
    /// directory's whole subtree included.
    fn put(
        &mut self,
        dir: usize,
        name: &[u8],
        kind: Kind,
        origin: (usize, usize),
    ) -> Result<usize, FetchError> {
        if let Some(old) = self.child(dir, name) {
            if matches!((&kind, &self.nodes[old].kind), (Kind::Dir, Kind::Dir)) {
                self.nodes[old].origin = Some(origin);
                return Ok(old);
            }
            self.detach(old);
        }
        self.add(dir, name, kind, Some(origin))
    }

    fn add(
        &mut self,
        parent: usize,
        name: &[u8],
        kind: Kind,
        origin: Option<(usize, usize)>,
    ) -> Result<usize, FetchError> {
        let len = match parent {
            ROOT => name.len(),
            _ => self.nodes[parent].len.saturating_add(1 + name.len()),
        };
        if len > MAX_PATH {
            return Err(FetchError::Refused(
                "layer entry path longer than PATH_MAX once its symlinks are followed".into(),
            ));
        }
        let name: Rc<[u8]> = Rc::from(name);
        let node = self.nodes.len();
        self.nodes.push(Node {
            parent,
            name: Rc::clone(&name),
            len,
            kind,
            origin,
            children: HashMap::new(),
            cleared: None,
            written: false,
        });
        self.nodes[parent].children.insert(name, node);
        Ok(node)
    }

    fn detach(&mut self, node: usize) {
        let Node { parent, name, .. } = &self.nodes[node];
        let (parent, name) = (*parent, Rc::clone(name));
        self.nodes[parent].children.remove(&name);
    }

    /// Apply layer `layer`'s marker on `top`: remove what lower layers put
    /// beneath it and, for a whiteout (`whole`), at it. The layer's own
    /// entries, and the directories leading to them, stay: markers constrain
    /// only the layers below. A node walked once in a layer is not walked
    /// again in it, as nothing lower has reached its subtree since; so many
    /// markers on nested directories, or on one directory by many symlinked
    /// spellings, cost no more than the nodes they reach.
    fn clear(&mut self, top: usize, layer: usize, whole: bool) {
        let mut stack = vec![(top, false)];
        while let Some((node, walked)) = stack.pop() {
            // A node is settled after its children, which may leave it
            // empty. One this layer has walked already is settled again but
            // not re-walked.
            if !walked && self.nodes[node].cleared != Some(layer) {
                self.nodes[node].cleared = Some(layer);
                stack.push((node, true));
                stack.extend(self.nodes[node].children.values().map(|&c| (c, false)));
                continue;
            }
            let n = &mut self.nodes[node];
            if (node == top && !whole) || n.origin.is_some_and(|(l, _)| l == layer) {
                continue;
            }
            if n.children.is_empty() {
                self.detach(node);
            } else {
                // A lower layer's directory holding this layer's entries
                // leads to them still, but is no longer its own entry.
                n.origin = None;
            }
        }
    }

    /// Each layer's surviving entries, as entry index → node.
    fn survivors(&self, layers: usize) -> Vec<HashMap<usize, usize>> {
        let mut out = vec![HashMap::new(); layers];
        let mut stack = vec![ROOT];
        while let Some(node) = stack.pop() {
            let n = &self.nodes[node];
            if let Some((layer, entry)) = n.origin
                && let Some(entries) = out.get_mut(layer)
            {
                entries.insert(entry, node);
            }
            stack.extend(n.children.values());
        }
        out
    }

    /// `node`'s path from the root.
    fn path(&self, mut node: usize) -> Vec<u8> {
        let mut names = Vec::new();
        while node != ROOT {
            names.push(&*self.nodes[node].name);
            node = self.nodes[node].parent;
        }
        names.reverse();
        names.join(&b'/')
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
        if self.written.saturating_add(buf.len() as u64) > self.limit {
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
    use crate::oci::tests::{entries_of, hostile_layer, layer, raw_header};

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
        raw_header(path, kind, 0, target)
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
    /// link to, and anchored at the root — and one naming no entry written is
    /// dropped. Symlink targets describe the image's filesystem and are kept
    /// as written.
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
                ("usr/sbin/y".into(), "../bin/a".into()),
            ]
        );
    }

    /// `a -> /etc`, then a hard link to `a/passwd`: the runtime resolves the
    /// link's target through the symlink to `etc/passwd`, which does not
    /// exist, so it links nothing, and neither does the output.
    #[test]
    fn a_hard_link_through_a_symlink_to_nothing_is_dropped() {
        let mut top = hostile_layer(&[]);
        top.truncate(top.len() - 1024);
        top.extend_from_slice(&link("a", tar::EntryType::Symlink, "/etc"));
        top.extend_from_slice(&link("x", tar::EntryType::Link, "a/passwd"));
        top.extend_from_slice(&[0u8; 1024]);
        assert_eq!(
            links_of(&flat(&[top]).unwrap()),
            vec![("a".into(), "/etc".into())]
        );
    }

    /// File capabilities are as telling as a setuid bit, and travel as a PAX
    /// extended attribute; the flattened entry keeps them.
    #[test]
    fn extended_attributes_survive_the_flatten() {
        let mut records = Vec::new();
        pax_record(
            &mut records,
            b"SCHILY.xattr.security.capability",
            b"\x01cap",
        );
        pax_record(&mut records, b"uname", &[b'u'; 40]);
        let mut pax = tar::Header::new_ustar();
        pax.set_entry_type(tar::EntryType::XHeader);
        pax.set_size(records.len() as u64);
        pax.set_mode(0o644);
        let mut builder = tar::Builder::new(Vec::new());
        builder
            .append_data(&mut pax, "PaxHeaders/ping", records.as_slice())
            .unwrap();
        let mut file = tar::Header::new_gnu();
        file.set_size(4);
        file.set_mode(0o755);
        builder
            .append_data(&mut file, "usr/bin/ping", &b"ELF!"[..])
            .unwrap();
        let layer = builder.into_inner().unwrap();

        let mut raw = Vec::new();
        xz2::read::XzDecoder::new(flat(&[layer]).unwrap().as_slice())
            .read_to_end(&mut raw)
            .unwrap();
        let mut archive = tar::Archive::new(raw.as_slice());
        let mut entry = archive.entries().unwrap().next().unwrap().unwrap();
        assert_eq!(&*entry.path_bytes(), b"usr/bin/ping");
        let kept: Vec<(Vec<u8>, Vec<u8>)> = entry
            .pax_extensions()
            .unwrap()
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (e.key_bytes().to_vec(), e.value_bytes().to_vec())
            })
            .collect();
        assert_eq!(
            kept,
            vec![
                (
                    b"SCHILY.xattr.security.capability".to_vec(),
                    b"\x01cap".to_vec()
                ),
                (b"uname".to_vec(), vec![b'u'; 40]),
            ]
        );
    }

    /// Every entry name is held in memory while an image flattens, so the
    /// image's entry count and name bytes are bounded, not just its size.
    #[test]
    fn an_image_of_too_many_entries_is_refused() {
        let mut names = Names {
            entries: MAX_ENTRIES - 1,
            bytes: 0,
        };
        assert!(names.admit(b"last").is_ok());
        assert_eq!(names.admit(b"one-more"), Err(FetchError::TooLarge));
        let mut names = Names {
            entries: 0,
            bytes: MAX_NAME_BYTES - 4,
        };
        assert!(names.admit(b"four").is_ok());
        assert_eq!(names.admit(b"x"), Err(FetchError::TooLarge));
    }

    #[test]
    fn pax_records_count_their_own_length() {
        let mut out = Vec::new();
        pax_record(&mut out, b"k", b"v");
        assert_eq!(out, b"6 k=v\n");
        let mut out = Vec::new();
        pax_record(&mut out, b"key", &[b'v'; 93]);
        // 3 + 93 + 3 = 99 bytes, plus three digits: 102.
        assert!(out.starts_with(b"102 key="));
        assert_eq!(out.len(), 102);
    }

    /// `a -> /etc` then `a/passwd`: the runtime writes `/etc/passwd`, so the
    /// output shows it there. The symlink replaced the base's directory `a`,
    /// and `a/shadow` with it.
    #[test]
    fn an_entry_beneath_a_symlink_lands_where_the_runtime_puts_it() {
        let mut top = hostile_layer(&[]);
        top.truncate(top.len() - 1024);
        top.extend_from_slice(&link("a", tar::EntryType::Symlink, "/etc"));
        top.extend_from_slice(&hostile_layer(&[("a/passwd", "root::0:0"), ("ab", "kept")]));
        let base = layer(&[("a/shadow", "x")]);
        let got = entries_of(&flat(&[base, top]).unwrap());
        assert_eq!(
            got,
            vec![
                ("a".into(), String::new()),
                ("etc/passwd".into(), "root::0:0".into()),
                ("ab".into(), "kept".into()),
            ]
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

    /// A layer of one PAX extension block carrying `records`, then the entry
    /// `name` whose ustar header declares size 0 and whose body is `body`.
    fn pax_layer(records: &str, name: &str, body: &[u8]) -> Vec<u8> {
        let mut out = raw_header("pax", tar::EntryType::XHeader, records.len() as u64, "");
        out.extend_from_slice(records.as_bytes());
        out.resize(out.len().div_ceil(512) * 512, 0);
        out.extend_from_slice(&raw_header(name, tar::EntryType::Regular, 0, ""));
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
        let forged = raw_header("etc/forged", tar::EntryType::Regular, 0, "");
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

    /// `blocks` as a layer: each padded to whole blocks, then the end marker.
    fn blocks(blocks: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for block in blocks {
            out.extend_from_slice(block);
            out.resize(out.len().div_ceil(512) * 512, 0);
        }
        out.extend_from_slice(&[0u8; 1024]);
        out
    }

    /// `header` with its raw bytes at `at` replaced by `bytes`, re-summed.
    fn patched(mut header: Vec<u8>, at: usize, bytes: &[u8]) -> Vec<u8> {
        header[at..at + bytes.len()].copy_from_slice(bytes);
        let mut h = tar::Header::new_old();
        h.as_mut_bytes().copy_from_slice(&header);
        h.set_cksum();
        h.as_bytes().to_vec()
    }

    /// Go gives a symlink (or any link, device or directory) no body, so
    /// the bytes tar-rs would skip as one are entries the runtime installs:
    /// `usr/bin/sshd` here, which tar-rs would never see.
    #[test]
    fn a_body_on_a_header_only_entry_is_refused() {
        let hidden = raw_header("usr/bin/sshd", tar::EntryType::Regular, 4, "");
        for kind in [
            tar::EntryType::Symlink,
            tar::EntryType::Link,
            tar::EntryType::Directory,
            tar::EntryType::Char,
            tar::EntryType::Fifo,
        ] {
            let layer = blocks(&[&raw_header("a", kind, 1024, "x"), &hidden, b"evil"]);
            assert!(
                matches!(flat(&[layer]), Err(FetchError::Refused(_))),
                "{kind:?} with a body must be refused"
            );
        }
    }

    /// A pre-POSIX entry (type `\0`) named `etc/` is a directory to Go, so it
    /// merges with the `etc` below rather than replacing it; and like any
    /// directory, it has no body.
    #[test]
    fn an_old_style_directory_is_a_directory() {
        let dir = patched(
            raw_header("etc/", tar::EntryType::Regular, 0, ""),
            156,
            &[0],
        );
        let base = layer(&[("etc/passwd", "base")]);
        let got = entries_of(&flat(&[base, blocks(&[&dir])]).unwrap());
        assert!(
            got.contains(&("etc/passwd".into(), "base".into())),
            "the lower etc/ is not hidden: {got:?}"
        );

        let sized = patched(
            raw_header("etc/", tar::EntryType::Regular, 512, ""),
            156,
            &[0],
        );
        let hidden = raw_header("etc/shadow", tar::EntryType::Regular, 0, "");
        assert!(matches!(
            flat(&[blocks(&[&sized, &hidden])]),
            Err(FetchError::Refused(_))
        ));
    }

    /// A PAX or GNU long-name header behind no ustar/GNU magic is applied by
    /// Go but handed over as an entry by tar-rs, so the name it carries would
    /// reach only the runtime.
    #[test]
    fn an_extension_header_without_a_magic_is_refused() {
        let records = "21 path=usr/bin/sshd\n";
        let mut pax = tar::Header::new_old();
        pax.set_entry_type(tar::EntryType::XHeader);
        pax.set_size(records.len() as u64);
        pax.set_mode(0o644);
        pax.as_old_mut().name[..3].copy_from_slice(b"pax");
        pax.set_cksum();
        let decoy = raw_header("decoy", tar::EntryType::Regular, 4, "");
        let layer = blocks(&[pax.as_bytes(), records.as_bytes(), &decoy, b"evil"]);
        assert!(matches!(flat(&[layer]), Err(FetchError::Refused(_))));

        let mut long = tar::Header::new_old();
        long.set_entry_type(tar::EntryType::GNULongName);
        long.set_size(12);
        long.set_mode(0o644);
        long.as_old_mut().name[..13].copy_from_slice(b"././@LongLink");
        long.set_cksum();
        let layer = blocks(&[long.as_bytes(), b"usr/bin/sshd", &decoy, b"evil"]);
        assert!(matches!(flat(&[layer]), Err(FetchError::Refused(_))));
    }

    /// Go renames a PAX-format GNU sparse file to its `GNU.sparse.name`.
    #[test]
    fn a_pax_sparse_file_is_refused() {
        let layer = pax_layer(
            "30 GNU.sparse.name=etc/shadow\n22 GNU.sparse.major=1\n22 GNU.sparse.minor=0\n",
            "decoy",
            b"",
        );
        assert!(matches!(flat(&[layer]), Err(FetchError::Refused(_))));
    }

    /// A ustar header's `prefix` joins its name in both readers, but one
    /// with another version, or STAR's trailer and a prefix running into
    /// the STAR timestamps, is read two ways.
    #[test]
    fn a_prefix_read_two_ways_is_refused() {
        let mut h = tar::Header::new_ustar();
        h.set_entry_type(tar::EntryType::Regular);
        h.set_size(0);
        h.set_mode(0o644);
        h.as_old_mut().name[..4].copy_from_slice(b"sshd");
        let ustar = patched(h.as_bytes().to_vec(), 345, b"usr/bin");
        let got = entries_of(&flat(&[blocks(&[&ustar])]).unwrap());
        assert_eq!(got, vec![("usr/bin/sshd".into(), String::new())]);

        let unversioned = patched(ustar.clone(), 263, b"  ");
        assert!(matches!(
            flat(&[blocks(&[&unversioned])]),
            Err(FetchError::Refused(_))
        ));

        // Go: `usr/bin/sshd`; tar-rs: `usr/bin00000000000/sshd`.
        let padding = "./".repeat(62);
        let prefix = format!("{padding}usr/bin00000000000");
        let star = patched(
            patched(ustar.clone(), 345, prefix.as_bytes()),
            508,
            b"tar\0",
        );
        assert!(matches!(
            flat(&[blocks(&[&star])]),
            Err(FetchError::Refused(_))
        ));
        // A STAR prefix both read alike is fine.
        let star = patched(ustar, 508, b"tar\0");
        assert!(flat(&[blocks(&[&star])]).is_ok());
    }

    #[test]
    fn a_root_opaque_marker_hides_every_lower_layer() {
        let base = layer(&[("etc/passwd", "base")]);
        let top = layer(&[(".wh..wh..opq", ""), ("new", "n")]);
        let got = entries_of(&flat(&[base, top]).unwrap());
        assert_eq!(got, vec![("new".into(), "n".into())]);
    }
    /// A file entry's blocks.
    fn file(path: &str, body: &str) -> Vec<u8> {
        let mut out = raw_header(path, tar::EntryType::Regular, body.len() as u64, "");
        out.extend_from_slice(body.as_bytes());
        out.resize(out.len().div_ceil(512) * 512, 0);
        out
    }

    fn sym(path: &str, target: &str) -> Vec<u8> {
        link(path, tar::EntryType::Symlink, target)
    }

    /// `entries` as a layer.
    fn tar_of(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut out = entries.concat();
        out.extend_from_slice(&[0u8; 1024]);
        out
    }

    /// Overlay unpacks each layer on its own, so a base layer's
    /// `bin -> usr/bin` does not redirect an upper layer's `bin/sh`: that
    /// lands in a real `bin` directory, which hides the symlink, and the
    /// base's `usr/bin/sh` stays.
    #[test]
    fn a_lower_layers_symlink_does_not_redirect_an_upper_layers_entry() {
        let base = tar_of(&[sym("bin", "usr/bin"), file("usr/bin/sh", "benign")]);
        let top = tar_of(&[file("bin/sh", "evil")]);
        let got = entries_of(&flat(&[base, top]).unwrap());
        assert_eq!(
            got,
            vec![
                ("bin/sh".into(), "evil".into()),
                ("usr/bin/sh".into(), "benign".into()),
            ]
        );
    }

    /// Following the base's symlink would let a benign upper `bin/sh` hide
    /// the evil `usr/bin/sh` the default runtimes install.
    #[test]
    fn an_upper_entry_cannot_hide_a_lower_file_through_a_lower_symlink() {
        let base = tar_of(&[sym("bin", "usr/bin"), file("usr/bin/sh", "EVIL")]);
        let top = tar_of(&[file("bin/sh", "benign")]);
        let got = entries_of(&flat(&[base, top]).unwrap());
        assert!(
            got.contains(&("usr/bin/sh".into(), "EVIL".into())),
            "{got:?}"
        );
    }

    #[test]
    fn relative_targets_resolve_from_the_symlinks_directory() {
        let layer = tar_of(&[
            sym("lib", "usr/lib"),
            file("lib/libc.so", "c"),
            sym("x/y", "../z"),
            file("x/y/f", "f"),
        ]);
        let got = entries_of(&flat(&[layer]).unwrap());
        assert_eq!(
            got,
            vec![
                ("lib".into(), String::new()),
                ("usr/lib/libc.so".into(), "c".into()),
                ("x/y".into(), String::new()),
                ("z/f".into(), "f".into()),
            ]
        );
    }

    #[test]
    fn chained_symlinks_are_followed_to_the_end() {
        let layer = tar_of(&[
            sym("a", "b"),
            sym("b", "c/d"),
            sym("e", "/a"),
            file("a/f", "1"),
            file("e/g", "2"),
        ]);
        let got = entries_of(&flat(&[layer]).unwrap());
        assert_eq!(
            &got[3..],
            [("c/d/f".into(), "1".into()), ("c/d/g".into(), "2".into())]
        );
    }

    /// `..` stops at the root and an absolute target restarts there, as
    /// within a chroot: a symlink cannot reach outside the image.
    #[test]
    fn symlinks_cannot_climb_out_of_the_root() {
        let layer = tar_of(&[
            sym("a", "../../../../etc"),
            sym("b", "/../../etc/../etc"),
            file("a/passwd", "p"),
            file("b/shadow", "s"),
        ]);
        let got = entries_of(&flat(&[layer]).unwrap());
        assert_eq!(
            &got[2..],
            [
                ("etc/passwd".into(), "p".into()),
                ("etc/shadow".into(), "s".into())
            ]
        );
    }

    /// A runtime fails to apply an entry beneath a symlink loop or a chain
    /// longer than Linux follows, so the image is refused, not guessed at.
    #[test]
    fn a_symlink_loop_or_overlong_chain_is_refused() {
        let refused = |layer: Vec<u8>| matches!(flat(&[layer]), Err(FetchError::Refused(_)));
        assert!(refused(tar_of(&[sym("a", "a"), file("a/f", "x")])));
        assert!(refused(tar_of(&[
            sym("a", "b"),
            sym("b", "/a"),
            file("a/f", "x")
        ])));
        // A loop nothing resolves through is harmless.
        assert!(flat(&[tar_of(&[sym("a", "b"), sym("b", "a")])]).is_ok());

        let chain = |hops: usize| {
            let mut entries: Vec<Vec<u8>> = (0..hops - 1)
                .map(|i| sym(&format!("l{i}"), &format!("l{}", i + 1)))
                .collect();
            entries.push(sym(&format!("l{}", hops - 1), "d"));
            entries.push(file("l0/f", "x"));
            tar_of(&entries)
        };
        let got = entries_of(&flat(&[chain(MAX_HOPS)]).unwrap());
        assert_eq!(got.last(), Some(&("d/f".into(), "x".into())));
        assert!(refused(chain(MAX_HOPS + 1)));
    }

    /// A layer's whiteout reaches through that layer's own symlink.
    #[test]
    fn a_whiteout_through_a_symlinked_directory_removes_the_real_file() {
        let base = tar_of(&[file("real/f", "x"), file("real/g", "keep")]);
        let top = tar_of(&[sym("s", "real"), file("s/.wh.f", "")]);
        let got = entries_of(&flat(&[base, top]).unwrap());
        assert_eq!(
            got,
            vec![
                ("s".into(), String::new()),
                ("real/g".into(), "keep".into())
            ]
        );
    }

    /// A lower layer's symlink is not there when overlay unpacks the upper
    /// layer: its whiteout lands in a new `s` directory, and `real/evil`
    /// stays.
    #[test]
    fn a_whiteout_cannot_reach_through_a_lower_layers_symlink() {
        let base = tar_of(&[file("real/evil", "EVIL"), sym("s", "real")]);
        let top = tar_of(&[file("s/.wh.evil", "")]);
        let got = entries_of(&flat(&[base, top]).unwrap());
        assert_eq!(got, vec![("real/evil".into(), "EVIL".into())]);
    }

    #[test]
    fn an_opaque_marker_through_a_symlinked_directory_clears_the_real_one() {
        let base = tar_of(&[file("real/f", "x")]);
        let top = tar_of(&[
            sym("s", "/real"),
            file("s/.wh..wh..opq", ""),
            file("s/new", "n"),
        ]);
        let got = entries_of(&flat(&[base, top]).unwrap());
        assert_eq!(
            got,
            vec![("s".into(), String::new()), ("real/new".into(), "n".into())]
        );
    }

    /// Once a later layer puts a directory where the symlink was, entries
    /// beneath it land in that directory.
    #[test]
    fn a_symlink_replaced_by_a_directory_stops_redirecting() {
        let base = tar_of(&[sym("bin", "usr/bin"), file("usr/bin/sh", "benign")]);
        let middle = tar_of(&[raw_header("bin", tar::EntryType::Directory, 0, "")]);
        let top = tar_of(&[file("bin/sh", "other")]);
        let got = entries_of(&flat(&[base, middle, top]).unwrap());
        assert_eq!(
            got,
            vec![
                ("bin/sh".into(), "other".into()),
                ("bin".into(), String::new()),
                ("usr/bin/sh".into(), "benign".into()),
            ]
        );
    }

    /// A hard link's target, and the link itself, resolve their parents
    /// through symlinks as any entry does.
    #[test]
    fn a_hard_link_through_a_symlinked_parent_links_the_real_file() {
        let layer = tar_of(&[
            file("real/f", "x"),
            sym("a", "real"),
            link("h", tar::EntryType::Link, "a/f"),
            link("a/h2", tar::EntryType::Link, "/real/f"),
        ]);
        assert_eq!(
            links_of(&flat(&[layer]).unwrap()),
            vec![
                ("a".into(), "real".into()),
                ("h".into(), "real/f".into()),
                ("real/h2".into(), "real/f".into()),
            ]
        );
    }

    /// A lower layer's file where an upper layer needs a directory is
    /// replaced by one, as overlayfs does.
    #[test]
    fn a_file_in_the_way_of_an_upper_entry_is_replaced() {
        let base = tar_of(&[file("d", "was a file")]);
        let top = tar_of(&[file("d/x", "x")]);
        let got = entries_of(&flat(&[base, top]).unwrap());
        assert_eq!(got, vec![("d/x".into(), "x".into())]);
    }

    /// Many symlinked spellings of one directory, each carrying an opaque
    /// marker, clear its lower contents and keep the layer's own.
    #[test]
    fn opaque_markers_by_many_spellings_keep_the_layers_own_entries() {
        let base = tar_of(&[file("w/old", "o")]);
        let mut top: Vec<Vec<u8>> = Vec::new();
        for i in 0..300 {
            top.push(sym(&format!("s{i}"), "w"));
            top.push(file(&format!("w/f{i}"), "n"));
        }
        top.extend((0..300).map(|i| file(&format!("s{i}/.wh..wh..opq"), "")));
        let got = entries_of(&flat(&[base, tar_of(&top)]).unwrap());
        assert_eq!(got.len(), 600);
        assert!(!got.iter().any(|(path, _)| path == "w/old"));
    }

    /// Each node is walked by a layer's markers at most once: repeated
    /// markers on a wide directory, and markers on every directory of a deep
    /// chain, cost no more than the nodes they reach. Quadratic, these would
    /// take seconds.
    #[test]
    fn markers_walk_each_node_once_per_layer() {
        const N: usize = 20_000;
        let mut tree = Tree::new();
        let wide = tree.put(ROOT, b"w", Kind::Dir, (0, 0)).unwrap();
        for i in 0..N {
            tree.put(wide, i.to_string().as_bytes(), Kind::File, (1, i))
                .unwrap();
        }
        for _ in 0..N {
            tree.clear(wide, 1, false);
        }
        assert_eq!(tree.nodes[wide].children.len(), N);

        let mut chain = vec![ROOT];
        for i in 0..2000 {
            let parent = *chain.last().unwrap();
            chain.push(tree.put(parent, b"d", Kind::Dir, (1, N + i)).unwrap());
        }
        for &dir in &chain {
            tree.clear(dir, 1, false);
        }
        assert_eq!(tree.path(*chain.last().unwrap()).len(), 2000 * 2 - 1);
        tree.clear(ROOT, 2, false);
        assert!(tree.nodes[ROOT].children.is_empty());
    }
}
