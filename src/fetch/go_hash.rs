//! Go module-tree integrity; no extraction or execution.
//! Algorithm: <https://go.dev/src/cmd/vendor/golang.org/x/mod/sumdb/dirhash/hash.go>

use std::io::Read;

use base64::Engine as _;
use sha2::{Digest, Sha256};

/// Go's x/mod/sumdb/dirhash.HashZip + Hash1: sorted names, each preceded by
/// its content SHA-256 and two spaces. Hashes include the module@version/
/// prefix and directory entries, exactly as HashZip does. Never extracts or
/// executes files. Unsupported/malformed archives and budget exhaustion are
/// unverified, not a digest mismatch. This is integrity, not trust in a module.
pub(super) fn zip_h1(mut archive: impl Read + std::io::Seek) -> Option<String> {
    const MAX_BYTES: u64 = 500 * 1024 * 1024;
    // The zip reader holds every central-directory entry in memory (about
    // 200 bytes each) before it can be asked how many there are, and a
    // directory of bare 46-byte entries packs millions into one artifact.
    if central_headers(&mut archive).ok()? > MAX_ENTRIES {
        return None;
    }
    archive.rewind().ok()?;
    let mut zip = zip::ZipArchive::new(archive).ok()?;
    if zip.len() > MAX_ENTRIES {
        return None;
    }
    let mut names = std::collections::BTreeMap::new();
    let mut total = 0u64;
    let mut name_bytes = 0usize;
    for i in 0..zip.len() {
        let file = zip.by_index(i).ok()?;
        let name = file.name().ok()?;
        name_bytes = name_bytes.checked_add(name.len())?;
        if name_bytes > 16 * 1024 * 1024 || file.name_raw() != name.as_bytes() {
            return None;
        }
        // `enclosed_name` alone admits an absolute name (it drops the root),
        // which no module zip holds.
        if name.len() > 4096
            || name.starts_with('/')
            || name.contains(['\n', '\r', '\0', '\\'])
            || file.enclosed_name().is_none()
            || names.insert(name.to_string(), i).is_some()
        {
            return None;
        }
        total = total.checked_add(file.size())?;
        if total > MAX_BYTES {
            return None;
        }
    }
    let mut tree = Sha256::new();
    let mut actual_total = 0u64;
    for (name, i) in names {
        let mut file = zip.by_index(i).ok()?;
        let mut digest = Sha256::new();
        let mut buf = [0u8; 32768];
        loop {
            let count = file.read(&mut buf).ok()?;
            if count == 0 {
                break;
            }
            actual_total = actual_total.checked_add(count as u64)?;
            if actual_total > MAX_BYTES {
                return None;
            }
            digest.update(&buf[..count]);
        }
        tree.update(format!("{}  {}\n", crate::fetch::to_hex(digest.finalize()), name).as_bytes());
    }
    Some(base64::engine::general_purpose::STANDARD.encode(tree.finalize()))
}

/// The most entries a module zip may hold to be hashed.
const MAX_ENTRIES: usize = 100_000;

/// How many times the central-directory header signature occurs in `archive`.
/// Every entry the zip reader parses starts with it at an offset of its own,
/// so this bounds the entries it will hold, whichever end-of-directory record
/// it trusts — before it reads any of them.
fn central_headers(mut archive: impl Read) -> std::io::Result<usize> {
    const SIGNATURE: &[u8] = b"PK\x01\x02";
    let mut count = 0;
    let mut buf = vec![0u8; 64 * 1024];
    // Bytes kept from the previous read, so a signature split across two
    // reads is seen; fewer than a signature, so none is counted twice.
    let mut kept = 0;
    loop {
        let n = match archive.read(&mut buf[kept..]) {
            Ok(0) => return Ok(count),
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        let filled = kept + n;
        count += buf[..filled]
            .windows(SIGNATURE.len())
            .filter(|window| *window == SIGNATURE)
            .count();
        kept = filled.min(SIGNATURE.len() - 1);
        buf.copy_within(filled - kept..filled, 0);
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    pub(in crate::fetch) fn archive(
        reverse: bool,
        method: zip::CompressionMethod,
        name: &str,
        content: &str,
    ) -> Vec<u8> {
        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let mut files = vec![
            ("example.test/m@v1.0.0/go.mod", "module example.test/m\n"),
            (name, content),
        ];
        if reverse {
            files.reverse();
        }
        for (name, value) in files {
            zip.start_file(
                name,
                zip::write::SimpleFileOptions::default().compression_method(method),
            )
            .unwrap();
            zip.write_all(value.as_bytes()).unwrap();
        }
        zip.finish().unwrap().into_inner()
    }

    #[test]
    fn golden_hash_is_independent_of_zip_encoding() {
        // Independently computed Hash1 summary, not generated by zip_h1.
        let expected = "7gPDTdAetOil7VBHFXxFU4lStBctQ7LKO/0XF15Bdy8=";
        for method in [
            zip::CompressionMethod::Stored,
            zip::CompressionMethod::Deflated,
        ] {
            for reverse in [false, true] {
                let data = archive(reverse, method, "example.test/m@v1.0.0/m.go", "package m\n");
                assert_eq!(
                    zip_h1(std::io::Cursor::new(&data)).as_deref(),
                    Some(expected)
                );
            }
        }
        for (name, content) in [
            ("example.test/m@v1.0.0/m.go", "package changed\n"),
            ("example.test/m@v1.0.0/other.go", "package m\n"),
        ] {
            let data = archive(false, zip::CompressionMethod::Stored, name, content);
            assert_ne!(
                zip_h1(std::io::Cursor::new(&data)).as_deref(),
                Some(expected)
            );
        }
    }

    /// A directory of bare 46-byte headers packs millions of entries into one
    /// artifact, and the zip reader would hold each (a gigabyte for a 256 MiB
    /// download) before the entry cap could be applied. The headers are
    /// counted first, and the reader never opens an archive with too many.
    #[test]
    fn too_many_directory_entries_are_refused_before_the_zip_is_read() {
        let data = archive(
            false,
            zip::CompressionMethod::Stored,
            "example.test/m@v1.0.0/m.go",
            "package m\n",
        );
        assert_eq!(central_headers(Cursor::new(&data)).unwrap(), 2);
        // A signature split across reads is counted once.
        struct Trickle<'a>(&'a [u8]);
        impl Read for Trickle<'_> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let Some((first, rest)) = self.0.split_first() else {
                    return Ok(0);
                };
                buf[0] = *first;
                self.0 = rest;
                Ok(1)
            }
        }
        assert_eq!(
            central_headers(Trickle(b"PPK\x01\x02PK\x01\x02PK\x01")).unwrap(),
            2
        );
        // The zip reader finds its directory by seeking to the end; it must
        // never get that far.
        struct Unopened(Cursor<Vec<u8>>);
        impl Read for Unopened {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.0.read(buf)
            }
        }
        impl std::io::Seek for Unopened {
            fn seek(&mut self, to: std::io::SeekFrom) -> std::io::Result<u64> {
                assert_eq!(to, std::io::SeekFrom::Start(0), "the zip reader ran");
                std::io::Seek::seek(&mut self.0, to)
            }
        }
        let bomb = b"PK\x01\x02".repeat(MAX_ENTRIES + 1);
        assert_eq!(zip_h1(Unopened(Cursor::new(bomb))), None);
    }

    #[test]
    fn malformed_or_ambiguous_archives_are_unverified() {
        assert_eq!(zip_h1(std::io::Cursor::new(b"not a zip")), None);
        for name in [
            "../escape.go",
            "/absolute.go",
            "line\nbreak.go",
            "back\\slash.go",
        ] {
            let data = archive(false, zip::CompressionMethod::Stored, name, "package m\n");
            assert_eq!(zip_h1(std::io::Cursor::new(&data)), None, "{name}");
        }
        let mut data = archive(
            false,
            zip::CompressionMethod::Stored,
            "example.test/m@v1.0.0/m.go",
            "package m\n",
        );
        let position = data
            .windows(10)
            .position(|part| part == b"package m\n")
            .unwrap();
        data[position] ^= 1;
        assert_eq!(
            zip_h1(std::io::Cursor::new(&data)),
            None,
            "CRC errors must not verify"
        );
    }
}
