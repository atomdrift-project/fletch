//! Pin verification: a fetched body against a declared hash or a PURL checksum,
//! from digests taken in one pass over the body.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

use base64::Engine as _;
use filefacts::{HashAlgo, PinnedHash};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

use crate::fetch::go_hash;
use crate::fetch::select::purl_checksums;
use crate::purl::Purl;

/// Every digest one reference declares for its bytes: the manifest's pin and
/// the checksums its PURL carries.
pub(crate) struct Pins<'a> {
    declared: Option<&'a PinnedHash>,
    checksums: BTreeMap<String, String>,
    /// Whether the PURL has a `checksum` qualifier at all, even one too
    /// malformed to yield a digest.
    checksum_qualifier: bool,
}

impl<'a> Pins<'a> {
    /// The pins of a reference declaring `declared`, fetched as `purl`.
    pub(crate) fn new(declared: Option<&'a PinnedHash>, purl: Option<&Purl>) -> Self {
        Self {
            declared,
            checksums: purl.map(purl_checksums).unwrap_or_default(),
            checksum_qualifier: purl.is_some_and(|p| p.qualifier("checksum").is_some()),
        }
    }

    /// Whether the reference declares any integrity requirement, so bytes no
    /// pin could be checked against are unverified rather than plain.
    pub(crate) fn declared(&self) -> bool {
        self.declared.is_some() || self.checksum_qualifier
    }

    /// Whether a manifest pin is a Go module-tree hash, read from the
    /// archive at random rather than streamed.
    pub(crate) fn is_go_tree(&self) -> bool {
        self.declared
            .is_some_and(|pin| pin.algo == HashAlgo::GoModH1)
    }

    /// Whether either pin calls for `algo`, named `name` in a PURL checksum.
    fn wants(&self, algo: HashAlgo, name: &str) -> bool {
        self.declared.is_some_and(|p| p.algo == algo) || self.checksums.contains_key(name)
    }
}

/// What one pass over a body tells about it: its SHA-256 and size, and the
/// other digests its pins name (computed only when they do).
pub(crate) struct Digests {
    sha256: [u8; 32],
    pub(crate) size: u64,
    sha1: Option<[u8; 20]>,
    sha512: Option<[u8; 64]>,
}

impl Digests {
    /// The body's SHA-256, lowercase hex.
    pub(crate) fn sha256_hex(&self) -> String {
        hex::encode(self.sha256)
    }
}

/// Read `body` to its end once, taking its SHA-256 and size, and its SHA-1
/// and SHA-512 when `pins` call for them.
pub(crate) fn digest(mut body: impl Read, pins: &Pins<'_>) -> std::io::Result<Digests> {
    let mut sha256 = Sha256::new();
    let mut sha1 = pins.wants(HashAlgo::Sha1, "sha1").then(Sha1::new);
    let mut sha512 = pins.wants(HashAlgo::Sha512, "sha512").then(Sha512::new);
    let mut size = 0u64;
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let n = match body.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        sha256.update(&chunk[..n]);
        if let Some(h) = sha1.as_mut() {
            h.update(&chunk[..n]);
        }
        if let Some(h) = sha512.as_mut() {
            h.update(&chunk[..n]);
        }
        size += n as u64;
    }
    Ok(Digests {
        sha256: sha256.finalize().into(),
        size,
        sha1: sha1.map(|h| h.finalize().into()),
        sha512: sha512.map(|h| h.finalize().into()),
    })
}

/// Whether `declared` spells `digest`, in hex (any case) or standard base64.
/// Lockfiles use both: npm `integrity` is SRI base64 (`sha256-…`, `sha1-…`,
/// `sha512-…`), a Cargo.lock `checksum` or a yarn `resolved` fragment is hex.
fn spells(declared: &str, digest: &[u8]) -> bool {
    hex::encode(digest).eq_ignore_ascii_case(declared)
        || base64::engine::general_purpose::STANDARD.encode(digest) == declared
}

/// Verify a body, by its `digests`, against the manifest's pin. A Go
/// module-tree pin reads the body's zip at `zip`. `None` when there is no pin
/// or verification is unsupported, malformed, or exceeds its budget.
///
/// SHA-1 is collision-weak, but a declared SHA-1 that matches the delivered
/// bytes is still evidence they are the bytes the lockfile named, and it is
/// all a yarn v1 lockfile pins.
pub(crate) fn verify_pin(pins: &Pins<'_>, digests: &Digests, zip: Option<&Path>) -> Option<bool> {
    let pin = pins.declared?;
    match pin.algo {
        HashAlgo::Sha256 => Some(spells(&pin.value, &digests.sha256)),
        HashAlgo::Sha512 => Some(spells(&pin.value, digests.sha512.as_ref()?)),
        HashAlgo::Sha1 => Some(spells(&pin.value, digests.sha1.as_ref()?)),
        HashAlgo::GoModH1 => go_hash::zip_h1(std::fs::File::open(zip?).ok()?)
            .map(|actual| actual == pin.value.trim_start_matches("h1:")),
        _ => None,
    }
}

/// Verify a body, by its `digests`, against the checksums its PURL carries.
/// `Some(false)` when any computable checksum disagrees, `Some(true)` when at
/// least one agrees and none disagrees, `None` when none can be computed. An
/// algorithm fletch does not compute (`blake2b-256`, `md5`) is no evidence
/// either way, so it neither verifies the bytes nor vetoes a match.
pub(crate) fn verify_purl_checksum(pins: &Pins<'_>, digests: &Digests) -> Option<bool> {
    let mut verified = false;
    for (algorithm, expected) in &pins.checksums {
        let actual: Option<&[u8]> = match algorithm.as_str() {
            "sha256" => Some(&digests.sha256),
            "sha512" => digests.sha512.as_ref().map(<[u8; 64]>::as_slice),
            "sha1" => digests.sha1.as_ref().map(<[u8; 20]>::as_slice),
            _ => continue,
        };
        if !actual.is_some_and(|actual| hex::encode(actual).eq_ignore_ascii_case(expected)) {
            return Some(false);
        }
        verified = true;
    }
    verified.then_some(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pinned(algo: HashAlgo, value: String) -> PinnedHash {
        PinnedHash { algo, value }
    }

    fn judged(pin: &PinnedHash, body: &[u8]) -> Option<bool> {
        let pins = Pins::new(Some(pin), None);
        let digests = digest(body, &pins).unwrap();
        verify_pin(&pins, &digests, None)
    }

    #[test]
    fn every_content_pin_verifies_in_hex_or_base64() {
        let b64 = |d: &[u8]| base64::engine::general_purpose::STANDARD.encode(d);
        let body = b"tarball bytes";
        let sha256 = Sha256::digest(body);
        let sha512 = Sha512::digest(body);
        let sha1 = Sha1::digest(body);
        for (algo, digest) in [
            (HashAlgo::Sha256, sha256.as_slice()),
            (HashAlgo::Sha512, sha512.as_slice()),
            (HashAlgo::Sha1, sha1.as_slice()),
        ] {
            for spelling in [
                hex::encode(digest),
                hex::encode(digest).to_ascii_uppercase(),
                b64(digest),
            ] {
                assert_eq!(
                    judged(&pinned(algo, spelling.clone()), body),
                    Some(true),
                    "{algo:?} {spelling}"
                );
                assert_eq!(
                    judged(&pinned(algo, spelling.clone()), b"other bytes"),
                    Some(false),
                    "{algo:?} {spelling} over other bytes"
                );
            }
        }
    }

    /// filefacts reads an SRI `sha256-<base64>` integrity as a SHA-256 pin
    /// carrying the base64 text; it must verify, not read as a mismatch.
    #[test]
    fn an_sri_sha256_integrity_pin_verifies() {
        let body = b"package";
        let sri = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(body));
        assert_eq!(judged(&pinned(HashAlgo::Sha256, sri), body), Some(true));
    }

    #[test]
    fn purl_checksums_ignore_algorithms_fletch_cannot_compute() {
        let body = b"REAL";
        let purl = |checksum: &str| {
            Purl::parse(&format!("pkg:cargo/foo@1.0.0?checksum={checksum}")).unwrap()
        };
        let verdict = |purl: &Purl| {
            let pins = Pins::new(None, Some(purl));
            let digests = digest(&body[..], &pins).unwrap();
            verify_purl_checksum(&pins, &digests)
        };
        let good = hex::encode(Sha256::digest(body));
        assert_eq!(
            verdict(&purl(&format!("blake2b-256:ab,sha256:{good}"))),
            Some(true)
        );
        assert_eq!(verdict(&purl("blake2b-256:ab,sha256:00")), Some(false));
        assert_eq!(verdict(&purl("md5:0123")), None);
        let sha1 = hex::encode(Sha1::digest(body));
        assert_eq!(verdict(&purl(&format!("sha1:{sha1}"))), Some(true));
    }
}
