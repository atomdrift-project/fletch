//! Pin verification: a fetched body against a declared hash or a PURL checksum,
//! from digests taken in one pass over the body.

use std::io::Read;
use std::path::Path;

use filefacts::{HashAlgo, PinnedHash};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

use crate::fetch::go_hash;
use crate::fetch::select::purl_checksums;

/// What one pass over a body tells about it: its SHA-256 and size, and the
/// other digests its pins name (computed only when they do).
pub(crate) struct Digests {
    pub(crate) sha256: String,
    pub(crate) size: u64,
    sha1: Option<[u8; 20]>,
    sha512: Option<[u8; 64]>,
}

/// Read `body` to its end once, taking its SHA-256 and size, and its SHA-1
/// and SHA-512 when `pin` or `locator`'s checksums call for them.
pub(crate) fn digest(
    mut body: impl Read,
    pin: Option<&PinnedHash>,
    locator: &str,
) -> std::io::Result<Digests> {
    let checksums = crate::purl::Purl::parse(locator)
        .map(|purl| purl_checksums(&purl))
        .unwrap_or_default();
    let wants = |algo: HashAlgo, name: &str| {
        pin.is_some_and(|p| p.algo == algo) || checksums.contains_key(name)
    };
    let mut sha256 = Sha256::new();
    let mut sha1 = wants(HashAlgo::Sha1, "sha1").then(Sha1::new);
    let mut sha512 = wants(HashAlgo::Sha512, "sha512").then(Sha512::new);
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
        sha256: hex::encode(sha256.finalize()),
        size,
        sha1: sha1.map(|h| h.finalize().into()),
        sha512: sha512.map(|h| h.finalize().into()),
    })
}

/// Verify a body, by its `digests`, against a declared pin. A Go module-tree
/// pin reads the body's zip at `zip`. `None` when there is no pin or
/// verification is unsupported, malformed, or exceeds its budget.
pub(crate) fn verify_pin(
    pin: Option<&PinnedHash>,
    digests: &Digests,
    zip: Option<&Path>,
) -> Option<bool> {
    use base64::Engine as _;
    let pin = pin?;
    let base64 = |digest: &[u8]| base64::engine::general_purpose::STANDARD.encode(digest);
    match pin.algo {
        HashAlgo::Sha256 => Some(pin.value.eq_ignore_ascii_case(&digests.sha256)),
        // npm `integrity` carries base64.
        HashAlgo::Sha512 => Some(base64(digests.sha512.as_ref()?) == pin.value),
        // Legacy npm `integrity` — everything a yarn v1 lockfile pins, so
        // treating it as unverifiable made a whole ecosystem's lockfiles
        // report an unchecked pin over bytes we had already hashed. SHA-1 is
        // collision-weak, but a declared digest that matches the delivered
        // bytes is still evidence they are the bytes the lockfile named.
        // `integrity` carries base64; a `resolved` fragment carries hex.
        HashAlgo::Sha1 => {
            let digest = digests.sha1.as_ref()?;
            Some(
                base64(digest) == pin.value || hex::encode(digest).eq_ignore_ascii_case(&pin.value),
            )
        }
        HashAlgo::GoModH1 => go_hash::zip_h1(std::fs::File::open(zip?).ok()?)
            .map(|actual| actual == pin.value.trim_start_matches("h1:")),
        _ => None,
    }
}

/// Verify a body, by its `digests`, against the checksums its PURL carries.
pub(crate) fn verify_purl_checksum(locator: &str, digests: &Digests) -> Option<bool> {
    let checksums = purl_checksums(&crate::purl::Purl::parse(locator).ok()?);
    if checksums.is_empty() {
        return None;
    }
    let sha512 = digests.sha512.map(hex::encode);
    let sha1 = digests.sha1.map(hex::encode);
    // A digest we cannot compute is no evidence either way, so it neither
    // verifies the bytes nor casts doubt on a supported digest that matched.
    // Letting it veto meant every PyPI artifact read as an unverified pin:
    // the provider publishes `blake2b_256` and `md5` beside the `sha256` we
    // check, and the two we skip were erasing the one we confirmed.
    let mut verified = false;
    for (algorithm, expected) in checksums {
        let actual = match algorithm.as_str() {
            "sha256" => digests.sha256.as_str(),
            "sha512" => sha512.as_deref().unwrap_or_default(),
            "sha1" => sha1.as_deref().unwrap_or_default(),
            _ => continue,
        };
        if !expected.eq_ignore_ascii_case(actual) {
            return Some(false);
        }
        verified = true;
    }
    verified.then_some(true)
}
