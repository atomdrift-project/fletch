//! Pin verification: fetched bytes against a declared hash or a PURL checksum.

use filefacts::{HashAlgo, PinnedHash};
use sha1::Sha1;
use sha2::{Digest, Sha512};

use crate::fetch::go_hash;
use crate::fetch::select::purl_checksums;

/// Verify fetched bytes against a declared pin. `None` when there is no pin
/// or verification is unsupported, malformed, or exceeds its budget.
pub(crate) fn verify_pin(pin: Option<&PinnedHash>, bytes: &[u8], sha256_hex: &str) -> Option<bool> {
    let pin = pin?;
    match pin.algo {
        HashAlgo::Sha256 => Some(pin.value.eq_ignore_ascii_case(sha256_hex)),
        HashAlgo::Sha512 => {
            // npm `integrity` carries base64.
            use base64::Engine as _;
            let b64 = base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes));
            Some(b64 == pin.value)
        }
        // Legacy npm `integrity` — everything a yarn v1 lockfile pins, so
        // treating it as unverifiable made a whole ecosystem's lockfiles
        // report an unchecked pin over bytes we had already hashed. SHA-1 is
        // collision-weak, but a declared digest that matches the delivered
        // bytes is still evidence they are the bytes the lockfile named.
        // `integrity` carries base64; a `resolved` fragment carries hex.
        HashAlgo::Sha1 => {
            use base64::Engine as _;
            let digest = Sha1::digest(bytes);
            let b64 = base64::engine::general_purpose::STANDARD.encode(digest);
            Some(b64 == pin.value || hex::encode(digest).eq_ignore_ascii_case(&pin.value))
        }
        HashAlgo::GoModH1 => {
            go_hash::zip_h1(bytes).map(|actual| actual == pin.value.trim_start_matches("h1:"))
        }
        _ => None,
    }
}

pub(crate) fn verify_purl_checksum(locator: &str, bytes: &[u8], sha256_hex: &str) -> Option<bool> {
    let checksums = purl_checksums(&crate::purl::Purl::parse(locator).ok()?);
    if checksums.is_empty() {
        return None;
    }
    let sha512 = checksums
        .contains_key("sha512")
        .then(|| hex::encode(Sha512::digest(bytes)));
    let sha1 = checksums
        .contains_key("sha1")
        .then(|| hex::encode(Sha1::digest(bytes)));
    // A digest we cannot compute is no evidence either way, so it neither
    // verifies the bytes nor casts doubt on a supported digest that matched.
    // Letting it veto meant every PyPI artifact read as an unverified pin:
    // the provider publishes `blake2b_256` and `md5` beside the `sha256` we
    // check, and the two we skip were erasing the one we confirmed.
    let mut verified = false;
    for (algorithm, expected) in checksums {
        let actual = match algorithm.as_str() {
            "sha256" => sha256_hex,
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
