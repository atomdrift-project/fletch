//! SHA-2 content digests: what a container registry addresses its blobs by,
//! and what an RPM repository publishes for its package index.

use std::fmt;

use sha2::{Digest as _, Sha256, Sha512};

use crate::fetch::to_hex;

/// A digest algorithm strong enough to hold content to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Algorithm {
    Sha256,
    Sha512,
}

impl Algorithm {
    /// The algorithm spelled `name` (`sha256`, `sha512`), if it is one held
    /// here.
    pub(crate) fn parse(name: &str) -> Option<Self> {
        match name {
            "sha256" => Some(Self::Sha256),
            "sha512" => Some(Self::Sha512),
            _ => None,
        }
    }

    /// How this algorithm is spelled.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
        }
    }

    /// A running digest under this algorithm.
    pub(crate) fn hasher(self) -> Hasher {
        match self {
            Self::Sha256 => Hasher::Sha256(Sha256::new()),
            Self::Sha512 => Hasher::Sha512(Sha512::new()),
        }
    }

    /// This algorithm's digest of `bytes`.
    pub(crate) fn digest(self, bytes: &[u8]) -> Digest {
        let mut hasher = self.hasher();
        hasher.update(bytes);
        hasher.finish()
    }
}

/// A digest: its algorithm and its lowercase hex. Displays as
/// `algorithm:hex`, the OCI spelling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Digest {
    pub(crate) algorithm: Algorithm,
    hex: String,
}

impl Digest {
    /// `algorithm`'s digest spelled `hex`, in either case; `None` unless it
    /// is the algorithm's full length in hex digits.
    pub(crate) fn new(algorithm: Algorithm, hex: &str) -> Option<Self> {
        let len = match algorithm {
            Algorithm::Sha256 => 64,
            Algorithm::Sha512 => 128,
        };
        (hex.len() == len && hex.bytes().all(|b| b.is_ascii_hexdigit())).then(|| Self {
            algorithm,
            hex: hex.to_ascii_lowercase(),
        })
    }

    /// A digest spelled `algorithm:hex` with lowercase hex, as the OCI
    /// distribution spec writes one; `None` for any other spelling.
    pub(crate) fn parse(spelled: &str) -> Option<Self> {
        let (name, hex) = spelled.split_once(':')?;
        if hex.bytes().any(|b| b.is_ascii_uppercase()) {
            return None;
        }
        Self::new(Algorithm::parse(name)?, hex)
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.algorithm.name(), self.hex)
    }
}

/// A running digest, fed as content streams past.
pub(crate) enum Hasher {
    Sha256(Sha256),
    Sha512(Sha512),
}

impl Hasher {
    pub(crate) fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Sha256(h) => h.update(bytes),
            Self::Sha512(h) => h.update(bytes),
        }
    }

    pub(crate) fn finish(self) -> Digest {
        let (algorithm, hex) = match self {
            Self::Sha256(h) => (Algorithm::Sha256, to_hex(h.finalize())),
            Self::Sha512(h) => (Algorithm::Sha512, to_hex(h.finalize())),
        };
        Digest { algorithm, hex }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digests_are_computed_under_the_named_algorithm() {
        assert_eq!(
            Algorithm::Sha256.digest(b"").to_string(),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let sha512 = Algorithm::Sha512.digest(b"x");
        assert_eq!(Digest::parse(&sha512.to_string()), Some(sha512));
    }

    #[test]
    fn only_a_full_lowercase_spelling_parses() {
        let hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert!(Digest::parse(&format!("sha256:{hex}")).is_some());
        for bad in [
            format!("sha256:{}", hex.to_ascii_uppercase()),
            format!("sha256:{}", &hex[1..]),
            format!("sha512:{hex}"),
            format!("md5:{hex}"),
            format!("sha256:{}z", &hex[1..]),
            hex.to_string(),
        ] {
            assert_eq!(Digest::parse(&bad), None, "{bad}");
        }
        // A repository index may publish its hex in uppercase.
        assert_eq!(
            Digest::new(Algorithm::Sha256, &hex.to_ascii_uppercase()),
            Digest::parse(&format!("sha256:{hex}"))
        );
    }
}
