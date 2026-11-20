//! Hosts that did not answer a connection attempt, remembered so that a dead
//! host costs one wait instead of one for every reference to it.
//!
//! The download host a hostile sample names is often gone by the time the
//! sample is scanned, and every scan of it then waited out the connect
//! timeout again. The memory lives in the blob cache, behind the trust check
//! fetched bytes get: an entry anyone else could plant would keep a second
//! stage from being fetched.
//!
//! Only a host fletch did not choose is remembered (see
//! [`HttpFetch`](super::HttpFetch)). When a registry does not answer, the
//! fault is likelier this machine's network than the registry, so it is asked
//! again at the next reference.

use reqwest::Url;

use super::cache::{BlobCache, CachedMeta, TTL_UNPINNED};
use super::{now, sha256_hex};

/// The hosts that did not answer, kept in a [`BlobCache`].
#[derive(Debug)]
pub(super) struct Unanswered(BlobCache);

impl Unanswered {
    pub(super) const fn new(cache: BlobCache) -> Self {
        Self(cache)
    }

    /// Whether the origin of `url` failed to answer within the last
    /// [`TTL_UNPINNED`]: silence is trusted for as long as the bytes of a
    /// URL that did answer are.
    pub(super) fn holds(&self, url: &Url) -> bool {
        self.0.fresh_sidecar(&key(url), TTL_UNPINNED).is_some()
    }

    /// Remember that the origin of `url` did not answer just now.
    pub(super) fn note(&self, url: &Url) {
        let meta = CachedMeta {
            fetched_at: now(),
            final_url: url.origin().ascii_serialization(),
            ..CachedMeta::default()
        };
        self.0.put(&key(url), &[], &meta);
    }
}

/// The cache key of the origin of `url`: scheme, host and port, so a port
/// that answers is not held for one that does not.
fn key(url: &Url) -> String {
    sha256_hex(format!("unanswered {}", url.origin().ascii_serialization()).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(text: &str) -> Url {
        Url::parse(text).expect("url")
    }

    /// A host noted as unanswered is held under every path, and no other
    /// origin is: not another host, port or scheme.
    #[test]
    fn a_noted_origin_is_held_and_no_other() {
        let dir = tempfile::tempdir().expect("tempdir");
        let hosts = Unanswered::new(BlobCache::with_dir(dir.path()));
        let dead = url("http://203.0.113.7/18/stage2.js");
        assert!(!hosts.holds(&dead), "nothing is held before it is noted");

        hosts.note(&dead);
        assert!(hosts.holds(&dead));
        assert!(hosts.holds(&url("http://203.0.113.7/another/path")));
        assert!(!hosts.holds(&url("http://203.0.113.8/18/stage2.js")));
        assert!(!hosts.holds(&url("http://203.0.113.7:8080/18/stage2.js")));
        assert!(!hosts.holds(&url("https://203.0.113.7/18/stage2.js")));
    }

    /// What one process noted, the next one finds: the memory is on disk.
    #[test]
    fn the_memory_outlives_the_client_that_wrote_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dead = url("https://gone.example/payload");
        Unanswered::new(BlobCache::with_dir(dir.path())).note(&dead);
        assert!(Unanswered::new(BlobCache::with_dir(dir.path())).holds(&dead));
    }

    /// A cache that keeps nothing remembers nothing, so every host is asked.
    #[test]
    fn a_disabled_cache_holds_no_host() {
        let hosts = Unanswered::new(BlobCache::disabled());
        let dead = url("https://gone.example/payload");
        hosts.note(&dead);
        assert!(!hosts.holds(&dead));
    }
}
