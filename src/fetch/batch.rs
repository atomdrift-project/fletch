//! A file's references fetched concurrently under one run-wide budget.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use filefacts::{RefKind, RefLocator, Reference};

use super::BlobCache;
use super::record::{FetchRecord, Outcome, fetch_contained};
use super::transport::{Fetch, FetchError, Fetched, Request};

/// Per-run ceiling on fetching, so one analysis can't turn into a fetch
/// storm. A manifest with thousands of deps fetches up to the cap; the rest
/// are recorded as [`Outcome::BudgetExceeded`], never silently dropped. Cache
/// hits are free of every limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FetchBudget {
    /// Maximum number of references to fetch over the network.
    pub max_count: usize,
    /// Maximum total bytes to retrieve over the network, registry metadata
    /// included. Best-effort: a request admitted under the cap may cross it.
    pub max_bytes: u64,
    /// Network requests allowed per reference the count admits: room for
    /// every resolution round (a dist-tag, a package document, a Go proxy's
    /// case probe, a container's token and manifests) plus the artifact.
    pub requests_per_fetch: usize,
    /// Wall-clock ceiling on the batch's network use. Each request has its
    /// own deadline, but a run of them against a tarpit (a host trickling
    /// every response out to that deadline) would otherwise hold the batch
    /// for days.
    pub deadline: Duration,
}

impl Default for FetchBudget {
    fn default() -> Self {
        Self {
            // A real dependency closure routinely exceeds 256 (a single Rust
            // crate's Cargo.lock can name 400+), so cap at 512 to cover the
            // common case without unbounding a crafted reference fan-out.
            max_count: 512,
            // 5 GiB retrieved per whole run (every hop, every file) — the safety
            // ceiling against a crafted reference chain, not a per-fetch limit
            // (that is `HttpFetch::with_max_bytes`).
            max_bytes: 5 * 1024 * 1024 * 1024,
            requests_per_fetch: 8,
            // An hour covers a full dependency closure, container pulls included.
            deadline: Duration::from_secs(60 * 60),
        }
    }
}

/// Whether a batch also fetches the URLs a script merely reaches for — a `curl`
/// or `wget` target ([`RefKind::UrlFetch`]). Packages, and dependencies or
/// commanded packages a manifest gives as a raw URL, are fetched either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UrlFetches {
    /// Leave them unfetched.
    Skip,
    /// Fetch them too.
    Include,
}

/// Fetch every selectable reference under `budget`, returning one
/// [`FetchRecord`] edge per selected reference, in declaration order: fetched,
/// served from cache, or recorded as over budget. `url_fetches` says whether a
/// script's own URL fetches are among them; identity references (a
/// repository) are never fetched. Each record is stamped with
/// `source_sha256`, the file that declared the references, so it is a
/// self-contained hash→hash edge.
///
/// Fetches run concurrently across a bounded pool of scoped threads.
/// `max_count` bounds *live* fetches exactly: a slot is claimed atomically the
/// moment a cache miss is about to reach the network, and cache hits are
/// served without one, even once the budget is spent — a warm re-run is never
/// throttled. Which references win a contested cap is not guaranteed. Every
/// network request the batch makes, registry metadata included, is charged
/// to `max_bytes`, `requests_per_fetch` and `deadline`; a reference the spent
/// budget cut off mid-resolution or mid-pull is recorded as
/// [`Outcome::BudgetExceeded`], while one that reached a verdict keeps it.
///
/// `on_fetched` fires once per selected reference with its final record, the
/// moment it lands, from whichever pool worker handled it — so it is invoked
/// concurrently and must be `Sync`. It receives the caller's own reference
/// (the key before any locator refinement), letting a caller drive live
/// progress. A panic inside one fetch is that reference's
/// [`FetchError::Internal`]; a panic in `on_fetched` reaches the caller.
#[must_use]
pub fn fetch_references(
    refs: &[Reference],
    source_sha256: Option<&str>,
    url_fetches: UrlFetches,
    net: &dyn Fetch,
    cache: &BlobCache,
    budget: FetchBudget,
    on_fetched: &(dyn Fn(&Reference, &FetchRecord) + Sync),
) -> Vec<FetchRecord> {
    let targets: Vec<&Reference> = refs.iter().filter(|r| selected(r, url_fetches)).collect();
    let run = Run::new(budget);
    let batch = Batch {
        targets: &targets,
        cursor: AtomicUsize::new(0),
        source_sha256,
        net,
        cache,
        run: &run,
        on_fetched,
    };
    // Fetching is network-bound, so the pool scales with the host but is
    // independent of the CPU pool: clamped so a long reference list can't
    // open an unbounded number of sockets while a small host still
    // parallelizes. Scoped OS threads rather than a shared CPU pool, so a
    // fetching worker never starves concurrent analysis.
    let workers = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(4)
        .clamp(2, 16)
        .min(targets.len());
    let mut done: Vec<(usize, FetchRecord)> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers).map(|_| scope.spawn(|| batch.work())).collect();
        // Fetch panics are contained per reference, so anything still
        // unwinding came from the caller's `on_fetched`: theirs to see.
        handles
            .into_iter()
            .flat_map(|h| {
                h.join()
                    .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
            })
            .collect()
    });
    done.sort_unstable_by_key(|(i, _)| *i);
    done.into_iter().map(|(_, rec)| rec).collect()
}

/// Whether a reference should be fetched: a fetch target whose locator resolves
/// to fetchable bytes. A package coordinate (PURL) is always fetched. A raw URL
/// is fetched when it *is* a declared dependency or a commanded package — a
/// PKGBUILD `source=()`, a lockfile URL entry — since those are genuine
/// dependencies that merely lack a package coordinate, so they follow the
/// deps/packages policy the caller already applied by [`RefKind`]. Only an
/// opportunistic [`RefKind::UrlFetch`] (a script's `curl`/`wget`) is gated
/// behind `url_fetches`. An intra-artifact path is resolved against sibling
/// files, not fetched, and a locator kind this fletch predates names nothing
/// it can fetch.
fn selected(r: &Reference, url_fetches: UrlFetches) -> bool {
    r.is_fetch_target()
        && match r.locator {
            RefLocator::Purl(_) => true,
            RefLocator::Url(_) => {
                matches!(r.kind, RefKind::Dependency | RefKind::Command)
                    || url_fetches == UrlFetches::Include
            }
            _ => false,
        }
}

/// One batch's shared state, read by every pool worker.
struct Batch<'a> {
    targets: &'a [&'a Reference],
    /// The next target index a worker takes.
    cursor: AtomicUsize,
    source_sha256: Option<&'a str>,
    net: &'a dyn Fetch,
    cache: &'a BlobCache,
    run: &'a Run,
    on_fetched: &'a (dyn Fn(&Reference, &FetchRecord) + Sync),
}

impl Batch<'_> {
    /// Take targets off the shared cursor until none remain, returning each
    /// record with its declaration index.
    fn work(&self) -> Vec<(usize, FetchRecord)> {
        let mut done = Vec::new();
        loop {
            let i = self.cursor.fetch_add(1, Ordering::Relaxed);
            let Some(r) = self.targets.get(i) else {
                return done;
            };
            done.push((i, self.fetch(r)));
        }
    }

    /// Fetch one reference through a meter of its own, so a refusal the
    /// spent budget caused is told apart from the reference's own verdict.
    fn fetch(&self, r: &Reference) -> FetchRecord {
        let started = Instant::now();
        let net = Metered {
            inner: self.net,
            run: self.run,
            refused: AtomicBool::new(false),
        };
        let mut rec = fetch_contained(r, &net, self.cache, || self.run.claim_fetch());
        if net.refused.load(Ordering::Relaxed)
            && matches!(rec.outcome, Outcome::Failed(_) | Outcome::Unresolved(_))
        {
            tracing::debug!(
                locator = %rec.locator,
                outcome = ?rec.outcome,
                "run budget cut the reference off mid-resolution or mid-pull; recorded as over budget"
            );
            let resolved_url = rec.resolved_url.take();
            rec = FetchRecord::terminal(std::mem::take(&mut rec.locator), Outcome::BudgetExceeded);
            rec.resolved_url = resolved_url;
        }
        rec.stamp(r);
        rec.source_sha256 = self.source_sha256.map(str::to_owned);
        crate::metrics::fetch(&rec, started.elapsed());
        (self.on_fetched)(r, &rec);
        rec
    }
}

/// What a batch has spent of its [`FetchBudget`], shared by every worker.
struct Run {
    budget: FetchBudget,
    started: Instant,
    /// Network bytes retrieved so far.
    bytes: AtomicU64,
    /// Counted network requests issued so far.
    requests: AtomicUsize,
    /// Live fetches claimed so far.
    fetches: AtomicUsize,
}

impl Run {
    fn new(budget: FetchBudget) -> Self {
        Self {
            budget,
            started: Instant::now(),
            bytes: AtomicU64::new(0),
            requests: AtomicUsize::new(0),
            fetches: AtomicUsize::new(0),
        }
    }

    fn max_requests(&self) -> usize {
        self.budget
            .max_count
            .saturating_add(1)
            .saturating_mul(self.budget.requests_per_fetch)
    }

    /// Whether the run's bytes, requests or time are used up.
    fn spent(&self) -> bool {
        self.bytes.load(Ordering::Relaxed) >= self.budget.max_bytes
            || self.requests.load(Ordering::Relaxed) >= self.max_requests()
            || self.started.elapsed() >= self.budget.deadline
    }

    /// Claim one live-fetch slot, unless the run is spent or every slot is
    /// taken. Atomic, so concurrent workers never claim more than
    /// `max_count`.
    fn claim_fetch(&self) -> bool {
        !self.spent()
            && self
                .fetches
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                    (n < self.budget.max_count).then_some(n + 1)
                })
                .is_ok()
    }
}

/// A batch worker's view of the backend for one reference: every request is
/// admitted against the run's budget and its network bytes charged once. A
/// cache hit never reaches it, so it is never charged.
struct Metered<'a> {
    inner: &'a dyn Fetch,
    run: &'a Run,
    /// Whether the budget refused one of this reference's requests.
    refused: AtomicBool,
}

impl Fetch for Metered<'_> {
    fn send(&self, request: &Request<'_>) -> Result<Fetched, FetchError> {
        // A request that names its own ceiling is a container pull's
        // size-declared blob read from an allowlisted registry — a pull is one
        // fetch slot however many layers it has — so it is charged by its
        // bytes alone, not counted against the request cap.
        let run = self.run;
        let admitted = !run.spent()
            && (request.max_bytes.is_some()
                || run.requests.fetch_add(1, Ordering::Relaxed) < run.max_requests());
        if !admitted {
            tracing::debug!(url = request.url, "run budget spent; request refused");
            self.refused.store(true, Ordering::Relaxed);
            return Err(FetchError::Refused("run budget spent".into()));
        }
        let fetched = self.inner.send(request)?;
        // A spooling backend hands back no bytes; what it wrote is the spool.
        let bytes = match request.spool {
            Some(spool) if fetched.bytes.is_empty() => {
                std::fs::metadata(spool).map_or(0, |m| m.len())
            }
            _ => fetched.bytes.len() as u64,
        };
        run.bytes.fetch_add(bytes, Ordering::Relaxed);
        Ok(fetched)
    }

    fn allows_oci(&self) -> bool {
        self.inner.allows_oci()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fetch::record::tests::{Spooling, dep};
    use crate::fetch::{Fixtures, Unresolved, sha256_hex};
    use filefacts::{HashAlgo, PinnedHash};

    fn as_kind(kind: RefKind, mut r: Reference) -> Reference {
        r.kind = kind;
        r
    }

    fn unlimited(max_count: usize) -> FetchBudget {
        FetchBudget {
            max_count,
            max_bytes: u64::MAX,
            ..FetchBudget::default()
        }
    }

    /// [`fetch_references`] without a progress callback.
    fn fetch_all(
        refs: &[Reference],
        url_fetches: UrlFetches,
        net: &dyn Fetch,
        cache: &BlobCache,
        budget: FetchBudget,
    ) -> Vec<FetchRecord> {
        fetch_references(
            refs,
            Some("sha"),
            url_fetches,
            net,
            cache,
            budget,
            &|_, _| {},
        )
    }

    /// A backend that counts every request issued, so tests can assert the
    /// budget against real network activity.
    struct CountingFetch {
        inner: Fixtures,
        gets: AtomicUsize,
    }

    impl CountingFetch {
        fn new(inner: Fixtures) -> Self {
            Self {
                inner,
                gets: AtomicUsize::new(0),
            }
        }
    }

    impl Fetch for CountingFetch {
        fn send(&self, request: &Request<'_>) -> Result<Fetched, FetchError> {
            self.gets.fetch_add(1, Ordering::SeqCst);
            self.inner.send(request)
        }
    }

    /// `n` distinct versioned npm refs (resolved offline, so each fetch is
    /// exactly one content request) and a matching fixture set.
    fn numbered_npm_refs(n: usize) -> (Fixtures, Vec<Reference>) {
        let mut fx = Fixtures::default();
        let mut refs = Vec::new();
        for i in 0..n {
            let url = format!("https://registry.npmjs.org/p{i}/-/p{i}-1.0.0.tgz");
            fx = fx.with(&url, format!("PKG{i}").as_bytes());
            refs.push(dep(RefLocator::Purl(format!("pkg:npm/p{i}@1.0.0")), None));
        }
        (fx, refs)
    }

    #[test]
    fn selected_gates_urls_by_kind_not_just_locator() {
        let with_kind =
            |locator: RefLocator, kind: RefKind| Reference::new(locator, kind, "test", "test");
        let url = || RefLocator::Url("https://example.com/x.tar.gz".into());
        let purl = || RefLocator::Purl("pkg:npm/left-pad@1.3.0".into());
        // A declared dependency or a commanded package expressed as a raw URL
        // is a genuine fetch target regardless of `url_fetches`.
        assert!(selected(
            &with_kind(url(), RefKind::Dependency),
            UrlFetches::Skip
        ));
        assert!(selected(
            &with_kind(url(), RefKind::Command),
            UrlFetches::Skip
        ));
        // An opportunistic URL fetch (a script's curl/wget) stays behind the flag.
        assert!(!selected(
            &with_kind(url(), RefKind::UrlFetch),
            UrlFetches::Skip
        ));
        assert!(selected(
            &with_kind(url(), RefKind::UrlFetch),
            UrlFetches::Include
        ));
        // A package coordinate is always fetched; a repository is identity.
        assert!(selected(
            &with_kind(purl(), RefKind::Dependency),
            UrlFetches::Skip
        ));
        assert!(!selected(
            &with_kind(url(), RefKind::Repository),
            UrlFetches::Include
        ));
    }

    /// A backend that panics when asked for one URL, as a parser bug tripped
    /// by hostile bytes would, and otherwise serves `inner`.
    struct PanicsOn {
        url: &'static str,
        inner: Fixtures,
    }

    impl Fetch for PanicsOn {
        fn send(&self, request: &Request<'_>) -> Result<Fetched, FetchError> {
            assert!(request.url != self.url, "hostile bytes");
            self.inner.send(request)
        }
    }

    #[test]
    fn a_panicking_fetch_fails_alone() {
        let ok = "https://ok.test/a.sh";
        let bad = "https://bad.test/b.sh";
        let net = PanicsOn {
            url: bad,
            inner: Fixtures::default().with(ok, b"A"),
        };
        let refs: Vec<Reference> = [bad, ok]
            .into_iter()
            .map(|url| dep(RefLocator::Url(url.into()), None))
            .collect();
        let recs = fetch_all(
            &refs,
            UrlFetches::Include,
            &net,
            &BlobCache::disabled(),
            FetchBudget::default(),
        );
        // The panic is that reference's failure, not a budget cut, and the
        // other reference is still fetched.
        assert_eq!(
            recs[0].outcome,
            Outcome::Failed(FetchError::Internal("hostile bytes".into()))
        );
        assert_eq!(recs[0].source_sha256.as_deref(), Some("sha"));
        assert_eq!(recs[1].outcome, Outcome::Ok);
    }

    #[test]
    fn a_panic_in_the_callers_callback_reaches_the_caller() {
        let url = "https://ok.test/a.sh";
        let net = Fixtures::default().with(url, b"A");
        let refs = [dep(RefLocator::Url(url.into()), None)];
        let run = std::panic::catch_unwind(|| {
            fetch_references(
                &refs,
                None,
                UrlFetches::Include,
                &net,
                &BlobCache::disabled(),
                FetchBudget::default(),
                &|_, _| panic!("caller bug"),
            )
        });
        assert!(run.is_err(), "the caller's panic must not be swallowed");
    }

    /// The callback sees each reference's final record, stamped as the batch
    /// returns it — source, offset, binding class and all.
    #[test]
    fn the_callback_receives_the_stamped_record() {
        let url = "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz";
        let net = Fixtures::default().with(url, b"PKG");
        let mut r = dep(RefLocator::Purl("pkg:npm/foo@1.0.0".into()), None);
        r.offset = Some(7);
        let seen = std::sync::Mutex::new(Vec::new());
        let recs = fetch_references(
            std::slice::from_ref(&r),
            Some("trigsha"),
            UrlFetches::Skip,
            &net,
            &BlobCache::disabled(),
            FetchBudget::default(),
            &|_, rec| seen.lock().unwrap().push(rec.clone()),
        );
        let seen = seen.into_inner().unwrap();
        assert_eq!(seen, recs);
        assert_eq!(seen[0].source_sha256.as_deref(), Some("trigsha"));
        assert_eq!(seen[0].source_offset, Some(7));
        assert_eq!(seen[0].kind, RefKind::Dependency);
    }

    #[test]
    fn fetch_references_selection_and_budget() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = BlobCache::with_dir(dir.path().to_path_buf());
        let npm_url = "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz";
        let raw_url = "https://evil.test/x.sh";
        let net = Fixtures::default()
            .with(npm_url, b"PKG")
            .with(raw_url, b"SH");
        let refs = vec![
            dep(RefLocator::Purl("pkg:npm/foo@1.0.0".into()), None),
            as_kind(
                RefKind::UrlFetch,
                dep(RefLocator::Url(raw_url.into()), None),
            ),
            as_kind(
                RefKind::Repository,
                dep(RefLocator::Purl("pkg:github/o/r".into()), None),
            ),
        ];

        // Without URL fetches: only the package (raw URL + repo excluded).
        let recs = fetch_all(
            &refs,
            UrlFetches::Skip,
            &net,
            &cache,
            FetchBudget::default(),
        );
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].locator, "pkg:npm/foo@1.0.0");
        // Every edge is stamped with its source endpoint and binding class.
        assert_eq!(recs[0].source_sha256.as_deref(), Some("sha"));
        assert_eq!(recs[0].kind, RefKind::Dependency);

        // With URL fetches: package + raw URL; the repository is never fetched.
        let recs = fetch_all(
            &refs,
            UrlFetches::Include,
            &net,
            &cache,
            FetchBudget::default(),
        );
        assert_eq!(recs.len(), 2);
        // The raw URL's edge carries its own binding class, and it serializes.
        let url_rec = recs
            .iter()
            .find(|r| r.locator == raw_url)
            .expect("raw URL edge");
        assert_eq!(url_rec.kind, RefKind::UrlFetch);
        let json = serde_json::to_value(url_rec).expect("serialize edge");
        assert_eq!(json["kind"], serde_json::json!("url_fetch"));

        // A budget of one live fetch over a *cold* cache: exactly one ref is
        // fetched and the other is recorded as `BudgetExceeded`, never dropped.
        // Both misses are equal priority, so which one wins the slot isn't
        // guaranteed under the concurrent sweep — assert the multiset.
        let cold_dir = tempfile::tempdir().expect("tempdir");
        let cold_cache = BlobCache::with_dir(cold_dir.path().to_path_buf());
        let recs = fetch_all(&refs, UrlFetches::Include, &net, &cold_cache, unlimited(1));
        assert_eq!(recs.len(), 2);
        assert_eq!(recs.iter().filter(|r| r.outcome == Outcome::Ok).count(), 1);
        assert_eq!(
            recs.iter()
                .filter(|r| r.outcome == Outcome::BudgetExceeded)
                .count(),
            1
        );
        assert!(
            recs.iter()
                .all(|r| r.source_sha256.as_deref() == Some("sha"))
        );
    }

    #[test]
    fn cached_references_are_served_free_of_the_count_budget() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = BlobCache::with_dir(dir.path().to_path_buf());
        let npm_url = "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz";
        let raw_url = "https://evil.test/x.sh";
        let net = Fixtures::default()
            .with(npm_url, b"PKG")
            .with(raw_url, b"SH");
        let refs = vec![
            dep(RefLocator::Purl("pkg:npm/foo@1.0.0".into()), None),
            as_kind(
                RefKind::UrlFetch,
                dep(RefLocator::Url(raw_url.into()), None),
            ),
        ];
        let warm = fetch_all(
            &refs,
            UrlFetches::Include,
            &net,
            &cache,
            FetchBudget::default(),
        );
        assert!(
            warm.iter()
                .all(|r| r.outcome == Outcome::Ok && !r.is_cached())
        );
        // Re-run with zero live-fetch budget: cache hits don't count.
        let warm = fetch_all(&refs, UrlFetches::Include, &net, &cache, unlimited(0));
        assert_eq!(
            warm.iter()
                .filter(|r| r.is_cached() && r.outcome == Outcome::Ok)
                .count(),
            2
        );
    }

    /// A spent byte budget stops network fetches, never cache hits.
    #[test]
    fn cache_hits_are_served_after_the_byte_budget_is_spent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = BlobCache::with_dir(dir.path().to_path_buf());
        let (fx, refs) = numbered_npm_refs(4);
        let warm = fetch_all(
            &refs[..2],
            UrlFetches::Skip,
            &fx,
            &cache,
            FetchBudget::default(),
        );
        assert!(warm.iter().all(|r| r.outcome == Outcome::Ok));
        let spent = FetchBudget {
            max_bytes: 0,
            ..FetchBudget::default()
        };
        let net = CountingFetch::new(fx);
        let recs = fetch_all(&refs, UrlFetches::Skip, &net, &cache, spent);
        assert!(
            recs[..2]
                .iter()
                .all(|r| r.outcome == Outcome::Ok && r.is_cached())
        );
        assert!(
            recs[2..]
                .iter()
                .all(|r| r.outcome == Outcome::BudgetExceeded)
        );
        assert_eq!(net.gets.load(Ordering::SeqCst), 0);
    }

    /// Only network bytes are charged, and each once: a backend that hands
    /// the body back in memory is not charged again from the record, and a
    /// spooling one is charged by what it spooled.
    #[test]
    fn network_bytes_are_charged_once() {
        let (fx, refs) = numbered_npm_refs(2);
        let backends: [&dyn Fetch; 2] = [&fx, &Spooling(fx.clone())];
        for net in backends {
            let run = Run::new(FetchBudget {
                // Room for the first body ("PKG0", 4 bytes) charged once, but
                // not twice.
                max_bytes: 7,
                ..FetchBudget::default()
            });
            let batch = Batch {
                targets: &[],
                cursor: AtomicUsize::new(0),
                source_sha256: None,
                net,
                cache: &BlobCache::disabled(),
                run: &run,
                on_fetched: &|_, _| {},
            };
            assert_eq!(batch.fetch(&refs[0]).outcome, Outcome::Ok);
            assert_eq!(run.bytes.load(Ordering::Relaxed), 4);
            assert_eq!(batch.fetch(&refs[1]).outcome, Outcome::Ok);
            assert_eq!(run.bytes.load(Ordering::Relaxed), 8);
        }
    }

    /// A verdict reached as the budget runs out stands: a pin mismatch is a
    /// finding and a release the registry does not list is unresolved, not
    /// an over-budget edge.
    #[test]
    fn a_verdict_is_never_rewritten_as_over_budget() {
        let url = "https://registry.npmjs.org/a/-/a-1.0.0.tgz";
        let net = Fixtures::default()
            .with(url, b"SUBSTITUTED")
            .with("https://registry.npmjs.org/empty", br#"{"versions":{}}"#);
        let pinned = dep(
            RefLocator::Purl("pkg:npm/a@1.0.0".into()),
            Some(PinnedHash {
                algo: HashAlgo::Sha256,
                value: sha256_hex(b"ARTIFACT"),
            }),
        );
        let unlisted = dep(RefLocator::Purl("pkg:npm/empty".into()), None);
        // The reference's own one read spends the run.
        let budget = FetchBudget {
            max_bytes: 1,
            ..FetchBudget::default()
        };
        for (r, outcome) in [
            (pinned, Outcome::PinMismatch),
            (unlisted, Outcome::Unresolved(Unresolved::NoRelease)),
        ] {
            let recs = fetch_all(
                std::slice::from_ref(&r),
                UrlFetches::Skip,
                &net,
                &BlobCache::disabled(),
                budget,
            );
            assert_eq!(recs[0].outcome, outcome);
        }
    }

    /// A reference the spent budget refused mid-resolution is over budget.
    #[test]
    fn a_refusal_by_the_spent_budget_is_over_budget() {
        let spent = FetchBudget {
            max_bytes: 0,
            ..FetchBudget::default()
        };
        let recs = fetch_all(
            &[dep(RefLocator::Purl("pkg:npm/left-pad".into()), None)],
            UrlFetches::Skip,
            &Fixtures::default(),
            &BlobCache::disabled(),
            spent,
        );
        assert_eq!(recs[0].outcome, Outcome::BudgetExceeded);
    }

    #[test]
    fn metadata_requests_are_charged_to_the_run_budget() {
        // Versionless npm refs each need a registry read before any artifact
        // fetch; with no fixtures every read fails, so none ever claims a
        // count slot. Unmetered, every read would go out.
        let refs: Vec<Reference> = (0..200)
            .map(|i| dep(RefLocator::Purl(format!("pkg:npm/p{i}")), None))
            .collect();
        let net = CountingFetch::new(Fixtures::default());
        let budget = unlimited(1);
        let records = fetch_all(
            &refs,
            UrlFetches::Include,
            &net,
            &BlobCache::disabled(),
            budget,
        );
        let ceiling = (budget.max_count + 1) * budget.requests_per_fetch;
        let gets = net.gets.load(Ordering::SeqCst);
        assert!(
            gets <= ceiling,
            "{gets} requests for a ceiling of {ceiling}"
        );
        assert_eq!(
            records.len(),
            refs.len(),
            "every reference is still recorded"
        );
        let over = records
            .iter()
            .filter(|r| r.outcome == Outcome::BudgetExceeded)
            .count();
        let attempted = records.len() - over;
        assert!(
            attempted <= ceiling,
            "{attempted} references reached the network for a ceiling of {ceiling}: \
             one cut off mid-resolution is over budget, not failed"
        );
    }

    #[test]
    fn live_fetch_count_is_an_exact_ceiling_under_concurrency() {
        // Many cold-cache targets, a small budget, run repeatedly: the
        // reserve-on-miss gate must issue *exactly* `max_count` live gets every
        // time, with the rest recorded, in declaration order, as BudgetExceeded.
        let n = 64usize;
        let max_count = 10usize;
        for attempt in 0..50 {
            let dir = tempfile::tempdir().expect("tempdir");
            let cache = BlobCache::with_dir(dir.path().to_path_buf());
            let (fx, refs) = numbered_npm_refs(n);
            let net = CountingFetch::new(fx);
            let recs = fetch_all(&refs, UrlFetches::Skip, &net, &cache, unlimited(max_count));
            assert_eq!(recs.len(), n);
            for (i, rec) in recs.iter().enumerate() {
                assert_eq!(rec.locator, format!("pkg:npm/p{i}@1.0.0"));
            }
            let gets = net.gets.load(Ordering::SeqCst);
            assert_eq!(gets, max_count, "attempt {attempt}");
            let ok = recs.iter().filter(|r| r.outcome == Outcome::Ok).count();
            let exceeded = recs
                .iter()
                .filter(|r| r.outcome == Outcome::BudgetExceeded)
                .count();
            assert_eq!(ok, max_count, "attempt {attempt}");
            assert_eq!(exceeded, n - max_count, "attempt {attempt}");
        }
    }

    #[test]
    fn cache_hits_never_consume_the_budget_under_concurrency() {
        // Half the targets are pre-cached and interleaved with cold ones. Cache
        // hits must be served free — never blocking a cold ref from the budget,
        // even transiently.
        let n = 64usize;
        let max_count = 12usize;
        for attempt in 0..50 {
            let dir = tempfile::tempdir().expect("tempdir");
            let cache = BlobCache::with_dir(dir.path().to_path_buf());
            let (fx, refs) = numbered_npm_refs(n);
            let warm: Vec<Reference> = refs.iter().step_by(2).cloned().collect();
            let warmed = fetch_all(&warm, UrlFetches::Skip, &fx, &cache, FetchBudget::default());
            assert!(
                warmed
                    .iter()
                    .all(|r| r.outcome == Outcome::Ok && !r.is_cached())
            );

            let net = CountingFetch::new(fx);
            let recs = fetch_all(&refs, UrlFetches::Skip, &net, &cache, unlimited(max_count));
            assert_eq!(recs.len(), n);
            for even in (0..n).step_by(2) {
                assert!(
                    recs[even].is_cached() && recs[even].outcome == Outcome::Ok,
                    "attempt {attempt}: cached ref {even} should be served free"
                );
            }
            let gets = net.gets.load(Ordering::SeqCst);
            assert_eq!(gets, max_count, "attempt {attempt}");
        }
    }

    #[test]
    fn fetch_references_preserves_declaration_order_under_concurrency() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = BlobCache::with_dir(dir.path().to_path_buf());
        let n = 20usize;
        let (net, refs) = numbered_npm_refs(n);
        let recs = fetch_all(
            &refs,
            UrlFetches::Skip,
            &net,
            &cache,
            FetchBudget::default(),
        );
        assert_eq!(recs.len(), n);
        for (i, rec) in recs.iter().enumerate() {
            assert_eq!(rec.locator, format!("pkg:npm/p{i}@1.0.0"));
            assert_eq!(rec.outcome, Outcome::Ok);
        }
    }
}
