//! The accumulator every recognizer pushes into: it places each reference in
//! the file, bounds what one file can produce, and records budget cut-offs.

use std::collections::{BTreeMap, HashMap, HashSet};

use filefacts::{DependencyContext, PinnedHash, RefKind, RefLocator, Reference};

use super::{Discovery, UnresolvedFetchCall};

/// How many times one file's text may be searched for a reference's evidence.
/// Each search can read the whole text, so a cap keeps a file with a huge
/// number of references from costing time quadratic in its size.
const EVIDENCE_SEARCHES: usize = 64;

/// The most evidence one reference keeps. Evidence is often a whole line, and
/// a crafted line can name a package per token: copying it for each would
/// cost memory quadratic in the line's length.
pub(super) const MAX_EVIDENCE_BYTES: usize = 1024;

/// The most distinct references the recognizers here add for one file. Past
/// this, a file is padding rather than a program.
pub(super) const MAX_FOUND_REFS: usize = 50_000;

/// `evidence` cut to [`MAX_EVIDENCE_BYTES`] on a character boundary.
pub(super) fn clip(evidence: &str) -> &str {
    &evidence[..evidence.floor_char_boundary(MAX_EVIDENCE_BYTES)]
}

/// Where `part` sits in `text`, when it is a slice of it.
pub(super) fn position_in(text: &str, part: &str) -> Option<usize> {
    let start = part.as_ptr().addr().checked_sub(text.as_ptr().addr())?;
    (start + part.len() <= text.len()).then_some(start)
}

/// What makes two references the same: the locator with its pin and
/// dependency context. The same URL or package legitimately surfaces through
/// more than one recognizer (declared, npm hook, decoded string, command
/// stream), and only its first sighting is kept.
type Key = (RefLocator, Option<PinnedHash>, Option<DependencyContext>);

/// `reference`'s [`Key`], or `None` for an unclassified fact: those can
/// describe distinct constraints on one locator (module-tree vs manifest
/// hashes, conflicting pins, replacement directives) and are never merged.
fn key(reference: &Reference) -> Option<Key> {
    (reference.kind != RefKind::Undefined).then(|| {
        (
            reference.locator.clone(),
            reference.pinned_hash.clone(),
            reference.context.clone(),
        )
    })
}

/// Drop references whose [`Key`] already appeared, keeping the first.
pub(super) fn dedup(refs: &mut Vec<Reference>) {
    let mut seen = HashSet::new();
    refs.retain(|r| key(r).is_none_or(|k| seen.insert(k)));
}

/// One file's discovery in progress. The file text, when there is one, gives
/// each pushed reference a citable byte offset. Each reference is kept once,
/// as it arrives, so a repeated one never spends the file's reference cap.
#[derive(Debug)]
pub(super) struct Found<'a> {
    refs: Vec<Reference>,
    /// Where each kept reference's [`Key`] sits in `refs`.
    seen: HashMap<Key, usize>,
    text: Option<&'a str>,
    /// The dependency context every reference added during
    /// [`with_context`](Self::with_context) carries.
    context: Option<DependencyContext>,
    unresolved: Vec<UnresolvedFetchCall>,
    truncated: bool,
    /// Evidence searches left (see [`EVIDENCE_SEARCHES`]).
    searches: usize,
    /// The last evidence searched for and where it was found, so the
    /// packages of one command line share one search.
    last_search: Option<(String, Option<u64>)>,
    /// References still allowed (see [`MAX_FOUND_REFS`]).
    room: usize,
    /// How many of `refs` came declared.
    declared: usize,
}

impl<'a> Found<'a> {
    pub(super) fn new(declared: &[Reference], text: Option<&'a str>) -> Self {
        let mut found = Self {
            refs: Vec::with_capacity(declared.len()),
            seen: HashMap::new(),
            text,
            context: None,
            unresolved: Vec::new(),
            truncated: false,
            searches: EVIDENCE_SEARCHES,
            last_search: None,
            room: MAX_FOUND_REFS,
            declared: 0,
        };
        // Declared references are the file's own and never spend its cap.
        for reference in declared {
            found.insert(reference.clone());
        }
        found.declared = found.refs.len();
        found
    }

    /// The file's text, when the recognizers have it.
    pub(super) fn text(&self) -> Option<&'a str> {
        self.text
    }

    /// Whether the file's reference cap is spent, so a recognizer can stop
    /// working for references that would be dropped.
    pub(super) fn is_full(&self) -> bool {
        self.room == 0
    }

    /// Run `scan` with every reference it adds carrying `context`: the
    /// packages an npm lifecycle hook installs are build-time dependencies
    /// that run install scripts.
    pub(super) fn with_context(
        &mut self,
        context: DependencyContext,
        scan: impl FnOnce(&mut Self),
    ) {
        let outer = self.context.replace(context);
        scan(self);
        self.context = outer;
    }

    /// Push an imperative reference (no pin) to each of `locators`, all cited
    /// by one `evidence` at `at`, or where `evidence` is placed when the
    /// caller does not know. Evidence cut from the file's own text is placed
    /// where it sits; evidence from elsewhere (an npm hook read from parsed
    /// JSON) is searched for (see [`search`](Self::search)). It is placed
    /// once for all the locators: a long line naming a package per word,
    /// compared with the text per package, would cost quadratic time.
    pub(super) fn push(
        &mut self,
        locators: impl IntoIterator<Item = RefLocator>,
        kind: RefKind,
        source: &str,
        evidence: &str,
        at: Option<u64>,
    ) {
        let mut locators = locators.into_iter();
        if self.is_full() {
            return;
        }
        let Some(first) = locators.next() else {
            return;
        };
        let at = at.or_else(|| match self.text.and_then(|t| position_in(t, evidence)) {
            Some(at) => Some(at as u64),
            None => self.search(evidence, &first),
        });
        for locator in std::iter::once(first).chain(locators) {
            self.push_at(locator, kind, source, evidence, at);
        }
    }

    /// Where `evidence` (else `locator`'s anchor) first occurs in the text,
    /// within the file's search allowance.
    fn search(&mut self, evidence: &str, locator: &RefLocator) -> Option<u64> {
        if let Some((last, at)) = &self.last_search
            && last == evidence
        {
            return *at;
        }
        let text = self.text?;
        if self.searches == 0 {
            return None;
        }
        self.searches -= 1;
        if self.searches == 0 {
            tracing::debug!(
                limit = EVIDENCE_SEARCHES,
                "evidence search budget spent; later references carry no offset"
            );
        }
        let at = text
            .find(evidence)
            .or_else(|| anchor(locator).and_then(|anchor| text.find(&anchor)))
            .map(|at| at as u64);
        self.last_search = Some((evidence.to_owned(), at));
        at
    }

    /// Push an imperative reference whose byte offset the caller already knows.
    pub(super) fn push_at(
        &mut self,
        locator: RefLocator,
        kind: RefKind,
        source: impl Into<String>,
        evidence: &str,
        offset: Option<u64>,
    ) {
        let mut reference = Reference::new(locator, kind, source, clip(evidence));
        reference.offset = offset;
        self.add(reference);
    }

    /// Add a reference a recognizer built, unless it is already here or the
    /// file's reference cap is spent.
    pub(super) fn add(&mut self, mut reference: Reference) {
        if self.is_full() {
            return;
        }
        if reference.context.is_none() {
            reference.context.clone_from(&self.context);
        }
        if reference.evidence.len() > MAX_EVIDENCE_BYTES {
            let keep = clip(&reference.evidence).len();
            reference.evidence.truncate(keep);
        }
        if !self.insert(reference) {
            return;
        }
        self.room -= 1;
        if self.room == 0 {
            self.truncated = true;
            tracing::warn!(
                limit = MAX_FOUND_REFS,
                "reference limit reached; later references in this file are dropped"
            );
        }
    }

    /// Add `reference` in place of an earlier one with the same [`Key`] whose
    /// source is one of `sources`: a citation by the API that uses a value
    /// outranks the plain string scans that also saw it. Any other earlier
    /// one keeps its place.
    pub(super) fn supersede(&mut self, mut reference: Reference, sources: &[&str]) {
        let Some(earlier) = key(&reference).and_then(|k| self.seen.get(&k).copied()) else {
            self.add(reference);
            return;
        };
        if let Some(old) = self.refs.get_mut(earlier)
            && sources.contains(&old.source.as_str())
        {
            let keep = clip(&reference.evidence).len();
            reference.evidence.truncate(keep);
            *old = reference;
        }
    }

    /// Keep `reference` unless its [`Key`] is already here. Reports whether
    /// it was kept.
    fn insert(&mut self, reference: Reference) -> bool {
        if let Some(key) = key(&reference) {
            if self.seen.contains_key(&key) {
                return false;
            }
            self.seen.insert(key, self.refs.len());
        }
        self.refs.push(reference);
        true
    }

    /// Take in a sub-recognizer's whole result.
    pub(super) fn absorb(&mut self, discovery: Discovery) {
        for reference in discovery.references {
            self.add(reference);
        }
        self.unresolved.extend(discovery.unresolved);
        self.truncated |= discovery.truncated;
    }

    /// Record that `recognizer` stopped at `limit` before reading everything.
    pub(super) fn cut_off(&mut self, recognizer: &'static str, limit: &'static str) {
        self.truncated = true;
        tracing::debug!(
            recognizer,
            limit,
            "recognizer stopped early; later references in this file may be missed"
        );
    }

    /// The finished result.
    pub(super) fn into_discovery(self) -> Discovery {
        let mut by_source = BTreeMap::<&str, usize>::new();
        for reference in &self.refs {
            *by_source.entry(reference.source.as_str()).or_default() += 1;
        }
        tracing::debug!(
            declared = self.declared,
            references = self.refs.len(),
            unresolved = self.unresolved.len(),
            truncated = self.truncated,
            ?by_source,
            "references discovered"
        );
        Discovery {
            references: self.refs,
            unresolved: self.unresolved,
            truncated: self.truncated,
        }
    }
}

/// A findable substring for placing a reference whose full evidence isn't
/// verbatim in the file: the URL, or a PURL's package name (`%40` → `@`,
/// version stripped).
fn anchor(locator: &RefLocator) -> Option<String> {
    match locator {
        RefLocator::Purl(p) => {
            let body = p.strip_prefix("pkg:").unwrap_or(p);
            let body = body.split_once('/').map_or(body, |(_, rest)| rest);
            let name = body.split('@').next().unwrap_or(body);
            Some(name.replace("%40", "@"))
        }
        RefLocator::Url(s) | RefLocator::Path(s) => Some(s.clone()),
        _ => None,
    }
    .filter(|anchor| !anchor.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_is_clipped_and_references_are_capped() {
        let mut script = String::from("npm install");
        for i in 0..2_000 {
            script.push_str(&format!(" pkg{i}"));
        }
        let found = super::super::references_in_bytes(script.as_bytes(), "install.sh");
        assert_eq!(found.references.len(), 2_000);
        assert!(!found.truncated);
        assert!(
            found
                .references
                .iter()
                .all(|r| r.evidence.len() <= MAX_EVIDENCE_BYTES && r.offset == Some(0))
        );

        let mut found = Found::new(&[], None);
        for i in 0..MAX_FOUND_REFS + 10 {
            let locator = RefLocator::Purl(format!("pkg:npm/p{i}"));
            found.push([locator], RefKind::Command, "test", "npm install", None);
        }
        let discovery = found.into_discovery();
        assert_eq!(discovery.references.len(), MAX_FOUND_REFS);
        assert!(discovery.truncated);

        let wide = "é".repeat(MAX_EVIDENCE_BYTES);
        assert!(clip(&wide).len() <= MAX_EVIDENCE_BYTES);
        assert!(wide.starts_with(clip(&wide)));
    }

    #[test]
    fn absorbed_references_count_against_the_cap() {
        let mut found = Found::new(&[], None);
        let many = (0..MAX_FOUND_REFS + 5).map(|i| {
            Reference::new(
                RefLocator::Url(format!("https://e.test/{i}")),
                RefKind::UrlFetch,
                "test",
                "x".repeat(MAX_EVIDENCE_BYTES + 1),
            )
        });
        found.absorb(Discovery {
            references: many.collect(),
            ..Discovery::default()
        });
        let discovery = found.into_discovery();
        assert_eq!(discovery.references.len(), MAX_FOUND_REFS);
        assert!(discovery.truncated);
        assert!(
            discovery
                .references
                .iter()
                .all(|r| r.evidence.len() == MAX_EVIDENCE_BYTES)
        );
    }

    #[test]
    fn dedup_preserves_scope_and_integrity_constraints() {
        let mut a = Reference::new(
            RefLocator::Purl("pkg:npm/a@1.0.0".into()),
            RefKind::Dependency,
            "lock",
            "a",
        );
        a.context = Some(filefacts::DependencyContext {
            scope: filefacts::DependencyScope::Development,
            optional: false,
            has_install_script: false,
            installed_path: None,
        });
        let mut runtime = a.clone();
        if let Some(context) = runtime.context.as_mut() {
            context.scope = filefacts::DependencyScope::Runtime;
        }
        let mut pinned = runtime.clone();
        pinned.pinned_hash = Some(filefacts::PinnedHash {
            algo: filefacts::HashAlgo::Sha512,
            value: "PIN".into(),
        });
        let refs = vec![a.clone(), a, runtime, pinned];
        let mut kept = refs.clone();
        dedup(&mut kept);
        assert_eq!(kept.len(), 3);
        // Declared and discovered references are kept once each the same way.
        let mut found = Found::new(&refs[..2], None);
        found.absorb(Discovery {
            references: refs,
            ..Discovery::default()
        });
        assert_eq!(found.into_discovery().references, kept);
    }

    #[test]
    fn a_repeated_reference_does_not_spend_the_cap() {
        let script = format!(
            "npm i {}\nnpm i evil\n",
            "a ".repeat(MAX_FOUND_REFS + 10_000)
        );
        let found = super::super::references_in_bytes(script.as_bytes(), "x.sh");
        assert_eq!(
            super::super::tests::locators(&found.references),
            ["pkg:npm/a", "pkg:npm/evil"]
        );
        assert!(!found.truncated);
    }

    #[test]
    fn a_superseding_citation_replaces_only_the_named_sources() {
        let url = |source: &str| {
            Reference::new(
                RefLocator::Url("https://x.test/p.pac".into()),
                RefKind::UrlFetch,
                source,
                "",
            )
        };
        let mut found = Found::new(&[], None);
        found.add(url("string"));
        found.supersede(url("api"), &["string"]);
        found.supersede(url("again"), &["string"]);
        found.add(url("text"));
        let refs = found.into_discovery().references;
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].source, "api");

        let mut found = Found::new(&[url("declared")], None);
        found.supersede(url("api"), &["string"]);
        assert_eq!(found.into_discovery().references[0].source, "declared");
    }
}
