//! The accumulator every recognizer pushes into: it places each reference in
//! the file, bounds what one file can produce, and records budget cut-offs.

use std::collections::{BTreeMap, HashSet};

use filefacts::{RefKind, RefLocator, Reference};

use super::{Discovery, UnresolvedFetchCall};

/// How many times one file's text may be searched for a reference's evidence.
/// Each search can read the whole text, so a cap keeps a file with a huge
/// number of references from costing time quadratic in its size.
const EVIDENCE_SEARCHES: usize = 64;

/// The most evidence one reference keeps. Evidence is often a whole line, and
/// a crafted line can name a package per token: copying it for each would
/// cost memory quadratic in the line's length.
pub(super) const MAX_EVIDENCE_BYTES: usize = 1024;

/// The most references the recognizers here add for one file. Past this, a
/// file is padding rather than a program.
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

/// One file's discovery in progress. The file text, when there is one, gives
/// each pushed reference a citable byte offset.
#[derive(Debug)]
pub(super) struct Found<'a> {
    pub(super) refs: Vec<Reference>,
    pub(super) text: Option<&'a str>,
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
        Self {
            refs: declared.to_vec(),
            text,
            unresolved: Vec::new(),
            truncated: false,
            searches: EVIDENCE_SEARCHES,
            last_search: None,
            room: MAX_FOUND_REFS,
            declared: declared.len(),
        }
    }

    /// Push an imperative reference (no pin) cited by `evidence`. Evidence cut
    /// from the file's own text is placed where it sits. Evidence from elsewhere
    /// — an npm hook read from parsed JSON — is searched for: its first
    /// occurrence, else the package name's or URL's, else no offset, which is
    /// also what it gets once the file's searches are spent.
    pub(super) fn push(
        &mut self,
        locator: RefLocator,
        kind: RefKind,
        source: impl Into<String>,
        evidence: &str,
    ) {
        if self.room == 0 {
            return;
        }
        let offset = self.locate(evidence, &locator);
        self.push_at(locator, kind, source, evidence, offset);
    }

    /// Where `evidence` sits: its place when it was cut from the file's own
    /// text, else where a search finds it (see [`search`](Self::search)).
    pub(super) fn locate(&mut self, evidence: &str, locator: &RefLocator) -> Option<u64> {
        match self.text.and_then(|t| position_in(t, evidence)) {
            Some(at) => Some(at as u64),
            None => self.search(evidence, locator),
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

    /// Add a reference a recognizer built, within the file's reference cap.
    pub(super) fn add(&mut self, mut reference: Reference) {
        if self.room == 0 {
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
        if reference.evidence.len() > MAX_EVIDENCE_BYTES {
            let keep = clip(&reference.evidence).len();
            reference.evidence.truncate(keep);
        }
        self.refs.push(reference);
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

    /// The finished result, each reference once.
    pub(super) fn into_discovery(mut self) -> Discovery {
        dedup(&mut self.refs);
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

/// Drop references whose locator already appeared, keeping the first. The same
/// URL or package legitimately surfaces through more than one recognizer
/// (declared, npm hook, decoded string, command stream).
pub(super) fn dedup(refs: &mut Vec<Reference>) {
    let mut seen = HashSet::new();
    refs.retain(|r| {
        // Unclassified facts can describe distinct constraints on the same
        // locator (module-tree vs manifest hashes, conflicting pins, or
        // replacement directives). They are not fetch targets to coalesce.
        r.kind == RefKind::Undefined
            || seen.insert((r.locator.clone(), r.pinned_hash.clone(), r.context.clone()))
    });
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
            found.push(locator, RefKind::Command, "test", "npm install");
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
        let mut refs = vec![a.clone(), a, runtime, pinned];
        dedup(&mut refs);
        assert_eq!(refs.len(), 3);
    }
}
