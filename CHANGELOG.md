# Changelog

## 3.0.0

A hardening and simplification release. The public API is smaller and more
strongly typed; the migration notes below cover every breaking change.

### Security

- `find`: four inputs that took quadratic time (backslash runs after a URL,
  `-/npm` token floods, deeply nested `exec(exec(…))`, mass PAC calls) are now
  linear, with timing-bounded regression tests.
- A `repository_url` is matched by parsed host, never by substring: a URL that
  merely contains `aur.archlinux.org` no longer folds onto the genuine AUR key.
- Registry lookups deny any `repository_url` that does not name the type's
  public registry; the fetcher applies the same policy, so bytes and
  reputation always come from one registry. An OCI `repository_url` is
  validated against the reference grammar.
- Container layers are read the way containerd reads them: nothing after the
  tar end-of-archive marker, and nothing beneath an emitted symlink. Layers are
  spooled to disk and streamed instead of held in memory.
- `GITHUB_TOKEN` is attached only to `api.github.com/repos/{owner}/{repo}`
  documents fletch builds, is never re-attached after a redirect chain leaves
  that origin, and authenticated responses are cached apart from anonymous
  ones. Private-repository metadata is never reported.
- The cache refuses directories (and shards) owned by another user or writable
  by group or others; the sweep checks before writing anything.
- A request can only lower the backend's size ceiling, never raise it.
- Distro indices are streamed with per-format caps; openSUSE's sha512
  `primary.xml` checksum is now verified.

### Fixes

- SRI `sha256-<base64>` pins verify; they were always reported as mismatches.
- A pin mismatch, real 404, or unresolved reference is no longer overwritten as
  `BudgetExceeded` when the batch budget runs out; cache hits are free.
- A yank, unlist, or retraction sets `version_removed` (Cargo, PyPI, JSR,
  pub.dev, Hex, NuGet, Firefox, Homebrew, CPAN); a takedown sets
  `security_hold` (ComfyUI, Dify, Firefox). A requested version is never
  silently replaced by the latest (NuGet, CPAN, Clojars, Firefox, JetBrains,
  VS Code, and others).
- `purl::identity` keeps qualifiers that distinguish a release (conda
  `channel`, rpm `epoch`, …).
- `find`: option values are no longer read as package names
  (`conda -c conda-forge`, `gem -v 1.2.3`, `apt -t …`); npm names ending in
  `.js` are found; `RUN [...]` exec forms keep the `FROM` distro.
- A transient 5xx is retried per request instead of holding the whole host.

### Migration

**Crate root**
- `fletch::registry`, `try_registry` → `fletch::registry::lookup` (returns
  `Result<Registry, RegistryError>`).
- `fletch::registry_with_sources`, `try_registry_with_sources` →
  `fletch::registry::lookup_recorded`.
- `fletch::url_to_purl` → `fletch::purl::url_to_purl`.
- `registry::parse_purl` → `purl::Purl::parse`.

**purl**
- `Purl::canonical()` → `to_string()` (`Display`).
- `release_identity`, `release_identity_at`, `artifact_identity` →
  `Purl::identity`, `Purl::release`, `Purl::artifact`.
- `PurlComponents`, `Purl::from_components` → `Purl::build`.
- `Purl::namespace_string` → `namespace().join("/")`.
- `PurlError::{Syntax, Type}` now carry a reason.
- `pkg:homebrew/…` normalizes to `pkg:brew/…`; identities keep more qualifiers,
  so lookup keys built by 2.x for such PURLs change.

**find**
- `references`, `references_in_bytes`, `references_from_facts` return
  `Discovery { references, unresolved, truncated }`.
- `fetch_calls`, `discover_fetch_calls`, `discover_batch_programs` →
  `references_from_facts(file_type, values, symbols, declared)`.
- `file_type: &str` parameters take `filefacts::FileType`.

**fetch**
- `fetch_references` and `fetch_references_with` → one `fetch_references(…,
  source_sha256: Option<&str>, …, on_fetched)`; `FetchBudget` gains
  `requests_per_fetch` and `deadline` (use `..FetchBudget::default()`).
- `FetchRecord::pin_verified` removed: `Outcome::PinMismatch` is a mismatch.
- `resolve_artifacts` and `resolve_declared_reference` return
  `Result<_, ResolveError>`; a registry outage is `ResolveError::Failed`.
- `ArtifactCandidate` has typed `kind`, `version`, `yanked`,
  `checksum_mismatch`, `subpath`; `ArtifactMatrix::select`, `ArtifactTarget`,
  `SelectionPolicy` removed.
- `Outcome` is `#[non_exhaustive]`; `FetchError::Io` added.
- `HttpFetch::new` returns `FetchError`.
- `Fixtures` requires the `test-util` feature.

**cache_sweep**
- `Root` and the `*_from_env` helpers removed; `Budget` is opaque.
  `cleanup`, `refs_budget`, `spawn`, `spawn_periodic` are unchanged.

**CLI**
- Exit codes `0`/`1`/`2`, `--help`, `--version`, `FLETCH_LOG`; an oversized
  source carries `truncated: true`; the CLI no longer sweeps the cache.
