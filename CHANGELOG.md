# Changelog

All notable changes to fletch. Versions follow [semantic versioning](https://semver.org/spec/v2.0.0.html).

## 3.0.0 (2026-11-17)

### Security

- Registry identity comes from the parsed host and path, so look-alike repository URLs cannot borrow another package's reputation.
- The GitHub token no longer follows redirects off its origin, and private-repository metadata is never reported.
- OCI flattening now reads tar like containerd, and refuses entries that tar-rs and Go parse differently.
- Overlay symlinks resolve within their own layer only, so no layer's bytes hide from the scan.
- Cap container entry counts, name bytes and Go module zip entries before they eat gigabytes of memory.
- Refuse cache roots and shards that another local user owns or can write, all the way down.
- Verify openSUSE's sha512 checksums instead of skipping them.
- Stale cache no longer masks a 404, 410 or refusal; only transient failures fall back.
- Back-off is held per origin and credential, so forged plain-http answers cannot stall authenticated requests.
- Every received body byte counts against the batch budget, including downloads abandoned as too large.
- Escape attacker-supplied URLs and error text in logs and CLI output, and keep signed query strings out of errors.
- Padding no longer hides hostile code: oversized manifests report truncation, and long stylesheets are read whole.
- Repeated filler no longer exhausts the reference cap and hides the references behind it.
- Crafted JavaScript, npm hook and shell input can no longer burn quadratic time or switch off the recognizer.
- Report an npm alias by its real target, and match PyPI yanks by PEP 440 equality.
- Encode gem versions, npm dist-tags and artifact file names as a single path segment.
- Find installs behind any number of options, and treat echoed commands as text, not installs.
- Report only http and https URLs from dynamic requires, and require https for PURL download URLs.
- Follow NuGet registration pages only on NuGet's own path, at most 64 of them.

### Features

- Breaking: `registry::lookup` replaces the registry functions and returns a typed error.
- Breaking: PURL identity is rebuilt around Purl::identity, keeping release qualifiers and normalizing homebrew to brew.
- Breaking: every finder returns a Discovery listing references, unresolved calls and truncation.
- Breaking: one fetch_references replaces the reference fetchers, with per-fetch request and deadline budgets.
- Breaking: PurlError now has typed reasons, RawSink is opaque, and FileType replaces file type strings.
- Breaking: the pin-verified flag is gone; a mismatched pin is reported as Outcome::PinMismatch.
- Breaking: the fletch binary builds only with the cli feature, so libraries skip its dependencies.
- Breaking: container records are named by full repository, such as docker.io/library/nginx.
- Fetch plain-HTTP URLs named by scanned files too; address, port and resolver guards still apply.
- Set `security_hold` on npm versions carrying a malware advisory, even when only that version was deleted.
- Add registry favorites, release timelines, and latest versions for many more registries, plus Wolfi and RPM Fusion.
- Find Ruby process-call downloaders, mshta and rundll32 targets, browser PAC URLs, and GNOME stylesheet imports.
- Add Purl::requirement to tell exact pins from ranges, tags and branches.
- Record per-reference coverage facts stating what went unexamined, and why.
- The CLI gains exit codes, help, version, and a log level through FLETCH_LOG.

### Fixes

- Downloads may exceed 30 seconds; large artifacts and container layers no longer fail as transient errors.
- Verify SRI sha256 pins, which always reported a mismatch.
- Never silently replace a requested version with the latest release.
- Report yanks, unlists and retractions as version removal across nine registries.
- Unreachable registries report a retryable failure and garbled answers InvalidResponse, never a missing release.
- Budget exhaustion no longer overwrites pin mismatches, 404s and unresolved references as BudgetExceeded.
- Retry a transient 5xx per request instead of holding the whole host.
- Keep qualifiers such as conda channel and rpm epoch in PURL identities.
- Stop reading option values, comments and printed text as package names or download targets.
- Cache pinned artifacts for the pinned TTL, and refetch a cached copy that fails its pin.
- Report the requested version, undated, for Arch, AUR and Fedora instead of the current build's.
- Reject Marketplace answers missing results or versions instead of guessing the extension is gone.
- Validate PURLs identically for download and lookup, and refuse unsafe coordinate shapes everywhere.

### Optimizations

- Spool container layers to disk and stream them instead of holding them in memory.
- A repeat Debian lookup drops from 15 ms to 0.13 ms by reusing the parsed index.
- Store already-compressed cache entries as-is, saving about 5 seconds per GB; older fletch refetches them.
- Compress container exports at xz preset 1: about 9x faster, output about a fifth larger.
- JavaScript reference finding is about 15% faster.
- Drop the hex and anyhow dependencies.

## 2.0.1 (2026-10-10)

### Fixes

- Make the GitHub token opt-in, and never send it to URLs from scanned files.
- Restrict `pkg:github` lookups to owner/repo, blocking token use against other API endpoints.
- Tighten SSRF: global-unicast IPv6 only, block ISATAP and special ranges and forbidden ports.
- Route OCI pulls through Fetch, so every registry and CDN hop gets SSRF checks.
- Stop registry responses from redirecting fetches through `oci://` targets or crafted AUR paths.
- Refuse off-registry PURLs with the new `RegistryError::OffRegistry`.
- Stop third-party namespaces (PPA, tap, Conda, CPAN, JSR) from borrowing official records.
- Require exact Maven and NuGet coordinate matches, rejecting look-alike artifacts.
- Read Chrome Web Store stats only from store-rendered text, not developer-controlled fields.
- Reject `%` in filename parts, blocking double-encoded path traversal.
- Verify openSUSE mirror indexes and OCI manifests against their published digests.
- Parse OCI references and digests strictly, and require HTTPS token realms.
- Stop serving stale cache on 404/410/451, so removed malware stays visibly removed.
- Length-prefix cache key parts, preventing URL/header key collisions.
- Create cache and spool files 0600/0700 with `create_new`, preventing symlink write-through.
- Cache sweeper skips roots owned by other users and refuses unexpected directories.
- Cap in-memory bodies, sidecar JSON, index lines and xz decoder memory.
- Add per-batch registry request and byte budgets with a one-hour deadline.
- Clamp `Retry-After` to 24 hours, preventing overflow panics.
- Error on distro index decompression over 512 MiB instead of silently truncating.
- Share one decompression budget across OCI layers and add a 30-minute flatten deadline.
- Match containerd OCI layering: last duplicate wins, whiteouts and directory replacement honored.
- Refuse ambiguous OCI tar entries and build fresh headers, preventing forged rootfs entries.
- Reject metacharacters and templated variables in install tokens, preventing forged PURLs.
- Stop reporting identifiers, redirects, subshells and runner arguments as package names.
- Recognize quoted packages, glued pipes and line continuations in install commands.
- Scan scripts containing invalid UTF-8 instead of skipping them.
- Raise the JS/Python AST node limit from 100k to 8M nodes.
- Escape PURLs in fletch registry errors.

### Features

- Resolve `child_process` and VS Code ShellExecution commands through constants, templates and imports.
- Report npm GitHub specs (`github:o/r#rev`) as `pkg:github` PURLs.
- Scan Dockerfile exec-form instructions and UTF-16 Shell, Dockerfile and PowerShell scripts.
- Recognize path-qualified and Windows tool names like `/opt/venv/bin/pip` and `npm.cmd`.
- Accept uppercase URL schemes and IP:port targets for bare curl/wget/iwr.
- Report Go `/...` install patterns by base path.
- Add a per-request `max_bytes` ceiling.

### Optimizations

- Replace oci-client with a built-in client, dropping about 65 crates including aws-lc-sys.
- Pull OCI blobs four at a time on scoped threads instead of a runtime per pull.
- Make OCI whiteout checks, distro XML scanning and bare-URL scanning linear.
- Build Python import alias maps once per file instead of per call.

## 2.0.0 (2026-10-09)

### Breaking Changes

- The `Fetch` trait's `get`, `get_with`, `get_any_status` and `post` are replaced by a single `send(&Request)`.
- `FetchRecord` replaces `cached`/`stale` with `served`, and several fields became `Option`, which also changes the JSON.
- `Outcome` variants now carry a typed reason and a `FetchError` instead of strings.
- The `distro` module is now private; the global byte-limit and TTL setters became `HttpFetch`/`BlobCache` builder methods.

### Features

- Adds Terraform providers, ComfyUI nodes and Dify plugins as fetchable registries.
- Detects `iwr|iex`, curl and wget one-liner droppers, including hosts given without a scheme.
- npm ranges like `^3` resolve to the highest matching release instead of latest.
- New `try_registry*` APIs return a typed `RegistryError`.
- Structured tracing metrics for fetches, registry lookups and back-offs.
- Honors `Retry-After` on 429/503 responses, waiting up to 30 seconds per host.
- Adds Quay.io pull counts and per-version CRAN release dates.

### Fixes

- Command hunting only considers real call sites, ignoring comments and strings.
- Python standard-library modules are no longer reported as PyPI dependencies.
- Go proxy timeouts or 5xx errors no longer mark releases as removed.
- Fixed NuGet versions with build metadata, and crates, npm and Maven packages that have only pre-releases.
- Credential headers are dropped on cross-origin redirects, and whole-request deadlines stop slow-drip servers.
- OCI pulls reject layers hosted at foreign URLs and no longer panic inside an existing tokio runtime.
- Panics caused by hostile input are now contained as `FetchError::Internal`.

### Optimizations

- Artifacts stream to a disk spool instead of being held in memory.
- Distro indexes are streamed and parsed once per process.
- Oversize responses are rejected using `Content-Length` before any download.
- OCI layers download concurrently, with a limit on parallelism.
- Dropped lzma-rs in favor of the existing xz2 dependency.

## 1.3.0 (2026-09-14)

### Features

- Go `h1:` module-tree hashes are actually verified.
- Cargo and Python version requirements resolve against registry metadata.
- `prefer_lock_pin` refines a manifest requirement from a co-located lock, staying unresolved when ambiguous.
- `resolve_declared_reference` exposes that refinement before age/reputation gating.
- Cache sweep gained entry-count ceiling, completion-aware marker, hourly retry and write-triggered re-sweep.

### Fixes

- Undefined-kind references aren't coalesced, so `go.sum` metadata hashes and conflicting pins survive discovery.
- Malformed or over-budget Go archives report as explicitly unverified rather than pinned.

## 1.2.1 (2026-09-10)

### Fixes

- Legacy npm/yarn-v1 SHA-1 integrity pins are now verified against fetched bytes instead of reporting an unverifiable pin.
- Go `h1:` digests no longer mark fetches as unverifiable.
- An unsupported digest (e.g. PyPI's `blake2b_256`/`md5`) no longer erases verification from a supported digest that matched.
- HTTP refusal status codes (e.g. 404) are recorded on the record's `status` field rather than only in error text.
- URL extraction trims trailing punctuation (line-continuation backslashes, sentence punctuation, empty fragments) so fewer bogus URLs are fetched.

### Optimizations

- Pin verification evaluates manifest pin and PURL checksum qualifier independently with simpler precedence; URL/pin code path simplified.

## 1.2.0 (2026-09-08)

### Features

- New `fetch::resolve_artifacts` / `ArtifactMatrix` enumerates every file a release publishes with its checksums, platform and ABI tags, and runtime constraints.
- Three PURL identities are now distinct and documented: `purl::identity` (broad lookup key), `purl::release_identity` (release-distinguishing), and `artifact_purl` (one exact file).
- `Purl::parse` repairs safe legacy spellings and emits one canonical PURL; `Purl::parse_strict` implements the purl-spec contract with no repairs.
- `make test-purl-spec` runs the upstream purl-spec suite, and PURL→URL→PURL is now tested bidirectionally for registries whose artifact URL is lossless.

### Fixes

- Single-segment Go modules (`tailscale.com`, `gioui.org`) are accepted instead of rejected as non-PURLs.
- Go module paths are matched case-insensitively against the proxy's `!x` encoding.
- The `name@version` repair now only applies when the coordinate carries no version of its own.
- A leading `@` is treated as an npm scope, not a version.

## 1.1.0 (2026-08-25)

### Features

- Added artifact-matrix resolution for npm, PyPI, RubyGems, Go modules, and Cargo crates.
- Added strict ECMA-427 PURL canonicalization and identity normalization.
- Expanded source reference extraction, including escaped imports and package-manager commands.
- Improved OCI image flattening and layer metadata handling.

### Bugfixes

- Hardened registry fetching against SSRF, malformed coordinates, and unsafe URL interpolation.
- Added checksum verification for PURL-selected artifacts.
- Fixed Go proxy escaping, npm dist-tag resolution, and platform-specific artifact selection.
- Made cache writes atomic and bounded decompression resistant to oversized or tampered entries.

### Optimizations

- Unified cached registry-document reads and stale-cache fallback behavior.
- Added bounded OCI layer counts and total decompressed-size limits.
- Improved artifact ranking and deterministic preferred-candidate selection.

## 1.0.0 (2026-07-25)

First release!

## Migrating from 2.x to 3.0

### Crate root

- `fletch::registry`, `try_registry` → `fletch::registry::lookup` (returns
  `Result<Registry, RegistryError>`).
- `fletch::registry_with_sources`, `try_registry_with_sources` →
  `fletch::registry::lookup_recorded`.
- `fletch::url_to_purl` → `fletch::purl::url_to_purl`.
- `registry::parse_purl` → `purl::Purl::parse`.

### purl

- `Purl::canonical()` → `to_string()` (`Display`).
- `release_identity`, `release_identity_at`, `artifact_identity` →
  `Purl::identity`, `Purl::release`, `Purl::artifact`.
- `PurlComponents`, `Purl::from_components` → `Purl::build`.
- `Purl::namespace_string` → `namespace().join("/")`.
- `PurlError::{Syntax, Type}` now carry a reason.
- `pkg:homebrew/…` normalizes to `pkg:brew/…`; identities keep more qualifiers,
  so lookup keys built by 2.x for such PURLs change.

### find

- `references`, `references_in_bytes`, `references_from_facts` return
  `Discovery { references, unresolved, truncated }`.
- `fetch_calls`, `discover_fetch_calls`, `discover_batch_programs` →
  `references_from_facts(file_type, values, symbols, declared)`, where
  `values` is a `&filefacts::Values`, not its `as_json()` tree: pass
  `parsed.values()`, or rebuild retained JSON with
  `filefacts::Values::from(json)`. Requires a filefacts with
  `filefacts::values`.
- `file_type: &str` parameters take `filefacts::FileType`.

### fetch

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

### cache_sweep

- `Root` and the `*_from_env` helpers removed; `Budget` is opaque.
  `cleanup`, `refs_budget`, `spawn`, `spawn_periodic` are unchanged.

### CLI

- Exit codes `0`/`1`/`2`, `--help`, `--version`, `FLETCH_LOG`; an oversized
  source carries `truncated: true`; the CLI no longer sweeps the cache.
