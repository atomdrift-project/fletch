# Changelog

All notable changes to fletch. Versions follow [semantic versioning](https://semver.org/spec/v2.0.0.html).

## 3.0.0-beta.1 (unreleased)

### Security

- Match repository URLs by parsed host, so a URL merely containing aur.archlinux.org can't borrow AUR reputation.
- Deny registry lookups whose repository URL names anything but the type's public registry.
- Stop reading OCI layer entries past the tar end marker, as containerd does.
- Place each flattened OCI entry where an overlay runtime installs it: through its own layer's symlinks (`a -> /etc`, then `a/passwd` lands at `etc/passwd`), but never through a lower layer's, so no layer's bytes are hidden from the scan.
- Never re-attach the GitHub token after a redirect leaves its origin, and cache authenticated responses separately.
- Never report private-repository metadata fetched with the GitHub token.
- Refuse cache shards owned by another user or writable by group or others.
- Verify the sha512 checksum on openSUSE's `primary.xml` instead of skipping it.
- Charge every body byte received to a batch's byte budget, including bodies abandoned as too large or timed out.
- Cap a container image's entry count and name bytes, which the flatten holds in memory.
- Drop a flattened hard link whose target was not written, such as one beneath a symlink.
- Never mask a 404, 410, refusal or oversize body with a stale cached artifact; only transient failures fall back.
- Follow NuGet registration pages only on NuGet's own registration path, at most 64 of them.
- Keep signed query strings out of transport error messages.
- Count only distinct references against a file's reference cap, so repeated filler cannot hide later references.
- Bound the text JavaScript resolution builds per file, so a crafted file cannot take seconds per kilobyte.
- Find installs behind any number of options, such as `pip --no-cache-dir -q install`.
- Report the target of an npm alias (`foo@npm:evil`), not its local name.
- Treat echoed or printed commands as text in source code, as in shell scripts.
- Only report `http` and `https` URLs from dynamic `require` and `import` calls.
- Require https for a PURL's `download_url`, as for every registry-named URL.
- Refuse OCI layer entries that tar-rs and Go's `archive/tar` read differently: a body on a header-only entry, an extension header without a ustar magic, PAX sparse files, and a ustar prefix read two ways. Treat old-style directories as Go does.
- Trust a cache root only when every directory and symlink on the path to it belongs to this user or root, so another local user cannot redirect the cache, its chmod, or its sweep into the victim's own directories.
- Check a cache root's trust before the sweep reads its marker, accept only hex cache keys, treat entries dated in the future as stale, and checksum blobs so damage reads as a miss.
- Count a Go module zip's central-directory entries before the zip reader loads them, so a hostile zip cannot use a gigabyte of memory.
- Hold back-off per origin and credential, so anonymous rate limiting or a forged plain-http answer cannot stall authenticated or https requests to the same host.
- Escape and bound peer-chosen error text and attacker-supplied URLs in logs and records, and escape diagnostics the CLI prints.
- Accept a `repository_url` as the public registry only at its root or documented index path, with no userinfo, port, query or fragment, so `https://registry.npmjs.org/@evil` cannot borrow another package's record.
- Match a PyPI version by PEP 440 equality, so `1.0.0` cannot hide a yank of the listed `1.0`.
- Encode gem versions and npm dist-tags as a single URL path segment.
- Query npm's malware advisories by the decoded package name.
- Keep artifact `file_name`s to a single path component, whether derived from the URL or named by PyPI.
- Resolve JavaScript names in one linear pass at any nesting depth; 257 nested braces used to switch off the recognizer, and deep scopes cost quadratic time.
- Bound `.set()` chains and repeated npm hook URLs to linear time.
- Reject scraped dates with years past 9999 instead of overflowing.
- Read a whole `GLib.file_set_contents` stylesheet body; bodies over 16 KB were skipped, so padding could hide a leading `@import`.

### Features

- Fetch URLs a scanned file names verbatim over plain HTTP too; address, port and resolver guards still apply.
- Set `security_hold` on npm versions carrying a malware advisory, even when npm deleted only that version.
- Report registry favorites: GitHub stars, Hugging Face likes, Docker Hub stars and Packagist favers.
- Find Ruby process-call downloaders such as `Kernel.exec` running curl.
- Find mshta and rundll32 remote-program targets in batch scripts.
- Find browser PAC URLs and remote CSS imported by GNOME extension stylesheets.
- Find PyPI candidates from Python imports and curl or wget targets in retained archive facts.
- Add Wolfi and RPM Fusion as distro registries.
- Record per-reference coverage facts stating what was left unexamined, and why.
- Give the CLI exit codes, help, version and a log level through `FLETCH_LOG`.
- Keep file capabilities and other extended attributes, and long owner names, in flattened container images.
- Add `BlobCache::load_with`, which streams a cached entry instead of reading it whole.
- Order `Purl` values, so they can key a `BTreeMap` or `BTreeSet`.
- Report release timelines for Hex, pub.dev, CRAN, Conda and Composer, and the latest version for nine more registries.
- Breaking: build the `fletch` binary only with the `cli` feature, so library users never compile its dependencies.
- Breaking: give `PurlError` typed `SyntaxError` and `TypeError` reasons instead of message strings.
- Breaking: make `RawSink` an opaque handle read with `take`.
- Breaking: name container records by their full repository, such as `docker.io/library/nginx`.
- Breaking: replace the registry functions with `registry::lookup`, returning a typed error.
- Breaking: rebuild PURL identity around `Purl::identity`, release and artifact; homebrew PURLs normalize to brew.
- Breaking: return a `Discovery` of references, unresolved calls and truncation from every finder.
- Breaking: merge the reference fetchers into one `fetch_references` with per-fetch request and deadline budgets.
- Breaking: take a `filefacts::FileType` instead of a string wherever a file type is passed.
- Breaking: remove the pin-verified flag; a mismatched pin is reported as `Outcome::PinMismatch`.
- Breaking: change lookup keys for PURLs whose identities now keep release-distinguishing qualifiers.

### Fixes

- Let downloads run past 30 seconds; the per-send timeout was also capping the whole body, so large artifacts and container layers failed as transient errors.
- Verify SRI sha256 pins, which were always reported as mismatches.
- Stop overwriting pin mismatches, 404s and unresolved references as `BudgetExceeded` when the budget runs out.
- Set version removal on yanks, unlists and retractions across Cargo, PyPI, NuGet and six other registries.
- Never silently replace a requested version with the latest release.
- Keep qualifiers such as conda channel and rpm epoch in PURL identities.
- Stop reading option values as package names, as in `conda -c conda-forge`.
- Report an unreachable registry as a retryable failure, not a missing release.
- Retry a transient 5xx per request instead of holding the whole host.
- Preserve ecosystem types for fetched CRAN, crate, Hackage, Hex and pub source packages.
- Make four find inputs linear that took quadratic time, including backslash runs and nested exec calls.
- Report the requested version, undated, for Arch, AUR and Fedora lookups instead of the current build's.
- Report `version_removed` as unknown for an npm version the registry does not list, and Firefox and Homebrew disabling as deprecation.
- Validate a PURL the same way when downloading as when looking it up, for Firefox, ComfyUI, Terraform, Dify and Composer.
- Refuse a coordinate shape a registry does not use as `UnsafeCoordinate` everywhere, including JSR and CPAN.
- Hold metadata reads outside a registry lookup to the one-hour unpinned TTL and honour `with_registry_ttl` for them.
- Cache artifacts pinned by a PURL checksum for the pinned TTL, and refetch a cached copy that fails its pin.
- Accept qualifier keys that start with `.`, `-` or `_`, as the spec allows.
- Decode numeric character references in openSUSE summaries and Chrome and WordPress text.
- Leave in-progress spools to the cache sweep's age pass, so a size sweep never fails a fetch in flight.
- Saturate Homebrew and Quay download totals instead of overflowing.
- Keep apt epochs in versions, and drop range, tag and wildcard versions from npm, pip and distro tokens.
- Carry a Dockerfile stage's distro to a later `FROM <stage>`.
- Stop reporting curl and wget targets from comments and printed text in shell scripts.
- Skip the values of `git clone` options such as `-b main`, which were read as the repository.

### Optimizations

- Spool container layers to disk and stream them instead of holding them in memory.
- Sweep the cache about daily, or sooner once a process writes a tenth of its budget.
- Skip reading and re-hashing a cached copy after a definite failure (404, 410, a refusal), since it is never served in place of one.
- Reuse a parsed distro index without reading it back while the cache still holds the same bytes, known from a digest the cache now records beside each document: a repeat Debian lookup drops from 15 ms to 0.13 ms and no longer allocates the 13 MB index.
- Store cache entries that are already gzip, bzip2, zip or checked xz (archives, wheels, container exports) as they came instead of zstd-compressing them again: no size gain was lost, and each GB costs about 5 s less to store and 3 s less to load. Their own checksums catch damage. The sidecar's new `raw` flag marks them; older entries read as before, and an older fletch reading a raw entry misses and refetches it.
- Compress container exports at xz preset 1 instead of 6: about 9x faster on a real rootfs, in a tenth of the memory, for output about a fifth larger.
- Read each JavaScript AST node's kind once and reuse one tree cursor across the walk, cutting reference finding by about 15%.
- Drop the `hex` and `anyhow` dependencies; a lowercase-hex helper and a boxed CLI error replace them.
- Hold parsed distro indices in the `BlobCache` instead of a process-wide map, and remember a failed parse until the index changes.

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
