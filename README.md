# fletch

**fletch** finds and fetches the external references hiding in a file — the
packages it installs, the URLs it reaches for, the images it pulls — and
retrieves each one safely enough to hand back to an analyzer.

It is the companion to
[filefacts](https://github.com/atomdrift-project/filefacts). filefacts owns
*parsing* and the dependencies a manifest *declares*. fletch owns the rest: the
fuzzy discovery of the **undeclared, imperative** references — a `curl … | sh`,
an `npm install` inside a `RUN`, a URL stashed in a shell variable — and the
**retrieval** of every reference, declared or not. The loop a consumer composes
is: analyze a file → *find* its references → *fetch* them → analyze what came
back. fletch never analyzes; it finds and fetches.

## How it works

Three modules, deliberately walled apart so the dangerous half stays auditable:

- **`find`** — recognition over filefacts facts. Returns filefacts' declared
  dependencies *plus* the imperative ones hunted out of command streams, decoded
  text, byte-scan strings, and AST module-load calls, along with the calls it
  saw but could not resolve. Heuristic by nature, so it lives away from the
  deterministic parsers and the fetch boundary.
- **`fetch`** — resolve a reference to a URL through one per-ecosystem table,
  retrieve it through an SSRF-guarded HTTP client, cache it, verify any pin,
  and record provenance. Pure mechanism; no recognition logic leaks in.
- **`registry`** — look up and normalize a package's *registry metadata*
  (publish date, author, download counts, rating, removal and hold status)
  across ecosystems into one shape, so a consumer can judge a dependency before
  paying to fetch and scan its bytes.

## Safety

Every input — the scanned file, registry responses, archives, container
layers — is treated as hostile.

- **SSRF-guarded by construction.** A custom DNS resolver refuses any host that
  resolves to a private, loopback, link-local, or cloud-metadata address (IPv6
  must be global unicast), re-checked on **every redirect hop**, and connects
  only to the addresses it vetted, so DNS rebinding has nothing to swap. HTTPS
  only, never through an environment proxy, and never to a port browsers refuse
  (SMTP, SSH, IRC, …). Container pulls go through the same client.
- **Bounded.** Every response is size-capped (a request may lower the
  operator's ceiling, never raise it), every request and every batch has a
  deadline, and a batch's registry metadata traffic counts against its budget
  alongside the artifacts. Container layers are spooled to disk and streamed,
  never held in memory whole.
- **Pins are verified.** A reference that carries a hash (hex or SRI base64) is
  checked against the bytes retrieved; a mismatch is always reported as one.
  Immutable artifacts are cached long, mutable `@latest` tags briefly.
- **One registry per record.** A `repository_url` that does not name the
  type's public registry is refused for metadata, and the same policy decides
  where the bytes come from, so a record never pairs one registry's bytes with
  another's reputation.
- **Provenance is recorded.** Every lookup keeps the raw provider document(s) it
  was derived from, so a normalized record can be archived and re-parsed later
  without a re-fetch.

See [SECURITY.md](SECURITY.md) for reporting and known limitations.

## Ecosystems

- **Language registries:** npm, JSR, PyPI, Conda, crates.io, RubyGems, Go,
  Maven, Clojars, NuGet, Composer, Hex, pub.dev, CRAN, CPAN, Terraform.
- **Distributions:** Debian, Ubuntu, Fedora, openSUSE, RPM Fusion, Alpine,
  Wolfi, Arch Linux and the AUR, FreeBSD, NetBSD, OpenBSD, Homebrew, Snap.
- **Extension and plugin stores:** VS Code Marketplace, Open VSX, Firefox
  add-ons, Chrome Web Store, JetBrains Marketplace, WordPress, ComfyUI, Dify,
  ClawHub, Hugging Face.
- **Sources and images:** GitHub repositories; OCI container images (Docker Hub
  and Quay), pulled and flattened to a single rootfs tarball.

## CLI

The binary is a thin companion to the library, so a non-Rust collector can obtain
exactly the record the library produces instead of maintaining a parallel,
drifting fetcher.

```bash
fletch registry pkg:npm/left-pad@1.3.0   # resolve + fetch + normalize registry metadata
fletch purl pkg:pypi/requests@2.31.0      # report how the PURL routes — no network I/O
fletch purl -                             # same, batched: one PURL per stdin line
FLETCH_LOG=debug fletch registry …        # diagnostics on stderr (default: warn)
```

`registry` prints a `{record, sources}` JSON envelope: the normalized record
alongside the raw provider responses it came from (a response larger than the
source limit is named, with `truncated: true`, but not copied). Exit status is
`0` on success, `1` for a usage or I/O error, and `2` (empty stdout, the reason
on stderr) when the argument is not a PURL or the registry has no record. `purl`
performs no network I/O — it reports the parsed coordinates, canonical
spelling, registry endpoint, and resolved artifact URL.

## Library

```rust
use fletch::fetch::{BlobCache, HttpFetch};
use fletch::{RefLocator, registry};

let refs = fletch::find::references_in_bytes(&bytes, "Dockerfile").references;
let net = HttpFetch::new()?;
let record = registry::lookup(&RefLocator::Purl(purl), &net, &BlobCache::open()?)?;
```

Add it as a git dependency:

```toml
fletch = { git = "https://github.com/atomdrift-project/fletch.git" }
```

The offline `fetch::Fixtures` backend is behind the `test-util` feature, for a
dependent's tests.

### PURL identity and artifacts

`purl::Purl` is the validated representation used at the fetch boundary; its
`Display` form is the one canonical spelling. `Purl::parse` follows Postel's
law for safe, common legacy spellings; `Purl::parse_strict` implements the
purl-spec parse contract without compatibility repairs. Three identities are
intentionally distinct:

- `Purl::identity` — the package lookup key: subpath and the qualifiers that
  only select an artifact dropped, everything that distinguishes a release
  (a conda `channel`, an rpm `epoch`, a `repository_url`) kept.
- `Purl::release` — the identity of one release at a given version.
- `Purl::artifact` — one exact file: the release plus its selectors and
  registry-published checksums.

`purl::normalize`, `purl::identity` and `purl::url_to_purl` are the string forms
of these for cross-language consumers.

Use `fetch::resolve_artifacts` when a release can publish more than one file.
Its `ArtifactMatrix` enumerates filenames, URLs, checksums, platform/ABI tags,
and runtime constraints, with the candidate a fetch would choose marked
`preferred`.

PURL-to-URL-to-PURL is tested bidirectionally for registries whose artifact URL
contains enough information to recover the coordinate. PyPI content-hash paths,
mutable tags, and other lossy URL schemes are tested through registry-backed
exact artifact identities instead; they are not falsely presented as bijective.

## Caching

Fetched blobs are cached on disk and reclaimed in the background — best-effort,
self-gated to once a day, non-blocking. Entries past a TTL or beyond the size
ceiling (10 GiB default) are swept oldest-first.

On Unix the cache is readable by the owning user alone: fletch refuses to read,
write or sweep a cache directory (or shard) owned by another user or writable by
group or others, and tightens one it owns. On Windows the cache relies on the
per-user OS cache directory's ACL.

| Variable | Default | Effect |
|---|---|---|
| `FLETCH_CACHE_TTL_DAYS` | `30` | Age after which cached blobs are dropped |
| `FLETCH_CACHE_MAX_BYTES` | `10737418240` | Size ceiling before oldest entries are dropped |
| `FLETCH_CACHE_MAX_ENTRIES` | `262144` | Entry ceiling (a blob and its metadata count once), spread over 256 shard directories |

These are read once per process.

## Registry etiquette

`fletch registry` sends `GITHUB_TOKEN`, when set, to the GitHub API, lifting its
anonymous limit of 60 requests an hour; library callers pass a token with
`HttpFetch::with_github_token`. It is attached only to repository documents
fletch addresses itself (`https://api.github.com/repos/{owner}/{repo}`), never
to a URL a scanned file or a registry response named, and never again once a
redirect chain leaves that origin. A private repository's metadata is never
reported. Prefer a token without private-repository scope; it exists for the
rate limit.

A registry that answers `429`, sends `Retry-After`, or reports its rate limit
exhausted is waited out for up to 30 s; a longer pause fails the request, and
every request to that host until it ends, without asking the host again. A
transient `408` or `5xx` is retried for that request alone.

## Metrics

Each fetch, registry lookup, metadata read, and registry back-off emits one
`tracing` event on the `fletch::metrics` target, with stable field names
(`event`, `ecosystem`, `outcome`, `served`, `status`, `bytes`, `elapsed_ms`, …)
and bounded label values, so a subscriber can count cache hit rates, outcomes by
ecosystem, throttling, and latency. The fields are listed in `src/metrics.rs`.

## Build

```bash
make release        # release binary in target/release/fletch
make test           # run the test suite
make lint           # rustfmt + clippy, warnings denied
make test-purl-spec PURL_SPEC_DIR=../purl-spec
```

Requires Rust 1.97 or later. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

Source and issues live on
[GitHub](https://github.com/atomdrift-project/fletch). Apache 2.0.
