# fletch

**fletch** finds and fetches the external references hiding in a file — the
packages it installs, the URLs it reaches for, the images it pulls — and
retrieves each one safely enough to hand back to an analyzer.

It is the companion to
[filefacts](https://github.com/atomdrift-project/filefacts). filefacts owns
*parsing* and the dependencies a manifest *declares*. fletch owns the rest: the
fuzzy discovery of the **undeclared, imperative** references — a `curl … | sh`,
an `npm install` inside a `RUN`, a URL stashed in a shell variable — and the
**retrieval** of every reference, declared or not. The loop a consumer (cleave,
scan) composes is: analyze a file → *find* its references → *fetch* them →
analyze what came back. fletch never analyzes; it finds and fetches.

## How it works

Three modules, deliberately walled apart so the dangerous half stays auditable:

- **`find`** — recognition over filefacts facts. Returns filefacts' declared
  dependencies *plus* the imperative ones hunted out of command streams, decoded
  text, byte-scan strings, and AST module-load calls. Heuristic by nature, so it
  lives away from the deterministic parsers and the fetch boundary.
- **`fetch`** — resolve a reference to a URL, retrieve it through an
  SSRF-guarded HTTP client, cache it, verify any pin, and record provenance.
  Pure mechanism; no recognition logic ever leaks in.
- **`registry`** — look up and normalize a package's *registry metadata*
  (publish date, author, download counts, rating, removal/hold status) across ecosystems
  into one shape, so a consumer can judge a dependency before paying to fetch and
  scan its bytes.

## Safety

Retrieval is the dangerous part, so it is the narrow, guarded one:

- **SSRF-guarded by construction.** A custom DNS resolver refuses any host that
  resolves to a private, loopback, link-local, or cloud-metadata address —
  re-checked on **every redirect hop**, not just the first.
- **Pins are verified.** A reference that carries a hash is checked against the
  bytes retrieved; immutable/pinned artifacts are cached long, mutable
  `@latest` tags briefly, so a cache hit is never a stale-but-wrong hit.
- **Provenance is recorded.** Every fetch keeps the raw provider document(s) it
  was derived from, so a normalized record can be archived and re-parsed later
  without a re-fetch.

## Ecosystems

Package registries: npm, PyPI, crates.io, RubyGems, NuGet, Maven, Go, Composer,
plus Firefox and VS Code extension marketplaces. OS distros with a compressed
index (Alpine, Wolfi, Debian, Ubuntu, openSUSE, RPM Fusion). OCI container
images, pulled and flattened to a single rootfs tarball.

## CLI

The binary is a thin companion to the library, so a non-Rust collector can obtain
exactly the record a consumer reasons over instead of maintaining a parallel,
drifting fetcher.

```bash
fletch registry pkg:npm/left-pad@1.3.0   # resolve + fetch + normalize registry metadata
fletch purl pkg:pypi/requests@2.31.0      # report how the PURL routes — no network I/O
fletch purl -                             # same, batched: one PURL per stdin line
```

`registry` prints a `{record, sources}` JSON envelope: the normalized record
alongside the raw provider responses it came from. It exits `2` (empty stdout)
when the ecosystem is unsupported or the registry is unreachable, so a caller can
tell "no record" from a usage error (exit `1`). `purl` performs no network I/O —
it reports the parsed coordinates, canonical spelling, registry endpoint, and
resolved artifact URL, and is the cross-tool consistency surface that keeps
sibling tools from silently drifting apart.

## Library

```rust
let refs = fletch::find::references_in_bytes(&bytes, "Dockerfile");
let record = fletch::registry(&purl)?;   // normalized registry metadata
```

Add it as a git dependency (the same pin consumers use):

```toml
fletch = { git = "https://github.com/atomdrift-project/fletch.git" }
```

### PURL identity and artifacts

`purl::Purl` is the validated representation used at the fetch boundary.
`Purl::parse` follows Postel's law for safe, common legacy spellings and emits
one canonical PURL; `Purl::parse_strict` implements the purl-spec parse contract
without compatibility repairs. Three identities are intentionally distinct:

- `purl::identity` is the broad, backward-compatible package lookup key.
- `purl::release_identity` retains qualifiers that distinguish a release.
- `ArtifactCandidate::artifact_purl` identifies one exact file, including its
  selectors and registry-published checksums.

Use `fetch::resolve_artifacts` when a release can publish more than one file.
Its `ArtifactMatrix` enumerates filenames, URLs, checksums, platform/ABI tags,
and runtime constraints. `ArtifactMatrix::select` applies an explicit
`ArtifactTarget` and `SelectionPolicy`; the older single-URL fetch API keeps a
deterministic best-effort choice for compatibility.

PURL-to-URL-to-PURL is tested bidirectionally for registries whose artifact URL
contains enough information to recover the coordinate. PyPI content-hash paths,
mutable tags, and other lossy URL schemes are tested through registry-backed
exact artifact identities instead; they are not falsely presented as bijective.

## Caching

Fetched blobs are cached on disk and reclaimed in the background — best-effort,
self-gated to once a day, non-blocking. Entries past a TTL or beyond the size
ceiling (10 GiB default) are swept oldest-first. Any process that links fletch
can perform the reclamation.

| Variable | Default | Effect |
|---|---|---|
| `FLETCH_CACHE_TTL_DAYS` | `30` | Age after which cached blobs are dropped |
| `FLETCH_CACHE_MAX_BYTES` | `10737418240` | Size ceiling before oldest entries are dropped |

## Build

```bash
make release        # release binary in target/release/fletch
make test           # run the test suite
make test-purl-spec PURL_SPEC_DIR=../purl-spec
```

Requires Rust 1.94+.

---

Source and issues live on
[GitHub](https://github.com/atomdrift-project/fletch). Apache 2.0.
