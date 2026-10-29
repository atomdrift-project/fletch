# Contributing

Thanks for helping. fletch is small on purpose; changes that keep it simple,
bounded, and auditable are the easiest to accept.

## Build and test

```bash
make build      # debug build
make test       # all tests (hermetic: no network)
make lint       # rustfmt check + clippy with warnings denied
make install-precommit   # run lint + test before every commit
```

The minimum supported Rust version is set by `rust-version` in `Cargo.toml`.
Network-bound smoke tests are `#[ignore]`d; run them with
`cargo test --test distro_live -- --ignored`.

## Ground rules

- Every input is hostile. Bound every read, loop, and allocation that a scanned
  file or a registry response can influence, and add a test that proves it.
- No `unwrap`, `expect`, or `panic!` outside tests; return a `Result`.
- Prefer enums and small structs to strings for anything with a fixed
  vocabulary (file types, ecosystems, outcomes).
- Log decisions that change an outcome with structured `tracing` fields. Never
  log credentials.
- A bug fix comes with a test that fails without it. Do not adjust an existing
  expectation to make a change pass unless that expectation was the bug.
- Comments describe what the code does and why; history belongs in commits.

## Adding an ecosystem

Registry metadata adapters live in `src/ecosystem/`, one file per registry,
using the shared helpers in `src/ecosystem/mod.rs` (timestamps, timelines,
coordinates). Route the PURL type in `src/registry.rs`, add artifact resolution
in `src/fetch/resolve.rs` if the registry serves downloadable artifacts, and
cover both with fixture tests.

## Reporting security issues

See [SECURITY.md](SECURITY.md).
