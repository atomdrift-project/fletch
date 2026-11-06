# Test data

## `purl-spec/`

The package-url specification's test vectors, vendored from
[package-url/purl-spec](https://github.com/package-url/purl-spec) at commit
`7cd2d3442fb9c88155db17ada7c911b40ec22d41` (MIT, see `purl-spec/LICENSE`).
`tests/purl_spec.rs` runs them; CI also checks them out at that commit. Move
both together.

## Package archives

Minimal, hand-built archives in each registry's download format, so tests can
check that fetched bytes are identified by their content rather than by URL or
file name. Every member has owner 0 and the epoch as its time, so the bytes are
reproducible.

| File | Format | Contents |
|---|---|---|
| `package-types/crate.tar.gz` | crates.io `.crate` | `demo-1.2.3/{Cargo.toml,src/lib.rs}` |
| `package-types/pub.tar.gz` | pub.dev archive | `pubspec.yaml`, `lib/demo.dart` |
| `package-types/cran.tar.gz` | CRAN source package | `demo/{DESCRIPTION,R/demo.R}` |
| `package-types/cpan.tar.gz` | CPAN distribution | `Demo-1.2.3/{META.json,lib/Demo.pm}` |
| `package-types/hackage.tar.gz` | Hackage sdist | `demo-1.2.3/{demo.cabal,src/Demo.hs}` |
| `package-types/hex.tar` | Hex package (outer tar) | `VERSION`, `CHECKSUM`, `metadata.config`, `contents.tar.gz` |
| `package-types/composer.zip` | Packagist dist zip | `demo-1.2.3/{composer.json,src/Demo.php}` |
| `go-module-stream.zip` | Go module proxy `.zip` | `example.com/hello@v1.2.3/{README.md,hello.go}` |

List one with `tar tvzf`, `tar tvf` or `unzip -l` to inspect it.
