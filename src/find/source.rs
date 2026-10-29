//! Source code: dynamic imports, and the commands that process-execution and
//! package-installer calls run. Only real call nodes count, so a comment,
//! documentation string or unrelated string never becomes a command.

use std::cmp::Reverse;
use std::collections::HashMap;
use std::ops::Range;

use filefacts::tree_sitter::Node;
use filefacts::{Arg, FileType, ParsedFile, RefKind, RefLocator, Reference, Symbol};

use super::Lang;
use super::builtins::{is_host_provided, is_node_builtin, is_python_stdlib};
use super::found::{Found, dedup};
use super::purl_token::{Eco, npm_purl_token, pypi_purl_token};
use super::shell::{Place, commands};
use super::urls::{git_refs, urls};

/// AST nodes one walk may visit. The walk visits the file's end first, so a
/// budget small enough for padding to exhaust would hide the calls and
/// imports above it.
pub(super) const AST_NODE_BUDGET: usize = 8_000_000;

/// The longest callee text worth reading as a dotted name. A longer one is an
/// inline function or similar, never a recognized API, and compacting nested
/// ones would cost time quadratic in the nesting.
pub(super) const MAX_CALLEE_BYTES: usize = 256;

/// Process APIs whose arguments are a program and its argument vector
/// (`spawn('npm', ['install', 'x'])`) rather than one shell command.
pub(super) const ARGV_METHODS: &[&str] = &[
    "spawn",
    "spawnSync",
    "execFile",
    "execFileSync",
    "execa",
    "execaSync",
];

/// Node modules whose members run processes.
const JS_PROCESS_MODULES: &[&str] = &["child_process", "node:child_process", "shelljs", "execa"];

/// The process-running members of [`JS_PROCESS_MODULES`].
const JS_EXEC_METHODS: &[&str] = &[
    "exec",
    "execSync",
    "execFile",
    "execFileSync",
    "spawn",
    "spawnSync",
    "execa",
    "execaSync",
    "execCommand",
    "execCommandSync",
];

/// Process APIs called by bare name once imported.
const JS_BARE_EXEC: &[&str] = &["execa", "execaSync", "execCommand", "execCommandSync"];

/// The last segment of a dotted callee.
pub(super) fn method(callee: &str) -> &str {
    callee.rsplit('.').next().unwrap_or(callee)
}

/// A callee's source text without whitespace, as a dotted name.
pub(super) fn compact(callee: &str) -> String {
    callee.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Whether `callee` (resolved to the API it names) runs a process.
pub(super) fn execution_call(lang: Lang, callee: &str) -> bool {
    match lang {
        Lang::Python => {
            callee.strip_prefix("subprocess.").is_some_and(|m| {
                matches!(m, "run" | "call" | "check_call" | "check_output" | "Popen")
            }) || callee.strip_prefix("os.").is_some_and(|m| {
                matches!(m, "system" | "popen") || m.starts_with("exec") || m.starts_with("spawn")
            })
        }
        Lang::JavaScript => {
            let (module, method) = callee.rsplit_once('.').unwrap_or(("", callee));
            let module = required_module(module).unwrap_or(module);
            let known = JS_PROCESS_MODULES.contains(&module)
                || (module.is_empty() && JS_BARE_EXEC.contains(&method));
            known && JS_EXEC_METHODS.contains(&method)
        }
        Lang::Shell | Lang::Dockerfile | Lang::PowerShell => false,
    }
}

/// The module a `require('m')` expression loads.
fn required_module(expression: &str) -> Option<&str> {
    let quoted = expression.strip_prefix("require(")?.strip_suffix(')')?;
    ['\'', '"']
        .iter()
        .find_map(|&q| quoted.strip_prefix(q)?.strip_suffix(q))
}

/// Whether `callee` is a package manager's programmatic install API.
fn installation_call(lang: Lang, callee: &str) -> bool {
    match lang {
        Lang::Python => matches!(callee, "pip.main" | "pip._internal.main"),
        Lang::JavaScript => matches!(
            callee,
            "npm.install" | "npm().install" | "bun.add" | "yarn.add" | "pnpm.add"
        ),
        Lang::Shell | Lang::Dockerfile | Lang::PowerShell => false,
    }
}

/// The source text of a process or installer call that carries its command:
/// the call from its start through its command arguments.
#[derive(Debug)]
pub(super) struct CallSpan {
    start: usize,
    end: usize,
    /// For an installer, its resolved callee and where its arguments start:
    /// the callee is the command (`pip.main` → `pip main`), taken from its
    /// resolved name since the source text may be an alias.
    installer: Option<(String, usize)>,
}

/// The [`CallSpan`] of a call to `callee`, or `None` when the call runs no
/// command. Only the executable and argv arguments belong to a process
/// command: environment, cwd, callbacks and later source text must not
/// become packages.
pub(super) fn call_span(
    lang: Lang,
    callee: &str,
    node: Node<'_>,
    arguments: Node<'_>,
) -> Option<CallSpan> {
    let process = execution_call(lang, callee);
    let installer = installation_call(lang, callee);
    if !process && !installer {
        return None;
    }
    let count = if process && ARGV_METHODS.contains(&method(callee)) {
        2
    } else {
        1
    };
    let mut cursor = arguments.walk();
    let end = arguments
        .named_children(&mut cursor)
        .filter(|a| a.kind() != "comment")
        .take(count)
        .last()?
        .end_byte();
    Some(CallSpan {
        start: node.start_byte(),
        end,
        installer: installer.then(|| (callee.to_owned(), arguments.start_byte())),
    })
}

/// Recognize the commands in each call span. A span nested in another (a
/// call in an outer call's arguments) is read as part of the outer one, so
/// every byte of the file is normalized at most once, however deep the
/// nesting.
pub(super) fn run_spans(
    text: &str,
    mut spans: Vec<CallSpan>,
    mut comments: Vec<Range<usize>>,
    lang: Lang,
    out: &mut Found<'_>,
) {
    spans.sort_by_key(|span| (span.start, Reverse(span.end)));
    comments.sort_by_key(|range| range.start);
    let mut covered = 0;
    for span in spans {
        if span.start < covered {
            continue;
        }
        covered = span.end;
        let Some(source) = text.get(span.start..span.end) else {
            continue;
        };
        let mut masked = source.as_bytes().to_vec();
        let first = comments.partition_point(|range| range.end <= span.start);
        for range in comments[first..]
            .iter()
            .take_while(|range| range.start < span.end)
        {
            let start = range.start.saturating_sub(span.start);
            let end = (range.end - span.start).min(masked.len());
            masked[start..end].fill(b' ');
        }
        let Ok(masked) = String::from_utf8(masked) else {
            continue;
        };
        let (normalized, remap) = match span.installer {
            Some((callee, arguments)) => {
                let arguments = arguments - span.start;
                let (text, remap) = normalize_call(&masked[arguments..], span.start + arguments);
                let prefix = format!("{} ", callee.replace(['.', '(', ')'], " "));
                let mut shifted = vec![(0, span.start)];
                shifted.extend(
                    remap
                        .into_iter()
                        .map(|(copy, file)| (copy + prefix.len(), file)),
                );
                (prefix + &text, shifted)
            }
            None => normalize_call(&masked, span.start),
        };
        commands(&normalized, Place::Mapped(&remap), lang, lang.label(), out);
    }
}

/// Normalize a call's source text into command text, with the byte map back
/// to the file that [`Place::Mapped`] reads.
///
/// Only string literals are command text, their escapes decoded: a
/// `'npm i a\nnpm i b'` runs two commands. An unquoted word is code — a
/// variable, a keyword argument, the callee — and is marked as a variable
/// (`$name`), which no package token accepts: `["pip", "install", pip_name]`
/// installs whatever `pip_name` holds, not a package called `pip_name`.
fn normalize_call(text: &str, base: usize) -> (String, Vec<(usize, usize)>) {
    let mut normalized = String::with_capacity(text.len());
    let mut remap = vec![(0, base)];
    let mut quote = None;
    let mut in_word = false;
    let mut at = 0;
    while let Some(c) = text[at..].chars().next() {
        if let Some(delimiter) = quote {
            in_word = false;
            if c == '\\' {
                let tail = &text[at..];
                let consumed = match continuation_len(tail) {
                    0 => match escape_at(tail) {
                        Some((decoded, consumed)) => {
                            normalized.push(decoded);
                            consumed
                        }
                        None => {
                            normalized.push('\\');
                            1
                        }
                    },
                    consumed => consumed,
                };
                at += consumed;
                remap.push((normalized.len(), base + at));
                continue;
            }
            if c == delimiter {
                normalized.push(' ');
                quote = None;
            } else {
                normalized.push(c);
            }
            at += c.len_utf8();
            continue;
        }
        let word = c.is_alphanumeric() || matches!(c, '_' | '$');
        if word && !in_word && (c.is_alphabetic() || c == '_') {
            normalized.push('$');
            remap.push((normalized.len(), base + at));
        }
        in_word = word;
        match c {
            '"' | '\'' | '`' => {
                normalized.push(' ');
                quote = Some(c);
            }
            '{' | '}' => {
                remap.push((normalized.len() + 1, base + at));
                normalized.extend([' ', c, ' ']);
                remap.push((normalized.len(), base + at + 1));
            }
            '.' | '(' | ')' | '[' | ']' | ',' | ':' | '\n' | '\r' | '\t' => normalized.push(' '),
            other => normalized.push(other),
        }
        at += c.len_utf8();
    }
    (normalized, remap)
}

/// The literal module specifier a load call's first argument spells, as
/// source text (escapes still encoded).
pub(super) fn import_argument<'t>(text: &'t str, arguments: Node<'_>) -> Option<&'t str> {
    let mut cursor = arguments.walk();
    let argument = arguments
        .named_children(&mut cursor)
        .find(|arg| arg.kind() != "comment")?;
    if !matches!(argument.kind(), "string" | "template_string") {
        return None;
    }
    literal_specifier(text.get(argument.byte_range())?)
}

/// The text inside a quoted string literal, when it is one plain word.
pub(super) fn literal_specifier(raw: &str) -> Option<&str> {
    let delimiter = raw.chars().next()?;
    if !matches!(delimiter, '\'' | '"' | '`') || raw.len() < 2 || !raw.ends_with(delimiter) {
        return None;
    }
    let value = &raw[1..raw.len() - 1];
    (!value.is_empty() && !value.contains(['$', ' ', '\n', '\t'])).then_some(value)
}

/// The [`Reference::source`] of a dynamic import in `eco`: a PyPI one is only
/// a candidate, since a Python module name does not establish which
/// distribution provides it.
pub(super) const fn import_source(eco: Eco) -> &'static str {
    match eco {
        Eco::Pypi => "ast-python-import-candidate",
        _ => "ast-call",
    }
}

/// Classify a dynamic-import specifier into a fetchable reference, or `None` for
/// a relative path or a language builtin (never an undeclared external dep).
///
/// The specifier arrives as the string literal's *source* text, so its escapes
/// are decoded first: a `require` whose argument spells every character as a
/// `\u00XX` escape still loads Node's `readline`, and only the decoded form can
/// be recognized as the builtin it is — or, for a real package, resolved to a
/// name a registry can serve.
pub(super) fn import_locator(eco: Eco, spec: &str) -> Option<(RefLocator, RefKind)> {
    let decoded = decode_escapes(spec);
    let spec = decoded.as_deref().unwrap_or(spec);
    if spec.contains("://") {
        return Some((RefLocator::Url(spec.to_owned()), RefKind::UrlFetch));
    }
    if spec.starts_with('.') || spec.starts_with('/') {
        return None;
    }
    let purl = match eco {
        Eco::Npm => {
            // `node:` names only builtins (some, like `node:test`, exist
            // nowhere else), never a registry package.
            if spec.starts_with("node:") {
                return None;
            }
            // Judge the package a specifier resolves to, not its text: the
            // builtin subpath `fs/promises` is still the builtin `fs`.
            let package = npm_import_package(spec)?;
            if is_node_builtin(&package) || is_host_provided(&package) {
                return None;
            }
            npm_purl_token(&package)?
        }
        Eco::Pypi => {
            let top = spec.split(['.', ':']).next()?;
            if top.is_empty() || is_python_stdlib(top) || !is_package_name(top) {
                return None;
            }
            pypi_purl_token(top)?
        }
        _ => return None,
    };
    Some((RefLocator::Purl(purl), RefKind::Command))
}

/// The installable package name from a JS import specifier: `@scope/name` from
/// `@scope/name/sub`, or `name` from `name/sub` (a deep import's subpath is not
/// part of the package identity). `None` when a segment is empty or is not a
/// plausible package name.
fn npm_import_package(spec: &str) -> Option<String> {
    if let Some(rest) = spec.strip_prefix('@') {
        let mut parts = rest.splitn(2, '/');
        let scope = parts.next()?;
        let name = parts.next()?.split('/').next()?;
        (is_package_name(scope) && is_package_name(name)).then(|| format!("@{scope}/{name}"))
    } else {
        let name = spec.split('/').next()?;
        is_package_name(name).then(|| name.to_owned())
    }
}

/// Whether a decoded specifier segment is a plausible registry package name —
/// non-empty ASCII letters, digits, `.`, `-`, or `_`. A specifier this module
/// could not fully decode (a leftover escape, a control byte, a concatenation
/// artifact) names no package any registry can serve, so it is dropped here
/// rather than emitted as a permanently unresolvable reference.
fn is_package_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// Decode the escape sequences in a string literal's source text — the `\u00XX`,
/// `\u{XX}`, `\xXX`, and legacy-octal forms — so an obfuscated module specifier
/// resolves to the module it actually loads. JS and Python spell these the same
/// way across the ASCII range a package name or URL lives in, so one decoder
/// serves both. `None` when there is no backslash and nothing to decode.
///
/// An escape that denotes no single character (a lone surrogate half, an
/// out-of-range code point) is left verbatim: the result is then not a
/// plausible package name, which is exactly the outcome such a specifier
/// deserves.
pub(super) fn decode_escapes(spec: &str) -> Option<String> {
    if !spec.contains('\\') {
        return None;
    }
    let mut out = String::with_capacity(spec.len());
    let mut rest = spec;
    while let Some(at) = rest.find('\\') {
        out.push_str(&rest[..at]);
        let tail = &rest[at..];
        let consumed = match continuation_len(tail) {
            0 => match escape_at(tail) {
                Some((c, consumed)) => {
                    out.push(c);
                    consumed
                }
                None => {
                    out.push('\\');
                    1
                }
            },
            consumed => consumed,
        };
        rest = &tail[consumed..];
    }
    out.push_str(rest);
    Some(out)
}

/// The length of a line continuation at the head of `src`: a backslash before
/// a line terminator, which both languages drop, so it must not split a
/// command in two. Zero when there is none.
fn continuation_len(src: &str) -> usize {
    let Some(rest) = src.strip_prefix('\\') else {
        return 0;
    };
    match rest.chars().next() {
        Some('\r') if rest[1..].starts_with('\n') => 3,
        Some(c @ ('\n' | '\r' | '\u{2028}' | '\u{2029}')) => 1 + c.len_utf8(),
        _ => 0,
    }
}

/// The character the escape sequence at the head of `src` denotes, and how many
/// bytes of `src` it spans. `None` when `src` does not begin with a decodable
/// escape.
fn escape_at(src: &str) -> Option<(char, usize)> {
    let rest = src.strip_prefix('\\')?;
    let c = rest.chars().next()?;
    match c {
        // Braced: variable width, at most six hex digits.
        'u' if rest[1..].starts_with('{') => {
            let close = rest[2..].bytes().take(7).position(|b| b == b'}')?;
            Some((code_point(&rest[2..2 + close])?, 4 + close))
        }
        'u' => Some((code_point(rest.get(1..5)?)?, 6)),
        'x' => Some((code_point(rest.get(1..3)?)?, 4)),
        // Legacy octal, `\0` through `\377`: a third digit belongs to the
        // escape only when the first is at most 3, so `\777` is `\77` then
        // `7`.
        '0'..='7' => {
            let max = if c <= '3' { 3 } else { 2 };
            let digits = rest
                .bytes()
                .take(max)
                .take_while(|b| (b'0'..=b'7').contains(b))
                .count();
            let value = rest.as_bytes()[..digits]
                .iter()
                .fold(0, |acc, b| acc * 8 + u32::from(b - b'0'));
            char::from_u32(value).map(|c| (c, 1 + digits))
        }
        // A control escape keeps its meaning; any other escaped char is itself
        // (`\/` is `/`), which is how both languages read it.
        'n' => Some(('\n', 2)),
        'r' => Some(('\r', 2)),
        't' => Some(('\t', 2)),
        'b' => Some(('\u{8}', 2)),
        'f' => Some(('\u{c}', 2)),
        'v' => Some(('\u{b}', 2)),
        c => Some((c, 1 + c.len_utf8())),
    }
}

/// The character a run of hex digits denotes, or `None` if the run is not hex
/// or is not a single Unicode scalar (a lone surrogate half, out of range).
fn code_point(hex: &str) -> Option<char> {
    if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    char::from_u32(u32::from_str_radix(hex, 16).ok()?)
}

/// Module-load calls recovered from a file's retained call symbols — the
/// facts-only path to the import vector, for an archive member whose bytes a
/// prior analysis discarded. A `require("pkg")` / `import("pkg")` (npm) or
/// `__import__("pkg")` / `importlib.import_module("pkg")` (PyPI) with a
/// string-literal specifier is emitted as the loaded package.
///
/// The load verb names an ecosystem only in its own language: Ruby spells a
/// library load `require "faraday"`, and reading that as npm would invent an
/// npm dependency for every Ruby `require`. Ruby's dependencies come from its
/// gemspec and `Gemfile.lock`, so a non-JS/TS `require` yields nothing here.
///
/// Diffing the result against the manifest's declared deps (see
/// [`undeclared_packages`](super::undeclared_packages)) surfaces a load of an
/// *undeclared* package even when no install command is visible. A computed
/// callee or non-literal argument yields nothing; relative paths and language
/// builtins are skipped.
#[must_use]
pub fn import_calls(file_type: FileType, symbols: &[Symbol]) -> Vec<Reference> {
    let mut refs = Vec::new();
    for sym in symbols {
        let Symbol::Call {
            target: Some(target),
            args,
            offset,
        } = sym
        else {
            continue;
        };
        let eco = match (file_type, target.as_str()) {
            (FileType::JavaScript | FileType::TypeScript, "require" | "import") => Eco::Npm,
            (FileType::Python, "__import__" | "import_module" | "importlib.import_module") => {
                Eco::Pypi
            }
            _ => continue,
        };
        let Some(Arg::String { value }) = args.first() else {
            continue;
        };
        if let Some((locator, kind)) = import_locator(eco, value) {
            let mut r = Reference::new(locator, kind, import_source(eco), value.as_str());
            r.offset = *offset;
            refs.push(r);
        }
    }
    refs
}

/// PyPI *candidates* from ordinary Python imports retained in source facts.
/// Import names do not establish distribution identity or an installed version.
/// Consumers must exclude supplied modules and verify a candidate's namespace
/// before treating its bytes as a potential provider. Relative and stdlib
/// imports never name external candidates here. Empty for any other file type.
#[must_use]
pub fn python_imports(file_type: FileType, symbols: &[Symbol]) -> Vec<Reference> {
    if file_type != FileType::Python {
        return Vec::new();
    }
    let mut refs = Vec::new();
    for symbol in symbols {
        let Symbol::Import {
            name,
            library,
            offset,
            ..
        } = symbol
        else {
            continue;
        };
        let module = library.as_deref().unwrap_or(name);
        if module.starts_with('.') || module.split('.').any(|part| !is_package_name(part)) {
            continue;
        }
        let Some((locator, kind)) = import_locator(Eco::Pypi, module) else {
            continue;
        };
        let mut reference = Reference::new(locator, kind, import_source(Eco::Pypi), module);
        reference.offset = *offset;
        refs.push(reference);
    }
    refs.sort_by_key(|r| r.offset.unwrap_or(u64::MAX));
    dedup(&mut refs);
    refs
}

/// Each imported local name and the canonical name it stands for, the first
/// import of a name winning. Built once per file, so resolving a call costs a
/// lookup rather than a pass over every symbol.
fn import_aliases(symbols: &[Symbol]) -> HashMap<&str, String> {
    let mut imports = HashMap::new();
    for symbol in symbols {
        if let Symbol::Import {
            name,
            alias,
            library,
            ..
        } = symbol
        {
            imports
                .entry(alias.as_deref().unwrap_or(name))
                .or_insert_with(|| match library {
                    Some(library) => format!("{library}.{name}"),
                    None => name.clone(),
                });
        }
    }
    imports
}

/// Python: dynamic imports, and the commands that `subprocess`, `os` and
/// `pip` calls run, with callees resolved through the file's import aliases
/// (`import subprocess as sp`).
pub(super) fn scan_python(parsed: &ParsedFile<'_>, out: &mut Found<'_>) {
    let lang = Lang::Python;
    let Some(ast) = parsed.source_ast() else {
        if let Some(text) = out.text {
            git_refs(text, lang.label(), out);
            urls(text, lang.label(), out);
        }
        return;
    };
    let text = ast.source;
    let aliases = import_aliases(parsed.symbols().as_slice());
    let mut stack = vec![ast.tree.root_node()];
    let mut visited = 0;
    let mut spans = Vec::new();
    let mut comments = Vec::new();
    while let Some(node) = stack.pop() {
        visited += 1;
        if visited > AST_NODE_BUDGET {
            out.cut_off(lang.label(), "AST node budget");
            break;
        }
        match node.kind() {
            "comment" => comments.push(node.byte_range()),
            "call" => {
                if let Some(span) = python_call(text, &aliases, node, out) {
                    spans.push(span);
                }
            }
            _ => {}
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    run_spans(text, spans, comments, lang, out);
    // The text scans read the file's own text, so each line is placed where
    // it sits rather than searched for.
    let text = out.text.unwrap_or(text);
    git_refs(text, lang.label(), out);
    urls(text, lang.label(), out);
}

/// Recognize one Python call: push a dynamic import it makes, and return its
/// span when it runs a command.
fn python_call(
    text: &str,
    aliases: &HashMap<&str, String>,
    node: Node<'_>,
    out: &mut Found<'_>,
) -> Option<CallSpan> {
    let function = node.child_by_field_name("function")?;
    let arguments = node.child_by_field_name("arguments")?;
    let raw = text
        .get(function.byte_range())
        .filter(|c| c.len() <= MAX_CALLEE_BYTES)?;
    let callee = compact(raw);
    let (head, tail) = callee.split_once('.').unwrap_or((&callee, ""));
    let callee = match aliases.get(head) {
        Some(canonical) if tail.is_empty() => canonical.clone(),
        Some(canonical) => format!("{canonical}.{tail}"),
        None => callee,
    };
    if matches!(
        callee.as_str(),
        "__import__" | "import_module" | "importlib.import_module"
    ) && let Some(spec) = import_argument(text, arguments)
        && let Some((locator, kind)) = import_locator(Eco::Pypi, spec)
    {
        out.push_at(
            locator,
            kind,
            import_source(Eco::Pypi),
            spec,
            Some(node.start_byte() as u64),
        );
    }
    call_span(Lang::Python, &callee, node, arguments)
}

#[cfg(test)]
mod tests {
    use super::super::references_in_bytes;
    use super::super::tests::{locators, purls};
    use super::*;

    fn require(m: &str) -> Symbol {
        Symbol::Call {
            target: Some("require".into()),
            args: vec![Arg::String { value: m.into() }],
            offset: Some(0),
        }
    }

    fn command_purls(text: &str, name: &str) -> Vec<String> {
        references_in_bytes(text.as_bytes(), name)
            .references
            .into_iter()
            .filter_map(|r| match r.locator {
                RefLocator::Purl(p) if r.kind == RefKind::Command => Some(p),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn python_static_imports_are_namespace_candidates_and_keep_owner_offsets() {
        let source = b"# import comment_only\nfrom scapy.tools.UTscapy import main as entry\nimport requests as client\nfrom .helpers import requests as helper\nfrom pathlib import Path\nimport __main__\n";
        let parsed = filefacts::OpenOptions::new()
            .path(std::path::Path::new("entry.py"))
            .open(source);
        let refs = python_imports(FileType::Python, parsed.symbols().as_slice());
        assert_eq!(locators(&refs), ["pkg:pypi/scapy", "pkg:pypi/requests"]);
        assert!(
            refs.iter()
                .all(|r| r.source == "ast-python-import-candidate" && r.kind == RefKind::Command)
        );
        assert_eq!(refs[0].evidence, "scapy.tools.UTscapy");
        assert_eq!(
            refs[0].offset,
            Some(std::str::from_utf8(source).unwrap().find("scapy").unwrap() as u64)
        );
        assert!(python_imports(FileType::JavaScript, parsed.symbols().as_slice()).is_empty());
        let root = references_in_bytes(source, "entry.py").references;
        let all = locators(&root);
        assert!(all.contains(&"pkg:pypi/scapy"));
        for absent in [
            "pkg:pypi/entry",
            "pkg:pypi/main",
            "pkg:pypi/helper",
            "pkg:pypi/comment_only",
            "pkg:pypi/pathlib",
            "pkg:pypi/__main__",
        ] {
            assert!(!all.contains(&absent), "{absent}: {all:?}");
        }
    }

    #[test]
    fn python_dynamic_imports_have_the_same_candidate_uncertainty() {
        let source = b"import importlib\nimportlib.import_module('scapy.tools.UTscapy')\n__import__('builtins')\n";
        let parsed = filefacts::OpenOptions::new()
            .path(std::path::Path::new("entry.py"))
            .open(source);
        let refs = import_calls(FileType::Python, parsed.symbols().as_slice());
        assert_eq!(locators(&refs), ["pkg:pypi/scapy"]);
        assert_eq!(refs[0].source, "ast-python-import-candidate");
    }

    #[test]
    fn require_vscode_and_builtins_are_not_npm_deps() {
        let syms = [
            require("vscode"),
            require("fs"),
            require("node:os"),
            require("lodash"),
        ];
        assert_eq!(
            locators(&import_calls(FileType::JavaScript, &syms)),
            ["pkg:npm/lodash"]
        );
    }

    #[test]
    fn escaped_require_specifiers_decode_before_classification() {
        // The literal's *source* text arrives with its escapes intact: a
        // spelled-out `readline` is Node's builtin and no reference at all,
        // while a real package resolves to its true name and a spelled-out
        // scheme to its URL.
        let syms = [
            require(r"\u0072\u0065\u0061\u0064\u006C\u0069\u006E\u0065"), // readline
            require(r"\x6c\x6f\x64\x61\x73\x68"),                         // lodash
            require(r"\u{40}acme/tool"),                                  // @acme/tool
            require(r"\146\163"),                                         // fs
            require(r"\u0068ttps://evil.test/s.js"),                      // a URL
            require(r"\u00zz"),                                           // undecodable
        ];
        assert_eq!(
            locators(&import_calls(FileType::JavaScript, &syms)),
            [
                "pkg:npm/lodash",
                "pkg:npm/%40acme/tool",
                "https://evil.test/s.js",
            ]
        );
    }

    #[test]
    fn import_calls_recovers_loads_from_symbols() {
        let js_symbols = vec![
            require("db-dx-connector"),
            require("node:fs"),
            // Computed callee (`npm().install`): no static target.
            Symbol::Call {
                target: None,
                args: vec![Arg::String {
                    value: "ignored".into(),
                }],
                offset: None,
            },
        ];
        assert_eq!(
            locators(&import_calls(FileType::JavaScript, &js_symbols)),
            ["pkg:npm/db-dx-connector"]
        );
        let py_symbols = vec![Symbol::Call {
            target: Some("importlib.import_module".into()),
            args: vec![Arg::String {
                value: "evil_telemetry".into(),
            }],
            offset: None,
        }];
        assert_eq!(
            locators(&import_calls(FileType::Python, &py_symbols)),
            ["pkg:pypi/evil_telemetry"]
        );
    }

    #[test]
    fn import_calls_ignores_ruby_require() {
        // Ruby's `require "name"` is the same call symbol as Node's, and
        // must not invent npm packages for Ruby stdlib or the gem's own name.
        let symbols = vec![require("faraday"), require("date")];
        assert!(import_calls(FileType::Ruby, &symbols).is_empty());
    }

    #[test]
    fn escapes_decode_once_with_javascript_octal_rules() {
        assert_eq!(decode_escapes(r"\777").as_deref(), Some("?7"));
        assert_eq!(decode_escapes(r"\377").as_deref(), Some("\u{ff}"));
        assert_eq!(
            decode_escapes(r"\101\x41\u0041\u{41}").as_deref(),
            Some("AAAA")
        );
        assert_eq!(
            decode_escapes(r"\u{1234567}").as_deref(),
            Some(r"\u{1234567}")
        );
        assert_eq!(decode_escapes(r"a\\b").as_deref(), Some(r"a\b"));
        assert_eq!(decode_escapes("plain"), None);
        assert_eq!(
            decode_escapes("npm install \\\nevil \\\r\nmore\\\u{2028}x").as_deref(),
            Some("npm install evil morex")
        );
    }

    #[test]
    fn recognizes_python_subprocess_pip_and_go_installs() {
        let purls = command_purls(
            "import subprocess\n\
            subprocess.run([\"pip\", \"install\", \"evil-pkg\", \"--quiet\"])\n\
            subprocess.run([\"go\", \"install\", \"github.com/evil/tool/cmd@v1.2.3\"])\n",
            "setup_helper.py",
        );
        assert_eq!(
            purls,
            [
                "pkg:pypi/evil-pkg",
                "pkg:golang/github.com/evil/tool/cmd@v1.2.3"
            ]
        );
    }

    #[test]
    fn ignores_go_install_in_python_prose() {
        let py = b"\"\"\"\nUse `go install github.com/evil/tool/cmd@v1.2.3` to install the example.\n\"\"\"\n";
        assert!(purls(py, "README_helper.py").is_empty());
    }

    #[test]
    fn recognizes_programmatic_pip_install_in_python() {
        let py = "import pip\n\
            pip.main([\"install\", \"evil-pkg\"])\n\
            pip._internal.main([\"install\", \"second-pkg\"])\n";
        let found = command_purls(py, "bootstrap.py");
        assert!(found.contains(&"pkg:pypi/evil-pkg".to_owned()), "{found:?}");
        assert!(
            found.contains(&"pkg:pypi/second-pkg".to_owned()),
            "{found:?}"
        );
    }

    #[test]
    fn builtin_subpaths_and_stdlib_modules_are_not_registry_packages() {
        let js = b"async function load(){\n\
            await import(\"fs/promises\");\n\
            await import(\"stream/web\");\n\
            await import(\"node:test\");\n\
            return import(\"left-pad/lib\");\n}\n";
        assert_eq!(purls(js, "loader.mjs"), ["pkg:npm/left-pad"]);

        let py = b"import importlib\n\
            importlib.import_module(\"csv\")\n\
            importlib.import_module(\"sqlite3\")\n\
            importlib.import_module(\"concurrent.futures\")\n\
            importlib.import_module(\"imp\")\n\
            importlib.import_module(\"requests\")\n";
        assert_eq!(purls(py, "plugin.py"), ["pkg:pypi/requests"]);
    }

    #[test]
    fn recognizes_python_importlib_dynamic_import() {
        let py = b"import importlib\n\
            mod = importlib.import_module(\"evil_telemetry\")\n\
            os_mod = __import__(\"os\")\n\
            sub = importlib.import_module(\"requests.adapters\")\n";
        let mut found = purls(py, "plugin.py");
        found.sort();
        assert_eq!(found, ["pkg:pypi/evil_telemetry", "pkg:pypi/requests"]);
    }

    #[test]
    fn prose_comments_and_examples_do_not_become_install_commands() {
        for (name, source) in [
            (
                "x.js",
                "// npm install executes Many\n/* npm install needed failed. */\nconst help = 'npm install lanceur auquel manque';",
            ),
            (
                "x.py",
                "# pip install needed failed\n\"\"\"pip install examples extra\"\"\"\nmessage = 'npm install executes Many'",
            ),
            (
                "x.ts",
                "const help: string = `npm install example`; // npm install another",
            ),
        ] {
            assert!(
                command_purls(source, name).is_empty(),
                "{name}: {:?}",
                command_purls(source, name)
            );
        }
    }

    #[test]
    fn argument_boundary_stops_prose_and_options_spillover() {
        let source = "child_process.exec('npm install real-pkg', { cwd: 'needed' }); const help = 'failed Many';";
        assert_eq!(command_purls(source, "x.js"), ["pkg:npm/real-pkg"]);
        let source =
            "subprocess.run(['pip', 'install', 'real-pkg'], cwd='needed')\nmessage = 'failed Many'";
        assert_eq!(command_purls(source, "x.py"), ["pkg:pypi/real-pkg"]);
    }

    #[test]
    fn multiline_argv_and_multiple_calls_remain_visible() {
        let source = "subprocess.run([\n 'pip',\n 'install',\n 'first-pkg'\n])\nsubprocess.run(['pip', 'install', 'second-pkg'])";
        let mut found = command_purls(source, "x.py");
        found.sort();
        assert_eq!(found, ["pkg:pypi/first-pkg", "pkg:pypi/second-pkg"]);
        assert_eq!(
            command_purls(
                "child_process.spawn('npm', ['install', 'real-pkg'], {env: {NAME:'noise'}})",
                "x.js"
            ),
            ["pkg:npm/real-pkg"]
        );
    }

    #[test]
    fn dynamic_import_examples_are_not_actual_loads() {
        assert!(
            command_purls(
                "// import('example')\nconst help = \"import('other')\"",
                "x.js"
            )
            .is_empty()
        );
        assert!(
            command_purls(
                "# __import__('example')\nhelp = \"import_module('other')\"",
                "x.py"
            )
            .is_empty()
        );
        assert_eq!(
            command_purls("import('actual-pkg')", "x.js"),
            ["pkg:npm/actual-pkg"]
        );
    }

    #[test]
    fn argv_comments_do_not_create_packages_and_python_aliases_work() {
        let source = "import subprocess as sp\nsp.run(['pip', # npm install bogus prose\n'install', 'real-pkg'])";
        assert_eq!(command_purls(source, "x.py"), ["pkg:pypi/real-pkg"]);
    }

    #[test]
    fn code_variables_in_a_call_are_not_package_names() {
        let py = b"import subprocess, sys\n\
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', pip_name])\n\
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'literal-pkg'])\n";
        assert_eq!(purls(py, "guard.py"), ["pkg:pypi/literal-pkg"]);
    }

    #[test]
    fn string_escapes_in_a_command_are_decoded() {
        let js = "const cp = require('child_process'); cp.exec('npm i a\\nnpm i b');";
        let mut found = command_purls(js, "x.js");
        found.sort();
        found.dedup();
        assert_eq!(found, ["pkg:npm/a", "pkg:npm/b"]);
        let py = "import subprocess\nsubprocess.run('pip install \\x65vil')\n";
        assert_eq!(command_purls(py, "x.py"), ["pkg:pypi/evil"]);
    }

    #[test]
    fn templated_urls_keep_only_a_real_host() {
        let py = b"a = f'http://{host}:{port}/'\n\
            b = 'http://127.0.0.1:${PORT}/health'\n\
            c = 'http://198.51.100.7/$path'\n\
            d = f'http://api.test:8081}'\n\
            e = 'https://dl.test/go/go${V}.tar.gz'\n\
            f = r'https://github\\.com/x'\n\
            f2 = 'https://github\\\\.com\\\\s*$'\n\
            g = 'https://\xd0\xbf\xd1\x80\xd0\xb8\xd0\xbc\xd0\xb5\xd1\x80.test/a'\n\
            h = 'http://q.test/search?q=${term}'\n";
        let mut found = super::super::tests::urls(py, "cfg.py");
        found.sort();
        found.dedup();
        assert_eq!(
            found,
            [
                "http://198.51.100.7/",
                "http://api.test:8081",
                "http://q.test/search",
                "https://dl.test/go/",
                "https://\u{43f}\u{440}\u{438}\u{43c}\u{435}\u{440}.test/a",
            ]
        );
    }
}
