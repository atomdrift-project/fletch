//! Leading literal CSS imports in a GLib file-write body
//! (`GLib.file_set_contents(path, "@import url('https://…');")`), the way a
//! GNOME extension installs a stylesheet that loads remote CSS. No CSS or JS
//! runs.

use filefacts::{Arg, RefKind, RefLocator, Reference, Symbol};

use super::Discovery;
use super::UnresolvedFetchCall;
use crate::fetch::is_http_url;

/// The file-write API whose body is read.
const WRITE_API: &str = "GLib.file_set_contents";

/// The longest body read. Each parsed import consumes a whole statement, so
/// this bounds both the work and the references one body yields.
const MAX_BODY: usize = 16_384;

/// Read the next simple import's URL token. Escapes, dynamic values and
/// unsupported token forms remain unresolved; leading comments are skipped.
fn initial_import(body: &str) -> Option<(&str, &str)> {
    let mut body = body.trim_start();
    while let Some(comment) = body.strip_prefix("/*") {
        body = comment.get(comment.find("*/")? + 2..)?.trim_start();
    }
    let tail = body.strip_prefix("@import")?;
    if !tail.starts_with(char::is_whitespace) {
        return None;
    }
    let tail = tail.trim_start();
    let (tail, function) = match tail.strip_prefix("url(") {
        Some(tail) => (tail.trim_start(), true),
        None => (tail, false),
    };
    let (url, tail) = if tail.starts_with(['\'', '"']) {
        let quote = tail.chars().next()?;
        let rest = tail.get(1..)?;
        let end = rest.find(quote)?;
        let value = &rest[..end];
        if value.contains(['\\', '\n', '\r']) {
            return None;
        }
        (value, rest.get(end + 1..)?)
    } else if function {
        let end = tail.find(')')?;
        let value = &tail[..end];
        if value.is_empty()
            || value
                .chars()
                .any(|c| c.is_whitespace() || matches!(c, '\\' | '\'' | '"' | '('))
        {
            return None;
        }
        (value, &tail[end..])
    } else {
        return None;
    };
    let tail = tail.trim_start();
    let tail = if function {
        tail.strip_prefix(')')?.trim_start()
    } else {
        tail
    };
    // Deliberately require a complete simple import. Conditional/media forms
    // need CSS parsing rather than guessing where another statement starts.
    if !tail.starts_with(';') {
        return None;
    }
    Some((url, &tail[1..]))
}

/// Remote stylesheets imported by the bodies a JavaScript file writes, and the
/// writes whose body is a runtime value.
pub(super) fn discover(symbols: &[Symbol]) -> Discovery {
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
        if target != WRITE_API {
            continue;
        }
        let value = match args.get(1) {
            Some(Arg::String { value }) => value,
            Some(_) => {
                out.unresolved.push(UnresolvedFetchCall {
                    command: WRITE_API.to_owned(),
                    offset: *offset,
                });
                continue;
            }
            None => continue,
        };
        if value.len() > MAX_BODY {
            out.truncated = true;
            tracing::debug!(
                recognizer = "glib",
                limit = MAX_BODY,
                bytes = value.len(),
                "stylesheet body too long to read"
            );
            continue;
        }
        let mut rest = value.as_str();
        while let Some((url, tail)) = initial_import(rest) {
            rest = tail;
            // A local/data import must not hide a later external import.
            if !is_http_url(url) {
                continue;
            }
            let mut reference = Reference::new(
                RefLocator::Url(url.to_owned()),
                RefKind::Dependency,
                "ast-glib-stylesheet-import",
                url,
            );
            reference.offset = *offset;
            out.references.push(reference);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn discovered(source: &str) -> Discovery {
        let parsed = filefacts::OpenOptions::new()
            .path(std::path::Path::new("extension.js"))
            .open(source.as_bytes());
        discover(parsed.symbols().as_slice())
    }

    fn refs(source: &str) -> Vec<Reference> {
        discovered(source).references
    }

    #[test]
    fn imports_from_the_complete_write_body_keep_source_offsets() {
        for (source, url) in [
            (
                r#"GLib.file_set_contents(path, "@import url('https://example.invalid/theme.css');\n" + "/* local stylesheet */\n");"#,
                "https://example.invalid/theme.css",
            ),
            (
                r#"GLib.file_set_contents(path, '@import "https://example.invalid/direct.css";');"#,
                "https://example.invalid/direct.css",
            ),
            (
                r#"GLib.file_set_contents(path, '@import url(https://example.invalid/plain.css);');"#,
                "https://example.invalid/plain.css",
            ),
        ] {
            let found = refs(source);
            assert_eq!(found.len(), 1, "{source}");
            assert_eq!(found[0].locator, RefLocator::Url(url.into()));
            assert_eq!(found[0].kind, RefKind::Dependency);
            assert_eq!(found[0].offset, Some(0));
        }
        let multiple = refs(
            r#"GLib.file_set_contents(path, "/* theme */ @import 'https://example.invalid/a.css';\n/* next */ @import url('https://example.invalid/b.css');\nstage {color:white}");"#,
        );
        assert_eq!(
            multiple.iter().map(|r| &r.locator).collect::<Vec<_>>(),
            [
                &RefLocator::Url("https://example.invalid/a.css".into()),
                &RefLocator::Url("https://example.invalid/b.css".into()),
            ]
        );
        let local_first = refs(
            r#"GLib.file_set_contents(path, "@import 'local.css'; @import url('https://example.invalid/remote.css');");"#,
        );
        assert_eq!(
            local_first.iter().map(|r| &r.locator).collect::<Vec<_>>(),
            [&RefLocator::Url(
                "https://example.invalid/remote.css".into()
            )]
        );
    }

    #[test]
    fn other_arguments_receivers_dynamic_bodies_and_unsupported_css_are_not_imports() {
        for source in [
            r#"const text="@import url('https://example.invalid/docs.css');";"#,
            r#"// GLib.file_set_contents(path, "@import url('https://example.invalid/docs.css');");"#,
            r#"logger.file_set_contents(path, "@import url('https://example.invalid/other.css');");"#,
            r#"GLib.file_set_contents(path, 'status', "@import url('https://example.invalid/ignored.css');");"#,
            r#"GLib.file_set_contents(path, unknown + "@import url('https://example.invalid/partial.css');");"#,
            r#"GLib.file_set_contents(path, "@import url('https://example.invalid/conditional.css') screen;");"#,
            r#"GLib.file_set_contents(path, "@import url('file:///local.css');");"#,
            r#"fetch('https://example.invalid/submit', {body:"@import url('https://example.invalid/body.css');"});"#,
        ] {
            assert!(refs(source).is_empty(), "{source}");
        }
    }

    #[test]
    fn a_runtime_body_is_a_gap_and_an_oversized_one_is_truncation() {
        let dynamic = discovered("GLib.file_set_contents(path, css);");
        assert_eq!(dynamic.unresolved.len(), 1);
        assert_eq!(dynamic.unresolved[0].command, WRITE_API);
        assert!(!dynamic.truncated);

        let body = format!(
            "@import url('https://example.invalid/a.css');{}",
            " ".repeat(MAX_BODY)
        );
        let oversized = discover(&[Symbol::Call {
            target: Some(WRITE_API.to_owned()),
            args: vec![
                Arg::Identifier {
                    name: "path".into(),
                },
                Arg::String { value: body },
            ],
            offset: Some(0),
        }]);
        assert!(oversized.references.is_empty() && oversized.truncated);
    }
}
