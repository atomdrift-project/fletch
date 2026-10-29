//! Leading literal CSS imports in a GLib file-write body. No CSS or JS runs.
use filefacts::{Arg, RefKind, RefLocator, Reference, Symbol};

use super::FetchCallDiscovery;

const MAX_BODY: usize = 16_384;

/// Read the next simple import's URL token. Escapes, dynamic values and
/// unsupported token forms remain unresolved; leading comments are skipped.
fn initial_import(body: &str) -> Option<(&str, &str)> {
    if body.len() > MAX_BODY {
        return None;
    }
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

pub(super) fn discover(symbols: &[Symbol]) -> FetchCallDiscovery {
    let mut discovery = FetchCallDiscovery::default();
    for symbol in symbols {
        let Symbol::Call {
            target: Some(target),
            args,
            offset,
        } = symbol
        else {
            continue;
        };
        if target != "GLib.file_set_contents" {
            continue;
        }
        let Some(Arg::String { value }) = args.get(1) else {
            continue;
        };
        if value.len() > MAX_BODY {
            continue;
        }
        let mut rest = value.as_str();
        // Each successful parse consumes a complete statement. The body-size
        // bound limits total work and output without a first-import shortcut.
        while let Some((url, tail)) = initial_import(rest) {
            rest = tail;
            // A local/data import must not hide a later external import.
            if !url::Url::parse(url).is_ok_and(|url| {
                matches!(url.scheme(), "http" | "https") && url.host_str().is_some()
            }) {
                continue;
            }
            let mut reference = Reference::new(
                RefLocator::Url(url.to_owned()),
                RefKind::Dependency,
                "ast-glib-stylesheet-import",
                url,
            );
            reference.offset = *offset;
            discovery.references.push(reference);
        }
    }
    super::dedup(&mut discovery.references);
    discovery
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refs(source: &str) -> Vec<Reference> {
        let parsed = filefacts::OpenOptions::new()
            .path(std::path::Path::new("extension.js"))
            .open(source.as_bytes());
        discover(parsed.symbols().as_slice()).references
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
            vec![
                &RefLocator::Url("https://example.invalid/a.css".into()),
                &RefLocator::Url("https://example.invalid/b.css".into()),
            ]
        );
        let local_first = refs(
            r#"GLib.file_set_contents(path, "@import 'local.css'; @import url('https://example.invalid/remote.css');");"#,
        );
        assert_eq!(local_first.len(), 1);
        assert_eq!(
            local_first[0].locator,
            RefLocator::Url("https://example.invalid/remote.css".into())
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
}
