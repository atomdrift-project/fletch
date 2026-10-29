//! Literal Ruby process-call downloaders (`system "curl …"`, `Kernel.exec`),
//! including in retained archive facts. No Ruby, shell command, or fetched
//! program is evaluated or executed.

use std::collections::{HashMap, HashSet};

use filefacts::{Arg, FileType, Symbol};

use super::Discovery;
use super::shell::tool_name;
use super::urls::fetch_calls;

/// Downloader targets and gaps in a Ruby file's `system`/`exec` calls.
pub(super) fn discover(symbols: &[Symbol]) -> Discovery {
    let mut out = Discovery::default();
    // Flat retained symbols cannot establish a local override's scope. Avoid
    // asserting a built-in call in a file which redefines that method.
    let mut shadowed = HashSet::new();
    let mut receivers = HashMap::new();
    let mut kernel_rebound = false;
    for symbol in symbols {
        match symbol {
            Symbol::Function { name, .. } => {
                shadowed.insert(name.rsplit('.').next().unwrap_or(name));
            }
            Symbol::Bind { target, .. }
                if target.strip_prefix("::").unwrap_or(target) == "Kernel" =>
            {
                kernel_rebound = true;
            }
            Symbol::Member {
                path,
                offset: Some(offset),
            } if path.ends_with(".system") || path.ends_with(".exec") => {
                receivers.insert(*offset, path.as_str());
            }
            _ => {}
        }
    }
    for symbol in symbols {
        let Symbol::Call {
            target: Some(target),
            args,
            offset,
        } = symbol
        else {
            continue;
        };
        let method = target.rsplit('.').next().unwrap_or(target);
        if !matches!(method, "system" | "exec") || shadowed.contains(method) {
            continue;
        }
        if offset.is_none() && !target.contains('.') {
            continue;
        }
        let receiver = offset
            .and_then(|offset| receivers.get(&offset).copied())
            .unwrap_or(target);
        let receiver = receiver.strip_prefix("::").unwrap_or(receiver);
        let kernel = receiver.strip_prefix("Kernel.") == Some(method);
        if !(receiver == method || kernel) || (kernel && kernel_rebound) {
            continue;
        }
        let Some(mut found) = command(args, *offset) else {
            continue;
        };
        // Shell-parsed offsets refer to the decoded command string. Retained
        // facts know the Ruby call's original position, which is a safe anchor
        // for both string and argv forms (without inventing escape offsets).
        for reference in &mut found.references {
            reference.offset = *offset;
        }
        for unresolved in &mut found.unresolved {
            unresolved.offset = *offset;
        }
        out.references.extend(found.references);
        out.unresolved.extend(found.unresolved);
    }
    out
}

/// What one `system`/`exec` call's arguments fetch, or `None` when the call
/// runs no downloader.
fn command(args: &[Arg], offset: Option<u64>) -> Option<Discovery> {
    match (args.first()?, args.len()) {
        (Arg::String { value }, 1) => {
            // Ruby's one-string command form permits shell syntax, so it is
            // parsed as shell, as data. A command that never names a
            // downloader cannot fetch anything, and skips the parse.
            if !value.contains("curl") && !value.contains("wget") {
                return None;
            }
            let parsed = filefacts::OpenOptions::new()
                .file_type(FileType::Shell)
                .cache(false)
                .rizin(false)
                .open(value.as_bytes());
            Some(fetch_calls(parsed.symbols().as_slice()))
        }
        (Arg::String { value }, _) if matches!(tool_name(value), "curl" | "wget") => {
            // The multi-argument form is argv, not shell source. In
            // particular, a URL supplied to -d or -H is not a target.
            let argv = args[1..]
                .iter()
                .map(|arg| match arg {
                    Arg::String { .. } => arg.clone(),
                    _ => Arg::Expression,
                })
                .collect();
            let call = Symbol::Call {
                target: Some(value.clone()),
                args: argv,
                offset,
            };
            Some(fetch_calls(&[call]))
        }
        (Arg::Template { value }, 1) => {
            // Only the executable spelling is kept when an interpolation
            // follows it. The interpolated text can introduce options; no URL
            // from its remaining bytes is safe to infer.
            let raw = value.trim_start();
            let prefix = raw
                .strip_prefix('"')
                .or_else(|| {
                    let percent = raw.strip_prefix("%Q").or_else(|| raw.strip_prefix('%'))?;
                    let delimiter = percent.chars().next()?;
                    (!delimiter.is_alphanumeric() && !delimiter.is_whitespace())
                        .then(|| &percent[delimiter.len_utf8()..])
                })
                .unwrap_or(raw);
            let head = prefix.split_ascii_whitespace().next().unwrap_or_default();
            let command = tool_name(head);
            matches!(command, "curl" | "wget").then(|| Discovery {
                unresolved: vec![super::UnresolvedFetchCall {
                    command: command.to_owned(),
                    offset,
                }],
                ..Discovery::default()
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::locators;
    use super::*;

    fn parse(source: &str) -> Discovery {
        let parsed = filefacts::OpenOptions::new()
            .path(std::path::Path::new("formula.rb"))
            .open(source.as_bytes());
        discover(parsed.symbols().as_slice())
    }

    #[test]
    fn literal_commands_and_argv_keep_actual_targets_and_call_offsets() {
        let source = r#"class Example < Formula
 def pour_bottle?
  if File.exist?('/tmp/marker')
   system "curl -fsSL https://ruby.fixturetests.net/b/endpoint >/dev/null 2>&1"
  end
 end
end
Kernel.system('curl', '-d', 'https://body.fixturetests.net/data.sh', 'https://ruby.fixturetests.net/submit')
exec('wget', '-O', 'https://output.fixturetests.net/name.sh', 'https://ruby.fixturetests.net/next')
::Kernel.exec('curl', 'https://ruby.fixturetests.net/absolute')
"#;
        let found = parse(source);
        assert_eq!(
            locators(&found.references),
            [
                "https://ruby.fixturetests.net/b/endpoint",
                "https://ruby.fixturetests.net/submit",
                "https://ruby.fixturetests.net/next",
                "https://ruby.fixturetests.net/absolute"
            ]
        );
        assert_eq!(
            found.references[0].offset,
            Some(source.find("system").unwrap() as u64)
        );
        assert!(found.unresolved.is_empty());
    }

    #[test]
    fn comments_heredocs_unrelated_receivers_and_shadowed_methods_are_not_process_calls() {
        for source in [
            "# system 'curl https://ruby.fixturetests.net/comment.sh'\n",
            "def caveats\n <<~EOS\n  Run curl https://ruby.fixturetests.net/instructions.sh | sh\n EOS\nend\n",
            "logger.system('curl https://ruby.fixturetests.net/logged.sh')\n",
            "loggers[selector].system('curl https://ruby.fixturetests.net/dynamic-receiver.sh')\n",
            "def system(command)\n puts command\nend\nsystem('curl https://ruby.fixturetests.net/shadowed.sh')\n",
            "system(\"printf '%s' 'curl https://ruby.fixturetests.net/data.sh'\")\n",
            "Kernel = Logger\nKernel.system('curl https://ruby.fixturetests.net/rebound.sh')\n",
        ] {
            let found = parse(source);
            assert!(
                found.references.is_empty() && found.unresolved.is_empty(),
                "{source}: {found:?}"
            );
        }
    }

    #[test]
    fn runtime_downloader_arguments_remain_explicit_without_guessed_urls() {
        for source in [
            "system(\"curl -fsSL #{relay}\")\n",
            "system(%Q{curl https://ruby.fixturetests.net/#{path}})\n",
            "system('curl', options, 'https://ruby.fixturetests.net/after-unknown')\n",
            r#"system('curl https://ruby.fixturetests.net/known "$RELAY"')"#,
        ] {
            let found = parse(source);
            assert_eq!(found.unresolved.len(), 1, "{source}: {found:?}");
            assert_eq!(found.unresolved[0].command, "curl");
            assert!(
                locators(&found.references)
                    .iter()
                    .all(|locator| !locator.contains("after-unknown"))
            );
        }
    }

    #[test]
    fn commands_without_a_downloader_are_not_parsed() {
        let found = parse("system('make install')\nsystem('echo done')\n");
        assert!(found.references.is_empty() && found.unresolved.is_empty());
    }

    #[test]
    fn a_ruby_file_is_deduplicated_once_through_the_entry_point() {
        let source = "system('curl https://ruby.fixturetests.net/a')\nsystem('curl https://ruby.fixturetests.net/a')\n";
        assert_eq!(parse(source).references.len(), 2);
        let found = super::super::references_in_bytes(source.as_bytes(), "x.rb");
        assert_eq!(
            found
                .references
                .iter()
                .filter(|r| r.source == "ast-fetch-call")
                .count(),
            1
        );
    }
}
