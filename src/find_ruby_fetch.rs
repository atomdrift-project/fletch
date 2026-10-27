//! Literal Ruby process-call downloaders, including retained archive facts.
//! No Ruby, shell command, or fetched program is evaluated or executed.

use super::{
    discover_fetch_calls, tool_name, Arg, FetchCallDiscovery, Symbol, UnresolvedFetchCall,
};

pub(super) fn discover(symbols: &[Symbol]) -> FetchCallDiscovery {
    let mut out = FetchCallDiscovery::default();
    // Flat retained symbols cannot establish a local override's scope. Avoid
    // asserting a built-in call in a file which redefines that method.
    let mut shadowed = std::collections::HashSet::new();
    let mut receivers = std::collections::HashMap::new();
    let mut kernel_rebound = false;
    for symbol in symbols {
        match symbol {
            Symbol::Function { name, .. } => {
                shadowed.insert(name.rsplit('.').next().unwrap_or(name));
            }
            Symbol::Bind { target, .. }
                if target.strip_prefix("::").unwrap_or(target) == "Kernel" =>
            {
                kernel_rebound = true
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
        if receiver != method && receiver != format!("Kernel.{method}") {
            continue;
        }
        if receiver.starts_with("Kernel.") && kernel_rebound {
            continue;
        }

        let Some(first) = args.first() else {
            continue;
        };
        let mut found = match (first, args.len()) {
            (Arg::String { value }, 1) => {
                // Ruby's one-string command form permits shell syntax. Parse
                // it as data, rather than splitting quoted words by hand.
                let parsed = filefacts::OpenOptions::new()
                    .path(std::path::Path::new("ruby-command.sh"))
                    .open(value.as_bytes());
                discover_fetch_calls("shell", parsed.symbols().as_slice())
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
                    offset: *offset,
                };
                discover_fetch_calls("shell", &[call])
            }
            (Arg::Template { value }, 1) => {
                // Only retain the executable spelling when an interpolation
                // follows it. The interpolated text can introduce options;
                // no URL from its remaining bytes is safe to infer.
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
                if !matches!(command, "curl" | "wget") {
                    continue;
                }
                FetchCallDiscovery {
                    references: Vec::new(),
                    unresolved: vec![UnresolvedFetchCall {
                        command: command.to_owned(),
                        offset: *offset,
                    }],
                }
            }
            _ => continue,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(source: &str) -> FetchCallDiscovery {
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
        let urls: Vec<_> = found
            .references
            .iter()
            .map(|reference| match &reference.locator {
                filefacts::RefLocator::Url(url) => url.as_str(),
                other => panic!("unexpected locator {other:?}"),
            })
            .collect();
        assert_eq!(
            urls,
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
            assert!(found.references.is_empty() && found.unresolved.is_empty(), "{source}: {found:?}");
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
            assert!(found
                .references
                .iter()
                .all(|reference| !format!("{:?}", reference.locator).contains("after-unknown")));
        }
    }
}
