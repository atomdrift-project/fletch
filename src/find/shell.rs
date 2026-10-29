//! Package-manager install commands in shell text: scripts, Dockerfiles, npm
//! lifecycle hooks, and the command strings source code hands to a process.

use filefacts::RefKind;

use super::Lang;
use super::found::{Found, position_in};
use super::purl_token::{Eco, pm_token_locator};
use super::urls;

/// How many global options a manager may carry before its verb
/// (`apt-get -y -q install`). Bounding the skip keeps a line of nothing but
/// options from being re-read at every manager name in it.
const MAX_GLOBAL_OPTIONS: usize = 8;

/// The characters that end one command and start the next on a line.
const SEPARATORS: [char; 4] = [';', '&', '|', '\r'];

/// Where text handed to [`commands`] sits in the file.
#[derive(Debug, Clone, Copy)]
pub(super) enum Place<'r> {
    /// Text from elsewhere (an npm hook read from parsed JSON): each command
    /// is searched for in the file.
    Search,
    /// A copy of the file's text: it runs byte for byte with the file, except
    /// that from each entry's `copy` position on it runs with the file from
    /// the entry's `file` position. An empty map is the file's text itself.
    Mapped(&'r [(usize, usize)]),
    /// Every command it holds is cited at this offset.
    At(u64),
}

/// Scan a shell script or Dockerfile for install commands and URLs.
pub(super) fn scan(lang: Lang, out: &mut Found<'_>) {
    let Some(text) = out.text else {
        return;
    };
    commands(text, Place::Mapped(&[]), lang, lang.label(), out);
    urls::git_refs(text, lang.label(), out);
    urls::urls(text, lang.label(), out);
    urls::bare_fetch_urls(text, lang, out);
}

/// npm lifecycle hooks: a `postinstall` that `wget … | sh` or `npm install`s a
/// package. The command string is the reference site. Reads the hooks from the
/// filefacts values JSON (`npm.scripts.{hook}`), so it works equally on a live
/// file and on the retained facts of an archive member.
pub(super) fn npm_hooks(values: &serde_json::Value, out: &mut Found<'_>) {
    let Some(scripts) = values.get("npm").and_then(|n| n.get("scripts")) else {
        return;
    };
    for hook in ["preinstall", "install", "postinstall"] {
        let Some(cmd) = scripts.get(hook).and_then(serde_json::Value::as_str) else {
            continue;
        };
        let source = format!("npm.scripts.{hook}");
        for url in urls::extract_urls(cmd) {
            out.push(
                urls::url_locator(url),
                RefKind::UrlFetch,
                source.as_str(),
                cmd,
            );
        }
        // The packages a hook installs are build-time dependencies that run
        // install scripts.
        let start = out.refs.len();
        commands(cmd, Place::Search, Lang::Shell, &source, out);
        for reference in &mut out.refs[start..] {
            reference.context = Some(filefacts::DependencyContext {
                scope: filefacts::DependencyScope::Build,
                optional: false,
                has_install_script: true,
                installed_path: None,
            });
        }
    }
}

/// Recognize package-manager install commands and emit a [`RefKind::Command`]
/// per named package, labelled `source`. Splits on command separators, joins
/// `\` line continuations, and matches the invocation anywhere in a command.
///
/// In a Dockerfile, a `FROM` sets the base distro, which decides the
/// ecosystem of the cross-distro managers (`apt` → Debian or Ubuntu, `apk` →
/// Alpine or Wolfi) in the instructions after it, exec form included. Other
/// text has no such context and uses each manager's dominant distro.
pub(super) fn commands(
    text: &str,
    place: Place<'_>,
    lang: Lang,
    source: &str,
    out: &mut Found<'_>,
) {
    // Continuations become as many spaces as they had bytes, so a position in
    // `joined` is the same position in `text`.
    let joined = text.replace("\\\r\n", "   ").replace("\\\n", "  ");
    let locate = |part: &str| -> Option<u64> {
        match place {
            Place::Search => None,
            Place::At(at) => Some(at),
            Place::Mapped(remap) => {
                let at = position_in(&joined, part)?;
                let file = match remap
                    .partition_point(|&(copy, _)| copy <= at)
                    .checked_sub(1)
                {
                    Some(i) => remap[i].1 + (at - remap[i].0),
                    None => at,
                };
                Some(file as u64)
            }
        }
    };
    let mut distro = None;
    for line in joined.split('\n') {
        if lang == Lang::Dockerfile {
            match instruction(line) {
                Some(Instruction::From(image)) => {
                    distro = image.and_then(image_distro);
                    continue;
                }
                Some(Instruction::Exec(words)) => {
                    let at = locate(line);
                    for part in words.split(['\n', ';', '&', '|', '\r']) {
                        segment(part, at, lang, distro, source, out);
                    }
                    continue;
                }
                None => {}
            }
        }
        for part in line.split(SEPARATORS) {
            let part = part.trim();
            segment(part, locate(part), lang, distro, source, out);
        }
    }
}

/// A Dockerfile instruction that is not shell text.
enum Instruction<'t> {
    /// `FROM [--platform=…] <image>`; `None` when the image is a build-arg
    /// placeholder (`$BASE`) or `scratch`, neither of which names a distro.
    From(Option<&'t str>),
    /// `RUN`/`CMD`/`ENTRYPOINT` in exec form (`RUN ["npm","install","x"]`):
    /// the words it runs, joined with spaces. The JSON array is one shell-less
    /// token to a shell reading, which would otherwise see none of its words.
    Exec(String),
}

fn instruction(line: &str) -> Option<Instruction<'_>> {
    let (keyword, rest) = line
        .trim()
        .split_once(char::is_whitespace)
        .unwrap_or((line.trim(), ""));
    if keyword.eq_ignore_ascii_case("FROM") {
        let image = rest
            .split_whitespace()
            .find(|t| !t.starts_with('-'))
            .filter(|t| !t.starts_with('$') && *t != "scratch");
        return Some(Instruction::From(image));
    }
    if !["RUN", "CMD", "ENTRYPOINT"]
        .iter()
        .any(|i| keyword.eq_ignore_ascii_case(i))
    {
        return None;
    }
    let words: Vec<String> = serde_json::from_str(rest.trim()).ok()?;
    Some(Instruction::Exec(words.join(" ")))
}

/// Recognize the install command in one separator-delimited `part`, cited at
/// `at` (searched for when `None`).
fn segment(
    part: &str,
    at: Option<u64>,
    lang: Lang,
    distro: Option<Eco>,
    source: &str,
    out: &mut Found<'_>,
) {
    let part = part.trim();
    if part.is_empty() || part.starts_with('#') {
        return;
    }
    // Quotes group a word without being part of it: `npm install "evil"`
    // installs `evil`.
    let toks: Vec<&str> = part
        .split_whitespace()
        .map(|t| t.trim_matches(['"', '\'']))
        .filter(|t| !t.is_empty())
        .collect();
    // A `for`/`select` header's words are a list of values, not a command:
    // `for pm in apt-get dnf pkg_add port` installs nothing.
    if toks.first().is_some_and(|t| matches!(*t, "for" | "select")) {
        return;
    }
    let Some((eco, start, runner)) = invocation(&toks, lang) else {
        return;
    };
    let eco = eco.on(distro);
    let args = argument_list(&toks[start..]);
    let packages = if runner {
        runner_packages(eco, &args)
    } else {
        let mut skip_value = false;
        args.into_iter()
            .filter(|arg| {
                if skip_value {
                    skip_value = false;
                    return false;
                }
                skip_value = takes_value(eco, arg);
                !skip_value
            })
            .collect()
    };
    let mut locators = packages
        .into_iter()
        .filter_map(|arg| pm_token_locator(eco, arg));
    let Some(first) = locators.next() else {
        return;
    };
    // One place for the whole command, found once: every package of it
    // shares the evidence, and comparing a long line per package is
    // quadratic.
    let at = match at {
        Some(at) => Some(at),
        None => out.locate(part, &first),
    };
    for locator in std::iter::once(first).chain(locators) {
        out.push_at(locator, RefKind::Command, source, part, at);
    }
}

/// The first package-manager invocation among `toks`: its ecosystem, where
/// its arguments start, and whether it is a one-shot runner (`npx`, `uvx`,
/// `pnpm dlx`, `pipx run`, `deno run`), which runs one package and passes it
/// the rest as arguments.
///
/// An option is never a command name, so `-/npm` is not `npm`. In shell text
/// a manager after `echo`/`printf` is printed, not run; in source code the
/// call itself is the evidence that the command runs.
fn invocation(toks: &[&str], lang: Lang) -> Option<(Eco, usize, bool)> {
    let echo = toks
        .iter()
        .position(|token| matches!(*token, "echo" | "printf"));
    toks.iter()
        .enumerate()
        .filter(|(_, tok)| !tok.starts_with('-'))
        .find_map(|(i, &tok)| {
            let (eco, consumed) = match_pm(&toks[i..])?;
            if !lang.is_source() && echo.is_some_and(|at| at < i) {
                return None;
            }
            let verb = toks[i + consumed - 1];
            let runner = match eco {
                Eco::Npm | Eco::Pypi => {
                    matches!(tool_name(tok), "npx" | "bunx" | "uvx")
                        || matches!(verb, "dlx" | "x" | "run")
                }
                Eco::Deno => verb == "run",
                _ => false,
            };
            Some((eco, i + consumed, runner))
        })
}

/// A command's arguments up to where its argument list ends: a redirect
/// (`>out`, `2>/dev/null`, `&>log`), an options-object `{`, a nested command
/// (`$(…)`, a backquote) or a comment. A word closing the subshell the command
/// ran in (`…/protoc-gen-go)`) is its last.
fn argument_list<'t>(args: &[&'t str]) -> Vec<&'t str> {
    let mut list = Vec::new();
    for &arg in args {
        let redirect = arg
            .trim_start_matches(|c: char| c.is_ascii_digit() || c == '&')
            .starts_with(['>', '<']);
        if redirect || arg.starts_with(['#', '`']) || arg.starts_with("$(") || arg == "{" {
            break;
        }
        let closes = arg.ends_with(')') && !arg.contains('(');
        let word = arg.trim_end_matches(')').trim_matches(['"', '\'']);
        if !word.is_empty() {
            list.push(word);
        }
        if closes {
            break;
        }
    }
    list
}

/// The packages a one-shot runner's arguments name: those its package option
/// names (`npx -p a -p b cmd`, `uvx --from a cmd`, `uvx --with a b`), and the
/// first positional unless a package option already named what it runs —
/// then the positional is a command. Everything after it is its arguments.
fn runner_packages<'t>(eco: Eco, args: &[&'t str]) -> Vec<&'t str> {
    // Options naming the package that runs, and ones adding packages beside it.
    let (names, adds): (&[&str], &[&str]) = match eco {
        Eco::Pypi => (&["--from"], &["--with"]),
        // `deno run` runs its first positional; only an `npm:`/`jsr:`
        // specifier there is a package.
        Eco::Deno => (&[], &[]),
        _ => (&["-p", "--package"], &[]),
    };
    let mut packages = Vec::new();
    let mut named = false;
    let mut args = args.iter().copied();
    while let Some(arg) = args.next() {
        let (option, attached) = arg
            .split_once('=')
            .map_or((arg, None), |(o, v)| (o, Some(v)));
        if names.contains(&option) || adds.contains(&option) {
            named |= names.contains(&option);
            packages.extend(attached.or_else(|| args.next()));
        } else if arg.starts_with('-') {
            if takes_value(eco, arg) {
                args.next();
            }
        } else {
            if !named {
                packages.push(arg);
            }
            break;
        }
    }
    packages
}

/// A command word's program name: `/opt/venv/bin/pip` and
/// `C:\Python312\Scripts\pip.exe` both run `pip`. A URL is not a path to a
/// program.
pub(super) fn tool_name(token: &str) -> &str {
    if token.contains("://") {
        return token;
    }
    // A command opening a subshell or substitution: `$(go install x)`,
    // `GEN=$(go install x)`, `(npm i y)`, a backquote.
    let token = token
        .rsplit_once("$(")
        .map_or(token, |(_, command)| command)
        .trim_start_matches(['(', '`']);
    let name = token.rsplit(['/', '\\']).next().unwrap_or(token);
    // Windows resolves `pip.exe`, `npm.cmd` and `npx.ps1` from a bare `pip`.
    name.len()
        .checked_sub(4)
        .and_then(|stem| Some((name.get(..stem)?, name.get(stem..)?)))
        .filter(|(_, ext)| {
            [".exe", ".cmd", ".bat", ".ps1"]
                .iter()
                .any(|known| ext.eq_ignore_ascii_case(known))
        })
        .map_or(name, |(stem, _)| stem)
}

/// Whether `option` takes the next word as its value in `eco`'s install
/// commands, so that value (`conda -c conda-forge`, `gem -v 1.2.3`,
/// `apt-get -o Dpkg::Options::=…`) is never read as a package. An attached
/// value (`--tag=beta`, `-tbookworm`) is part of its own word. `nuget.exe`
/// options are case-insensitive.
fn takes_value(eco: Eco, option: &str) -> bool {
    let options = value_options(eco);
    if eco == Eco::NuGet {
        options.iter().any(|o| o.eq_ignore_ascii_case(option))
    } else {
        options.contains(&option)
    }
}

/// The options of `eco`'s install commands that take a value.
#[rustfmt::skip]
const fn value_options(eco: Eco) -> &'static [&'static str] {
    match eco {
        Eco::Npm => &[
            "--registry", "--prefix", "--cache", "--cwd", "--userconfig", "--loglevel",
            "--platform", "--arch", "--target", "--tag", "--workspace", "-w", "--omit",
            "--include", "--dir", "-C", "--filter", "-F", "--modules-folder",
            "--network-timeout", "--backend", "--call", "-c",
        ],
        Eco::Pypi => &[
            "-r", "--requirement", "-c", "--constraint", "-i", "--index-url",
            "--extra-index-url", "-f", "--find-links", "--trusted-host", "-t", "--target",
            "--prefix", "--root", "-p", "--python", "--platform", "--python-version",
            "--implementation", "--abi", "-e", "--editable", "--src", "--cache-dir", "--log",
            "--progress-bar", "--upgrade-strategy", "--global-option", "-C",
            "--config-settings", "--only-binary", "--no-binary", "--proxy", "--retries",
            "--timeout", "--exists-action", "--cert", "--client-cert", "--report", "--index",
            "--default-index", "-G", "--group", "--extra", "--optional", "--source", "-E",
            "--extras", "--pip-args", "--suffix", "--spec",
        ],
        Eco::Deno => &[
            "-c", "--config", "--import-map", "--lock", "--cert", "--location", "--seed",
            "--env-file", "--watch-exclude", "--ext", "-L", "--log-level", "-n", "--name",
            "--root",
        ],
        Eco::Golang => &[
            "-C", "-p", "-tags", "-ldflags", "-gcflags", "-asmflags", "-gccgoflags", "-o",
            "-modfile", "-mod", "-toolexec", "-buildmode", "-compiler", "-pkgdir",
            "-overlay", "-pgo", "-exec", "-installsuffix",
        ],
        Eco::Cargo => &[
            "--version", "--vers", "--git", "--branch", "--tag", "--rev", "--path", "--root",
            "--index", "--registry", "--target", "--target-dir", "-F", "--features", "-j",
            "--jobs", "--profile", "--config", "-Z", "--rename", "-p", "--package",
            "--manifest-path", "--color", "--bin", "--example",
        ],
        Eco::Gem => &[
            "-v", "--version", "-i", "--install-dir", "-n", "--bindir", "-s", "--source",
            "--platform", "-P", "--trust-policy", "--build-root", "-g", "--group", "-r",
            "--require", "--path", "--git", "--github", "--branch", "--ref",
        ],
        Eco::Conda => &[
            "-c", "--channel", "-n", "--name", "-p", "--prefix", "--file", "--repodata-fn",
            "--solver", "--subdir", "--platform",
        ],
        Eco::Composer => &["-d", "--working-dir"],
        Eco::Debian | Eco::Ubuntu => &[
            "-t", "--target-release", "--default-release", "-o", "--option", "-c",
            "--config-file", "-a", "--host-architecture", "-P", "--build-profiles",
        ],
        Eco::Alpine | Eco::Wolfi => &[
            "-X", "--repository", "-p", "--root", "--arch", "-t", "--virtual", "--cache-dir",
            "--keys-dir", "--repositories-file",
        ],
        Eco::Fedora => &[
            "--repo", "--repoid", "--enablerepo", "--disablerepo", "--releasever",
            "--installroot", "-c", "--config", "--setopt", "-x", "--exclude", "--forcearch",
            "-d", "--debuglevel", "-e", "--errorlevel", "--downloaddir", "--destdir",
            "--repofrompath",
        ],
        Eco::OpenSuse => &[
            "-r", "--repo", "--from", "-t", "--type", "-R", "--root", "--releasever", "-D",
            "--reposd-dir", "-C", "--cache-dir",
        ],
        Eco::Arch | Eco::Aur => &[
            "--config", "-b", "--dbpath", "-r", "--root", "--cachedir", "--arch", "--gpgdir",
            "--hookdir", "--logfile", "--assume-installed", "--ignore", "--ignoregroup",
            "--overwrite", "--print-format",
        ],
        Eco::Snap => &["--channel", "--revision"],
        Eco::FreeBsd => &[
            "-r", "--repository", "-j", "--jail", "-c", "--chroot", "-R", "--repo-conf-dir",
            "-o", "--option",
        ],
        Eco::NuGet => &[
            "-v", "--version", "-s", "--source", "-f", "--framework", "--package-directory",
            "--add-source", "--tool-path", "--configfile", "-version", "-source",
            "-outputdirectory", "-configfile", "-framework", "-fallbacksource",
            "-packagesdirectory", "-solutiondirectory", "-verbosity",
        ],
        Eco::Cpan => &["-l", "--local-lib", "-L", "--local-lib-contained", "--mirror"],
        Eco::Pub => &[
            "--path", "--git-url", "--git-ref", "--git-path", "--hosted-url", "--directory",
            "-C", "--sdk",
        ],
        Eco::Homebrew | Eco::NetBsd | Eco::OpenBsd => &[],
    }
}

/// Classify a Dockerfile base image to the distro whose package manager its
/// `RUN`s will use. Both the repository and the tag carry the signal
/// (`python:3.12-slim` is Debian, `node:20-alpine` is Alpine). `None` when the
/// image is unrecognized — the manager then falls back to its dominant distro.
fn image_distro(image: &str) -> Option<Eco> {
    let img = image.to_ascii_lowercase();
    // A distro's own name is distinctive anywhere in the reference
    // (`alpinelinux/build-base`); a release codename or `slim` is an ordinary
    // word, so it counts only as a whole word of letters (`3.12-slim-bookworm`,
    // `debian:sid`) — never inside another (`sidekiq`, `focalboard`).
    let has = |n: &str| img.contains(n);
    let word = |w: &str| img.split(|c: char| !c.is_ascii_lowercase()).any(|t| t == w);
    if has("wolfi") || has("chainguard") {
        Some(Eco::Wolfi)
    } else if has("alpine") {
        Some(Eco::Alpine)
    } else if has("ubuntu")
        || ["focal", "jammy", "noble", "mantic", "lunar"]
            .iter()
            .any(|c| word(c))
    {
        Some(Eco::Ubuntu)
    } else if has("opensuse") || has("/suse") || img.starts_with("suse") {
        Some(Eco::OpenSuse)
    } else if has("fedora") {
        Some(Eco::Fedora)
    } else if has("archlinux") || img == "arch" || img.starts_with("arch:") {
        Some(Eco::Arch)
    } else if has("debian")
        || ["bookworm", "bullseye", "trixie", "buster", "slim", "sid"]
            .iter()
            .any(|c| word(c))
    {
        Some(Eco::Debian)
    } else {
        None
    }
}

/// Recognize a package-manager invocation at the start of a token slice,
/// returning its ecosystem and how many tokens the invocation spans
/// (`npm install` → 2, `uv pip install` → 3). A cross-distro manager reports
/// its dominant distro (`apt` → Debian, `apk` → Alpine); [`Eco::on`] moves it
/// to the base image's.
fn match_pm(toks: &[&str]) -> Option<(Eco, usize)> {
    // A subcommand verb after global options (`apt-get -y install`,
    // `apk --no-cache add`, `npm --prefix dir install`): skip at most
    // MAX_GLOBAL_OPTIONS options and their values, then require one of
    // `verbs`. Skipping options rather than scanning a window keeps a later
    // argument that merely equals a short verb (`npm run x`) from being read
    // as an install.
    let after = |eco: Eco, verbs: &[&str]| -> Option<(Eco, usize)> {
        let mut i = 1;
        for _ in 0..MAX_GLOBAL_OPTIONS {
            let Some(option) = toks.get(i).filter(|t| t.starts_with('-')) else {
                break;
            };
            i += if takes_value(eco, option) { 2 } else { 1 };
        }
        verbs.contains(toks.get(i)?).then_some((eco, i + 1))
    };
    // A verb within the next few words, for forms whose verb follows a
    // non-option word: `pip main install` (the flattened `pip.main([...])`),
    // `pacman --noconfirm -Syu`.
    let within = |eco: Eco, from: usize, words: usize, is_verb: fn(&str) -> bool| {
        toks.get(from..)?
            .iter()
            .take(words)
            .position(|t| is_verb(t))
            .map(|i| (eco, from + i + 1))
    };
    match tool_name(toks.first()?) {
        // One-shot remote runners fetch and run a package without declaring
        // it; the package follows immediately.
        "npx" | "bunx" => Some((Eco::Npm, 1)),
        "uvx" => Some((Eco::Pypi, 1)),
        "npm" | "pnpm" | "yarn" | "bun" => {
            if matches!(toks.get(1..3), Some(["global", "add"])) {
                Some((Eco::Npm, 3))
            } else {
                after(Eco::Npm, &["install", "i", "add", "a", "dlx", "x"])
            }
        }
        "pip" | "pip3" => within(Eco::Pypi, 1, 3, |t| t == "install"),
        "python" | "python3" if matches!(toks.get(1..3), Some(["-m", "pip"])) => {
            within(Eco::Pypi, 3, 3, |t| t == "install")
        }
        "pipx" => after(Eco::Pypi, &["install", "run"]),
        "pipenv" => after(Eco::Pypi, &["install"]),
        // Their `install` reads the manifest, so it stays declared-only.
        "poetry" | "pdm" | "rye" => after(Eco::Pypi, &["add"]),
        "uv" => match *toks.get(1)? {
            "pip" | "tool" if toks.get(2) == Some(&"install") => Some((Eco::Pypi, 3)),
            "add" => Some((Eco::Pypi, 2)),
            _ => None,
        },
        // The per-token prefix (`npm:`/`jsr:`) picks the registry.
        "deno" => after(Eco::Deno, &["install", "add", "cache", "run"]),
        "go" => after(Eco::Golang, &["get", "install"]),
        "cargo" => after(Eco::Cargo, &["install", "add", "binstall"]),
        "gem" => after(Eco::Gem, &["install"]),
        "bundle" | "bundler" => after(Eco::Gem, &["add"]),
        "conda" | "mamba" | "micromamba" => after(Eco::Conda, &["install"]),
        "composer" => match (toks.get(1), toks.get(2)) {
            (Some(&"require"), _) => Some((Eco::Composer, 2)),
            (Some(&"global"), Some(&"require")) => Some((Eco::Composer, 3)),
            _ => None,
        },
        "apt-get" | "apt" | "aptitude" => after(Eco::Debian, &["install"]),
        "apk" => after(Eco::Alpine, &["add"]),
        "dnf" | "dnf5" | "yum" | "microdnf" | "tdnf" => after(Eco::Fedora, &["install"]),
        "zypper" => after(Eco::OpenSuse, &["install", "in"]),
        "pacman" => within(Eco::Arch, 1, 4, is_pacman_sync),
        "yay" | "paru" | "pikaur" | "trizen" => within(Eco::Aur, 1, 4, is_pacman_sync),
        "brew" => after(Eco::Homebrew, &["install", "reinstall"]),
        "snap" => after(Eco::Snap, &["install"]),
        "pkg" => after(Eco::FreeBsd, &["install", "add"]),
        "pkgin" => after(Eco::NetBsd, &["install"]),
        "pkg_add" => Some((Eco::OpenBsd, 1)),
        // `dotnet add package <Id>`, `dotnet tool install -g <Id>`.
        "dotnet" => matches!(
            toks.get(1..3),
            Some(["add", "package"] | ["tool", "install"])
        )
        .then_some((Eco::NuGet, 3)),
        "nuget" => after(Eco::NuGet, &["install"]),
        "paket" => after(Eco::NuGet, &["add"]),
        "cpanm" => Some((Eco::Cpan, 1)),
        "cpan" => Some((
            Eco::Cpan,
            if toks.get(1) == Some(&"install") {
                2
            } else {
                1
            },
        )),
        "dart" | "flutter" => {
            matches!(toks.get(1..3), Some(["pub", "add"])).then_some((Eco::Pub, 3))
        }
        _ => None,
    }
}

/// Whether a pacman/AUR-helper flag requests an install sync (`-S`, `-Sy`,
/// `-Syu`, `-Su`, `-Sw`, `--sync`) rather than a search (`-Ss`) or query
/// (`-Si`, `-Sl`, …), so a `pacman -Ss <term>` search isn't read as an install.
fn is_pacman_sync(t: &str) -> bool {
    t == "-S"
        || t == "--sync"
        || t.starts_with("-Sy")
        || t.starts_with("-Su")
        || t.starts_with("-Sw")
}

#[cfg(test)]
mod tests {
    use super::super::references_in_bytes;
    use super::super::tests::purls;
    use super::*;

    /// The sorted, distinct PURLs discovered in `text`, read as `name`.
    fn sorted(text: &str, name: &str) -> Vec<String> {
        let mut found = purls(text.as_bytes(), name);
        found.sort();
        found.dedup();
        found
    }

    fn assert_contains_all(found: &[String], wanted: &[&str]) {
        for want in wanted {
            assert!(found.iter().any(|p| p == want), "want {want} in {found:?}");
        }
    }

    #[test]
    fn offsets_cite_the_evidence_where_it_sits() {
        let shell = "echo start\n\
                     apt-get install -y \\\n  curl\n\
                     # npm install left-pad\n\
                     npm install left-pad\n";
        let cited: Vec<(String, String)> = references_in_bytes(shell.as_bytes(), "install.sh")
            .references
            .into_iter()
            .filter(|r| r.kind == RefKind::Command)
            .map(|r| {
                let at = usize::try_from(r.offset.unwrap_or(u64::MAX)).unwrap_or(usize::MAX);
                let word = shell.get(at..).and_then(|t| t.split_whitespace().next());
                (format!("{:?}", r.locator), word.unwrap_or("").to_owned())
            })
            .collect();
        assert_eq!(
            cited,
            [
                (
                    r#"Purl("pkg:debian/curl")"#.to_owned(),
                    "apt-get".to_owned()
                ),
                (r#"Purl("pkg:npm/left-pad")"#.to_owned(), "npm".to_owned()),
            ]
        );
    }

    #[test]
    fn shell_pkg_manager_commands() {
        let found = sorted(
            "#!/bin/sh\n\
            sudo npm install evil-pkg\n\
            uv pip install requests==2.1 flask\n",
            "x.sh",
        );
        assert_eq!(
            found,
            [
                "pkg:npm/evil-pkg",
                "pkg:pypi/flask",
                "pkg:pypi/requests@2.1"
            ]
        );
    }

    #[test]
    fn recognizes_go_cargo_gem_composer_apt_installs() {
        let found = sorted(
            "#!/bin/sh\n\
            go get github.com/evil/mod@v1.2.3\n\
            go install github.com/evil/tool/cmd@v1.2.3\n\
            cargo install badcrate\n\
            gem install evilgem\n\
            composer require evil/pkg:^2.0\n\
            apt-get install -y sneakydeb nginx=1.18.0\n",
            "x.sh",
        );
        // A bare shell script has no FROM, so apt is Debian.
        assert_eq!(
            found,
            [
                "pkg:cargo/badcrate",
                "pkg:composer/evil/pkg",
                "pkg:debian/nginx@1.18.0",
                "pkg:debian/sneakydeb",
                "pkg:gem/evilgem",
                "pkg:golang/github.com/evil/mod@v1.2.3",
                "pkg:golang/github.com/evil/tool/cmd@v1.2.3",
            ]
        );
    }

    #[test]
    fn image_distro_reads_codenames_only_as_whole_words() {
        for (image, distro) in [
            ("python:3.12-slim", Some(Eco::Debian)),
            ("python:3.12-slim-bookworm", Some(Eco::Debian)),
            ("debian:sid", Some(Eco::Debian)),
            ("ubuntu:22.04", Some(Eco::Ubuntu)),
            ("buildpack-deps:jammy", Some(Eco::Ubuntu)),
            ("python:3.12-alpine3.19", Some(Eco::Alpine)),
            ("alpinelinux/build-base", Some(Eco::Alpine)),
            // Codenames inside other words are not codenames.
            ("sidekiq:7", None),
            ("mattermost/focalboard", None),
            ("lunarvim/lunarvim", None),
            ("ghcr.io/acme/dustbuster:1", None),
        ] {
            assert_eq!(image_distro(image), distro, "{image}");
        }
    }

    #[test]
    fn dockerfile_from_context_disambiguates_distro() {
        let df = "FROM ubuntu:22.04\n\
            RUN apt-get install -y nginx\n\
            FROM python:3.12-slim AS build\n\
            RUN apt-get install -y libpq-dev\n\
            FROM node:20-alpine\n\
            RUN apk add --no-cache curl\n\
            FROM cgr.dev/chainguard/wolfi-base\n\
            RUN apk add wget\n\
            FROM fedora:40\n\
            RUN dnf install -y httpd\n";
        assert_contains_all(
            &purls(df.as_bytes(), "Dockerfile"),
            &[
                "pkg:ubuntu/nginx",
                "pkg:debian/libpq-dev",
                "pkg:alpine/curl",
                "pkg:wolfi/wget",
                "pkg:fedora/httpd",
            ],
        );
    }

    #[test]
    fn exec_form_commands_keep_the_base_distro() {
        let df = "FROM ubuntu:24.04\n\
            RUN [\"apt-get\",\"install\",\"curl\"]\n\
            RUN [\"/bin/sh\",\"-c\",\"apt-get update && apt-get install -y jq\"]\n\
            FROM cgr.dev/chainguard/wolfi-base\n\
            RUN [\"apk\",\"add\",\"git\"]\n";
        let found = references_in_bytes(df.as_bytes(), "Dockerfile");
        let purls: Vec<_> = found
            .references
            .iter()
            .filter_map(|r| match &r.locator {
                filefacts::RefLocator::Purl(p) => Some((p.as_str(), r.offset)),
                _ => None,
            })
            .collect();
        let line = |needle: &str| df.find(needle).map(|at| at as u64);
        assert_eq!(
            purls,
            [
                ("pkg:ubuntu/curl", line("RUN [\"apt-get\"")),
                ("pkg:ubuntu/jq", line("RUN [\"/bin/sh\"")),
                ("pkg:wolfi/git", line("RUN [\"apk\"")),
            ]
        );
    }

    #[test]
    fn references_in_bytes_emits_distro_purls_from_dockerfile() {
        let df = "FROM node:20-alpine AS web\n\
            RUN apk add --no-cache curl\n\
            FROM ubuntu:24.04\n\
            RUN apt-get update && apt-get install -y nginx libpq-dev=16.1-1\n\
            RUN pip install requests && npm install -g typescript\n";
        assert_contains_all(
            &purls(df.as_bytes(), "Dockerfile"),
            &[
                "pkg:alpine/curl",
                "pkg:ubuntu/nginx",
                "pkg:ubuntu/libpq-dev@16.1-1",
                "pkg:pypi/requests",
                "pkg:npm/typescript",
            ],
        );
    }

    #[test]
    fn recognizes_arch_aur_bsd_and_store_installs() {
        let found = sorted(
            "#!/bin/sh\n\
            pacman -Syu --noconfirm base-devel\n\
            yay -S some-aur-helper\n\
            zypper -n install vim\n\
            brew install wget\n\
            snap install code\n\
            dotnet add package Newtonsoft.Json\n\
            cpanm Mojolicious\n\
            dart pub add http\n\
            pkg install curl\n\
            pkg_add tmux\n",
            "x.sh",
        );
        assert_contains_all(
            &found,
            &[
                "pkg:arch/base-devel",
                "pkg:aur/some-aur-helper",
                "pkg:opensuse/vim",
                "pkg:homebrew/wget",
                "pkg:snap/code",
                "pkg:nuget/Newtonsoft.Json",
                "pkg:cpan/Mojolicious",
                "pkg:pub/http",
                "pkg:freebsd/curl",
                "pkg:openbsd/tmux",
            ],
        );
    }

    #[test]
    fn pacman_search_is_not_an_install() {
        assert!(purls(b"pacman -Ss firefox\n", "x.sh").is_empty());
    }

    #[test]
    fn recognizes_install_with_options_before_subcommand() {
        let found = sorted(
            "#!/bin/sh\n\
            apt-get -y install nginx\n\
            apk --no-cache add curl\n\
            dnf -y install httpd\n\
            npm --global install typescript\n\
            npm --prefix ./dir install left-pad\n\
            apt-get -o Debug::pkgProblemResolver=yes install jq\n",
            "x.sh",
        );
        assert_eq!(
            found,
            [
                "pkg:alpine/curl",
                "pkg:debian/jq",
                "pkg:debian/nginx",
                "pkg:fedora/httpd",
                "pkg:npm/left-pad",
                "pkg:npm/typescript",
            ]
        );
    }

    #[test]
    fn recognizes_additional_manager_subcommands() {
        assert_contains_all(
            &sorted(
                "#!/bin/sh\n\
                python3 -m pip install flask\n\
                poetry add requests\n\
                pipenv install django\n\
                uv tool install ruff\n\
                yarn global add prettier\n\
                dotnet tool install -g dotnetsay\n\
                bundle add rails\n\
                composer global require phpunit/phpunit\n\
                cargo add serde\n",
                "x.sh",
            ),
            &[
                "pkg:pypi/flask",
                "pkg:pypi/requests",
                "pkg:pypi/django",
                "pkg:pypi/ruff",
                "pkg:npm/prettier",
                "pkg:nuget/dotnetsay",
                "pkg:gem/rails",
                "pkg:composer/phpunit/phpunit",
                "pkg:cargo/serde",
            ],
        );
    }

    #[test]
    fn option_values_are_not_packages() {
        for (script, want) in [
            ("conda install -c conda-forge numpy\n", "pkg:conda/numpy"),
            (
                "conda install --channel bioconda -n env samtools\n",
                "pkg:conda/samtools",
            ),
            ("gem install rails -v 7.1.0\n", "pkg:gem/rails"),
            ("gem install -v 1.2.3 nokogiri\n", "pkg:gem/nokogiri"),
            (
                "apt-get install -t bookworm-backports foo\n",
                "pkg:debian/foo",
            ),
            (
                "apt-get install -o Dpkg::Options::=--force-confnew foo\n",
                "pkg:debian/foo",
            ),
            ("cargo install --version 1.0 ripgrep\n", "pkg:cargo/ripgrep"),
            ("cargo add serde --features derive\n", "pkg:cargo/serde"),
            ("dnf install --repo fedora httpd\n", "pkg:fedora/httpd"),
            ("dnf --repo fedora install httpd\n", "pkg:fedora/httpd"),
            ("npm install --tag beta left-pad\n", "pkg:npm/left-pad"),
            ("pip install -e ./src requests\n", "pkg:pypi/requests"),
            (
                "pip install --editable vendor requests\n",
                "pkg:pypi/requests",
            ),
            ("apk add --virtual build-deps gcc\n", "pkg:alpine/gcc"),
            ("snap install --channel edge code\n", "pkg:snap/code"),
            ("nuget install Foo -Version 1.0.0\n", "pkg:nuget/Foo"),
        ] {
            assert_eq!(sorted(script, "x.sh"), [want], "{script:?}");
        }
    }

    #[test]
    fn deno_pipx_and_go_skip_global_options() {
        for (script, want) in [
            ("deno --quiet run npm:cowsay\n", "pkg:npm/cowsay"),
            (
                "deno -q install jsr:@evil/loader\n",
                "pkg:jsr/%40evil/loader",
            ),
            ("pipx --verbose install black\n", "pkg:pypi/black"),
            (
                "go -C tools install example.test/tool@v1\n",
                "pkg:golang/example.test/tool@v1",
            ),
            (
                "go -x get example.test/mod\n",
                "pkg:golang/example.test/mod",
            ),
        ] {
            assert_eq!(sorted(script, "x.sh"), [want], "{script:?}");
        }
    }

    #[test]
    fn an_option_is_never_a_command_name() {
        assert!(purls(b"echo -/npm install evil\n", "x.sh").is_empty());
        assert!(purls(b"run -/npm install evil\n", "x.sh").is_empty());
        assert!(purls(b"x --npm install evil\n", "x.sh").is_empty());
    }

    #[test]
    fn recognizes_deno_specifiers() {
        let found = sorted(
            "#!/bin/sh\n\
            deno add npm:cowsay@1.5.0\n\
            deno install jsr:@evil/loader\n\
            deno run -A npm:@scope/payload\n\
            deno run https://evil.test/mod.ts\n\
            deno run ./local.ts\n",
            "x.sh",
        );
        assert_eq!(
            found,
            [
                "pkg:jsr/%40evil/loader",
                "pkg:npm/%40scope/payload",
                "pkg:npm/cowsay@1.5.0"
            ]
        );
    }

    #[test]
    fn deno_run_passes_its_script_arguments_through() {
        assert_eq!(
            sorted(
                "deno run main.ts npm:not-a-dep\n\
                deno run -A npm:runs-this\n\
                deno run --config deno.json jsr:@scope/runs-too\n",
                "run.sh"
            ),
            ["pkg:jsr/%40scope/runs-too", "pkg:npm/runs-this"]
        );
    }

    #[test]
    fn recognizes_conda_installs() {
        assert_eq!(
            sorted(
                "#!/bin/sh\n\
                conda install -y numpy=1.21\n\
                mamba install conda-forge::evilpkg\n",
                "x.sh"
            ),
            ["pkg:conda/evilpkg", "pkg:conda/numpy@1.21"]
        );
    }

    #[test]
    fn one_shot_runners_run_one_package_and_pass_it_arguments() {
        for (text, want) in [
            (
                "npx create-react-app my-app\n",
                vec!["pkg:npm/create-react-app"],
            ),
            ("npx -y cowsay hello\n", vec!["pkg:npm/cowsay"]),
            (
                "npx -p typescript -p ts-node tsc --init\n",
                vec!["pkg:npm/typescript", "pkg:npm/ts-node"],
            ),
            ("npx --package=typescript tsc\n", vec!["pkg:npm/typescript"]),
            ("pnpm dlx degit user/repo dir\n", vec!["pkg:npm/degit"]),
            ("pnpm dlx sketchy-tool\n", vec!["pkg:npm/sketchy-tool"]),
            ("uvx ruff check src\n", vec!["pkg:pypi/ruff"]),
            ("uvx evilcli\n", vec!["pkg:pypi/evilcli"]),
            (
                "uvx --from httpie http example.com\n",
                vec!["pkg:pypi/httpie"],
            ),
            (
                "uvx --with requests black .\n",
                vec!["pkg:pypi/requests", "pkg:pypi/black"],
            ),
            ("pipx run black src\n", vec!["pkg:pypi/black"]),
        ] {
            assert_eq!(purls(text.as_bytes(), "a.sh"), want, "{text:?}");
        }
        // An install still names every package.
        assert_eq!(
            purls(b"npm install a b\n", "a.sh"),
            ["pkg:npm/a", "pkg:npm/b"]
        );
    }

    #[test]
    fn shell_syntax_around_a_command_is_not_a_package() {
        assert_eq!(
            sorted(
                "GEN=$(go install example.test/tool/cmd/gen)\n\
                go get -u $(go list ./...)\n\
                go install example.test/quiet@latest 2>/dev/null\n\
                for pm in apt-get dnf pkg_add port; do echo \"$pm\"; done\n\
                ruby -e 'Kernel.send(:system, \"bun install wrapped-pkg\")'\n",
                "setup.sh"
            ),
            [
                "pkg:golang/example.test/quiet@latest",
                "pkg:golang/example.test/tool/cmd/gen",
                "pkg:npm/wrapped-pkg",
            ]
        );
    }

    #[test]
    fn shell_comments_echo_and_option_values_are_not_packages() {
        for (name, text, expected) in [
            (
                "x.sh",
                "# npm install documented\nnpm install --prefix directory --loglevel silent real-pkg # explanatory words",
                "pkg:npm/real-pkg",
            ),
            (
                "x.sh",
                "pip install --index-url https://registry.example.test/simple --trusted-host registry.example.test real-pkg",
                "pkg:pypi/real-pkg",
            ),
            (
                "x.sh",
                "pip install -r requirements.txt realpkg https://x.test/y.whl",
                "pkg:pypi/realpkg",
            ),
            (
                "Dockerfile",
                "FROM alpine\n# npm install example\nRUN echo npm install documented\nRUN npm install real-pkg",
                "pkg:npm/real-pkg",
            ),
        ] {
            assert_eq!(purls(text.as_bytes(), name), [expected], "{name}: {text}");
        }
    }

    #[test]
    fn quoted_words_and_exec_form_commands_are_found() {
        for (text, name) in [
            ("npm install \"evil\"\n", "install.sh"),
            ("pip install 'evil'\n", "install.sh"),
            (
                "FROM node:20\nRUN [\"npm\",\"install\",\"evil\"]\n",
                "Dockerfile",
            ),
            (
                "FROM node:20\nRUN [\"/bin/sh\", \"-c\", \"npm i evil\"]\n",
                "Dockerfile",
            ),
            ("FROM node:20\nCMD [\"npx\", \"evil\"]\n", "Dockerfile"),
        ] {
            let found = purls(text.as_bytes(), name);
            assert!(
                found.iter().any(|p| p.ends_with("/evil")),
                "{text:?}: {found:?}"
            );
        }
    }

    #[test]
    fn windows_tool_paths_are_recognized() {
        assert_eq!(tool_name(r"C:\Python312\Scripts\pip.exe"), "pip");
        assert_eq!(tool_name("npm.CMD"), "npm");
        assert_eq!(tool_name("npx.ps1"), "npx");
        assert_eq!(tool_name("curl"), "curl");
        assert_eq!(tool_name("x.exe.tar"), "x.exe.tar");
        assert_eq!(tool_name("é.ex"), "é.ex", "no slicing inside a character");
    }

    #[test]
    fn path_qualified_tools_are_recognized() {
        let found = purls(
            b"/opt/venv/bin/pip install x\n./node_modules/.bin/npm i y\n",
            "install.sh",
        );
        assert_eq!(found, ["pkg:pypi/x", "pkg:npm/y"]);
        // The program a URL names is not a program.
        assert!(purls(b"wget https://example.com/bin/npm install z\n", "a.sh").is_empty());
    }
}
