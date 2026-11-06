//! Package ecosystems a command can install from, and the PURL a command-line
//! token names in each.

use std::borrow::Cow;

use filefacts::RefLocator;

/// A package ecosystem an install command or import names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Eco {
    Npm,
    Pypi,
    /// Deno specifiers, which name an npm or JSR package by prefix.
    Deno,
    Golang,
    Cargo,
    Gem,
    Conda,
    Composer,
    Debian,
    Ubuntu,
    Alpine,
    Wolfi,
    Fedora,
    OpenSuse,
    Arch,
    Aur,
    Homebrew,
    Snap,
    FreeBsd,
    NetBsd,
    OpenBsd,
    NuGet,
    Cpan,
    Pub,
}

impl Eco {
    /// The PURL type, which is also this ecosystem's name in logs.
    const fn label(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Pypi => "pypi",
            Self::Deno => "deno",
            Self::Golang => "golang",
            Self::Cargo => "cargo",
            Self::Gem => "gem",
            Self::Conda => "conda",
            Self::Composer => "composer",
            Self::Debian => "debian",
            Self::Ubuntu => "ubuntu",
            Self::Alpine => "alpine",
            Self::Wolfi => "wolfi",
            Self::Fedora => "fedora",
            Self::OpenSuse => "opensuse",
            Self::Arch => "arch",
            Self::Aur => "aur",
            Self::Homebrew => "homebrew",
            Self::Snap => "snap",
            Self::FreeBsd => "freebsd",
            Self::NetBsd => "netbsd",
            Self::OpenBsd => "openbsd",
            Self::NuGet => "nuget",
            Self::Cpan => "cpan",
            Self::Pub => "pub",
        }
    }

    /// This ecosystem as installed on `distro`: `apt` serves Ubuntu there and
    /// Debian elsewhere, `apk` Wolfi there and Alpine elsewhere. Every other
    /// ecosystem is the same on any distro.
    pub(super) fn on(self, distro: Option<Self>) -> Self {
        match (self, distro) {
            (Self::Debian, Some(Self::Ubuntu)) => Self::Ubuntu,
            (Self::Alpine, Some(Self::Wolfi)) => Self::Wolfi,
            (eco, _) => eco,
        }
    }
}

/// A command argument as a package locator, or `None` if it is a flag, file,
/// path, or URL rather than a named package.
pub(super) fn pm_token_locator(eco: Eco, tok: &str) -> Option<RefLocator> {
    if eco == Eco::Npm
        && let Some(locator) = npm_github_locator(tok)
    {
        return Some(locator);
    }
    // A variable is a value this text does not hold. In the version
    // (`kind@v$KIND_VERSION`, `pkg==$V`) it leaves a known name; anywhere in
    // the name (`$PKG`, `mingw-${arch}-gcc`) there is no package to name.
    let tok = match tok.find(['$', '`']) {
        Some(at) => {
            let head = &tok[..at];
            let version_at = head.rfind(['@', '=']).filter(|&at| at > 0)?;
            head[..version_at].trim_end_matches('=')
        }
        None => tok,
    };
    // Go's `/...` pattern names every package under a path; the path is the
    // package to report (`golang.org/x/tools/cmd/...@latest`).
    let pattern;
    let tok = if eco == Eco::Golang && tok.contains("/...") {
        pattern = tok.replacen("/...", "", 1);
        pattern.as_str()
    } else {
        tok
    };
    // Every builder below pastes the token into a PURL, where these would
    // forge a qualifier (`download_url`, `checksum`), a subpath, or an
    // escape: attacker bytes filed under a genuine package's name. Quotes,
    // parentheses, braces and backslashes are shell or code syntax a word
    // kept, never part of a package name.
    if tok.contains(['?', '#', '%', '&', '"', '\'', '(', ')', '{', '}', '\\'])
        || !looks_like_package(eco, tok)
    {
        return None;
    }
    let purl = match eco {
        Eco::Npm => npm_purl_token(tok)?,
        Eco::Pypi => pypi_purl_token(tok)?,
        Eco::Golang | Eco::Cargo => version_purl_token(eco, tok)?,
        Eco::Conda => conda_purl_token(tok)?,
        Eco::Deno => deno_purl_token(tok)?,
        // Composer names are always `vendor/name`; a `:<constraint>` is a
        // range, not a fetchable pin.
        Eco::Composer => {
            let name = tok.split(':').next().unwrap_or(tok);
            name.contains('/').then(|| format!("pkg:composer/{name}"))?
        }
        Eco::Debian
        | Eco::Ubuntu
        | Eco::Alpine
        | Eco::Wolfi
        | Eco::Fedora
        | Eco::OpenSuse
        | Eco::Arch
        | Eco::Aur
        | Eco::FreeBsd
        | Eco::NetBsd
        | Eco::OpenBsd => distro_purl_token(eco, tok)?,
        // A bare name: a version arrives as a separate flag, or after a
        // `:`/`=`/`@` that is dropped.
        Eco::Homebrew | Eco::Snap | Eco::Pub => {
            named_purl(eco, tok.split([':', '=', '@']).next().unwrap_or(tok))?
        }
        // NuGet keeps its `.`, CPAN its `::`.
        Eco::Gem | Eco::NuGet | Eco::Cpan => named_purl(eco, tok)?,
    };
    Some(RefLocator::Purl(purl))
}

/// A GitHub source package passed to npm/npx is an executable package
/// reference, not an npm name and not merely repository metadata.
fn npm_github_locator(token: &str) -> Option<RefLocator> {
    let spec = token
        .strip_prefix("github:")
        .or_else(|| token.strip_prefix("https://github.com/"))
        .or_else(|| token.strip_prefix("git+https://github.com/"))?;
    let (repo, revision) = spec
        .split_once('#')
        .map_or((spec, None), |(r, v)| (r, Some(v)));
    let (owner, name) = repo.split_once('/')?;
    let name = name.strip_suffix(".git").unwrap_or(name);
    let safe = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
            && s != "."
            && s != ".."
    };
    if !safe(owner) || !safe(name) {
        return None;
    }
    // A revision that can't be spelled safely still names the repository.
    let revision = revision.filter(|v| safe(v));
    Some(RefLocator::Purl(match revision {
        Some(revision) => format!("pkg:github/{owner}/{name}@{revision}"),
        None => format!("pkg:github/{owner}/{name}"),
    }))
}

/// `pkg:<eco>/<name>[@<version>]` for an OS-package token: `name[:arch]`
/// with an optional `=version` pin (apt, apk). The architecture qualifier
/// (`libc6:amd64`) is dropped from the name; a version keeps its epoch
/// (`1:2.30-1`). A range constraint (`>=`, `<`, `~`) or a wildcard version
/// (`=1.2*`) keeps just the name.
fn distro_purl_token(eco: Eco, tok: &str) -> Option<String> {
    let eco = eco.label();
    let (spec, version) = tok
        .split_once('=')
        .map_or((tok, None), |(spec, version)| (spec, Some(version)));
    let name = spec.split([':', '<', '>', '~', '!']).next().unwrap_or(spec);
    if name.is_empty() {
        return None;
    }
    match version {
        Some(version)
            if !spec.contains(['<', '>', '~', '!'])
                && version.starts_with(|c: char| c.is_ascii_digit())
                && !version.contains('*') =>
        {
            Some(format!("pkg:{eco}/{name}@{version}"))
        }
        _ => Some(format!("pkg:{eco}/{name}")),
    }
}

/// `pkg:<eco>/<name>`, or `None` for an empty name.
fn named_purl(eco: Eco, name: &str) -> Option<String> {
    (!name.is_empty()).then(|| format!("pkg:{}/{name}", eco.label()))
}

/// Whether a command argument looks like a named package rather than a flag, a
/// URL, a path, or a file. Slashes are ecosystem-specific: npm allows one in a
/// `@scope/name`, Go/Composer names are `host/path` or `vendor/name`, the rest
/// reject `/` (it means a path). A file extension means a file, except where
/// the ecosystem's names commonly carry it (npm's `chart.js`).
fn looks_like_package(eco: Eco, tok: &str) -> bool {
    const FILE_EXT: &[&str] = &[
        ".txt", ".whl", ".toml", ".lock", ".cfg", ".tar", ".gz", ".zip", ".py", ".js",
    ];
    if !tok.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '@') || tok.contains("://") {
        return false;
    }
    if tok.contains('/') {
        let slash_ok = match eco {
            // A scope's slash, in the package or the one an alias installs
            // (`alias@npm:@scope/name`).
            Eco::Npm => {
                let spec = tok.split_once("@npm:").map_or(tok, |(_, target)| target);
                spec.starts_with('@') && spec.matches('/').count() == 1
            }
            // Deno `jsr:@scope/name` and `npm:@scope/pkg` specifiers carry a
            // slash; URL specifiers are rejected above.
            Eco::Golang | Eco::Composer | Eco::Deno => true,
            _ => false,
        };
        if !slash_ok {
            return false;
        }
    }
    !FILE_EXT
        .iter()
        .filter(|&&ext| !(eco == Eco::Npm && ext == ".js"))
        .any(|ext| tok.ends_with(ext))
}

/// `pkg:<eco>/<name>[@<version>]` from a `name@version` token. The name keeps
/// its real case (Go module paths are case-sensitive).
fn version_purl_token(eco: Eco, tok: &str) -> Option<String> {
    let (name, version) = tok
        .split_once('@')
        .map_or((tok, None), |(n, v)| (n, Some(v)));
    if name.is_empty() {
        return None;
    }
    let eco = eco.label();
    Some(match version {
        Some(v) if !v.is_empty() => format!("pkg:{eco}/{name}@{v}"),
        _ => format!("pkg:{eco}/{name}"),
    })
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
/// is a plain fetch the URL scan reports, not a registry package.
fn deno_purl_token(tok: &str) -> Option<String> {
    if let Some(spec) = tok.strip_prefix("npm:") {
        npm_purl_token(without_subpath(spec))
    } else if let Some(spec) = tok.strip_prefix("jsr:") {
        jsr_purl_token(without_subpath(spec))
    } else {
        None
    }
}

/// A Deno package specifier without its module subpath: `pkg@1/sub` → `pkg@1`,
/// `@scope/pkg/sub` → `@scope/pkg`. The subpath names a file inside the
/// package, not another package.
fn without_subpath(spec: &str) -> &str {
    let segments = if spec.starts_with('@') { 2 } else { 1 };
    spec.match_indices('/')
        .nth(segments - 1)
        .map_or(spec, |(at, _)| &spec[..at])
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

/// `pkg:npm/...` from a command-line token (`foo`, `foo@1.2.3`, `@s/n`,
/// `@s/n@1.2.3`). An alias (`foo@npm:bar@1.0.0`) installs its target, `bar`.
/// Only an exact version is kept: a range or tag (`^1.2`, `latest`) is
/// resolved by the registry at install time, so it pins nothing. `None` for
/// an empty name or a scope without one (`@scope`).
pub(super) fn npm_purl_token(tok: &str) -> Option<String> {
    // The name ends at the first `@` past a leading scope `@`.
    fn split(spec: &str) -> (&str, Option<&str>) {
        match spec.get(1..).and_then(|rest| rest.find('@')) {
            Some(i) => (&spec[..=i], spec.get(i + 2..)),
            None => (spec, None),
        }
    }
    let (mut name, mut version) = split(tok);
    if let Some(target) = version.and_then(|v| v.strip_prefix("npm:")) {
        (name, version) = split(target);
    }
    let base = match name.strip_prefix('@') {
        Some(scoped) => {
            let (scope, pkg) = scoped.split_once('/')?;
            if scope.is_empty() || pkg.is_empty() {
                return None;
            }
            format!("pkg:npm/%40{scope}/{pkg}")
        }
        None if !name.is_empty() => format!("pkg:npm/{name}"),
        None => return None,
    };
    Some(match version.filter(|v| is_exact_version(v)) {
        Some(version) => format!("{base}@{version}"),
        None => base,
    })
}

/// Whether `version` names one release (`1.2.3`, `2.0`, `1.0.0-rc.1`)
/// rather than a range, wildcard or tag.
fn is_exact_version(version: &str) -> bool {
    version.starts_with(|c: char| c.is_ascii_digit())
        && version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'))
        && !version
            .split('.')
            .any(|part| part.eq_ignore_ascii_case("x"))
}

/// `pkg:pypi/...` from a command-line token, stripping extras (`pkg[x]`) and
/// version constraints: only an `==` (or `===`) pin of one version, not a
/// wildcard (`==1.*`), becomes a PURL version.
pub(super) fn pypi_purl_token(tok: &str) -> Option<String> {
    // Strip an `[extras]` span anywhere, keeping any trailing version.
    let base: Cow<'_, str> = match (tok.find('['), tok.find(']')) {
        (Some(o), Some(c)) if c > o => format!("{}{}", &tok[..o], &tok[c + 1..]).into(),
        _ => tok.into(),
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
        .map(|(_, v)| {
            let v = v.strip_prefix('=').unwrap_or(v);
            v.split([',', ';', ' ']).next().unwrap_or(v)
        })
        .filter(|v| !v.is_empty() && !v.contains('*'));
    Some(match ver {
        Some(v) => format!("pkg:pypi/{name}@{v}"),
        None => format!("pkg:pypi/{name}"),
    })
}

#[cfg(test)]
mod tests {
    use super::super::tests::purls;
    use super::*;

    #[test]
    fn scoped_and_versioned_tokens() {
        assert_eq!(
            npm_purl_token("@acme/tool").as_deref(),
            Some("pkg:npm/%40acme/tool")
        );
        assert_eq!(
            npm_purl_token("evil@2.0").as_deref(),
            Some("pkg:npm/evil@2.0")
        );
        assert_eq!(
            pypi_purl_token("requests[security]==2.1").as_deref(),
            Some("pkg:pypi/requests@2.1")
        );
    }

    #[test]
    fn npm_aliases_install_their_target_and_ranges_pin_nothing() {
        for (tok, want) in [
            ("foo@npm:evil-pkg@1.0.0", Some("pkg:npm/evil-pkg@1.0.0")),
            ("foo@npm:@evil/pkg", Some("pkg:npm/%40evil/pkg")),
            ("foo@^1.2.3", Some("pkg:npm/foo")),
            ("foo@~1.2", Some("pkg:npm/foo")),
            ("foo@1.x", Some("pkg:npm/foo")),
            ("foo@latest", Some("pkg:npm/foo")),
            ("foo@>=1", Some("pkg:npm/foo")),
            ("foo@1.0.0-rc.1", Some("pkg:npm/foo@1.0.0-rc.1")),
            ("@scope/n@2.0.0", Some("pkg:npm/%40scope/n@2.0.0")),
            ("@scope", None),
            ("@scope/", None),
            ("@/n", None),
        ] {
            assert_eq!(
                pm_token_locator(Eco::Npm, tok),
                want.map(|p| RefLocator::Purl(p.into())),
                "{tok}"
            );
        }
    }

    #[test]
    fn versions_keep_their_epoch_and_drop_wildcards() {
        for (eco, tok, want) in [
            (Eco::Debian, "libfoo=1:2.30-1", "pkg:debian/libfoo@1:2.30-1"),
            (Eco::Debian, "libc6:amd64=2.31-0", "pkg:debian/libc6@2.31-0"),
            (Eco::Debian, "libc6:amd64", "pkg:debian/libc6"),
            (Eco::Debian, "nginx=1.18*", "pkg:debian/nginx"),
            (Eco::Alpine, "curl>=7.0", "pkg:alpine/curl"),
            (Eco::Alpine, "curl~7.0", "pkg:alpine/curl"),
            (Eco::Alpine, "curl=7.0-r0", "pkg:alpine/curl@7.0-r0"),
            (Eco::Pypi, "foo==1.*", "pkg:pypi/foo"),
            (Eco::Pypi, "foo===1.0", "pkg:pypi/foo@1.0"),
            (Eco::Pypi, "foo==1.0", "pkg:pypi/foo@1.0"),
        ] {
            assert_eq!(
                pm_token_locator(eco, tok),
                Some(RefLocator::Purl(want.into())),
                "{tok}"
            );
            assert!(crate::purl::Purl::parse(want).is_ok(), "{want}");
        }
    }

    #[test]
    fn install_tokens_cannot_forge_purl_qualifiers_or_subpaths() {
        let script = b"npm install foo@1.0?download_url=https:%2F%2Fevil.test%2Fx.tgz\n\
            gem install bar?checksum=sha256:00\n\
            pip install baz==1#sub\n\
            apt-get install qux=1%3Fx\n\
            npm install plain@1.0\n";
        assert_eq!(purls(script, "install.sh"), ["pkg:npm/plain@1.0"]);
    }

    #[test]
    fn a_backslash_is_never_part_of_a_package() {
        assert_eq!(pm_token_locator(Eco::Npm, "a\\nnpm"), None);
        assert_eq!(pm_token_locator(Eco::Pypi, "x\\"), None);
    }

    #[test]
    fn npm_names_may_end_in_js_but_files_do_not_become_packages() {
        assert_eq!(
            purls(
                b"npm install chart.js highlight.js bn.js decimal.js\n",
                "a.sh"
            ),
            [
                "pkg:npm/chart.js",
                "pkg:npm/highlight.js",
                "pkg:npm/bn.js",
                "pkg:npm/decimal.js"
            ]
        );
        assert!(purls(b"pip install setup.py\n", "a.sh").is_empty());
        assert!(purls(b"pip install -r requirements.txt\n", "a.sh").is_empty());
    }

    #[test]
    fn an_unsafe_github_revision_still_names_the_repository() {
        assert_eq!(
            purls(b"npx github:owner/tool#feature/x\n", "run.sh"),
            ["pkg:github/owner/tool"]
        );
    }

    #[test]
    fn deno_specifiers_drop_their_module_subpath() {
        assert_eq!(
            purls(
                b"deno install npm:foo@1.2/bin/cli npm:@s/n/sub jsr:@std/path@1/posix\n",
                "a.sh",
            ),
            ["pkg:npm/foo@1.2", "pkg:npm/%40s/n", "pkg:jsr/%40std/path@1"],
        );
    }

    #[test]
    fn a_variable_drops_its_version_or_its_whole_name() {
        let mut found = purls(
            b"go install example.test/kind@v$KIND_VERSION\n\
            pip install tool==$TOOL_VERSION\n\
            pacman -S mingw-w64-${arch}-gcc\n\
            npm i $PKG\n",
            "setup.sh",
        );
        found.sort();
        assert_eq!(found, ["pkg:golang/example.test/kind", "pkg:pypi/tool"]);
    }

    #[test]
    fn a_go_package_pattern_names_its_path() {
        assert_eq!(
            purls(b"go install example.test/x/cmd/...@latest\n", "setup.sh"),
            ["pkg:golang/example.test/x/cmd@latest"]
        );
    }

    #[test]
    fn distro_ecosystems_follow_the_base_image() {
        assert_eq!(Eco::Debian.on(Some(Eco::Ubuntu)), Eco::Ubuntu);
        assert_eq!(Eco::Debian.on(Some(Eco::Alpine)), Eco::Debian);
        assert_eq!(Eco::Alpine.on(Some(Eco::Wolfi)), Eco::Wolfi);
        assert_eq!(Eco::Fedora.on(Some(Eco::Ubuntu)), Eco::Fedora);
        assert_eq!(Eco::Alpine.on(None), Eco::Alpine);
    }
}
