//! Package ecosystems a command can install from, and the PURL a command-line
//! token names in each.

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

/// `pkg:<eco>/<name>` for an OS-package token: strips an apt architecture
/// qualifier (`libc6:amd64`) and keeps only a clean `name=version` pin (apt,
/// apk); a range constraint (`>=`, `<`, `~`) keeps just the name.
fn distro_purl_token(eco: Eco, tok: &str) -> Option<String> {
    let eco = eco.label();
    let tok = tok.split(':').next().unwrap_or(tok);
    if let Some((name, ver)) = tok.split_once('=')
        && !name.is_empty()
        && !name.ends_with(['<', '>', '~', '!'])
        && ver.starts_with(|c: char| c.is_ascii_digit())
    {
        return Some(format!("pkg:{eco}/{name}@{ver}"));
    }
    let name = tok.split(['=', '<', '>', '~']).next().unwrap_or(tok);
    (!name.is_empty()).then(|| format!("pkg:{eco}/{name}"))
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
    let first = tok.chars().next().unwrap_or(' ');
    if !(first.is_ascii_alphanumeric() || first == '@') || tok.contains("://") {
        return false;
    }
    if tok.contains('/') {
        let slash_ok = match eco {
            Eco::Npm => tok.starts_with('@') && tok.matches('/').count() == 1,
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

/// `pkg:npm/...` from a command-line token (`foo`, `foo@1.2`, `@s/n`,
/// `@s/n@1.2`). `None` if the name is empty.
pub(super) fn npm_purl_token(tok: &str) -> Option<String> {
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
pub(super) fn pypi_purl_token(tok: &str) -> Option<String> {
    // Strip an `[extras]` span anywhere, keeping any trailing version.
    let base = match (tok.find('['), tok.find(']')) {
        (Some(o), Some(c)) if c > o => format!("{}{}", &tok[..o], &tok[c + 1..]),
        _ => tok.to_owned(),
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
