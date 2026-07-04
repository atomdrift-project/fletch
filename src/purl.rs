//! Recognize the package a download URL points at, as a PURL.
//!
//! This is the inverse of the [`fetch`](crate::fetch) resolver: given a concrete
//! artifact URL from a public registry, recover `pkg:<type>/<name>@<version>`.
//! It's a pure, offline, host-directed string mapping — no network, no guessing
//! beyond the well-known registry URL shapes. An unrecognized host or path
//! yields `None`; callers treat that as "identity unknown" and fall back to the
//! bytes (a hash lookup, a full scan).
//!
//! The two directions are deliberately tested against each other: for the
//! ecosystems whose download URL is a pure `name+version` function
//! (npm, crates.io, RubyGems, Go module proxy, GitHub archives), a PURL routed
//! through [`fetch::resolve`](crate::fetch::resolve) and back through
//! [`url_to_purl`] must return the original. The asymmetric ecosystems — PyPI
//! (its `files.pythonhosted.org` path carries an undrivable content hash) and
//! platform-tagged gems — cannot round-trip and are covered forward-only.

/// Map a registry artifact URL to its PURL, or `None` when the host/path isn't a
/// recognized package download.
///
/// Recognized: npm (`registry.npmjs.org`, `registry.yarnpkg.com`), crates.io
/// (`static.crates.io`, the `crates.io` API download), PyPI
/// (`files.pythonhosted.org`), RubyGems (`rubygems.org`), the Go module proxy
/// (`proxy.golang.org`), NuGet (`api.nuget.org`), Maven Central
/// (`repo1.maven.org`, `repo.maven.apache.org`), and GitHub archives
/// (`codeload.github.com`).
#[must_use]
pub fn url_to_purl(url: &str) -> Option<String> {
    let (host, path) = split_host_path(url)?;
    let host = host.to_ascii_lowercase();
    match host.as_str() {
        "registry.npmjs.org" | "registry.yarnpkg.com" => npm(path),
        "static.crates.io" | "crates.io" => cargo(path),
        "files.pythonhosted.org" => pypi(path),
        "rubygems.org" => gem(path),
        "proxy.golang.org" => golang(path),
        "api.nuget.org" => nuget(path),
        "repo1.maven.org" | "repo.maven.apache.org" => maven(path),
        "codeload.github.com" => github(path),
        _ => None,
    }
}

/// Split `scheme://host[:port]/path?query` into `(host, path)`, dropping the
/// scheme, any port, and any `?query`/`#fragment`. The returned path has no
/// leading slash. `None` if the input isn't an `http(s)` URL.
fn split_host_path(url: &str) -> Option<(&str, &str)> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let host = authority.split(':').next().unwrap_or(authority);
    let path = path.split(['?', '#']).next().unwrap_or(path);
    Some((host, path))
}

/// npm: `{name}/-/{base}-{version}.tgz`, where `name` may be `@scope/pkg` and
/// `base` is its last segment. The scope `@` is `%40`-encoded in the PURL.
fn npm(path: &str) -> Option<String> {
    let (name, file) = path.split_once("/-/")?;
    let stem = file.strip_suffix(".tgz")?;
    let base = name.rsplit('/').next()?;
    let version = stem.strip_prefix(&format!("{base}-"))?;
    Some(format!("pkg:npm/{}@{version}", name.replace('@', "%40")))
}

/// crates.io: the CDN path `crates/{name}/{name}-{version}.crate`, or the API
/// download `api/v1/crates/{name}/{version}/download`.
fn cargo(path: &str) -> Option<String> {
    if let Some(rest) = path.strip_prefix("crates/") {
        let (name, file) = rest.split_once('/')?;
        let version = file
            .strip_prefix(&format!("{name}-"))?
            .strip_suffix(".crate")?;
        return Some(format!("pkg:cargo/{name}@{version}"));
    }
    let rest = path.strip_prefix("api/v1/crates/")?;
    let mut segs = rest.split('/');
    let name = segs.next()?;
    let version = segs.next()?;
    (segs.next() == Some("download")).then(|| format!("pkg:cargo/{name}@{version}"))
}

/// PyPI: parse the filename. Wheels
/// (`{dist}-{version}-{python}-{abi}-{platform}.whl`) carry name and version as
/// their first two `-`-separated fields; sdists (`{name}-{version}.tar.gz`) put
/// the version last. Names are normalized per PEP 503.
fn pypi(path: &str) -> Option<String> {
    let file = path.rsplit('/').next()?;
    if let Some(stem) = file.strip_suffix(".whl") {
        let mut fields = stem.splitn(3, '-');
        let dist = fields.next()?;
        let version = fields.next()?;
        return Some(format!("pkg:pypi/{}@{version}", normalize_pypi(dist)));
    }
    let stem = strip_any_suffix(file, &[".tar.gz", ".tar.bz2", ".tar.xz", ".zip", ".tgz"])?;
    let (name, version) = stem.rsplit_once('-')?;
    starts_with_digit(version).then(|| format!("pkg:pypi/{}@{version}", normalize_pypi(name)))
}

/// RubyGems: `downloads/{name}-{version}.gem` (or the legacy `gems/` prefix).
/// Platform-tagged gems (`name-version-platform.gem`) don't round-trip and
/// resolve to `None` — the caller falls back to the hash path.
fn gem(path: &str) -> Option<String> {
    let rest = path
        .strip_prefix("downloads/")
        .or_else(|| path.strip_prefix("gems/"))?;
    let stem = rest.strip_suffix(".gem")?;
    let (name, version) = stem.rsplit_once('-')?;
    starts_with_digit(version).then(|| format!("pkg:gem/{name}@{version}"))
}

/// Go module proxy: `{module}/@v/{version}.zip`, both fields `!`-escaped for
/// uppercase (the GOPROXY case-encoding). Only the `.zip` artifact carries the
/// module bytes; `.mod`/`.info` metadata fetches are not packages.
fn golang(path: &str) -> Option<String> {
    let (module, tail) = path.split_once("/@v/")?;
    let version = tail.strip_suffix(".zip")?;
    Some(format!(
        "pkg:golang/{}@{}",
        goproxy_unescape(module),
        goproxy_unescape(version)
    ))
}

/// NuGet flat container: `v3-flatcontainer/{id}/{version}/{id}.{version}.nupkg`.
/// The URL lowercases the id; the recovered PURL carries that lowercased form.
fn nuget(path: &str) -> Option<String> {
    let rest = path.strip_prefix("v3-flatcontainer/")?;
    let mut segs = rest.split('/');
    let id = segs.next()?;
    let version = segs.next()?;
    Some(format!("pkg:nuget/{id}@{version}"))
}

/// Maven: `maven2/{group/as/path}/{artifact}/{version}/{file}`. The group is the
/// dotted join of every segment before the trailing `artifact/version/file`.
fn maven(path: &str) -> Option<String> {
    let rest = path.strip_prefix("maven2/")?;
    let segs: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
    let [group @ .., artifact, version, _file] = segs.as_slice() else {
        return None;
    };
    if group.is_empty() {
        return None;
    }
    Some(format!("pkg:maven/{}/{artifact}@{version}", group.join(".")))
}

/// GitHub source archive: `{owner}/{repo}/{tar.gz|zip}/{ref}`.
fn github(path: &str) -> Option<String> {
    let segs: Vec<&str> = path.split('/').collect();
    let [owner, repo, kind, reference, ..] = segs.as_slice() else {
        return None;
    };
    matches!(*kind, "tar.gz" | "zip")
        .then(|| format!("pkg:github/{owner}/{repo}@{reference}"))
}

/// Reverse [`fetch::goproxy_escape`](crate::fetch): `!x` → uppercase `X`.
fn goproxy_unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '!' {
            if let Some(next) = chars.next() {
                out.push(next.to_ascii_uppercase());
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Normalize a PyPI project name per PEP 503: lowercase, and collapse any run of
/// `-`, `_`, or `.` to a single `-`.
fn normalize_pypi(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut prev_sep = false;
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !prev_sep {
                out.push('-');
                prev_sep = true;
            }
        } else {
            out.push(c.to_ascii_lowercase());
            prev_sep = false;
        }
    }
    out
}

fn starts_with_digit(s: &str) -> bool {
    s.bytes().next().is_some_and(|b| b.is_ascii_digit())
}

/// Strip the first matching suffix from `s`, or `None` if none match.
fn strip_any_suffix<'a>(s: &'a str, suffixes: &[&str]) -> Option<&'a str> {
    suffixes.iter().find_map(|suf| s.strip_suffix(suf))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::RefLocator;

    /// Bi-directional check: for ecosystems whose download URL is a pure
    /// name+version function, `purl → URL → purl` is the identity.
    #[test]
    fn purl_url_roundtrips_for_deterministic_ecosystems() {
        for purl in [
            "pkg:npm/lodash@4.17.21",
            "pkg:npm/%40babel/core@7.24.0",
            "pkg:cargo/serde@1.0.0",
            "pkg:gem/rails@7.0.0",
            "pkg:golang/github.com/BurntSushi/toml@v1.0.0",
            "pkg:github/owner/repo@v1.0.0",
        ] {
            let url = crate::fetch::resolve(&RefLocator::Purl(purl.to_string()))
                .unwrap_or_else(|| panic!("resolve produced no URL for {purl}"));
            assert_eq!(
                url_to_purl(&url).as_deref(),
                Some(purl),
                "roundtrip failed via {url}",
            );
        }
    }

    #[test]
    fn npm_scoped_and_dashed_names() {
        assert_eq!(
            url_to_purl("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz").as_deref(),
            Some("pkg:npm/left-pad@1.3.0"),
        );
        assert_eq!(
            url_to_purl("https://registry.npmjs.org/@babel/core/-/core-7.24.0.tgz").as_deref(),
            Some("pkg:npm/%40babel/core@7.24.0"),
        );
    }

    #[test]
    fn cargo_cdn_and_api_forms() {
        assert_eq!(
            url_to_purl("https://static.crates.io/crates/serde/serde-1.0.203.crate").as_deref(),
            Some("pkg:cargo/serde@1.0.203"),
        );
        assert_eq!(
            url_to_purl("https://crates.io/api/v1/crates/serde/1.0.203/download").as_deref(),
            Some("pkg:cargo/serde@1.0.203"),
        );
    }

    // PyPI can't round-trip (the pythonhosted path carries an undrivable content
    // hash), so it's covered forward-only, exercising both artifact kinds and
    // PEP 503 name normalization.
    #[test]
    fn pypi_wheel_and_sdist_with_normalization() {
        assert_eq!(
            url_to_purl(
                "https://files.pythonhosted.org/packages/ab/cd/ef/requests-2.31.0-py3-none-any.whl"
            )
            .as_deref(),
            Some("pkg:pypi/requests@2.31.0"),
        );
        assert_eq!(
            url_to_purl(
                "https://files.pythonhosted.org/packages/aa/bb/cc/typing_extensions-4.9.0-py3-none-any.whl"
            )
            .as_deref(),
            Some("pkg:pypi/typing-extensions@4.9.0"),
        );
        assert_eq!(
            url_to_purl("https://files.pythonhosted.org/packages/aa/bb/cc/Django-4.2.1.tar.gz")
                .as_deref(),
            Some("pkg:pypi/django@4.2.1"),
        );
    }

    #[test]
    fn nuget_and_maven_forward() {
        assert_eq!(
            url_to_purl(
                "https://api.nuget.org/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg"
            )
            .as_deref(),
            Some("pkg:nuget/newtonsoft.json@13.0.3"),
        );
        assert_eq!(
            url_to_purl(
                "https://repo1.maven.org/maven2/com/google/guava/guava/32.1.3-jre/guava-32.1.3-jre.jar"
            )
            .as_deref(),
            Some("pkg:maven/com.google.guava/guava@32.1.3-jre"),
        );
    }

    #[test]
    fn go_proxy_uppercase_escape_reversed() {
        assert_eq!(
            url_to_purl(
                "https://proxy.golang.org/github.com/!burnt!sushi/toml/@v/v1.0.0.zip"
            )
            .as_deref(),
            Some("pkg:golang/github.com/BurntSushi/toml@v1.0.0"),
        );
        // Metadata fetches (.mod/.info) are not package artifacts.
        assert_eq!(
            url_to_purl("https://proxy.golang.org/rsc.io/quote/@v/v1.5.2.mod"),
            None,
        );
    }

    #[test]
    fn platform_gem_and_unknowns_decline() {
        // A platform-tagged gem's version field isn't the last segment, so we
        // decline rather than emit a wrong PURL.
        assert_eq!(
            url_to_purl("https://rubygems.org/downloads/nokogiri-1.16.0-x86_64-linux.gem"),
            None,
        );
        assert_eq!(url_to_purl("https://example.com/whatever.tgz"), None);
        assert_eq!(url_to_purl("ftp://registry.npmjs.org/x/-/x-1.0.0.tgz"), None);
        assert_eq!(url_to_purl("https://registry.npmjs.org/no-artifact-here"), None);
    }
}
