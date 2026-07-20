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
//! (npm, crates.io, RubyGems, Go module proxy, NuGet, Maven Central, GitHub
//! archives), a PURL routed through [`fetch::resolve`](crate::fetch::resolve)
//! and back through [`url_to_purl`] must return the original. The asymmetric
//! ecosystems — PyPI (its `files.pythonhosted.org` path carries an undrivable
//! content hash) and platform-tagged gems — cannot round-trip and are covered
//! forward-only.
//!
//! This module also owns PURL **normalization**: [`normalize`] collapses every
//! spelling this project has ever emitted onto one canonical form, and
//! [`identity`] flattens that to the release-coordinate key the bloom filters
//! use — scan calls both for lookups and its `scan-bloom-build` producer calls
//! [`identity`] during generation, so the two sides can never drift. The Go
//! twin is hopper's `pkgparse.CanonicalizePURL` (generation side); the
//! `fletch purl` CLI probe and hopper's crosscheck tests hold the pair in
//! lockstep.

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
    Some(format!(
        "pkg:maven/{}/{artifact}@{version}",
        group.join(".")
    ))
}

/// GitHub source archive: `{owner}/{repo}/{tar.gz|zip}/{ref}`.
fn github(path: &str) -> Option<String> {
    let segs: Vec<&str> = path.split('/').collect();
    let [owner, repo, kind, reference, ..] = segs.as_slice() else {
        return None;
    };
    matches!(*kind, "tar.gz" | "zip").then(|| format!("pkg:github/{owner}/{repo}@{reference}"))
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

    /// Every PURL recovered from a download URL is already canonical: a
    /// provenance-side spelling and a generated spelling of the same package
    /// must never differ, so `url_to_purl → normalize` is the identity.
    #[test]
    fn url_to_purl_outputs_are_canonical() {
        for url in [
            "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
            "https://registry.npmjs.org/@babel/core/-/core-7.24.0.tgz",
            "https://static.crates.io/crates/serde/serde-1.0.0.crate",
            "https://files.pythonhosted.org/packages/ab/cd/Ruamel.Yaml-0.18.6.tar.gz",
            "https://rubygems.org/downloads/rails-7.0.0.gem",
            "https://proxy.golang.org/github.com/!burnt!sushi/toml/@v/v1.4.0.zip",
            "https://api.nuget.org/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg",
            "https://repo1.maven.org/maven2/org/apache/logging/log4j/2.0/log4j-2.0.jar",
            "https://codeload.github.com/owner/repo/tar.gz/v1.0.0",
        ] {
            let purl = url_to_purl(url).unwrap_or_else(|| panic!("{url} must map"));
            assert_eq!(
                normalize(&purl).as_deref(),
                Some(purl.as_str()),
                "url_to_purl({url}) = {purl} is not canonical"
            );
        }
    }

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
            "pkg:nuget/newtonsoft.json@13.0.3",
            "pkg:maven/com.google.guava/guava@32.1.3-jre",
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
            url_to_purl("https://proxy.golang.org/github.com/!burnt!sushi/toml/@v/v1.0.0.zip")
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
        assert_eq!(
            url_to_purl("ftp://registry.npmjs.org/x/-/x-1.0.0.tgz"),
            None
        );
        assert_eq!(
            url_to_purl("https://registry.npmjs.org/no-artifact-here"),
            None
        );
    }
}

/// Normalize a PURL to its canonical string, or `None` when the input cannot
/// denote a package.
///
/// This is the shared contract between the bloom producer (which builds the
/// filter) and the scanner (which queries it): both **must** key on this exact
/// form or lookups silently miss. It is also the entry-point normalizer for
/// PURLs arriving from outside (the `purl` subcommand, pool records), so every
/// downstream consumer — registry lookup, fetch, display, provenance — sees one
/// spelling.
///
/// The `pkg` scheme and package *type* are case-insensitive per the PURL spec,
/// so they are lowercased; the remainder is left untouched, since case
/// significance is type-specific (the extension types and the deb/apk/alpm
/// distro names are case-insensitive and lowercased; rpm names keep their
/// case).
///
/// Folded spellings, so an old and a new spelling of the same package compare
/// equal: `pkg:chrome`→`chrome-extension`, `pkg:vscode`/`pkg:openvsx`→
/// `vscode-extension` (Open VSX keeping its `repository_url` qualifier), the
/// bare distro types `pkg:debian`/`arch`/`fedora`/… → `deb`/`rpm`/`apk`/`alpm`
/// with the distro as namespace, and every AUR spelling (bare `pkg:aur/<name>`,
/// and the vendor-plus-qualifier
/// `pkg:alpm/arch/<name>?repository_url=…aur.archlinux.org` this project
/// generated before) → `pkg:alpm/aur/<name>`, the AUR as its own alpm
/// namespace. The non-spec `?qualifiers@version` ordering older exports
/// composed (`purl_base || '@' || version` glued the version after a
/// qualifier-bearing base) is repaired to the spec `@version?qualifiers` order.
/// For the spec distro types (deb/rpm/apk/alpm) the vendor namespace is
/// lowercased, and a missing one is recovered from the `distro` qualifier
/// (`pkg:rpm/curl?distro=fedora-25` → `pkg:rpm/fedora/curl?distro=fedora-25`).
///
/// `None` — never an empty or degenerate key — when the input has no `pkg:`
/// scheme, an empty type, or an empty package name. Callers treat `None` as
/// "not a package": the producer drops the record's PURL key, the scanner
/// answers no-decision, the CLI reports the argument as invalid.
#[must_use]
pub fn normalize(raw: &str) -> Option<String> {
    // The `pkg` scheme and type are case-insensitive; the shared splitter
    // folds their case and trims. No scheme → not a PURL.
    let (typ, rest) = scheme_type_rest(raw)?;
    let typ = typ.as_str();
    // Split the remainder into the coordinate path and the @version/?qualifier
    // tail so the type can be re-keyed without disturbing either.
    let (path, tail) = match rest.find(['@', '?']) {
        Some(i) => rest.split_at(i),
        None => (rest, ""),
    };
    // An empty type or an empty name can only produce a degenerate key
    // (`pkg:`, `pkg:npm/`) that would collide with every other degenerate
    // input — refuse rather than emit one.
    if typ.is_empty() || last_segment(path).is_empty() {
        return None;
    }
    // Repair the non-spec `?qualifiers@version` ordering: move the trailing
    // version back before the qualifiers. The chunk after the last `@` is only
    // a version when it is free of `=`/`&`/`/`, any of which would mark it as
    // part of a qualifier value (e.g. a repository_url with userinfo) instead.
    let tail = match tail.strip_prefix('?').and_then(|q| q.rsplit_once('@')) {
        Some((quals, v)) if !v.is_empty() && !v.contains(['=', '&', '/']) => {
            format!("@{v}?{quals}")
        }
        _ => tail.to_string(),
    };
    let tail = tail.as_str();
    // For the spec distro types, canonicalize the vendor namespace: it is
    // case-insensitive per spec (lowercased in canonical form), and when
    // missing it is recovered from a `distro=<vendor>-<release>` qualifier —
    // the spec's rpm note says the repository is implied by `distro` — but
    // only when the vendor prefix names a distro this project models
    // (`fedora-25` → fedora; a bare deb codename like `jessie` never
    // matches). The qualifier itself stays; [`identity`] strips it later.
    let path = if matches!(typ, "deb" | "rpm" | "apk" | "alpm") {
        distro_path(typ, path, tail)
    } else {
        std::borrow::Cow::Borrowed(path)
    };
    let path = path.as_ref();

    Some(match typ {
        // Browser / editor extensions: case-insensitive bodies, ratified types.
        "chrome" | "chrome-extension" => {
            format!(
                "pkg:chrome-extension/{}{tail}",
                last_segment(path).to_ascii_lowercase()
            )
        }
        "vscode" | "vscode-extension" => {
            format!("pkg:vscode-extension/{}{tail}", path.to_ascii_lowercase())
        }
        "openvsx" => format!(
            "pkg:vscode-extension/{}{}",
            path.to_ascii_lowercase(),
            add_qualifier(tail, "repository_url=https://open-vsx.org")
        ),
        // PyPI treats `-`/`_`/`.` as one separator and names as
        // case-insensitive — PEP 503 is the registry's own equivalence — so
        // the canonical name is the PEP 503 normalization. (There is no
        // namespace; the path is the name.) npm is deliberately NOT folded:
        // legacy mixed-case names were grandfathered in and stay distinct.
        "pypi" => format!("pkg:pypi/{}{tail}", normalize_pypi(path)),
        // Composer names are case-insensitive per spec and lowercased.
        "composer" => format!("pkg:composer/{}{tail}", path.to_ascii_lowercase()),
        "alpm" => {
            // The AUR is its own alpm namespace: `pkg:alpm/aur/<name>`. Fold
            // the vendor-plus-qualifier spelling this project generated before
            // onto it, dropping that qualifier (others are kept). A
            // repository_url naming anything else, and the other alpm
            // namespaces (the official repos), stay as they are. alpm names
            // are case-insensitive per spec, so the AUR name is lowercased.
            if let Some((val, rest_tail)) = cut_qualifier(tail, "repository_url")
                && val.contains("aur.archlinux.org")
            {
                format!(
                    "pkg:alpm/aur/{}{rest_tail}",
                    last_segment(path).to_ascii_lowercase()
                )
            } else if let Some(name) = path.strip_prefix("aur/") {
                format!("pkg:alpm/aur/{}{tail}", name.to_ascii_lowercase())
            } else {
                format!("pkg:alpm/{path}{tail}")
            }
        }
        other => {
            if let Some((spec, ns)) = distro_spec(other) {
                // deb/apk/alpm names are case-insensitive per spec and
                // lowercase in canonical form; rpm names are case-sensitive.
                let name = last_segment(path);
                let name = if spec == "rpm" {
                    name.to_string()
                } else {
                    name.to_ascii_lowercase()
                };
                // An AUR repository_url wins over the mapped vendor: a legacy
                // bare type carrying it (`pkg:aur/x` redundantly, or
                // `pkg:arch/x` pointing at the AUR) folds onto the aur
                // namespace with the now-redundant qualifier dropped — the
                // same fold the alpm arm applies, so a single pass converges
                // to the fixed point.
                let (ns, tail) = match cut_qualifier(tail, "repository_url") {
                    Some((val, rest)) if spec == "alpm" && val.contains("aur.archlinux.org") => {
                        ("aur", rest)
                    }
                    _ => (ns, tail.to_string()),
                };
                format!("pkg:{spec}/{ns}/{name}{tail}")
            } else {
                // Language/registry and unrecognized types: canonical type, body
                // case preserved (significance is type-specific).
                format!("pkg:{typ}/{path}{tail}")
            }
        }
    })
}

/// The identity-key form of a PURL: [`normalize`], with artifact-selection
/// qualifiers dropped. This — not the full normalized form — is what the bloom
/// producer inserts and the scanner looks up.
///
/// Real-world distro PURLs (SBOM tools, OS package feeds) routinely stamp
/// `?arch=…&distro=…` onto the coordinate, and a PyPI PURL may carry
/// `?kind=…`: qualifiers that select *which artifact* of a release, not
/// *which package* it is. Our pool is keyed by release coordinate (hopper's
/// filename parser deliberately drops the architecture), so an arch-qualified
/// spelling must collide with the bare one or every SBOM-derived lookup
/// misses. Only `repository_url` survives, because it selects which registry
/// the name lives in (Open VSX vs the Microsoft marketplace) — that *is*
/// identity.
///
/// Fetching keeps the full [`normalize`]d form, where `kind=sdist` and friends
/// legitimately steer artifact selection; only key derivation flattens.
#[must_use]
pub fn identity(raw: &str) -> Option<String> {
    let full = normalize(raw)?;
    let Some((head, quals)) = full.split_once('?') else {
        return Some(full);
    };
    let kept: Vec<&str> = quals
        .split('&')
        .filter(|q| {
            q.split('=')
                .next()
                .is_some_and(|k| k.eq_ignore_ascii_case("repository_url"))
        })
        .collect();
    Some(if kept.is_empty() {
        head.to_string()
    } else {
        format!("{head}?{}", kept.join("&"))
    })
}

/// Split a raw PURL into its lowercased type and the untouched remainder after
/// `pkg:<type>/`. The `pkg` scheme and the type are case-insensitive per spec,
/// so this is the one place that folds their case; leading/trailing whitespace
/// is trimmed. `None` when the string has no `pkg:` scheme or no `/`. Shared by
/// the registry parser and the fetch resolver so both read any spelling
/// [`normalize`] accepts.
pub(crate) fn scheme_type_rest(purl: &str) -> Option<(String, &str)> {
    let s = purl.trim();
    // `get(..4)` (not a direct slice) so a multi-byte character at the
    // boundary yields None instead of a panic.
    let body = s
        .get(..4)
        .filter(|scheme| scheme.eq_ignore_ascii_case("pkg:"))
        .map(|_| &s[4..])?;
    let (ty, rest) = body.split_once('/')?;
    Some((ty.to_ascii_lowercase(), rest))
}

/// The final `/`-separated segment (the app-store and distro types drop any
/// vendor path, matching `fletch`'s resolver and `hopper`'s builder).
fn last_segment(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Canonicalize the vendor namespace of a spec distro type's coordinate path:
/// lowercase an existing vendor, or recover a missing one from the `distro`
/// qualifier when its `<vendor>-<release>` prefix names a distro this project
/// models for that type. Mirrors `hopper`'s `pkgparse.distroPath`.
fn distro_path<'a>(typ: &str, path: &'a str, tail: &str) -> std::borrow::Cow<'a, str> {
    use std::borrow::Cow;
    if let Some((ns, name)) = path.split_once('/') {
        if ns.bytes().any(|b| b.is_ascii_uppercase()) {
            return Cow::Owned(format!("{}/{name}", ns.to_ascii_lowercase()));
        }
        return Cow::Borrowed(path);
    }
    if let Some((val, _)) = cut_qualifier(tail, "distro") {
        let vendor = val.split('-').next().unwrap_or(&val).to_ascii_lowercase();
        if let Some((spec, ns)) = distro_spec(&vendor)
            && spec == typ
            && ns == vendor
        {
            return Cow::Owned(format!("{vendor}/{path}"));
        }
    }
    Cow::Borrowed(path)
}

/// Map a legacy bare-distro PURL type onto the spec type and namespace.
fn distro_spec(typ: &str) -> Option<(&'static str, &'static str)> {
    Some(match typ {
        "debian" => ("deb", "debian"),
        "ubuntu" => ("deb", "ubuntu"),
        "fedora" => ("rpm", "fedora"),
        "opensuse" => ("rpm", "opensuse"),
        "rpmfusion" => ("rpm", "rpmfusion"),
        "arch" => ("alpm", "arch"),
        "aur" => ("alpm", "aur"),
        "alpine" => ("apk", "alpine"),
        "wolfi" => ("apk", "wolfi"),
        _ => return None,
    })
}

/// Remove the named qualifier from a PURL `@version`/`?qualifiers` tail,
/// returning its value and the tail without it (the `?` goes too when it was
/// the only qualifier). `None` when the key isn't present.
fn cut_qualifier(tail: &str, key: &str) -> Option<(String, String)> {
    let (ver, quals) = tail.split_once('?')?;
    let mut value = None;
    let kept: Vec<&str> = quals
        .split('&')
        .filter(|q| {
            let (k, v) = q.split_once('=').unwrap_or((q, ""));
            if value.is_none() && k.eq_ignore_ascii_case(key) {
                value = Some(v.to_string());
                false
            } else {
                true
            }
        })
        .collect();
    let value = value?;
    let rest = if kept.is_empty() {
        ver.to_string()
    } else {
        format!("{ver}?{}", kept.join("&"))
    };
    Some((value, rest))
}

/// Merge one qualifier into a PURL `@version`/`?qualifiers` tail, leaving an
/// already-present key untouched.
fn add_qualifier(tail: &str, qualifier: &str) -> String {
    let key = qualifier.split('=').next().unwrap_or(qualifier);
    match tail.split_once('?') {
        None => format!("{tail}?{qualifier}"),
        Some((ver, quals)) => {
            if quals.split('&').any(|q| {
                q.split('=')
                    .next()
                    .is_some_and(|k| k.eq_ignore_ascii_case(key))
            }) {
                tail.to_string()
            } else {
                format!("{ver}?{quals}&{qualifier}")
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod normalize_tests {
    use super::*;

    /// `normalize` on input that must succeed.
    fn norm(raw: &str) -> String {
        normalize(raw).unwrap_or_else(|| panic!("{raw} must normalize"))
    }

    #[test]
    fn scheme_and_type_fold_case_bodies_per_type() {
        // Scheme and type always lowercase; the body's case rule is
        // type-specific: npm keeps it (legacy mixed-case names are
        // grandfathered and distinct), pypi folds per PEP 503.
        assert_eq!(norm("  PKG:NPM/Left-Pad@1.3.0 "), "pkg:npm/Left-Pad@1.3.0");
        assert_eq!(norm("pkg:PyPI/Requests"), "pkg:pypi/requests");
    }

    #[test]
    fn folds_legacy_spellings_onto_canonical() {
        // Legacy fletch spellings fold onto the spec/common-practice form, so a
        // stored spec PURL and a scanned legacy PURL hit the same filter key.
        let pairs = [
            ("pkg:chrome/KhKimila", "pkg:chrome-extension/khkimila"),
            (
                "pkg:chrome/KhKimila@25.7.1",
                "pkg:chrome-extension/khkimila@25.7.1",
            ),
            (
                "pkg:vscode/Saoudrizwan/Claude-Dev",
                "pkg:vscode-extension/saoudrizwan/claude-dev",
            ),
            (
                "pkg:openvsx/jinryx/crontally@1.0.3",
                "pkg:vscode-extension/jinryx/crontally@1.0.3?repository_url=https://open-vsx.org",
            ),
            // PyPI folds per PEP 503 (the registry's own equivalence:
            // lowercase, separator runs collapse); composer lowercases.
            ("pkg:pypi/Ruamel.Yaml@0.18.6", "pkg:pypi/ruamel-yaml@0.18.6"),
            ("pkg:pypi/backports__zoneinfo", "pkg:pypi/backports-zoneinfo"),
            (
                "pkg:composer/Symfony/Console@6.4.0",
                "pkg:composer/symfony/console@6.4.0",
            ),
            ("pkg:debian/curl", "pkg:deb/debian/curl"),
            ("pkg:arch/pacman@6.0", "pkg:alpm/arch/pacman@6.0"),
            ("pkg:fedora/curl", "pkg:rpm/fedora/curl"),
            ("pkg:alpine/musl", "pkg:apk/alpine/musl"),
            // Every AUR spelling folds onto the aur-namespace form: the bare
            // legacy type (with or without a redundant repository_url) and the
            // vendor-plus-qualifier form generated before (its repository_url
            // dropped, other qualifiers kept).
            ("pkg:aur/yay", "pkg:alpm/aur/yay"),
            ("pkg:aur/yay@12.0.0-1", "pkg:alpm/aur/yay@12.0.0-1"),
            (
                "pkg:aur/yay?repository_url=https://aur.archlinux.org",
                "pkg:alpm/aur/yay",
            ),
            ("PKG:AUR/Yay@1.0-1", "pkg:alpm/aur/yay@1.0-1"),
            ("pkg:alpm/aur/Foo-Bar@1.0-1", "pkg:alpm/aur/foo-bar@1.0-1"),
            (
                "pkg:alpm/arch/yay@12.3.0-1?arch=x86_64&repository_url=https://aur.archlinux.org",
                "pkg:alpm/aur/yay@12.3.0-1?arch=x86_64",
            ),
            (
                "pkg:alpm/arch/yay@12.3.0-1?repository_url=https://aur.archlinux.org&arch=x86_64",
                "pkg:alpm/aur/yay@12.3.0-1?arch=x86_64",
            ),
        ];
        for (legacy, spec) in pairs {
            assert_eq!(norm(legacy), spec, "fold {legacy}");
            // Idempotent: the canonical form normalizes to itself.
            assert_eq!(norm(spec), spec, "idempotent {spec}");
        }
    }

    #[test]
    fn repairs_misplaced_version() {
        // The non-spec `?qualifiers@version` ordering older hopper exports
        // composed (purl_base || '@' || version onto a qualifier-bearing base)
        // is repaired to spec order — and an AUR repository_url folds onto the
        // aur namespace in the same pass.
        assert_eq!(
            norm(
                "pkg:alpm/arch/claude-desktop-hardened-bin?repository_url=https://aur.archlinux.org@1.20186.0-1"
            ),
            "pkg:alpm/aur/claude-desktop-hardened-bin@1.20186.0-1"
        );
        assert_eq!(
            norm("pkg:vscode-extension/pub/name?repository_url=https://open-vsx.org@1.0.3"),
            "pkg:vscode-extension/pub/name@1.0.3?repository_url=https://open-vsx.org"
        );
        // A qualifier value containing `@` (URL userinfo) is not a version, and
        // a repository_url naming something other than the AUR is kept.
        assert_eq!(
            norm("pkg:alpm/arch/yay?repository_url=https://user@example.com/repo"),
            "pkg:alpm/arch/yay?repository_url=https://user@example.com/repo"
        );
    }

    #[test]
    fn distro_namespace_canonicalizes_and_recovers() {
        // The purl-spec rpm examples: an already-canonical purl is a fixed
        // point; a namespace-less one recovers its vendor from the distro
        // qualifier (the spec's rpm note: the repository is implied by
        // `distro`). The vendor namespace is case-insensitive and lowercased;
        // a distro value naming no vendor we model (a bare deb codename)
        // never recovers.
        let cases = [
            (
                "pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25",
                "pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25",
            ),
            (
                "pkg:rpm/centerim@4.22.10-1.el6?arch=i686&epoch=1&distro=fedora-25",
                "pkg:rpm/fedora/centerim@4.22.10-1.el6?arch=i686&epoch=1&distro=fedora-25",
            ),
            ("pkg:rpm/Fedora/curl@1.0", "pkg:rpm/fedora/curl@1.0"),
            (
                "pkg:deb/curl@7.50.3-1?arch=i386&distro=jessie",
                "pkg:deb/curl@7.50.3-1?arch=i386&distro=jessie",
            ),
            (
                "pkg:deb/curl@7.50.3-1?arch=amd64&distro=ubuntu-22.04",
                "pkg:deb/ubuntu/curl@7.50.3-1?arch=amd64&distro=ubuntu-22.04",
            ),
        ];
        for (input, want) in cases {
            assert_eq!(norm(input), want, "normalize {input}");
            assert_eq!(norm(want), want, "idempotent {want}");
        }
        // Identity then flattens the artifact-selection qualifiers, so the
        // spec example keys onto the pool's bare release coordinate.
        assert_eq!(
            identity("pkg:rpm/centerim@4.22.10-1.el6?arch=i686&epoch=1&distro=fedora-25").as_deref(),
            Some("pkg:rpm/fedora/centerim@4.22.10-1.el6")
        );
    }

    #[test]
    fn degenerate_inputs_never_yield_a_key() {
        // No output may ever be empty or a bare `pkg:` prefix — a degenerate
        // key would collide with every other degenerate input.
        for junk in [
            "",
            "   ",
            "pkg:",
            "pkg:npm",           // no name at all
            "pkg:npm/",          // empty name
            "pkg:npm/@1.0.0",    // version but no name
            "pkg:/lodash",       // empty type
            "pkg:alpm/aur/",     // empty name behind a namespace
            "npm/lodash@1.0.0",  // no pkg: scheme
            "not-a-purl",
            "https://example.com/x.tgz",
        ] {
            assert_eq!(normalize(junk), None, "{junk:?} must not normalize");
        }
        // The guards reject degenerate inputs, not unusual-but-real ones.
        assert!(normalize("pkg:npm/%40scope/name@1.0.0").is_some());
    }

    #[test]
    fn identity_drops_artifact_selection_qualifiers() {
        // SBOM-style distro purls stamp arch/distro onto the coordinate; the
        // pool keys are bare release coordinates, so identity must collapse
        // the two. repository_url survives — it selects the registry.
        let cases = [
            (
                "pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=x86_64&distro=fedora-25",
                "pkg:rpm/fedora/curl@7.50.3-1.fc25",
            ),
            (
                "pkg:deb/debian/curl@7.50.3-1?arch=amd64",
                "pkg:deb/debian/curl@7.50.3-1",
            ),
            (
                "pkg:alpm/aur/yay@12.3.0-1?arch=x86_64",
                "pkg:alpm/aur/yay@12.3.0-1",
            ),
            (
                "pkg:apk/alpine/musl@1.2.4-r0?arch=aarch64",
                "pkg:apk/alpine/musl@1.2.4-r0",
            ),
            ("pkg:pypi/requests@2.31.0?kind=sdist", "pkg:pypi/requests@2.31.0"),
            (
                "pkg:openvsx/pub/name@1.0.3",
                "pkg:vscode-extension/pub/name@1.0.3?repository_url=https://open-vsx.org",
            ),
            // Folding and identity compose: the qualifier AUR form with an
            // arch stamp lands on the bare aur-namespace coordinate.
            (
                "pkg:alpm/arch/yay@12.3.0-1?arch=x86_64&repository_url=https://aur.archlinux.org",
                "pkg:alpm/aur/yay@12.3.0-1",
            ),
            // No qualifiers → identity is the normalized form itself.
            ("pkg:npm/lodash@4.17.21", "pkg:npm/lodash@4.17.21"),
        ];
        for (input, want) in cases {
            assert_eq!(identity(input).as_deref(), Some(want), "identity {input}");
        }
        assert_eq!(identity("not-a-purl"), None);
    }

    #[test]
    fn every_output_is_a_wellformed_fixed_point() {
        // Structural invariants over a broad corpus — canonical, legacy,
        // broken, junk: every `Some` output keeps the scheme, a non-empty type,
        // and a non-empty name, and both functions are fixed points
        // (f(f(x)) == f(x)) — the producer and the scanner can never disagree
        // however many times a purl passes through.
        let corpus = [
            "pkg:npm/lodash@4.17.21",
            "pkg:npm/%40babel/core@7.24.0",
            "pkg:pypi/Ruamel.Yaml@0.18.6",
            "pkg:composer/Symfony/Console@6.4.0",
            "pkg:golang/github.com/BurntSushi/toml@v1.4.0",
            "pkg:maven/org.apache.logging/log4j@2.0",
            "pkg:alpm/aur/yay@12.3.0-1?arch=x86_64",
            "pkg:alpm/core/pacman@6.0-1?arch=x86_64",
            "pkg:deb/debian/curl@7.88",
            "pkg:vscode-extension/pub/name@1.0.3?repository_url=https://open-vsx.org",
            "pkg:chrome/KhKimila@25.7.1",
            "pkg:vscode/Pub/Name",
            "pkg:openvsx/pub/name@1.0.3",
            "pkg:aur/yay",
            "pkg:aur/yay?repository_url=https://aur.archlinux.org",
            "pkg:alpm/aur/Foo-Bar",
            "pkg:alpm/arch/yay@12.0-1?repository_url=https://aur.archlinux.org",
            "PKG:AUR/Yay@1.0-1",
            "pkg:debian/curl",
            "pkg:ubuntu/curl",
            "pkg:fedora/curl",
            "pkg:opensuse/curl",
            "pkg:rpmfusion/LibFoo",
            "pkg:arch/pacman",
            "pkg:alpine/musl",
            "pkg:wolfi/musl",
            "pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=x86_64&distro=fedora-25",
            "pkg:rpm/centerim@4.22.10-1.el6?arch=i686&epoch=1&distro=fedora-25",
            "pkg:rpm/Fedora/curl@1.0",
            "pkg:deb/curl@7.50.3-1?arch=i386&distro=jessie",
            "pkg:alpm/arch/x?repository_url=https://aur.archlinux.org@1.0-1",
            "pkg:alpm/arch/x?repository_url=https://aur.archlinux.org&arch=x86_64@1.0-1",
            "pkg:alpm/arch/x?arch=x86_64&repository_url=https://aur.archlinux.org@1.0-1",
            "pkg:vscode-extension/pub/name?repository_url=https://open-vsx.org@1.0.3",
            "pkg:npm/x@",
            "pkg:npm/x?",
            "pkg:npm/x@1.0#src/index.js",
            "pkg:npm/x?repository_url=https://user@example.com/repo",
            "",
            "pkg:",
            "pkg:npm/",
            "pkg:/x",
            "npm/x",
            "not-a-purl",
        ];
        for raw in corpus {
            for (name, f) in [
                ("normalize", normalize as fn(&str) -> Option<String>),
                ("identity", identity as fn(&str) -> Option<String>),
            ] {
                let Some(out) = f(raw) else { continue };
                let body = out
                    .strip_prefix("pkg:")
                    .unwrap_or_else(|| panic!("{name}({raw:?}) = {out:?} lost the scheme"));
                let (typ, rest) = body
                    .split_once('/')
                    .unwrap_or_else(|| panic!("{name}({raw:?}) = {out:?} has no name"));
                assert!(!typ.is_empty(), "{name}({raw:?}) = {out:?}: empty type");
                let coord = rest.split(['@', '?']).next().unwrap_or(rest);
                let pkg = coord.rsplit('/').next().unwrap_or(coord);
                assert!(!pkg.is_empty(), "{name}({raw:?}) = {out:?}: empty name");
                assert_eq!(
                    f(&out).as_deref(),
                    Some(out.as_str()),
                    "{name}({raw:?}) = {out:?} is not a fixed point"
                );
            }
        }
    }
}
