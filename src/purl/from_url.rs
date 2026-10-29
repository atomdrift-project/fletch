//! Recognize the package a registry download URL points at.
//!
//! The inverse of the fetch resolver: given a concrete artifact URL from a
//! public registry, recover `pkg:<type>/<name>@<version>`. A pure, offline,
//! host-directed mapping of the well-known registry URL shapes. An
//! unrecognized host or path yields `None`, which a caller treats as "identity
//! unknown".
//!
//! For the ecosystems whose download URL is a pure function of name and
//! version (npm, crates.io, RubyGems, the Go module proxy, NuGet, Maven
//! Central, GitHub archives), a PURL routed through
//! [`fetch::resolve`](crate::fetch::resolve) and back through
//! [`url_to_purl`] returns the original; the tests hold both directions
//! together. PyPI (its `files.pythonhosted.org` path carries a content hash)
//! and platform-tagged gems cannot round-trip and are covered forward-only.

use std::collections::BTreeMap;

use url::Url;

use super::{Mode, Purl, decode, finish};

impl Purl {
    /// The package a registry artifact URL downloads, or `None` when the host
    /// or path is not a recognized package download.
    ///
    /// Recognized: npm (`registry.npmjs.org`, `registry.yarnpkg.com`),
    /// crates.io (`static.crates.io`, the `crates.io` API download), PyPI
    /// (`files.pythonhosted.org`), RubyGems (`rubygems.org`), the Go module
    /// proxy (`proxy.golang.org`), NuGet (`api.nuget.org`), Maven Central
    /// (`repo1.maven.org`, `repo.maven.apache.org`), and GitHub archives
    /// (`codeload.github.com`).
    #[must_use]
    pub fn from_url(url: &str) -> Option<Self> {
        let (host, path) = split_host_path(url)?;
        match host.as_str() {
            "registry.npmjs.org" | "registry.yarnpkg.com" => npm(&path),
            "static.crates.io" | "crates.io" => cargo(&path),
            "files.pythonhosted.org" => pypi(&path),
            "rubygems.org" => gem(&path),
            "proxy.golang.org" => golang(&path),
            "api.nuget.org" => nuget(&path),
            "repo1.maven.org" | "repo.maven.apache.org" => maven(&path),
            "codeload.github.com" => github(&path),
            _ => None,
        }
    }
}

/// The canonical PURL a registry artifact URL downloads: the string form of
/// [`Purl::from_url`].
#[must_use]
pub fn url_to_purl(url: &str) -> Option<String> {
    Purl::from_url(url).map(|purl| purl.to_string())
}

/// Split an `http(s)` URL into its lowercase host and its path without the
/// leading slash. `None` for any other scheme, or a URL with userinfo, which
/// could make a look-alike authority read as a registry host.
fn split_host_path(url: &str) -> Option<(String, String)> {
    let parsed = Url::parse(url).ok()?;
    if !matches!(parsed.scheme(), "http" | "https")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return None;
    }
    Some((
        parsed.host_str()?.to_ascii_lowercase(),
        parsed.path().trim_start_matches('/').to_owned(),
    ))
}

/// The PURL of `typ` at `path` (`/`-separated, the name last) and `version`,
/// every piece still percent-encoded as it was in the URL.
fn purl(typ: &str, path: &str, version: &str, qualifiers: &[(&str, &str)]) -> Option<Purl> {
    let mut namespace = path
        .split('/')
        .map(decode)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    let name = namespace.pop()?;
    let version = decode(version).ok()?;
    let qualifiers = qualifiers
        .iter()
        .map(|(key, value)| Some(((*key).to_owned(), decode(value).ok()?)))
        .collect::<Option<BTreeMap<_, _>>>()?;
    let purl = Purl {
        typ: typ.to_owned(),
        namespace,
        name,
        version: (!version.is_empty()).then_some(version),
        qualifiers,
        subpath: Vec::new(),
    };
    finish(purl, Mode::Lenient)
        .inspect_err(|error| tracing::debug!(%error, typ, "registry URL names no valid package"))
        .ok()
}

/// npm: `{name}/-/{base}-{version}.tgz`, where `name` may be `@scope/pkg` and
/// `base` is its last segment.
fn npm(path: &str) -> Option<Purl> {
    let (name, file) = path.split_once("/-/")?;
    let stem = file.strip_suffix(".tgz")?;
    let base = name.rsplit('/').next()?;
    let version = stem.strip_prefix(base)?.strip_prefix('-')?;
    purl("npm", name, version, &[])
}

/// crates.io: the CDN path `crates/{name}/{name}-{version}.crate`, or the API
/// download `api/v1/crates/{name}/{version}/download`.
fn cargo(path: &str) -> Option<Purl> {
    if let Some(rest) = path.strip_prefix("crates/") {
        let (name, file) = rest.split_once('/')?;
        let version = file
            .strip_prefix(name)?
            .strip_prefix('-')?
            .strip_suffix(".crate")?;
        return purl("cargo", name, version, &[]);
    }
    let rest = path.strip_prefix("api/v1/crates/")?;
    let mut segments = rest.split('/');
    let name = segments.next()?;
    let version = segments.next()?;
    if segments.next() != Some("download") || segments.next().is_some() {
        return None;
    }
    purl("cargo", name, version, &[])
}

/// PyPI: parse the filename. Wheels
/// (`{dist}-{version}-{python}-{abi}-{platform}.whl`) carry name and version
/// as their first two `-`-separated fields; sdists (`{name}-{version}.tar.gz`)
/// put the version last. The PyPI type rules normalize the name per PEP 503.
fn pypi(path: &str) -> Option<Purl> {
    let file = path.rsplit('/').next()?;
    let (name, version) = if let Some(stem) = file.strip_suffix(".whl") {
        let mut fields = stem.splitn(3, '-');
        (fields.next()?, fields.next()?)
    } else {
        let stem = [".tar.gz", ".tar.bz2", ".tar.xz", ".zip", ".tgz"]
            .iter()
            .find_map(|suffix| file.strip_suffix(suffix))?;
        stem.rsplit_once('-')
            .filter(|(_, version)| starts_with_digit(version))?
    };
    purl("pypi", name, version, &[("file_name", file)])
}

/// RubyGems: `downloads/{name}-{version}.gem` (or the `gems/` prefix). A
/// platform build keeps its platform as an exact-artifact selector.
fn gem(path: &str) -> Option<Purl> {
    let rest = path
        .strip_prefix("downloads/")
        .or_else(|| path.strip_prefix("gems/"))?;
    let stem = rest.strip_suffix(".gem")?;
    // A gem name may itself contain a numeric-leading hyphenated field, so the
    // final numeric-looking field is the least ambiguous version boundary.
    let (name, release) = stem.match_indices('-').rev().find_map(|(index, _)| {
        let (name, release) = stem.split_at(index);
        let release = release.strip_prefix('-')?;
        starts_with_digit(release).then_some((name, release))
    })?;
    match release
        .split_once('-')
        .filter(|(_, platform)| looks_like_gem_platform(platform))
    {
        Some((version, platform)) => purl("gem", name, version, &[("platform", platform)]),
        None => purl("gem", name, release, &[]),
    }
}

fn looks_like_gem_platform(value: &str) -> bool {
    [
        "ruby",
        "java",
        "linux",
        "darwin",
        "mingw",
        "mswin",
        "x86",
        "x64",
        "arm",
        "aarch",
        "universal",
        "wasm",
    ]
    .iter()
    .any(|marker| value.eq_ignore_ascii_case(marker) || value.contains(marker))
}

/// Go module proxy: `{module}/@v/{version}.zip`, both fields `!`-escaped for
/// uppercase (the GOPROXY case-encoding). Only the `.zip` artifact carries the
/// module bytes; `.mod`/`.info` metadata fetches are not packages.
fn golang(path: &str) -> Option<Purl> {
    let (module, tail) = path.split_once("/@v/")?;
    let version = tail.strip_suffix(".zip")?;
    purl(
        "golang",
        &goproxy_unescape(module)?,
        &goproxy_unescape(version)?,
        &[],
    )
}

/// NuGet flat container: `v3-flatcontainer/{id}/{version}/{id}.{version}.nupkg`.
/// The URL lowercases the id; the recovered PURL carries that lowercased form.
fn nuget(path: &str) -> Option<Purl> {
    let rest = path.strip_prefix("v3-flatcontainer/")?;
    let mut segments = rest.split('/');
    let id = segments.next()?;
    let version = segments.next()?;
    let file = segments.next()?;
    if segments.next().is_some() || !file.eq_ignore_ascii_case(&format!("{id}.{version}.nupkg")) {
        return None;
    }
    purl("nuget", id, version, &[])
}

/// Maven: `maven2/{group/as/path}/{artifact}/{version}/{file}`. The group is
/// the dotted join of every segment before the trailing
/// `artifact/version/file`; a file other than the plain jar keeps its
/// classifier and extension as qualifiers.
fn maven(path: &str) -> Option<Purl> {
    let rest = path.strip_prefix("maven2/")?;
    let segments: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
    let [group @ .., artifact, version, file] = segments.as_slice() else {
        return None;
    };
    if group.is_empty() {
        return None;
    }
    let suffix = file
        .strip_prefix(artifact)?
        .strip_prefix('-')?
        .strip_prefix(version)?;
    let (classifier, extension) = ["tar.gz", "tar.bz2", "tar.xz"]
        .into_iter()
        .find_map(|extension| {
            suffix
                .strip_suffix(extension)?
                .strip_suffix('.')
                .map(|classifier| (classifier, extension))
        })
        .or_else(|| suffix.rsplit_once('.'))?;
    if extension.is_empty() {
        return None;
    }
    let mut qualifiers = Vec::new();
    if !classifier.is_empty() {
        let classifier = classifier.strip_prefix('-').filter(|c| !c.is_empty())?;
        qualifiers.push(("classifier", classifier));
    }
    if extension != "jar" {
        qualifiers.push(("type", extension));
    }
    let coordinate = format!("{}/{artifact}", group.join("."));
    purl("maven", &coordinate, version, &qualifiers)
}

/// GitHub source archive: `{owner}/{repo}/{tar.gz|zip}/{ref}`.
fn github(path: &str) -> Option<Purl> {
    let segments: Vec<&str> = path.split('/').collect();
    let [owner, repo, kind, reference] = segments.as_slice() else {
        return None;
    };
    if !matches!(*kind, "tar.gz" | "zip") {
        return None;
    }
    purl("github", &format!("{owner}/{repo}"), reference, &[])
}

/// Reverse [`goproxy_escape`](crate::ecosystem::golang::goproxy_escape):
/// `!x` → uppercase `X`.
fn goproxy_unescape(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '!' {
            let next = chars.next().filter(char::is_ascii_lowercase)?;
            out.push(next.to_ascii_uppercase());
        } else {
            out.push(c);
        }
    }
    Some(out)
}

fn starts_with_digit(s: &str) -> bool {
    s.bytes().next().is_some_and(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::super::normalize;
    use super::*;
    use crate::RefLocator;

    /// Every PURL recovered from a download URL is already canonical, so
    /// `url_to_purl → normalize` is the identity.
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
            assert_eq!(Purl::from_url(url).map(|p| p.to_string()), Some(purl));
        }
    }

    /// For ecosystems whose download URL is a pure name+version function,
    /// `purl → URL → purl` is the identity.
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
            "pkg:maven/org.example/demo@1.0.0%20Final?classifier=sources&type=tar.gz",
            "pkg:gem/nokogiri@1.16.0?platform=x86_64-linux",
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
    fn generated_purl_url_purl_roundtrips_cover_coordinate_shapes() {
        let names = ["alpha", "dash-name", "name_underscore"];
        let versions = ["0.0.1", "1.2.3", "2026.08.25-beta.1"];
        for name in names {
            for version in versions {
                for purl in [
                    format!("pkg:npm/{name}@{version}"),
                    format!("pkg:cargo/{name}@{version}"),
                    format!("pkg:gem/{name}@{version}"),
                    format!("pkg:nuget/{name}@{version}"),
                    format!("pkg:github/acme/{name}@{version}"),
                    format!("pkg:maven/org.example/{name}@{version}"),
                ] {
                    let canonical = normalize(&purl).unwrap();
                    let url = crate::fetch::resolve(&RefLocator::Purl(canonical.clone()))
                        .unwrap_or_else(|| panic!("resolve produced no URL for {canonical}"));
                    assert_eq!(url_to_purl(&url), Some(canonical), "roundtrip via {url}");
                }
            }
        }
    }

    #[test]
    fn canonical_artifact_urls_roundtrip_through_purls() {
        for url in [
            "https://registry.npmjs.org/@babel/core/-/core-7.24.0.tgz",
            "https://static.crates.io/crates/serde/serde-1.0.203.crate",
            "https://rubygems.org/downloads/nokogiri-1.16.0-x86_64-linux.gem",
            "https://rubygems.org/downloads/demo-2.0.0-beta.1.gem",
            "https://proxy.golang.org/github.com/!burnt!sushi/toml/@v/v1.4.0.zip",
            "https://api.nuget.org/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg",
            "https://repo1.maven.org/maven2/org/example/demo/1.0.0%20Final/demo-1.0.0%20Final-sources.tar.gz",
            "https://codeload.github.com/owner/repo/tar.gz/v1.0.0",
        ] {
            let purl = url_to_purl(url).unwrap_or_else(|| panic!("no PURL for {url}"));
            let recovered = crate::fetch::resolve(&RefLocator::Purl(purl.clone()))
                .unwrap_or_else(|| panic!("no URL for {purl}"));
            assert_eq!(recovered, url, "URL roundtrip via {purl}");
        }
    }

    #[test]
    fn reverse_mapping_rejects_paths_that_only_look_like_artifacts() {
        for url in [
            "https://crates.io/api/v1/crates/serde/1.0.0/download/extra",
            "https://codeload.github.com/owner/repo/tar.gz/v1/extra",
            "https://proxy.golang.org/github.com/bad!/module/@v/v1.0.0.zip",
            "https://api.nuget.org/v3-flatcontainer/demo/1.0/not-demo.nupkg",
            "https://repo1.maven.org/maven2/demo/1.0/demo-1.0.jar",
            "https://repo1.maven.org/maven2/org/example/demo/1.0/demo-1.0-.jar",
        ] {
            assert_eq!(url_to_purl(url), None, "accepted malformed URL {url}");
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

    #[test]
    fn pypi_wheel_and_sdist_with_normalization() {
        assert_eq!(
            url_to_purl(
                "https://files.pythonhosted.org/packages/ab/cd/ef/requests-2.31.0-py3-none-any.whl"
            )
            .as_deref(),
            Some("pkg:pypi/requests@2.31.0?file_name=requests-2.31.0-py3-none-any.whl"),
        );
        assert_eq!(
            url_to_purl(
                "https://files.pythonhosted.org/packages/aa/bb/cc/typing_extensions-4.9.0-py3-none-any.whl"
            )
            .as_deref(),
            Some("pkg:pypi/typing-extensions@4.9.0?file_name=typing_extensions-4.9.0-py3-none-any.whl"),
        );
        assert_eq!(
            url_to_purl("https://files.pythonhosted.org/packages/aa/bb/cc/Django-4.2.1.tar.gz")
                .as_deref(),
            Some("pkg:pypi/django@4.2.1?file_name=Django-4.2.1.tar.gz"),
        );
    }

    /// The URL path is percent-encoded; the `file_name` qualifier holds the
    /// file's real name, as the registry lists it.
    #[test]
    fn pypi_file_name_is_the_decoded_file_name() {
        let purl = Purl::from_url(
            "https://files.pythonhosted.org/packages/aa/bb/torch-2.0.0%2Bcu118-cp311-cp311-linux_x86_64.whl",
        )
        .unwrap();
        assert_eq!(purl.version(), Some("2.0.0+cu118"));
        assert_eq!(
            purl.qualifier("file_name"),
            Some("torch-2.0.0+cu118-cp311-cp311-linux_x86_64.whl")
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
        assert_eq!(
            url_to_purl("https://repo1.maven.org/maven2/org/example/tool/1.2/tool-1.2-sources.zip"),
            Some("pkg:maven/org.example/tool@1.2?classifier=sources&type=zip".into())
        );
    }

    #[test]
    fn go_proxy_uppercase_escape_reversed() {
        assert_eq!(
            url_to_purl("https://proxy.golang.org/github.com/!burnt!sushi/toml/@v/v1.0.0.zip")
                .as_deref(),
            Some("pkg:golang/github.com/BurntSushi/toml@v1.0.0"),
        );
        assert_eq!(
            url_to_purl("https://proxy.golang.org/rsc.io/quote/@v/v1.5.2.mod"),
            None,
        );
    }

    /// A ref holding `@` is one version, never a second version separator.
    #[test]
    fn github_ref_with_at_sign_stays_the_version() {
        let purl = Purl::from_url("https://codeload.github.com/owner/repo/zip/v1@x").unwrap();
        assert_eq!(purl.name(), "repo");
        assert_eq!(purl.version(), Some("v1@x"));
    }

    #[test]
    fn platform_gem_recovers_exact_artifact_and_unknowns_decline() {
        assert_eq!(
            url_to_purl("https://rubygems.org/downloads/nokogiri-1.16.0-x86_64-linux.gem")
                .as_deref(),
            Some("pkg:gem/nokogiri@1.16.0?platform=x86_64-linux"),
        );
        assert_eq!(
            url_to_purl("https://rubygems.org/downloads/foo-2fa-1.0.gem").as_deref(),
            Some("pkg:gem/foo-2fa@1.0"),
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

    #[test]
    fn url_authority_userinfo_cannot_spoof_a_registry_host() {
        assert_eq!(
            url_to_purl("https://registry.npmjs.org:443@evil.example/lodash/-/lodash-1.0.0.tgz"),
            None
        );
    }

    #[test]
    fn url_scheme_and_host_are_case_insensitive() {
        assert_eq!(
            url_to_purl("HTTPS://REGISTRY.NPMJS.ORG/lodash/-/lodash-1.0.0.tgz"),
            Some("pkg:npm/lodash@1.0.0".into())
        );
    }
}
