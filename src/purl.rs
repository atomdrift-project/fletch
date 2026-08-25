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

use std::collections::BTreeMap;

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

#[derive(Debug)]
struct CanonicalPurl {
    typ: String,
    namespace: Vec<String>,
    name: String,
    version: Option<String>,
    qualifiers: BTreeMap<String, String>,
    subpath: Vec<String>,
}

/// Parse a PURL using ECMA-427's right-to-left component rules and rebuild its
/// canonical ASCII spelling. This is deliberately stricter about structure
/// than fletch's legacy type folding, but tolerant about non-canonical input:
/// percent triplets, qualifier order/key case, literal Unicode, repeated path
/// separators, and ignorable subpath segments all converge here.
fn canonicalize_purl(raw: &str) -> Option<String> {
    let mut parts = parse_purl_components(raw)?;
    apply_type_rules(&mut parts)?;
    Some(build_purl(&parts))
}

fn parse_purl_components(raw: &str) -> Option<CanonicalPurl> {
    let raw = raw.trim();
    let (scheme, body) = raw.split_once(':')?;
    if !scheme.eq_ignore_ascii_case("pkg") {
        return None;
    }
    let body = body.trim_start_matches('/');
    let (typ, remainder) = body.split_once('/')?;
    if !valid_type(typ) {
        return None;
    }

    // The standard parses from right to left. A second raw delimiter left in
    // an earlier component is not data; data occurrences must be percent
    // encoded, so reject rather than produce an ambiguous key.
    let (remainder, raw_subpath) = remainder
        .rsplit_once('#')
        .map_or((remainder, None), |(left, right)| (left, Some(right)));
    if remainder.contains('#') {
        return None;
    }
    let (mut coordinate, raw_qualifiers) = remainder
        .rsplit_once('?')
        .map_or((remainder, None), |(left, right)| (left, Some(right)));
    if coordinate.contains('?') {
        return None;
    }

    // Older atomdrift producers emitted `?qualifiers@version`. Preserve that
    // compatibility repair before applying the standard coordinate split.
    let mut repaired_qualifiers = raw_qualifiers;
    let mut repaired_version = None;
    if let Some(qualifiers) = raw_qualifiers
        && let Some((before, version)) = qualifiers.rsplit_once('@')
        && !version.is_empty()
        && !version.contains(['=', '&', '/'])
    {
        repaired_qualifiers = Some(before);
        repaired_version = Some(version);
    }

    coordinate = coordinate.trim_matches('/');
    let (raw_path, raw_version) = if let Some(version) = repaired_version {
        (coordinate, Some(version))
    } else if typ.eq_ignore_ascii_case("npm") && coordinate.starts_with('@') {
        let scope_end = coordinate.find('/')?;
        coordinate[scope_end + 1..]
            .rfind('@')
            .map_or((coordinate, None), |relative| {
                let separator = scope_end + 1 + relative;
                (&coordinate[..separator], Some(&coordinate[separator + 1..]))
            })
    } else {
        coordinate
            .rsplit_once('@')
            .map_or((coordinate, None), |(path, version)| (path, Some(version)))
    };
    if raw_path.ends_with('/') && namespace_requirement(&typ.to_ascii_lowercase()) == 1 {
        return None;
    }
    let raw_path = raw_path.trim_matches('/');
    if raw_path.is_empty() {
        return None;
    }
    let mut path = raw_path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(decode_component)
        .collect::<Option<Vec<_>>>()?;
    let name = path.pop()?;
    if name.is_empty()
        || path
            .iter()
            .any(|segment| segment.is_empty() || segment.contains('/'))
    {
        return None;
    }

    let version = match raw_version.filter(|value| !value.is_empty()) {
        Some(value) => Some(decode_component(value)?),
        None => None,
    };
    let qualifiers = parse_qualifiers(repaired_qualifiers)?;
    if version.is_some() && qualifiers.contains_key("vers") {
        return None;
    }
    let subpath = parse_subpath(raw_subpath)?;
    Some(CanonicalPurl {
        typ: typ.to_ascii_lowercase(),
        namespace: path,
        name,
        version,
        qualifiers,
        subpath,
    })
}

fn valid_type(typ: &str) -> bool {
    typ.bytes()
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && typ
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
}

fn valid_qualifier_key(key: &str) -> bool {
    key.bytes()
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && key.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_')
        })
}

fn parse_qualifiers(raw: Option<&str>) -> Option<BTreeMap<String, String>> {
    let mut qualifiers = BTreeMap::new();
    for pair in raw.unwrap_or_default().split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=')?;
        let key = key.to_ascii_lowercase();
        if !valid_qualifier_key(&key) {
            return None;
        }
        let value = decode_component(value)?;
        if value.is_empty() {
            continue;
        }
        if qualifiers.insert(key, value).is_some() {
            return None;
        }
    }
    Some(qualifiers)
}

fn parse_subpath(raw: Option<&str>) -> Option<Vec<String>> {
    let mut subpath = Vec::new();
    for segment in raw.unwrap_or_default().split('/') {
        let decoded = decode_component(segment)?;
        if decoded.is_empty() || matches!(decoded.as_str(), "." | "..") {
            continue;
        }
        if decoded.contains('/') {
            return None;
        }
        subpath.push(decoded);
    }
    Some(subpath)
}

fn decode_component(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let triplet = bytes.get(index + 1..index + 3)?;
            let hex = std::str::from_utf8(triplet).ok()?;
            decoded.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

fn namespace_requirement(typ: &str) -> i8 {
    match typ {
        "alpm" | "apk" | "bitbucket" | "composer" | "deb" | "git" | "github" | "golang"
        | "huggingface" | "maven" | "qpkg" | "rpm" | "swift" | "vscode-extension" => 1,
        "bazel" | "bitnami" | "cargo" | "chrome-extension" | "cocoapods" | "conda" | "cran"
        | "gem" | "hackage" | "julia" | "mlflow" | "nuget" | "oci" | "opam" | "otp" | "pub"
        | "pypi" | "vcpkg" => -1,
        _ => 0,
    }
}

fn apply_type_rules(parts: &mut CanonicalPurl) -> Option<()> {
    let namespace_requirement = namespace_requirement(&parts.typ);
    let recoverable_distro_namespace = parts.namespace.is_empty()
        && (parts
            .qualifiers
            .get("distro")
            .and_then(|value| distro_spec(value.split('-').next().unwrap_or(value)))
            .is_some_and(|(spec, _)| spec == parts.typ)
            || (parts.typ == "alpm"
                && parts
                    .qualifiers
                    .get("repository_url")
                    .is_some_and(|value| value.contains("aur.archlinux.org"))));
    if (namespace_requirement == 1 && parts.namespace.is_empty() && !recoverable_distro_namespace)
        || (namespace_requirement == -1 && !parts.namespace.is_empty())
    {
        return None;
    }
    if matches!(parts.typ.as_str(), "julia" | "swid") {
        let required = if parts.typ == "julia" {
            "uuid"
        } else {
            "tag_id"
        };
        if !parts.qualifiers.contains_key(required) {
            return None;
        }
    }
    if parts.typ == "cpan" && parts.name.contains("::") {
        return None;
    }
    if matches!(
        parts.typ.as_str(),
        "alpm"
            | "apk"
            | "bitbucket"
            | "brew"
            | "composer"
            | "deb"
            | "github"
            | "hex"
            | "luarocks"
            | "qpkg"
            | "rpm"
            | "vscode-extension"
            | "yocto"
    ) {
        for segment in &mut parts.namespace {
            *segment = segment.to_lowercase();
        }
    }
    if matches!(
        parts.typ.as_str(),
        "alpm"
            | "apk"
            | "bitbucket"
            | "bitnami"
            | "brew"
            | "chrome-extension"
            | "composer"
            | "deb"
            | "github"
            | "hex"
            | "luarocks"
            | "oci"
            | "otp"
            | "pub"
            | "vscode-extension"
    ) {
        parts.name = parts.name.to_lowercase();
    }
    if matches!(
        parts.typ.as_str(),
        "huggingface" | "oci" | "pypi" | "vscode-extension"
    ) {
        parts.version = parts.version.take().map(|value| value.to_lowercase());
    }

    match parts.typ.as_str() {
        "pypi" => {
            parts.name = normalize_pypi(&parts.name);
        }
        "git" if parts.namespace.first().is_some_and(|host| host == "github") => {
            for segment in &mut parts.namespace {
                *segment = segment.to_lowercase();
            }
            parts.name = parts.name.to_lowercase();
        }
        "mlflow"
            if parts
                .qualifiers
                .get("repository_url")
                .is_some_and(|url| url.contains("databricks")) =>
        {
            parts.name = parts.name.to_lowercase();
        }
        "pub" => {
            parts.name = parts
                .name
                .chars()
                .map(|character| {
                    if character.is_ascii_lowercase() || character.is_ascii_digit() {
                        character
                    } else {
                        '_'
                    }
                })
                .collect();
        }
        _ => {}
    }
    (!parts.name.is_empty()).then_some(())
}

fn encode_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'-' | b'_' | b'~' | b':') {
            encoded.push(char::from(*byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

fn build_purl(parts: &CanonicalPurl) -> String {
    let mut output = format!("pkg:{}/", parts.typ);
    if !parts.namespace.is_empty() {
        output.push_str(
            &parts
                .namespace
                .iter()
                .map(|segment| encode_component(segment))
                .collect::<Vec<_>>()
                .join("/"),
        );
        output.push('/');
    }
    output.push_str(&encode_component(&parts.name));
    if let Some(version) = parts.version.as_deref() {
        output.push('@');
        output.push_str(&encode_component(version));
    }
    if !parts.qualifiers.is_empty() {
        output.push('?');
        output.push_str(
            &parts
                .qualifiers
                .iter()
                .map(|(key, value)| format!("{key}={}", encode_component(value)))
                .collect::<Vec<_>>()
                .join("&"),
        );
    }
    if !parts.subpath.is_empty() {
        output.push('#');
        output.push_str(
            &parts
                .subpath
                .iter()
                .map(|segment| encode_component(segment))
                .collect::<Vec<_>>()
                .join("/"),
        );
    }
    output
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
/// All ECMA-427 components are parsed and rebuilt canonically: percent escapes
/// use uppercase triplets, qualifier keys are lowercase and sorted, empty
/// qualifier values and ignorable subpath segments are removed, and component
/// case follows the PURL type definitions. Type-specific rules such as PyPI
/// name normalization and required/prohibited namespaces are enforced.
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
/// scheme, has malformed components, or violates a type requirement. Callers
/// treat `None` as
/// "not a package": the producer drops the record's PURL key, the scanner
/// answers no-decision, the CLI reports the argument as invalid.
#[must_use]
pub fn normalize(raw: &str) -> Option<String> {
    // Canonicalize once so the legacy folding layer sees unambiguous
    // components, then again because folds may add a qualifier or change a
    // type's case/namespace rules.
    let canonical = canonicalize_purl(raw)?;
    let folded = normalize_legacy(&canonical)?;
    canonicalize_purl(&folded)
}

/// Apply atomdrift's historical type aliases and distro namespace recovery to
/// an already-canonical PURL. Generic ECMA-427 canonicalization belongs in
/// [`canonicalize_purl`], on both sides of this compatibility layer.
fn normalize_legacy(raw: &str) -> Option<String> {
    // The `pkg` scheme and type are case-insensitive; the shared splitter
    // folds their case and trims. No scheme → not a PURL.
    let (typ, rest) = scheme_type_rest(raw)?;
    let typ = typ.as_str();
    let (rest, subpath) = rest
        .split_once('#')
        .map_or((rest, ""), |(coordinate, value)| (coordinate, value));
    let subpath = if subpath.is_empty() {
        String::new()
    } else {
        format!("#{subpath}")
    };
    // Split the remainder into the coordinate path and the @version/?qualifier
    // tail so the type can be re-keyed without disturbing either.
    //
    // A *leading* `@` opens an npm scope (`pkg:npm/@scope/name@1.0.0`), never a
    // version: a coordinate path cannot begin with its own version separator.
    // Searching from 0 would split `@scope/name@1.0.0` into an empty path and a
    // tail of everything, and the empty-name guard below would then refuse a
    // perfectly good PURL — every scoped npm package, which is a large part of
    // the registry.
    //
    // It is a scope only when a `/` closes it, because a scope is always
    // `@scope/name`. Where the next delimiter is a version or a qualifier
    // instead, the `@` really does open a version over an empty name
    // (`pkg:npm/@1.0.0`), which the guard below must still refuse.
    let scope_sigil = usize::from(
        rest.starts_with('@')
            && rest[1..]
                .find(['/', '@', '?'])
                .is_some_and(|i| rest[1 + i..].starts_with('/')),
    );
    let (path, tail) = match rest[scope_sigil..].find(['@', '?']) {
        Some(i) => rest.split_at(scope_sigil + i),
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
    // Fold a literal npm scope onto its percent-encoded spelling. The spec
    // percent-encodes `@` inside a namespace, and that is what this module's
    // own `url_to_purl` emits, so without the fold `@scope/name` and
    // `%40scope/name` are one package under two keys and every bloom or index
    // lookup made with one spelling misses the other.
    //
    // Applied to every type, before the distro rewrite, not only to the types
    // where a scope is idiomatic: the split above already reads a leading `@`
    // as part of the path whatever the type is, so `pkg:rpm/@scope/pkg` has to
    // canonicalize the same way here as it does in hopper's twin — a rule that
    // is type-specific on one side and universal on the other is a divergence
    // waiting to be found by a fuzzer instead of by a test.
    let scoped = path.strip_prefix('@').map(|scope| format!("%40{scope}"));
    let path = scoped.as_deref().unwrap_or(path);
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
                "pkg:chrome-extension/{}{tail}{subpath}",
                last_segment(path).to_ascii_lowercase()
            )
        }
        "vscode" | "vscode-extension" => {
            format!(
                "pkg:vscode-extension/{}{tail}{subpath}",
                path.to_ascii_lowercase()
            )
        }
        "openvsx" => format!(
            "pkg:vscode-extension/{}{}{}",
            path.to_ascii_lowercase(),
            add_qualifier(tail, "repository_url=https://open-vsx.org"),
            subpath,
        ),
        // PyPI treats `-`/`_`/`.` as one separator and names as
        // case-insensitive — PEP 503 is the registry's own equivalence — so
        // the canonical name is the PEP 503 normalization. (There is no
        // namespace; the path is the name.) npm is deliberately NOT folded:
        // legacy mixed-case names were grandfathered in and stay distinct.
        "pypi" => format!("pkg:pypi/{}{tail}{subpath}", normalize_pypi(path)),
        // Composer names are case-insensitive per spec and lowercased.
        "composer" => format!("pkg:composer/{}{tail}{subpath}", path.to_ascii_lowercase()),
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
                    "pkg:alpm/aur/{}{rest_tail}{subpath}",
                    last_segment(path).to_ascii_lowercase()
                )
            } else if let Some(name) = path.strip_prefix("aur/") {
                format!("pkg:alpm/aur/{}{tail}{subpath}", name.to_ascii_lowercase())
            } else {
                format!("pkg:alpm/{path}{tail}{subpath}")
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
                format!("pkg:{spec}/{ns}/{name}{tail}{subpath}")
            } else {
                // Language/registry and unrecognized types: canonical type, body
                // case preserved (significance is type-specific).
                format!("pkg:{typ}/{path}{tail}{subpath}")
            }
        }
    })
}

/// The identity-key form of a PURL: [`normalize`], with the subpath and
/// artifact-selection qualifiers dropped. This — not the full normalized form
/// — is what the bloom producer inserts and the scanner looks up.
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
    // A subpath addresses content inside the package, not a different release.
    // Drop it before qualifiers so a fragment cannot hitch a ride in the last
    // qualifier value and survive release-key flattening.
    let coordinate = full.split_once('#').map_or(full.as_str(), |(head, _)| head);
    let Some((head, quals)) = coordinate.split_once('?') else {
        return Some(coordinate.to_string());
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
/// and the permitted slashes after `pkg:` are ignored. `None` when the string
/// has no `pkg:` scheme, has an invalid type, or has no `/`. Shared by the
/// registry parser and the fetch resolver so both read any spelling
/// [`normalize`] accepts.
pub(crate) fn scheme_type_rest(purl: &str) -> Option<(String, &str)> {
    let s = purl.trim();
    // `get(..4)` (not a direct slice) so a multi-byte character at the
    // boundary yields None instead of a panic.
    let body = s
        .get(..4)
        .filter(|scheme| scheme.eq_ignore_ascii_case("pkg:"))
        .map(|_| &s[4..])?;
    let body = body.trim_start_matches('/');
    let (ty, rest) = body.split_once('/')?;
    if !valid_type(ty) {
        return None;
    }
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
    fn purl_spec_vectors_for_target_ecosystems_are_canonical() {
        // Snapshot of every non-trivial `validate` vector in the local
        // purl-spec corpus for npm, PyPI, Gem, Go, and Cargo. Keeping these
        // inline makes the test hermetic while tying each behavior to the
        // specification rather than registry folklore.
        let cases = [
            (
                "pkg:npm/%40angular/animation@12.3.1",
                "pkg:npm/%40angular/animation@12.3.1",
            ),
            (
                "pkg:npm/mypackage@12.4.5?vcs_url=git://host.com/path/to/repo.git%404345abcd34343",
                "pkg:npm/mypackage@12.4.5?vcs_url=git:%2F%2Fhost.com%2Fpath%2Fto%2Frepo.git%404345abcd34343",
            ),
            (
                "pkg:npm/@babel/core#/googleapis/api/annotations/",
                "pkg:npm/%40babel/core#googleapis/api/annotations",
            ),
            (
                "pkg:npm/core@2.0.1#/googleapis/api/annotations/",
                "pkg:npm/core@2.0.1#googleapis/api/annotations",
            ),
            (
                "pkg:PYPI/Django_package@1.11.1.DEV1",
                "pkg:pypi/django-package@1.11.1.dev1",
            ),
            (
                "pkg:pypi/django@1.11.1?file_name=Django-1.11.1-py2.py3-none-any.whl",
                "pkg:pypi/django@1.11.1?file_name=Django-1.11.1-py2.py3-none-any.whl",
            ),
            (
                "pkg:gem/jruby-launcher@1.1.2?Platform=java",
                "pkg:gem/jruby-launcher@1.1.2?platform=java",
            ),
            (
                "pkg:GOLANG/google.golang.org/genproto@abcdedf#/googleapis/api/annotations/",
                "pkg:golang/google.golang.org/genproto@abcdedf#googleapis/api/annotations",
            ),
            ("pkg:cargo/structopt@0.3.11", "pkg:cargo/structopt@0.3.11"),
        ];
        for (input, expected) in cases {
            assert_eq!(norm(input), expected, "purl-spec vector {input}");
        }
    }

    #[test]
    fn generic_component_rules_canonicalize_or_reject() {
        let cases = [
            (
                "PKG:////generic/naïve package@1.0+local?Z=last&a=https://x/y&empty=#/src//./../lib/",
                "pkg:generic/na%C3%AFve%20package@1.0%2Blocal?a=https:%2F%2Fx%2Fy&z=last#src/lib",
            ),
            (
                "pkg:generic/bitwarderl?checksum=sha1:ad9503%2csha256:41bf",
                "pkg:generic/bitwarderl?checksum=sha1:ad9503%2Csha256:41bf",
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(norm(input), expected, "canonicalize {input}");
            assert_eq!(norm(expected), expected, "fixed point {expected}");
        }

        for invalid in [
            "pkg:3npm/name",
            "pkg:n&pm/name",
            "pkg:npm/name?in%20production=true",
            "pkg:npm/name?a=1&A=2",
            "pkg:npm/name@1.0?vers=vers:npm%2F%3E1",
            "pkg:pypi/namespace/name@1",
            "pkg:gem/namespace/name@1",
            "pkg:cargo/namespace/name@1",
            "pkg:golang/name@1",
            "pkg:golang/example.com/name#safe%2Fescape",
            "pkg:npm/name@bad%2",
        ] {
            assert_eq!(normalize(invalid), None, "reject {invalid}");
        }
    }

    #[test]
    fn cross_type_definition_edge_rules_are_covered() {
        let cases = [
            (
                "pkg:bitbucket/birKenfeld/pyGments-main@244fd47e",
                "pkg:bitbucket/birkenfeld/pygments-main@244fd47e",
            ),
            (
                "pkg:git/github/Package-url/purl-Spec@244fd47e",
                "pkg:git/github/package-url/purl-spec@244fd47e",
            ),
            (
                "pkg:hackage/AC-HalfInteger@1.2.1",
                "pkg:hackage/AC-HalfInteger@1.2.1",
            ),
            (
                "pkg:mlflow/CreditFraud@3?repository_url=https://adb-1.azuredatabricks.net/api/2.0/mlflow",
                "pkg:mlflow/creditfraud@3?repository_url=https:%2F%2Fadb-1.azuredatabricks.net%2Fapi%2F2.0%2Fmlflow",
            ),
            (
                "pkg:mlflow/CreditFraud@3?repository_url=https://westus.api.azureml.ms/mlflow",
                "pkg:mlflow/CreditFraud@3?repository_url=https:%2F%2Fwestus.api.azureml.ms%2Fmlflow",
            ),
            (
                "pkg:julia/Dates@1.9.0?uuid=ade2ca70-3891-5945-98fb-dc099432e06a",
                "pkg:julia/Dates@1.9.0?uuid=ade2ca70-3891-5945-98fb-dc099432e06a",
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(norm(input), expected, "type rule {input}");
        }

        for invalid in [
            "pkg:cpan/GDT/URI::PackageURL",
            "pkg:julia/Dates@1.9.0",
            "pkg:swid/Fedora@29",
            "pkg:swift/github.com/Alamofire/@5.4.3",
        ] {
            assert_eq!(normalize(invalid), None, "type rule rejects {invalid}");
        }
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
                "pkg:vscode-extension/jinryx/crontally@1.0.3?repository_url=https:%2F%2Fopen-vsx.org",
            ),
            // PyPI folds per PEP 503 (the registry's own equivalence:
            // lowercase, separator runs collapse); composer lowercases.
            ("pkg:pypi/Ruamel.Yaml@0.18.6", "pkg:pypi/ruamel-yaml@0.18.6"),
            (
                "pkg:pypi/backports__zoneinfo",
                "pkg:pypi/backports-zoneinfo",
            ),
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
            "pkg:vscode-extension/pub/name@1.0.3?repository_url=https:%2F%2Fopen-vsx.org"
        );
        // A qualifier value containing `@` (URL userinfo) is not a version, and
        // a repository_url naming something other than the AUR is kept.
        assert_eq!(
            norm("pkg:alpm/arch/yay?repository_url=https://user@example.com/repo"),
            "pkg:alpm/arch/yay?repository_url=https:%2F%2Fuser%40example.com%2Frepo"
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
                "pkg:rpm/fedora/centerim@4.22.10-1.el6?arch=i686&distro=fedora-25&epoch=1",
            ),
            ("pkg:rpm/Fedora/curl@1.0", "pkg:rpm/fedora/curl@1.0"),
            (
                "pkg:deb/curl@7.50.3-1?arch=amd64&distro=ubuntu-22.04",
                "pkg:deb/ubuntu/curl@7.50.3-1?arch=amd64&distro=ubuntu-22.04",
            ),
        ];
        for (input, want) in cases {
            assert_eq!(norm(input), want, "normalize {input}");
            assert_eq!(norm(want), want, "idempotent {want}");
        }
        // `deb` requires a namespace. A codename alone cannot identify the
        // repository vendor and therefore cannot repair the missing component.
        assert_eq!(
            normalize("pkg:deb/curl@7.50.3-1?arch=i386&distro=jessie"),
            None
        );
        // Identity then flattens the artifact-selection qualifiers, so the
        // spec example keys onto the pool's bare release coordinate.
        assert_eq!(
            identity("pkg:rpm/centerim@4.22.10-1.el6?arch=i686&epoch=1&distro=fedora-25")
                .as_deref(),
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
            "pkg:npm",          // no name at all
            "pkg:npm/",         // empty name
            "pkg:npm/@1.0.0",   // version but no name
            "pkg:/lodash",      // empty type
            "pkg:alpm/aur/",    // empty name behind a namespace
            "npm/lodash@1.0.0", // no pkg: scheme
            "not-a-purl",
            "https://example.com/x.tgz",
        ] {
            assert_eq!(normalize(junk), None, "{junk:?} must not normalize");
        }
        // The guards reject degenerate inputs, not unusual-but-real ones.
        assert!(normalize("pkg:npm/%40scope/name@1.0.0").is_some());
        assert!(normalize("pkg:npm/@scope/name@1.0.0").is_some());
    }

    /// An npm scope is written `@scope/name`, and the leading `@` is part of
    /// the name — not the version separator. Reading it as a separator left an
    /// empty coordinate path, so every scoped package (a large share of npm)
    /// was refused outright as "not a package URL".
    #[test]
    fn scoped_npm_names_are_not_read_as_versions() {
        assert_eq!(
            norm("pkg:npm/@scope/name@1.0.0"),
            "pkg:npm/%40scope/name@1.0.0"
        );
        assert_eq!(
            norm("pkg:npm/@babel/core@7.24.0"),
            "pkg:npm/%40babel/core@7.24.0"
        );
        // No version, and with qualifiers, still split at the right `@`.
        assert_eq!(norm("pkg:npm/@scope/name"), "pkg:npm/%40scope/name");
        assert_eq!(
            norm("pkg:npm/@scope/name@1.0.0?arch=x64"),
            "pkg:npm/%40scope/name@1.0.0?arch=x64",
        );
        // The sigil is a scope only when a `/` closes it. These name nothing.
        assert_eq!(normalize("pkg:npm/@1.0.0"), None);
        assert_eq!(normalize("pkg:npm/@1.0.0?repository_url=https://x/y"), None);
        assert_eq!(normalize("pkg:npm/@"), None);
    }

    /// Both spellings of a scope are the same package, so they must produce the
    /// same key: the bloom filters and the verdict index are keyed on this
    /// output, and two keys for one package means every lookup made with one
    /// spelling misses an answer stored under the other.
    #[test]
    fn scope_spellings_converge_on_one_key() {
        assert_eq!(
            norm("pkg:npm/@babel/core@7.24.0"),
            norm("pkg:npm/%40babel/core@7.24.0"),
        );
        assert_eq!(
            identity("pkg:npm/@babel/core@7.24.0?kind=x"),
            identity("pkg:npm/%40babel/core@7.24.0?kind=x"),
        );
    }

    #[test]
    fn encoded_version_is_a_normalization_fixed_point() {
        let purl = "pkg:golang/github.com/gofrs/uuid@v4.4.0%2Bincompatible";
        assert_eq!(norm(purl), purl);
        assert_eq!(identity(purl).as_deref(), Some(purl));
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
            (
                "pkg:pypi/requests@2.31.0?kind=sdist",
                "pkg:pypi/requests@2.31.0",
            ),
            (
                "pkg:openvsx/pub/name@1.0.3",
                "pkg:vscode-extension/pub/name@1.0.3?repository_url=https:%2F%2Fopen-vsx.org",
            ),
            // Folding and identity compose: the qualifier AUR form with an
            // arch stamp lands on the bare aur-namespace coordinate.
            (
                "pkg:alpm/arch/yay@12.3.0-1?arch=x86_64&repository_url=https://aur.archlinux.org",
                "pkg:alpm/aur/yay@12.3.0-1",
            ),
            // No qualifiers → identity is the normalized form itself.
            ("pkg:npm/lodash@4.17.21", "pkg:npm/lodash@4.17.21"),
            (
                "pkg:golang/google.golang.org/genproto@abcd#googleapis/api",
                "pkg:golang/google.golang.org/genproto@abcd",
            ),
            (
                "pkg:npm/%40scope/name@1.0?repository_url=https://npm.example#src/index.js",
                "pkg:npm/%40scope/name@1.0?repository_url=https:%2F%2Fnpm.example",
            ),
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
            "pkg:npm/@babel/core@7.24.0",
            "pkg:npm/@scope/name",
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod url_to_purl_tests {
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
