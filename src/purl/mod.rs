//! Package URLs: parsing, the canonical spelling, and the keys derived from it.
//!
//! [`Purl`] is a decoded, validated package URL (ECMA-427, the purl-spec).
//! Every constructor yields its one canonical form, so two spellings of the
//! same package compare equal and print the same.
//!
//! Three string forms are a contract with every consumer that keys on them,
//! and must be computed here on both sides of a lookup or lookups silently
//! miss:
//!
//! - [`normalize`]: the canonical spelling ([`Purl`]'s `Display`).
//! - [`identity`]: the release key ([`Purl::identity`]), with the qualifiers
//!   that only select bytes within a release dropped.
//! - [`url_to_purl`]: the package a registry download URL points at
//!   ([`Purl::from_url`]).

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::fmt::{self, Write as _};

use serde::Serialize;

mod from_url;
mod rules;

pub use from_url::url_to_purl;
pub(crate) use rules::known_type;

/// A decoded, validated package URL with one canonical spelling.
///
/// Its `Display` form is canonical: percent escapes use uppercase triplets,
/// qualifier keys are lowercase and sorted, empty qualifier values and
/// ignorable subpath segments are gone, and component case follows the type's
/// definition. Parsing that form yields an equal value.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct Purl {
    #[serde(rename = "type")]
    typ: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    namespace: Vec<String>,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    qualifiers: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    subpath: Vec<String>,
}

/// Why a string or a set of components is not a package URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum PurlError {
    /// The generic ECMA-427 structure is malformed.
    #[error("invalid package URL syntax: {0}")]
    Syntax(&'static str),
    /// The structure is valid but violates its type's definition.
    #[error("package URL violates its type definition: {0}")]
    Type(&'static str),
}

/// How literally a package URL is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// The purl-spec, plus the non-spec type
    /// spellings [`rules::fold_legacy`] folds, and the misplaced version
    /// [`misplaced_version`] repairs.
    Lenient,
    /// The purl-spec `parse` contract and nothing more: in particular, a
    /// qualifier key the type declares must be lowercase.
    Strict,
}

impl Purl {
    /// Parse a package URL into its canonical form.
    ///
    /// Tolerates non-canonical spelling: the case of the scheme, type, percent
    /// escapes and qualifier keys, qualifier order, literal Unicode, repeated
    /// `/`, and ignorable subpath segments. Folds the non-spec spellings
    /// listed on [`normalize`] onto their spec form.
    pub fn parse(raw: &str) -> Result<Self, PurlError> {
        parse(raw, Mode::Lenient)
    }

    /// Parse per the purl-spec `parse` contract. Unlike [`Purl::parse`], this
    /// rejects a qualifier key the type's definition declares (gem
    /// `platform`, rpm `arch`, …) unless it is spelled in lowercase, folds no
    /// non-spec type spelling, and never reads a version out of the
    /// qualifiers.
    pub fn parse_strict(raw: &str) -> Result<Self, PurlError> {
        parse(raw, Mode::Strict)
    }

    /// Build a package URL from decoded components: the purl-spec `build`
    /// operation.
    ///
    /// `namespace` and `subpath` are `/`-separated; their empty segments, and
    /// `.` and `..` subpath segments, are dropped. An empty `version` is
    /// absent. Qualifier keys are case-folded and qualifiers with an empty
    /// value dropped. The result is folded and validated as by
    /// [`Purl::parse`].
    pub fn build<'a>(
        typ: &str,
        namespace: Option<&str>,
        name: &str,
        version: Option<&str>,
        qualifiers: impl IntoIterator<Item = (&'a str, &'a str)>,
        subpath: Option<&str>,
    ) -> Result<Self, PurlError> {
        let mut decoded = BTreeMap::new();
        for (key, value) in qualifiers {
            insert_qualifier(&mut decoded, key.to_ascii_lowercase(), value.to_owned())?;
        }
        let purl = Self {
            typ: typ.to_owned(),
            namespace: namespace
                .unwrap_or_default()
                .split('/')
                .filter(|segment| !segment.is_empty())
                .map(str::to_owned)
                .collect(),
            name: name.to_owned(),
            version: version
                .filter(|version| !version.is_empty())
                .map(str::to_owned),
            qualifiers: decoded,
            subpath: subpath
                .unwrap_or_default()
                .split('/')
                .filter(|segment| !matches!(*segment, "" | "." | ".."))
                .map(str::to_owned)
                .collect(),
        };
        finish(purl, Mode::Lenient)
    }

    /// Registered or custom package type, lowercase.
    #[must_use]
    pub fn typ(&self) -> &str {
        &self.typ
    }

    /// Decoded namespace segments.
    #[must_use]
    pub fn namespace(&self) -> &[String] {
        &self.namespace
    }

    /// Decoded package name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Decoded opaque version.
    #[must_use]
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    /// Decoded qualifiers in canonical key order.
    #[must_use]
    pub fn qualifiers(&self) -> &BTreeMap<String, String> {
        &self.qualifiers
    }

    /// One qualifier's decoded value. Keys are canonical, so lowercase.
    #[must_use]
    pub fn qualifier(&self, key: &str) -> Option<&str> {
        self.qualifiers.get(key).map(String::as_str)
    }

    /// Decoded relative subpath segments.
    #[must_use]
    pub fn subpath(&self) -> &[String] {
        &self.subpath
    }

    /// The namespace and name as one `/`-joined path, every segment
    /// percent-encoded exactly as in the [`Display`](std::fmt::Display) form
    /// (`%40scope/name`, `vendor/name`): the coordinate a registry URL is
    /// built from.
    #[must_use]
    pub fn encoded_path(&self) -> String {
        EncodedPath(self).to_string()
    }

    /// The version, percent-encoded exactly as in the [`Display`](std::fmt::Display) form.
    #[must_use]
    pub fn encoded_version(&self) -> Option<String> {
        self.version.as_deref().map(encode_component)
    }

    /// The decoded subpath joined with `/`.
    pub(crate) fn subpath_string(&self) -> Option<String> {
        (!self.subpath.is_empty()).then(|| self.subpath.join("/"))
    }

    /// The key of the release this PURL names: the subpath dropped, and every
    /// qualifier that selects bytes within a release (`checksum`,
    /// `file_name`, and the type's own, such as PyPI `kind` or rpm `arch`).
    ///
    /// Every other qualifier is kept, because it can name a different release
    /// of the same name and version: a conda `channel`, an rpm `epoch`, a
    /// `repository_url`, or a `download_url` that swaps the bytes outright. A
    /// qualifier not known to select bytes is kept too, so an unfamiliar
    /// spelling misses a lookup rather than borrowing another release's
    /// record.
    #[must_use]
    pub fn identity(&self) -> Self {
        let mut key = self.clone();
        key.subpath.clear();
        key.qualifiers
            .retain(|qualifier, _| !rules::selects_artifact(&self.typ, qualifier));
        key
    }

    /// The [`identity`](Self::identity) of this package's release `version`,
    /// with any `vers` range replaced by that version.
    pub fn release(&self, version: &str) -> Result<Self, PurlError> {
        if version.is_empty() {
            return Err(PurlError::Syntax("version is empty"));
        }
        let mut release = self.identity();
        release.version = Some(version.to_owned());
        release.qualifiers.remove("vers");
        rules::apply(&mut release)?;
        Ok(release)
    }

    /// One concrete artifact of this release: its
    /// [`identity`](Self::identity) with the resolver's exact `selectors`
    /// (`file_name`, `platform`, `checksum`, …) set as qualifiers.
    pub fn artifact(&self, selectors: &BTreeMap<String, String>) -> Result<Self, PurlError> {
        let mut artifact = self.identity();
        for (key, value) in selectors {
            if !valid_qualifier_key(key) {
                return Err(PurlError::Syntax("invalid qualifier key"));
            }
            if value.is_empty() {
                return Err(PurlError::Syntax("artifact selector is empty"));
            }
            artifact.qualifiers.insert(key.clone(), value.clone());
        }
        rules::apply(&mut artifact)?;
        Ok(artifact)
    }

    /// This PURL at `version` (none when empty), validated against the
    /// type's rules as a parsed one would be.
    pub(crate) fn with_version(&self, version: &str) -> Option<Self> {
        let mut next = self.clone();
        next.version = (!version.is_empty()).then(|| version.to_owned());
        finish(next, Mode::Lenient).ok()
    }

    /// This PURL with qualifier `key` set to `value`, or removed when `None`
    /// or empty, validated against the type's rules as a parsed one would be.
    pub(crate) fn with_qualifier(&self, key: &str, value: Option<&str>) -> Option<Self> {
        let mut next = self.clone();
        next.qualifiers.remove(key);
        if let Some(value) = value {
            insert_qualifier(&mut next.qualifiers, key.to_owned(), value.to_owned()).ok()?;
        }
        finish(next, Mode::Lenient).ok()
    }
}

impl std::str::FromStr for Purl {
    type Err = PurlError;

    /// The same as [`Purl::parse`].
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        Self::parse(raw)
    }
}

impl fmt::Display for Purl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pkg:{}/{}", self.typ, EncodedPath(self))?;
        if let Some(version) = &self.version {
            write!(f, "@{}", Encoded(version))?;
        }
        for (index, (key, value)) in self.qualifiers.iter().enumerate() {
            let separator = if index == 0 { '?' } else { '&' };
            write!(f, "{separator}{key}={}", Encoded(value))?;
        }
        for (index, segment) in self.subpath.iter().enumerate() {
            let separator = if index == 0 { '#' } else { '/' };
            write!(f, "{separator}{}", Encoded(segment))?;
        }
        Ok(())
    }
}

/// A [`Purl`]'s namespace and name, percent-encoded and `/`-joined.
struct EncodedPath<'a>(&'a Purl);

impl fmt::Display for EncodedPath<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // A git name is a repository path whose `/` separators stay literal.
        let git = self.0.typ == "git";
        let name = self.0.name.split(move |c| git && c == '/');
        let segments = self.0.namespace.iter().map(String::as_str).chain(name);
        for (index, segment) in segments.enumerate() {
            if index > 0 {
                f.write_char('/')?;
            }
            Encoded(segment).fmt(f)?;
        }
        Ok(())
    }
}

/// One component percent-encoded: every byte but the unreserved set and `:`.
struct Encoded<'a>(&'a str);

impl fmt::Display for Encoded<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0.bytes() {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'~' | b':') {
                f.write_char(char::from(byte))?;
            } else {
                write!(f, "%{byte:02X}")?;
            }
        }
        Ok(())
    }
}

/// Percent-encode one PURL component as the canonical spelling does.
pub(crate) fn encode_component(value: &str) -> String {
    Encoded(value).to_string()
}

/// The canonical spelling of a package URL, or `None` when the input does not
/// denote a package: the string form of [`Purl::parse`].
///
/// This is the entry-point normalizer for package URLs arriving from outside,
/// so that registry lookup, fetch, display and provenance all see one
/// spelling, and a key both a producer and a consumer must compute
/// identically.
///
/// Beyond the purl-spec it folds these spellings onto spec form:
/// - `pkg:chrome` → `chrome-extension`; `pkg:vscode` → `vscode-extension`;
///   `pkg:openvsx` → `vscode-extension` with
///   `repository_url=https://open-vsx.org`; `pkg:homebrew` → `brew`.
/// - The bare distro types `pkg:debian`/`ubuntu`/`fedora`/`opensuse`/
///   `rpmfusion`/`arch`/`aur`/`alpine`/`wolfi` → `deb`/`rpm`/`alpm`/`apk`
///   with the distro as namespace.
/// - An alpm PURL whose `repository_url` is hosted on `aur.archlinux.org` →
///   `pkg:alpm/aur/<name>`, that qualifier dropped.
/// - A deb/rpm/apk/alpm PURL with no namespace recovers it from a `distro`
///   qualifier naming a known vendor
///   (`pkg:rpm/curl?distro=fedora-25` → `pkg:rpm/fedora/curl?distro=fedora-25`).
/// - The `?repository_url=<origin>@<version>` order one producer wrote is
///   read as `@<version>?repository_url=<origin>`.
#[must_use]
pub fn normalize(raw: &str) -> Option<String> {
    Purl::parse(raw).ok().map(|purl| purl.to_string())
}

/// The release key of a package URL, or `None` when the input does not denote
/// a package: the string form of [`Purl::identity`].
///
/// Producers that build lookup indexes and consumers that query them must
/// both key on this exact form.
#[must_use]
pub fn identity(raw: &str) -> Option<String> {
    Purl::parse(raw)
        .ok()
        .map(|purl| purl.identity().to_string())
}

fn parse(raw: &str, mode: Mode) -> Result<Purl, PurlError> {
    split(raw, mode)
        .and_then(|purl| finish(purl, mode))
        .inspect_err(|error| {
            tracing::trace!(%error, strict = mode == Mode::Strict, "not a package URL");
        })
}

/// Validate decoded components, fold non-spec spellings when lenient, and
/// apply the type's rules: the one path every constructor ends on.
fn finish(mut purl: Purl, mode: Mode) -> Result<Purl, PurlError> {
    let valid_type = purl
        .typ
        .bytes()
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && purl
            .typ
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'));
    if !valid_type {
        return Err(PurlError::Syntax(
            "type is not a letter followed by letters, digits, '.' or '-'",
        ));
    }
    purl.typ.make_ascii_lowercase();
    if purl.name.is_empty() {
        return Err(PurlError::Syntax("name is empty"));
    }
    if purl
        .namespace
        .iter()
        .any(|segment| segment.is_empty() || segment.contains('/'))
    {
        return Err(PurlError::Syntax("namespace segment is empty or holds '/'"));
    }
    if mode == Mode::Lenient {
        rules::fold_legacy(&mut purl);
    }
    rules::apply(&mut purl)?;
    Ok(purl)
}

/// Split and decode the ECMA-427 components, right to left as the standard
/// reads them.
fn split(raw: &str, mode: Mode) -> Result<Purl, PurlError> {
    let (scheme, body) = raw
        .trim()
        .split_once(':')
        .ok_or(PurlError::Syntax("no scheme"))?;
    if !scheme.eq_ignore_ascii_case("pkg") {
        return Err(PurlError::Syntax("scheme is not pkg"));
    }
    let (typ, remainder) = body
        .trim_start_matches('/')
        .split_once('/')
        .ok_or(PurlError::Syntax("no type"))?;
    let (remainder, subpath) = remainder
        .rsplit_once('#')
        .map_or((remainder, None), |(left, right)| (left, Some(right)));
    let (coordinate, qualifiers) = remainder
        .rsplit_once('?')
        .map_or((remainder, None), |(left, right)| (left, Some(right)));
    // A delimiter left in an earlier component is not data (data is
    // percent-encoded), so reject it rather than guess which one splits.
    if remainder.contains('#') || coordinate.contains('?') {
        return Err(PurlError::Syntax("unencoded '#' or '?'"));
    }

    let (path, version) = split_version(coordinate.trim_matches('/'))?;
    let (version, qualifiers) = match (mode, version, qualifiers.and_then(misplaced_version)) {
        (Mode::Lenient, None, Some((qualifiers, version))) => {
            tracing::debug!(%version, "read a version misplaced after the qualifiers");
            (Some(version), Some(qualifiers))
        }
        _ => (version, qualifiers),
    };
    if path.ends_with('/') {
        return Err(PurlError::Syntax("name is empty"));
    }
    let mut namespace = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(decode)
        .collect::<Result<Vec<_>, _>>()?;
    let name = namespace.pop().ok_or(PurlError::Syntax("name is empty"))?;
    Ok(Purl {
        typ: typ.to_owned(),
        namespace,
        name,
        version: version
            .filter(|version| !version.is_empty())
            .map(decode)
            .transpose()?,
        qualifiers: parse_qualifiers(qualifiers.unwrap_or_default(), typ, mode)?,
        subpath: parse_subpath(subpath.unwrap_or_default())?,
    })
}

/// Split `coordinate` at its version `@`: the last one, except that a
/// coordinate never starts with its version, so a leading `@` opens a scope
/// (`@babel/core`, `@std/path`) and the version can only follow the `/` that
/// closes it.
fn split_version(coordinate: &str) -> Result<(&str, Option<&str>), PurlError> {
    let start = if coordinate.starts_with('@') {
        coordinate
            .find('/')
            .ok_or(PurlError::Syntax("'@' scope is not closed by '/'"))?
            + 1
    } else {
        0
    };
    Ok(match coordinate[start..].rfind('@') {
        Some(at) => (
            &coordinate[..start + at],
            Some(&coordinate[start + at + 1..]),
        ),
        None => (coordinate, None),
    })
}

/// The version one producer misplaced after the qualifiers, by appending
/// `@<version>` to a PURL whose last qualifier was a `repository_url` naming a
/// bare registry origin: `…?repository_url=https://aur.archlinux.org@1.0-1`.
/// Returns the qualifiers without it, and the version.
///
/// Only that exact shape is read as a version. Anywhere else a trailing `@…`
/// belongs to a qualifier value: the userinfo of a URL
/// (`vcs_url=git+ssh://git@github.com`) or a revision
/// (`vcs_url=…/repo.git@4345abcd`).
fn misplaced_version(qualifiers: &str) -> Option<(&str, &str)> {
    let (before, version) = qualifiers.rsplit_once('@')?;
    let origin = before.rsplit('&').next()?.strip_prefix("repository_url=")?;
    let host = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))?;
    let bare_host = host.contains('.')
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'));
    let plain_version = version
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_digit())
        && !version.contains(['=', '&', '/']);
    (bare_host && plain_version).then_some((before, version))
}

/// Parse the `&`-separated qualifiers of a PURL of type `typ`. Keys are
/// case-insensitive (ECMA-427), except that strict mode holds a key the type's
/// definition declares to its declared lowercase spelling.
fn parse_qualifiers(
    raw: &str,
    typ: &str,
    mode: Mode,
) -> Result<BTreeMap<String, String>, PurlError> {
    let mut qualifiers = BTreeMap::new();
    for pair in raw.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair
            .split_once('=')
            .ok_or(PurlError::Syntax("qualifier has no '='"))?;
        let lower = key.to_ascii_lowercase();
        if mode == Mode::Strict
            && lower != key
            && rules::defines_qualifier(&typ.to_ascii_lowercase(), &lower)
        {
            return Err(PurlError::Syntax(
                "qualifier key declared by the type is not lowercase",
            ));
        }
        insert_qualifier(&mut qualifiers, lower, decode(value)?)?;
    }
    Ok(qualifiers)
}

/// Add one qualifier: the key must be canonical, an empty value is no
/// qualifier at all, and a key may appear once.
fn insert_qualifier(
    qualifiers: &mut BTreeMap<String, String>,
    key: String,
    value: String,
) -> Result<(), PurlError> {
    if !valid_qualifier_key(&key) {
        return Err(PurlError::Syntax("invalid qualifier key"));
    }
    if value.is_empty() {
        return Ok(());
    }
    match qualifiers.entry(key) {
        Entry::Vacant(entry) => {
            entry.insert(value);
            Ok(())
        }
        Entry::Occupied(_) => Err(PurlError::Syntax("duplicate qualifier key")),
    }
}

fn parse_subpath(raw: &str) -> Result<Vec<String>, PurlError> {
    let mut subpath = Vec::new();
    for segment in raw.split('/') {
        let segment = decode(segment)?;
        if matches!(segment.as_str(), "" | "." | "..") {
            continue;
        }
        if segment.contains('/') {
            return Err(PurlError::Syntax("subpath segment holds '/'"));
        }
        subpath.push(segment);
    }
    Ok(subpath)
}

fn valid_qualifier_key(key: &str) -> bool {
    key.bytes()
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && key.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_')
        })
}

/// The byte a `%HH` escape's two hex digits spell. Only ASCII hex digits
/// count: `u8::from_str_radix` alone also accepts a sign, so `%+4` would
/// decode to `0x04`.
pub(crate) fn hex_pair(pair: &[u8]) -> Option<u8> {
    let [hi, lo] = pair else {
        return None;
    };
    let digit = |d: &u8| char::from(*d).to_digit(16);
    u8::try_from(digit(hi)? * 16 + digit(lo)?).ok()
}

/// Percent-decode one component; every `%` must open a valid escape and the
/// result must be UTF-8.
fn decode(value: &str) -> Result<String, PurlError> {
    const INVALID: PurlError = PurlError::Syntax("invalid percent-encoding");
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        if byte == b'%' {
            let escape = bytes.get(index + 1..index + 3).ok_or(INVALID)?;
            decoded.push(hex_pair(escape).ok_or(INVALID)?);
            index += 3;
        } else {
            decoded.push(byte);
            index += 1;
        }
    }
    String::from_utf8(decoded).map_err(|_not_utf8| PurlError::Syntax("not UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `normalize` on input that must succeed.
    fn norm(raw: &str) -> String {
        normalize(raw).unwrap_or_else(|| panic!("{raw} must normalize"))
    }

    #[test]
    fn scheme_and_type_fold_case_bodies_per_type() {
        // npm keeps name case (mixed-case names are grandfathered and
        // distinct); pypi folds per PEP 503.
        assert_eq!(norm("  PKG:NPM/Left-Pad@1.3.0 "), "pkg:npm/Left-Pad@1.3.0");
        assert_eq!(norm("pkg:PyPI/Requests"), "pkg:pypi/requests");
    }

    #[test]
    fn purl_spec_vectors_for_target_ecosystems_are_canonical() {
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
            "pkg:golang/example.com/name#safe%2Fescape",
            "pkg:npm/name@bad%2",
            "pkg:npm/a#b#c",
            "pkg:npm/a?b?c=1",
        ] {
            assert_eq!(normalize(invalid), None, "reject {invalid}");
        }
    }

    #[test]
    fn errors_name_their_reason() {
        assert!(matches!(
            Purl::parse("not-a-purl"),
            Err(PurlError::Syntax("no scheme"))
        ));
        assert!(matches!(
            Purl::parse("pkg:npm/name@bad%2"),
            Err(PurlError::Syntax("invalid percent-encoding"))
        ));
        assert!(matches!(
            Purl::parse("pkg:pypi/namespace/name"),
            Err(PurlError::Type(_))
        ));
        let error = Purl::parse("pkg:npm/a?x").expect_err("qualifier without '='");
        assert_eq!(
            error.to_string(),
            "invalid package URL syntax: qualifier has no '='"
        );
    }

    #[test]
    fn display_and_from_str_are_the_canonical_spelling() {
        let purl: Purl = "pkg:NPM/@babel/core@7.24.0?B=2&a=1#/src/".parse().unwrap();
        assert_eq!(purl.to_string(), "pkg:npm/%40babel/core@7.24.0?a=1&b=2#src");
        assert_eq!(purl.to_string(), purl.to_string());
        assert_eq!(purl.to_string().parse::<Purl>(), Ok(purl.clone()));
        assert_eq!(purl.encoded_path(), "%40babel/core");
        assert_eq!(purl.encoded_version().as_deref(), Some("7.24.0"));
        assert_eq!(purl.subpath_string().as_deref(), Some("src"));
    }

    #[test]
    fn degenerate_inputs_never_yield_a_key() {
        for junk in [
            "",
            "   ",
            "pkg:",
            "pkg:npm",
            "pkg:npm/",
            "pkg:npm/@1.0.0",
            "pkg:/lodash",
            "pkg:alpm/aur/",
            "pkg:npm/foo/@1.0",
            "npm/lodash@1.0.0",
            "not-a-purl",
            "https://example.com/x.tgz",
        ] {
            assert_eq!(normalize(junk), None, "{junk:?} must not normalize");
        }
        assert!(normalize("pkg:npm/%40scope/name@1.0.0").is_some());
        assert!(normalize("pkg:npm/@scope/name@1.0.0").is_some());
    }

    /// A scope is written `@scope/name`, and its leading `@` is part of the
    /// name, not the version separator.
    #[test]
    fn scoped_names_are_not_read_as_versions() {
        assert_eq!(
            norm("pkg:npm/@scope/name@1.0.0"),
            "pkg:npm/%40scope/name@1.0.0"
        );
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

    /// A JSR package is always scoped, and its leading `@` is never the
    /// version separator, with or without a version.
    #[test]
    fn jsr_scope_parses_with_and_without_a_version() {
        assert_eq!(norm("pkg:jsr/@std/path"), "pkg:jsr/%40std/path");
        assert_eq!(norm("pkg:jsr/@std/path@1.0.0"), "pkg:jsr/%40std/path@1.0.0");
        let purl = Purl::parse("pkg:jsr/@std/path").unwrap();
        assert_eq!(purl.namespace(), ["@std"]);
        assert_eq!(purl.name(), "path");
        assert_eq!(purl.version(), None);
    }

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
    fn repairs_the_misplaced_version_producer_shape() {
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
        assert_eq!(
            norm("pkg:alpm/arch/x?arch=x86_64&repository_url=https://aur.archlinux.org@1.0-1"),
            "pkg:alpm/aur/x@1.0-1?arch=x86_64"
        );
        // A coordinate with its own version was not written by that producer.
        assert_eq!(
            norm("pkg:npm/lodash@1.0.0?repository_url=https://r.example@1.2-1"),
            "pkg:npm/lodash@1.0.0?repository_url=https:%2F%2Fr.example%401.2-1"
        );
    }

    /// A trailing `@…` in the qualifiers is a version only in the exact
    /// producer shape; a VCS revision or URL userinfo is never read as one.
    #[test]
    fn a_trailing_at_in_another_qualifier_is_never_a_version() {
        for (raw, value) in [
            (
                "pkg:npm/mypackage?vcs_url=git://host.com/path/to/repo.git@4345abcd34343",
                ("vcs_url", "git://host.com/path/to/repo.git@4345abcd34343"),
            ),
            (
                "pkg:npm/mypackage?vcs_url=git+ssh://git@github.com",
                ("vcs_url", "git+ssh://git@github.com"),
            ),
            (
                "pkg:npm/x?repository_url=https://user@example.com/repo",
                ("repository_url", "https://user@example.com/repo"),
            ),
            (
                "pkg:npm/x?repository_url=https://user@example.com",
                ("repository_url", "https://user@example.com"),
            ),
            (
                "pkg:npm/x?repository_url=https://r.example/path@1.0",
                ("repository_url", "https://r.example/path@1.0"),
            ),
            (
                "pkg:npm/x?repository_url=https://r.example@main",
                ("repository_url", "https://r.example@main"),
            ),
        ] {
            let purl = Purl::parse(raw).unwrap();
            assert_eq!(purl.version(), None, "{raw}");
            assert_eq!(purl.qualifier(value.0), Some(value.1), "{raw}");
        }
    }

    #[test]
    fn strict_parse_repairs_and_folds_nothing() {
        let raw = "pkg:vscode-extension/pub/name?repository_url=https://open-vsx.org@1.0.3";
        assert_eq!(Purl::parse(raw).unwrap().version(), Some("1.0.3"));
        assert_eq!(Purl::parse_strict(raw).unwrap().version(), None);
        assert!(Purl::parse_strict("pkg:debian/curl").is_ok_and(|p| p.typ() == "debian"));
        assert!(Purl::parse_strict("pkg:rpm/curl?distro=fedora-25").is_err());
    }

    /// Strict parsing holds every key a type's definition declares to
    /// lowercase, for every type, finding the qualifiers the way the parser
    /// does (`#` split off before `?`).
    #[test]
    fn strict_parse_rejects_uppercase_type_declared_keys() {
        for raw in [
            "pkg:gem/rails@7.0.0?Platform=java",
            "pkg:gem/rails@7.0.0?Platform=java#lib?x",
            "pkg:rpm/fedora/curl@1?EPOCH=1",
            "pkg:maven/g/a@1?Classifier=sources",
            "pkg:conda/numpy@1?Channel=conda-forge",
            "pkg:julia/Dates?UUID=ade2ca70-3891-5945-98fb-dc099432e06a",
        ] {
            assert!(
                matches!(Purl::parse_strict(raw), Err(PurlError::Syntax(_))),
                "{raw}"
            );
            assert!(Purl::parse(raw).is_ok(), "lenient {raw}");
        }
        // Keys no type declares are case-insensitive, as ECMA-427 says.
        let generic = Purl::parse_strict("pkg:maven/g/a@1?Repository_URL=https://x").unwrap();
        assert_eq!(generic.qualifier("repository_url"), Some("https://x"));
    }

    #[test]
    fn build_normalizes_raw_components() {
        let purl = Purl::build(
            "Golang",
            Some("/github.com//gorilla/"),
            "context",
            Some("v1.0.0+incompatible"),
            [("Repository_Url", "https://x"), ("empty", "")],
            Some("/a/./b/../c/"),
        )
        .unwrap();
        assert_eq!(
            purl.to_string(),
            "pkg:golang/github.com/gorilla/context@v1.0.0%2Bincompatible?repository_url=https:%2F%2Fx#a/b/c"
        );
        assert_eq!(
            Purl::build("npm", None, "", Some("1"), [], None),
            Err(PurlError::Syntax("name is empty"))
        );
        assert!(Purl::build("npm", None, "x", None, [("a b", "1")], None).is_err());
    }

    /// Build folds non-spec spellings exactly as parse does, so it never
    /// yields a spelling parse would not (`pkg:debian/curl`).
    #[test]
    fn build_folds_legacy_spellings_like_parse() {
        let built = Purl::build("debian", None, "curl", None, [], None).unwrap();
        assert_eq!(built.to_string(), "pkg:deb/debian/curl");
        assert_eq!(Ok(built), Purl::parse("pkg:debian/curl"));
    }

    #[test]
    fn encoded_version_is_a_normalization_fixed_point() {
        let purl = "pkg:golang/github.com/gofrs/uuid@v4.4.0%2Bincompatible";
        assert_eq!(norm(purl), purl);
        assert_eq!(identity(purl).as_deref(), Some(purl));
    }

    #[test]
    fn version_and_kind_come_from_the_parsed_purl() {
        for (tail, kind) in [
            ("1.2.3", None),
            ("1.2.3?kind=wheel", Some("wheel")),
            ("1.2.3?kind=sdist", Some("sdist")),
            ("1.2.3?foo=bar&kind=wheel", Some("wheel")),
            ("1.2.3?foo=bar", None),
        ] {
            let purl = Purl::parse(&format!("pkg:pypi/x@{tail}")).unwrap();
            assert_eq!(purl.version(), Some("1.2.3"), "{tail}");
            assert_eq!(purl.qualifier("kind"), kind, "{tail}");
        }
    }

    #[test]
    fn a_percent_escape_needs_two_hex_digits() {
        for bad in ["pkg:npm/foo%+4@1", "pkg:generic/a%+41@1", "pkg:npm/foo%4@1"] {
            assert!(
                matches!(Purl::parse(bad), Err(PurlError::Syntax(_))),
                "{bad}"
            );
        }
        assert_eq!(
            normalize("pkg:npm/foo%2d@1").as_deref(),
            Some("pkg:npm/foo-@1")
        );
        assert_eq!(hex_pair(b"4f"), Some(0x4f));
        assert_eq!(hex_pair(b"+4"), None);
        assert_eq!(hex_pair(b"4"), None);
        assert_eq!(crate::fetch::percent_decode("a%+41%41"), "a%+41A");
    }

    #[test]
    fn with_version_and_with_qualifier_revalidate() {
        let purl = Purl::parse("pkg:npm/a@1?version_requirement=%5E1").unwrap();
        let next = purl
            .with_qualifier("version_requirement", None)
            .and_then(|p| p.with_version("2.0.0"))
            .unwrap();
        assert_eq!(next.to_string(), "pkg:npm/a@2.0.0");
        let checksum = next.with_qualifier("checksum", Some("SHA256:AB")).unwrap();
        assert_eq!(checksum.to_string(), "pkg:npm/a@2.0.0?checksum=sha256:ab");
        assert_eq!(next.with_qualifier("checksum", Some("bogus")), None);
        assert_eq!(
            next.with_version("").map(|p| p.to_string()).as_deref(),
            Some("pkg:npm/a")
        );
        let id = "dlpngalgnefjeiefhmpklpfiohadpglk";
        let chrome = Purl::parse(&format!("pkg:chrome-extension/{id}")).unwrap();
        assert_eq!(chrome.with_version("1.2-beta"), None);
    }

    #[test]
    fn identity_drops_artifact_selection_qualifiers() {
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
            (
                "pkg:alpm/arch/yay@12.3.0-1?arch=x86_64&repository_url=https://aur.archlinux.org",
                "pkg:alpm/aur/yay@12.3.0-1",
            ),
            ("pkg:npm/lodash@4.17.21", "pkg:npm/lodash@4.17.21"),
            (
                "pkg:golang/google.golang.org/genproto@abcd#googleapis/api",
                "pkg:golang/google.golang.org/genproto@abcd",
            ),
            (
                "pkg:npm/%40scope/name@1.0?repository_url=https://npm.example#src/index.js",
                "pkg:npm/%40scope/name@1.0?repository_url=https:%2F%2Fnpm.example",
            ),
            (
                "pkg:pypi/demo@1?file_name=demo-1.tar.gz&checksum=sha256:ab",
                "pkg:pypi/demo@1",
            ),
            (
                "pkg:rpm/centerim@4.22.10-1.el6?arch=i686&epoch=1&distro=fedora-25",
                "pkg:rpm/fedora/centerim@4.22.10-1.el6?epoch=1",
            ),
        ];
        for (input, want) in cases {
            assert_eq!(identity(input).as_deref(), Some(want), "identity {input}");
        }
        assert_eq!(identity("not-a-purl"), None);
    }

    /// Identity keeps every qualifier that can name another release: a
    /// package from an attacker's conda channel never keys as the
    /// conda-forge one, and two rpm epochs never collide.
    #[test]
    fn identity_keeps_every_release_distinguishing_qualifier() {
        for (left, right) in [
            (
                "pkg:conda/numpy@1.26?channel=evil-ch",
                "pkg:conda/numpy@1.26?channel=conda-forge",
            ),
            (
                "pkg:conda/numpy@1.26?channel=evil-ch",
                "pkg:conda/numpy@1.26",
            ),
            (
                "pkg:rpm/fedora/x@1.0?epoch=1",
                "pkg:rpm/fedora/x@1.0?epoch=2",
            ),
            (
                "pkg:npm/lodash@4.17.21?download_url=https://evil.test/x.tgz",
                "pkg:npm/lodash@4.17.21",
            ),
            (
                "pkg:maven/g/a@1?repository_url=https://evil.test",
                "pkg:maven/g/a@1",
            ),
            ("pkg:npm/a@1?unknown=x", "pkg:npm/a@1"),
        ] {
            assert_ne!(identity(left), identity(right), "{left} vs {right}");
        }
        assert_eq!(
            identity("pkg:conda/numpy@1.26?build=py313_0&channel=conda-forge&subdir=linux-64")
                .as_deref(),
            Some("pkg:conda/numpy@1.26?channel=conda-forge")
        );
        assert_eq!(
            identity("pkg:conan/acme/widget@1?channel=stable&prev=p1&rrev=r1&user=bob").as_deref(),
            Some("pkg:conan/acme/widget@1?channel=stable&rrev=r1&user=bob")
        );
    }

    #[test]
    fn release_replaces_the_version_and_any_range() {
        let purl = Purl::parse("pkg:npm/a?vers=vers:npm%2F%3E1&checksum=sha256:ab#x").unwrap();
        assert_eq!(
            purl.release("2.0.0").unwrap().to_string(),
            "pkg:npm/a@2.0.0"
        );
        assert_eq!(purl.release(""), Err(PurlError::Syntax("version is empty")));
        let p = |raw: &str| Purl::parse(raw).unwrap();
        assert_eq!(
            p("pkg:npm/a@1?kind=x").identity().to_string(),
            "pkg:npm/a@1?kind=x"
        );
        assert_eq!(
            p("pkg:pypi/a@1?kind=sdist")
                .release("2")
                .unwrap()
                .to_string(),
            "pkg:pypi/a@2"
        );
    }

    #[test]
    fn exact_artifact_identity_does_not_collapse_release_siblings() {
        let artifact = |raw: &str, selectors: &BTreeMap<String, String>| {
            Purl::parse(raw)
                .unwrap()
                .artifact(selectors)
                .map(|artifact| artifact.to_string())
        };
        let left = BTreeMap::from([("file_name".into(), "demo-1-py3-none-any.whl".into())]);
        let right = BTreeMap::from([("file_name".into(), "demo-1.tar.gz".into())]);
        assert_ne!(
            artifact("pkg:pypi/demo@1", &left),
            artifact("pkg:pypi/demo@1", &right)
        );
        assert_eq!(
            artifact("pkg:pypi/demo@1?kind=sdist", &right).as_deref(),
            Ok("pkg:pypi/demo@1?file_name=demo-1.tar.gz")
        );
        let bad = BTreeMap::from([("Bad Key".into(), "x".into())]);
        assert!(artifact("pkg:pypi/demo@1", &bad).is_err());
        let empty = BTreeMap::from([("file_name".into(), String::new())]);
        assert!(artifact("pkg:pypi/demo@1", &empty).is_err());
    }

    #[test]
    fn every_output_is_a_wellformed_fixed_point() {
        // Every `Some` output keeps the scheme, a non-empty type and a
        // non-empty name, and normalize and identity are both fixed points.
        let corpus = [
            "pkg:npm/lodash@4.17.21",
            "pkg:npm/%40babel/core@7.24.0",
            "pkg:npm/@babel/core@7.24.0",
            "pkg:npm/@scope/name",
            "pkg:jsr/@std/path",
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
            "pkg:homebrew/wget",
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
            "pkg:git/github/Package-url/purl-Spec@244fd47e",
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
