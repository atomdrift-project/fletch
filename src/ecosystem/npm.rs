//! npm: registry metadata and artifact resolution, both read from the one
//! packument document.

use filefacts::{Ecosystem, Registry};
use serde::Deserialize;
use serde::de::IgnoredAny;
use std::collections::{BTreeMap, HashMap};

use crate::ecosystem::{
    Coordinates, email_domain, fetch_json, for_version, last_seg, lenient, non_empty, null_default,
    optional, set_timeline, unix_secs,
};
use crate::fetch::{
    ArtifactCandidate, ArtifactKind, BlobCache, Fetch, artifact_candidate, file_name_matches,
    percent_decode, repository_base,
};
use crate::registry::RegistryError;

/// The public registry, the base for a PURL with no `repository_url`.
const REGISTRY: &str = "https://registry.npmjs.org";

/// The tarball `purl` names: the requested version, or the dist-tag a
/// non-version spelling names, or `latest` when unversioned. Carries the
/// release's platform constraints (`os`, `cpu`, `libc`, `engines.node`) and
/// its registry digests. Empty when the packument is unreadable or names no
/// such release.
pub(crate) fn npm_artifacts(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Vec<ArtifactCandidate> {
    let (path, requested_version, purl) = (c.path(), c.encoded_version(), c.purl());
    let name = npm_registry_name(path);
    let Some(repository) = repository_base(purl, REGISTRY) else {
        tracing::debug!(
            purl = %purl.to_string().escape_debug(),
            "npm artifacts unresolved: repository_url is not a web URL"
        );
        return Vec::new();
    };
    let api = format!("{repository}/{name}");
    let doc: Packument = match fetch_json(&api, net, &for_version(cache, requested_version)) {
        Ok(doc) => doc,
        Err(error) => {
            tracing::debug!(url = %api, %error, "npm artifacts unresolved: packument unreadable");
            return Vec::new();
        }
    };
    let resolved = match purl.version() {
        Some(version) if doc.versions.contains_key(version) => Some(version),
        Some(tag) => doc.tag(tag),
        None => doc.tag("latest"),
    };
    let Some(version) = resolved else {
        tracing::debug!(
            url = %api,
            requested = ?purl.version(),
            "npm artifacts unresolved: no such version or dist-tag"
        );
        return Vec::new();
    };
    let release = doc.versions.get(version);
    let dist = release.and_then(|r| r.dist.as_ref());
    let url = dist
        .and_then(|d| d.tarball.clone())
        .unwrap_or_else(|| format!("{repository}/{name}/-/{}-{version}.tgz", last_seg(&name)));
    let mut candidate = artifact_candidate(url, ArtifactKind::Tgz);
    candidate.version = Some(version.to_string());
    if let Some(release) = release {
        for (key, platforms) in [
            ("os", &release.os),
            ("cpu", &release.cpu),
            ("libc", &release.libc),
        ] {
            // A list is recorded comma-joined; an empty one is no constraint.
            let value = match platforms {
                Some(Platforms::One(value)) => value.clone(),
                Some(Platforms::Many(values)) if !values.is_empty() => values.join(","),
                _ => continue,
            };
            candidate.attributes.insert(key.to_string(), value);
        }
        if let Some(node) = release.engines.as_ref().and_then(|e| e.node.clone()) {
            candidate.attributes.insert("node".into(), node);
        }
    }
    if let Some(integrity) = dist.and_then(|d| d.integrity.as_deref()) {
        candidate
            .attributes
            .insert("integrity".into(), integrity.to_string());
        add_sri_checksums(integrity, &mut candidate.checksums);
    }
    if let Some(sha1) = dist.and_then(|d| d.shasum.clone()) {
        candidate.checksums.insert("sha1".into(), sha1);
    }
    candidate.preferred = file_name_matches(purl, &candidate.file_name);
    vec![candidate]
}

/// Add each `algorithm-base64` token of a Subresource Integrity string to
/// `checksums` as lowercase hex, keeping any digest already there. A token
/// that does not decode is skipped.
fn add_sri_checksums(integrity: &str, checksums: &mut BTreeMap<String, String>) {
    use base64::Engine as _;
    for token in integrity.split_ascii_whitespace() {
        let Some((algorithm, encoded)) = token.split_once('-') else {
            continue;
        };
        let encoded = encoded.split('?').next().unwrap_or(encoded);
        let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
            tracing::debug!(
                algorithm = %algorithm.escape_debug(),
                "npm integrity token skipped: not base64"
            );
            continue;
        };
        checksums
            .entry(algorithm.to_ascii_lowercase())
            .or_insert_with(|| hex::encode(bytes));
    }
}

/// The packument path for a PURL's encoded coordinate path: a scope's
/// encoded `%40` spelled `@` (`%40scope/name` → `@scope/name`), the way the
/// registry addresses scoped packages.
pub(crate) fn npm_registry_name(path: &str) -> String {
    match path.strip_prefix("%40") {
        Some(scoped) => format!("@{scoped}"),
        None => path.to_string(),
    }
}

/// Whether an encoded PURL version names one release rather than a range or
/// a dist-tag: it starts with a digit (after an optional `v`) and holds no
/// range operator, wildcard, or whitespace.
pub(crate) fn npm_version_is_concrete(version: &str) -> bool {
    let version = percent_decode(version);
    let version = version.strip_prefix('v').unwrap_or(&version);
    version
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_digit())
        && !version.bytes().any(|byte| {
            byte.is_ascii_whitespace()
                || matches!(
                    byte,
                    b'*' | b'x' | b'X' | b'<' | b'>' | b'=' | b'^' | b'~' | b'|'
                )
        })
}

/// Look up the package `c` names on npm. The packument carries publish times,
/// custody, and links in one document; download counts come from a second,
/// best-effort endpoint.
pub(crate) fn lookup(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    // A namespace is a scope, `@scope`, or nothing: any other path would
    // address another endpoint of the registry, not a package.
    let one_scope = match c.namespace() {
        [] => true,
        [scope] => scope.starts_with('@'),
        _ => false,
    };
    if !one_scope {
        tracing::debug!(
            namespace = %c.namespace().join("/").escape_debug(),
            "npm lookup refused: namespace is not one @scope"
        );
        return Err(RegistryError::UnsafeCoordinate);
    }
    let name = npm_registry_name(c.path());
    let doc: Packument = fetch_json(&format!("{REGISTRY}/{name}"), net, cache)?;

    let latest = doc.tag("latest");
    let version = c.target(latest);
    let release = doc.versions.get(version);
    let published = |key: &str| doc.time.get(key).and_then(TimeEntry::secs);

    let mut p = Registry::new(Ecosystem::Npm, c.full_name());
    p.version = version.to_string();
    p.published_at = published(version);
    // `created` dates the package itself, before any version's entry.
    p.first_published_at = published("created");
    p.latest_version = latest.map(str::to_string);
    // The version's own manifest field, else the package root's: npm
    // packuments carry both, and the version's copy is authoritative.
    p.author = release
        .and_then(|r| r.author.as_ref())
        .or(doc.author.as_ref())
        .and_then(Person::name)
        .or_else(|| doc.maintainers.as_deref()?.first()?.name())
        .map(str::to_string);
    p.description = release
        .and_then(|r| r.description.clone())
        .or_else(|| doc.description.clone());
    p.homepage = release
        .and_then(|r| r.homepage.clone())
        .or_else(|| doc.homepage.clone());
    p.repository = release
        .and_then(|r| r.repository.as_ref())
        .or(doc.repository.as_ref())
        .and_then(|r| r.url.clone());
    p.license = release
        .and_then(|r| r.license.clone())
        .or_else(|| doc.license.clone());
    p.deprecated = release
        .and_then(|r| r.deprecated.as_ref())
        .and_then(Deprecated::reason);
    // A live package always lists at least one maintainer, so a missing,
    // null, or empty list is itself the anomaly: zero, not unknown.
    p.maintainers = Some(
        doc.maintainers
            .as_ref()
            .map_or(0, |m| u32::try_from(m.len()).unwrap_or(u32::MAX)),
    );
    // npm replaces a taken-down malicious package with a stub whose
    // description is exactly this: the registry's own verdict.
    p.security_hold = Some(doc.description.as_deref() == Some("security holding package"));
    // An unpublished version keeps its `time` entry but leaves `versions`;
    // a live version is in both.
    p.version_removed = Some(release.is_none() && doc.time.contains_key(version));
    // Every `time` entry but the `created`/`modified` bookkeeping is a
    // version's publish time.
    set_timeline(
        &mut p,
        doc.time
            .iter()
            .filter(|(key, _)| !matches!(key.as_str(), "created" | "modified"))
            .filter_map(|(_, time)| time.secs()),
    );
    if let Some(release) = release {
        record_release(&mut p, release, doc.maintainers.as_deref());
    }

    let downloads = format!("https://api.npmjs.org/downloads/point/last-month/{name}");
    p.downloads_recent = optional(fetch_json::<Downloads>(&downloads, net, cache), &downloads)
        .and_then(|d| d.downloads);
    Ok(p)
}

/// Record what this version's own manifest says: the account that pushed it
/// (`_npmUser`) and whether it is a listed maintainer — a publisher outside
/// that set is the account-takeover tell — then the artifact's shape and its
/// install hooks.
fn record_release(p: &mut Registry, release: &Release, maintainers: Option<&[Person]>) {
    let publisher = release.npm_user.as_ref().and_then(|u| u.name.as_deref());
    p.publisher = publisher.map(str::to_string);
    p.publisher_email_domain = release
        .npm_user
        .as_ref()
        .and_then(|u| u.email.as_deref())
        .and_then(email_domain);
    if let Some(publisher) = publisher {
        p.publisher_in_maintainers =
            maintainers.map(|ms| ms.iter().any(|m| m.name() == Some(publisher)));
    }
    let dist = release.dist.as_ref();
    p.unpacked_size = dist.and_then(|d| d.unpacked_size);
    p.file_count = dist
        .and_then(|d| d.file_count)
        .and_then(|n| u32::try_from(n).ok());
    p.has_install_script = Some(
        release.has_install_script.unwrap_or(false)
            || release.scripts.as_ref().is_some_and(|scripts| {
                ["install", "preinstall", "postinstall"]
                    .iter()
                    .any(|hook| scripts.contains_key(*hook))
            }),
    );
}

/// The parts of an npm packument the registry record and the artifact
/// resolver read.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Packument {
    #[serde(rename = "dist-tags", deserialize_with = "lenient")]
    dist_tags: Option<HashMap<String, String>>,
    #[serde(deserialize_with = "null_default")]
    versions: HashMap<String, Release>,
    #[serde(deserialize_with = "null_default")]
    time: HashMap<String, TimeEntry>,
    #[serde(deserialize_with = "lenient")]
    author: Option<Person>,
    #[serde(deserialize_with = "lenient")]
    maintainers: Option<Vec<Person>>,
    #[serde(deserialize_with = "non_empty")]
    description: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    homepage: Option<String>,
    #[serde(deserialize_with = "lenient")]
    repository: Option<Repository>,
    #[serde(deserialize_with = "non_empty")]
    license: Option<String>,
}

impl Packument {
    /// The version the dist-tag `tag` points at.
    fn tag(&self, tag: &str) -> Option<&str> {
        self.dist_tags.as_ref()?.get(tag).map(String::as_str)
    }
}

/// One version's manifest, as the packument lists it.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Release {
    #[serde(deserialize_with = "lenient")]
    author: Option<Person>,
    #[serde(deserialize_with = "non_empty")]
    description: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    homepage: Option<String>,
    #[serde(deserialize_with = "lenient")]
    repository: Option<Repository>,
    #[serde(deserialize_with = "non_empty")]
    license: Option<String>,
    #[serde(deserialize_with = "lenient")]
    deprecated: Option<Deprecated>,
    #[serde(rename = "_npmUser", deserialize_with = "lenient")]
    npm_user: Option<NpmUser>,
    #[serde(deserialize_with = "lenient")]
    dist: Option<Dist>,
    #[serde(rename = "hasInstallScript", deserialize_with = "lenient")]
    has_install_script: Option<bool>,
    #[serde(deserialize_with = "lenient")]
    scripts: Option<HashMap<String, IgnoredAny>>,
    #[serde(deserialize_with = "lenient")]
    os: Option<Platforms>,
    #[serde(deserialize_with = "lenient")]
    cpu: Option<Platforms>,
    #[serde(deserialize_with = "lenient")]
    libc: Option<Platforms>,
    #[serde(deserialize_with = "lenient")]
    engines: Option<Engines>,
}

/// A `time` entry: a version's publish time, or npm's `unpublished` record.
#[derive(Deserialize)]
#[serde(untagged)]
enum TimeEntry {
    At(String),
    Other(IgnoredAny),
}

impl TimeEntry {
    /// The publish time, Unix seconds.
    fn secs(&self) -> Option<u64> {
        match self {
            Self::At(time) => unix_secs(time),
            Self::Other(_) => None,
        }
    }
}

/// An `author` or maintainer: a bare string, or an object with a `name`.
#[derive(Deserialize)]
#[serde(untagged)]
enum Person {
    Name(String),
    Object { name: Option<String> },
}

impl Person {
    fn name(&self) -> Option<&str> {
        match self {
            Self::Name(name) => Some(name),
            Self::Object { name } => name.as_deref(),
        }
    }
}

/// `repository` read in its object form (`{type, url}`).
#[derive(Deserialize)]
struct Repository {
    url: Option<String>,
}

/// `deprecated`: absent or `false`, a reason, or a bare `true`. An empty
/// reason is how npm records an un-deprecation.
#[derive(Deserialize)]
#[serde(untagged)]
enum Deprecated {
    Reason(String),
    Flag(bool),
}

impl Deprecated {
    fn reason(&self) -> Option<String> {
        match self {
            Self::Reason(reason) if reason.trim().is_empty() => None,
            Self::Reason(reason) => Some(reason.clone()),
            Self::Flag(true) => Some("deprecated".to_string()),
            Self::Flag(false) => None,
        }
    }
}

/// `_npmUser`: the account that published the version.
#[derive(Deserialize)]
struct NpmUser {
    #[serde(default, deserialize_with = "lenient")]
    name: Option<String>,
    #[serde(default, deserialize_with = "lenient")]
    email: Option<String>,
}

/// A version's `dist` block: its tarball, digests, and unpacked shape.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Dist {
    #[serde(deserialize_with = "non_empty")]
    tarball: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    integrity: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    shasum: Option<String>,
    #[serde(rename = "unpackedSize", deserialize_with = "lenient")]
    unpacked_size: Option<u64>,
    #[serde(rename = "fileCount", deserialize_with = "lenient")]
    file_count: Option<u64>,
}

/// An `os`, `cpu`, or `libc` constraint: one value or a list of them.
#[derive(Deserialize)]
#[serde(untagged)]
enum Platforms {
    One(String),
    Many(Vec<String>),
}

/// A version's `engines` block.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Engines {
    #[serde(deserialize_with = "non_empty")]
    node: Option<String>,
}

/// The downloads endpoint's answer.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Downloads {
    #[serde(deserialize_with = "lenient")]
    downloads: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::coordinates;

    use crate::fetch::{Fixtures, resolve_artifacts};
    use filefacts::RefLocator;

    fn look(purl: &str, net: &Fixtures) -> Result<Registry, RegistryError> {
        crate::registry::lookup(&RefLocator::Purl(purl.into()), net, &BlobCache::disabled())
    }

    #[test]
    fn npm_packument_normalizes() {
        let packument = serde_json::json!({
            "dist-tags": {"latest": "1.3.0"},
            "author": {"name": "Una"},
            "maintainers": [{"name": "Una"}, {"name": "Bob"}],
            "time": {
                "created": "2019-01-01T00:00:00.000Z",
                "modified": "2021-04-23T10:00:00.000Z",
                "1.0.0": "2019-01-01T00:00:00.000Z",
                "1.2.0": "2021-04-22T10:00:00.000Z",
                "1.3.0": "2021-04-23T10:00:00.000Z"
            },
            "versions": {
                "1.3.0": {
                    "description": "pad it",
                    "homepage": "https://example.test",
                    "license": "MIT",
                    "repository": {"url": "git+https://github.test/x.git"},
                    "_npmUser": {"name": "mallory", "email": "mallory@gmail.com"},
                    "dist": {"unpackedSize": 4096, "fileCount": 7},
                    "scripts": {"postinstall": "node steal.js"}
                }
            }
        })
        .to_string();
        let net = Fixtures::default()
            .with("https://registry.npmjs.org/left-pad", packument.as_bytes())
            .with(
                "https://api.npmjs.org/downloads/point/last-month/left-pad",
                br#"{"downloads": 1234}"#,
            );
        let p = look("pkg:npm/left-pad@1.3.0", &net).expect("provenance");
        assert_eq!(p.ecosystem, Ecosystem::Npm);
        assert_eq!(p.name, "left-pad");
        assert_eq!(p.published_at, Some(1_619_172_000));
        assert_eq!(p.latest_version.as_deref(), Some("1.3.0"));
        assert_eq!(p.author.as_deref(), Some("Una"));
        assert_eq!(p.license.as_deref(), Some("MIT"));
        assert_eq!(p.maintainers, Some(2));
        // Release history: three versions, born at `time.created`, prior release
        // is 1.2.0 (the latest strictly before this one).
        assert_eq!(p.release_count, Some(3));
        assert_eq!(p.first_published_at, Some(1_546_300_800)); // 2019-01-01
        assert_eq!(p.previous_published_at, Some(1_619_085_600)); // 2021-04-22
        assert_eq!(p.release_times.len(), 3);
        // Custody: the publisher of this version is NOT a listed maintainer.
        assert_eq!(p.publisher.as_deref(), Some("mallory"));
        assert_eq!(p.publisher_email_domain.as_deref(), Some("gmail.com"));
        assert_eq!(p.publisher_in_maintainers, Some(false));
        // Artifact shape + the postinstall hook.
        assert_eq!(p.unpacked_size, Some(4096));
        assert_eq!(p.file_count, Some(7));
        assert_eq!(p.has_install_script, Some(true));
        // A normal package is not a security-hold tombstone.
        assert_eq!(p.security_hold, Some(false));
        assert_eq!(p.downloads_recent, Some(1234));
    }

    #[test]
    fn a_scoped_package_is_named_and_addressed_as_npm_does() {
        let doc = br#"{"dist-tags":{"latest":"2.0.0"},"versions":{"2.0.0":{}}}"#;
        let net = Fixtures::default().with("https://registry.npmjs.org/@scope/util", doc);
        let p = look("pkg:npm/%40scope/util", &net).expect("record");
        assert_eq!(p.name, "@scope/util");
        assert_eq!(p.version, "2.0.0");
    }

    #[test]
    fn a_namespace_that_is_not_one_scope_is_refused() {
        for purl in ["pkg:npm/lodash/4.17.21", "pkg:npm/%40a/%40b/c"] {
            assert_eq!(
                look(purl, &Fixtures::default()),
                Err(RegistryError::UnsafeCoordinate),
                "{purl}"
            );
        }
    }

    #[test]
    fn an_empty_deprecation_is_no_deprecation() {
        let doc = br#"{"dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"deprecated":""},"0.9.0":{"deprecated":"use 1.x"}}}"#;
        let net = Fixtures::default().with("https://registry.npmjs.org/p", doc);
        assert_eq!(
            look("pkg:npm/p@1.0.0", &net).expect("record").deprecated,
            None
        );
        assert_eq!(
            look("pkg:npm/p@0.9.0", &net)
                .expect("record")
                .deprecated
                .as_deref(),
            Some("use 1.x")
        );
    }

    #[test]
    fn npm_maintainerless_and_security_hold_tombstone() {
        // A taken-down package: npm's stub description, and a null maintainers
        // field (a live npm package always lists at least one).
        let stub = serde_json::json!({
            "dist-tags": {"latest": "0.0.1-security"},
            "description": "security holding package",
            "maintainers": serde_json::Value::Null,
            "time": {"0.0.1-security": "2026-06-20T00:00:00.000Z"},
            "versions": {"0.0.1-security": {"description": "security holding package"}}
        })
        .to_string();
        let net = Fixtures::default().with("https://registry.npmjs.org/evilpkg", stub.as_bytes());
        let p = look("pkg:npm/evilpkg@0.0.1-security", &net).expect("provenance");
        assert_eq!(
            p.security_hold,
            Some(true),
            "npm tombstone description detected"
        );
        assert_eq!(
            p.maintainers,
            Some(0),
            "null maintainers recorded as zero, not unknown"
        );
        assert_eq!(p.version_removed, Some(false), "stub version still listed");
    }

    #[test]
    fn npm_unpublished_version_is_flagged_removed() {
        // An unpublished version: its `time` entry survives (plus a `time
        // .unpublished` block) but it is gone from `versions` and `dist-tags`.
        let doc = serde_json::json!({
            "dist-tags": serde_json::Value::Null,
            "versions": {},
            "time": {
                "created": "2026-06-22T00:00:00.000Z",
                "modified": "2026-06-24T12:04:37.146Z",
                "1.0.0": "2026-06-22T00:00:00.000Z",
                "unpublished": {"time": "2026-06-24T12:04:37.146Z", "versions": ["1.0.0"]}
            }
        })
        .to_string();
        let net = Fixtures::default().with("https://registry.npmjs.org/evilpkg", doc.as_bytes());
        let p = look("pkg:npm/evilpkg@1.0.0", &net).expect("provenance");
        assert_eq!(
            p.version_removed,
            Some(true),
            "in `time`, gone from `versions` => removed"
        );
        // The surviving timestamp still gives us the publish date / age signals.
        assert_eq!(p.published_at, unix_secs("2026-06-22T00:00:00.000Z"));
    }

    #[test]
    fn the_artifact_resolver_reads_the_same_packument() {
        let doc = br#"{"dist-tags":{"latest":"1.0.0","next":"2.0.0"},"versions":{
            "1.0.0":{"dist":{"tarball":"https://registry.npmjs.org/p/-/p-1.0.0.tgz","shasum":"abc","integrity":"sha512-AAAA"}},
            "2.0.0":{}}}"#;
        let net = Fixtures::default().with("https://registry.npmjs.org/p", doc);
        let cache = BlobCache::disabled();
        let artifacts = |raw: &str| npm_artifacts(&coordinates(raw), &net, &cache);
        let latest = artifacts("pkg:npm/p");
        assert_eq!(latest[0].url, "https://registry.npmjs.org/p/-/p-1.0.0.tgz");
        assert_eq!(
            latest[0].checksums.get("sha1").map(String::as_str),
            Some("abc")
        );
        assert_eq!(
            latest[0].checksums.get("sha512").map(String::as_str),
            Some("000000")
        );
        // A tag spelled as the version, with no tarball listed: the derived URL.
        let next = artifacts("pkg:npm/p@next");
        assert_eq!(next[0].url, "https://registry.npmjs.org/p/-/p-2.0.0.tgz");
        assert!(artifacts("pkg:npm/p@9.9.9").is_empty());
    }

    #[test]
    fn registry_names_spell_the_scope_as_npm_does() {
        assert_eq!(npm_registry_name("%40scope/util"), "@scope/util");
        assert_eq!(npm_registry_name("left-pad"), "left-pad");
    }

    #[test]
    fn the_matrix_records_npm_platform_constraints() {
        let body = br#"{"versions":{"1.0.0":{"os":["linux","!darwin"],"cpu":["x64"],"libc":"glibc","dist":{"tarball":"https://x/native.tgz"}}}}"#;
        let net = Fixtures::default().with("https://registry.npmjs.org/native", body);
        let matrix = resolve_artifacts(
            &RefLocator::Purl("pkg:npm/native@1.0.0".into()),
            &net,
            &BlobCache::disabled(),
        )
        .expect("npm matrix");
        let candidate = &matrix.candidates[0];
        let attribute = |key: &str| candidate.attributes.get(key).map(String::as_str);
        assert_eq!(attribute("os"), Some("linux,!darwin"));
        assert_eq!(attribute("cpu"), Some("x64"));
        assert_eq!(attribute("libc"), Some("glibc"));
    }
}
