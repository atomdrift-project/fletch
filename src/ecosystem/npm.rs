//! Npm: registry metadata and artifact resolution.

use filefacts::Registry;
use serde_json::Value;
use std::collections::BTreeMap;

use crate::ecosystem::{email_domain, json_meta, parse_rfc3339_secs};
use crate::fetch::{
    ArtifactCandidate, BlobCache, Fetch, artifact_candidate, cached_metadata, file_name_from_url,
    file_name_matches, meta_ttl_pinned, meta_ttl_unpinned, percent_decode, repository_base,
    resolve_purl,
};
use crate::purl::Purl;

pub(crate) fn npm_artifacts(
    path: &str,
    requested_version: Option<&str>,
    purl: &Purl,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Vec<ArtifactCandidate> {
    let name = npm_registry_name(path);
    let ttl = if requested_version.is_some() {
        meta_ttl_pinned()
    } else {
        meta_ttl_unpinned()
    };
    let Some(repository) = repository_base(purl, "https://registry.npmjs.org") else {
        return Vec::new();
    };
    let api = format!("{repository}/{name}");
    let doc = cached_metadata(&api, net, &cache.with_meta_ttl(ttl))
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
    let requested = requested_version.map(percent_decode);
    let resolved = requested.as_ref().map_or_else(
        || {
            doc.as_ref()?
                .pointer("/dist-tags/latest")?
                .as_str()
                .map(str::to_string)
        },
        |value| {
            doc.as_ref()
                .and_then(|document| document.get("versions"))
                .and_then(|versions| versions.get(value))
                .map(|_| value.clone())
                .or_else(|| {
                    doc.as_ref()?
                        .get("dist-tags")?
                        .get(value)?
                        .as_str()
                        .map(str::to_string)
                })
        },
    );
    let Some(version) = resolved else {
        return Vec::new();
    };
    let version_doc = doc
        .as_ref()
        .and_then(|value| value.get("versions"))
        .and_then(|versions| versions.get(&version));
    let base_name = name.rsplit('/').next().unwrap_or(name.as_str());
    let url = version_doc
        .and_then(|value| value.pointer("/dist/tarball"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .or_else(|| Some(format!("{repository}/{name}/-/{base_name}-{version}.tgz")));
    let Some(url) = url else {
        return Vec::new();
    };
    let mut candidate = artifact_candidate(url, "tgz");
    candidate.attributes.insert("version".into(), version);
    for key in ["os", "cpu", "libc"] {
        if let Some(value) = version_doc
            .and_then(|doc| doc.get(key))
            .and_then(json_string_list)
        {
            candidate.attributes.insert(key.to_string(), value);
        }
    }
    if let Some(node) = version_doc
        .and_then(|doc| doc.pointer("/engines/node"))
        .and_then(serde_json::Value::as_str)
    {
        candidate.attributes.insert("node".into(), node.to_string());
    }
    if let Some(integrity) = version_doc
        .and_then(|doc| doc.pointer("/dist/integrity"))
        .and_then(serde_json::Value::as_str)
    {
        candidate
            .attributes
            .insert("integrity".into(), integrity.to_string());
        add_sri_checksums(integrity, &mut candidate.checksums);
    }
    if let Some(sha1) = version_doc
        .and_then(|doc| doc.pointer("/dist/shasum"))
        .and_then(serde_json::Value::as_str)
    {
        candidate.checksums.insert("sha1".into(), sha1.to_string());
    }
    candidate.preferred = file_name_matches(purl, &candidate.file_name);
    vec![candidate]
}

fn add_sri_checksums(integrity: &str, checksums: &mut BTreeMap<String, String>) {
    use base64::Engine as _;
    for token in integrity.split_ascii_whitespace() {
        let Some((algorithm, encoded)) = token.split_once('-') else {
            continue;
        };
        let Some(bytes) = base64::engine::general_purpose::STANDARD
            .decode(encoded.split('?').next().unwrap_or(encoded))
            .ok()
        else {
            continue;
        };
        checksums
            .entry(algorithm.to_ascii_lowercase())
            .or_insert_with(|| hex::encode(bytes));
    }
}

pub(crate) fn npm_registry_name(path: &str) -> String {
    if path
        .get(..3)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("%40"))
    {
        format!("@{}", &path[3..])
    } else {
        path.to_string()
    }
}

fn json_string_list(value: &serde_json::Value) -> Option<String> {
    if let Some(value) = value.as_str() {
        return Some(value.to_string());
    }
    let values = value
        .as_array()?
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect::<Vec<_>>();
    (!values.is_empty()).then(|| values.join(","))
}

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

/// A versionless npm PURL with no declared version requirement resolves through
/// dist-tags. Manifest ranges are resolved separately by `resolve_requirement`
/// so a current latest release outside the declared range is never substituted.
/// The refined locator is the declared PURL at the tagged version, its
/// qualifiers and subpath kept.
pub(crate) fn resolve_npm_dist_tag(
    purl: &Purl,
    tag: &str,
    net: &dyn Fetch,
) -> Option<(String, String)> {
    let name = npm_registry_name(&purl.encoded_path());
    let repository = repository_base(purl, "https://registry.npmjs.org")?;
    let packument = net.get(&format!("{repository}/{name}")).ok()?;
    let doc: serde_json::Value = serde_json::from_slice(&packument.bytes).ok()?;
    let version = doc.get("dist-tags")?.get(tag)?.as_str()?;
    let exact = purl.with_version(version)?;
    let url = doc
        .get("versions")
        .and_then(|versions| versions.get(version))
        .and_then(|release| release.pointer("/dist/tarball"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .or_else(|| resolve_purl(&exact))?;
    if !file_name_matches(purl, &file_name_from_url(&url)) {
        return None;
    }
    Some((exact.canonical(), url))
}

/// npm: the packument carries publish times, custody, and links in one
/// document; download counts need a second (cached) endpoint.
pub(crate) fn npm(
    path: &str,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Option<Registry> {
    let name = path.replace("%40", "@");
    let doc = json_meta(&format!("https://registry.npmjs.org/{name}"), net, cache)?;

    let latest = doc.pointer("/dist-tags/latest").and_then(Value::as_str);
    let version = version.or(latest).unwrap_or_default();
    let v = doc.get("versions").and_then(|vs| vs.get(version));

    let published_at = doc
        .get("time")
        .and_then(|t| t.get(version))
        .and_then(Value::as_str)
        .and_then(parse_rfc3339_secs);

    let mut p = Registry {
        ecosystem: "npm".into(),
        name: name.clone(),
        version: version.to_string(),
        published_at,
        latest_version: latest.map(str::to_string),
        // `author` is a bare string or an object with a `name`.
        author: v
            .and_then(|v| v.get("author"))
            .or_else(|| doc.get("author"))
            .and_then(|a| a.as_str().or_else(|| a.get("name")?.as_str()))
            .or_else(|| doc.pointer("/maintainers/0/name").and_then(Value::as_str))
            .map(str::to_string),
        title: None,
        description: field_str(v, &doc, "description"),
        homepage: field_str(v, &doc, "homepage"),
        repository: v
            .and_then(|v| v.pointer("/repository/url"))
            .or_else(|| doc.pointer("/repository/url"))
            .and_then(Value::as_str)
            .map(str::to_string),
        license: field_str(v, &doc, "license"),
        deprecated: v.and_then(|v| v.get("deprecated")).and_then(deprecation),
        // npm always lists at least one maintainer for a live package, so a
        // missing/null/empty array is the anomaly itself — record it as zero
        // rather than "unknown" so a custody trait can fire on it.
        maintainers: Some(
            doc.get("maintainers")
                .and_then(Value::as_array)
                .map_or(0, |m| m.len() as u32),
        ),
        // npm replaces a taken-down malicious package with a stub whose
        // description is exactly `security holding package`. That tombstone is
        // the registry's own verdict — surface it.
        security_hold: Some(
            doc.get("description").and_then(Value::as_str) == Some("security holding package"),
        ),
        // An unpublished version keeps its `time` entry (and npm records a
        // `time.unpublished` block) but loses its `versions` object. A live
        // package always lists its versions, so "timestamped but gone from
        // versions" is a removal — for a fresh package, almost always a malware
        // takedown.
        version_removed: Some(
            v.is_none() && doc.get("time").and_then(|t| t.get(version)).is_some(),
        ),
        ..Default::default()
    };

    // Release timeline from the packument `time` map: every entry but the
    // `created`/`modified` bookkeeping keys is `version → publish time`. The
    // counts derive from this; `with_age` later turns it into the 24h/48h burst
    // metrics relative to the scan clock.
    if let Some(time) = doc.get("time").and_then(Value::as_object) {
        let mut times: Vec<u64> = time
            .iter()
            .filter(|(k, _)| k.as_str() != "created" && k.as_str() != "modified")
            .filter_map(|(_, v)| v.as_str().and_then(parse_rfc3339_secs))
            .collect();
        times.sort_unstable();
        p.release_count = Some(times.len() as u32);
        p.first_published_at = time
            .get("created")
            .and_then(Value::as_str)
            .and_then(parse_rfc3339_secs)
            .or_else(|| times.first().copied());
        if let Some(this) = p.published_at {
            p.previous_published_at = times.iter().copied().filter(|&t| t < this).max();
        }
        p.release_times = times;
    }

    // Custody: the account that pushed *this* version (`_npmUser`) and whether
    // it is among the listed maintainers — a publisher outside that set is the
    // account-takeover tell.
    let publisher = v
        .and_then(|v| v.pointer("/_npmUser/name"))
        .and_then(Value::as_str);
    p.publisher = publisher.map(str::to_string);
    p.publisher_email_domain = v
        .and_then(|v| v.pointer("/_npmUser/email"))
        .and_then(Value::as_str)
        .and_then(email_domain);
    if let Some(name) = publisher {
        p.publisher_in_maintainers = doc.get("maintainers").and_then(Value::as_array).map(|ms| {
            ms.iter()
                .any(|m| m.get("name").and_then(Value::as_str) == Some(name))
        });
    }

    // Artifact shape and the registry's own install-hook flag.
    p.unpacked_size = v
        .and_then(|v| v.pointer("/dist/unpackedSize"))
        .and_then(Value::as_u64);
    p.file_count = v
        .and_then(|v| v.pointer("/dist/fileCount"))
        .and_then(Value::as_u64)
        .map(|n| n as u32);
    p.has_install_script = v.map(|v| {
        v.get("hasInstallScript")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || v.get("scripts")
                .and_then(Value::as_object)
                .is_some_and(|s| {
                    s.contains_key("install")
                        || s.contains_key("preinstall")
                        || s.contains_key("postinstall")
                })
    });

    // Best-effort popularity: last-month downloads from the stats endpoint.
    if let Some(d) = json_meta(
        &format!("https://api.npmjs.org/downloads/point/last-month/{name}"),
        net,
        cache,
    )
    .and_then(|j| j.get("downloads").and_then(Value::as_u64))
    {
        p.downloads_recent = Some(d);
    }
    Some(p)
}

/// A field preferred from the version object, falling back to the package root
/// (npm packuments carry both; the version's copy is authoritative).
fn field_str(ver: Option<&Value>, root: &Value, key: &str) -> Option<String> {
    ver.and_then(|v| v.get(key))
        .or_else(|| root.get(key))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// npm `deprecated` is `false`/absent, or a truthy string reason.
fn deprecation(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Bool(true) => Some("deprecated".to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::ecosystem::parse_rfc3339_secs;

    use crate::fetch::{BlobCache, Fixtures};

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
        let net =
            Fixtures::default().with("https://registry.npmjs.org/left-pad", packument.as_bytes());
        let cache = BlobCache::disabled();
        let p = npm("left-pad", Some("1.3.0"), &net, &cache).expect("provenance");
        assert_eq!(p.ecosystem, "npm");
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
        let p = npm(
            "evilpkg",
            Some("0.0.1-security"),
            &net,
            &BlobCache::disabled(),
        )
        .expect("provenance");
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
        let p = npm("evilpkg", Some("1.0.0"), &net, &BlobCache::disabled()).expect("provenance");
        assert_eq!(
            p.version_removed,
            Some(true),
            "in `time`, gone from `versions` => removed"
        );
        // The surviving timestamp still gives us the publish date / age signals.
        assert_eq!(
            p.published_at,
            parse_rfc3339_secs("2026-06-22T00:00:00.000Z")
        );
    }
}
