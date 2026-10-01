//! Go modules (proxy.golang.org): registry metadata and artifact resolution.

use filefacts::Registry;
use serde::Deserialize;

use crate::ecosystem::{decode, fetch_json, parse_rfc3339_secs};
use crate::fetch::{
    ArtifactCandidate, BlobCache, CachedMeta, Fetch, FetchError, cached_metadata_status,
    deterministic_artifacts, now, percent_decode, safe_coordinate, sha256_hex, store_metadata,
};
use crate::purl::Purl;
use crate::registry::RegistryError;

/// Go module zips: the proxy's URL for the module path as written, unless
/// the proxy's refusal names the spelling it wants ([`goproxy_canonical_path`]),
/// in which case the candidate is built for that spelling.
pub(crate) fn golang_artifacts(
    purl: &Purl,
    path: &str,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Vec<ArtifactCandidate> {
    let resolved = goproxy_canonical_path(path, version, net, cache);
    if resolved.path == path {
        return deterministic_artifacts(purl, "zip");
    }
    // The canonical string opens with the path as written; anything after it
    // (version, qualifiers, subpath) carries over to the proxy's spelling.
    let canonical = purl.canonical();
    let Some(proxy_spelled) = canonical
        .strip_prefix(&format!("pkg:golang/{path}"))
        .and_then(|tail| Purl::parse(&format!("pkg:golang/{}{tail}", resolved.path)).ok())
    else {
        return deterministic_artifacts(purl, "zip");
    };
    deterministic_artifacts(&proxy_spelled, "zip")
}

/// What [`goproxy_canonical_path`] learned about a module path.
pub(crate) struct GoproxyPath {
    /// The spelling the proxy serves: the path as given, or the case variant
    /// its refusal named.
    pub(crate) path: String,
    /// When `path` is the path as given and the probe was a refusal with no
    /// alternative in it, that status — so the caller need not ask the same
    /// question again (each proxy miss costs it a second or more upstream).
    pub(crate) refused: Option<u16>,
}

/// The spelling of a Go module path that proxy.golang.org will serve.
///
/// Module paths are case-sensitive and the proxy encodes uppercase as `!x`,
/// but a PURL can arrive lowercased — a producer that normalizes names does
/// it to every ecosystem alike — and then every request for
/// `gitlab.com/nebulouslabs/sia` is a 404 that costs the proxy an upstream
/// round trip (1–5 s, measured) and costs the caller the artifact: a
/// metadata-only verdict on a package whose bytes were one letter-case away.
/// The proxy's refusal body says which spelling it wanted, in one of two
/// forms — a vanity/host import redirect (`meta tag gitlab.com/NebulousLabs/Sia
/// did not match import path gitlab.com/nebulouslabs/sia`) or the module's own
/// `go.mod` (`module declares its path as: X but was required as: Y`). Only
/// a spelling that differs from the given one by letter case is accepted
/// (a rename is a different module, not this one respelled), and the answer
/// is cached for the metadata TTL so the miss is paid once per module.
///
/// A successful probe is filed under the `.info` / `@latest` document's
/// own cache key, so the registry read that follows is a hit, not a second
/// request.
pub(crate) fn goproxy_canonical_path(
    path: &str,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> GoproxyPath {
    let key = sha256_hex(format!("meta:goproxy-canonical:{path}").as_bytes());
    if let Some((bytes, _)) = cache.fresh(&key, cache.meta_ttl)
        && let Ok(known) = String::from_utf8(bytes)
        && !known.is_empty()
    {
        return GoproxyPath {
            path: known,
            refused: None,
        };
    }
    let escaped = goproxy_escape(path);
    let url = match version {
        Some(v) => format!(
            "https://proxy.golang.org/{escaped}/@v/{}.info",
            goproxy_escape(v)
        ),
        None => format!("https://proxy.golang.org/{escaped}/@latest"),
    };
    let Ok(fetched) = net.get_any_status(&url, &[]) else {
        return GoproxyPath {
            path: path.to_string(),
            refused: None,
        };
    };
    if (200..300).contains(&fetched.status) {
        store_metadata(&url, &fetched, cache);
        remember_goproxy_path(&key, path, &url, cache);
        return GoproxyPath {
            path: path.to_string(),
            refused: None,
        };
    }
    match goproxy_declared_path(path, &String::from_utf8_lossy(&fetched.bytes)) {
        Some(canonical) => {
            remember_goproxy_path(&key, &canonical, &url, cache);
            GoproxyPath {
                path: canonical,
                refused: None,
            }
        }
        None => GoproxyPath {
            path: path.to_string(),
            refused: Some(fetched.status),
        },
    }
}

fn remember_goproxy_path(key: &str, canonical: &str, url: &str, cache: &BlobCache) {
    let meta = CachedMeta {
        fetched_at: now(),
        status: 200,
        final_url: url.to_string(),
        redirects: Vec::new(),
        headers: Vec::new(),
        size: None,
    };
    cache.put(key, canonical.as_bytes(), &meta);
}

/// The module path a proxy.golang.org refusal names, when it is `given`
/// respelled: the same path letter-case-insensitively, or a prefix of it
/// (an import redirect names the repository module; the remainder of the
/// given path is a package inside it and carries over).
fn goproxy_declared_path(given: &str, body: &str) -> Option<String> {
    const MARKERS: [&str; 2] = ["meta tag ", "module declares its path as: "];
    let named = MARKERS.iter().find_map(|marker| {
        let start = body.find(marker)? + marker.len();
        let rest = &body[start..];
        let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
        let candidate = rest[..end].trim_end_matches(',');
        (!candidate.is_empty()).then(|| candidate.to_string())
    })?;
    if !safe_coordinate(&named) || named == given {
        return None;
    }
    if named.eq_ignore_ascii_case(given) {
        return Some(named);
    }
    let (head, tail) = given.split_at_checked(named.len())?;
    (head.eq_ignore_ascii_case(&named) && tail.starts_with('/')).then(|| format!("{named}{tail}"))
}

/// GOPROXY case-encoding: every unescaped uppercase ASCII letter becomes `!`
/// followed by its lowercase form, so module paths can't collide on
/// case-insensitive file systems (`github.com/BurntSushi/toml` →
/// `github.com/!burnt!sushi/toml`).
///
/// A PURL is already percent-encoded. Its `%HH` triplets are URL escapes, not
/// native module text, and must pass through atomically: turning the `B` in
/// `%2B` into `!b` changes `+` into the invalid URL text `%2!b`. This matters
/// for every Go `+incompatible` version, and applies equally to escapes in a
/// module path or any future version spelling.
pub(crate) fn goproxy_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            let mut rest = chars.clone();
            if let (Some(hi), Some(lo)) = (rest.next(), rest.next())
                && hi.is_ascii_hexdigit()
                && lo.is_ascii_hexdigit()
            {
                out.push(c);
                out.push(hi);
                out.push(lo);
                chars = rest;
                continue;
            }
        }
        if c.is_ascii_uppercase() {
            out.push('!');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Go modules: the module proxy serves a per-version `.info` (and an `@latest`)
/// document with the version and its commit time — the only registry facts Go
/// exposes. The module path is GOPROXY case-encoded. `Origin.URL` recovers the
/// backing VCS repository.
///
/// A release the proxy will not serve falls back to the module's own `@latest`
/// record; see the comment on that path for why.
pub(crate) fn golang(
    path: &str,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    // The spelling the proxy serves — a lowercased PURL is a 404 at the proxy
    // for every request until the case is put back (see
    // `goproxy_canonical_path`).
    let resolved = goproxy_canonical_path(path, version, net, cache);
    let path = resolved.path.as_str();
    let escaped = goproxy_escape(path);
    let latest_url = format!("https://proxy.golang.org/{escaped}/@latest");

    // A versionless lookup asks the proxy what the current release is, so the
    // answer names itself in both fields.
    let Some(version) = version else {
        let mut record = golang_record(path, fetch_json(&latest_url, net, cache)?);
        record.latest_version = Some(record.version.clone()).filter(|v| !v.is_empty());
        record.version_removed = Some(false);
        record.security_hold = Some(false);
        return Ok(record);
    };

    let info_url = format!(
        "https://proxy.golang.org/{escaped}/@v/{}.info",
        goproxy_escape(version)
    );
    // Kept as a status rather than a document, because a refusal is the answer
    // here and `.ok()` would throw away which refusal it was.
    // The probe above already asked for this `.info`; when it was refused
    // outright, that is the answer, and asking again would cost the proxy
    // another upstream round trip for the same 404.
    let info = match resolved.refused {
        Some(status) => Err(FetchError::Status(status)),
        None => cached_metadata_status(&info_url, &[], net, cache),
    };
    if let Ok(bytes) = &info
        && let Ok(doc) = decode::<VersionInfo>(&info_url, bytes)
    {
        let mut record = golang_record(path, doc);
        record.version_removed = Some(false);
        record.security_hold = Some(false);
        return Ok(record);
    }

    // The proxy would not serve this release's `.info`, so it will not serve
    // its `.zip` either: both come from the same index entry, and a retracted,
    // withdrawn, withheld, or never-published version is missing from both.
    //
    // Every other ecosystem already survives that. npm, PyPI, crates.io and
    // RubyGems each answer the *package* document from an endpoint that is not
    // the artifact, so a release whose bytes are gone still yields registry
    // facts a caller can scan instead. Go's `.info` is the artifact's own
    // neighbour, so without this a missing release yielded no record at all —
    // and a caller with nothing to fall back on has to report a server fault
    // where it should be reporting a missing artifact.
    //
    // `version_removed` is set from the same evidence npm's is: the registry
    // knows the module and does not offer this release. A transient failure
    // reaching `.info` also lands here, and costs a metadata-only answer about
    // a release that was in fact fetchable — the safe direction to be wrong in.
    let mut record = golang_record(path, fetch_json(&latest_url, net, cache)?);
    record.latest_version = Some(std::mem::take(&mut record.version)).filter(|v| !v.is_empty());
    // The release asked about, not the one the proxy offered instead. Its
    // publish time is not knowable: it lives in the record being withheld.
    record.version = percent_decode(version);
    record.published_at = None;
    record.version_removed = Some(true);
    // The Go analogue of npm's `security holding package` tombstone.
    //
    // The proxy separates the two things a missing release can mean, and only
    // the status carries the distinction: 404 for a version it does not have,
    // 403 for one it will not serve — "the module proxy considers this module
    // to be malicious", in its own words. Without reading it the fallback
    // above would report a module Go has taken down as quietly unpublished,
    // and scan treats `security_hold` as a hostile signal precisely so it does
    // not have to.
    record.security_hold = Some(matches!(info, Err(FetchError::Status(GOPROXY_WITHHELD))));
    Ok(record)
}

/// The status proxy.golang.org answers for a module it has taken down for
/// malware, as against the 404 it gives for one it simply does not hold.
const GOPROXY_WITHHELD: u16 = 403;

/// The registry facts one proxy document carries. `version_removed` and
/// `latest_version` are left to the caller, the only side that knows whether
/// this document describes the release that was asked about.
fn golang_record(path: &str, doc: VersionInfo) -> Registry {
    Registry {
        ecosystem: "golang".into(),
        name: path.to_string(),
        version: doc.version.unwrap_or_default(),
        published_at: doc.time.as_deref().and_then(parse_rfc3339_secs),
        repository: doc.origin.and_then(|o| o.url),
        ..Default::default()
    }
}

/// A module proxy `.info` (or `@latest`) document: one version of a module.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct VersionInfo {
    version: Option<String>,
    time: Option<String>,
    origin: Option<Origin>,
}

/// Where the proxy fetched the version from.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Origin {
    #[serde(rename = "URL")]
    url: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fetch::resolve;
    use crate::fetch::resolve_artifacts;
    use filefacts::RefLocator;

    use crate::fetch::{BlobCache, Fixtures};

    #[test]
    fn resolve_golang_module_to_goproxy_zip_with_case_encoding() {
        assert_eq!(
            resolve(&RefLocator::Purl(
                "pkg:golang/github.com/BurntSushi/toml@v1.4.0".into()
            )),
            Some("https://proxy.golang.org/github.com/!burnt!sushi/toml/@v/v1.4.0.zip".to_string())
        );
        // A pseudo-version resolves verbatim (no uppercase to encode).
        assert_eq!(
            resolve(&RefLocator::Purl(
                "pkg:golang/codeberg.org/a/b@v0.0.0-20260507212222-cbe932efc123".into()
            )),
            Some(
                "https://proxy.golang.org/codeberg.org/a/b/@v/v0.0.0-20260507212222-cbe932efc123.zip"
                    .to_string()
            )
        );
        // Canonical PURLs percent-encode `+`. The escape is already valid URL
        // syntax and GOPROXY's case transform must not rewrite its hex digits.
        assert_eq!(
            resolve(&RefLocator::Purl(
                "pkg:golang/github.com/gofrs/uuid@v4.4.0%2Bincompatible".into()
            )),
            Some(
                "https://proxy.golang.org/github.com/gofrs/uuid/@v/v4.4.0%2Bincompatible.zip"
                    .to_string()
            )
        );
        // The rule is about percent triplets, not this one suffix: escapes in
        // either component survive while ordinary uppercase text is encoded.
        assert_eq!(
            goproxy_escape("Example.com/A%2FB@v1%2bmeta"),
            "!example.com/!a%2F!b@v1%2bmeta"
        );
        // Without a version there is no fetchable artifact.
        assert_eq!(
            resolve(&RefLocator::Purl("pkg:golang/golang.org/x/net".into())),
            None
        );
    }

    /// The proxy's refusal names the spelling it wanted; only a letter-case
    /// respelling of the path asked for is taken as this module's.
    #[test]
    fn goproxy_declared_path_accepts_case_variants_only() {
        let meta = "not found: gitlab.com/nebulouslabs/sia@v1.5.5: unrecognized import path \
            \"gitlab.com/nebulouslabs/sia\": parse https://gitlab.com/nebulouslabs/sia?go-get=1: \
            no go-import meta tags (meta tag gitlab.com/NebulousLabs/Sia did not match import \
            path gitlab.com/nebulouslabs/sia)";
        assert_eq!(
            goproxy_declared_path("gitlab.com/nebulouslabs/sia", meta).as_deref(),
            Some("gitlab.com/NebulousLabs/Sia")
        );
        // An import redirect names the repository module; a package inside
        // it keeps its tail.
        assert_eq!(
            goproxy_declared_path("gitlab.com/nebulouslabs/sia/modules/host", meta).as_deref(),
            Some("gitlab.com/NebulousLabs/Sia/modules/host")
        );
        let gomod = "go.mod has post-v0 module path: module declares its path as: \
            github.com/BurntSushi/toml\n\tbut was required as: github.com/burntsushi/toml";
        assert_eq!(
            goproxy_declared_path("github.com/burntsushi/toml", gomod).as_deref(),
            Some("github.com/BurntSushi/toml")
        );
        // A rename is another module, not this one respelled.
        let renamed = "module declares its path as: github.com/IBM/sarama\n\tbut was \
            required as: github.com/shopify/sarama";
        assert_eq!(
            goproxy_declared_path("github.com/shopify/sarama", renamed),
            None
        );
        // No hint at all.
        assert_eq!(
            goproxy_declared_path(
                "github.com/hatch1fy/errors",
                "not found: could not read Username"
            ),
            None
        );
        // The spelling asked for is already the one named.
        assert_eq!(
            goproxy_declared_path("gitlab.com/NebulousLabs/Sia", meta),
            None
        );
    }

    /// A lowercased module path resolves through the refusal to the
    /// spelling the proxy serves, and the zip candidate is built for it.
    #[test]
    fn golang_artifacts_recover_case_from_the_proxy_refusal() {
        let body = "not found: gitlab.com/nebulouslabs/sia@v1.5.5: no go-import meta tags \
            (meta tag gitlab.com/NebulousLabs/Sia did not match import path \
            gitlab.com/nebulouslabs/sia)";
        let net = Fixtures::default().refusing_with_body(
            "https://proxy.golang.org/gitlab.com/nebulouslabs/sia/@v/v1.5.5.info",
            404,
            body.as_bytes(),
        );
        let cache = BlobCache::disabled();
        let resolved =
            goproxy_canonical_path("gitlab.com/nebulouslabs/sia", Some("v1.5.5"), &net, &cache);
        assert_eq!(resolved.path, "gitlab.com/NebulousLabs/Sia");
        assert_eq!(resolved.refused, None);
        let matrix = resolve_artifacts(
            &RefLocator::Purl("pkg:golang/gitlab.com/nebulouslabs/sia@v1.5.5".into()),
            &net,
            &cache,
        )
        .expect("matrix");
        let urls: Vec<&str> = matrix.candidates.iter().map(|c| c.url.as_str()).collect();
        assert_eq!(
            urls,
            ["https://proxy.golang.org/gitlab.com/!nebulous!labs/!sia/@v/v1.5.5.zip"]
        );
    }

    /// A refusal that names nothing is reported once, so the registry read
    /// that follows does not ask the proxy the same question again.
    #[test]
    fn goproxy_canonical_path_reports_a_bare_refusal() {
        let net = Fixtures::default().refusing_with_body(
            "https://proxy.golang.org/github.com/hatch1fy/errors/@v/v0.2.0.info",
            404,
            b"not found: could not read Username",
        );
        let resolved = goproxy_canonical_path(
            "github.com/hatch1fy/errors",
            Some("v0.2.0"),
            &net,
            &BlobCache::disabled(),
        );
        assert_eq!(resolved.path, "github.com/hatch1fy/errors");
        assert_eq!(resolved.refused, Some(404));
        let matrix = resolve_artifacts(
            &RefLocator::Purl("pkg:golang/github.com/hatch1fy/errors@v0.2.0".into()),
            &net,
            &BlobCache::disabled(),
        )
        .expect("matrix");
        assert_eq!(
            matrix.candidates[0].url,
            "https://proxy.golang.org/github.com/hatch1fy/errors/@v/v0.2.0.zip"
        );
    }

    #[test]
    fn golang_proxy_info_normalizes() {
        let info = serde_json::json!({
            "Version": "v1.12.0", "Time": "2021-04-23T10:00:00Z",
            "Origin": {"VCS": "git", "URL": "https://github.com/gin-gonic/gin"}
        })
        .to_string();
        let net = Fixtures::default().with(
            "https://proxy.golang.org/github.com/gin-gonic/gin/@latest",
            info.as_bytes(),
        );
        let cache = BlobCache::disabled();
        let r = golang("github.com/gin-gonic/gin", None, &net, &cache).expect("registry");
        assert_eq!(r.ecosystem, "golang");
        assert_eq!(r.version, "v1.12.0");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(
            r.repository.as_deref(),
            Some("https://github.com/gin-gonic/gin")
        );
    }

    #[test]
    fn golang_proxy_info_preserves_percent_encoded_version() {
        let info = serde_json::json!({
            "Version": "v4.4.0+incompatible", "Time": "2021-04-23T10:00:00Z"
        })
        .to_string();
        let net = Fixtures::default().with(
            "https://proxy.golang.org/github.com/gofrs/uuid/@v/v4.4.0%2Bincompatible.info",
            info.as_bytes(),
        );
        let cache = BlobCache::disabled();
        let r = golang(
            "github.com/gofrs/uuid",
            Some("v4.4.0%2Bincompatible"),
            &net,
            &cache,
        )
        .expect("registry");
        assert_eq!(r.version, "v4.4.0+incompatible");
        assert_eq!(r.version_removed, Some(false));
    }

    /// A release the proxy will not serve still yields the module's record,
    /// marked removed — the same shape npm answers with for an unpublished
    /// version, and what lets a caller scan metadata instead of reporting a
    /// fault it cannot act on.
    /// A lowercased PURL reaches the proxy as a spelling it refuses; the
    /// refusal names the real one and the record is that module's.
    #[test]
    fn golang_lowercased_path_resolves_to_the_proxy_spelling() {
        let info = serde_json::json!({
            "Version": "v1.5.5", "Time": "2021-04-23T10:00:00Z",
            "Origin": {"VCS": "git", "URL": "https://gitlab.com/NebulousLabs/Sia"}
        })
        .to_string();
        let net = Fixtures::default()
            .refusing_with_body(
                "https://proxy.golang.org/gitlab.com/nebulouslabs/sia/@v/v1.5.5.info",
                404,
                b"no go-import meta tags (meta tag gitlab.com/NebulousLabs/Sia did not match \
                  import path gitlab.com/nebulouslabs/sia)",
            )
            .with(
                "https://proxy.golang.org/gitlab.com/!nebulous!labs/!sia/@v/v1.5.5.info",
                info.as_bytes(),
            );
        let r = golang(
            "gitlab.com/nebulouslabs/sia",
            Some("v1.5.5"),
            &net,
            &BlobCache::disabled(),
        )
        .expect("registry");
        assert_eq!(r.name, "gitlab.com/NebulousLabs/Sia");
        assert_eq!(r.version, "v1.5.5");
        assert_eq!(r.version_removed, Some(false));
        assert_eq!(
            r.repository.as_deref(),
            Some("https://gitlab.com/NebulousLabs/Sia")
        );
    }

    #[test]
    fn golang_unservable_version_falls_back_to_the_module_record() {
        let latest = serde_json::json!({
            "Version": "v1.5.9", "Time": "2021-04-23T10:00:00Z",
            "Origin": {"VCS": "git", "URL": "https://gitlab.com/NebulousLabs/Sia"}
        })
        .to_string();
        // Only `@latest` answers: the retracted release's `.info` is absent,
        // exactly as the proxy serves it.
        let net = Fixtures::default().with(
            "https://proxy.golang.org/gitlab.com/!nebulous!labs/!sia/@latest",
            latest.as_bytes(),
        );
        let cache = BlobCache::disabled();
        let r = golang(
            "gitlab.com/NebulousLabs/Sia",
            Some("v1.5.5-rc2"),
            &net,
            &cache,
        )
        .expect("registry");
        assert_eq!(r.version, "v1.5.5-rc2", "the release asked about");
        assert_eq!(r.latest_version.as_deref(), Some("v1.5.9"));
        assert_eq!(r.version_removed, Some(true));
        assert_eq!(r.published_at, None, "not knowable without the .info");
        assert_eq!(
            r.repository.as_deref(),
            Some("https://gitlab.com/NebulousLabs/Sia")
        );
        assert_eq!(r.security_hold, Some(false), "absent, not withheld");
    }

    /// The proxy's malware refusal is a verdict, not an absence. Without this
    /// the fallback above would report a module Go has taken down as merely
    /// unpublished, and scan's registry signals — which read `security_hold`
    /// as hostile — would see nothing at all.
    #[test]
    fn golang_proxy_security_refusal_is_a_hold() {
        let latest = serde_json::json!({
            "Version": "v0.74.0", "Time": "2026-08-14T10:24:58Z",
            "Origin": {"VCS": "git", "URL": "https://github.com/aquasecurity/trivy"}
        })
        .to_string();
        // proxy.golang.org answers 403 here. The body explains it to a human
        // ("SECURITY ERROR / The module proxy considers this module to be
        // malicious"), but an HTTP client discards the body of a refusal, so
        // the status is the whole of what reaches us — which is what this
        // fixture reproduces.
        let net = Fixtures::default()
            .refusing(
                "https://proxy.golang.org/github.com/aquasecurity/trivy/@v/v0.69.4.info",
                403,
            )
            .with(
                "https://proxy.golang.org/github.com/aquasecurity/trivy/@latest",
                latest.as_bytes(),
            );
        let cache = BlobCache::disabled();
        let r = golang(
            "github.com/aquasecurity/trivy",
            Some("v0.69.4"),
            &net,
            &cache,
        )
        .expect("registry");
        assert_eq!(r.version, "v0.69.4");
        assert_eq!(r.security_hold, Some(true));
        assert_eq!(r.version_removed, Some(true), "no bytes either way");
    }

    /// And the ordinary refusal is not one. 404 is what the proxy says about
    /// the great majority of releases poppy asks for and cannot get; reading
    /// that as a malware verdict would drown the real ones.
    #[test]
    fn golang_missing_version_is_not_a_hold() {
        let latest = serde_json::json!({"Version": "v1.5.9"}).to_string();
        let net = Fixtures::default()
            .refusing("https://proxy.golang.org/example.com/m/@v/v9.9.9.info", 404)
            .with(
                "https://proxy.golang.org/example.com/m/@latest",
                latest.as_bytes(),
            );
        let cache = BlobCache::disabled();
        let r = golang("example.com/m", Some("v9.9.9"), &net, &cache).expect("registry");
        assert_eq!(r.version_removed, Some(true));
        assert_eq!(r.security_hold, Some(false));
    }

    /// A module the proxy does not know at all still has no record: there is
    /// no package here to report facts about, and inventing one would turn "not
    /// a module" into "a module with nothing in it".
    #[test]
    fn golang_unknown_module_stays_unknown() {
        let net = Fixtures::default();
        let cache = BlobCache::disabled();
        assert!(golang("example.invalid/nope", Some("v1.0.0"), &net, &cache).is_err());
    }
}
