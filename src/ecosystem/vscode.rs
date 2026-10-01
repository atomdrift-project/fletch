//! The VS Code Marketplace and Open VSX: registry metadata and artifact resolution.

use filefacts::Registry;
use serde_json::Value;

use crate::ecosystem::{json_meta, parse_rfc3339_secs};
use crate::fetch::{BlobCache, Fetch, cached_post, safe_coordinate};
use crate::purl::Purl;

/// Whether `value` is a VS Code Marketplace publisher ID — the rule `vsce`
/// enforces (`^[a-z0-9][a-z0-9-]*$`, any case), which also keeps it a single
/// hostname label of at most 63 bytes. The publisher is interpolated into a
/// hostname, where [`safe_coordinate`]'s path rules are not enough.
fn is_vscode_publisher(value: &str) -> bool {
    value.len() <= 63
        && value
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Open VSX publishes the `.vsix` download URL in its JSON API. The PURL is
/// `<namespace>/<name>[@<version>]`; without a version the API returns the
/// latest release. Returns the `files.download` URL — the exact artifact a
/// client would install.
pub(crate) fn resolve_openvsx(purl: &Purl, net: &dyn Fetch) -> Option<String> {
    let (path, version) = (purl.encoded_path(), purl.encoded_version());
    let (ns, name) = path.split_once('/')?;
    let api = match version {
        Some(v) => format!("https://open-vsx.org/api/{ns}/{name}/{v}"),
        None => format!("https://open-vsx.org/api/{ns}/{name}"),
    };
    let resp = net.get(&api).ok()?;
    let json: serde_json::Value = serde_json::from_slice(&resp.bytes).ok()?;
    json.pointer("/files/download")
        .and_then(serde_json::Value::as_str)
        .map(String::from)
}

/// The VS Code Marketplace `.vsix` lives at a deterministic gallery URL once the
/// version is known. The PURL is `<publisher>/<name>[@<version>]`; an unpinned
/// reference resolves the latest version through the JSON-RPC query first.
pub(crate) fn resolve_vscode(purl: &Purl, net: &dyn Fetch) -> Option<String> {
    let (path, version) = (purl.encoded_path(), purl.encoded_version());
    let (publisher, name) = path.split_once('/')?;
    // The publisher becomes a label of the gallery's hostname.
    if !is_vscode_publisher(publisher) {
        return None;
    }
    let version = match version {
        Some(v) => v,
        None => {
            // Built with the JSON writer, never `format!`: `publisher` and
            // `name` come from the PURL, so a `"` in either would otherwise
            // close the string literal and let the caller restructure the
            // query — returning some *other* extension's record under this
            // coordinate, which is exactly the judgement this feeds.
            let body = serde_json::to_vec(&serde_json::json!({
                "filters": [{"criteria": [{"filterType": 7, "value": format!("{publisher}.{name}")}]}],
                "flags": 914,
            }))
            .ok()?;
            let headers = [
                ("Content-Type", "application/json"),
                ("Accept", "application/json;api-version=3.0-preview.1"),
            ];
            let resp = net
                .post(
                    "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery",
                    &body,
                    &headers,
                )
                .ok()?;
            let json: serde_json::Value = serde_json::from_slice(&resp.bytes).ok()?;
            json.pointer("/results/0/extensions/0/versions/0/version")
                .and_then(serde_json::Value::as_str)
                .filter(|v| safe_coordinate(v))?
                .to_string()
        }
    };
    Some(format!(
        "https://{publisher}.gallery.vsassets.io/_apis/public/gallery/publisher/{publisher}/extension/{name}/{version}/assetbyname/Microsoft.VisualStudio.Services.VSIXPackage"
    ))
}

/// Open VSX: a JSON API, so the marketplace's facts come back structured — no
/// scraping. `path` is `<namespace>/<name>`; one GET yields the requested
/// version (or the latest) with rating, downloads, publisher, and publish time.
pub(crate) fn openvsx(
    path: &str,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Option<Registry> {
    let (ns, name) = path.split_once('/')?;
    let url = match version {
        Some(v) => format!("https://open-vsx.org/api/{ns}/{name}/{v}"),
        None => format!("https://open-vsx.org/api/{ns}/{name}"),
    };
    let doc = json_meta(&url, net, cache)?;

    Some(Registry {
        ecosystem: "openvsx".into(),
        // The canonical extension id everyone types is `namespace.name`.
        name: format!("{ns}.{name}"),
        version: doc
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        published_at: doc
            .get("timestamp")
            .and_then(Value::as_str)
            .and_then(parse_rfc3339_secs),
        author: doc
            .pointer("/publishedBy/loginName")
            .and_then(Value::as_str)
            .map(str::to_string),
        publisher: doc
            .pointer("/publishedBy/loginName")
            .and_then(Value::as_str)
            .map(str::to_string),
        // `allVersions` maps every published version to its URL — its size is the
        // release count, free in this one response (timestamps need the versions
        // endpoint). A `restricted` namespace is owner-controlled; a `public` one
        // is open for anyone to publish under, so it is *not* verified custody.
        release_count: doc
            .get("allVersions")
            .and_then(Value::as_object)
            .map(|v| v.len() as u32),
        publisher_verified: doc
            .get("namespaceAccess")
            .and_then(Value::as_str)
            .map(|a| a.eq_ignore_ascii_case("restricted")),
        title: doc
            .get("displayName")
            .and_then(Value::as_str)
            .map(str::to_string),
        description: doc
            .get("description")
            .and_then(Value::as_str)
            .map(str::to_string),
        homepage: doc
            .get("homepage")
            .and_then(Value::as_str)
            .map(str::to_string),
        repository: doc
            .get("repository")
            .and_then(Value::as_str)
            .map(str::to_string),
        license: doc
            .get("license")
            .and_then(Value::as_str)
            .map(str::to_string),
        downloads_total: doc.get("downloadCount").and_then(Value::as_u64),
        rating: doc
            .get("averageRating")
            .and_then(Value::as_f64)
            .map(|f| f as f32),
        rating_count: doc.get("reviewCount").and_then(Value::as_u64),
        deprecated: doc
            .get("deprecated")
            .and_then(Value::as_bool)
            .and_then(|d| d.then(|| "deprecated".to_string())),
        ..Default::default()
    })
}

/// The Microsoft VS Code Marketplace. Its metadata lives behind a JSON-RPC
/// `POST` to the gallery's `extensionquery` (there is no GET form), keyed by the
/// `<publisher>.<name>` id. One query returns the latest version with its
/// install count, rating, publisher, and timestamps — the same marketplace
/// shape as Open VSX, over a different transport.
pub(crate) fn vscode(path: &str, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    let ext_id = path.replace('/', ".");
    // flags 403 = IncludeVersions(1) | IncludeFiles(2) | IncludeVersionProperties(16)
    // | IncludeAssetUri(128) | IncludeStatistics(256). Dropping IncludeLatestVersionOnly
    // (512, what 914 set) returns the *full* version array in the same request, so the
    // release timeline costs no extra round-trip; `versions[0]` is still the latest.
    // Built with the JSON writer, never `format!`: `ext_id` comes from the
    // PURL, so a `"` in it would otherwise close the string literal and let a
    // crafted coordinate restructure the query — returning some *other*
    // extension's reputation record under this one's name.
    let body = serde_json::to_vec(&serde_json::json!({
        "filters": [{"criteria": [{"filterType": 7, "value": ext_id}]}],
        "flags": 403,
    }))
    .ok()?;
    let headers = [
        ("Content-Type", "application/json"),
        ("Accept", "application/json;api-version=3.0-preview.1"),
    ];
    let doc: Value = serde_json::from_slice(&cached_post(
        "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery",
        &body,
        &headers,
        net,
        cache,
    )?)
    .ok()?;
    let ext = doc.pointer("/results/0/extensions/0")?;

    // `statistics` is an array of `{statisticName, value}` pairs.
    let stat = |name: &str| -> Option<f64> {
        ext.get("statistics")?
            .as_array()?
            .iter()
            .find(|s| s.get("statisticName").and_then(Value::as_str) == Some(name))?
            .get("value")?
            .as_f64()
    };

    let mut p = Registry {
        ecosystem: "vscode".into(),
        name: ext_id,
        version: ext
            .pointer("/versions/0/version")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        // `lastUpdated` is the supply-chain-relevant age: when the extension last
        // changed, not when it first shipped.
        published_at: ext
            .get("lastUpdated")
            .and_then(Value::as_str)
            .and_then(parse_rfc3339_secs),
        // `publishedDate` is the extension's birth — the package-age signal.
        first_published_at: ext
            .get("publishedDate")
            .and_then(Value::as_str)
            .and_then(parse_rfc3339_secs),
        author: ext
            .pointer("/publisher/displayName")
            .and_then(Value::as_str)
            .map(str::to_string),
        // The unique publisher account, and whether the marketplace verified its
        // domain — an unverified publisher is one anyone could have registered.
        publisher: ext
            .pointer("/publisher/publisherName")
            .and_then(Value::as_str)
            .map(str::to_string),
        publisher_verified: ext
            .pointer("/publisher/isDomainVerified")
            .and_then(Value::as_bool),
        title: ext
            .get("displayName")
            .and_then(Value::as_str)
            .map(str::to_string),
        description: ext
            .get("shortDescription")
            .and_then(Value::as_str)
            .map(str::to_string),
        downloads_total: stat("install").map(|v| v as u64),
        rating: stat("averagerating").map(|v| v as f32),
        rating_count: stat("ratingcount").map(|v| v as u64),
        ..Default::default()
    };

    // The full version array (one entry per published version) yields the release
    // timeline — its size is the release count, and `with_age` turns the times
    // into the 24h/48h burst metrics.
    if let Some(versions) = ext.get("versions").and_then(Value::as_array) {
        let mut times: Vec<u64> = versions
            .iter()
            .filter_map(|v| v.get("lastUpdated").and_then(Value::as_str))
            .filter_map(parse_rfc3339_secs)
            .collect();
        times.sort_unstable();
        if !times.is_empty() {
            p.release_count = Some(times.len() as u32);
            if let Some(this) = p.published_at {
                p.previous_published_at = times.iter().copied().filter(|&t| t < this).max();
            }
            p.release_times = times;
        }
    }

    Some(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::test_cache;

    use crate::ecosystem::parse_rfc3339_secs;

    use crate::fetch::{BlobCache, Fixtures};
    use serde_json::Value;

    #[test]
    fn vscode_marketplace_query_normalizes() {
        let resp = serde_json::json!({
            "results": [{"extensions": [{
                "displayName": "Language Support for Java",
                "shortDescription": "Java tooling",
                "publisher": {"displayName": "Red Hat", "publisherName": "redhat", "isDomainVerified": true},
                "publishedDate": "2017-01-01T00:00:00Z",
                "lastUpdated": "2026-06-23T09:30:32.957Z",
                "versions": [
                    {"version": "1.55.0", "lastUpdated": "2026-06-23T09:30:32.957Z"},
                    {"version": "1.54.0", "lastUpdated": "2026-06-20T09:30:32.957Z"},
                    {"version": "1.53.0", "lastUpdated": "2026-05-01T09:30:32.957Z"}
                ],
                "statistics": [
                    {"statisticName": "install", "value": 55_043_274.0},
                    {"statisticName": "averagerating", "value": 3.315},
                    {"statisticName": "ratingcount", "value": 184.0}
                ]
            }]}]
        })
        .to_string();
        // Fixtures key on URL; the POST body is ignored.
        let net = Fixtures::default().with(
            "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery",
            resp.as_bytes(),
        );
        let cache = BlobCache::disabled();
        let r = vscode("redhat/java", &net, &cache).expect("registry");
        assert_eq!(r.ecosystem, "vscode");
        assert_eq!(r.name, "redhat.java");
        assert_eq!(r.version, "1.55.0");
        assert_eq!(r.title.as_deref(), Some("Language Support for Java"));
        assert_eq!(r.author.as_deref(), Some("Red Hat"));
        assert_eq!(r.downloads_total, Some(55_043_274));
        assert_eq!(r.rating, Some(3.315));
        assert_eq!(r.rating_count, Some(184));
        assert!(r.published_at.is_some());
        // Custody + history: verified publisher domain, first-seen date, and the
        // full three-version timeline (with the prior release before this one).
        assert_eq!(r.publisher.as_deref(), Some("redhat"));
        assert_eq!(r.publisher_verified, Some(true));
        assert!(r.first_published_at.is_some());
        assert_eq!(r.release_count, Some(3));
        assert_eq!(r.release_times.len(), 3);
        assert_eq!(
            r.previous_published_at,
            parse_rfc3339_secs("2026-06-20T09:30:32.957Z")
        );
    }

    #[test]
    fn openvsx_api_normalizes() {
        let api = serde_json::json!({
            "namespace": "redhat", "name": "java", "version": "1.55.0",
            "timestamp": "2026-06-23T09:16:36.442135Z",
            "displayName": "Language Support for Java", "description": "Java tooling",
            "averageRating": 5.0, "reviewCount": 16, "downloadCount": 33_978_555u64,
            "publishedBy": {"loginName": "rhdevelopers-ci"},
            "license": "EPL-2.0", "deprecated": false,
            "files": {"download": "https://open-vsx.org/api/redhat/java/1.55.0/file/redhat.java-1.55.0.vsix"}
        })
        .to_string();
        let net = Fixtures::default().with("https://open-vsx.org/api/redhat/java", api.as_bytes());
        let cache = BlobCache::disabled();
        let r = openvsx("redhat/java", None, &net, &cache).expect("registry");
        assert_eq!(r.ecosystem, "openvsx");
        assert_eq!(r.name, "redhat.java");
        assert_eq!(r.version, "1.55.0");
        assert_eq!(r.published_at, Some(1_782_206_196));
        assert_eq!(r.author.as_deref(), Some("rhdevelopers-ci"));
        assert_eq!(r.rating, Some(5.0));
        assert_eq!(r.rating_count, Some(16));
        assert_eq!(r.downloads_total, Some(33_978_555));
        assert_eq!(r.deprecated, None);
    }

    #[test]
    fn vscode_query_body_cannot_be_restructured_by_a_crafted_id() {
        use crate::fetch::{FetchError, Fetched};

        /// Captures the POST body so the emitted request can be inspected.
        #[derive(Default, Debug)]
        struct CaptureBody(std::sync::Mutex<Vec<u8>>);
        impl Fetch for CaptureBody {
            fn get(&self, _url: &str) -> Result<Fetched, FetchError> {
                Err(FetchError::Refused("get not used".into()))
            }
            fn post(
                &self,
                _url: &str,
                body: &[u8],
                _headers: &[(&str, &str)],
            ) -> Result<Fetched, FetchError> {
                if let Ok(mut seen) = self.0.lock() {
                    *seen = body.to_vec();
                }
                Err(FetchError::Refused("captured".into()))
            }
        }

        // A coordinate crafted to close the JSON string literal and graft on
        // sibling keys — the classic injection the old `format!` body allowed.
        let crafted = r#"evil","flags":9999,"junk":"x/pkg"#;
        let net = CaptureBody::default();
        let _ = vscode(crafted, &net, &test_cache("vscode-inject"));

        let body = net.0.lock().expect("lock").clone();
        let doc: Value = serde_json::from_slice(&body).expect("body must still be valid JSON");
        // The crafted text stays one opaque string value...
        assert_eq!(
            doc.pointer("/filters/0/criteria/0/value")
                .and_then(Value::as_str),
            Some(crafted.replace('/', ".").as_str()),
            "the whole coordinate must remain a single JSON string: {body:?}"
        );
        // ...and cannot reach the query's own structure.
        assert_eq!(doc.get("flags"), Some(&Value::from(403)));
        assert_eq!(doc.get("junk"), None);
    }
}
