//! JSR: registry metadata and artifact resolution.

use filefacts::Registry;
use serde_json::Value;

use crate::ecosystem::{json_meta, parse_ts};
use crate::fetch::{BlobCache, Fetch, percent_decode};

/// JSR: the native API's package record (description, score, repo, latest) plus
/// the versions list (each with a `createdAt` publish time). `path` is the
/// `@scope/name` the locator carries, percent-encoded (`%40` is `@`).
pub(crate) fn jsr(
    path: &str,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Option<Registry> {
    let decoded = path.replace("%40", "@");
    let (scope, pkg) = decoded.trim_start_matches('@').split_once('/')?;
    let doc = json_meta(
        &format!("https://api.jsr.io/scopes/{scope}/packages/{pkg}"),
        net,
        cache,
    )?;
    let latest = doc.get("latestVersion").and_then(Value::as_str);
    let requested = version.map(percent_decode);
    let want = requested.as_deref().or(latest).unwrap_or_default();

    // Per-version publish time comes from the versions list; a version it
    // lacks gets none rather than the newest's.
    let published_at = json_meta(
        &format!("https://api.jsr.io/scopes/{scope}/packages/{pkg}/versions"),
        net,
        cache,
    )
    .and_then(|vs| {
        vs.as_array()?
            .iter()
            .find(|v| v.get("version").and_then(Value::as_str) == Some(want))?
            .get("createdAt")
            .and_then(Value::as_str)
            .and_then(parse_ts)
    });
    let repository = doc.get("githubRepository").and_then(|g| {
        let owner = g.get("owner").and_then(Value::as_str)?;
        let repo = g.get("name").and_then(Value::as_str)?;
        Some(format!("https://github.com/{owner}/{repo}"))
    });

    Some(Registry {
        ecosystem: "jsr".into(),
        name: format!("@{scope}/{pkg}"),
        version: want.to_string(),
        published_at,
        latest_version: latest.map(str::to_string),
        description: doc
            .get("description")
            .and_then(Value::as_str)
            .map(str::to_string),
        repository,
        // JSR's 0–100 quality score is its popularity analogue.
        rating: doc.get("score").and_then(Value::as_f64).map(|f| f as f32),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::test_cache;

    use crate::fetch::Fixtures;

    #[test]
    fn jsr_api_normalizes() {
        let pkg = serde_json::json!({
            "scope": "std", "name": "path", "description": "File-path utilities",
            "latestVersion": "1.1.5", "score": 100,
            "githubRepository": {"owner": "denoland", "name": "std"}
        })
        .to_string();
        let versions = serde_json::json!([
            {"version": "1.1.5", "createdAt": "2021-04-23T10:00:00.000Z", "yanked": false}
        ])
        .to_string();
        let net = Fixtures::default()
            .with(
                "https://api.jsr.io/scopes/std/packages/path",
                pkg.as_bytes(),
            )
            .with(
                "https://api.jsr.io/scopes/std/packages/path/versions",
                versions.as_bytes(),
            );
        let r = jsr("%40std/path", None, &net, &test_cache("jsr")).expect("registry");
        assert_eq!(r.ecosystem, "jsr");
        assert_eq!(r.name, "@std/path");
        assert_eq!(r.version, "1.1.5");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(
            r.repository.as_deref(),
            Some("https://github.com/denoland/std")
        );
        assert_eq!(r.rating, Some(100.0));
    }
}
