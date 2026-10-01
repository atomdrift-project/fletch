//! JSR: registry metadata and artifact resolution.

use filefacts::Registry;
use serde::Deserialize;

use crate::ecosystem::{fetch_json, parse_ts};
use crate::fetch::{BlobCache, Fetch, percent_decode};
use crate::registry::RegistryError;

/// JSR: the native API's package record (description, score, repo, latest) plus
/// the versions list (each with a `createdAt` publish time). `path` is the
/// `@scope/name` the locator carries, percent-encoded (`%40` is `@`).
pub(crate) fn jsr(
    path: &str,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let decoded = path.replace("%40", "@");
    let (scope, pkg) = decoded
        .trim_start_matches('@')
        .split_once('/')
        .ok_or(RegistryError::NoRecord)?;
    let doc: Package = fetch_json(
        &format!("https://api.jsr.io/scopes/{scope}/packages/{pkg}"),
        net,
        cache,
    )?;
    let latest = doc.latest_version.as_deref();
    let requested = version.map(percent_decode);
    let want = requested.as_deref().or(latest).unwrap_or_default();

    // Per-version publish time comes from the versions list; a version it
    // lacks gets none rather than the newest's.
    let published_at = fetch_json::<Vec<PackageVersion>>(
        &format!("https://api.jsr.io/scopes/{scope}/packages/{pkg}/versions"),
        net,
        cache,
    )
    .ok()
    .and_then(|vs| {
        vs.into_iter()
            .find(|v| v.version.as_deref() == Some(want))?
            .created_at
    })
    .as_deref()
    .and_then(parse_ts);
    let repository = doc.github_repository.and_then(|g| {
        let owner = g.owner?;
        let repo = g.name?;
        Some(format!("https://github.com/{owner}/{repo}"))
    });

    Ok(Registry {
        ecosystem: "jsr".into(),
        name: format!("@{scope}/{pkg}"),
        version: want.to_string(),
        published_at,
        latest_version: latest.map(str::to_string),
        description: doc.description,
        repository,
        // JSR's 0–100 quality score is its popularity analogue.
        rating: doc.score.map(|f| f as f32),
        ..Default::default()
    })
}

/// The parts of a JSR package record the registry record reads.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Package {
    latest_version: Option<String>,
    description: Option<String>,
    github_repository: Option<GithubRepository>,
    score: Option<f64>,
}

/// The package's linked GitHub repository.
#[derive(Default, Deserialize)]
#[serde(default)]
struct GithubRepository {
    owner: Option<String>,
    name: Option<String>,
}

/// One entry of the package's versions list.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct PackageVersion {
    version: Option<String>,
    created_at: Option<String>,
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
