//! JSR: registry metadata and artifact resolution.

use filefacts::Registry;
use serde::Deserialize;

use crate::ecosystem::{fetch_json, parse_ts};
use crate::fetch::{BlobCache, Fetch, percent_decode};
use crate::purl::encode_component;
use crate::registry::RegistryError;

/// Whether `s` is a JSR scope or package name: non-empty lowercase ASCII
/// letters, digits and hyphens.
fn jsr_segment(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// JSR: the native API's package record (description, score, repo, latest) plus
/// the release's own version document (its `createdAt` publish time). `path` is the
/// `@scope/name` the locator carries, percent-encoded (`%40` is `@`).
pub(crate) fn jsr(
    path: &str,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let decoded = path.replace("%40", "@");
    // Exactly `@scope/name`: a lenient `@@@std/path` must not borrow
    // `@std/path`'s record. JSR scopes and names are `[a-z0-9-]`.
    let (scope, pkg) = decoded
        .strip_prefix('@')
        .unwrap_or(&decoded)
        .split_once('/')
        .filter(|(scope, pkg)| [scope, pkg].iter().all(|s| jsr_segment(s)))
        .ok_or(RegistryError::NoRecord)?;
    let doc: Package = fetch_json(
        &format!("https://api.jsr.io/scopes/{scope}/packages/{pkg}"),
        net,
        cache,
    )?;
    let latest = doc.latest_version.as_deref();
    let requested = version.map(percent_decode);
    let want = requested.as_deref().or(latest).unwrap_or_default();

    // The release's own document dates it; a version JSR does not have is a
    // 404 there, and gets no date rather than the newest's.
    let published_at = fetch_json::<PackageVersion>(
        &format!(
            "https://api.jsr.io/scopes/{scope}/packages/{pkg}/versions/{}",
            encode_component(want)
        ),
        net,
        cache,
    )
    .ok()
    .and_then(|v| v.created_at)
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

/// A release's version document.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct PackageVersion {
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
        let release = serde_json::json!({
            "scope": "std", "package": "path", "version": "1.1.5",
            "createdAt": "2021-04-23T10:00:00.000Z", "yanked": false
        })
        .to_string();
        let net = Fixtures::default()
            .with(
                "https://api.jsr.io/scopes/std/packages/path",
                pkg.as_bytes(),
            )
            .with(
                "https://api.jsr.io/scopes/std/packages/path/versions/1.1.5",
                release.as_bytes(),
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

        // The version is a path segment: encoded once, whatever the PURL
        // percent-encoded.
        let net = net.with(
            "https://api.jsr.io/scopes/std/packages/path/versions/1.0.0%2Bbuild",
            release.as_bytes(),
        );
        let r = jsr(
            "%40std/path",
            Some("1.0.0%2Bbuild"),
            &net,
            &test_cache("jsr"),
        )
        .expect("registry");
        assert_eq!(r.version, "1.0.0+build");
        assert_eq!(r.published_at, Some(1_619_172_000));
    }
}
