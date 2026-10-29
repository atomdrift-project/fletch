//! JSR: registry metadata.

use filefacts::{Ecosystem, Registry};
use serde::Deserialize;

use crate::ecosystem::{Coordinates, fetch_json, non_empty, optional, unix_secs};
use crate::fetch::{BlobCache, Fetch};
use crate::purl::encode_component;
use crate::registry::RegistryError;

/// JSR's native API: the package record (description, repository, latest)
/// plus the release's own version document (its `createdAt` publish time and
/// `yanked` flag). The PURL names the package `@scope/name`.
pub(crate) fn lookup(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    // Exactly `@scope/name`, both `[a-z0-9-]` as JSR spells them, so they
    // fill the URL as they are and a lenient `@@@std/path` never borrows
    // `@std/path`'s record.
    let jsr_segment = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    let names = match c.namespace() {
        [scope] => Some((scope.strip_prefix('@').unwrap_or(scope), c.name())),
        _ => None,
    };
    let Some((scope, pkg)) = names.filter(|(scope, pkg)| jsr_segment(scope) && jsr_segment(pkg))
    else {
        tracing::debug!(
            purl = %c.purl().to_string().escape_debug(),
            "JSR lookup refused: not an @scope/name package"
        );
        return Err(RegistryError::NoRecord);
    };
    let doc: Package = fetch_json(
        &format!("https://api.jsr.io/scopes/{scope}/packages/{pkg}"),
        net,
        cache,
    )?;
    let latest = doc.latest_version.as_deref();
    let version = c.target(latest);

    // The release's own document dates it; a version JSR does not have is a
    // 404 there, and gets no date rather than the newest's.
    let url = format!(
        "https://api.jsr.io/scopes/{scope}/packages/{pkg}/versions/{}",
        encode_component(version)
    );
    let release = optional(fetch_json::<PackageVersion>(&url, net, cache), &url);
    let repository = doc.github_repository.and_then(|g| {
        let owner = g.owner?;
        let repo = g.name?;
        Some(format!("https://github.com/{owner}/{repo}"))
    });

    let mut registry = Registry::new(Ecosystem::Jsr, format!("@{scope}/{pkg}"));
    registry.version = version.to_string();
    registry.published_at = release
        .as_ref()
        .and_then(|r| r.created_at.as_deref())
        .and_then(unix_secs);
    registry.latest_version = latest.map(str::to_string);
    registry.description = doc.description;
    registry.repository = repository;
    registry.version_removed = release.and_then(|r| r.yanked);
    Ok(registry)
}

/// The parts of a JSR package record the registry record reads.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Package {
    latest_version: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    description: Option<String>,
    github_repository: Option<GithubRepository>,
}

/// The package's linked GitHub repository.
#[derive(Default, Deserialize)]
#[serde(default)]
struct GithubRepository {
    #[serde(deserialize_with = "non_empty")]
    owner: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    name: Option<String>,
}

/// A release's version document.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct PackageVersion {
    created_at: Option<String>,
    yanked: Option<bool>,
}

#[cfg(test)]
mod tests {
    use crate::fetch::{BlobCache, Fixtures};
    use crate::registry::lookup;
    use filefacts::{Ecosystem, RefLocator, Registry};

    fn look(net: &Fixtures, purl: &str) -> Registry {
        lookup(&RefLocator::Purl(purl.into()), net, &BlobCache::disabled()).expect("registry")
    }

    #[test]
    fn jsr_api_normalizes() {
        let pkg = serde_json::json!({
            "scope": "std", "name": "path", "description": "File-path utilities",
            "latestVersion": "1.1.5", "score": 100,
            "githubRepository": {"owner": "denoland", "name": "std"}
        })
        .to_string();
        let release = |yanked: bool| {
            serde_json::json!({
                "scope": "std", "package": "path", "version": "1.1.5",
                "createdAt": "2021-04-23T10:00:00.000Z", "yanked": yanked
            })
            .to_string()
        };
        let net = Fixtures::default()
            .with(
                "https://api.jsr.io/scopes/std/packages/path",
                pkg.as_bytes(),
            )
            .with(
                "https://api.jsr.io/scopes/std/packages/path/versions/1.1.5",
                release(false).as_bytes(),
            )
            // The version is a path segment: encoded once, whatever the PURL
            // percent-encoded.
            .with(
                "https://api.jsr.io/scopes/std/packages/path/versions/1.0.0%2Bbuild",
                release(true).as_bytes(),
            );
        let r = look(&net, "pkg:jsr/%40std/path");
        assert_eq!(r.ecosystem, Ecosystem::Jsr);
        assert_eq!(r.name, "@std/path");
        assert_eq!(r.version, "1.1.5");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(
            r.repository.as_deref(),
            Some("https://github.com/denoland/std")
        );
        // The 0-100 score rates the package's quality, not its users' opinion.
        assert_eq!(r.rating, None);
        assert_eq!(r.version_removed, Some(false));

        let r = look(&net, "pkg:jsr/%40std/path@1.0.0%2Bbuild");
        assert_eq!(r.version, "1.0.0+build");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(r.version_removed, Some(true), "a yanked release");
    }
}
