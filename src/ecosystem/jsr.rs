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
        return Err(RegistryError::UnsafeCoordinate);
    };
    let doc: Package = fetch_json(
        &format!("https://api.jsr.io/scopes/{scope}/packages/{pkg}"),
        net,
        cache,
    )?;
    let mut record = c.record(
        Ecosystem::Jsr,
        format!("@{scope}/{pkg}"),
        doc.latest_version,
    );

    // The release's own document dates it; a version JSR does not have is a
    // 404 there, and gets no date rather than the newest's.
    let url = format!(
        "https://api.jsr.io/scopes/{scope}/packages/{pkg}/versions/{}",
        encode_component(&record.version)
    );
    let release = optional(fetch_json::<PackageVersion>(&url, net, cache), &url);
    record.published_at = release
        .as_ref()
        .and_then(|r| r.created_at.as_deref())
        .and_then(unix_secs);
    record.description = doc.description;
    record.repository = doc
        .github_repository
        .and_then(|g| Some(format!("https://github.com/{}/{}", g.owner?, g.name?)));
    record.version_removed = release.and_then(|r| r.yanked);
    Ok(record)
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
    use crate::ecosystem::look;
    use crate::fetch::Fixtures;
    use crate::registry::RegistryError;
    use filefacts::Ecosystem;

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
        let r = look("pkg:jsr/%40std/path", &net).expect("registry");
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

        let r = look("pkg:jsr/%40std/path@1.0.0%2Bbuild", &net).expect("registry");
        assert_eq!(r.version, "1.0.0+build");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(r.version_removed, Some(true), "a yanked release");
    }

    #[test]
    fn a_coordinate_that_is_not_scope_and_name_is_refused_unread() {
        for purl in [
            "pkg:jsr/%40%40%40std/path",
            "pkg:jsr/path",
            "pkg:jsr/%40std/a/path",
            "pkg:jsr/%40Std/path",
        ] {
            assert_eq!(
                look(purl, &Fixtures::default()),
                Err(RegistryError::UnsafeCoordinate),
                "{purl}"
            );
        }
    }
}
