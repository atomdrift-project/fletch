//! GitHub repositories: registry metadata.

use filefacts::Registry;
use serde::Deserialize;

use crate::ecosystem::{Coordinates, decode, flag, non_empty, unix_secs};
use crate::fetch::{BlobCache, Fetch, cached_github_api};
use crate::registry::RegistryError;

/// GitHub: a `pkg:github/<owner>/<repo>` reference has no package registry —
/// the repository itself is the upstream. The REST API supplies the
/// registry-shaped facts: recency (`pushed_at`), custody (`owner`), license,
/// and whether the repo is archived (a deprecation analogue).
///
/// The request carries the user's GitHub token when one is configured
/// ([`cached_github_api`]), so a coordinate from an untrusted file must never
/// reach anything but one public repository's document: owner and repo are
/// GitHub names (`[A-Za-z0-9._-]`, not `.` or `..`), the answer must be the
/// repository asked for (GitHub follows a rename to another one), and a
/// private repository — readable only through that token — yields no record.
pub(crate) fn lookup(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let (owner, repo) = c.pair()?;
    let github_name = |s: &str| {
        !matches!(s, "." | "..")
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    };
    if !github_name(owner) || !github_name(repo) {
        tracing::debug!(
            path = %c.path().escape_debug(),
            "registry lookup refused: not a GitHub owner/repository name"
        );
        return Err(RegistryError::UnsafeCoordinate);
    }
    let url = format!("https://api.github.com/repos/{owner}/{repo}");
    let doc: Repo = decode(&url, &cached_github_api(&url, net, cache)?)?;

    let asked = format!("{owner}/{repo}");
    if !doc
        .full_name
        .as_deref()
        .is_some_and(|name| name.eq_ignore_ascii_case(&asked))
    {
        tracing::debug!(
            url,
            full_name = %doc.full_name.as_deref().unwrap_or_default().escape_debug(),
            "no registry record: GitHub answered for another repository"
        );
        return Err(RegistryError::NoRecord);
    }
    if doc.private == Some(true) {
        tracing::debug!(url, "no registry record: the repository is private");
        return Err(RegistryError::NoRecord);
    }

    Ok(Registry {
        ecosystem: "github".into(),
        name: c.full_name(),
        version: c.target(None).to_string(),
        // `pushed_at` (last code change) is the supply-chain-relevant recency;
        // it dates the default branch, not a requested ref.
        published_at: if c.version().is_none() {
            doc.pushed_at.as_deref().and_then(unix_secs)
        } else {
            None
        },
        author: doc.owner.and_then(|o| o.login),
        title: doc.full_name,
        description: doc.description,
        homepage: doc.homepage,
        repository: doc.html_url,
        license: doc
            .license
            .and_then(|l| l.spdx_id)
            .filter(|s| s != "NOASSERTION"),
        deprecated: flag(doc.archived, "archived"),
        ..Default::default()
    })
}

/// The GitHub REST repository document (`/repos/{owner}/{repo}`).
#[derive(Default, Deserialize)]
#[serde(default)]
struct Repo {
    pushed_at: Option<String>,
    owner: Option<Owner>,
    full_name: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    description: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    homepage: Option<String>,
    html_url: Option<String>,
    license: Option<License>,
    archived: Option<bool>,
    private: Option<bool>,
}

/// The account that owns the repository.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Owner {
    login: Option<String>,
}

/// The license GitHub detected for the repository.
#[derive(Default, Deserialize)]
#[serde(default)]
struct License {
    spdx_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use filefacts::RefLocator;

    use crate::fetch::Fixtures;

    const GIN: &str = "https://api.github.com/repos/gin-gonic/gin";

    fn look(purl: &str, net: &Fixtures) -> Result<Registry, RegistryError> {
        crate::registry::lookup(&RefLocator::Purl(purl.into()), net, &BlobCache::disabled())
    }

    fn gin(extra: &serde_json::Value) -> Fixtures {
        let mut repo = serde_json::json!({
            "full_name": "gin-gonic/gin", "description": "HTTP web framework",
            "pushed_at": "2021-04-23T10:00:00Z", "stargazers_count": 88_739u64,
            "archived": false, "private": false, "homepage": "https://gin-gonic.com/",
            "html_url": "https://github.com/gin-gonic/gin",
            "owner": {"login": "gin-gonic"}, "license": {"spdx_id": "MIT"}
        });
        if let (Some(repo), Some(extra)) = (repo.as_object_mut(), extra.as_object()) {
            repo.extend(extra.clone());
        }
        Fixtures::default().with(GIN, repo.to_string().as_bytes())
    }

    #[test]
    fn github_repo_normalizes() {
        let r = look("pkg:github/gin-gonic/gin", &gin(&serde_json::json!({}))).expect("registry");
        assert_eq!(r.ecosystem, "github");
        assert_eq!(r.name, "gin-gonic/gin");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(r.author.as_deref(), Some("gin-gonic"));
        assert_eq!(r.license.as_deref(), Some("MIT"));
        // Stars are not ratings: nothing stands behind a `rating`.
        assert_eq!(r.rating_count, None);
        assert_eq!(r.deprecated, None);
    }

    #[test]
    fn an_archived_repository_is_deprecated() {
        let r = look(
            "pkg:github/gin-gonic/gin",
            &gin(&serde_json::json!({"archived": true})),
        )
        .expect("registry");
        assert_eq!(r.deprecated.as_deref(), Some("archived"));
    }

    #[test]
    fn a_requested_ref_is_the_version_and_the_last_push_does_not_date_it() {
        let r = look(
            "pkg:github/gin-gonic/gin@v1.9.0",
            &gin(&serde_json::json!({})),
        )
        .expect("registry");
        assert_eq!(r.version, "v1.9.0");
        assert_eq!(r.published_at, None);
    }

    #[test]
    fn a_private_repository_yields_no_record() {
        assert_eq!(
            look(
                "pkg:github/gin-gonic/gin",
                &gin(&serde_json::json!({"private": true}))
            ),
            Err(RegistryError::NoRecord)
        );
    }

    #[test]
    fn an_answer_for_another_repository_yields_no_record() {
        // GitHub follows a renamed repository to its new name.
        assert_eq!(
            look(
                "pkg:github/gin-gonic/gin",
                &gin(&serde_json::json!({"full_name": "attacker/gin"}))
            ),
            Err(RegistryError::NoRecord)
        );
        assert_eq!(
            look(
                "pkg:github/gin-gonic/gin",
                &gin(&serde_json::json!({"full_name": null}))
            ),
            Err(RegistryError::NoRecord)
        );
        // The name GitHub answers with may differ from the request in case.
        assert!(
            look(
                "pkg:github/gin-gonic/gin",
                &gin(&serde_json::json!({"full_name": "Gin-Gonic/Gin"}))
            )
            .is_ok()
        );
    }

    #[test]
    fn only_a_github_name_reaches_the_api() {
        // No fixtures: each must be refused before any read.
        let net = Fixtures::default();
        for purl in [
            "pkg:github/victim/private/contents",
            "pkg:github/gin-gonic/gin~1",
            "pkg:github/gin-gonic/gin%3A1",
            "pkg:github/gin-gonic/gin%40x",
            "pkg:github/gin-gonic/gin%2Bx",
        ] {
            assert_eq!(
                look(purl, &net),
                Err(RegistryError::UnsafeCoordinate),
                "{purl}"
            );
        }
    }
}
