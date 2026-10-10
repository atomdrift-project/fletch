//! GitHub repositories: registry metadata and artifact resolution.

use filefacts::Registry;
use serde::Deserialize;

use crate::ecosystem::{decode, parse_rfc3339_secs};
use crate::fetch::{BlobCache, Fetch, cached_github_api};
use crate::registry::RegistryError;

/// GitHub: a `pkg:github/<owner>/<repo>` reference has no package registry — the
/// repository itself is the upstream. The REST API supplies the registry-shaped
/// facts: recency (`pushed_at`), custody (`owner`), endorsement (stars),
/// license, and whether the repo is archived (a deprecation analogue).
/// Unauthenticated, so subject to GitHub's 60-req/hour anonymous limit; a
/// throttled lookup simply degrades to "unknown".
pub(crate) fn github(
    path: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    // Exactly `owner/repo`: the request carries the GitHub token, so a longer
    // path (`victim/private/contents/.env`) must never reach another endpoint.
    if !path
        .split_once('/')
        .is_some_and(|(owner, repo)| !owner.is_empty() && !repo.is_empty() && !repo.contains('/'))
    {
        return Err(RegistryError::NoRecord);
    }
    // fletch names this URL itself, so it alone may carry the GitHub token.
    let url = format!("https://api.github.com/repos/{path}");
    let doc: Repo = decode(&url, &cached_github_api(&url, net, cache)?)?;

    Ok(Registry {
        ecosystem: "github".into(),
        name: path.to_string(),
        version: String::new(),
        // `pushed_at` (last code change) is the supply-chain-relevant recency.
        published_at: doc.pushed_at.as_deref().and_then(parse_rfc3339_secs),
        author: doc.owner.and_then(|o| o.login),
        title: doc.full_name,
        description: doc.description,
        homepage: doc.homepage.filter(|s| !s.is_empty()),
        repository: doc.html_url,
        license: doc
            .license
            .and_then(|l| l.spdx_id)
            .filter(|s| s != "NOASSERTION"),
        // Stars are GitHub's endorsement count — the nearest popularity analogue.
        rating_count: doc.stargazers_count,
        deprecated: doc.archived.and_then(|a| a.then(|| "archived".to_string())),
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
    description: Option<String>,
    homepage: Option<String>,
    html_url: Option<String>,
    license: Option<License>,
    stargazers_count: Option<u64>,
    archived: Option<bool>,
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

    use crate::fetch::{BlobCache, Fixtures};

    #[test]
    fn github_repo_normalizes() {
        let repo = serde_json::json!({
            "full_name": "gin-gonic/gin", "description": "HTTP web framework",
            "pushed_at": "2021-04-23T10:00:00Z", "stargazers_count": 88_739u64,
            "archived": false, "homepage": "https://gin-gonic.com/",
            "html_url": "https://github.com/gin-gonic/gin",
            "owner": {"login": "gin-gonic"}, "license": {"spdx_id": "MIT"}
        })
        .to_string();
        let net = Fixtures::default().with(
            "https://api.github.com/repos/gin-gonic/gin",
            repo.as_bytes(),
        );
        let cache = BlobCache::disabled();
        let r = github("gin-gonic/gin", &net, &cache).expect("registry");
        assert_eq!(r.ecosystem, "github");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(r.author.as_deref(), Some("gin-gonic"));
        assert_eq!(r.license.as_deref(), Some("MIT"));
        assert_eq!(r.rating_count, Some(88_739));
        assert_eq!(r.deprecated, None);
    }
}
