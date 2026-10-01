//! GitHub repositories: registry metadata and artifact resolution.

use filefacts::Registry;
use serde_json::Value;

use crate::ecosystem::{json_meta, parse_rfc3339_secs};
use crate::fetch::{BlobCache, Fetch};

/// GitHub: a `pkg:github/<owner>/<repo>` reference has no package registry — the
/// repository itself is the upstream. The REST API supplies the registry-shaped
/// facts: recency (`pushed_at`), custody (`owner`), endorsement (stars),
/// license, and whether the repo is archived (a deprecation analogue).
/// Unauthenticated, so subject to GitHub's 60-req/hour anonymous limit; a
/// throttled lookup simply degrades to "unknown".
pub(crate) fn github(path: &str, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    let doc = json_meta(&format!("https://api.github.com/repos/{path}"), net, cache)?;

    Some(Registry {
        ecosystem: "github".into(),
        name: path.to_string(),
        version: String::new(),
        // `pushed_at` (last code change) is the supply-chain-relevant recency.
        published_at: doc
            .get("pushed_at")
            .and_then(Value::as_str)
            .and_then(parse_rfc3339_secs),
        author: doc
            .pointer("/owner/login")
            .and_then(Value::as_str)
            .map(str::to_string),
        title: doc
            .get("full_name")
            .and_then(Value::as_str)
            .map(str::to_string),
        description: doc
            .get("description")
            .and_then(Value::as_str)
            .map(str::to_string),
        homepage: doc
            .get("homepage")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        repository: doc
            .get("html_url")
            .and_then(Value::as_str)
            .map(str::to_string),
        license: doc
            .pointer("/license/spdx_id")
            .and_then(Value::as_str)
            .filter(|&s| s != "NOASSERTION")
            .map(str::to_string),
        // Stars are GitHub's endorsement count — the nearest popularity analogue.
        rating_count: doc.get("stargazers_count").and_then(Value::as_u64),
        deprecated: doc
            .get("archived")
            .and_then(Value::as_bool)
            .and_then(|a| a.then(|| "archived".to_string())),
        ..Default::default()
    })
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
