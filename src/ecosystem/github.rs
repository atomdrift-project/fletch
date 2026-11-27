//! GitHub repositories: registry metadata.

use filefacts::{Ecosystem, Registry};
use serde::Deserialize;

use crate::ecosystem::{Coordinates, decode, flag, non_empty, unix_secs};
use crate::fetch::{BlobCache, Fetch, cached_github_api, cached_metadata_status};
use crate::registry::RegistryError;

/// GitHub: a `pkg:github/<owner>/<repo>` reference has no package registry —
/// the repository itself is the upstream.
///
/// Two sources. The REST API supplies every registry-shaped fact — recency
/// (`pushed_at`), custody (`owner`), license, stars, and whether the repo is
/// archived (a deprecation analogue) — but anonymously it allows 60 requests an
/// hour per address, shared by every client behind it, and a busy scanner
/// spends that in minutes. So it is used only when the backend carries a token
/// ([`Fetch::has_github_token`]); otherwise, and whenever the API is
/// unavailable, the record comes from the public commit feed, which is not
/// metered that way (see [`from_commit_feed`]).
///
/// The API request carries the user's GitHub token ([`cached_github_api`]), so
/// a coordinate from an untrusted file must never reach anything but one public
/// repository's document: owner and repo are GitHub names (`[A-Za-z0-9._-]`,
/// not `.` or `..`), the answer must be the repository asked for (GitHub
/// follows a rename to another one), and a private repository — readable only
/// through that token — yields no record.
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
    if net.has_github_token() {
        match from_api(c, owner, repo, net, cache) {
            Err(RegistryError::Unavailable(error)) => tracing::info!(
                owner,
                repo,
                %error,
                "GitHub API unavailable; reading the public commit feed instead"
            ),
            answered => return answered,
        }
    }
    from_commit_feed(c, owner, repo, net, cache)
}

/// The full record, from the REST repository document.
fn from_api(
    c: &Coordinates<'_>,
    owner: &str,
    repo: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
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

    // A repository has no releases of its own to call latest.
    let mut record = c.record(Ecosystem::Github, c.full_name(), None);
    // `pushed_at` (last code change) is the supply-chain-relevant recency;
    // it dates the default branch, not a requested ref.
    record.published_at = if c.version().is_none() {
        doc.pushed_at.as_deref().and_then(unix_secs)
    } else {
        None
    };
    record.author = doc.owner.and_then(|o| o.login);
    record.title = doc.full_name;
    record.description = doc.description;
    record.homepage = doc.homepage;
    record.repository = doc.html_url;
    record.license = doc
        .license
        .and_then(|l| l.spdx_id)
        .filter(|s| s != "NOASSERTION");
    record.favorites = doc.stargazers_count;
    record.deprecated = flag(doc.archived, "archived");
    Ok(record)
}

/// The record GitHub's public commit feed supports, read without the metered
/// REST API: `github.com/{owner}/{repo}/commits.atom`.
///
/// The feed exists only for a public repository (a private or missing one is a
/// 404, so [`RegistryError::NotFound`]), names the repository it describes in
/// its `<id>` — GitHub redirects a renamed repository's feed to the new name,
/// which is how a rename shows here, and it yields no record just as in the API
/// — and its newest entry dates the default branch's last commit, standing in
/// for `pushed_at`. Stars, license, description, homepage and archived status
/// exist only in the API and are left unknown, never guessed.
fn from_commit_feed(
    c: &Coordinates<'_>,
    owner: &str,
    repo: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let url = format!("https://github.com/{owner}/{repo}/commits.atom");
    let bytes = cached_metadata_status(&url, &[], net, cache)?;
    let feed = std::str::from_utf8(&bytes).map_err(|e| RegistryError::Malformed {
        url: url.clone(),
        reason: e.to_string(),
    })?;
    // `<id>tag:github.com,2008:/{owner}/{repo}/commits/{branch}</id>`: names
    // carry no `/`, so the first `/commits/` ends the repository.
    let Some(named) = element(feed, "id")
        .and_then(|id| id.strip_prefix("tag:github.com,2008:/"))
        .and_then(|rest| rest.split_once("/commits/"))
        .map(|(name, _)| name)
    else {
        return Err(RegistryError::Malformed {
            url,
            reason: "no repository-commits feed id".into(),
        });
    };
    if !named.eq_ignore_ascii_case(&format!("{owner}/{repo}")) {
        tracing::debug!(
            url,
            named = %named.escape_debug(),
            "no registry record: GitHub answered for another repository"
        );
        return Err(RegistryError::NoRecord);
    }

    let mut record = c.record(Ecosystem::Github, c.full_name(), None);
    // As with `pushed_at`, the feed dates the default branch, not a requested
    // ref; an empty repository has no entry and so no date.
    record.published_at = if c.version().is_none() {
        feed.split_once("<entry>")
            .and_then(|(_, entry)| element(entry, "updated"))
            .and_then(unix_secs)
    } else {
        None
    };
    record.author = named.split_once('/').map(|(login, _)| login.to_owned());
    record.title = Some(named.to_owned());
    record.repository = Some(format!("https://github.com/{named}"));
    tracing::debug!(
        url,
        "GitHub record from the public commit feed; stars, license and archived status unknown"
    );
    Ok(record)
}

/// The text of the first `<name>` element in `xml`, trimmed.
fn element<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let (_, rest) = xml.split_once(&format!("<{name}>"))?;
    let (text, _) = rest.split_once(&format!("</{name}>"))?;
    Some(text.trim())
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
    #[serde(deserialize_with = "non_empty")]
    html_url: Option<String>,
    license: Option<License>,
    archived: Option<bool>,
    private: Option<bool>,
    stargazers_count: Option<u64>,
}

/// The account that owns the repository.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Owner {
    #[serde(deserialize_with = "non_empty")]
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
    use crate::ecosystem::look;
    use crate::fetch::Fixtures;

    const GIN: &str = "https://api.github.com/repos/gin-gonic/gin";

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
        Fixtures::default()
            .with_github_token()
            .with(GIN, repo.to_string().as_bytes())
    }

    #[test]
    fn github_repo_normalizes() {
        let r = look("pkg:github/gin-gonic/gin", &gin(&serde_json::json!({}))).expect("registry");
        assert_eq!(r.ecosystem, Ecosystem::Github);
        assert_eq!(r.name, "gin-gonic/gin");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(r.author.as_deref(), Some("gin-gonic"));
        assert_eq!(r.license.as_deref(), Some("MIT"));
        // Stars are favorites, not ratings: nothing stands behind a `rating`.
        assert_eq!(r.favorites, Some(88_739));
        assert_eq!(r.rating_count, None);
        assert_eq!(r.deprecated, None);
    }

    #[test]
    fn blank_links_are_unknown() {
        let r = look(
            "pkg:github/gin-gonic/gin",
            &gin(&serde_json::json!({"html_url": "", "owner": {"login": ""}})),
        )
        .expect("registry");
        assert_eq!(r.repository, None);
        assert_eq!(r.author, None);
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

    const GIN_FEED: &str = "https://github.com/gin-gonic/gin/commits.atom";

    /// A commits feed as GitHub serves it, for `name` on branch `master`.
    fn feed(name: &str, entries: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom" xml:lang="en-US">
  <id>tag:github.com,2008:/{name}/commits/master</id>
  <title>Recent Commits to gin:master</title>
  <updated>2021-04-23T10:00:00Z</updated>{entries}
</feed>"#
        )
    }

    const ENTRY: &str = r#"
  <entry>
    <id>tag:github.com,2008:Grit::Commit/f548e57e544e1ff5a4c46bf1e1b8685f8e4a348a</id>
    <updated>2021-04-23T10:00:00Z</updated>
    <author><name>someone</name></author>
  </entry>
  <entry>
    <updated>2020-01-01T00:00:00Z</updated>
  </entry>"#;

    #[test]
    fn without_a_token_the_record_comes_from_the_commit_feed() {
        // No API fixture: an anonymous lookup must not spend the shared quota.
        let net = Fixtures::default().with(GIN_FEED, feed("gin-gonic/gin", ENTRY).as_bytes());
        let r = look("pkg:github/gin-gonic/gin", &net).expect("registry");
        assert_eq!(r.ecosystem, Ecosystem::Github);
        assert_eq!(r.name, "gin-gonic/gin");
        assert_eq!(
            r.published_at,
            Some(1_619_172_000),
            "newest commit dates it"
        );
        assert_eq!(r.author.as_deref(), Some("gin-gonic"));
        assert_eq!(r.title.as_deref(), Some("gin-gonic/gin"));
        assert_eq!(
            r.repository.as_deref(),
            Some("https://github.com/gin-gonic/gin")
        );
        // API-only facts are unknown, never guessed.
        assert_eq!(r.license, None);
        assert_eq!(r.favorites, None);
        assert_eq!(r.deprecated, None);
        assert_eq!(r.description, None);
    }

    #[test]
    fn the_feed_does_not_date_a_requested_ref() {
        let net = Fixtures::default().with(GIN_FEED, feed("gin-gonic/gin", ENTRY).as_bytes());
        let r = look("pkg:github/gin-gonic/gin@v1.9.0", &net).expect("registry");
        assert_eq!(r.version, "v1.9.0");
        assert_eq!(r.published_at, None);
    }

    #[test]
    fn an_empty_repository_has_a_record_but_no_date() {
        let net = Fixtures::default().with(GIN_FEED, feed("gin-gonic/gin", "").as_bytes());
        let r = look("pkg:github/gin-gonic/gin", &net).expect("registry");
        assert_eq!(r.published_at, None);
    }

    #[test]
    fn a_feed_for_another_repository_yields_no_record() {
        // GitHub redirects a renamed repository's feed to its new name.
        let net = Fixtures::default().with(GIN_FEED, feed("attacker/gin", ENTRY).as_bytes());
        assert_eq!(
            look("pkg:github/gin-gonic/gin", &net),
            Err(RegistryError::NoRecord)
        );
        // Case is not a rename.
        let net = Fixtures::default().with(GIN_FEED, feed("Gin-Gonic/Gin", ENTRY).as_bytes());
        let r = look("pkg:github/gin-gonic/gin", &net).expect("registry");
        assert_eq!(r.title.as_deref(), Some("Gin-Gonic/Gin"));
    }

    #[test]
    fn a_missing_or_private_repository_has_no_feed() {
        let net = Fixtures::default().refusing(GIN_FEED, 404);
        assert_eq!(
            look("pkg:github/gin-gonic/gin", &net),
            Err(RegistryError::NotFound)
        );
    }

    #[test]
    fn a_page_that_is_not_a_commits_feed_is_malformed() {
        let net = Fixtures::default().with(GIN_FEED, b"<html>rate limited</html>");
        assert!(matches!(
            look("pkg:github/gin-gonic/gin", &net),
            Err(RegistryError::Malformed { .. })
        ));
    }

    #[test]
    fn an_unavailable_api_falls_back_to_the_feed() {
        // A token, but no API answer (rate limited, down): the feed still answers.
        let net = Fixtures::default()
            .with_github_token()
            .refusing(GIN, 403)
            .with(GIN_FEED, feed("gin-gonic/gin", ENTRY).as_bytes());
        let r = look("pkg:github/gin-gonic/gin", &net).expect("registry");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(r.favorites, None, "from the feed, not the API");
    }

    #[test]
    fn an_api_answer_of_no_record_is_final() {
        // The API's "private" is an answer, not an outage: no fallback.
        let net = gin(&serde_json::json!({"private": true}))
            .with(GIN_FEED, feed("gin-gonic/gin", ENTRY).as_bytes());
        assert_eq!(
            look("pkg:github/gin-gonic/gin", &net),
            Err(RegistryError::NoRecord)
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
