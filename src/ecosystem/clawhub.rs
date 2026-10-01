//! ClawHub: registry metadata and artifact resolution.

use filefacts::Registry;
use serde::Deserialize;

use crate::ecosystem::fetch_json;
use crate::fetch::{BlobCache, Fetch};
use crate::registry::RegistryError;

/// ClawHub agent-skill registry: `GET /api/v1/skills/{slug}` returns the one
/// skill (404 for an unknown slug). Slugs are not unique across publishers, so
/// `path` is the purl's `[owner/]slug` and the owner handle picks the
/// publisher; a slug several publishers share, asked for without one, is
/// refused (409, naming the owners).
pub(crate) fn clawhub(
    path: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let (owner, slug) = path
        .rsplit_once('/')
        .map_or((None, path), |(owner, slug)| (Some(owner), slug));
    let mut url = format!("https://clawhub.ai/api/v1/skills/{slug}");
    if let Some(owner) = owner {
        url.push_str("?ownerHandle=");
        url.push_str(owner);
    }
    let doc: SkillDocument = fetch_json(&url, net, cache)?;
    let skill = doc.skill;
    // Epoch-millisecond timestamps, occasionally fractional; fold to seconds.
    let ms_to_secs = |ms: f64| ms as u64 / 1_000;
    let stats = skill.stats.unwrap_or_default();
    Ok(Registry {
        ecosystem: "clawhub".into(),
        name: slug.to_string(),
        version: skill.tags.and_then(|t| t.latest).unwrap_or_default(),
        published_at: skill.updated_at.map(ms_to_secs),
        first_published_at: skill.created_at.map(ms_to_secs),
        title: skill.display_name,
        description: skill.summary,
        downloads_total: stats.downloads,
        rating_count: stats.stars,
        release_count: stats.versions.and_then(|v| u32::try_from(v).ok()),
        ..Default::default()
    })
}

/// A ClawHub skill document: the one skill under `skill`.
#[derive(Deserialize)]
struct SkillDocument {
    skill: Skill,
}

/// A ClawHub skill listing.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Skill {
    display_name: Option<String>,
    summary: Option<String>,
    tags: Option<SkillTags>,
    stats: Option<SkillStats>,
    created_at: Option<f64>,
    updated_at: Option<f64>,
}

/// A skill's version tags.
#[derive(Default, Deserialize)]
#[serde(default)]
struct SkillTags {
    latest: Option<String>,
}

/// A skill's popularity and release counters.
#[derive(Default, Deserialize)]
#[serde(default)]
struct SkillStats {
    downloads: Option<u64>,
    stars: Option<u64>,
    versions: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::test_cache;

    use crate::fetch::Fixtures;

    #[test]
    fn clawhub_skill_normalizes() {
        let doc = serde_json::json!({"skill": {
            "slug": "cool-skill", "displayName": "Cool Skill",
            "summary": "Does cool things.",
            "tags": {"latest": "1.0.2"},
            "stats": {"downloads": 357u64, "stars": 4u64, "versions": 12u64},
            "createdAt": 1_782_654_274_836u64,
            "updatedAt": 1_783_710_964_189u64
        }})
        .to_string();
        let net = Fixtures::default().with(
            "https://clawhub.ai/api/v1/skills/cool-skill",
            doc.as_bytes(),
        );
        let r = clawhub("cool-skill", &net, &test_cache("clawhub")).expect("registry");
        assert_eq!(r.ecosystem, "clawhub");
        assert_eq!(r.name, "cool-skill");
        assert_eq!(r.version, "1.0.2");
        assert_eq!(r.published_at, Some(1_783_710_964));
        assert_eq!(r.first_published_at, Some(1_782_654_274));
        assert_eq!(r.downloads_total, Some(357));
        assert_eq!(r.rating_count, Some(4));
        assert_eq!(r.release_count, Some(12));
    }

    /// A slug two publishers share answers 409 without an owner; the purl's
    /// owner namespace names which publisher's skill this is.
    #[test]
    fn clawhub_owner_picks_the_publisher() {
        let doc = serde_json::json!({"skill": {"slug": "web-search", "tags": {"latest": "2.0.0"}}})
            .to_string();
        let net = Fixtures::default()
            .refusing("https://clawhub.ai/api/v1/skills/web-search", 409)
            .with(
                "https://clawhub.ai/api/v1/skills/web-search?ownerHandle=acme",
                doc.as_bytes(),
            );
        let cache = test_cache("clawhub-owner");
        let r = clawhub("acme/web-search", &net, &cache).expect("registry");
        assert_eq!(r.name, "web-search");
        assert_eq!(r.version, "2.0.0");
        assert!(clawhub("web-search", &net, &cache).is_err());
    }
}
