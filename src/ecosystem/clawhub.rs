//! ClawHub agent skills: registry metadata.

use filefacts::{Ecosystem, Registry};
use serde::Deserialize;

use crate::ecosystem::{Coordinates, count, fetch_json, non_empty, release_time, secs_from_millis};
use crate::fetch::{BlobCache, Fetch};
use crate::registry::RegistryError;

/// ClawHub agent-skill registry: `GET /api/v1/skills/{slug}` returns the one
/// skill (404 for an unknown slug). Slugs are not unique across publishers, so
/// the coordinate is `[owner/]slug` and the owner handle picks the publisher;
/// a slug several publishers share, asked for without one, is refused (409,
/// naming the owners), and the record is named `[owner/]slug` to match. The
/// skill document describes its latest release only.
pub(crate) fn lookup(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let url = if c.namespace().is_empty() {
        format!("https://clawhub.ai/api/v1/skills/{}", c.encoded_name())
    } else {
        let (owner, slug) = c.pair()?;
        format!("https://clawhub.ai/api/v1/skills/{slug}?ownerHandle={owner}")
    };
    let skill = fetch_json::<SkillDocument>(&url, net, cache)?.skill;
    let stats = skill.stats.unwrap_or_default();
    let mut record = c.record(
        Ecosystem::Clawhub,
        c.full_name(),
        skill.tags.and_then(|t| t.latest),
    );
    record.published_at = release_time(
        &record,
        record.latest_version.as_deref(),
        skill.updated_at.and_then(secs_from_millis),
    );
    record.first_published_at = skill.created_at.and_then(secs_from_millis);
    record.title = skill.display_name;
    record.description = skill.summary;
    record.downloads_total = stats.downloads;
    record.favorites = stats.stars;
    record.release_count = stats.versions.map(count);
    Ok(record)
}

/// A ClawHub skill document: the one skill under `skill`.
#[derive(Deserialize)]
struct SkillDocument {
    skill: Skill,
}

/// A ClawHub skill listing; its times are epoch milliseconds, occasionally
/// fractional.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Skill {
    #[serde(deserialize_with = "non_empty")]
    display_name: Option<String>,
    #[serde(deserialize_with = "non_empty")]
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
    #[serde(deserialize_with = "non_empty")]
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
    use crate::ecosystem::look;
    use crate::fetch::Fixtures;

    fn cool_skill(created_at: f64) -> Fixtures {
        let doc = serde_json::json!({"skill": {
            "slug": "cool-skill", "displayName": "Cool Skill",
            "summary": "Does cool things.",
            "tags": {"latest": "1.0.2"},
            "stats": {"downloads": 357u64, "stars": 4u64, "versions": 12u64},
            "createdAt": created_at,
            "updatedAt": 1_783_710_964_189u64
        }})
        .to_string();
        Fixtures::default().with(
            "https://clawhub.ai/api/v1/skills/cool-skill",
            doc.as_bytes(),
        )
    }

    #[test]
    fn clawhub_skill_normalizes() {
        let r = look("pkg:clawhub/cool-skill", &cool_skill(1_782_654_274_836.0)).expect("registry");
        assert_eq!(r.ecosystem, Ecosystem::Clawhub);
        assert_eq!(r.name, "cool-skill");
        assert_eq!(r.version, "1.0.2");
        assert_eq!(r.latest_version.as_deref(), Some("1.0.2"));
        assert_eq!(r.published_at, Some(1_783_710_964));
        assert_eq!(r.first_published_at, Some(1_782_654_274));
        assert_eq!(r.downloads_total, Some(357));
        // Stars are favorites, not ratings: nothing stands behind a `rating`.
        assert_eq!(r.favorites, Some(4));
        assert_eq!(r.rating_count, None);
        assert_eq!(r.release_count, Some(12));
    }

    #[test]
    fn a_negative_time_is_unknown_not_the_epoch() {
        let r = look("pkg:clawhub/cool-skill", &cool_skill(-5_000.0)).expect("registry");
        assert_eq!(r.first_published_at, None);
    }

    #[test]
    fn a_requested_version_is_the_record_and_the_latest_does_not_date_it() {
        let r = look("pkg:clawhub/cool-skill@1.0.0", &cool_skill(0.0)).expect("registry");
        assert_eq!(r.version, "1.0.0");
        assert_eq!(r.latest_version.as_deref(), Some("1.0.2"));
        assert_eq!(r.published_at, None);
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
        let r = look("pkg:clawhub/acme/web-search", &net).expect("registry");
        assert_eq!(r.name, "acme/web-search", "the owner is part of the name");
        assert_eq!(r.version, "2.0.0");
        assert!(look("pkg:clawhub/web-search", &net).is_err());
    }

    #[test]
    fn an_owner_handle_cannot_restructure_the_query() {
        // `a&x=y` stays one encoded handle; a nested owner is refused outright.
        let doc = serde_json::json!({"skill": {"tags": {"latest": "1.0.0"}}}).to_string();
        let net = Fixtures::default().with(
            "https://clawhub.ai/api/v1/skills/s?ownerHandle=a%26x%3Dy",
            doc.as_bytes(),
        );
        assert!(look("pkg:clawhub/a%26x%3Dy/s", &net).is_ok());
        assert_eq!(
            look("pkg:clawhub/a/b/s", &Fixtures::default()),
            Err(RegistryError::UnsafeCoordinate)
        );
    }
}
