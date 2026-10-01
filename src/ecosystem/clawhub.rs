//! ClawHub: registry metadata and artifact resolution.

use filefacts::Registry;
use serde_json::Value;

use crate::ecosystem::json_meta;
use crate::fetch::{BlobCache, Fetch};

/// Homebrew: the formula JSON carries the stable version, description, license,
/// and 30-day install analytics. It records no publish date.
/// ClawHub agent-skill registry: `GET /api/v1/skills/{slug}` returns the one
/// skill (404 for an unknown slug). The purl's optional owner namespace
/// disambiguates *downloads* (slugs are not unique across publishers); the
/// metadata endpoint is slug-keyed, so a shared slug resolves to the
/// registry's primary holder of that slug.
pub(crate) fn clawhub(slug: &str, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    let doc = json_meta(
        &format!("https://clawhub.ai/api/v1/skills/{slug}"),
        net,
        cache,
    )?;
    let skill = doc.get("skill")?;
    // Epoch-millisecond timestamps, occasionally fractional; fold to seconds.
    let ms_to_secs = |v: &Value| {
        v.as_u64()
            .or_else(|| v.as_f64().map(|f| f as u64))
            .map(|ms| ms / 1_000)
    };
    Some(Registry {
        ecosystem: "clawhub".into(),
        name: slug.to_string(),
        version: skill
            .pointer("/tags/latest")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        published_at: skill.get("updatedAt").and_then(ms_to_secs),
        first_published_at: skill.get("createdAt").and_then(ms_to_secs),
        title: skill
            .get("displayName")
            .and_then(Value::as_str)
            .map(str::to_string),
        description: skill
            .get("summary")
            .and_then(Value::as_str)
            .map(str::to_string),
        downloads_total: skill.pointer("/stats/downloads").and_then(Value::as_u64),
        rating_count: skill.pointer("/stats/stars").and_then(Value::as_u64),
        release_count: skill
            .pointer("/stats/versions")
            .and_then(Value::as_u64)
            .and_then(|v| u32::try_from(v).ok()),
        ..Default::default()
    })
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
}
