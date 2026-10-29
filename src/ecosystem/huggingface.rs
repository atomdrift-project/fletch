//! Hugging Face Hub models: registry metadata.

use filefacts::Registry;
use serde::Deserialize;

use crate::ecosystem::{Coordinates, fetch_json, lenient, non_empty, null_default, unix_secs};
use crate::fetch::{BlobCache, Fetch};
use crate::registry::RegistryError;

/// Hugging Face Hub model repository: the models API carries the author,
/// creation and last-modified times, and a rolling 30-day download count. The
/// coordinate is `owner/model` or a bare `model`, nothing longer, so it can
/// only ever name a model document; the version is a git revision.
pub(crate) fn lookup(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    if c.namespace().len() > 1 {
        tracing::debug!(
            path = %c.path().escape_debug(),
            "registry lookup refused: a Hugging Face model is owner/model or model"
        );
        return Err(RegistryError::UnsafeCoordinate);
    }
    let doc: Model = fetch_json(
        &format!("https://huggingface.co/api/models/{}", c.path()),
        net,
        cache,
    )?;

    // No version in the locator → the current default-branch commit.
    let version = c.target(doc.sha.as_deref());
    // `lastModified` is that commit's time, so it dates only that revision;
    // `createdAt` is the repo's birth — a long-dormant model that suddenly
    // ships again is the hijack tell.
    let current = doc.sha.as_deref() == Some(version);
    let license = doc
        .license
        .or_else(|| doc.card_data.and_then(|c| c.license))
        .or_else(|| {
            doc.tags
                .iter()
                .find_map(|t| t.strip_prefix("license:"))
                .map(str::to_string)
        });
    Ok(Registry {
        ecosystem: "huggingface".into(),
        name: c.full_name(),
        version: version.to_string(),
        published_at: doc
            .last_modified
            .as_deref()
            .filter(|_| current)
            .and_then(unix_secs),
        first_published_at: doc.created_at.as_deref().and_then(unix_secs),
        author: doc.author,
        homepage: Some(format!("https://huggingface.co/{}", c.path())),
        license,
        // HF's `downloads` is a rolling 30-day count, not a lifetime total.
        downloads_recent: doc.downloads,
        ..Default::default()
    })
}

/// A Hugging Face Hub model document. A model's license is a top-level
/// field, under `cardData`, or a `license:<id>` tag — read in that order.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Model {
    #[serde(deserialize_with = "non_empty")]
    sha: Option<String>,
    last_modified: Option<String>,
    created_at: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    author: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    license: Option<String>,
    card_data: Option<CardData>,
    #[serde(deserialize_with = "null_default")]
    tags: Vec<String>,
    downloads: Option<u64>,
}

/// The model card's front matter, as the Hub parsed it.
#[derive(Default, Deserialize)]
#[serde(default)]
struct CardData {
    // A card may list several licenses (`[mit, other]`) instead of naming one.
    #[serde(deserialize_with = "lenient")]
    license: Option<String>,
}

#[cfg(test)]
mod tests {
    use filefacts::RefLocator;

    use crate::fetch::{BlobCache, Fixtures};
    use crate::registry::RegistryError;

    const RESNET: &str = "https://huggingface.co/api/models/microsoft/resnet-50";

    fn resnet() -> Fixtures {
        let doc = serde_json::json!({
            "id": "microsoft/resnet-50", "author": "microsoft", "sha": "abc123def",
            "createdAt": "2022-03-16T10:00:00.000Z", "lastModified": "2023-04-23T10:00:00.000Z",
            "downloads": 1_234_567u64, "likes": 89u64, "license": "apache-2.0"
        })
        .to_string();
        Fixtures::default().with(RESNET, doc.as_bytes())
    }

    fn look(purl: &str, net: &Fixtures) -> Result<filefacts::Registry, RegistryError> {
        crate::registry::lookup(&RefLocator::Purl(purl.into()), net, &BlobCache::disabled())
    }

    #[test]
    fn huggingface_model_normalizes() {
        let r =
            look("pkg:huggingface/microsoft/resnet-50", &resnet()).expect("huggingface registry");
        assert_eq!(r.ecosystem, "huggingface");
        assert_eq!(r.name, "microsoft/resnet-50");
        assert_eq!(r.version, "abc123def");
        assert_eq!(r.author.as_deref(), Some("microsoft"));
        assert_eq!(r.license.as_deref(), Some("apache-2.0"));
        assert_eq!(r.downloads_recent, Some(1_234_567));
        // Likes are not ratings: nothing stands behind a `rating`.
        assert_eq!(r.rating_count, None);
        assert_eq!(r.published_at, Some(1_682_244_000)); // lastModified
        assert_eq!(r.first_published_at, Some(1_647_424_800)); // createdAt
        assert_eq!(
            r.homepage.as_deref(),
            Some("https://huggingface.co/microsoft/resnet-50")
        );
    }

    #[test]
    fn a_requested_revision_is_the_version_and_the_head_does_not_date_it() {
        let r = look("pkg:huggingface/microsoft/resnet-50@0ld", &resnet()).expect("registry");
        assert_eq!(r.version, "0ld");
        assert_eq!(r.published_at, None);
        let r = look("pkg:huggingface/microsoft/resnet-50@abc123def", &resnet()).expect("registry");
        assert_eq!(r.published_at, Some(1_682_244_000));
    }

    #[test]
    fn a_license_comes_from_the_card_or_a_tag() {
        let doc =
            serde_json::json!({"cardData": {"license": ["mit", "other"]}, "tags": ["license:mit"]})
                .to_string();
        let net = Fixtures::default().with(RESNET, doc.as_bytes());
        let r = look("pkg:huggingface/microsoft/resnet-50", &net).expect("registry");
        assert_eq!(r.license.as_deref(), Some("mit"));
    }

    #[test]
    fn a_longer_path_never_reaches_another_endpoint() {
        // No fixtures: refused before any read.
        assert_eq!(
            look(
                "pkg:huggingface/microsoft/resnet-50/tree/main",
                &Fixtures::default()
            ),
            Err(RegistryError::UnsafeCoordinate)
        );
    }

    #[test]
    fn the_record_is_named_with_the_decoded_coordinate() {
        let doc = serde_json::json!({"sha": "1"}).to_string();
        let net = Fixtures::default().with(
            "https://huggingface.co/api/models/org/m%2Bx",
            doc.as_bytes(),
        );
        let r = look("pkg:huggingface/org/m%2Bx", &net).expect("registry");
        assert_eq!(r.name, "org/m+x");
    }
}
