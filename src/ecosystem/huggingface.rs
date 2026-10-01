//! Hugging Face: registry metadata and artifact resolution.

use filefacts::Registry;
use serde::Deserialize;

use crate::ecosystem::{fetch_json, lenient, null_default, parse_ts};
use crate::fetch::{BlobCache, Fetch};
use crate::registry::RegistryError;

/// Hugging Face Hub model repository: the models API carries the author, creation
/// and last-modified times, a rolling 30-day download count, and the like count —
/// the same popularity/custody shape as the other marketplaces. `path` is
/// `owner/model` (or a canonical bare `model`); `version` is a git revision.
pub(crate) fn huggingface(
    path: &str,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let doc: Model = fetch_json(
        &format!("https://huggingface.co/api/models/{path}"),
        net,
        cache,
    )?;

    let id = doc.id.as_deref().unwrap_or(path);
    Ok(Registry {
        ecosystem: "huggingface".into(),
        name: id.to_string(),
        // No version in the locator → the current default-branch commit.
        version: version
            .map(str::to_string)
            .or_else(|| doc.sha.clone())
            .unwrap_or_default(),
        // `lastModified` is the latest commit's time; `createdAt` is the repo's
        // birth — a long-dormant model that suddenly ships again is the hijack tell.
        published_at: doc.last_modified.as_deref().and_then(parse_ts),
        first_published_at: doc.created_at.as_deref().and_then(parse_ts),
        author: doc.author.clone(),
        homepage: Some(format!("https://huggingface.co/{id}")),
        license: hf_license(&doc),
        // HF's `downloads` is a rolling 30-day count, not a lifetime total.
        downloads_recent: doc.downloads,
        // `likes` are the popularity/vote signal, like AUR's NumVotes.
        rating_count: doc.likes,
        ..Default::default()
    })
}

/// Hugging Face exposes a model's license as a top-level field, under `cardData`,
/// or as a `license:<id>` tag — try them in that order.
fn hf_license(doc: &Model) -> Option<String> {
    if let Some(l) = &doc.license {
        return Some(l.clone());
    }
    if let Some(l) = doc.card_data.as_ref().and_then(|c| c.license.as_ref()) {
        return Some(l.clone());
    }
    doc.tags
        .iter()
        .find_map(|t| t.strip_prefix("license:"))
        .map(str::to_string)
}

/// A Hugging Face Hub model document.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Model {
    id: Option<String>,
    sha: Option<String>,
    last_modified: Option<String>,
    created_at: Option<String>,
    author: Option<String>,
    license: Option<String>,
    card_data: Option<CardData>,
    #[serde(deserialize_with = "null_default")]
    tags: Vec<String>,
    downloads: Option<u64>,
    likes: Option<u64>,
}

/// The model card's front matter, as the Hub parsed it.
#[derive(Default, Deserialize)]
#[serde(default)]
struct CardData {
    // A card may list several licenses (`[mit, other]`) instead of naming one.
    #[serde(deserialize_with = "lenient")]
    license: Option<String>,
}
