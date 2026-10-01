//! Hugging Face: registry metadata and artifact resolution.

use filefacts::Registry;
use serde_json::Value;

use crate::ecosystem::{json_meta, parse_ts};
use crate::fetch::{BlobCache, Fetch};

/// Hugging Face Hub model repository: the models API carries the author, creation
/// and last-modified times, a rolling 30-day download count, and the like count —
/// the same popularity/custody shape as the other marketplaces. `path` is
/// `owner/model` (or a canonical bare `model`); `version` is a git revision.
pub(crate) fn huggingface(
    path: &str,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Option<Registry> {
    let doc = json_meta(
        &format!("https://huggingface.co/api/models/{path}"),
        net,
        cache,
    )?;

    let id = doc.get("id").and_then(Value::as_str).unwrap_or(path);
    Some(Registry {
        ecosystem: "huggingface".into(),
        name: id.to_string(),
        // No version in the locator → the current default-branch commit.
        version: version
            .map(str::to_string)
            .or_else(|| doc.get("sha").and_then(Value::as_str).map(str::to_string))
            .unwrap_or_default(),
        // `lastModified` is the latest commit's time; `createdAt` is the repo's
        // birth — a long-dormant model that suddenly ships again is the hijack tell.
        published_at: doc
            .get("lastModified")
            .and_then(Value::as_str)
            .and_then(parse_ts),
        first_published_at: doc
            .get("createdAt")
            .and_then(Value::as_str)
            .and_then(parse_ts),
        author: doc
            .get("author")
            .and_then(Value::as_str)
            .map(str::to_string),
        homepage: Some(format!("https://huggingface.co/{id}")),
        license: hf_license(&doc),
        // HF's `downloads` is a rolling 30-day count, not a lifetime total.
        downloads_recent: doc.get("downloads").and_then(Value::as_u64),
        // `likes` are the popularity/vote signal, like AUR's NumVotes.
        rating_count: doc.get("likes").and_then(Value::as_u64),
        ..Default::default()
    })
}

/// Hugging Face exposes a model's license as a top-level field, under `cardData`,
/// or as a `license:<id>` tag — try them in that order.
fn hf_license(doc: &Value) -> Option<String> {
    if let Some(l) = doc.get("license").and_then(Value::as_str) {
        return Some(l.to_string());
    }
    if let Some(l) = doc.pointer("/cardData/license").and_then(Value::as_str) {
        return Some(l.to_string());
    }
    doc.get("tags")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .find_map(|t| t.strip_prefix("license:"))
        .map(str::to_string)
}
