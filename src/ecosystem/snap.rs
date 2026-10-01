//! The Snap Store: registry metadata and artifact resolution.

use filefacts::Registry;
use serde_json::Value;

use crate::ecosystem::parse_ts;
use crate::fetch::{BlobCache, Fetch, cached_metadata_with};

/// Snap Store: the v2 info endpoint (which requires the `Snap-Device-Series`
/// header) returns the publisher and per-channel releases. The latest stable
/// channel's release time and version are the supply-chain-relevant facts.
pub(crate) fn snap(name: &str, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    let url = format!(
        "https://api.snapcraft.io/v2/snaps/info/{name}\
         ?fields=title,summary,description,license,publisher,store-url,website,version"
    );
    let doc: Value = serde_json::from_slice(&cached_metadata_with(
        &url,
        &[("Snap-Device-Series", "16")],
        net,
        cache,
    )?)
    .ok()?;
    let s = doc.get("snap")?;
    // Prefer the latest/stable channel; fall back to the first mapping.
    let chan = doc
        .get("channel-map")
        .and_then(Value::as_array)
        .and_then(|cm| {
            cm.iter()
                .find(|c| {
                    c.pointer("/channel/track").and_then(Value::as_str) == Some("latest")
                        && c.pointer("/channel/risk").and_then(Value::as_str) == Some("stable")
                })
                .or_else(|| cm.first())
        });

    Some(Registry {
        ecosystem: "snap".into(),
        name: name.to_string(),
        version: chan
            .and_then(|c| c.get("version"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        published_at: chan
            .and_then(|c| c.pointer("/channel/released-at"))
            .and_then(Value::as_str)
            .and_then(parse_ts),
        author: s
            .pointer("/publisher/display-name")
            .and_then(Value::as_str)
            .map(str::to_string),
        title: s.get("title").and_then(Value::as_str).map(str::to_string),
        description: s
            .get("summary")
            .and_then(Value::as_str)
            .or_else(|| s.get("description").and_then(Value::as_str))
            .map(str::to_string),
        homepage: s
            .get("website")
            .and_then(Value::as_str)
            .filter(|w| !w.is_empty())
            .or_else(|| s.get("store-url").and_then(Value::as_str))
            .map(str::to_string),
        license: s
            .get("license")
            .and_then(Value::as_str)
            .filter(|l| !l.is_empty())
            .map(str::to_string),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::test_cache;

    use crate::fetch::Fixtures;

    #[test]
    fn snap_info_normalizes() {
        let doc = serde_json::json!({
            "snap": {"title": "hello", "summary": "GNU Hello", "license": "GPL-3.0",
                     "publisher": {"display-name": "Canonical"},
                     "store-url": "https://snapcraft.io/hello", "website": null},
            "channel-map": [{
                "channel": {"track": "latest", "risk": "stable", "released-at": "2021-04-23T10:00:00+00:00"},
                "version": "2.10"
            }]
        })
        .to_string();
        let net = Fixtures::default().with(
            "https://api.snapcraft.io/v2/snaps/info/hello?fields=title,summary,description,license,publisher,store-url,website,version",
            doc.as_bytes(),
        );
        let r = snap("hello", &net, &test_cache("snap")).expect("registry");
        assert_eq!(r.ecosystem, "snap");
        assert_eq!(r.version, "2.10");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(r.author.as_deref(), Some("Canonical"));
        assert_eq!(r.homepage.as_deref(), Some("https://snapcraft.io/hello"));
    }
}
