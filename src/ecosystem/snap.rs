//! The Snap Store: registry metadata and artifact resolution.

use filefacts::Registry;
use serde::Deserialize;

use crate::ecosystem::{decode, null_default, parse_ts};
use crate::fetch::{BlobCache, Fetch, cached_metadata_status};
use crate::registry::RegistryError;

/// Snap Store: the v2 info endpoint (which requires the `Snap-Device-Series`
/// header) returns the publisher and per-channel releases. The latest stable
/// channel's release time and version are the supply-chain-relevant facts.
pub(crate) fn snap(
    name: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let url = format!(
        "https://api.snapcraft.io/v2/snaps/info/{name}\
         ?fields=title,summary,description,license,publisher,store-url,website,version"
    );
    let bytes = cached_metadata_status(&url, &[("Snap-Device-Series", "16")], net, cache)?;
    let doc: SnapInfo = decode(&url, &bytes)?;
    let s = doc.snap;
    // Prefer the latest/stable channel; fall back to the first mapping.
    let chan = doc
        .channel_map
        .iter()
        .find(|c| {
            c.channel.track.as_deref() == Some("latest")
                && c.channel.risk.as_deref() == Some("stable")
        })
        .or_else(|| doc.channel_map.first());

    Ok(Registry {
        ecosystem: "snap".into(),
        name: name.to_string(),
        version: chan.and_then(|c| c.version.clone()).unwrap_or_default(),
        published_at: chan
            .and_then(|c| c.channel.released_at.as_deref())
            .and_then(parse_ts),
        author: s.publisher.and_then(|p| p.display_name),
        title: s.title,
        description: s.summary.or(s.description),
        homepage: s.website.filter(|w| !w.is_empty()).or(s.store_url),
        license: s.license.filter(|l| !l.is_empty()),
        ..Default::default()
    })
}

/// A Snap Store v2 info document: the snap and its channel map.
#[derive(Deserialize)]
struct SnapInfo {
    snap: SnapDetails,
    #[serde(rename = "channel-map", default)]
    #[serde(deserialize_with = "null_default")]
    channel_map: Vec<ChannelMapEntry>,
}

/// The snap's store listing.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
struct SnapDetails {
    title: Option<String>,
    summary: Option<String>,
    description: Option<String>,
    license: Option<String>,
    publisher: Option<SnapPublisher>,
    store_url: Option<String>,
    website: Option<String>,
}

/// The account a snap is published under.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
struct SnapPublisher {
    display_name: Option<String>,
}

/// One release in the channel map: a channel and the version it holds.
#[derive(Default, Deserialize)]
#[serde(default)]
struct ChannelMapEntry {
    #[serde(deserialize_with = "null_default")]
    channel: SnapChannel,
    version: Option<String>,
}

/// A channel's track, risk level, and release time.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
struct SnapChannel {
    track: Option<String>,
    risk: Option<String>,
    released_at: Option<String>,
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
