//! The Snap Store: registry metadata.

use filefacts::{Ecosystem, Registry};
use serde::Deserialize;

use crate::ecosystem::{Coordinates, decode, listed, non_empty, null_default, unix_secs};
use crate::fetch::{BlobCache, Fetch, cached_metadata_status};
use crate::registry::RegistryError;

/// Look up the snap `c` names through the v2 info endpoint (which requires
/// the `Snap-Device-Series` header): the publisher, and the release each
/// channel holds. The latest/stable channel's release is the latest, and the
/// one the record describes unless a version is requested; a requested
/// version is dated by any channel that holds it, else left undated.
pub(crate) fn lookup(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let name = c.bare_name(&[])?;
    let url = format!(
        "https://api.snapcraft.io/v2/snaps/info/{name}\
         ?fields=title,summary,description,license,publisher,store-url,website,version"
    );
    let bytes = cached_metadata_status(&url, &[("Snap-Device-Series", "16")], net, cache)?;
    let doc: SnapInfo = decode(&url, &bytes)?;
    let channels = &doc.channel_map;
    let stable = channels
        .iter()
        .find(|e| {
            e.channel.track.as_deref() == Some("latest")
                && e.channel.risk.as_deref() == Some("stable")
        })
        .or_else(|| channels.first());
    let release = match c.version() {
        Some(v) => listed(
            channels.iter().find(|e| e.version.as_deref() == Some(v)),
            c.name(),
            v,
        ),
        None => stable,
    };
    let s = doc.snap;

    let mut record = c.record(
        Ecosystem::Snap,
        c.name(),
        stable.and_then(|e| e.version.clone()),
    );
    record.published_at = release
        .and_then(|e| e.channel.released_at.as_deref())
        .and_then(unix_secs);
    record.author = s.publisher.and_then(|p| p.display_name);
    record.title = s.title;
    record.description = s.summary.or(s.description);
    record.homepage = s.website.or(s.store_url);
    record.license = s.license;
    Ok(record)
}

/// A Snap Store v2 info document: the snap and its channel map.
#[derive(Deserialize)]
struct SnapInfo {
    snap: SnapDetails,
    #[serde(rename = "channel-map", default, deserialize_with = "null_default")]
    channel_map: Vec<ChannelMapEntry>,
}

/// The snap's store listing.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
struct SnapDetails {
    #[serde(deserialize_with = "non_empty")]
    title: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    summary: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    description: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    license: Option<String>,
    publisher: Option<SnapPublisher>,
    #[serde(deserialize_with = "non_empty")]
    store_url: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    website: Option<String>,
}

/// The account a snap is published under.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
struct SnapPublisher {
    #[serde(deserialize_with = "non_empty")]
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
    use crate::ecosystem::look;
    use crate::fetch::Fixtures;

    /// The record for `purl` when the store describes `hello`.
    fn hello(purl: &str) -> Result<Registry, RegistryError> {
        let doc = serde_json::json!({
            "snap": {"title": "hello", "summary": "GNU Hello", "license": "GPL-3.0",
                     "publisher": {"display-name": "Canonical"},
                     "store-url": "https://snapcraft.io/hello", "website": null},
            "channel-map": [
                {"channel": {"track": "latest", "risk": "edge", "released-at": "2021-05-01T10:00:00+00:00"},
                 "version": "2.11"},
                {"channel": {"track": "latest", "risk": "stable", "released-at": "2021-04-23T10:00:00+00:00"},
                 "version": "2.10"}
            ]
        })
        .to_string();
        let net = Fixtures::default().with(
            "https://api.snapcraft.io/v2/snaps/info/hello?fields=title,summary,description,license,publisher,store-url,website,version",
            doc.as_bytes(),
        );
        look(purl, &net)
    }

    #[test]
    fn snap_info_normalizes() {
        let r = hello("pkg:snap/hello").expect("registry");
        assert_eq!(r.ecosystem, Ecosystem::Snap);
        assert_eq!(r.version, "2.10");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(r.author.as_deref(), Some("Canonical"));
        assert_eq!(r.homepage.as_deref(), Some("https://snapcraft.io/hello"));
    }

    #[test]
    fn a_requested_version_is_dated_by_the_channel_holding_it_or_not_at_all() {
        let r = hello("pkg:snap/hello@2.11").expect("registry");
        assert_eq!(r.version, "2.11");
        assert_eq!(r.latest_version.as_deref(), Some("2.10"), "latest/stable");
        assert_eq!(r.published_at, Some(1_619_863_200));
        let r = hello("pkg:snap/hello@1.0").expect("registry");
        assert_eq!(r.version, "1.0");
        assert_eq!(r.published_at, None);
    }
}
