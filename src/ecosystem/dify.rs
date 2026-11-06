//! The Dify Marketplace: registry metadata and artifact resolution.

use filefacts::{Ecosystem, Registry};
use serde::Deserialize;

use crate::ecosystem::{
    Coordinates, Localized, fetch_json, held, immutable_or_fresh, non_empty, release_time,
    unix_secs,
};
use crate::fetch::{BlobCache, Fetch};
use crate::purl::encode_component;
use crate::registry::RegistryError;

/// The marketplace's plugin API root: `/<org>/<name>` is a plugin's
/// document, `/<org>/<name>/<version>` one release's.
const PLUGINS: &str = "https://marketplace.dify.ai/api/v1/plugins";

/// The status the marketplace gives a plugin in good standing.
const ACTIVE: &str = "active";

/// Resolve a Dify Marketplace plugin (`<org>/<name>`) to `(version, .difypkg
/// URL)`. The download endpoint is keyed by the release's unique identifier,
/// `<org>/<name>:<version>@<checksum>`, whose checksum is Dify's own (not the
/// package's sha256), so it is read from the per-version document — or, for an
/// unpinned plugin, from the plugin document's current release. The
/// identifier must name the plugin and release asked for, with a hex
/// checksum, so a surprising response cannot point the download at another
/// plugin's (or another release's) package.
pub(crate) fn resolve_dify(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<(String, String), RegistryError> {
    let (org, name) = c.pair()?;
    let version = c.encoded_version();
    let base = format!("{PLUGINS}/{org}/{name}");
    let (plugin_id, wanted) = (c.full_name(), c.version());
    let vetted = |resolved: Option<String>, identifier: Option<String>, url: &str| {
        let (Some(resolved), Some(identifier)) = (resolved, identifier) else {
            tracing::debug!(url, "dify artifact unresolved: no release or identifier");
            return Err(RegistryError::NoRecord);
        };
        let checksum = identifier.strip_prefix(&format!("{plugin_id}:{resolved}@"));
        if wanted.is_some_and(|want| want != resolved)
            || !checksum.is_some_and(|c| !c.is_empty() && c.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            tracing::debug!(
                url,
                identifier = %identifier.escape_debug(),
                "dify artifact refused: the answer is not the plugin and release asked for"
            );
            return Err(RegistryError::NoRecord);
        }
        Ok((resolved, identifier))
    };
    let (resolved, identifier) = match version {
        Some(v) => immutable_or_fresh(cache, |cache| {
            let url = format!("{base}/{v}");
            let release = fetch_json::<VersionDocument>(&url, net, cache)
                .inspect_err(|error| tracing::debug!(url, %error, "dify release unreadable"))?
                .data
                .version;
            vetted(release.version, release.unique_identifier, &url)
        })?,
        None => {
            let cache = cache.with_meta_ttl(cache.meta_ttl_unpinned());
            let plugin = fetch_json::<PluginDocument>(&base, net, &cache)
                .inspect_err(|error| tracing::debug!(url = base, %error, "dify plugin unreadable"))?
                .data
                .plugin;
            vetted(
                plugin.latest_version,
                plugin.latest_package_identifier,
                &base,
            )?
        }
    };
    Ok((
        resolved,
        format!(
            "{PLUGINS}/download?unique_identifier={}",
            encode_component(&identifier)
        ),
    ))
}

/// Dify Marketplace: the plugin document is the listing (installs, publisher
/// org, repository, verification, standing) plus its latest release, so a
/// pinned older version gets no publish time. A plugin the marketplace no
/// longer lists as active is a security hold; a deprecation notice is its
/// `deprecated_reason`.
pub(crate) fn lookup(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let (org, name) = c.pair()?;
    let doc: PluginDocument = fetch_json(&format!("{PLUGINS}/{org}/{name}"), net, cache)?;
    let plugin = doc.data.plugin;
    let mut record = c.record(
        Ecosystem::Dify,
        plugin.plugin_id.unwrap_or_else(|| c.full_name()),
        plugin.latest_version,
    );
    record.published_at = release_time(
        &record,
        record.latest_version.as_deref(),
        plugin.version_updated_at.as_deref().and_then(unix_secs),
    );
    record.first_published_at = plugin.created_at.as_deref().and_then(unix_secs);
    // Localized as `{ "en_US": … }`, underscore where AMO has a hyphen.
    record.title = plugin
        .label
        .and_then(|l| l.translation("en_US").or_else(|| l.text()));
    record.description = plugin
        .brief
        .and_then(|b| b.translation("en_US").or_else(|| b.text()));
    record.repository = plugin.repository;
    record.publisher = c.namespace().first().cloned();
    record.downloads_total = plugin.install_count;
    // Dify's own and its partners' plugins are vetted; `community` is
    // anyone's.
    record.publisher_verified = plugin
        .verification
        .and_then(|v| v.authorized_category)
        .map(|c| matches!(c.as_str(), "langgenius" | "partner"));
    record.deprecated = plugin.deprecated_reason;
    record.security_hold = held(plugin.status.as_deref(), ACTIVE, &c.full_name());
    Ok(record)
}

/// A Dify Marketplace plugin document: the listing under `data.plugin`.
#[derive(Deserialize)]
struct PluginDocument {
    data: PluginData,
}

/// The `data` envelope of a plugin document.
#[derive(Deserialize)]
struct PluginData {
    plugin: Plugin,
}

/// A Dify plugin listing with its latest release.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Plugin {
    #[serde(deserialize_with = "non_empty")]
    plugin_id: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    latest_version: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    latest_package_identifier: Option<String>,
    version_updated_at: Option<String>,
    created_at: Option<String>,
    label: Option<Localized>,
    brief: Option<Localized>,
    #[serde(deserialize_with = "non_empty")]
    repository: Option<String>,
    install_count: Option<u64>,
    verification: Option<Verification>,
    #[serde(deserialize_with = "non_empty")]
    deprecated_reason: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    status: Option<String>,
}

/// Dify's vetting of a plugin.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Verification {
    authorized_category: Option<String>,
}

/// A Dify Marketplace per-version document: the release under `data.version`.
#[derive(Deserialize)]
struct VersionDocument {
    data: VersionData,
}

/// The `data` envelope of a per-version document.
#[derive(Deserialize)]
struct VersionData {
    version: Release,
}

/// One release of a plugin and the identifier its package downloads by.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Release {
    #[serde(deserialize_with = "non_empty")]
    version: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    unique_identifier: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::{coordinates, look};

    use crate::fetch::Fixtures;

    const EVAL_LOOP: &str = "https://marketplace.dify.ai/api/v1/plugins/fr3on/eval-loop";

    fn eval_loop(status: &str, deprecated_reason: &str) -> Fixtures {
        let doc = serde_json::json!({"code": 0, "data": {"plugin": {
            "plugin_id": "fr3on/eval-loop", "org": "fr3on", "name": "eval-loop",
            "label": {"en_US": "Eval Loop"}, "brief": {"en_US": "Evaluates Q&A."},
            "repository": "https://github.com/fr3on/eval-loop",
            "install_count": 9u64, "status": status, "deprecated_reason": deprecated_reason,
            "verification": {"authorized_category": "community"},
            "created_at": "2026-09-26T01:46:12.196377Z",
            "version_updated_at": "2026-09-26T01:46:15.993933Z",
            "latest_version": "0.1.1",
            "latest_package_identifier": "fr3on/eval-loop:0.1.1@0a1b2c"
        }}})
        .to_string();
        Fixtures::default().with(EVAL_LOOP, doc.as_bytes())
    }

    #[test]
    fn dify_plugin_normalizes() {
        let net = eval_loop(ACTIVE, "");
        let r = look("pkg:dify/fr3on/eval-loop", &net).expect("registry");
        assert_eq!(r.ecosystem, Ecosystem::Dify);
        assert_eq!(r.name, "fr3on/eval-loop");
        assert_eq!(r.version, "0.1.1");
        assert_eq!(r.published_at, Some(1_790_387_175)); // 2026-09-26T01:46:15Z
        assert_eq!(r.first_published_at, Some(1_790_387_172));
        assert_eq!(r.title.as_deref(), Some("Eval Loop"));
        assert_eq!(r.description.as_deref(), Some("Evaluates Q&A."));
        assert_eq!(r.publisher.as_deref(), Some("fr3on"));
        assert_eq!(r.publisher_verified, Some(false));
        assert_eq!(r.downloads_total, Some(9));
        assert_eq!(r.deprecated, None);
        assert_eq!(r.security_hold, Some(false));
        for purl in ["pkg:dify/eval-loop", "pkg:dify/fr3on/eval-loop/x"] {
            assert_eq!(look(purl, &net), Err(RegistryError::UnsafeCoordinate));
            // The resolver holds the coordinate to the same shape.
            assert_eq!(
                resolve_dify(&coordinates(purl), &net, &BlobCache::disabled()),
                Err(RegistryError::UnsafeCoordinate),
                "{purl}"
            );
        }
    }

    #[test]
    fn an_inactive_plugin_is_a_security_hold_not_a_deprecation() {
        let r = look("pkg:dify/fr3on/eval-loop", &eval_loop("banned", "")).expect("registry");
        assert_eq!(r.security_hold, Some(true));
        assert_eq!(r.deprecated, None);
        // A real deprecation notice is carried as such.
        let r = look(
            "pkg:dify/fr3on/eval-loop",
            &eval_loop(ACTIVE, "Use fr3on/eval-loop-2."),
        )
        .expect("registry");
        assert_eq!(r.deprecated.as_deref(), Some("Use fr3on/eval-loop-2."));
        assert_eq!(r.security_hold, Some(false));
    }

    #[test]
    fn the_artifact_is_the_release_the_typed_documents_name() {
        let cache = BlobCache::disabled();
        let download = "https://marketplace.dify.ai/api/v1/plugins/download?unique_identifier=fr3on%2Feval-loop:0.1.1%400a1b2c";
        assert_eq!(
            resolve_dify(
                &coordinates("pkg:dify/fr3on/eval-loop"),
                &eval_loop(ACTIVE, ""),
                &cache
            )
            .ok(),
            Some(("0.1.1".to_string(), download.to_string()))
        );
        let release = |identifier: &str| {
            let doc = serde_json::json!({"data": {"version": {
                "version": "0.1.0", "unique_identifier": identifier
            }}})
            .to_string();
            Fixtures::default().with(&format!("{EVAL_LOOP}/0.1.0"), doc.as_bytes())
        };
        assert!(
            resolve_dify(
                &coordinates("pkg:dify/fr3on/eval-loop@0.1.0"),
                &release("fr3on/eval-loop:0.1.0@ff"),
                &cache
            )
            .ok()
            .is_some()
        );
        for identifier in [
            "evil/plugin:0.1.0@ff",
            "fr3on/eval-loop:0.1.1@ff",
            "fr3on/eval-loop:0.1.0@",
            "fr3on/eval-loop:0.1.0@xyz",
        ] {
            assert_eq!(
                resolve_dify(
                    &coordinates("pkg:dify/fr3on/eval-loop@0.1.0"),
                    &release(identifier),
                    &cache
                )
                .ok(),
                None,
                "{identifier}"
            );
        }
    }
}
