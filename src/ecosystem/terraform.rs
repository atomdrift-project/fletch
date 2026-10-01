//! The Terraform Registry: registry metadata and artifact resolution.

use filefacts::Registry;
use serde::Deserialize;
use std::time::Duration;

use crate::ecosystem::{fetch_json, null_default, parse_ts};
use crate::fetch::{
    ArtifactCandidate, BlobCache, Fetch, FetchError, META_TTL_IMMUTABLE, artifact_candidate,
    cached_metadata, cached_metadata_status, file_name_matches, is_web_scheme, percent_decode,
    safe_coordinate,
};
use crate::purl::Purl;
use crate::registry::RegistryError;

/// A Terraform provider zip, from the registry's download API. That API
/// answers one platform per request, so this builds one candidate rather than
/// the whole matrix: the `linux_amd64` build a CI runner installs, or, for a
/// provider that doesn't ship one (the API's 404), the first platform the
/// version lists. The registry's `shasum` becomes the candidate's sha256 —
/// through the artifact PURL's `checksum` the fetch record verifies it against
/// the downloaded bytes — and a response without a well-formed one is refused
/// rather than fetched unverified. A versionless PURL takes the provider's
/// current `version`.
pub(crate) fn terraform_artifact(
    path: &str,
    version: Option<&str>,
    purl: &Purl,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Option<ArtifactCandidate> {
    let (namespace, name) = path.split_once('/')?;
    if name.contains('/') {
        return None;
    }
    let base = format!("https://registry.terraform.io/v1/providers/{namespace}/{name}");
    // Each of these fills one URL path segment, and may come from the registry.
    let segment = |value: &str| safe_coordinate(value) && !value.contains('/');
    let json = |url: &str, ttl: Duration| {
        cached_metadata(url, net, &cache.with_meta_ttl(ttl))
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
    };
    let version = match version {
        Some(version) => percent_decode(version),
        None => json(&base, cache.meta_ttl_unpinned())?
            .get("version")?
            .as_str()?
            .to_string(),
    };
    if !segment(&version) {
        return None;
    }
    // A published release's per-platform download never changes.
    let immutable = cache.with_meta_ttl(META_TTL_IMMUTABLE);
    let download = |os: &str, arch: &str| {
        cached_metadata_status(
            &format!("{base}/{version}/download/{os}/{arch}"),
            &[],
            net,
            &immutable,
        )
    };
    let info = match download("linux", "amd64") {
        Ok(bytes) => bytes,
        Err(FetchError::Status(404)) => {
            // The version list grows, so it is read with the unpinned TTL.
            let versions = json(&format!("{base}/versions"), cache.meta_ttl_unpinned())?;
            let platform = versions
                .get("versions")?
                .as_array()?
                .iter()
                .find(|v| v.get("version").and_then(serde_json::Value::as_str) == Some(&version))?
                .pointer("/platforms/0")?;
            let os = platform.get("os")?.as_str()?;
            let arch = platform.get("arch")?.as_str()?;
            if !segment(os) || !segment(arch) {
                return None;
            }
            download(os, arch).ok()?
        }
        Err(_) => return None,
    };
    let info: serde_json::Value = serde_json::from_slice(&info).ok()?;
    let url = info.get("download_url")?.as_str()?.to_string();
    let shasum = info
        .get("shasum")?
        .as_str()
        .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))?
        .to_ascii_lowercase();
    if !is_web_scheme(&url) {
        return None;
    }
    let mut candidate = artifact_candidate(url, "provider");
    candidate.preferred = file_name_matches(purl, &candidate.file_name);
    candidate
        .qualifiers
        .insert("file_name".into(), candidate.file_name.clone());
    candidate.checksums.insert("sha256".into(), shasum);
    for key in ["os", "arch"] {
        if let Some(value) = info.get(key).and_then(serde_json::Value::as_str) {
            candidate.attributes.insert(key.into(), value.to_string());
        }
    }
    candidate.attributes.insert("version".into(), version);
    Some(candidate)
}

/// Terraform Registry: the v2 provider document with its provider-versions
/// included is the whole record in one request — tier, source repository,
/// total downloads, the deprecation `warning`, and every version's publish
/// time. v2 marks no latest version, so the most recently published one stands
/// in for it. `path` is the `<namespace>/<type>` provider address.
pub(crate) fn terraform(
    path: &str,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let Some((namespace, name)) = path.split_once('/') else {
        return Err(RegistryError::NoRecord);
    };
    if name.contains('/') {
        return Err(RegistryError::NoRecord);
    }
    let doc: ProviderDocument = fetch_json(
        &format!(
            "https://registry.terraform.io/v2/providers/{namespace}/{name}?include=provider-versions"
        ),
        net,
        cache,
    )?;
    let attrs = &doc.data.attributes;
    let text = |v: Option<&String>| v.filter(|s| !s.is_empty()).cloned();
    // `(version, publish time, attributes)` for every included release.
    let releases: Vec<(&str, Option<u64>, &VersionAttributes)> = doc
        .included
        .iter()
        .filter(|i| i.kind.as_deref() == Some("provider-versions"))
        .filter_map(|i| {
            let a = i.attributes.as_ref()?;
            let published = a.published_at.as_deref().and_then(parse_ts);
            Some((a.version.as_deref()?, published, a))
        })
        .collect();
    let latest = releases
        .iter()
        .filter_map(|&(v, t, _)| Some((t?, v)))
        .max()
        .map(|(_, v)| v);
    // A PURL percent-encodes what the registry spells literally (`1.0.0%2Bbuild`).
    let requested = version.map(percent_decode);
    let version = requested.as_deref().or(latest).unwrap_or_default();
    let release = releases.iter().find(|(v, _, _)| *v == version);

    let mut p = Registry {
        ecosystem: "terraform".into(),
        name: format!("{namespace}/{name}"),
        version: version.to_string(),
        published_at: release.and_then(|r| r.1),
        latest_version: latest.map(str::to_string),
        author: text(attrs.owner_name.as_ref()),
        publisher: Some(namespace.to_string()),
        // The provider-level description is often empty where the release's
        // is not.
        description: text(release.and_then(|r| r.2.description.as_ref()))
            .or_else(|| text(attrs.description.as_ref())),
        repository: text(attrs.source.as_ref()),
        downloads_total: attrs.downloads,
        // `official` and `partner` providers are vetted by HashiCorp; a
        // `community` namespace is anyone's GitHub account.
        publisher_verified: attrs
            .tier
            .as_deref()
            .map(|t| matches!(t, "official" | "partner")),
        deprecated: text(attrs.warning.as_ref()),
        ..Default::default()
    };
    let mut times: Vec<u64> = releases.iter().filter_map(|r| r.1).collect();
    if !times.is_empty() {
        times.sort_unstable();
        p.release_count = Some(times.len() as u32);
        p.first_published_at = times.first().copied();
        if let Some(this) = p.published_at {
            p.previous_published_at = times.iter().copied().filter(|&t| t < this).max();
        }
        p.release_times = times;
    }
    Ok(p)
}

/// The v2 provider document, with its provider-versions included.
#[derive(Deserialize)]
struct ProviderDocument {
    data: Provider,
    #[serde(default, deserialize_with = "null_default")]
    included: Vec<Included>,
}

/// The provider resource itself.
#[derive(Deserialize)]
struct Provider {
    attributes: ProviderAttributes,
}

/// The provider's own attributes.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
struct ProviderAttributes {
    owner_name: Option<String>,
    description: Option<String>,
    source: Option<String>,
    downloads: Option<u64>,
    tier: Option<String>,
    warning: Option<String>,
}

/// An included resource; the record reads the `provider-versions` ones.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Included {
    #[serde(rename = "type")]
    kind: Option<String>,
    attributes: Option<VersionAttributes>,
}

/// One provider version's attributes.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
struct VersionAttributes {
    version: Option<String>,
    published_at: Option<String>,
    description: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::test_cache;
    use crate::registry;
    use filefacts::RefLocator;

    use crate::fetch::Fixtures;

    /// A PURL percent-encodes the `+` the registry spells literally.
    #[test]
    fn terraform_decodes_the_requested_version() {
        let doc = serde_json::json!({
            "data": {"type": "providers", "attributes": {}},
            "included": [{"type": "provider-versions", "attributes":
                {"version": "1.0.0+ent", "published-at": "2021-04-23T10:00:00Z"}}]
        })
        .to_string();
        let net = Fixtures::default().with(
            "https://registry.terraform.io/v2/providers/acme/vault?include=provider-versions",
            doc.as_bytes(),
        );
        let r = terraform(
            "acme/vault",
            Some("1.0.0%2Bent"),
            &net,
            &test_cache("tf-meta"),
        )
        .expect("registry");
        assert_eq!(r.version, "1.0.0+ent");
        assert_eq!(r.published_at, Some(1_619_172_000));
    }

    #[test]
    fn terraform_provider_normalizes() {
        let version = |id: &str, v: &str, at: &str, description: &str| {
            serde_json::json!({
                "type": "provider-versions", "id": id,
                "attributes": {"version": v, "published-at": at, "tag": format!("v{v}"),
                    "downloads": 10, "description": description}
            })
        };
        let doc = serde_json::json!({
            "data": {"type": "providers", "id": "2322743", "attributes": {
                "description": "", "downloads": 1463, "full-name": "kreuzwenker/docker",
                "name": "docker", "namespace": "kreuzwenker", "owner-name": "",
                "source": "https://github.com/kreuzwenker/terraform-provider-docker",
                "tier": "community", "unlisted": false, "warning": "Typosquat of kreuzwerker/docker"
            }},
            // Deliberately out of order: the registry doesn't sort them.
            "included": [
                version("110184", "4.7.0", "2026-09-23T05:17:28Z", ""),
                version("107813", "4.5.0", "2026-09-04T07:07:03Z", ""),
                version("110116", "4.6.0", "2026-09-22T14:50:27Z", "Terraform Docker provider"),
            ]
        })
        .to_string();
        let net = Fixtures::default().with(
            "https://registry.terraform.io/v2/providers/kreuzwenker/docker?include=provider-versions",
            doc.as_bytes(),
        );
        // The mixed-case address routes to the one lowercase provider.
        let locator = RefLocator::Purl("pkg:terraform/Kreuzwenker/Docker@4.6.0".into());
        let r = registry(&locator, &net, &test_cache("terraform")).expect("registry");
        assert_eq!(r.ecosystem, "terraform");
        assert_eq!(r.name, "kreuzwenker/docker");
        assert_eq!(r.version, "4.6.0");
        assert_eq!(r.published_at, Some(1_790_088_627)); // 2026-09-22T14:50:27Z
        assert_eq!(r.latest_version.as_deref(), Some("4.7.0"));
        assert_eq!(r.publisher.as_deref(), Some("kreuzwenker"));
        assert_eq!(r.author, None); // an empty owner-name is unknown
        assert_eq!(r.description.as_deref(), Some("Terraform Docker provider"));
        assert_eq!(
            r.repository.as_deref(),
            Some("https://github.com/kreuzwenker/terraform-provider-docker")
        );
        assert_eq!(r.downloads_total, Some(1463));
        assert_eq!(r.publisher_verified, Some(false));
        assert_eq!(
            r.deprecated.as_deref(),
            Some("Typosquat of kreuzwerker/docker")
        );
        assert_eq!(r.release_count, Some(3));
        assert_eq!(r.first_published_at, Some(1_788_505_623)); // 2026-09-04T07:07:03Z
        assert_eq!(r.previous_published_at, r.first_published_at);

        // Versionless: the most recently published release is current.
        let r = terraform("kreuzwenker/docker", None, &net, &test_cache("terraform"))
            .expect("registry");
        assert_eq!(r.version, "4.7.0");
        assert_eq!(r.description, None);
        assert!(terraform("docker", None, &net, &test_cache("terraform")).is_err());
    }
}
