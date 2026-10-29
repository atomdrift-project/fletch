//! The Terraform Registry: registry metadata and artifact resolution.

use filefacts::Registry;
use serde::Deserialize;

use crate::ecosystem::{
    Coordinates, fetch_json, non_empty, null_default, set_timeline, split_pair, unix_secs,
};
use crate::fetch::{
    ArtifactCandidate, ArtifactKind, BlobCache, Fetch, META_TTL_IMMUTABLE, artifact_candidate,
    file_name_matches, is_web_scheme, safe_coordinate,
};
use crate::purl::encode_component;
use crate::registry::RegistryError;

/// The registry's provider API root.
const PROVIDERS: &str = "https://registry.terraform.io";

/// A Terraform provider zip, from the registry's download API. That API
/// answers one platform per request, so this builds one candidate rather than
/// the whole matrix: the `linux_amd64` build a CI runner installs, or, for a
/// provider that doesn't ship one (the API's 404), the first platform the
/// version lists. The registry's `shasum` becomes the candidate's sha256 —
/// through the artifact PURL's `checksum` the fetch record verifies it against
/// the downloaded bytes — and a response without a well-formed one is refused
/// rather than fetched unverified. A versionless PURL takes the
/// [`latest`] version the registry lists, as the registry record does.
/// `path` and `version` are
/// `purl`'s percent-encoded coordinates.
pub(crate) fn terraform_artifact(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Option<ArtifactCandidate> {
    let (path, version, purl) = (c.path(), c.encoded_version(), c.purl());
    let (namespace, name) = split_pair(path).ok()?;
    // A value from the registry fills one URL path segment only once encoded
    // and checked, like the PURL's own coordinates.
    let segment = |value: &str| {
        let encoded = encode_component(value);
        let safe = safe_coordinate(&encoded);
        if !safe {
            tracing::debug!(value = %value.escape_debug(), "Terraform segment refused");
        }
        safe.then_some(encoded)
    };
    // The version list grows, so it is read with the unpinned TTL.
    let versions = || {
        let url = format!("{PROVIDERS}/v1/providers/{namespace}/{name}/versions");
        fetch_json::<VersionList>(&url, net, &cache.with_meta_ttl(cache.meta_ttl_unpinned()))
            .inspect_err(|error| tracing::debug!(url, %error, "Terraform version list unavailable"))
            .ok()
    };
    let (version, encoded_version) = match (purl.version(), version) {
        (Some(decoded), Some(encoded)) => (decoded.to_string(), encoded.to_string()),
        _ => {
            let list = versions()?;
            let current = latest(list.versions.iter().filter_map(|v| v.version.as_deref()))?;
            (current.to_string(), segment(current)?)
        }
    };
    let base = format!("{PROVIDERS}/v1/providers/{namespace}/{name}/{encoded_version}");
    // A published release's per-platform download never changes.
    let immutable = cache.with_meta_ttl(META_TTL_IMMUTABLE);
    let download = |os: &str, arch: &str| {
        fetch_json::<Download>(&format!("{base}/download/{os}/{arch}"), net, &immutable)
    };
    let info = match download("linux", "amd64") {
        Ok(info) => info,
        Err(RegistryError::NotFound) => {
            let list = versions()?;
            let platform = list
                .versions
                .iter()
                .find(|v| v.version.as_deref() == Some(version.as_str()))?
                .platforms
                .first()?;
            let (os, arch) = (
                segment(platform.os.as_deref()?)?,
                segment(platform.arch.as_deref()?)?,
            );
            tracing::debug!(os, arch, "Terraform provider has no linux_amd64 build");
            download(&os, &arch)
                .inspect_err(|error| tracing::debug!(%error, "Terraform download unavailable"))
                .ok()?
        }
        Err(error) => {
            tracing::debug!(%error, "Terraform download unavailable");
            return None;
        }
    };
    let (Some(url), Some(shasum)) = (info.download_url, info.shasum) else {
        tracing::debug!("Terraform download names no URL or checksum");
        return None;
    };
    if shasum.len() != 64 || !shasum.bytes().all(|b| b.is_ascii_hexdigit()) || !is_web_scheme(&url)
    {
        tracing::debug!(
            url = %url.escape_debug(),
            "Terraform download refused: no sha256 to verify it, or not a web URL"
        );
        return None;
    }
    let mut candidate = artifact_candidate(url, ArtifactKind::Provider);
    candidate.preferred = file_name_matches(purl, &candidate.file_name);
    candidate
        .qualifiers
        .insert("file_name".into(), candidate.file_name.clone());
    candidate
        .checksums
        .insert("sha256".into(), shasum.to_ascii_lowercase());
    for (key, value) in [("os", info.os), ("arch", info.arch)] {
        if let Some(value) = value {
            candidate.attributes.insert(key.into(), value);
        }
    }
    candidate.version = Some(version);
    Some(candidate)
}

/// The Terraform Registry's v2 provider document is the whole record in one
/// request — tier, source repository, total downloads, the deprecation
/// `warning`, and every version's publish time. A provider is always
/// `namespace/type`.
pub(crate) fn lookup(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let (namespace, name) = c.pair()?;
    let doc: ProviderDocument = fetch_json(
        &format!("{PROVIDERS}/v2/providers/{namespace}/{name}?include=provider-versions"),
        net,
        cache,
    )?;
    let attrs = &doc.data.attributes;
    let releases = doc.releases();
    let latest = latest(releases.iter().filter_map(|r| r.version.as_deref()));
    let version = c.target(latest);
    let release = releases
        .iter()
        .find(|r| r.version.as_deref() == Some(version));
    if release.is_none() {
        tracing::debug!(
            provider = %c.full_name().escape_debug(),
            version = %version.escape_debug(),
            "Terraform provider version not listed; leaving it undated"
        );
    }

    let mut record = Registry {
        ecosystem: "terraform".into(),
        name: c.full_name(),
        version: version.to_string(),
        published_at: release
            .and_then(|r| r.published_at.as_deref())
            .and_then(unix_secs),
        latest_version: latest.map(str::to_string),
        author: attrs.owner_name.clone(),
        publisher: c.namespace().first().cloned(),
        // The provider-level description is often empty where the release's
        // is not.
        description: release
            .and_then(|r| r.description.clone())
            .or_else(|| attrs.description.clone()),
        repository: attrs.source.clone(),
        downloads_total: attrs.downloads,
        // `official` and `partner` providers are vetted by HashiCorp; a
        // `community` namespace is anyone's GitHub account.
        publisher_verified: attrs
            .tier
            .as_deref()
            .map(|t| matches!(t, "official" | "partner")),
        deprecated: attrs.warning.clone(),
        ..Default::default()
    };
    set_timeline(
        &mut record,
        releases
            .iter()
            .filter_map(|r| r.published_at.as_deref().and_then(unix_secs)),
    );
    Ok(record)
}

/// The latest release: the highest SemVer version, a stable one when there is
/// any. The registry lists versions in no order and marks none latest, and a
/// patch to an older line can be published after a newer line's release.
/// Versions that are not SemVer never count.
fn latest<'a>(versions: impl IntoIterator<Item = &'a str>) -> Option<&'a str> {
    versions
        .into_iter()
        .filter_map(|v| {
            let parsed = semver::Version::parse(v).ok()?;
            Some(((parsed.pre.is_empty(), parsed), v))
        })
        .max_by(|(a, _), (b, _)| a.cmp(b))
        .map(|(_, v)| v)
}

/// The v2 provider document, with its provider-versions included.
#[derive(Deserialize)]
struct ProviderDocument {
    data: Provider,
    #[serde(default, deserialize_with = "null_default")]
    included: Vec<Included>,
}

impl ProviderDocument {
    /// Every included provider-version's attributes.
    fn releases(&self) -> Vec<&VersionAttributes> {
        self.included
            .iter()
            .filter(|i| i.kind.as_deref() == Some("provider-versions"))
            .filter_map(|i| i.attributes.as_ref())
            .collect()
    }
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
    #[serde(deserialize_with = "non_empty")]
    owner_name: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    description: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    source: Option<String>,
    downloads: Option<u64>,
    tier: Option<String>,
    #[serde(deserialize_with = "non_empty")]
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
    #[serde(deserialize_with = "non_empty")]
    description: Option<String>,
}

/// The v1 version list (`/v1/providers/{namespace}/{type}/versions`): every
/// version, and the platforms each ships for.
#[derive(Default, Deserialize)]
#[serde(default)]
struct VersionList {
    #[serde(deserialize_with = "null_default")]
    versions: Vec<PlatformVersion>,
}

/// One version in the v1 list.
#[derive(Default, Deserialize)]
#[serde(default)]
struct PlatformVersion {
    version: Option<String>,
    #[serde(deserialize_with = "null_default")]
    platforms: Vec<Platform>,
}

/// One platform a version ships for.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Platform {
    os: Option<String>,
    arch: Option<String>,
}

/// The v1 download document for one version and platform.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Download {
    download_url: Option<String>,
    shasum: Option<String>,
    os: Option<String>,
    arch: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::coordinates;
    use crate::fetch::Fixtures;
    use filefacts::RefLocator;

    fn look(net: &Fixtures, purl: &str) -> Result<Registry, RegistryError> {
        crate::registry::lookup(&RefLocator::Purl(purl.into()), net, &BlobCache::disabled())
    }

    fn release(v: &str, at: &str, description: &str) -> serde_json::Value {
        serde_json::json!({
            "type": "provider-versions", "id": v,
            "attributes": {"version": v, "published-at": at, "tag": format!("v{v}"),
                "downloads": 10, "description": description}
        })
    }

    fn provider(net: Fixtures, path: &str, included: &[serde_json::Value]) -> Fixtures {
        let doc = serde_json::json!({
            "data": {"type": "providers", "attributes": {
                "description": "", "downloads": 1463, "owner-name": "",
                "source": "https://github.com/kreuzwenker/terraform-provider-docker",
                "tier": "community", "warning": "Typosquat of kreuzwerker/docker"
            }},
            "included": included
        })
        .to_string();
        net.with(
            &format!("https://registry.terraform.io/v2/providers/{path}?include=provider-versions"),
            doc.as_bytes(),
        )
    }

    /// A PURL percent-encodes the `+` the registry spells literally.
    #[test]
    fn terraform_decodes_the_requested_version() {
        let net = provider(
            Fixtures::default(),
            "acme/vault",
            &[release("1.0.0+ent", "2021-04-23T10:00:00Z", "")],
        );
        let r = look(&net, "pkg:terraform/acme/vault@1.0.0%2Bent").expect("registry");
        assert_eq!(r.version, "1.0.0+ent");
        assert_eq!(r.published_at, Some(1_619_172_000));
    }

    #[test]
    fn terraform_provider_normalizes() {
        // Deliberately out of order: the registry doesn't sort them.
        let net = provider(
            Fixtures::default(),
            "kreuzwenker/docker",
            &[
                release("4.7.0", "2026-09-23T05:17:28Z", ""),
                release("4.5.0", "2026-09-04T07:07:03Z", ""),
                release("4.6.0", "2026-09-22T14:50:27Z", "Terraform Docker provider"),
            ],
        );
        // The mixed-case address routes to the one lowercase provider.
        let r = look(&net, "pkg:terraform/Kreuzwenker/Docker@4.6.0").expect("registry");
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

        // Versionless: the latest release is current.
        let r = look(&net, "pkg:terraform/kreuzwenker/docker").expect("registry");
        assert_eq!(r.version, "4.7.0");
        assert_eq!(r.description, None);
        assert_eq!(
            look(&net, "pkg:terraform/a/kreuzwenker/docker"),
            Err(RegistryError::UnsafeCoordinate)
        );
    }

    #[test]
    fn the_latest_is_the_highest_version_not_the_newest_upload() {
        // A patch to the 4.x line ships after 5.0.0; a 6.0 pre-release and a
        // non-SemVer tag never outrank the stable 5.0.0.
        let net = provider(
            Fixtures::default(),
            "acme/cloud",
            &[
                release("5.0.0", "2026-01-01T00:00:00Z", ""),
                release("4.9.1", "2026-02-01T00:00:00Z", ""),
                release("6.0.0-beta1", "2026-03-01T00:00:00Z", ""),
                release("nightly", "2026-04-01T00:00:00Z", ""),
            ],
        );
        let r = look(&net, "pkg:terraform/acme/cloud").expect("registry");
        assert_eq!(r.latest_version.as_deref(), Some("5.0.0"));
        assert_eq!(r.version, "5.0.0");

        // With only pre-releases, the highest of them is the latest.
        let net = provider(
            Fixtures::default(),
            "acme/beta",
            &[
                release("1.0.0-rc.2", "2026-01-01T00:00:00Z", ""),
                release("1.0.0-rc.10", "2025-01-01T00:00:00Z", ""),
            ],
        );
        let r = look(&net, "pkg:terraform/acme/beta").expect("registry");
        assert_eq!(r.latest_version.as_deref(), Some("1.0.0-rc.10"));
    }

    fn download(os: &str, arch: &str, shasum: &str) -> Vec<u8> {
        serde_json::json!({
            "os": os, "arch": arch, "shasum": shasum,
            "download_url": format!("https://releases.example.test/p_{os}_{arch}.zip")
        })
        .to_string()
        .into_bytes()
    }

    fn artifact(net: &Fixtures, purl: &str) -> Option<ArtifactCandidate> {
        terraform_artifact(&coordinates(purl), net, &BlobCache::disabled())
    }

    #[test]
    fn a_provider_artifact_carries_the_registrys_sha256() {
        let sha = "AB".repeat(32);
        // Listed out of order, with a newer pre-release: the latest is the
        // highest stable version.
        let versions = serde_json::json!({"versions": [
            {"version": "4.9.1", "platforms": [{"os": "darwin", "arch": "arm64"}]},
            {"version": "5.0.0", "platforms": [{"os": "linux", "arch": "amd64"}]},
            {"version": "5.1.0-beta.1", "platforms": [{"os": "linux", "arch": "amd64"}]}
        ]})
        .to_string();
        let net = Fixtures::default()
            .with(
                "https://registry.terraform.io/v1/providers/acme/cloud/5.0.0/download/linux/amd64",
                &download("linux", "amd64", &sha),
            )
            .refusing(
                "https://registry.terraform.io/v1/providers/acme/cloud/4.9.1/download/linux/amd64",
                404,
            )
            .with(
                "https://registry.terraform.io/v1/providers/acme/cloud/versions",
                versions.as_bytes(),
            )
            .with(
                "https://registry.terraform.io/v1/providers/acme/cloud/4.9.1/download/darwin/arm64",
                &download("darwin", "arm64", &sha),
            );

        // Versionless: the latest version the registry lists.
        let c = artifact(&net, "pkg:terraform/acme/cloud").expect("candidate");
        assert_eq!(c.version.as_deref(), Some("5.0.0"));
        assert_eq!(
            c.checksums.get("sha256").map(String::as_str),
            Some("ab".repeat(32).as_str())
        );
        assert_eq!(c.attributes.get("os").map(String::as_str), Some("linux"));

        // No linux_amd64 build: the first platform the version lists.
        let c = artifact(&net, "pkg:terraform/acme/cloud@4.9.1").expect("candidate");
        assert_eq!(c.url, "https://releases.example.test/p_darwin_arm64.zip");
        assert_eq!(c.attributes.get("arch").map(String::as_str), Some("arm64"));
    }

    #[test]
    fn a_provider_artifact_without_a_sha256_or_a_safe_platform_is_refused() {
        let base = "https://registry.terraform.io/v1/providers/acme/cloud";
        let net = Fixtures::default()
            .with(
                &format!("{base}/1.0.0/download/linux/amd64"),
                &download("linux", "amd64", "not-a-sha"),
            )
            .refusing(&format!("{base}/2.0.0/download/linux/amd64"), 404)
            .with(
                &format!("{base}/versions"),
                serde_json::json!({"versions": [
                    {"version": "2.0.0", "platforms": [{"os": "..", "arch": "x"}]}
                ]})
                .to_string()
                .as_bytes(),
            );
        assert!(artifact(&net, "pkg:terraform/acme/cloud@1.0.0").is_none());
        assert!(artifact(&net, "pkg:terraform/acme/cloud@2.0.0").is_none());
    }
}
