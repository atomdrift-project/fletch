//! CPAN: registry metadata.

use filefacts::Registry;
use serde::Deserialize;

use crate::ecosystem::{
    Coordinates, fetch_json, flag, non_empty, null_default, optional, unix_secs,
};
use crate::fetch::{BlobCache, Fetch};
use crate::purl::encode_component;
use crate::registry::RegistryError;

/// MetaCPAN's API root.
const METACPAN: &str = "https://fastapi.metacpan.org/v1/release";

/// MetaCPAN: the distribution's latest release (date, PAUSE author, abstract,
/// resources), and for an older version asked for, that release's own
/// document under its author. The PURL's namespace, when present, is the
/// PAUSE id that released the distribution: another author's upload of the
/// same name is not the one CPAN indexes.
pub(crate) fn lookup(
    c: &Coordinates<'_>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let claimed = match c.namespace() {
        [] => None,
        [author] => Some(author),
        _ => {
            tracing::debug!(
                purl = %c.purl().to_string().escape_debug(),
                "CPAN lookup refused: more than one author segment"
            );
            return Err(RegistryError::OffRegistry);
        }
    };
    let dist = c.encoded_name();
    let latest: Release = fetch_json(&format!("{METACPAN}/{dist}"), net, cache)?;
    if let Some(claimed) = claimed
        && !latest
            .author
            .as_deref()
            .is_some_and(|a| a.eq_ignore_ascii_case(claimed))
    {
        tracing::debug!(
            claimed = %claimed.escape_debug(),
            author = ?latest.author,
            "CPAN lookup refused: the namespace is not the releasing author"
        );
        return Err(RegistryError::OffRegistry);
    }

    // An older release lives under `{author}/{dist}-{version}`. It counts
    // only if it is this distribution at the version asked for; otherwise the
    // record describes the version undated, from the latest's facts.
    let older;
    let release = match (c.version(), latest.author.as_deref()) {
        (Some(want), Some(author)) if latest.version.as_deref() != Some(want) => {
            let url = format!(
                "{METACPAN}/{}/{dist}-{}",
                encode_component(author),
                encode_component(want)
            );
            older = optional(fetch_json::<ReleaseDocument>(&url, net, cache), &url)
                .map(|d| d.release)
                .filter(|r| {
                    r.version.as_deref() == Some(want) && r.distribution == latest.distribution
                });
            older.as_ref()
        }
        (Some(want), None) if latest.version.as_deref() != Some(want) => None,
        _ => Some(&latest),
    };
    if release.is_none() {
        tracing::debug!(
            dist = %c.name().escape_debug(),
            version = %c.target(None).escape_debug(),
            "CPAN release not found; describing it undated from the latest"
        );
    }
    let facts = release.unwrap_or(&latest);

    Ok(Registry {
        ecosystem: "cpan".into(),
        name: latest
            .distribution
            .clone()
            .unwrap_or_else(|| c.name().to_string()),
        version: c.target(latest.version.as_deref()).to_string(),
        // MetaCPAN dates are naive ISO (no zone), which is UTC.
        published_at: release.and_then(|r| r.date.as_deref()).and_then(unix_secs),
        latest_version: latest.version.clone(),
        author: facts.author.clone(),
        description: facts.r#abstract.clone(),
        homepage: facts.resources.homepage.clone(),
        repository: facts
            .resources
            .repository
            .as_ref()
            .and_then(|r| r.url.clone()),
        license: facts.license.first().cloned(),
        deprecated: flag(facts.deprecated, "deprecated"),
        // A BackPAN release was deleted from CPAN and survives only in the
        // archive.
        version_removed: release.and_then(|r| r.status.as_deref().map(|s| s == "backpan")),
        ..Default::default()
    })
}

/// The per-release endpoint's envelope.
#[derive(Deserialize)]
struct ReleaseDocument {
    release: Release,
}

/// The parts of a MetaCPAN release document the registry record reads.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Release {
    distribution: Option<String>,
    version: Option<String>,
    date: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    author: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    r#abstract: Option<String>,
    #[serde(deserialize_with = "null_default")]
    resources: Resources,
    #[serde(deserialize_with = "null_default")]
    license: Vec<String>,
    /// `latest`, `cpan`, or `backpan`.
    status: Option<String>,
    deprecated: Option<bool>,
}

/// The release's `resources` links.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Resources {
    #[serde(deserialize_with = "non_empty")]
    homepage: Option<String>,
    repository: Option<Repository>,
}

/// `resources.repository`, read for its `url`.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Repository {
    #[serde(deserialize_with = "non_empty")]
    url: Option<String>,
}

#[cfg(test)]
mod tests {
    use crate::fetch::{BlobCache, Fixtures};
    use crate::registry::{RegistryError, lookup};
    use filefacts::{RefLocator, Registry};

    fn look(net: &Fixtures, purl: &str) -> Result<Registry, RegistryError> {
        lookup(&RefLocator::Purl(purl.into()), net, &BlobCache::disabled())
    }

    fn moose() -> Fixtures {
        let latest = serde_json::json!({
            "distribution": "Moose", "version": "2.4000", "date": "2021-04-23T10:00:00",
            "author": "ETHER", "abstract": "A postmodern object system for Perl 5",
            "license": ["perl_5"], "status": "latest", "deprecated": false,
            "resources": {"homepage": "https://metacpan.org/pod/Moose",
                          "repository": {"url": "https://github.com/moose/Moose"}}
        })
        .to_string();
        let older = serde_json::json!({"release": {
            "distribution": "Moose", "version": "2.2015", "date": "2021-03-31T01:11:39",
            "author": "ETHER", "abstract": "Moose, older", "status": "backpan",
            "deprecated": true
        }})
        .to_string();
        Fixtures::default()
            .with(
                "https://fastapi.metacpan.org/v1/release/Moose",
                latest.as_bytes(),
            )
            .with(
                "https://fastapi.metacpan.org/v1/release/ETHER/Moose-2.2015",
                older.as_bytes(),
            )
    }

    #[test]
    fn cpan_release_normalizes() {
        let r = look(&moose(), "pkg:cpan/Moose").expect("registry");
        assert_eq!(r.ecosystem, "cpan");
        assert_eq!(r.version, "2.4000");
        assert_eq!(r.latest_version.as_deref(), Some("2.4000"));
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(r.author.as_deref(), Some("ETHER"));
        assert_eq!(r.license.as_deref(), Some("perl_5"));
        assert_eq!(
            r.repository.as_deref(),
            Some("https://github.com/moose/Moose")
        );
        assert_eq!(r.deprecated, None);
        assert_eq!(r.version_removed, Some(false));
    }

    #[test]
    fn a_requested_release_is_dated_by_its_own_document_or_not_at_all() {
        let net = moose();
        let r = look(&net, "pkg:cpan/Moose@2.2015").expect("registry");
        assert_eq!(r.version, "2.2015");
        assert_eq!(r.published_at, Some(1_617_153_099)); // 2021-03-31T01:11:39Z
        assert_eq!(r.latest_version.as_deref(), Some("2.4000"));
        assert_eq!(r.description.as_deref(), Some("Moose, older"));
        assert_eq!(r.deprecated.as_deref(), Some("deprecated"));
        assert_eq!(r.version_removed, Some(true), "a BackPAN release");

        // MetaCPAN has no such release: the version stands, undated.
        let r = look(&net, "pkg:cpan/Moose@0.1").expect("registry");
        assert_eq!(r.version, "0.1");
        assert_eq!(r.published_at, None);
        assert_eq!(r.version_removed, None);
        assert_eq!(r.author.as_deref(), Some("ETHER"));
    }

    #[test]
    fn a_cpan_author_namespace_must_be_the_releasing_author() {
        let net = moose();
        assert!(look(&net, "pkg:cpan/ETHER/Moose").is_ok());
        assert!(look(&net, "pkg:cpan/ether/Moose").is_ok());
        for purl in ["pkg:cpan/EVIL/Moose", "pkg:cpan/A/B/Moose"] {
            assert_eq!(look(&net, purl), Err(RegistryError::OffRegistry), "{purl}");
        }
    }
}
