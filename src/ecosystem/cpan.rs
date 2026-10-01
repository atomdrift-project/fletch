//! CPAN: registry metadata and artifact resolution.

use filefacts::Registry;
use serde::Deserialize;

use crate::ecosystem::{fetch_json, null_default, parse_ts};
use crate::fetch::{BlobCache, Fetch};
use crate::registry::RegistryError;

/// CPAN: MetaCPAN's release endpoint returns the latest release of a
/// distribution with its date, author (PAUSE id), abstract, and resources.
pub(crate) fn cpan(
    dist: &str,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Result<Registry, RegistryError> {
    let doc: Release = fetch_json(
        &format!("https://fastapi.metacpan.org/v1/release/{dist}"),
        net,
        cache,
    )?;

    Ok(Registry {
        ecosystem: "cpan".into(),
        name: doc.distribution.unwrap_or_else(|| dist.to_string()),
        version: doc.version.unwrap_or_default(),
        // MetaCPAN dates are naive ISO (no zone); treat as UTC.
        published_at: doc.date.as_deref().and_then(parse_ts),
        author: doc.author,
        description: doc.r#abstract,
        homepage: doc.resources.homepage,
        repository: doc.resources.repository.and_then(|r| r.url),
        license: doc.license.into_iter().next(),
        deprecated: (doc.status.as_deref() == Some("backpan"))
            .then(|| "removed from CPAN".to_string()),
        ..Default::default()
    })
}

/// The parts of a MetaCPAN release document the registry record reads.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Release {
    distribution: Option<String>,
    version: Option<String>,
    date: Option<String>,
    author: Option<String>,
    r#abstract: Option<String>,
    #[serde(deserialize_with = "null_default")]
    resources: Resources,
    #[serde(deserialize_with = "null_default")]
    license: Vec<String>,
    status: Option<String>,
}

/// The release's `resources` links.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Resources {
    homepage: Option<String>,
    repository: Option<Repository>,
}

/// `resources.repository`, read for its `url`.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Repository {
    url: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::test_cache;

    use crate::fetch::Fixtures;

    #[test]
    fn cpan_release_normalizes() {
        let doc = serde_json::json!({
            "distribution": "Moose", "version": "2.4000", "date": "2021-04-23T10:00:00",
            "author": "ETHER", "abstract": "A postmodern object system for Perl 5",
            "license": ["perl_5"], "status": "latest",
            "resources": {"homepage": "https://metacpan.org/pod/Moose",
                          "repository": {"url": "https://github.com/moose/Moose"}}
        })
        .to_string();
        let net = Fixtures::default().with(
            "https://fastapi.metacpan.org/v1/release/Moose",
            doc.as_bytes(),
        );
        let r = cpan("Moose", &net, &test_cache("cpan")).expect("registry");
        assert_eq!(r.ecosystem, "cpan");
        assert_eq!(r.version, "2.4000");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(r.author.as_deref(), Some("ETHER"));
        assert_eq!(r.license.as_deref(), Some("perl_5"));
        assert_eq!(
            r.repository.as_deref(),
            Some("https://github.com/moose/Moose")
        );
    }
}
