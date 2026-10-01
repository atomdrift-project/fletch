//! CPAN: registry metadata and artifact resolution.

use filefacts::Registry;
use serde_json::Value;

use crate::ecosystem::{json_meta, parse_ts};
use crate::fetch::{BlobCache, Fetch};

/// CPAN: MetaCPAN's release endpoint returns the latest release of a
/// distribution with its date, author (PAUSE id), abstract, and resources.
pub(crate) fn cpan(dist: &str, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    let doc = json_meta(
        &format!("https://fastapi.metacpan.org/v1/release/{dist}"),
        net,
        cache,
    )?;

    Some(Registry {
        ecosystem: "cpan".into(),
        name: doc
            .get("distribution")
            .and_then(Value::as_str)
            .unwrap_or(dist)
            .to_string(),
        version: doc
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        // MetaCPAN dates are naive ISO (no zone); treat as UTC.
        published_at: doc.get("date").and_then(Value::as_str).and_then(parse_ts),
        author: doc
            .get("author")
            .and_then(Value::as_str)
            .map(str::to_string),
        description: doc
            .get("abstract")
            .and_then(Value::as_str)
            .map(str::to_string),
        homepage: doc
            .pointer("/resources/homepage")
            .and_then(Value::as_str)
            .map(str::to_string),
        repository: doc
            .pointer("/resources/repository/url")
            .and_then(Value::as_str)
            .map(str::to_string),
        license: doc
            .pointer("/license/0")
            .and_then(Value::as_str)
            .map(str::to_string),
        deprecated: (doc.get("status").and_then(Value::as_str) == Some("backpan"))
            .then(|| "removed from CPAN".to_string()),
        ..Default::default()
    })
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
