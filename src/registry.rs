//! Look up and normalize a package's registry metadata.
//!
//! [`fetch`](crate::fetch) retrieves the *artifact*; this module retrieves the
//! registry's *metadata about* the artifact — publish date, author, downloads,
//! rating, deprecation — and reduces every ecosystem's bespoke JSON to one
//! common [`filefacts::Registry`] shape (which filefacts can re-parse from a
//! serialized `*.registry.json` document into trait-matchable facts). A consumer
//! (scan) then applies uniform policy — age gating, reputation heuristics —
//! without knowing whether the source was npm, PyPI, crates.io, Packagist, or
//! the AUR.
//!
//! The lookup is small (a JSON document, not a tarball) and cached, so it is the
//! cheap thing to do *first*: learn a dependency's age before deciding whether
//! the expensive fetch-and-scan of its bytes is worth it.

use serde_json::Value;

use crate::fetch::{BlobCache, Fetch, cached_metadata, cached_post, goproxy_escape};
use filefacts::{RefLocator, Registry};

/// Look up and normalize the registry metadata for a dependency `locator`.
///
/// Dispatches on the PURL ecosystem, fetches the metadata document through the
/// blob cache (one round-trip per package per cache window, free on a hit), and
/// maps it to [`Registry`]. `None` when the locator is a raw URL, the ecosystem
/// is unsupported, or the registry can't be reached/parsed — the caller decides
/// what an absent answer means (scan fails open and fetches). The returned
/// record leaves [`Registry::age_days`] unset; the caller stamps it with
/// [`Registry::with_age`] from its own clock.
#[must_use]
pub fn registry(locator: &RefLocator, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    let RefLocator::Purl(purl) = locator else {
        return None;
    };
    let (ty, path, version) = parse_purl(purl)?;
    let version = version.as_deref();
    match ty.as_str() {
        "npm" => npm(&path, version, net, cache),
        "cargo" => crates(&path, version, net, cache),
        "pypi" => pypi(&path, version, net, cache),
        "composer" => composer(&path, version, net, cache),
        "gem" => gem(&path, version, net, cache),
        "golang" => golang(&path, version, net, cache),
        // A `pkg:github/<owner>/<repo>` source: the repo *is* the upstream. Its
        // metadata is the closest thing to a registry record.
        "github" => github(&path, net, cache),
        // Arch deps surface as `pkg:alpm/arch/<name>`; the AUR is the
        // user-contributed, attacker-reachable half worth provenancing.
        "alpm" => aur(path.rsplit('/').next().unwrap_or(&path), net, cache),
        // Browser extensions: `pkg:chrome/<extension-id>`. The store's risk
        // signals (reach, rating, recency, the developer's own description of
        // what it harvests) live on the listing, not in a manifest.
        "chrome" => chrome(path.rsplit('/').next().unwrap_or(&path), net, cache),
        // VS Code / editor extensions: `pkg:openvsx/<namespace>/<name>`. Open
        // VSX exposes a clean JSON API, so no scraping — the same marketplace
        // shape (rating, downloads, publisher, recency) as the Chrome store.
        "openvsx" => openvsx(&path, version, net, cache),
        // The Microsoft VS Code Marketplace: `pkg:vscode/<publisher>/<name>`.
        // Its data lives behind a JSON-RPC `POST` query — same marketplace shape
        // as Open VSX, just a different transport.
        "vscode" => vscode(&path, net, cache),
        _ => None,
    }
}

/// Split a PURL into `(type, name-path, version?)`, mirroring `fetch`'s
/// resolver: the version follows a literal `@` (a scope is `%40`).
fn parse_purl(purl: &str) -> Option<(String, String, Option<String>)> {
    let body = purl.strip_prefix("pkg:")?;
    let (ty, rest) = body.split_once('/')?;
    let (path, version) = rest
        .rsplit_once('@')
        .map_or((rest, None), |(p, v)| (p, Some(v.to_string())));
    Some((ty.to_string(), path.to_string(), version))
}

/// npm: the packument carries publish times, custody, and links in one
/// document; download counts need a second (cached) endpoint.
fn npm(path: &str, version: Option<&str>, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    let name = path.replace("%40", "@");
    let doc: Value = serde_json::from_slice(&cached_metadata(
        &format!("https://registry.npmjs.org/{name}"),
        net,
        cache,
    )?)
    .ok()?;

    let latest = doc.pointer("/dist-tags/latest").and_then(Value::as_str);
    let version = version.or(latest).unwrap_or_default();
    let v = doc.pointer(&format!("/versions/{}", json_ptr_escape(version)));

    let published_at = doc
        .get("time")
        .and_then(|t| t.get(version))
        .and_then(Value::as_str)
        .and_then(parse_rfc3339_secs);

    let mut p = Registry {
        ecosystem: "npm".into(),
        name: name.clone(),
        version: version.to_string(),
        published_at,
        latest_version: latest.map(str::to_string),
        author: v
            .and_then(|v| v.get("author"))
            .or_else(|| doc.get("author"))
            .and_then(person)
            .or_else(|| {
                doc.pointer("/maintainers/0/name")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            }),
        title: None,
        description: field_str(v, &doc, "description"),
        homepage: field_str(v, &doc, "homepage"),
        repository: v
            .and_then(|v| v.pointer("/repository/url"))
            .or_else(|| doc.pointer("/repository/url"))
            .and_then(Value::as_str)
            .map(str::to_string),
        license: field_str(v, &doc, "license"),
        deprecated: v.and_then(|v| v.get("deprecated")).and_then(deprecation),
        maintainers: doc
            .get("maintainers")
            .and_then(Value::as_array)
            .map(|m| m.len() as u32),
        ..Default::default()
    };

    // Best-effort popularity: last-month downloads from the stats endpoint.
    if let Some(d) = cached_metadata(
        &format!("https://api.npmjs.org/downloads/point/last-month/{name}"),
        net,
        cache,
    )
    .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
    .and_then(|j| j.get("downloads").and_then(Value::as_u64))
    {
        p.downloads_recent = Some(d);
    }
    Some(p)
}

/// crates.io: the per-crate API returns custody-free but rich popularity and
/// links; the matching version object carries its own publish time.
fn crates(
    path: &str,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Option<Registry> {
    let doc: Value = serde_json::from_slice(&cached_metadata(
        &format!("https://crates.io/api/v1/crates/{path}"),
        net,
        cache,
    )?)
    .ok()?;
    let krate = doc.get("crate")?;

    let latest = krate
        .get("max_stable_version")
        .or_else(|| krate.get("max_version"))
        .and_then(Value::as_str);
    let version = version.or(latest).unwrap_or_default();
    let ver = doc
        .get("versions")
        .and_then(Value::as_array)
        .and_then(|vs| {
            vs.iter()
                .find(|v| v.get("num").and_then(Value::as_str) == Some(version))
        });

    Some(Registry {
        ecosystem: "crates".into(),
        name: path.to_string(),
        version: version.to_string(),
        published_at: ver
            .and_then(|v| v.get("created_at"))
            .or_else(|| krate.get("created_at"))
            .and_then(Value::as_str)
            .and_then(parse_rfc3339_secs),
        latest_version: latest.map(str::to_string),
        author: None,
        title: None,
        description: krate
            .get("description")
            .and_then(Value::as_str)
            .map(str::to_string),
        homepage: krate
            .get("homepage")
            .and_then(Value::as_str)
            .map(str::to_string),
        repository: krate
            .get("repository")
            .and_then(Value::as_str)
            .map(str::to_string),
        license: ver
            .and_then(|v| v.get("license"))
            .and_then(Value::as_str)
            .map(str::to_string),
        downloads_total: krate.get("downloads").and_then(Value::as_u64),
        downloads_recent: krate.get("recent_downloads").and_then(Value::as_u64),
        deprecated: ver
            .and_then(|v| v.get("yanked"))
            .and_then(Value::as_bool)
            .and_then(|y| y.then(|| "yanked".to_string())),
        ..Default::default()
    })
}

/// PyPI: the JSON API's `info` block plus the per-version upload times.
fn pypi(path: &str, version: Option<&str>, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    let url = match version {
        Some(v) => format!("https://pypi.org/pypi/{path}/{v}/json"),
        None => format!("https://pypi.org/pypi/{path}/json"),
    };
    let doc: Value = serde_json::from_slice(&cached_metadata(&url, net, cache)?).ok()?;
    let info = doc.get("info")?;

    // The earliest upload across this version's files is its publish time.
    let published_at = doc.get("urls").and_then(Value::as_array).and_then(|urls| {
        urls.iter()
            .filter_map(|u| u.get("upload_time_iso_8601").and_then(Value::as_str))
            .filter_map(parse_rfc3339_secs)
            .min()
    });

    Some(Registry {
        ecosystem: "pypi".into(),
        name: path.to_string(),
        version: info
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        published_at,
        author: info
            .get("author")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .or_else(|| {
                info.get("maintainer")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
            })
            .map(str::to_string),
        description: info
            .get("summary")
            .and_then(Value::as_str)
            .map(str::to_string),
        homepage: info
            .get("home_page")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        license: info
            .get("license")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        deprecated: info.get("yanked").and_then(Value::as_bool).and_then(|y| {
            y.then(|| {
                info.get("yanked_reason")
                    .and_then(Value::as_str)
                    .unwrap_or("yanked")
                    .to_string()
            })
        }),
        ..Default::default()
    })
}

/// Composer/Packagist: the package endpoint carries lifetime downloads and a
/// favers (stars) count alongside the per-version time, authors, and license.
fn composer(
    path: &str,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Option<Registry> {
    let doc: Value = serde_json::from_slice(&cached_metadata(
        &format!("https://packagist.org/packages/{path}.json"),
        net,
        cache,
    )?)
    .ok()?;
    let pkg = doc.get("package")?;

    let versions = pkg.get("versions").and_then(Value::as_object);
    let want = version.map(|v| v.trim_start_matches('v').to_string());
    let ver = versions.and_then(|vs| {
        vs.iter()
            .find(|(k, _)| match &want {
                Some(w) => k.trim_start_matches('v') == w,
                None => !k.contains("dev"),
            })
            .map(|(_, v)| v)
    });

    Some(Registry {
        ecosystem: "composer".into(),
        name: path.to_string(),
        version: ver
            .and_then(|v| v.get("version"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        published_at: ver
            .and_then(|v| v.get("time"))
            .and_then(Value::as_str)
            .and_then(parse_rfc3339_secs),
        author: ver
            .and_then(|v| v.pointer("/authors/0/name"))
            .and_then(Value::as_str)
            .map(str::to_string),
        description: pkg
            .get("description")
            .and_then(Value::as_str)
            .map(str::to_string),
        repository: pkg
            .get("repository")
            .and_then(Value::as_str)
            .map(str::to_string),
        license: ver
            .and_then(|v| v.pointer("/license/0"))
            .and_then(Value::as_str)
            .map(str::to_string),
        downloads_total: pkg.pointer("/downloads/total").and_then(Value::as_u64),
        downloads_recent: pkg.pointer("/downloads/monthly").and_then(Value::as_u64),
        rating_count: pkg.get("favers").and_then(Value::as_u64),
        maintainers: pkg
            .get("maintainers")
            .and_then(Value::as_array)
            .map(|m| m.len() as u32),
        ..Default::default()
    })
}

/// RubyGems: a clean JSON API. The package endpoint carries downloads, author,
/// and links; the per-version publish date comes from the versions endpoint.
fn gem(name: &str, version: Option<&str>, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    let doc: Value = serde_json::from_slice(&cached_metadata(
        &format!("https://rubygems.org/api/v1/gems/{name}.json"),
        net,
        cache,
    )?)
    .ok()?;
    let resolved = version
        .map(str::to_string)
        .or_else(|| {
            doc.get("version")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_default();

    // The gem endpoint omits dates; the versions list carries `created_at` per
    // release. Match the resolved version, else fall back to the newest entry.
    let published_at = cached_metadata(
        &format!("https://rubygems.org/api/v1/versions/{name}.json"),
        net,
        cache,
    )
    .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
    .and_then(|vs| {
        let arr = vs.as_array()?;
        arr.iter()
            .find(|v| v.get("number").and_then(Value::as_str) == Some(resolved.as_str()))
            .or_else(|| arr.first())?
            .get("created_at")
            .and_then(Value::as_str)
            .and_then(parse_rfc3339_secs)
    });

    Some(Registry {
        ecosystem: "gem".into(),
        name: name.to_string(),
        version: resolved,
        published_at,
        author: doc
            .get("authors")
            .and_then(Value::as_str)
            .map(str::to_string),
        description: doc.get("info").and_then(Value::as_str).map(str::to_string),
        homepage: doc
            .get("homepage_uri")
            .and_then(Value::as_str)
            .map(str::to_string),
        repository: doc
            .get("source_code_uri")
            .and_then(Value::as_str)
            .map(str::to_string),
        license: doc
            .get("licenses")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .and_then(Value::as_str)
            .map(str::to_string),
        downloads_total: doc.get("downloads").and_then(Value::as_u64),
        downloads_recent: doc.get("version_downloads").and_then(Value::as_u64),
        ..Default::default()
    })
}

/// Go modules: the module proxy serves a per-version `.info` (and an `@latest`)
/// document with the version and its commit time — the only registry facts Go
/// exposes. The module path is GOPROXY case-encoded. `Origin.URL` recovers the
/// backing VCS repository.
fn golang(
    path: &str,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Option<Registry> {
    let escaped = goproxy_escape(path);
    let url = match version {
        Some(v) => format!(
            "https://proxy.golang.org/{escaped}/@v/{}.info",
            goproxy_escape(v)
        ),
        None => format!("https://proxy.golang.org/{escaped}/@latest"),
    };
    let doc: Value = serde_json::from_slice(&cached_metadata(&url, net, cache)?).ok()?;

    Some(Registry {
        ecosystem: "golang".into(),
        name: path.to_string(),
        version: doc
            .get("Version")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        published_at: doc
            .get("Time")
            .and_then(Value::as_str)
            .and_then(parse_rfc3339_secs),
        repository: doc
            .pointer("/Origin/URL")
            .and_then(Value::as_str)
            .map(str::to_string),
        ..Default::default()
    })
}

/// GitHub: a `pkg:github/<owner>/<repo>` reference has no package registry — the
/// repository itself is the upstream. The REST API supplies the registry-shaped
/// facts: recency (`pushed_at`), custody (`owner`), endorsement (stars),
/// license, and whether the repo is archived (a deprecation analogue).
/// Unauthenticated, so subject to GitHub's 60-req/hour anonymous limit; a
/// throttled lookup simply degrades to "unknown".
fn github(path: &str, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    let doc: Value = serde_json::from_slice(&cached_metadata(
        &format!("https://api.github.com/repos/{path}"),
        net,
        cache,
    )?)
    .ok()?;

    Some(Registry {
        ecosystem: "github".into(),
        name: path.to_string(),
        version: String::new(),
        // `pushed_at` (last code change) is the supply-chain-relevant recency.
        published_at: doc
            .get("pushed_at")
            .and_then(Value::as_str)
            .and_then(parse_rfc3339_secs),
        author: doc
            .pointer("/owner/login")
            .and_then(Value::as_str)
            .map(str::to_string),
        title: doc
            .get("full_name")
            .and_then(Value::as_str)
            .map(str::to_string),
        description: doc
            .get("description")
            .and_then(Value::as_str)
            .map(str::to_string),
        homepage: doc
            .get("homepage")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        repository: doc
            .get("html_url")
            .and_then(Value::as_str)
            .map(str::to_string),
        license: doc
            .pointer("/license/spdx_id")
            .and_then(Value::as_str)
            .filter(|&s| s != "NOASSERTION")
            .map(str::to_string),
        // Stars are GitHub's endorsement count — the nearest popularity analogue.
        rating_count: doc.get("stargazers_count").and_then(Value::as_u64),
        deprecated: doc
            .get("archived")
            .and_then(Value::as_bool)
            .and_then(|a| a.then(|| "archived".to_string())),
        ..Default::default()
    })
}

/// AUR: the RPC `info` endpoint. The AUR has no downloads; its custody signal
/// is the maintainer plus vote count and popularity score, and `LastModified`
/// (when the PKGBUILD last changed) is the supply-chain-relevant "age". Official
/// repo packages aren't in the AUR, so they return an empty result → `None`.
fn aur(name: &str, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    let url = format!("https://aur.archlinux.org/rpc/v5/info?arg%5B%5D={name}");
    let doc: Value = serde_json::from_slice(&cached_metadata(&url, net, cache)?).ok()?;
    let r = doc.pointer("/results/0")?;

    Some(Registry {
        ecosystem: "aur".into(),
        name: r
            .get("Name")
            .and_then(Value::as_str)
            .unwrap_or(name)
            .to_string(),
        version: r
            .get("Version")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        // LastModified is a Unix-seconds integer already.
        published_at: r.get("LastModified").and_then(Value::as_u64),
        author: r
            .get("Maintainer")
            .and_then(Value::as_str)
            .map(str::to_string),
        title: r.get("Name").and_then(Value::as_str).map(str::to_string),
        description: r
            .get("Description")
            .and_then(Value::as_str)
            .map(str::to_string),
        homepage: r.get("URL").and_then(Value::as_str).map(str::to_string),
        rating: r
            .get("Popularity")
            .and_then(Value::as_f64)
            .map(|f| f as f32),
        rating_count: r.get("NumVotes").and_then(Value::as_u64),
        deprecated: r
            .get("OutOfDate")
            .and_then(Value::as_u64)
            .and_then(|t| (t > 0).then(|| "flagged out-of-date".to_string())),
        ..Default::default()
    })
}

/// Chrome Web Store: the listing has no JSON API, so scrape the public detail
/// page. The signals that matter for an extension — what it claims to do (the
/// developer's own description), how far it reaches (user count), how it's
/// rated, and when it last changed — are all rendered into the HTML. Best-effort
/// by design: a field that moves in the markup degrades to "unknown", never a
/// wrong value.
fn chrome(id: &str, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    let url = format!("https://chromewebstore.google.com/detail/{id}");
    let bytes = cached_metadata(&url, net, cache)?;
    let html = std::str::from_utf8(&bytes).ok()?;

    // og:title carries the listing name with a `- Chrome Web Store` suffix.
    let title = meta_content(html, "og:title")
        .map(|t| t.trim_end_matches(" - Chrome Web Store").trim().to_string());

    Some(Registry {
        ecosystem: "chrome".into(),
        name: id.to_string(),
        version: String::new(),
        // "Updated <Month D, YYYY>" is the listing's last-change date.
        published_at: text_after(html, "Updated").and_then(|s| parse_month_day_year(&s)),
        author: text_after(html, "Offered by"),
        title: title.clone(),
        description: meta_content(html, "og:description"),
        homepage: Some(url),
        // "N,NNN users" — the store's reach figure, a downloads analogue.
        downloads_total: before(html, " users")
            .as_deref()
            .and_then(parse_grouped_u64),
        // "X out of 5 stars" / "N ratings".
        rating: before(html, " out of 5 stars").and_then(|s| s.parse::<f32>().ok()),
        rating_count: before(html, " ratings")
            .as_deref()
            .and_then(parse_grouped_u64),
        ..Default::default()
    })
}

/// Open VSX: a JSON API, so the marketplace's facts come back structured — no
/// scraping. `path` is `<namespace>/<name>`; one GET yields the requested
/// version (or the latest) with rating, downloads, publisher, and publish time.
fn openvsx(
    path: &str,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Option<Registry> {
    let (ns, name) = path.split_once('/')?;
    let url = match version {
        Some(v) => format!("https://open-vsx.org/api/{ns}/{name}/{v}"),
        None => format!("https://open-vsx.org/api/{ns}/{name}"),
    };
    let doc: Value = serde_json::from_slice(&cached_metadata(&url, net, cache)?).ok()?;

    Some(Registry {
        ecosystem: "openvsx".into(),
        // The canonical extension id everyone types is `namespace.name`.
        name: format!("{ns}.{name}"),
        version: doc
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        published_at: doc
            .get("timestamp")
            .and_then(Value::as_str)
            .and_then(parse_rfc3339_secs),
        author: doc
            .pointer("/publishedBy/loginName")
            .and_then(Value::as_str)
            .map(str::to_string),
        title: doc
            .get("displayName")
            .and_then(Value::as_str)
            .map(str::to_string),
        description: doc
            .get("description")
            .and_then(Value::as_str)
            .map(str::to_string),
        homepage: doc
            .get("homepage")
            .and_then(Value::as_str)
            .map(str::to_string),
        repository: doc
            .get("repository")
            .and_then(Value::as_str)
            .map(str::to_string),
        license: doc
            .get("license")
            .and_then(Value::as_str)
            .map(str::to_string),
        downloads_total: doc.get("downloadCount").and_then(Value::as_u64),
        rating: doc
            .get("averageRating")
            .and_then(Value::as_f64)
            .map(|f| f as f32),
        rating_count: doc.get("reviewCount").and_then(Value::as_u64),
        deprecated: doc
            .get("deprecated")
            .and_then(Value::as_bool)
            .and_then(|d| d.then(|| "deprecated".to_string())),
        ..Default::default()
    })
}

/// The Microsoft VS Code Marketplace. Its metadata lives behind a JSON-RPC
/// `POST` to the gallery's `extensionquery` (there is no GET form), keyed by the
/// `<publisher>.<name>` id. One query returns the latest version with its
/// install count, rating, publisher, and timestamps — the same marketplace
/// shape as Open VSX, over a different transport.
fn vscode(path: &str, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    let ext_id = path.replace('/', ".");
    let body = format!(
        r#"{{"filters":[{{"criteria":[{{"filterType":7,"value":"{ext_id}"}}]}}],"flags":914}}"#
    );
    let headers = [
        ("Content-Type", "application/json"),
        ("Accept", "application/json;api-version=3.0-preview.1"),
    ];
    let doc: Value = serde_json::from_slice(&cached_post(
        "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery",
        body.as_bytes(),
        &headers,
        net,
        cache,
    )?)
    .ok()?;
    let ext = doc.pointer("/results/0/extensions/0")?;

    // `statistics` is an array of `{statisticName, value}` pairs.
    let stat = |name: &str| -> Option<f64> {
        ext.get("statistics")?
            .as_array()?
            .iter()
            .find(|s| s.get("statisticName").and_then(Value::as_str) == Some(name))?
            .get("value")?
            .as_f64()
    };

    Some(Registry {
        ecosystem: "vscode".into(),
        name: ext_id,
        version: ext
            .pointer("/versions/0/version")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        // `lastUpdated` is the supply-chain-relevant age: when the extension last
        // changed, not when it first shipped.
        published_at: ext
            .get("lastUpdated")
            .and_then(Value::as_str)
            .and_then(parse_rfc3339_secs),
        author: ext
            .pointer("/publisher/displayName")
            .and_then(Value::as_str)
            .map(str::to_string),
        title: ext
            .get("displayName")
            .and_then(Value::as_str)
            .map(str::to_string),
        description: ext
            .get("shortDescription")
            .and_then(Value::as_str)
            .map(str::to_string),
        downloads_total: stat("install").map(|v| v as u64),
        rating: stat("averagerating").map(|v| v as f32),
        rating_count: stat("ratingcount").map(|v| v as u64),
        ..Default::default()
    })
}

// --- HTML scraping helpers --------------------------------------------------

/// Extract a `<meta property="og:NAME" content="VALUE">` value.
fn meta_content(html: &str, property: &str) -> Option<String> {
    let anchor = format!("property=\"{property}\" content=\"");
    let start = html.find(&anchor)? + anchor.len();
    let rest = &html[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// The first non-empty text run *after* `marker`, skipping any intervening
/// tags — for label/value pairs the markup splits across elements, like
/// `Updated</div><div>June 9, 2026</div>` → `June 9, 2026`.
fn text_after(html: &str, marker: &str) -> Option<String> {
    let start = html.find(marker)? + marker.len();
    let mut in_tag = false;
    let mut out = String::new();
    for c in html[start..].chars().take(400) {
        match c {
            '<' => {
                if !out.trim().is_empty() {
                    break;
                }
                in_tag = true;
            }
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    let trimmed = out.trim().to_string();
    (!trimmed.is_empty()).then_some(trimmed)
}

/// The token immediately *before* `marker` — for `N users`, `4.9 out of 5
/// stars`, `122 ratings`: walk back over the value characters.
fn before(html: &str, marker: &str) -> Option<String> {
    let idx = html.find(marker)?;
    let head = &html[..idx];
    let token: String = head
        .chars()
        .rev()
        .take_while(|&c| c.is_ascii_digit() || matches!(c, '.' | ','))
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    Some(token).filter(|s| !s.is_empty())
}

/// Parse a thousands-grouped count like `40,000` to `u64`.
fn parse_grouped_u64(s: &str) -> Option<u64> {
    s.replace(',', "").parse().ok()
}

/// Parse a US-style `Month D, YYYY` (`June 9, 2026`) to Unix seconds at UTC
/// midnight. `None` on anything unrecognized.
fn parse_month_day_year(s: &str) -> Option<u64> {
    let s = s.trim();
    let (month_name, rest) = s.split_once(' ')?;
    let month = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ]
    .iter()
    .position(|m| m.eq_ignore_ascii_case(month_name))? as i64
        + 1;
    let (day, year) = rest.split_once(',')?;
    let day: i64 = day.trim().parse().ok()?;
    let year: i64 = year.trim().parse().ok()?;
    u64::try_from(days_from_civil(year, month, day) * 86_400).ok()
}

// --- JSON shaping helpers ---------------------------------------------------

/// A field preferred from the version object, falling back to the package root
/// (npm packuments carry both; the version's copy is authoritative).
fn field_str(ver: Option<&Value>, root: &Value, key: &str) -> Option<String> {
    ver.and_then(|v| v.get(key))
        .or_else(|| root.get(key))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// npm `author`/`maintainer` is either a bare string or an object with `name`.
fn person(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        _ => v.get("name").and_then(Value::as_str).map(str::to_string),
    }
}

/// npm `deprecated` is `false`/absent, or a truthy string reason.
fn deprecation(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Bool(true) => Some("deprecated".to_string()),
        _ => None,
    }
}

/// Escape a JSON-pointer path segment (`~`→`~0`, `/`→`~1`) so a version string
/// is matched literally inside a pointer.
fn json_ptr_escape(seg: &str) -> String {
    seg.replace('~', "~0").replace('/', "~1")
}

/// Parse an RFC 3339 / ISO 8601 timestamp to Unix seconds, covering the shapes
/// registries emit: `2021-04-23T10:00:00.000Z`, `…+00:00`, fractional seconds of
/// any width, space or `T` separator. `None` on anything unrecognized — an
/// unparseable date becomes "age unknown", never a wrong age.
fn parse_rfc3339_secs(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 19 {
        return None;
    }
    let n = |a: usize, z: usize| -> Option<i64> { s.get(a..z)?.parse().ok() };
    let (year, month, day) = (n(0, 4)?, n(5, 7)?, n(8, 10)?);
    let (hour, min, sec) = (n(11, 13)?, n(14, 16)?, n(17, 19)?);

    let mut i = 19;
    if b.get(i) == Some(&b'.') {
        i += 1;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
    }
    let offset = match b.get(i) {
        None | Some(b'Z') | Some(b'z') => 0,
        Some(&c @ (b'+' | b'-')) => {
            let oh = n(i + 1, i + 3)?;
            let mm = if b.get(i + 3) == Some(&b':') {
                i + 4
            } else {
                i + 3
            };
            let om = n(mm, mm + 2).unwrap_or(0);
            if c == b'+' {
                oh * 3600 + om * 60
            } else {
                -(oh * 3600 + om * 60)
            }
        }
        _ => return None,
    };
    let days = days_from_civil(year, month, day);
    u64::try_from(days * 86400 + hour * 3600 + min * 60 + sec - offset).ok()
}

/// Days since 1970-01-01 for a proleptic-Gregorian civil date (Howard
/// Hinnant's algorithm). Valid for any year in range.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::fetch::{BlobCache, Fixtures};

    #[test]
    fn rfc3339_shapes_parse_to_unix_seconds() {
        // 2021-04-23T10:00:00Z == 1619172000.
        assert_eq!(
            parse_rfc3339_secs("2021-04-23T10:00:00Z"),
            Some(1_619_172_000)
        );
        assert_eq!(
            parse_rfc3339_secs("2021-04-23T10:00:00.000Z"),
            Some(1_619_172_000)
        );
        assert_eq!(
            parse_rfc3339_secs("2021-04-23T10:00:00.123456Z"),
            Some(1_619_172_000)
        );
        // +02:00 offset is two hours earlier in UTC.
        assert_eq!(
            parse_rfc3339_secs("2021-04-23T12:00:00+02:00"),
            Some(1_619_172_000)
        );
        assert_eq!(
            parse_rfc3339_secs("2021-04-23 10:00:00"),
            Some(1_619_172_000)
        );
        // The Unix epoch itself.
        assert_eq!(parse_rfc3339_secs("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339_secs("garbage"), None);
        assert!(parse_rfc3339_secs("2021-13-01T00:00:00Z").is_some()); // no calendar validation
    }

    #[test]
    fn npm_packument_normalizes() {
        let packument = serde_json::json!({
            "dist-tags": {"latest": "1.3.0"},
            "author": {"name": "Una"},
            "maintainers": [{"name": "Una"}, {"name": "Bob"}],
            "time": {"1.3.0": "2021-04-23T10:00:00.000Z"},
            "versions": {
                "1.3.0": {
                    "description": "pad it",
                    "homepage": "https://example.test",
                    "license": "MIT",
                    "repository": {"url": "git+https://github.test/x.git"}
                }
            }
        })
        .to_string();
        let net =
            Fixtures::default().with("https://registry.npmjs.org/left-pad", packument.as_bytes());
        let cache = BlobCache::with_dir(std::env::temp_dir().join("fletch-prov-npm-test"));
        let p = npm("left-pad", Some("1.3.0"), &net, &cache).expect("provenance");
        assert_eq!(p.ecosystem, "npm");
        assert_eq!(p.published_at, Some(1_619_172_000));
        assert_eq!(p.latest_version.as_deref(), Some("1.3.0"));
        assert_eq!(p.author.as_deref(), Some("Una"));
        assert_eq!(p.license.as_deref(), Some("MIT"));
        assert_eq!(p.maintainers, Some(2));
    }

    #[test]
    fn aur_rpc_maps_votes_and_modified() {
        let rpc = serde_json::json!({
            "resultcount": 1,
            "results": [{
                "Name": "yay", "Version": "12.0.0-1", "Description": "AUR helper",
                "URL": "https://github.test/yay", "Maintainer": "jverify",
                "NumVotes": 1234, "Popularity": 42.5, "LastModified": 1_619_172_000u64,
                "OutOfDate": serde_json::Value::Null
            }]
        })
        .to_string();
        let net = Fixtures::default().with(
            "https://aur.archlinux.org/rpc/v5/info?arg%5B%5D=yay",
            rpc.as_bytes(),
        );
        let cache = BlobCache::with_dir(std::env::temp_dir().join("fletch-prov-aur-test"));
        let p = aur("yay", &net, &cache).expect("provenance");
        assert_eq!(p.ecosystem, "aur");
        assert_eq!(p.published_at, Some(1_619_172_000));
        assert_eq!(p.author.as_deref(), Some("jverify"));
        assert_eq!(p.rating, Some(42.5));
        assert_eq!(p.rating_count, Some(1234));
        assert_eq!(p.deprecated, None);
    }

    #[test]
    fn unsupported_locator_is_none() {
        let net = Fixtures::default();
        let cache = BlobCache::with_dir(std::env::temp_dir().join("fletch-prov-none-test"));
        assert!(
            registry(
                &RefLocator::Url("https://x.test/a.tgz".into()),
                &net,
                &cache
            )
            .is_none()
        );
        assert!(
            registry(
                &RefLocator::Purl("pkg:gem/rails@7.0.0".into()),
                &net,
                &cache
            )
            .is_none()
        );
    }

    #[test]
    fn gem_api_normalizes() {
        let gem_doc = serde_json::json!({
            "name": "rails", "version": "8.1.3", "downloads": 756_666_563u64,
            "version_downloads": 7_420_432u64, "authors": "David Heinemeier Hansson",
            "info": "Full-stack web framework", "licenses": ["MIT"],
            "homepage_uri": "https://rubyonrails.org",
            "source_code_uri": "https://github.com/rails/rails"
        })
        .to_string();
        let versions = serde_json::json!([
            {"number": "8.1.3", "created_at": "2021-04-23T10:00:00.000Z"},
            {"number": "8.1.2", "created_at": "2021-01-01T00:00:00.000Z"}
        ])
        .to_string();
        let net = Fixtures::default()
            .with(
                "https://rubygems.org/api/v1/gems/rails.json",
                gem_doc.as_bytes(),
            )
            .with(
                "https://rubygems.org/api/v1/versions/rails.json",
                versions.as_bytes(),
            );
        let cache = BlobCache::with_dir(std::env::temp_dir().join("fletch-prov-gem-test"));
        let r = gem("rails", None, &net, &cache).expect("registry");
        assert_eq!(r.ecosystem, "gem");
        assert_eq!(r.version, "8.1.3");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(r.author.as_deref(), Some("David Heinemeier Hansson"));
        assert_eq!(r.license.as_deref(), Some("MIT"));
        assert_eq!(r.downloads_total, Some(756_666_563));
    }

    #[test]
    fn golang_proxy_info_normalizes() {
        let info = serde_json::json!({
            "Version": "v1.12.0", "Time": "2021-04-23T10:00:00Z",
            "Origin": {"VCS": "git", "URL": "https://github.com/gin-gonic/gin"}
        })
        .to_string();
        let net = Fixtures::default().with(
            "https://proxy.golang.org/github.com/gin-gonic/gin/@latest",
            info.as_bytes(),
        );
        let cache = BlobCache::with_dir(std::env::temp_dir().join("fletch-prov-go-test"));
        let r = golang("github.com/gin-gonic/gin", None, &net, &cache).expect("registry");
        assert_eq!(r.ecosystem, "golang");
        assert_eq!(r.version, "v1.12.0");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(
            r.repository.as_deref(),
            Some("https://github.com/gin-gonic/gin")
        );
    }

    #[test]
    fn github_repo_normalizes() {
        let repo = serde_json::json!({
            "full_name": "gin-gonic/gin", "description": "HTTP web framework",
            "pushed_at": "2021-04-23T10:00:00Z", "stargazers_count": 88_739u64,
            "archived": false, "homepage": "https://gin-gonic.com/",
            "html_url": "https://github.com/gin-gonic/gin",
            "owner": {"login": "gin-gonic"}, "license": {"spdx_id": "MIT"}
        })
        .to_string();
        let net = Fixtures::default().with(
            "https://api.github.com/repos/gin-gonic/gin",
            repo.as_bytes(),
        );
        let cache = BlobCache::with_dir(std::env::temp_dir().join("fletch-prov-gh-test"));
        let r = github("gin-gonic/gin", &net, &cache).expect("registry");
        assert_eq!(r.ecosystem, "github");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(r.author.as_deref(), Some("gin-gonic"));
        assert_eq!(r.license.as_deref(), Some("MIT"));
        assert_eq!(r.rating_count, Some(88_739));
        assert_eq!(r.deprecated, None);
    }

    #[test]
    fn vscode_marketplace_query_normalizes() {
        let resp = serde_json::json!({
            "results": [{"extensions": [{
                "displayName": "Language Support for Java",
                "shortDescription": "Java tooling",
                "publisher": {"displayName": "Red Hat", "publisherName": "redhat"},
                "lastUpdated": "2026-06-23T09:30:32.957Z",
                "versions": [{"version": "1.55.0"}],
                "statistics": [
                    {"statisticName": "install", "value": 55_043_274.0},
                    {"statisticName": "averagerating", "value": 3.315},
                    {"statisticName": "ratingcount", "value": 184.0}
                ]
            }]}]
        })
        .to_string();
        // Fixtures key on URL; the POST body is ignored.
        let net = Fixtures::default().with(
            "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery",
            resp.as_bytes(),
        );
        let cache = BlobCache::with_dir(std::env::temp_dir().join("fletch-prov-vscode-test"));
        let r = vscode("redhat/java", &net, &cache).expect("registry");
        assert_eq!(r.ecosystem, "vscode");
        assert_eq!(r.name, "redhat.java");
        assert_eq!(r.version, "1.55.0");
        assert_eq!(r.title.as_deref(), Some("Language Support for Java"));
        assert_eq!(r.author.as_deref(), Some("Red Hat"));
        assert_eq!(r.downloads_total, Some(55_043_274));
        assert_eq!(r.rating, Some(3.315));
        assert_eq!(r.rating_count, Some(184));
        assert!(r.published_at.is_some());
    }

    #[test]
    fn openvsx_api_normalizes() {
        let api = serde_json::json!({
            "namespace": "redhat", "name": "java", "version": "1.55.0",
            "timestamp": "2026-06-23T09:16:36.442135Z",
            "displayName": "Language Support for Java", "description": "Java tooling",
            "averageRating": 5.0, "reviewCount": 16, "downloadCount": 33_978_555u64,
            "publishedBy": {"loginName": "rhdevelopers-ci"},
            "license": "EPL-2.0", "deprecated": false,
            "files": {"download": "https://open-vsx.org/api/redhat/java/1.55.0/file/redhat.java-1.55.0.vsix"}
        })
        .to_string();
        let net = Fixtures::default().with("https://open-vsx.org/api/redhat/java", api.as_bytes());
        let cache = BlobCache::with_dir(std::env::temp_dir().join("fletch-prov-ovsx-test"));
        let r = openvsx("redhat/java", None, &net, &cache).expect("registry");
        assert_eq!(r.ecosystem, "openvsx");
        assert_eq!(r.name, "redhat.java");
        assert_eq!(r.version, "1.55.0");
        assert_eq!(r.published_at, Some(1_782_206_196));
        assert_eq!(r.author.as_deref(), Some("rhdevelopers-ci"));
        assert_eq!(r.rating, Some(5.0));
        assert_eq!(r.rating_count, Some(16));
        assert_eq!(r.downloads_total, Some(33_978_555));
        assert_eq!(r.deprecated, None);
    }

    #[test]
    fn month_day_year_parses() {
        // 1970-01-01 is the epoch; June 9, 2026 is 20613 days later.
        assert_eq!(parse_month_day_year("January 1, 1970"), Some(0));
        assert_eq!(parse_month_day_year("June 9, 2026"), Some(1_780_963_200));
        assert_eq!(parse_month_day_year("not a date"), None);
    }

    #[test]
    fn html_scrape_helpers() {
        let html = r#"<meta property="og:title" content="社媒助手 - Chrome Web Store">
            <span>40,000 users</span><div>4.9 out of 5 stars</div>
            <div class="x">Updated</div><div>June 9, 2026</div>"#;
        assert_eq!(
            meta_content(html, "og:title").as_deref(),
            Some("社媒助手 - Chrome Web Store")
        );
        assert_eq!(
            before(html, " users")
                .as_deref()
                .and_then(parse_grouped_u64),
            Some(40_000)
        );
        assert_eq!(
            before(html, " out of 5 stars").and_then(|s| s.parse::<f32>().ok()),
            Some(4.9)
        );
        // The value is split across tags after the marker.
        assert_eq!(text_after(html, "Updated").as_deref(), Some("June 9, 2026"));
    }

    #[test]
    fn chrome_listing_normalizes() {
        let id = "dbichmdlbjdeplpkhcejgkakobjbjalc";
        let html = r#"<meta property="og:title" content="社媒助手 - 数据采集工具 - Chrome Web Store">
               <meta property="og:description" content="小红书、抖音等社媒平台数据采集工具，批量导出数据">
               <span>40,000 users</span><div>4.9 out of 5 stars</div><div>122 ratings</div>
               <div>Updated</div><div>June 9, 2026</div>"#.to_string();
        let net = Fixtures::default().with(
            &format!("https://chromewebstore.google.com/detail/{id}"),
            html.as_bytes(),
        );
        let cache = BlobCache::with_dir(std::env::temp_dir().join("fletch-prov-chrome-test"));
        let r = chrome(id, &net, &cache).expect("registry");
        assert_eq!(r.ecosystem, "chrome");
        assert_eq!(r.title.as_deref(), Some("社媒助手 - 数据采集工具"));
        assert_eq!(r.downloads_total, Some(40_000));
        assert_eq!(r.rating, Some(4.9));
        assert_eq!(r.rating_count, Some(122));
        assert_eq!(r.published_at, Some(1_780_963_200));
        assert!(r.description.is_some_and(|d| d.contains("数据采集")));
    }
}
