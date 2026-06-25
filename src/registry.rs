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

use crate::distro;
use crate::fetch::{
    BlobCache, Fetch, cached_metadata, cached_metadata_with, cached_post, goproxy_escape,
};
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
    // A versioned PURL is an immutable release — cache its metadata forever; a
    // versionless one tracks a moving tag, so bound staleness to the unpinned
    // window. Selected here, the one place that knows the PURL's version-ness,
    // and carried on the cache rather than threaded through every ecosystem fn.
    let cache = &cache.with_meta_ttl(if version.is_some() {
        crate::fetch::META_TTL_PINNED
    } else {
        crate::fetch::META_TTL_UNPINNED
    });
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
        // Language registries with a clean JSON API: one GET mapped onto the
        // common shape.
        "nuget" => nuget(&path, version, net, cache),
        "maven" => maven(&path, version, net, cache),
        "hex" => hex_pm(&path, version, net, cache),
        "cran" => cran(last_seg(&path), net, cache),
        "cpan" => cpan(last_seg(&path), net, cache),
        "pub" => pub_dev(last_seg(&path), version, net, cache),
        "conda" => conda(last_seg(&path), version, net, cache),
        "clojars" => clojars(&path, net, cache),
        // JSR ships through npm-compatible mirrors, but its own API carries the
        // richer record (score, repo, per-version dates).
        "jsr" => jsr(&path, version, net, cache),
        // OS package registries each get their own PURL type so a scan can name
        // `pkg:fedora/curl` vs `pkg:arch/pacman` directly. The package name is
        // the last path segment (any vendor namespace is dropped).
        "arch" => arch(last_seg(&path), net, cache),
        "fedora" => fedora(last_seg(&path), net, cache),
        // The AUR is the user-contributed, attacker-reachable half of Arch.
        // `pkg:alpm` (the SBOM-standard spelling) routes by namespace: an `aur`
        // namespace to the AUR RPC, any other (official repo) to archlinux.org.
        "aur" => aur(last_seg(&path), net, cache),
        "alpm" => match path.split_once('/') {
            Some(("aur", name)) => aur(name, net, cache),
            Some((_, name)) => arch(name, net, cache),
            None => arch(&path, net, cache),
        },
        // Distro registries with no JSON API: each metadata lookup fetches a
        // compressed index/catalog and scans it. See [`crate::distro`].
        "alpine" => distro::alpine(last_seg(&path), net, cache),
        "wolfi" => distro::wolfi(last_seg(&path), net, cache),
        "debian" => distro::debian(last_seg(&path), net, cache),
        "ubuntu" => distro::ubuntu(last_seg(&path), net, cache),
        "opensuse" => distro::opensuse(last_seg(&path), net, cache),
        "rpmfusion" => distro::rpmfusion(last_seg(&path), net, cache),
        "netbsd" => distro::netbsd(last_seg(&path), net, cache),
        "freebsd" => distro::freebsd(last_seg(&path), net, cache),
        "openbsd" => distro::openbsd(last_seg(&path), net, cache),
        // Package managers and app stores.
        "homebrew" => homebrew(last_seg(&path), net, cache),
        "snap" => snap(last_seg(&path), net, cache),
        "wordpress" => wordpress(last_seg(&path), net, cache),
        // Browser-extension / plugin marketplaces — the same listing shape as
        // the Chrome and VS Code stores (rating, downloads, recency).
        "firefox" => firefox(last_seg(&path), net, cache),
        "jetbrains" => jetbrains(last_seg(&path), net, cache),
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

/// Like [`registry`], but also returns the raw provider documents the lookup
/// consumed: the `(url, bytes)` of every metadata response it read, from the warm
/// cache or a fresh fetch. A consumer that archives provenance (scan's `--upload`)
/// keeps these as the re-parsing backup beside the normalized record, without
/// re-deriving which endpoints an ecosystem needs. The record is `None` on the
/// same conditions as [`registry`]; `sources` is then whatever was read before
/// the lookup gave up (often empty). Order matches read order — the primary
/// registry document first.
#[must_use]
pub fn registry_with_sources(
    locator: &RefLocator,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> (Option<Registry>, Vec<(String, Vec<u8>)>) {
    let (recording, sink) = cache.recording();
    let record = registry(locator, net, &recording);
    let sources = sink
        .lock()
        .map(|mut s| std::mem::take(&mut *s))
        .unwrap_or_default();
    (record, sources)
}

/// Split a PURL into `(type, name-path, version?)`, mirroring `fetch`'s
/// resolver: the version follows a literal `@` (a scope is `%40`).
fn parse_purl(purl: &str) -> Option<(String, String, Option<String>)> {
    let body = purl.strip_prefix("pkg:")?;
    let (ty, rest) = body.split_once('/')?;
    let (path, version) = rest
        .rsplit_once('@')
        .map_or((rest, None), |(p, v)| (p, Some(v.to_string())));
    // A registry record is the same whichever artifact a PURL `?qualifiers`
    // string selects (e.g. `?kind=wheel`), so drop it — a query string glued to
    // the version would otherwise corrupt the metadata API URL.
    let version = version.map(|v| match v.split_once('?') {
        Some((bare, _)) => bare.to_string(),
        None => v,
    });
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
        // npm always lists at least one maintainer for a live package, so a
        // missing/null/empty array is the anomaly itself — record it as zero
        // rather than "unknown" so a custody trait can fire on it.
        maintainers: Some(
            doc.get("maintainers")
                .and_then(Value::as_array)
                .map_or(0, |m| m.len() as u32),
        ),
        // npm replaces a taken-down malicious package with a stub whose
        // description is exactly `security holding package`. That tombstone is
        // the registry's own verdict — surface it.
        security_hold: Some(
            doc.get("description").and_then(Value::as_str)
                == Some("security holding package"),
        ),
        ..Default::default()
    };

    // Release timeline from the packument `time` map: every entry but the
    // `created`/`modified` bookkeeping keys is `version → publish time`. The
    // counts derive from this; `with_age` later turns it into the 24h/48h burst
    // metrics relative to the scan clock.
    if let Some(time) = doc.get("time").and_then(Value::as_object) {
        let mut times: Vec<u64> = time
            .iter()
            .filter(|(k, _)| k.as_str() != "created" && k.as_str() != "modified")
            .filter_map(|(_, v)| v.as_str().and_then(parse_rfc3339_secs))
            .collect();
        times.sort_unstable();
        p.release_count = Some(times.len() as u32);
        p.first_published_at = time
            .get("created")
            .and_then(Value::as_str)
            .and_then(parse_rfc3339_secs)
            .or_else(|| times.first().copied());
        if let Some(this) = p.published_at {
            p.previous_published_at = times.iter().copied().filter(|&t| t < this).max();
        }
        p.release_times = times;
    }

    // Custody: the account that pushed *this* version (`_npmUser`) and whether
    // it is among the listed maintainers — a publisher outside that set is the
    // account-takeover tell.
    let publisher = v
        .and_then(|v| v.pointer("/_npmUser/name"))
        .and_then(Value::as_str);
    p.publisher = publisher.map(str::to_string);
    p.publisher_email_domain = v
        .and_then(|v| v.pointer("/_npmUser/email"))
        .and_then(Value::as_str)
        .and_then(email_domain);
    if let Some(name) = publisher {
        p.publisher_in_maintainers = doc.get("maintainers").and_then(Value::as_array).map(|ms| {
            ms.iter()
                .any(|m| m.get("name").and_then(Value::as_str) == Some(name))
        });
    }

    // Artifact shape and the registry's own install-hook flag.
    p.unpacked_size = v
        .and_then(|v| v.pointer("/dist/unpackedSize"))
        .and_then(Value::as_u64);
    p.file_count = v
        .and_then(|v| v.pointer("/dist/fileCount"))
        .and_then(Value::as_u64)
        .map(|n| n as u32);
    p.has_install_script = v.map(|v| {
        v.get("hasInstallScript")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || v.get("scripts").and_then(Value::as_object).is_some_and(|s| {
                s.contains_key("install")
                    || s.contains_key("preinstall")
                    || s.contains_key("postinstall")
            })
    });

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

/// The domain half of an email address (`a@b.com` → `b.com`), lowercased.
/// `None` when there is no `@` or the domain is empty. Tolerates the
/// `Display Name <user@domain>` form PyPI uses by keeping only the leading run
/// of valid domain characters after the `@` (so a trailing `>` or comment is
/// dropped). A freemail/disposable domain behind a sensitive package is a weak
/// custody signal; the local-part is dropped so no per-user identifier is kept.
fn email_domain(email: &str) -> Option<String> {
    let after = email.rsplit_once('@')?.1;
    let domain: String = after
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-')
        .collect::<String>()
        .to_ascii_lowercase();
    (!domain.is_empty()).then_some(domain)
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

/// PyPI: the package-level JSON API carries the `info` block, the full
/// `releases` timeline (every version's files and upload times), `ownership`
/// (the owning accounts), and the version's known `vulnerabilities` — all in one
/// document, so the per-version endpoint is unnecessary. The requested version's
/// own publish time and yank status come from its `releases` entry; identity
/// text falls back to the latest release's `info`.
fn pypi(path: &str, version: Option<&str>, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    let doc: Value =
        serde_json::from_slice(&cached_metadata(&format!("https://pypi.org/pypi/{path}/json"), net, cache)?)
            .ok()?;
    let info = doc.get("info")?;
    let releases = doc.get("releases").and_then(Value::as_object);

    // Target version: the one requested, else the registry's latest.
    let latest = info.get("version").and_then(Value::as_str);
    let target = version.or(latest).unwrap_or_default();

    // The earliest upload across a version's files is its publish time. Prefer
    // the target version's files from `releases`; fall back to `urls` (the
    // latest version's files) when the timeline omits it.
    let publish_time = |files: &[Value]| {
        files
            .iter()
            .filter_map(|u| u.get("upload_time_iso_8601").and_then(Value::as_str))
            .filter_map(parse_rfc3339_secs)
            .min()
    };
    let target_files = releases
        .and_then(|r| r.get(target))
        .and_then(Value::as_array)
        .or_else(|| doc.get("urls").and_then(Value::as_array));
    let published_at = target_files.map(Vec::as_slice).and_then(publish_time);
    // Per-version yank status (a specific version can be yanked while latest is
    // not), with the per-version reason where the file records carry one.
    let yanked_reason = target_files.and_then(|fs| {
        fs.iter()
            .any(|f| f.get("yanked").and_then(Value::as_bool).unwrap_or(false))
            .then(|| {
                fs.iter()
                    .find_map(|f| f.get("yanked_reason").and_then(Value::as_str))
                    .unwrap_or("yanked")
                    .to_string()
            })
    });

    let mut p = Registry {
        ecosystem: "pypi".into(),
        name: path.to_string(),
        version: target.to_string(),
        published_at,
        latest_version: latest.map(str::to_string),
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
        deprecated: yanked_reason,
        vulnerability_count: doc
            .get("vulnerabilities")
            .and_then(Value::as_array)
            .map(|a| a.len() as u32),
        ..Default::default()
    };

    // Release timeline: one publish time per version (the earliest of its files).
    if let Some(rel) = releases {
        let mut times: Vec<u64> = rel
            .values()
            .filter_map(|files| files.as_array().and_then(|fs| publish_time(fs)))
            .collect();
        times.sort_unstable();
        p.release_count = Some(times.len() as u32);
        p.first_published_at = times.first().copied();
        if let Some(this) = p.published_at {
            p.previous_published_at = times.iter().copied().filter(|&t| t < this).max();
        }
        p.release_times = times;
    }

    // Custody: the owning account (PyPI exposes roles, not a per-version
    // publisher), and the email domain from the package's author/maintainer.
    p.publisher = doc
        .get("ownership")
        .and_then(|o| o.get("roles"))
        .and_then(Value::as_array)
        .and_then(|roles| {
            roles
                .iter()
                .find(|r| r.get("role").and_then(Value::as_str) == Some("Owner"))
                .or_else(|| roles.first())
        })
        .and_then(|r| r.get("user"))
        .and_then(Value::as_str)
        .map(str::to_string);
    p.publisher_email_domain = info
        .get("author_email")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .or_else(|| info.get("maintainer_email").and_then(Value::as_str))
        .and_then(email_domain);

    Some(p)
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
        // FirstSubmitted is the package's birth; the gap to LastModified is the
        // dormancy a revived abandoned package would show.
        first_published_at: r.get("FirstSubmitted").and_then(Value::as_u64),
        // The primary maintainer plus any co-maintainers — the custody set.
        maintainers: Some(
            u32::from(r.get("Maintainer").and_then(Value::as_str).is_some())
                + r.get("CoMaintainers")
                    .and_then(Value::as_array)
                    .map_or(0, |c| c.len() as u32),
        ),
        author: r
            .get("Maintainer")
            .and_then(Value::as_str)
            .map(str::to_string),
        publisher: r
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
        publisher: doc
            .pointer("/publishedBy/loginName")
            .and_then(Value::as_str)
            .map(str::to_string),
        // `allVersions` maps every published version to its URL — its size is the
        // release count, free in this one response (timestamps need the versions
        // endpoint). A `restricted` namespace is owner-controlled; a `public` one
        // is open for anyone to publish under, so it is *not* verified custody.
        release_count: doc
            .get("allVersions")
            .and_then(Value::as_object)
            .map(|v| v.len() as u32),
        publisher_verified: doc
            .get("namespaceAccess")
            .and_then(Value::as_str)
            .map(|a| a.eq_ignore_ascii_case("restricted")),
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
    // flags 403 = IncludeVersions(1) | IncludeFiles(2) | IncludeVersionProperties(16)
    // | IncludeAssetUri(128) | IncludeStatistics(256). Dropping IncludeLatestVersionOnly
    // (512, what 914 set) returns the *full* version array in the same request, so the
    // release timeline costs no extra round-trip; `versions[0]` is still the latest.
    let body = format!(
        r#"{{"filters":[{{"criteria":[{{"filterType":7,"value":"{ext_id}"}}]}}],"flags":403}}"#
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

    let mut p = Registry {
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
        // `publishedDate` is the extension's birth — the package-age signal.
        first_published_at: ext
            .get("publishedDate")
            .and_then(Value::as_str)
            .and_then(parse_rfc3339_secs),
        author: ext
            .pointer("/publisher/displayName")
            .and_then(Value::as_str)
            .map(str::to_string),
        // The unique publisher account, and whether the marketplace verified its
        // domain — an unverified publisher is one anyone could have registered.
        publisher: ext
            .pointer("/publisher/publisherName")
            .and_then(Value::as_str)
            .map(str::to_string),
        publisher_verified: ext.pointer("/publisher/isDomainVerified").and_then(Value::as_bool),
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
    };

    // The full version array (one entry per published version) yields the release
    // timeline — its size is the release count, and `with_age` turns the times
    // into the 24h/48h burst metrics.
    if let Some(versions) = ext.get("versions").and_then(Value::as_array) {
        let mut times: Vec<u64> = versions
            .iter()
            .filter_map(|v| v.get("lastUpdated").and_then(Value::as_str))
            .filter_map(parse_rfc3339_secs)
            .collect();
        times.sort_unstable();
        if !times.is_empty() {
            p.release_count = Some(times.len() as u32);
            if let Some(this) = p.published_at {
                p.previous_published_at = times.iter().copied().filter(|&t| t < this).max();
            }
            p.release_times = times;
        }
    }

    Some(p)
}

/// NuGet: the registration index is gzip-encoded (which this client doesn't
/// decode), so the uncompressed search API supplies the facts — version,
/// downloads, custody, links. It carries no publish time, so age stays unknown.
fn nuget(
    path: &str,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Option<Registry> {
    let id = path.to_lowercase();
    let doc: Value = serde_json::from_slice(&cached_metadata(
        &format!(
            "https://azuresearch-usnc.nuget.org/query?q=packageid:{id}&prerelease=true&semVerLevel=2.0.0"
        ),
        net,
        cache,
    )?)
    .ok()?;
    let d = doc.pointer("/data/0")?;
    let latest = d.get("version").and_then(Value::as_str);
    // Honor a requested version only if the registry lists it; metadata below is
    // the latest release's regardless (the search API exposes no per-version doc).
    let version = version
        .filter(|v| {
            d.get("versions")
                .and_then(Value::as_array)
                .is_some_and(|vs| {
                    vs.iter()
                        .any(|e| e.get("version").and_then(Value::as_str) == Some(*v))
                })
        })
        .or(latest)
        .unwrap_or_default();

    Some(Registry {
        ecosystem: "nuget".into(),
        name: d
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or(path)
            .to_string(),
        version: version.to_string(),
        latest_version: latest.map(str::to_string),
        author: d
            .pointer("/authors/0")
            .and_then(Value::as_str)
            .or_else(|| d.get("authors").and_then(Value::as_str))
            .map(str::to_string),
        description: d
            .get("description")
            .and_then(Value::as_str)
            .map(str::to_string),
        homepage: d
            .get("projectUrl")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        downloads_total: d.get("totalDownloads").and_then(Value::as_u64),
        ..Default::default()
    })
}

/// Maven Central: the solrsearch `gav` core returns one document per release
/// with its publish `timestamp` (ms). `path` is `<group>/<artifact>`; results
/// sort newest-first, so the first doc (or the version match) is the answer.
fn maven(
    path: &str,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Option<Registry> {
    let (group, artifact) = path.split_once('/')?;
    let mut q = format!("g:%22{group}%22+AND+a:%22{artifact}%22");
    if let Some(v) = version {
        q.push_str(&format!("+AND+v:%22{v}%22"));
    }
    let doc: Value = serde_json::from_slice(&cached_metadata(
        &format!("https://search.maven.org/solrsearch/select?q={q}&core=gav&rows=20&wt=json"),
        net,
        cache,
    )?)
    .ok()?;
    let d = doc.pointer("/response/docs/0")?;

    Some(Registry {
        ecosystem: "maven".into(),
        name: format!("{group}:{artifact}"),
        version: d
            .get("v")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        published_at: d
            .get("timestamp")
            .and_then(Value::as_u64)
            .map(|ms| ms / 1000),
        // With a version filter the result set is that one version, so "latest"
        // is only meaningful for an unversioned query.
        latest_version: if version.is_none() {
            d.get("v").and_then(Value::as_str).map(str::to_string)
        } else {
            None
        },
        ..Default::default()
    })
}

/// hex.pm: a clean JSON API. The package doc carries downloads and links; each
/// entry in the release list has its own `inserted_at` publish time.
fn hex_pm(
    name: &str,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Option<Registry> {
    let doc: Value = serde_json::from_slice(&cached_metadata(
        &format!("https://hex.pm/api/packages/{name}"),
        net,
        cache,
    )?)
    .ok()?;
    let latest = doc
        .get("latest_stable_version")
        .or_else(|| doc.get("latest_version"))
        .and_then(Value::as_str);
    let version = version.or(latest).unwrap_or_default();
    let published_at = doc
        .get("releases")
        .and_then(Value::as_array)
        .and_then(|rs| {
            rs.iter()
                .find(|r| r.get("version").and_then(Value::as_str) == Some(version))
                .or_else(|| rs.first())?
                .get("inserted_at")
                .and_then(Value::as_str)
                .and_then(parse_ts)
        })
        .or_else(|| {
            doc.get("inserted_at")
                .and_then(Value::as_str)
                .and_then(parse_ts)
        });
    let meta = doc.get("meta");

    Some(Registry {
        ecosystem: "hex".into(),
        name: name.to_string(),
        version: version.to_string(),
        published_at,
        latest_version: latest.map(str::to_string),
        description: meta
            .and_then(|m| m.get("description"))
            .and_then(Value::as_str)
            .map(str::to_string),
        license: meta
            .and_then(|m| m.pointer("/licenses/0"))
            .and_then(Value::as_str)
            .map(str::to_string),
        repository: meta.and_then(|m| m.get("links")).and_then(links_repo),
        downloads_total: doc.pointer("/downloads/all").and_then(Value::as_u64),
        downloads_recent: doc.pointer("/downloads/recent").and_then(Value::as_u64),
        ..Default::default()
    })
}

/// CRAN: the crandb mirror serves one JSON document per package with the
/// description, license, maintainer, and the `Date/Publication` of the release.
fn cran(name: &str, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    let doc: Value = serde_json::from_slice(&cached_metadata(
        &format!("https://crandb.r-pkg.org/{name}"),
        net,
        cache,
    )?)
    .ok()?;

    Some(Registry {
        ecosystem: "cran".into(),
        name: doc
            .get("Package")
            .and_then(Value::as_str)
            .unwrap_or(name)
            .to_string(),
        version: doc
            .get("Version")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        published_at: doc
            .get("Date/Publication")
            .and_then(Value::as_str)
            .and_then(parse_ts),
        author: doc
            .get("Maintainer")
            .and_then(Value::as_str)
            .map(strip_email),
        description: doc.get("Title").and_then(Value::as_str).map(str::to_string),
        homepage: doc.get("URL").and_then(Value::as_str).and_then(first_line),
        license: doc
            .get("License")
            .and_then(Value::as_str)
            .map(str::to_string),
        ..Default::default()
    })
}

/// CPAN: MetaCPAN's release endpoint returns the latest release of a
/// distribution with its date, author (PAUSE id), abstract, and resources.
fn cpan(dist: &str, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    let doc: Value = serde_json::from_slice(&cached_metadata(
        &format!("https://fastapi.metacpan.org/v1/release/{dist}"),
        net,
        cache,
    )?)
    .ok()?;

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

/// pub.dev: the package endpoint carries the latest release inline and every
/// version under `versions[]`, each with its `published` time and pubspec.
fn pub_dev(
    name: &str,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Option<Registry> {
    let doc: Value = serde_json::from_slice(&cached_metadata(
        &format!("https://pub.dev/api/packages/{name}"),
        net,
        cache,
    )?)
    .ok()?;
    let latest = doc.pointer("/latest/version").and_then(Value::as_str);
    let rel = match version.or(latest) {
        Some(w) => doc
            .get("versions")
            .and_then(Value::as_array)
            .and_then(|vs| {
                vs.iter()
                    .find(|v| v.get("version").and_then(Value::as_str) == Some(w))
            })
            .or_else(|| doc.get("latest")),
        None => doc.get("latest"),
    };
    let spec = rel.and_then(|r| r.get("pubspec"));

    Some(Registry {
        ecosystem: "pub".into(),
        name: name.to_string(),
        version: rel
            .and_then(|r| r.get("version"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        published_at: rel
            .and_then(|r| r.get("published"))
            .and_then(Value::as_str)
            .and_then(parse_ts),
        latest_version: latest.map(str::to_string),
        description: spec
            .and_then(|s| s.get("description"))
            .and_then(Value::as_str)
            .map(str::to_string),
        homepage: spec
            .and_then(|s| s.get("homepage"))
            .and_then(Value::as_str)
            .map(str::to_string),
        repository: spec
            .and_then(|s| s.get("repository"))
            .and_then(Value::as_str)
            .map(str::to_string),
        ..Default::default()
    })
}

/// conda (Anaconda.org, conda-forge channel): the package doc lists every file
/// with its upload time and downloads; the channel has no per-version record, so
/// the earliest upload of the matching version is its publish time.
fn conda(
    name: &str,
    version: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Option<Registry> {
    let doc: Value = serde_json::from_slice(&cached_metadata(
        &format!("https://api.anaconda.org/package/conda-forge/{name}"),
        net,
        cache,
    )?)
    .ok()?;
    let latest = doc.get("latest_version").and_then(Value::as_str);
    let version = version.or(latest).unwrap_or_default();
    let published_at = doc
        .get("files")
        .and_then(Value::as_array)
        .and_then(|fs| {
            fs.iter()
                .filter(|f| f.get("version").and_then(Value::as_str) == Some(version))
                .filter_map(|f| {
                    f.get("upload_time")
                        .and_then(Value::as_str)
                        .and_then(parse_ts)
                })
                .min()
        })
        .or_else(|| {
            doc.get("created_at")
                .and_then(Value::as_str)
                .and_then(parse_ts)
        });

    Some(Registry {
        ecosystem: "conda".into(),
        name: name.to_string(),
        version: version.to_string(),
        published_at,
        latest_version: latest.map(str::to_string),
        description: doc
            .get("summary")
            .and_then(Value::as_str)
            .map(str::to_string),
        homepage: doc.get("home").and_then(Value::as_str).map(str::to_string),
        repository: doc
            .get("source_git_url")
            .and_then(Value::as_str)
            .or_else(|| doc.get("dev_url").and_then(Value::as_str))
            .map(str::to_string),
        license: doc
            .get("license")
            .and_then(Value::as_str)
            .map(str::to_string),
        downloads_total: doc.get("ndownloads").and_then(Value::as_u64),
        ..Default::default()
    })
}

/// Clojars: the artifacts API returns lifetime downloads, the SCM link, and the
/// license, but no publish date — so `published_at` stays unknown.
fn clojars(path: &str, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    let doc: Value = serde_json::from_slice(&cached_metadata(
        &format!("https://clojars.org/api/artifacts/{path}"),
        net,
        cache,
    )?)
    .ok()?;
    let group = doc.get("group_name").and_then(Value::as_str);
    let jar = doc.get("jar_name").and_then(Value::as_str);
    let name = match (group, jar) {
        (Some(g), Some(j)) if g != j => format!("{g}/{j}"),
        (_, Some(j)) => j.to_string(),
        _ => path.to_string(),
    };

    Some(Registry {
        ecosystem: "clojars".into(),
        name,
        version: doc
            .get("latest_release")
            .or_else(|| doc.get("latest_version"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        latest_version: doc
            .get("latest_version")
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
            .pointer("/scm/url")
            .and_then(Value::as_str)
            .map(str::to_string),
        license: doc
            .pointer("/licenses/0/name")
            .and_then(Value::as_str)
            .map(str::to_string),
        downloads_total: doc.get("downloads").and_then(Value::as_u64),
        ..Default::default()
    })
}

/// JSR: the native API's package record (description, score, repo, latest) plus
/// the versions list (each with a `createdAt` publish time). `path` is the
/// `@scope/name` the locator carries, percent-encoded (`%40` is `@`).
fn jsr(path: &str, version: Option<&str>, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    let decoded = path.replace("%40", "@");
    let (scope, pkg) = decoded.trim_start_matches('@').split_once('/')?;
    let doc: Value = serde_json::from_slice(&cached_metadata(
        &format!("https://api.jsr.io/scopes/{scope}/packages/{pkg}"),
        net,
        cache,
    )?)
    .ok()?;
    let latest = doc.get("latestVersion").and_then(Value::as_str);
    let want = version.or(latest).unwrap_or_default();

    // Per-version publish time comes from the versions list.
    let published_at = cached_metadata(
        &format!("https://api.jsr.io/scopes/{scope}/packages/{pkg}/versions"),
        net,
        cache,
    )
    .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
    .and_then(|vs| {
        let arr = vs.as_array()?;
        arr.iter()
            .find(|v| v.get("version").and_then(Value::as_str) == Some(want))
            .or_else(|| arr.first())?
            .get("createdAt")
            .and_then(Value::as_str)
            .and_then(parse_ts)
    });
    let repository = doc.get("githubRepository").and_then(|g| {
        let owner = g.get("owner").and_then(Value::as_str)?;
        let repo = g.get("name").and_then(Value::as_str)?;
        Some(format!("https://github.com/{owner}/{repo}"))
    });

    Some(Registry {
        ecosystem: "jsr".into(),
        name: format!("@{scope}/{pkg}"),
        version: want.to_string(),
        published_at,
        latest_version: latest.map(str::to_string),
        description: doc
            .get("description")
            .and_then(Value::as_str)
            .map(str::to_string),
        repository,
        // JSR's 0–100 quality score is its popularity analogue.
        rating: doc.get("score").and_then(Value::as_f64).map(|f| f as f32),
        ..Default::default()
    })
}

/// Arch Linux official repositories: the packages site exposes a JSON search.
/// Recency comes from `last_update`; an out-of-date flag is the deprecation
/// analogue. AUR-only packages aren't here, so they return `None`.
fn arch(name: &str, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    let doc: Value = serde_json::from_slice(&cached_metadata(
        &format!("https://archlinux.org/packages/search/json/?name={name}"),
        net,
        cache,
    )?)
    .ok()?;
    let r = doc.pointer("/results/0")?;
    let version = match (
        r.get("pkgver").and_then(Value::as_str),
        r.get("pkgrel").and_then(Value::as_str),
    ) {
        (Some(v), Some(rel)) => format!("{v}-{rel}"),
        (Some(v), None) => v.to_string(),
        _ => String::new(),
    };

    Some(Registry {
        ecosystem: "arch".into(),
        name: r
            .get("pkgname")
            .and_then(Value::as_str)
            .unwrap_or(name)
            .to_string(),
        version,
        published_at: r
            .get("last_update")
            .and_then(Value::as_str)
            .or_else(|| r.get("build_date").and_then(Value::as_str))
            .and_then(parse_ts),
        author: r
            .get("packager")
            .and_then(Value::as_str)
            .map(str::to_string),
        description: r.get("pkgdesc").and_then(Value::as_str).map(str::to_string),
        homepage: r.get("url").and_then(Value::as_str).map(str::to_string),
        license: r
            .pointer("/licenses/0")
            .and_then(Value::as_str)
            .map(str::to_string),
        maintainers: r
            .get("maintainers")
            .and_then(Value::as_array)
            .map(|m| m.len() as u32),
        deprecated: r
            .get("flag_date")
            .and_then(Value::as_str)
            .map(|_| "flagged out-of-date".to_string()),
        ..Default::default()
    })
}

/// Fedora (Rawhide via mdapi): the per-package record carries the version,
/// summary, and homepage. mdapi reports no build time, so age stays unknown.
fn fedora(name: &str, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    let doc: Value = serde_json::from_slice(&cached_metadata(
        &format!("https://mdapi.fedoraproject.org/rawhide/pkg/{name}"),
        net,
        cache,
    )?)
    .ok()?;
    let version = match (
        doc.get("version").and_then(Value::as_str),
        doc.get("release").and_then(Value::as_str),
    ) {
        (Some(v), Some(rel)) => format!("{v}-{rel}"),
        (Some(v), None) => v.to_string(),
        _ => String::new(),
    };

    Some(Registry {
        ecosystem: "fedora".into(),
        name: doc
            .get("basename")
            .and_then(Value::as_str)
            .unwrap_or(name)
            .to_string(),
        version,
        description: doc
            .get("summary")
            .and_then(Value::as_str)
            .or_else(|| doc.get("description").and_then(Value::as_str))
            .map(str::to_string),
        homepage: doc.get("url").and_then(Value::as_str).map(str::to_string),
        license: doc
            .get("license")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        ..Default::default()
    })
}

/// Homebrew: the formula JSON carries the stable version, description, license,
/// and 30-day install analytics. It records no publish date.
fn homebrew(name: &str, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    let doc: Value = serde_json::from_slice(&cached_metadata(
        &format!("https://formulae.brew.sh/api/formula/{name}.json"),
        net,
        cache,
    )?)
    .ok()?;

    Some(Registry {
        ecosystem: "homebrew".into(),
        name: doc
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or(name)
            .to_string(),
        version: doc
            .pointer("/versions/stable")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        description: doc.get("desc").and_then(Value::as_str).map(str::to_string),
        homepage: doc
            .get("homepage")
            .and_then(Value::as_str)
            .map(str::to_string),
        license: doc
            .get("license")
            .and_then(Value::as_str)
            .map(str::to_string),
        // The 30-day analytics map counts installs per invocation; sum them.
        downloads_recent: doc
            .pointer("/analytics/install/30d")
            .and_then(Value::as_object)
            .map(|m| m.values().filter_map(Value::as_u64).sum::<u64>()),
        deprecated: deprecation_flag(&doc, "deprecated", "deprecated")
            .or_else(|| deprecation_flag(&doc, "disabled", "disabled")),
        ..Default::default()
    })
}

/// Snap Store: the v2 info endpoint (which requires the `Snap-Device-Series`
/// header) returns the publisher and per-channel releases. The latest stable
/// channel's release time and version are the supply-chain-relevant facts.
fn snap(name: &str, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
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

/// WordPress plugin directory: the info API carries installs, rating (0–100),
/// the author (as an HTML anchor), and the last-updated date.
fn wordpress(slug: &str, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    let doc: Value = serde_json::from_slice(&cached_metadata(
        &format!("https://api.wordpress.org/plugins/info/1.0/{slug}.json"),
        net,
        cache,
    )?)
    .ok()?;

    Some(Registry {
        ecosystem: "wordpress".into(),
        name: doc
            .get("slug")
            .and_then(Value::as_str)
            .unwrap_or(slug)
            .to_string(),
        version: doc
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        // `last_updated` is `2026-04-23 10:34pm GMT`; keep the date.
        published_at: doc
            .get("last_updated")
            .and_then(Value::as_str)
            .and_then(parse_ymd),
        author: doc.get("author").and_then(Value::as_str).map(strip_html),
        title: doc.get("name").and_then(Value::as_str).map(str::to_string),
        homepage: doc
            .get("homepage")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        downloads_total: doc.get("downloaded").and_then(Value::as_u64),
        // The directory reports rating as a 0–100 percentage; scale to 5 stars.
        rating: doc
            .get("rating")
            .and_then(Value::as_f64)
            .map(|r| (r / 20.0) as f32),
        rating_count: doc.get("num_ratings").and_then(Value::as_u64),
        ..Default::default()
    })
}

/// Firefox Add-ons (addons.mozilla.org v5): the same marketplace shape as the
/// Chrome and VS Code stores — localized name/summary, rating, weekly installs,
/// and the current version with its review date.
fn firefox(slug: &str, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    let doc: Value = serde_json::from_slice(&cached_metadata(
        &format!("https://addons.mozilla.org/api/v5/addons/addon/{slug}/"),
        net,
        cache,
    )?)
    .ok()?;

    let mut p = Registry {
        ecosystem: "firefox".into(),
        name: doc
            .get("slug")
            .and_then(Value::as_str)
            .unwrap_or(slug)
            .to_string(),
        version: doc
            .pointer("/current_version/version")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        // `reviewed` (the current version's approval) is the supply-chain recency.
        published_at: doc
            .pointer("/current_version/reviewed")
            .and_then(Value::as_str)
            .or_else(|| doc.get("last_updated").and_then(Value::as_str))
            .and_then(parse_ts),
        // `created` is the add-on's first listing — the package-age signal.
        first_published_at: doc.get("created").and_then(Value::as_str).and_then(parse_ts),
        author: doc
            .pointer("/authors/0/name")
            .and_then(Value::as_str)
            .map(str::to_string),
        // The author set is the custody signal AMO exposes.
        maintainers: doc
            .get("authors")
            .and_then(Value::as_array)
            .map(|a| a.len() as u32),
        title: doc.get("name").and_then(localized),
        description: doc.get("summary").and_then(localized),
        homepage: doc.pointer("/homepage/url").and_then(localized),
        license: doc
            .pointer("/current_version/license/name")
            .and_then(localized),
        // `average_daily_users` is the install base (a lifetime-reach analogue);
        // `weekly_downloads` stays the recent-window figure.
        downloads_total: doc.get("average_daily_users").and_then(Value::as_u64),
        downloads_recent: doc.get("weekly_downloads").and_then(Value::as_u64),
        rating: doc
            .pointer("/ratings/average")
            .and_then(Value::as_f64)
            .map(|f| f as f32),
        rating_count: doc.pointer("/ratings/count").and_then(Value::as_u64),
        deprecated: deprecation_flag(&doc, "is_disabled", "disabled"),
        ..Default::default()
    };

    // One extra GET to the versions endpoint yields the release timeline (each
    // version's `reviewed` approval time) for the cadence metrics. Best-effort:
    // a failure leaves the package-age signal (from `created`) intact.
    if let Some(versions) = cached_metadata(
        &format!("https://addons.mozilla.org/api/v5/addons/addon/{slug}/versions/?page_size=50"),
        net,
        cache,
    )
    .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
    .and_then(|d| d.get("results").and_then(Value::as_array).cloned())
    {
        let mut times: Vec<u64> = versions
            .iter()
            .filter_map(|v| {
                v.get("reviewed")
                    .or_else(|| v.get("created"))
                    .and_then(Value::as_str)
                    .and_then(parse_ts)
            })
            .collect();
        times.sort_unstable();
        if !times.is_empty() {
            p.release_count = Some(times.len() as u32);
            if let Some(this) = p.published_at {
                p.previous_published_at = times.iter().copied().filter(|&t| t < this).max();
            }
            p.release_times = times;
        }
    }

    Some(p)
}

/// JetBrains Marketplace: resolve the plugin id (numeric, or an `xmlId` via
/// search), then read its listing plus latest update — the same marketplace
/// shape as the editor stores (rating, downloads, the update's publish date).
fn jetbrains(path: &str, net: &dyn Fetch, cache: &BlobCache) -> Option<Registry> {
    // A numeric path is the plugin id directly; otherwise resolve the xmlId.
    let id = if !path.is_empty() && path.bytes().all(|b| b.is_ascii_digit()) {
        path.to_string()
    } else {
        let search: Value = serde_json::from_slice(&cached_metadata(
            &format!("https://plugins.jetbrains.com/api/searchPlugins?search={path}&max=20"),
            net,
            cache,
        )?)
        .ok()?;
        search
            .get("plugins")
            .and_then(Value::as_array)?
            .iter()
            .find(|p| p.get("xmlId").and_then(Value::as_str) == Some(path))
            .and_then(|p| p.get("id"))
            .and_then(Value::as_u64)?
            .to_string()
    };
    let doc: Value = serde_json::from_slice(&cached_metadata(
        &format!("https://plugins.jetbrains.com/api/plugins/{id}"),
        net,
        cache,
    )?)
    .ok()?;
    // The latest update carries the released version and its publish time.
    let updates = cached_metadata(
        &format!("https://plugins.jetbrains.com/api/plugins/{id}/updates?size=1"),
        net,
        cache,
    )
    .and_then(|b| serde_json::from_slice::<Value>(&b).ok());
    let update = updates
        .as_ref()
        .and_then(|u| u.as_array())
        .and_then(|a| a.first());

    Some(Registry {
        ecosystem: "jetbrains".into(),
        name: doc
            .get("xmlId")
            .and_then(Value::as_str)
            .unwrap_or(path)
            .to_string(),
        version: update
            .and_then(|u| u.get("version"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        published_at: update.and_then(|u| u.get("cdate")).and_then(parse_millis),
        // `vendor` is a bare string here, an object in search results.
        author: doc.get("vendor").and_then(|v| {
            v.as_str()
                .map(str::to_string)
                .or_else(|| v.get("name").and_then(Value::as_str).map(str::to_string))
        }),
        title: doc.get("name").and_then(Value::as_str).map(str::to_string),
        description: doc
            .get("preview")
            .and_then(Value::as_str)
            .map(str::to_string),
        homepage: doc
            .pointer("/urls/url")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        repository: doc
            .pointer("/urls/sourceCodeUrl")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        downloads_total: doc.get("downloads").and_then(Value::as_u64),
        rating: doc.get("rating").and_then(Value::as_f64).map(|f| f as f32),
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

/// The final path segment — the bare package name, dropping any vendor/namespace
/// prefix an OS-package locator carries (`pkg:aur/foo`, `pkg:alpm/arch/foo`).
fn last_seg(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// A boolean deprecation flag → its `label` when set, else `None`.
fn deprecation_flag(doc: &Value, key: &str, label: &str) -> Option<String> {
    doc.get(key)
        .and_then(Value::as_bool)
        .and_then(|f| f.then(|| label.to_string()))
}

/// Resolve an addons.mozilla.org localized field: a bare string, or a
/// `{ lang: text }` map from which `en-US` (else any non-empty value) is taken.
fn localized(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => (!s.is_empty()).then(|| s.clone()),
        Value::Object(map) => map
            .get("en-US")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .or_else(|| {
                map.values()
                    .filter_map(Value::as_str)
                    .find(|s| !s.is_empty())
            })
            .map(str::to_string),
        _ => None,
    }
}

/// Pick a source-repository URL from a registry's free-form links map (hex.pm),
/// preferring a forge link, else any value.
fn links_repo(links: &Value) -> Option<String> {
    let map = links.as_object()?;
    for key in [
        "GitHub",
        "Github",
        "github",
        "GitLab",
        "Repository",
        "Source",
    ] {
        if let Some(u) = map.get(key).and_then(Value::as_str) {
            return Some(u.to_string());
        }
    }
    map.values()
        .filter_map(Value::as_str)
        .next()
        .map(str::to_string)
}

/// `Name <email>` → `Name`; a bare name is returned unchanged.
fn strip_email(s: &str) -> String {
    s.split('<').next().unwrap_or(s).trim().to_string()
}

/// Drop HTML tags from a one-line field (WordPress wraps the author in an `<a>`).
fn strip_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.trim().to_string()
}

/// The first non-empty line, trimmed — CRAN crowds several URLs into one field.
fn first_line(s: &str) -> Option<String> {
    s.lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(str::to_string)
}

/// Unix-millis (a JSON string or number, as JetBrains emits) → Unix seconds.
fn parse_millis(v: &Value) -> Option<u64> {
    let ms = match v {
        Value::String(s) => s.parse::<u64>().ok()?,
        Value::Number(n) => n.as_u64()?,
        _ => return None,
    };
    Some(ms / 1000)
}

/// Parse a registry timestamp, tolerating a trailing zone word (`… UTC`, `…
/// GMT`) that crandb and others append: retry on just the `YYYY-…-SS` core,
/// which such a suffix always denotes as UTC.
pub(crate) fn parse_ts(s: &str) -> Option<u64> {
    parse_rfc3339_secs(s).or_else(|| s.get(..19).and_then(parse_rfc3339_secs))
}

/// Parse a leading `YYYY-MM-DD` to Unix seconds at UTC midnight, ignoring any
/// trailing time/zone text (`2026-04-23 10:34pm GMT`).
fn parse_ymd(s: &str) -> Option<u64> {
    let y: i64 = s.get(0..4)?.parse().ok()?;
    let m: i64 = s.get(5..7)?.parse().ok()?;
    let d: i64 = s.get(8..10)?.parse().ok()?;
    u64::try_from(days_from_civil(y, m, d) * 86_400).ok()
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
            "time": {
                "created": "2019-01-01T00:00:00.000Z",
                "modified": "2021-04-23T10:00:00.000Z",
                "1.0.0": "2019-01-01T00:00:00.000Z",
                "1.2.0": "2021-04-22T10:00:00.000Z",
                "1.3.0": "2021-04-23T10:00:00.000Z"
            },
            "versions": {
                "1.3.0": {
                    "description": "pad it",
                    "homepage": "https://example.test",
                    "license": "MIT",
                    "repository": {"url": "git+https://github.test/x.git"},
                    "_npmUser": {"name": "mallory", "email": "mallory@gmail.com"},
                    "dist": {"unpackedSize": 4096, "fileCount": 7},
                    "scripts": {"postinstall": "node steal.js"}
                }
            }
        })
        .to_string();
        let net =
            Fixtures::default().with("https://registry.npmjs.org/left-pad", packument.as_bytes());
        let cache = BlobCache::disabled();
        let p = npm("left-pad", Some("1.3.0"), &net, &cache).expect("provenance");
        assert_eq!(p.ecosystem, "npm");
        assert_eq!(p.published_at, Some(1_619_172_000));
        assert_eq!(p.latest_version.as_deref(), Some("1.3.0"));
        assert_eq!(p.author.as_deref(), Some("Una"));
        assert_eq!(p.license.as_deref(), Some("MIT"));
        assert_eq!(p.maintainers, Some(2));
        // Release history: three versions, born at `time.created`, prior release
        // is 1.2.0 (the latest strictly before this one).
        assert_eq!(p.release_count, Some(3));
        assert_eq!(p.first_published_at, Some(1_546_300_800)); // 2019-01-01
        assert_eq!(p.previous_published_at, Some(1_619_085_600)); // 2021-04-22
        assert_eq!(p.release_times.len(), 3);
        // Custody: the publisher of this version is NOT a listed maintainer.
        assert_eq!(p.publisher.as_deref(), Some("mallory"));
        assert_eq!(p.publisher_email_domain.as_deref(), Some("gmail.com"));
        assert_eq!(p.publisher_in_maintainers, Some(false));
        // Artifact shape + the postinstall hook.
        assert_eq!(p.unpacked_size, Some(4096));
        assert_eq!(p.file_count, Some(7));
        assert_eq!(p.has_install_script, Some(true));
        // A normal package is not a security-hold tombstone.
        assert_eq!(p.security_hold, Some(false));
    }

    #[test]
    fn npm_maintainerless_and_security_hold_tombstone() {
        // A taken-down package: npm's stub description, and a null maintainers
        // field (a live npm package always lists at least one).
        let stub = serde_json::json!({
            "dist-tags": {"latest": "0.0.1-security"},
            "description": "security holding package",
            "maintainers": serde_json::Value::Null,
            "time": {"0.0.1-security": "2026-06-20T00:00:00.000Z"},
            "versions": {"0.0.1-security": {"description": "security holding package"}}
        })
        .to_string();
        let net = Fixtures::default().with("https://registry.npmjs.org/evilpkg", stub.as_bytes());
        let p = npm("evilpkg", Some("0.0.1-security"), &net, &BlobCache::disabled())
            .expect("provenance");
        assert_eq!(p.security_hold, Some(true), "npm tombstone description detected");
        assert_eq!(p.maintainers, Some(0), "null maintainers recorded as zero, not unknown");
    }

    #[test]
    fn pypi_releases_yield_cadence_and_custody() {
        let doc = serde_json::json!({
            "info": {
                "version": "0.3.0",
                "summary": "a tool",
                "author_email": "Huw <huw@evil.example>",
                "license": "MIT"
            },
            "ownership": {"organization": null, "roles": [{"role": "Owner", "user": "hoo29"}]},
            "vulnerabilities": [{"id": "PYSEC-1"}],
            "urls": [
                {"packagetype": "sdist", "upload_time_iso_8601": "2021-04-23T10:00:00Z", "yanked": false}
            ],
            "releases": {
                "0.1.0": [{"upload_time_iso_8601": "2021-01-01T00:00:00Z", "yanked": false}],
                "0.2.0": [{"upload_time_iso_8601": "2021-04-22T10:00:00Z", "yanked": false}],
                "0.3.0": [{"upload_time_iso_8601": "2021-04-23T10:00:00Z", "yanked": false}]
            }
        })
        .to_string();
        let net = Fixtures::default().with("https://pypi.org/pypi/widget/json", doc.as_bytes());
        let cache = BlobCache::disabled();
        let p = pypi("widget", Some("0.3.0"), &net, &cache).expect("provenance");

        assert_eq!(p.ecosystem, "pypi");
        assert_eq!(p.version, "0.3.0");
        assert_eq!(p.published_at, Some(1_619_172_000)); // 2021-04-23
        assert_eq!(p.latest_version.as_deref(), Some("0.3.0"));
        // Cadence from the full `releases` timeline.
        assert_eq!(p.release_count, Some(3));
        assert_eq!(p.first_published_at, Some(1_609_459_200)); // 2021-01-01
        assert_eq!(p.previous_published_at, Some(1_619_085_600)); // 2021-04-22
        // Custody: the owning account, and the domain from the author email
        // (the `Name <user@domain>` form is parsed cleanly).
        assert_eq!(p.publisher.as_deref(), Some("hoo29"));
        assert_eq!(p.publisher_email_domain.as_deref(), Some("evil.example"));
        assert_eq!(p.vulnerability_count, Some(1));
        // PyPI exposes no per-version publisher account or unpacked size.
        assert_eq!(p.publisher_in_maintainers, None);
        assert_eq!(p.unpacked_size, None);
    }

    #[test]
    fn aur_rpc_maps_votes_and_modified() {
        let rpc = serde_json::json!({
            "resultcount": 1,
            "results": [{
                "Name": "yay", "Version": "12.0.0-1", "Description": "AUR helper",
                "URL": "https://github.test/yay", "Maintainer": "jverify",
                "CoMaintainers": ["alice", "bob"],
                "NumVotes": 1234, "Popularity": 42.5,
                "FirstSubmitted": 1_600_000_000u64, "LastModified": 1_619_172_000u64,
                "OutOfDate": serde_json::Value::Null
            }]
        })
        .to_string();
        let net = Fixtures::default().with(
            "https://aur.archlinux.org/rpc/v5/info?arg%5B%5D=yay",
            rpc.as_bytes(),
        );
        let cache = BlobCache::disabled();
        let p = aur("yay", &net, &cache).expect("provenance");
        assert_eq!(p.ecosystem, "aur");
        assert_eq!(p.published_at, Some(1_619_172_000));
        assert_eq!(p.first_published_at, Some(1_600_000_000));
        // Primary maintainer + two co-maintainers = a custody set of three.
        assert_eq!(p.maintainers, Some(3));
        assert_eq!(p.author.as_deref(), Some("jverify"));
        assert_eq!(p.publisher.as_deref(), Some("jverify"));
        assert_eq!(p.rating, Some(42.5));
        assert_eq!(p.rating_count, Some(1234));
        assert_eq!(p.deprecated, None);
    }

    #[test]
    fn unsupported_locator_is_none() {
        let net = Fixtures::default();
        let cache = BlobCache::disabled();
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
        let cache = BlobCache::disabled();
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
        let cache = BlobCache::disabled();
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
        let cache = BlobCache::disabled();
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
                "publisher": {"displayName": "Red Hat", "publisherName": "redhat", "isDomainVerified": true},
                "publishedDate": "2017-01-01T00:00:00Z",
                "lastUpdated": "2026-06-23T09:30:32.957Z",
                "versions": [
                    {"version": "1.55.0", "lastUpdated": "2026-06-23T09:30:32.957Z"},
                    {"version": "1.54.0", "lastUpdated": "2026-06-20T09:30:32.957Z"},
                    {"version": "1.53.0", "lastUpdated": "2026-05-01T09:30:32.957Z"}
                ],
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
        let cache = BlobCache::disabled();
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
        // Custody + history: verified publisher domain, first-seen date, and the
        // full three-version timeline (with the prior release before this one).
        assert_eq!(r.publisher.as_deref(), Some("redhat"));
        assert_eq!(r.publisher_verified, Some(true));
        assert!(r.first_published_at.is_some());
        assert_eq!(r.release_count, Some(3));
        assert_eq!(r.release_times.len(), 3);
        assert_eq!(r.previous_published_at, parse_rfc3339_secs("2026-06-20T09:30:32.957Z"));
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
        let cache = BlobCache::disabled();
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
        let cache = BlobCache::disabled();
        let r = chrome(id, &net, &cache).expect("registry");
        assert_eq!(r.ecosystem, "chrome");
        assert_eq!(r.title.as_deref(), Some("社媒助手 - 数据采集工具"));
        assert_eq!(r.downloads_total, Some(40_000));
        assert_eq!(r.rating, Some(4.9));
        assert_eq!(r.rating_count, Some(122));
        assert_eq!(r.published_at, Some(1_780_963_200));
        assert!(r.description.is_some_and(|d| d.contains("数据采集")));
    }

    /// Build a fresh temp-dir blob cache keyed by a per-test name, purging any
    /// entry a prior run left behind so a changed fixture is never masked by a
    /// stale cached response.
    fn test_cache(_name: &str) -> BlobCache {
        // Hermetic: an inert cache so every lookup goes straight to the fixture,
        // with no shared on-disk state across tests or runs.
        BlobCache::disabled()
    }

    #[test]
    fn nuget_search_normalizes() {
        let doc = serde_json::json!({"data": [{
            "id": "Newtonsoft.Json", "version": "13.0.3",
            "description": "Json.NET", "authors": ["James Newton-King"],
            "projectUrl": "https://www.newtonsoft.com/json",
            "totalDownloads": 8_537_565_389u64,
            "versions": [{"version": "13.0.3"}, {"version": "13.0.2"}]
        }]})
        .to_string();
        let net = Fixtures::default().with(
            "https://azuresearch-usnc.nuget.org/query?q=packageid:newtonsoft.json&prerelease=true&semVerLevel=2.0.0",
            doc.as_bytes(),
        );
        let r = nuget("Newtonsoft.Json", None, &net, &test_cache("nuget")).expect("registry");
        assert_eq!(r.ecosystem, "nuget");
        assert_eq!(r.name, "Newtonsoft.Json");
        assert_eq!(r.version, "13.0.3");
        assert_eq!(r.author.as_deref(), Some("James Newton-King"));
        assert_eq!(r.downloads_total, Some(8_537_565_389));
        assert_eq!(r.published_at, None); // search API carries no publish time
    }

    #[test]
    fn maven_solrsearch_normalizes() {
        let doc = serde_json::json!({"response": {"docs": [
            {"g": "com.google.guava", "a": "guava", "v": "33.4.8-jre", "timestamp": 1_619_172_000_000u64}
        ]}})
        .to_string();
        let net = Fixtures::default().with(
            "https://search.maven.org/solrsearch/select?q=g:%22com.google.guava%22+AND+a:%22guava%22&core=gav&rows=20&wt=json",
            doc.as_bytes(),
        );
        let r =
            maven("com.google.guava/guava", None, &net, &test_cache("maven")).expect("registry");
        assert_eq!(r.ecosystem, "maven");
        assert_eq!(r.name, "com.google.guava:guava");
        assert_eq!(r.version, "33.4.8-jre");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(r.latest_version.as_deref(), Some("33.4.8-jre"));
    }

    #[test]
    fn hex_api_normalizes() {
        let doc = serde_json::json!({
            "latest_stable_version": "1.20.1",
            "downloads": {"all": 159_722_813u64, "recent": 3_812_427u64},
            "meta": {"description": "Compose web applications", "licenses": ["Apache-2.0"],
                     "links": {"GitHub": "https://github.com/elixir-plug/plug"}},
            "releases": [{"version": "1.20.1", "inserted_at": "2021-04-23T10:00:00.000000Z"}]
        })
        .to_string();
        let net = Fixtures::default().with("https://hex.pm/api/packages/plug", doc.as_bytes());
        let r = hex_pm("plug", None, &net, &test_cache("hex")).expect("registry");
        assert_eq!(r.ecosystem, "hex");
        assert_eq!(r.version, "1.20.1");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(r.license.as_deref(), Some("Apache-2.0"));
        assert_eq!(
            r.repository.as_deref(),
            Some("https://github.com/elixir-plug/plug")
        );
        assert_eq!(r.downloads_total, Some(159_722_813));
    }

    #[test]
    fn cran_crandb_normalizes() {
        let doc = serde_json::json!({
            "Package": "jsonlite", "Version": "2.0.0",
            "Title": "A Simple and Robust JSON Parser", "License": "MIT + file LICENSE",
            "Maintainer": "Jeroen Ooms <jeroenooms@gmail.com>",
            "URL": "https://jeroen.r-universe.dev/jsonlite\nhttps://arxiv.org/abs/1403.2805",
            "Date/Publication": "2021-04-23 10:00:00 UTC"
        })
        .to_string();
        let net = Fixtures::default().with("https://crandb.r-pkg.org/jsonlite", doc.as_bytes());
        let r = cran("jsonlite", &net, &test_cache("cran")).expect("registry");
        assert_eq!(r.ecosystem, "cran");
        assert_eq!(r.version, "2.0.0");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(r.author.as_deref(), Some("Jeroen Ooms"));
        assert_eq!(
            r.homepage.as_deref(),
            Some("https://jeroen.r-universe.dev/jsonlite")
        );
    }

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

    #[test]
    fn pub_dev_normalizes() {
        let doc = serde_json::json!({
            "name": "http",
            "latest": {"version": "1.6.0", "published": "2021-04-23T10:00:00.000000Z",
                       "pubspec": {"description": "Future-based HTTP requests",
                                   "repository": "https://github.com/dart-lang/http"}},
            "versions": [{"version": "1.6.0", "published": "2021-04-23T10:00:00.000000Z",
                          "pubspec": {"description": "Future-based HTTP requests",
                                      "repository": "https://github.com/dart-lang/http"}}]
        })
        .to_string();
        let net = Fixtures::default().with("https://pub.dev/api/packages/http", doc.as_bytes());
        let r = pub_dev("http", None, &net, &test_cache("pub")).expect("registry");
        assert_eq!(r.ecosystem, "pub");
        assert_eq!(r.version, "1.6.0");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(
            r.repository.as_deref(),
            Some("https://github.com/dart-lang/http")
        );
    }

    #[test]
    fn conda_anaconda_normalizes() {
        let doc = serde_json::json!({
            "latest_version": "1.9.3", "summary": "Scientific computing",
            "license": "BSD-3-Clause", "home": "https://numpy.org",
            "dev_url": "https://github.com/numpy/numpy", "source_git_url": null,
            "ndownloads": 138_106_777u64,
            "files": [{"version": "1.9.3", "upload_time": "2021-04-23T10:00:00.000Z"}]
        })
        .to_string();
        let net = Fixtures::default().with(
            "https://api.anaconda.org/package/conda-forge/numpy",
            doc.as_bytes(),
        );
        let r = conda("numpy", None, &net, &test_cache("conda")).expect("registry");
        assert_eq!(r.ecosystem, "conda");
        assert_eq!(r.version, "1.9.3");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(
            r.repository.as_deref(),
            Some("https://github.com/numpy/numpy")
        );
        assert_eq!(r.downloads_total, Some(138_106_777));
    }

    #[test]
    fn clojars_artifacts_normalizes() {
        let doc = serde_json::json!({
            "group_name": "ring", "jar_name": "ring", "latest_release": "1.15.5",
            "latest_version": "1.15.5", "description": "A Clojure web library",
            "homepage": "https://github.com/ring-clojure/ring", "downloads": 11_285_905u64,
            "scm": {"url": "https://github.com/ring-clojure/ring"},
            "licenses": [{"name": "The MIT License"}]
        })
        .to_string();
        let net =
            Fixtures::default().with("https://clojars.org/api/artifacts/ring", doc.as_bytes());
        let r = clojars("ring", &net, &test_cache("clojars")).expect("registry");
        assert_eq!(r.ecosystem, "clojars");
        assert_eq!(r.name, "ring");
        assert_eq!(r.version, "1.15.5");
        assert_eq!(r.license.as_deref(), Some("The MIT License"));
        assert_eq!(r.downloads_total, Some(11_285_905));
        assert_eq!(r.published_at, None);
    }

    #[test]
    fn jsr_api_normalizes() {
        let pkg = serde_json::json!({
            "scope": "std", "name": "path", "description": "File-path utilities",
            "latestVersion": "1.1.5", "score": 100,
            "githubRepository": {"owner": "denoland", "name": "std"}
        })
        .to_string();
        let versions = serde_json::json!([
            {"version": "1.1.5", "createdAt": "2021-04-23T10:00:00.000Z", "yanked": false}
        ])
        .to_string();
        let net = Fixtures::default()
            .with(
                "https://api.jsr.io/scopes/std/packages/path",
                pkg.as_bytes(),
            )
            .with(
                "https://api.jsr.io/scopes/std/packages/path/versions",
                versions.as_bytes(),
            );
        let r = jsr("%40std/path", None, &net, &test_cache("jsr")).expect("registry");
        assert_eq!(r.ecosystem, "jsr");
        assert_eq!(r.name, "@std/path");
        assert_eq!(r.version, "1.1.5");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(
            r.repository.as_deref(),
            Some("https://github.com/denoland/std")
        );
        assert_eq!(r.rating, Some(100.0));
    }

    #[test]
    fn arch_packages_normalizes() {
        let doc = serde_json::json!({"results": [{
            "pkgname": "pacman", "pkgver": "7.1.0", "pkgrel": "2",
            "pkgdesc": "A library-based package manager", "url": "https://archlinux.org/pacman/",
            "licenses": ["GPL-2.0-or-later"], "packager": "eworm",
            "maintainers": ["anthraxx", "Foxboron"],
            "last_update": "2021-04-23T10:00:00.379Z", "flag_date": null
        }]})
        .to_string();
        let net = Fixtures::default().with(
            "https://archlinux.org/packages/search/json/?name=pacman",
            doc.as_bytes(),
        );
        let r = arch("pacman", &net, &test_cache("arch")).expect("registry");
        assert_eq!(r.ecosystem, "arch");
        assert_eq!(r.version, "7.1.0-2");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(r.author.as_deref(), Some("eworm"));
        assert_eq!(r.maintainers, Some(2));
        assert_eq!(r.deprecated, None);
    }

    #[test]
    fn fedora_mdapi_normalizes() {
        let doc = serde_json::json!({
            "basename": "curl", "version": "8.21.0", "release": "3.fc45",
            "summary": "A command line tool for transferring data", "license": "curl",
            "url": "https://curl.se/"
        })
        .to_string();
        let net = Fixtures::default().with(
            "https://mdapi.fedoraproject.org/rawhide/pkg/curl",
            doc.as_bytes(),
        );
        let r = fedora("curl", &net, &test_cache("fedora")).expect("registry");
        assert_eq!(r.ecosystem, "fedora");
        assert_eq!(r.version, "8.21.0-3.fc45");
        assert_eq!(r.homepage.as_deref(), Some("https://curl.se/"));
        assert_eq!(r.published_at, None);
    }

    #[test]
    fn homebrew_formula_normalizes() {
        let doc = serde_json::json!({
            "name": "wget", "desc": "Internet file retriever",
            "homepage": "https://www.gnu.org/software/wget/", "license": "GPL-3.0-or-later",
            "versions": {"stable": "1.25.0"}, "deprecated": false, "disabled": false,
            "analytics": {"install": {"30d": {"wget": 20_568u64, "wget --HEAD": 26u64}}}
        })
        .to_string();
        let net = Fixtures::default().with(
            "https://formulae.brew.sh/api/formula/wget.json",
            doc.as_bytes(),
        );
        let r = homebrew("wget", &net, &test_cache("homebrew")).expect("registry");
        assert_eq!(r.ecosystem, "homebrew");
        assert_eq!(r.version, "1.25.0");
        assert_eq!(r.license.as_deref(), Some("GPL-3.0-or-later"));
        assert_eq!(r.downloads_recent, Some(20_594));
        assert_eq!(r.deprecated, None);
    }

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

    #[test]
    fn wordpress_plugin_normalizes() {
        let doc = serde_json::json!({
            "name": "Akismet Anti-spam", "slug": "akismet", "version": "5.7",
            "author": "<a href=\"https://profiles.wordpress.org/automattic/\">Automattic</a>",
            "homepage": "https://akismet.com/", "last_updated": "2021-04-23 10:34pm GMT",
            "downloaded": 395_330_422u64, "rating": 94, "num_ratings": 1184
        })
        .to_string();
        let net = Fixtures::default().with(
            "https://api.wordpress.org/plugins/info/1.0/akismet.json",
            doc.as_bytes(),
        );
        let r = wordpress("akismet", &net, &test_cache("wordpress")).expect("registry");
        assert_eq!(r.ecosystem, "wordpress");
        assert_eq!(r.version, "5.7");
        assert_eq!(r.author.as_deref(), Some("Automattic"));
        assert_eq!(r.published_at, Some(1_619_136_000)); // date floored to UTC midnight
        assert_eq!(r.downloads_total, Some(395_330_422));
        assert_eq!(r.rating, Some(4.7));
        assert_eq!(r.rating_count, Some(1184));
    }

    #[test]
    fn firefox_amo_normalizes() {
        let doc = serde_json::json!({
            "slug": "ublock-origin",
            "name": {"en-US": "uBlock Origin"}, "summary": {"en-US": "An efficient blocker"},
            "homepage": {"url": {"en-US": "https://github.com/gorhill/uBlock"}},
            "authors": [{"name": "Raymond Hill"}, {"name": "co-author"}],
            "created": "2015-04-25T07:26:22Z",
            "ratings": {"average": 4.7997, "count": 21_850u64},
            "weekly_downloads": 123_456u64, "average_daily_users": 8_000_000u64,
            "is_disabled": false,
            "current_version": {"version": "1.66.4", "reviewed": "2021-04-23T10:00:00Z",
                                "license": {"name": {"en-US": "GPL-3.0-only"}}}
        })
        .to_string();
        // The versions endpoint (one extra GET) supplies the release timeline.
        let versions = serde_json::json!({
            "results": [
                {"version": "1.66.4", "reviewed": "2021-04-23T10:00:00Z"},
                {"version": "1.66.3", "reviewed": "2021-04-20T10:00:00Z"},
                {"version": "1.66.2", "reviewed": "2021-03-01T10:00:00Z"}
            ]
        })
        .to_string();
        let net = Fixtures::default()
            .with(
                "https://addons.mozilla.org/api/v5/addons/addon/ublock-origin/",
                doc.as_bytes(),
            )
            .with(
                "https://addons.mozilla.org/api/v5/addons/addon/ublock-origin/versions/?page_size=50",
                versions.as_bytes(),
            );
        let r = firefox("ublock-origin", &net, &test_cache("firefox")).expect("registry");
        assert_eq!(r.ecosystem, "firefox");
        assert_eq!(r.title.as_deref(), Some("uBlock Origin"));
        assert_eq!(r.version, "1.66.4");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(
            r.homepage.as_deref(),
            Some("https://github.com/gorhill/uBlock")
        );
        assert_eq!(r.license.as_deref(), Some("GPL-3.0-only"));
        assert_eq!(r.rating, Some(4.7997));
        assert_eq!(r.rating_count, Some(21_850));
        // New: first-listing date, install base, author count, release timeline.
        assert!(r.first_published_at.is_some()); // `created`
        assert_eq!(r.downloads_total, Some(8_000_000)); // average_daily_users
        assert_eq!(r.maintainers, Some(2)); // two authors
        assert_eq!(r.release_count, Some(3));
        assert_eq!(r.previous_published_at, parse_rfc3339_secs("2021-04-20T10:00:00Z"));
    }

    #[test]
    fn jetbrains_plugin_normalizes() {
        let plugin = serde_json::json!({
            "id": 22407, "xmlId": "com.jetbrains.rust", "name": "Rust",
            "preview": "Rust support", "vendor": "JetBrains s.r.o.",
            "downloads": 1_964_675u64, "rating": 2.78,
            "urls": {"url": "", "sourceCodeUrl": "https://github.com/intellij-rust/intellij-rust"}
        })
        .to_string();
        let updates = serde_json::json!([
            {"version": "262.8117.29", "cdate": "1619172000000"}
        ])
        .to_string();
        let net = Fixtures::default()
            .with(
                "https://plugins.jetbrains.com/api/plugins/22407",
                plugin.as_bytes(),
            )
            .with(
                "https://plugins.jetbrains.com/api/plugins/22407/updates?size=1",
                updates.as_bytes(),
            );
        let r = jetbrains("22407", &net, &test_cache("jetbrains")).expect("registry");
        assert_eq!(r.ecosystem, "jetbrains");
        assert_eq!(r.name, "com.jetbrains.rust");
        assert_eq!(r.version, "262.8117.29");
        assert_eq!(r.published_at, Some(1_619_172_000));
        assert_eq!(r.author.as_deref(), Some("JetBrains s.r.o."));
        assert_eq!(
            r.repository.as_deref(),
            Some("https://github.com/intellij-rust/intellij-rust")
        );
        assert_eq!(r.downloads_total, Some(1_964_675));
    }

    #[test]
    fn alpm_namespace_routes_aur_vs_official() {
        // `pkg:alpm/aur/<name>` → AUR RPC; any other namespace → official repos.
        let aur_rpc = serde_json::json!({
            "resultcount": 1,
            "results": [{"Name": "yay", "Version": "12.0.0-1", "Maintainer": "jverify",
                         "LastModified": 1_619_172_000u64, "OutOfDate": serde_json::Value::Null}]
        })
        .to_string();
        let arch_json = serde_json::json!({"results": [{
            "pkgname": "pacman", "pkgver": "7.1.0", "pkgrel": "2", "packager": "eworm",
            "last_update": "2021-04-23T10:00:00Z"
        }]})
        .to_string();
        let net = Fixtures::default()
            .with(
                "https://aur.archlinux.org/rpc/v5/info?arg%5B%5D=yay",
                aur_rpc.as_bytes(),
            )
            .with(
                "https://archlinux.org/packages/search/json/?name=pacman",
                arch_json.as_bytes(),
            );
        let cache = test_cache("alpm");
        let from_aur = registry(&RefLocator::Purl("pkg:alpm/aur/yay".into()), &net, &cache)
            .expect("aur registry");
        assert_eq!(from_aur.ecosystem, "aur");
        let from_official = registry(
            &RefLocator::Purl("pkg:alpm/core/pacman".into()),
            &net,
            &cache,
        )
        .expect("arch registry");
        assert_eq!(from_official.ecosystem, "arch");
    }
}
