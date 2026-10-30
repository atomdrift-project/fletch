//! End-to-end resolution through the per-ecosystem table: each test drives
//! [`resolve`], [`resolve_artifacts`] or [`fetch_ref`] for one ecosystem
//! against canned registry documents, so the table, the ecosystem's resolver
//! and the fetch path are exercised together.

use filefacts::RefLocator;

use super::record::tests::dep;
use super::resolve::tests::resolved;
use super::*;
use crate::ecosystem::pypi::pypi_artifacts;
use crate::purl::Purl;

/// `raw`'s artifact matrix, asked of `net`.
fn matrix(raw: &str, net: &dyn Fetch) -> ArtifactMatrix {
    resolve_artifacts(&RefLocator::Purl(raw.into()), net, &BlobCache::disabled()).expect("matrix")
}

// ---------------------------------------------------------------------------
// Ecosystem resolvers: npm
// ---------------------------------------------------------------------------

#[test]
fn resolve_npm_unversioned_picks_latest_tarball() {
    // The packument names a current release; resolution refines the
    // versionless locator to it and returns the registry's tarball URL.
    let packument = br#"{
        "dist-tags": { "latest": "1.12.0", "next": "2.0.0-beta.1" },
        "versions": {
            "1.11.21": { "dist": { "tarball": "https://registry.npmjs.org/easy-day-js/-/easy-day-js-1.11.21.tgz" } },
            "1.12.0":  { "dist": { "tarball": "https://registry.npmjs.org/easy-day-js/-/easy-day-js-1.12.0.tgz" } },
            "2.0.0-beta.1": { "dist": { "tarball": "https://registry.npmjs.org/easy-day-js/-/easy-day-js-2.0.0-beta.1.tgz" } }
        }
    }"#;
    let net = Fixtures::default().with("https://registry.npmjs.org/easy-day-js", packument);
    assert_eq!(
        resolved("pkg:npm/easy-day-js", &net, &BlobCache::disabled()),
        Some((
            "pkg:npm/easy-day-js@1.12.0".to_string(),
            "https://registry.npmjs.org/easy-day-js/-/easy-day-js-1.12.0.tgz".to_string()
        ))
    );
    assert_eq!(
        resolved("pkg:npm/easy-day-js@next", &net, &BlobCache::disabled()),
        Some((
            "pkg:npm/easy-day-js@2.0.0-beta.1".into(),
            "https://registry.npmjs.org/easy-day-js/-/easy-day-js-2.0.0-beta.1.tgz".into(),
        ))
    );
    // Scoped name: the `%40` encoding survives into the refined locator.
    let scoped = br#"{"dist-tags":{"latest":"2.0.0"},"versions":{"2.0.0":{"dist":{"tarball":"https://registry.npmjs.org/@scope/util/-/util-2.0.0.tgz"}}}}"#;
    let net = Fixtures::default().with("https://registry.npmjs.org/@scope/util", scoped);
    assert_eq!(
        resolved("pkg:npm/%40scope/util", &net, &BlobCache::disabled()),
        Some((
            "pkg:npm/%40scope/util@2.0.0".to_string(),
            "https://registry.npmjs.org/@scope/util/-/util-2.0.0.tgz".to_string()
        ))
    );
    // Registry unreachable / unknown package → unresolved.
    assert_eq!(
        resolved("pkg:npm/nope", &Fixtures::default(), &BlobCache::disabled()),
        None
    );
}

#[test]
fn npm_artifact_matrix_keeps_runtime_compatibility_modifiers() {
    let packument = br#"{
        "versions": {"1.2.3": {
            "os": ["linux", "darwin"], "cpu": ["x64", "arm64"],
            "libc": "glibc", "engines": {"node": ">=20"},
            "dist": {
                "tarball": "https://registry.npmjs.org/native-addon/-/native-addon-1.2.3.tgz",
                "shasum": "0123456789abcdef",
                "integrity": "sha512-Zm9v"
            }
        }}
    }"#;
    let net = Fixtures::default().with("https://registry.npmjs.org/native-addon", packument);
    let matrix = matrix("pkg:npm/native-addon@1.2.3", &net);
    assert_eq!(matrix.candidates.len(), 1);
    let candidate = matrix.preferred().expect("preferred");
    assert_eq!(candidate.file_name, "native-addon-1.2.3.tgz");
    assert_eq!(candidate.kind, ArtifactKind::Tgz);
    assert_eq!(
        candidate.attributes.get("os").map(String::as_str),
        Some("linux,darwin")
    );
    assert_eq!(
        candidate.attributes.get("cpu").map(String::as_str),
        Some("x64,arm64")
    );
    assert_eq!(
        candidate.attributes.get("libc").map(String::as_str),
        Some("glibc")
    );
    assert_eq!(
        candidate.attributes.get("node").map(String::as_str),
        Some(">=20")
    );
    assert_eq!(
        candidate.checksums.get("sha1").map(String::as_str),
        Some("0123456789abcdef")
    );
}

#[test]
fn npm_matrix_never_invents_unknown_versions_or_ranges() {
    let body = br#"{"dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"dist":{"tarball":"https://x/pkg-1.0.0.tgz"}}}}"#;
    let net = Fixtures::default().with("https://registry.npmjs.org/pkg", body);
    for purl in [
        "pkg:npm/pkg@9.9.9",
        "pkg:npm/pkg@1.x",
        "pkg:npm/pkg@%3E%3D1",
    ] {
        let matrix =
            resolve_artifacts(&RefLocator::Purl(purl.into()), &net, &BlobCache::disabled())
                .expect("npm matrix");
        assert!(matrix.candidates.is_empty(), "{purl}");
    }
}

#[test]
fn npm_integrity_is_promoted_to_a_hex_checksum() {
    let body = br#"{"versions":{"1.0.0":{"dist":{"tarball":"https://x/pkg.tgz","integrity":"sha512-Zm9v"}}}}"#;
    let net = Fixtures::default().with("https://registry.npmjs.org/pkg", body);
    let matrix = matrix("pkg:npm/pkg@1.0.0", &net);
    assert_eq!(
        matrix.candidates[0]
            .checksums
            .get("sha512")
            .map(String::as_str),
        Some("666f6f")
    );
}

// ---------------------------------------------------------------------------
// Ecosystem resolvers: PyPI
// ---------------------------------------------------------------------------

/// PyPI publishes no deterministic download URL (the `files.pythonhosted.org`
/// path carries an undrivable hash segment), so ask the JSON API and pick an
/// artifact from the version's files.
///
/// Default is wheel-first with an sdist fallback, mirroring what a modern `pip
/// install` actually runs on the victim's machine; `?kind=sdist` flips the
/// preference to the source distribution (one per version, carrying `setup.py` /
/// `pyproject.toml` — the install-hook attack surface), and `?kind=wheel` is the
/// default's explicit form. Whichever is preferred, the other is the fallback so
/// a package that ships only one kind still resolves.
fn resolve_pypi(
    name: &str,
    version: &str,
    kind: Option<&str>,
    net: &dyn Fetch,
    cache: &BlobCache,
) -> Option<String> {
    let rest = kind.map_or_else(
        || format!("{name}@{version}"),
        |value| format!("{name}@{version}?kind={value}"),
    );
    let purl = Purl::parse(&format!("pkg:pypi/{rest}")).ok()?;
    pypi_artifacts(&crate::ecosystem::Coordinates::new(&purl).ok()?, net, cache)
        .ok()?
        .into_iter()
        .find(|candidate| candidate.preferred)
        .map(|candidate| candidate.url)
}

#[test]
fn resolve_pypi_defaults_to_wheel_with_sdist_fallback() {
    let api = "https://pypi.org/pypi/requests/2.28.1/json";
    let body = br#"{"urls":[
        {"packagetype":"bdist_wheel","filename":"requests-2.28.1-py3-none-any.whl","url":"https://files.pythonhosted.org/w/requests-2.28.1-py3-none-any.whl"},
        {"packagetype":"sdist","filename":"requests-2.28.1.tar.gz","url":"https://files.pythonhosted.org/s/requests-2.28.1.tar.gz"}
    ]}"#;
    let net = Fixtures::default().with(api, body);
    let wheel = "https://files.pythonhosted.org/w/requests-2.28.1-py3-none-any.whl".to_string();
    let sdist = "https://files.pythonhosted.org/s/requests-2.28.1.tar.gz".to_string();
    // A disabled cache forces the fixture fetch, keeping the test hermetic.
    let cache = BlobCache::disabled();
    // Default: wheel-first, mirroring `pip install`.
    assert_eq!(
        resolve_pypi("requests", "2.28.1", None, &net, &cache),
        Some(wheel.clone())
    );
    // `?kind=wheel` is the default's explicit form.
    assert_eq!(
        resolve_pypi("requests", "2.28.1", Some("wheel"), &net, &cache),
        Some(wheel)
    );
    // `?kind=sdist` flips to the source distribution.
    assert_eq!(
        resolve_pypi("requests", "2.28.1", Some("sdist"), &net, &cache),
        Some(sdist)
    );
    // No fixture (registry unreachable / unknown package) → unresolved.
    assert_eq!(
        resolve_pypi("nope", "9.9.9", None, &Fixtures::default(), &cache),
        None
    );
}

#[test]
fn resolve_pypi_picks_universal_wheel_and_falls_back_each_way() {
    // A compiled package: many platform wheels plus the universal one. The
    // universal `py3-none-any` wheel must win over the platform wheels.
    let api = "https://pypi.org/pypi/widget/1.0.0/json";
    let body = br#"{"urls":[
        {"packagetype":"bdist_wheel","filename":"widget-1.0.0-cp311-cp311-manylinux_x86_64.whl","url":"https://x/plat.whl"},
        {"packagetype":"bdist_wheel","filename":"widget-1.0.0-py3-none-any.whl","url":"https://x/universal.whl"},
        {"packagetype":"sdist","filename":"widget-1.0.0.tar.gz","url":"https://x/widget.tar.gz"}
    ]}"#;
    let net = Fixtures::default().with(api, body);
    let cache = BlobCache::disabled();
    assert_eq!(
        resolve_pypi("widget", "1.0.0", None, &net, &cache),
        Some("https://x/universal.whl".to_string())
    );
    assert_eq!(
        resolve_pypi("widget", "1.0.0", Some("wheel"), &net, &cache),
        Some("https://x/universal.whl".to_string())
    );
    assert_eq!(
        resolve_pypi("widget", "1.0.0", Some("sdist"), &net, &cache),
        Some("https://x/widget.tar.gz".to_string())
    );

    // The middle rank: no `py3-none-any`, but a non-py3 universal wheel
    // (`py2.py3-none-any`) is still platform-agnostic and must beat the
    // platform wheels — and must lose to `py3-none-any` when both exist.
    // Listed after the platform wheel so passing cannot be an artifact of
    // input order.
    let mid = "https://pypi.org/pypi/midwidget/1.0.0/json";
    let mbody = br#"{"urls":[
        {"packagetype":"bdist_wheel","filename":"midwidget-1.0.0-cp311-cp311-manylinux_x86_64.whl","url":"https://x/plat.whl"},
        {"packagetype":"bdist_wheel","filename":"midwidget-1.0.0-py2.py3-none-any.whl","url":"https://x/universal2.whl"}
    ]}"#;
    let net = Fixtures::default().with(mid, mbody);
    assert_eq!(
        resolve_pypi("midwidget", "1.0.0", None, &net, &cache),
        Some("https://x/universal2.whl".to_string())
    );

    // sdist-only version: wheel-first default falls back to the sdist.
    let sonly = "https://pypi.org/pypi/srconly/1.0.0/json";
    let sbody = br#"{"urls":[{"packagetype":"sdist","filename":"srconly-1.0.0.tar.gz","url":"https://x/src.tar.gz"}]}"#;
    let net = Fixtures::default().with(sonly, sbody);
    assert_eq!(
        resolve_pypi("srconly", "1.0.0", None, &net, &cache),
        Some("https://x/src.tar.gz".to_string())
    );

    // wheel-only version: explicit `kind=sdist` falls back to the wheel.
    let wonly = "https://pypi.org/pypi/wheelonly/1.0.0/json";
    let wbody = br#"{"urls":[{"packagetype":"bdist_wheel","filename":"wheelonly-1.0.0-py3-none-any.whl","url":"https://x/w.whl"}]}"#;
    let net = Fixtures::default().with(wonly, wbody);
    assert_eq!(
        resolve_pypi("wheelonly", "1.0.0", Some("sdist"), &net, &cache),
        Some("https://x/w.whl".to_string())
    );
}

#[test]
fn pypi_artifact_matrix_exposes_file_and_wheel_tag_dimensions() {
    let api = "https://pypi.org/pypi/widget/1.0.0/json";
    let body = br#"{"urls":[
        {"packagetype":"sdist","filename":"widget-1.0.0.tar.gz","url":"https://x/widget-1.0.0.tar.gz","digests":{"sha256":"srcsha"}},
        {"packagetype":"bdist_wheel","filename":"widget-1.0.0-2-cp313-cp313-musllinux_1_2_aarch64.whl","url":"https://x/widget-musl.whl","python_version":"cp313","requires_python":">=3.10","yanked":true,"yanked_reason":"bad build","digests":{"sha256":"muslsha","blake2b_256":"blake"}},
        {"packagetype":"bdist_wheel","filename":"widget-1.0.0-cp313-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl","url":"https://x/widget-linux.whl"},
        {"packagetype":"bdist_wheel","filename":"widget-1.0.0-py3-none-any.whl","url":"https://x/widget-any.whl"}
    ]}"#;
    let net = Fixtures::default().with(api, body);
    let cache = BlobCache::disabled();
    let matrix = resolve_artifacts(
        &RefLocator::Purl("pkg:pypi/widget@1.0.0".into()),
        &net,
        &cache,
    )
    .expect("matrix");
    assert_eq!(matrix.candidates.len(), 4);
    assert_eq!(
        matrix.preferred().map(|value| value.file_name.as_str()),
        Some("widget-1.0.0-py3-none-any.whl")
    );
    let musl = matrix
        .candidates
        .iter()
        .find(|candidate| candidate.file_name.contains("musllinux"))
        .expect("musl wheel");
    assert_eq!(
        musl.qualifiers.get("file_name").map(String::as_str),
        Some("widget-1.0.0-2-cp313-cp313-musllinux_1_2_aarch64.whl")
    );
    assert_eq!(musl.attributes.get("build").map(String::as_str), Some("2"));
    assert_eq!(
        musl.attributes.get("yanked_reason").map(String::as_str),
        Some("bad build")
    );
    assert_eq!(
        musl.checksums.get("blake2b-256").map(String::as_str),
        Some("blake")
    );
    assert_eq!(
        musl.attributes.get("python").map(String::as_str),
        Some("cp313")
    );
    assert_eq!(
        musl.attributes.get("abi").map(String::as_str),
        Some("cp313")
    );
    assert_eq!(
        musl.attributes.get("platform").map(String::as_str),
        Some("musllinux_1_2_aarch64")
    );

    let exact = "widget-1.0.0-cp313-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl";
    let purl = format!("pkg:pypi/widget@1.0.0?file_name={exact}");
    let selected =
        resolve_artifacts(&RefLocator::Purl(purl.clone()), &net, &cache).expect("selected matrix");
    assert_eq!(
        selected.preferred().map(|value| value.file_name.as_str()),
        Some(exact)
    );
    assert_eq!(
        resolved(&purl, &net, &cache).map(|(_, url)| url),
        Some("https://x/widget-linux.whl".into())
    );

    let missing = resolve_artifacts(
        &RefLocator::Purl("pkg:pypi/widget@1.0.0?file_name=missing.whl".into()),
        &net,
        &cache,
    )
    .expect("unselected matrix");
    assert!(missing.preferred().is_none());
}

#[test]
fn pypi_platform_wheels_do_not_beat_a_portable_sdist_without_a_target() {
    let api = "https://pypi.org/pypi/native/1.0/json";
    let body = br#"{"urls":[
        {"packagetype":"bdist_wheel","filename":"native-1.0-cp313-cp313-macosx_14_0_arm64.whl","url":"https://x/mac.whl"},
        {"packagetype":"bdist_wheel","filename":"native-1.0-cp313-cp313-manylinux_2_17_x86_64.whl","url":"https://x/linux.whl"},
        {"packagetype":"sdist","filename":"native-1.0.tar.gz","url":"https://x/native.tar.gz"}
    ]}"#;
    let net = Fixtures::default().with(api, body);
    let matrix = matrix("pkg:pypi/native@1.0", &net);
    assert_eq!(
        matrix
            .preferred()
            .map(|candidate| candidate.file_name.as_str()),
        Some("native-1.0.tar.gz")
    );
}

#[test]
fn pypi_yanked_universal_wheel_does_not_beat_a_healthy_sdist() {
    let api = "https://pypi.org/pypi/yanked/1.0/json";
    let body = br#"{"urls":[
        {"packagetype":"bdist_wheel","filename":"yanked-1.0-py3-none-any.whl","url":"https://x/yanked.whl","yanked":true},
        {"packagetype":"sdist","filename":"yanked-1.0.tar.gz","url":"https://x/healthy.tar.gz"}
    ]}"#;
    let net = Fixtures::default().with(api, body);
    let matrix = matrix("pkg:pypi/yanked@1.0", &net);
    assert_eq!(
        matrix.preferred().map(|candidate| candidate.url.as_str()),
        Some("https://x/healthy.tar.gz")
    );
}

// ---------------------------------------------------------------------------
// Ecosystem resolvers: RubyGems and Cargo
// ---------------------------------------------------------------------------

#[test]
fn gem_artifact_matrix_exposes_every_published_platform() {
    let versions = br#"[
        {"number":"1.19.4","platform":"x86_64-linux-musl","sha":"muslsha","ruby_version":">= 3.1"},
        {"number":"1.19.4","platform":"ruby","sha":"rubysha"},
        {"number":"1.19.4","platform":"arm64-darwin","sha":"darwinsha"},
        {"number":"1.19.4","platform":"../../not-a-platform","sha":"badsha"},
        {"number":"1.19.3","platform":"ruby","sha":"oldsha"}
    ]"#;
    let net = Fixtures::default().with(
        "https://rubygems.org/api/v1/versions/nokogiri.json",
        versions,
    );
    let cache = BlobCache::disabled();
    let base = resolve_artifacts(
        &RefLocator::Purl("pkg:gem/nokogiri@1.19.4".into()),
        &net,
        &cache,
    )
    .expect("matrix");
    assert_eq!(base.candidates.len(), 3);
    assert_eq!(
        base.preferred().map(|value| value.file_name.as_str()),
        Some("nokogiri-1.19.4.gem")
    );

    let native = resolve_artifacts(
        &RefLocator::Purl("pkg:gem/nokogiri@1.19.4?platform=x86_64-linux-musl".into()),
        &net,
        &cache,
    )
    .expect("native matrix");
    let selected = native.preferred().expect("native preferred");
    assert_eq!(selected.file_name, "nokogiri-1.19.4-x86_64-linux-musl.gem");
    assert_eq!(
        selected.qualifiers.get("platform").map(String::as_str),
        Some("x86_64-linux-musl")
    );
    assert_eq!(
        selected.checksums.get("sha256").map(String::as_str),
        Some("muslsha")
    );
}

#[test]
fn gem_without_a_ruby_build_has_no_targetless_preference() {
    let body = br#"[{"number":"1.0","platform":"x86_64-linux"},{"number":"1.0","platform":"arm64-darwin"}]"#;
    let net = Fixtures::default().with("https://rubygems.org/api/v1/versions/native.json", body);
    let matrix = matrix("pkg:gem/native@1.0", &net);
    assert!(matrix.preferred().is_none());
}

#[test]
fn cargo_checksum_template_uses_the_sparse_index_record() {
    let repository = "https://cargo.example.test/index";
    let config =
        br#"{"dl":"https://cargo.example.test/files/{crate}/{version}/{sha256-checksum}.crate"}"#;
    let index = br#"{"name":"serde","vers":"1.0.0","cksum":"abc123"}"#;
    let net = Fixtures::default()
        .with(&format!("{repository}/config.json"), config)
        .with(&format!("{repository}/se/rd/serde"), index);
    let matrix = resolve_artifacts(
        &RefLocator::Purl(
            "pkg:cargo/serde@1.0.0?repository_url=https:%2F%2Fcargo.example.test%2Findex".into(),
        ),
        &net,
        &BlobCache::disabled(),
    )
    .expect("cargo matrix");
    let candidate = matrix.preferred().expect("cargo artifact");
    assert_eq!(
        candidate.url,
        "https://cargo.example.test/files/serde/1.0.0/abc123.crate"
    );
    assert_eq!(
        candidate.checksums.get("sha256").map(String::as_str),
        Some("abc123")
    );
}

// ---------------------------------------------------------------------------
// Ecosystem resolvers: Terraform
// ---------------------------------------------------------------------------

/// The registry's download API for one Terraform provider platform.
fn terraform_download(os: &str, arch: &str, bytes: &[u8]) -> (String, String) {
    let file = format!("terraform-provider-docker_3.0.2_{os}_{arch}.zip");
    let url = format!(
        "https://github.com/kreuzwerker/terraform-provider-docker/releases/download/v3.0.2/{file}"
    );
    let info = serde_json::json!({
        "os": os, "arch": arch, "filename": file, "download_url": url,
        "shasum": sha256_hex(bytes).to_ascii_uppercase(),
    });
    (info.to_string(), url)
}

const TERRAFORM_DOCKER: &str = "https://registry.terraform.io/v1/providers/kreuzwerker/docker";

#[test]
fn terraform_fetch_verifies_the_registry_shasum() {
    let (info, zip) = terraform_download("linux", "amd64", b"ZIP");
    let api = format!("{TERRAFORM_DOCKER}/3.0.2/download/linux/amd64");
    let net = Fixtures::default()
        .with(&api, info.as_bytes())
        .with(&zip, b"ZIP");
    let cache = BlobCache::disabled();
    // A mixed-case address is the same provider.
    let reference = dep(
        RefLocator::Purl("pkg:terraform/Kreuzwerker/Docker@3.0.2".into()),
        None,
    );
    let rec = fetch_ref(&reference, &net, &cache);
    assert_eq!(rec.outcome, Outcome::Ok);
    assert_eq!(rec.resolved_url.as_deref(), Some(&*zip));
    assert_eq!(
        rec.locator,
        format!(
            "pkg:terraform/kreuzwerker/docker@3.0.2?checksum=sha256:{}\
             &file_name=terraform-provider-docker_3.0.2_linux_amd64.zip",
            sha256_hex(b"ZIP")
        )
    );

    // Bytes that disagree with the registry's shasum are a finding.
    let net = Fixtures::default()
        .with(&api, info.as_bytes())
        .with(&zip, b"SUBSTITUTED");
    let rec = fetch_ref(&reference, &net, &cache);
    assert_eq!(rec.outcome, Outcome::PinMismatch);

    // Without a well-formed shasum nothing can be verified: refuse.
    let unsigned = info.replace(&sha256_hex(b"ZIP").to_ascii_uppercase(), "abc");
    let net = Fixtures::default()
        .with(&api, unsigned.as_bytes())
        .with(&zip, b"ZIP");
    assert_eq!(
        fetch_ref(&reference, &net, &cache).outcome,
        Outcome::Unresolved(Unresolved::NoRelease)
    );
}

#[test]
fn terraform_falls_back_to_the_first_listed_platform() {
    let (info, zip) = terraform_download("darwin", "arm64", b"ZIP");
    let versions = serde_json::json!({"versions": [
        {"version": "3.0.1", "platforms": [{"os": "linux", "arch": "amd64"}]},
        {"version": "3.0.2", "platforms": [
            {"os": "darwin", "arch": "arm64"}, {"os": "windows", "arch": "amd64"}
        ]},
    ]})
    .to_string();
    let net = Fixtures::default()
        .refusing(
            &format!("{TERRAFORM_DOCKER}/3.0.2/download/linux/amd64"),
            404,
        )
        .with(&format!("{TERRAFORM_DOCKER}/versions"), versions.as_bytes())
        .with(
            &format!("{TERRAFORM_DOCKER}/3.0.2/download/darwin/arm64"),
            info.as_bytes(),
        );
    let cache = BlobCache::disabled();
    let locator = "pkg:terraform/kreuzwerker/docker@3.0.2";
    let (exact, url) = resolved(locator, &net, &cache).unwrap();
    assert_eq!(url, zip);
    assert!(exact.ends_with("&file_name=terraform-provider-docker_3.0.2_darwin_arm64.zip"));

    // Only a 404 means "no such platform"; an unreachable registry is not
    // a reason to pick a different build.
    let net = Fixtures::default()
        .with(&format!("{TERRAFORM_DOCKER}/versions"), versions.as_bytes())
        .with(
            &format!("{TERRAFORM_DOCKER}/3.0.2/download/darwin/arm64"),
            info.as_bytes(),
        );
    assert_eq!(resolved(locator, &net, &cache), None);
}

#[test]
fn terraform_versionless_resolves_the_current_release() {
    let (info, zip) = terraform_download("linux", "amd64", b"ZIP");
    let net = Fixtures::default()
        .with(
            &format!("{TERRAFORM_DOCKER}/versions"),
            br#"{"versions":[{"version":"3.0.2"},{"version":"2.25.0"},{"version":"3.0.1"}]}"#,
        )
        .with(
            &format!("{TERRAFORM_DOCKER}/3.0.2/download/linux/amd64"),
            info.as_bytes(),
        );
    let locator = "pkg:terraform/kreuzwerker/docker";
    let (exact, url) = resolved(locator, &net, &BlobCache::disabled()).unwrap();
    assert_eq!(url, zip);
    assert!(exact.starts_with("pkg:terraform/kreuzwerker/docker@3.0.2?checksum=sha256:"));
}

// ---------------------------------------------------------------------------
// Ecosystem resolvers: Firefox, ComfyUI, Dify, VS Code
// ---------------------------------------------------------------------------

#[test]
fn resolve_firefox_uses_exact_version_and_refines_latest() {
    let pinned_api = "https://addons.mozilla.org/api/v5/addons/addon/surf-click/versions/1.0.9/";
    let latest_api = "https://addons.mozilla.org/api/v5/addons/addon/surf-click/";
    let xpi = "https://addons.mozilla.org/firefox/downloads/file/4909333/surf_click-1.0.9.xpi";
    let pinned = serde_json::json!({
        "version": "1.0.9",
        "file": {"url": xpi}
    })
    .to_string();
    let latest = serde_json::json!({
        "current_version": {
            "version": "1.0.9",
            "file": {"url": xpi}
        }
    })
    .to_string();
    let net = Fixtures::default()
        .with(pinned_api, pinned.as_bytes())
        .with(latest_api, latest.as_bytes())
        .with(xpi, b"XPI");
    let cache = BlobCache::disabled();

    assert_eq!(
        resolved("pkg:firefox/surf-click@1.0.9", &net, &cache),
        Some(("pkg:firefox/surf-click@1.0.9".to_string(), xpi.to_string()))
    );
    assert_eq!(
        resolved("pkg:firefox/surf-click", &net, &cache),
        Some(("pkg:firefox/surf-click@1.0.9".to_string(), xpi.to_string()))
    );
    let rec = fetch_ref(
        &dep(
            RefLocator::Purl("pkg:firefox/surf-click@1.0.9".into()),
            None,
        ),
        &net,
        &cache,
    );
    assert_eq!(rec.outcome, Outcome::Ok);
    assert_eq!(rec.resolved_url.as_deref(), Some(xpi));
    assert_eq!(rec.content_sha256.as_deref(), Some(&*sha256_hex(b"XPI")));

    // A mismatched per-version response is refused rather than silently
    // substituting another release for the requested artifact.
    let wrong = serde_json::json!({
        "version": "1.0.8",
        "file": {"url": "https://example.invalid/wrong.xpi"}
    })
    .to_string();
    let net = Fixtures::default().with(pinned_api, wrong.as_bytes());
    assert_eq!(resolved("pkg:firefox/surf-click@1.0.9", &net, &cache), None);
}

#[test]
fn resolve_comfyui_uses_exact_version_and_refines_latest() {
    let base = "https://api.comfy.org/nodes/comfyui-loopstrip/install";
    let pinned_api = format!("{base}?version=1.3.1");
    // The CDN path is the publisher's, not derivable from the node id.
    let zip = "https://cdn.comfy.org/serhiiyashyn-sf/comfyui-loopstrip/1.3.1/node.zip";
    let doc = serde_json::json!({
        "node_id": "comfyui-loopstrip", "version": "1.3.1", "downloadUrl": zip
    })
    .to_string();
    let net = Fixtures::default()
        .with(&pinned_api, doc.as_bytes())
        .with(base, doc.as_bytes())
        .with(zip, b"ZIP");
    let cache = BlobCache::disabled();
    let exact = "pkg:comfyui/comfyui-loopstrip@1.3.1";
    for purl in [exact, "pkg:comfyui/comfyui-loopstrip"] {
        assert_eq!(
            resolved(purl, &net, &cache),
            Some((exact.to_string(), zip.to_string())),
            "{purl}"
        );
    }
    let rec = fetch_ref(&dep(RefLocator::Purl(exact.into()), None), &net, &cache);
    assert_eq!(rec.outcome, Outcome::Ok);
    assert_eq!(rec.content_sha256.as_deref(), Some(&*sha256_hex(b"ZIP")));

    // Another release or another node in the answer is refused, as is a
    // namespaced id (the registry has none).
    for wrong in [
        serde_json::json!({"node_id": "comfyui-loopstrip", "version": "1.3.0", "downloadUrl": zip}),
        serde_json::json!({"node_id": "other-node", "version": "1.3.1", "downloadUrl": zip}),
    ] {
        let net = Fixtures::default().with(&pinned_api, wrong.to_string().as_bytes());
        assert_eq!(resolved(exact, &net, &cache), None);
    }
    assert_eq!(
        resolved("pkg:comfyui/owner/comfyui-loopstrip@1.3.1", &net, &cache),
        None
    );
}

#[test]
fn resolve_dify_downloads_by_unique_identifier() {
    let base = "https://marketplace.dify.ai/api/v1/plugins/fr3on/eval-loop";
    let identifier = format!("fr3on/eval-loop:0.1.1@{}", "b2".repeat(32));
    let pkg = format!(
        "https://marketplace.dify.ai/api/v1/plugins/download?unique_identifier=fr3on%2Feval-loop:0.1.1%40{}",
        "b2".repeat(32)
    );
    let pinned = serde_json::json!({"code": 0, "data": {"version": {
        "version": "0.1.1", "unique_identifier": identifier
    }}})
    .to_string();
    let latest = serde_json::json!({"code": 0, "data": {"plugin": {
        "latest_version": "0.1.1", "latest_package_identifier": identifier
    }}})
    .to_string();
    let net = Fixtures::default()
        .with(&format!("{base}/0.1.1"), pinned.as_bytes())
        .with(base, latest.as_bytes())
        .with(&pkg, b"DIFYPKG");
    let cache = BlobCache::disabled();
    let exact = "pkg:dify/fr3on/eval-loop@0.1.1";
    for purl in [exact, "pkg:dify/fr3on/eval-loop"] {
        assert_eq!(
            resolved(purl, &net, &cache),
            Some((exact.to_string(), pkg.clone())),
            "{purl}"
        );
    }
    let rec = fetch_ref(&dep(RefLocator::Purl(exact.into()), None), &net, &cache);
    assert_eq!(rec.outcome, Outcome::Ok);
    assert_eq!(
        rec.content_sha256.as_deref(),
        Some(&*sha256_hex(b"DIFYPKG"))
    );

    // An identifier naming another plugin or release is refused, as is a
    // bare name (the marketplace keys every plugin by its org).
    for wrong in [
        format!("evil/eval-loop:0.1.1@{}", "b2".repeat(32)),
        format!("fr3on/eval-loop:0.1.0@{}", "b2".repeat(32)),
        "fr3on/eval-loop:0.1.1@not-a-checksum".to_string(),
    ] {
        let doc = serde_json::json!({"data": {"version": {
            "version": "0.1.1", "unique_identifier": wrong
        }}})
        .to_string();
        let net = Fixtures::default().with(&format!("{base}/0.1.1"), doc.as_bytes());
        assert_eq!(resolved(exact, &net, &cache), None, "{wrong}");
    }
    assert_eq!(resolved("pkg:dify/eval-loop@0.1.1", &net, &cache), None);
}

#[test]
fn a_vscode_publisher_must_be_a_hostname_label() {
    let url = |purl: &str| {
        resolved(purl, &Fixtures::default(), &BlobCache::disabled()).map(|(_, url)| url)
    };
    assert!(
        url("pkg:vscode/ms-python/python@2024.1.0")
            .is_some_and(|u| u.starts_with("https://ms-python.gallery.vsassets.io/"))
    );
    // The publisher is a label of the gallery's hostname, so anything that
    // would add a label or isn't a publisher ID is refused, as is a
    // version that climbs out of the gallery path.
    for purl in [
        "pkg:vscode/evil.example/x@1.0.0",
        "pkg:vscode/a_b/x@1.0.0",
        "pkg:vscode/-pub/x@1.0.0",
        "pkg:vscode/pub/x@..%2F..%2Fx",
    ] {
        assert_eq!(url(purl), None, "{purl}");
    }
}

// ---------------------------------------------------------------------------
// Ecosystem resolvers: Arch and the AUR
// ---------------------------------------------------------------------------

#[test]
fn official_arch_fetches_current_candidate_but_does_not_guess_pins() {
    let net = Fixtures::default()
        .with(
            "https://archlinux.org/packages/search/json/?name=bash",
            br#"{"results":[{"pkgname":"bash","repo":"Core","arch":"x86_64"}]}"#,
        )
        .with(
            "https://archlinux.org/packages/core/os/x86_64/bash/download/",
            b"PACKAGE",
        );
    let cache = BlobCache::disabled();
    let current = dep(RefLocator::Purl("pkg:alpm/arch/bash".into()), None);
    assert_eq!(fetch_ref(&current, &net, &cache).outcome, Outcome::Ok);
    let pinned = dep(RefLocator::Purl("pkg:alpm/arch/bash@5.0-1".into()), None);
    assert_eq!(
        fetch_ref(&pinned, &net, &cache).outcome,
        Outcome::Unresolved(Unresolved::Unsupported)
    );
    let constrained = dep(
        RefLocator::Purl("pkg:alpm/arch/bash?version_requirement=%3E%3D5".into()),
        None,
    );
    assert_eq!(
        fetch_ref(&constrained, &net, &cache).outcome,
        Outcome::Unresolved(Unresolved::Unsupported)
    );
}

#[test]
fn aur_purl_fetches_pkgbase_snapshot() {
    let rpc = "https://aur.archlinux.org/rpc/v5/info?arg%5B%5D=yay";
    // The RPC names the snapshot by *pkgbase* (here differing from the
    // package name, the split-package case a derived URL would get wrong).
    let rpc_body = br#"{"resultcount":1,"results":[{"Name":"yay","PackageBase":"yay-base","URLPath":"/cgit/aur.git/snapshot/yay-base.tar.gz"}]}"#;
    let snapshot = "https://aur.archlinux.org/cgit/aur.git/snapshot/yay-base.tar.gz";
    let net = Fixtures::default()
        .with(rpc, rpc_body)
        .with(snapshot, b"SNAPSHOT");

    // Every AUR spelling resolves to the same snapshot, including the spec
    // form carrying a version (snapshots track HEAD; the version can't pin)
    // and the non-spec `?qualifiers@version` ordering some producers emit.
    for purl in [
        "pkg:aur/yay",
        "pkg:alpm/aur/yay",
        "pkg:alpm/arch/yay@12.0-1?repository_url=https://aur.archlinux.org",
        "pkg:alpm/arch/yay?repository_url=https://aur.archlinux.org@12.0-1",
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = BlobCache::with_dir(dir.path().to_path_buf());
        let rec = fetch_ref(&dep(RefLocator::Purl(purl.into()), None), &net, &cache);
        assert_eq!(rec.outcome, Outcome::Ok, "{purl}");
        assert_eq!(rec.resolved_url.as_deref(), Some(snapshot), "{purl}");
    }

    // RPC unreachable → the name-derived snapshot fallback still fetches.
    let derived = "https://aur.archlinux.org/cgit/aur.git/snapshot/yay.tar.gz";
    let net = Fixtures::default().with(derived, b"SNAPSHOT");
    let dir = tempfile::tempdir().expect("tempdir");
    let cache = BlobCache::with_dir(dir.path().to_path_buf());
    let rec = fetch_ref(
        &dep(RefLocator::Purl("pkg:aur/yay".into()), None),
        &net,
        &cache,
    );
    assert_eq!(rec.outcome, Outcome::Ok);
    assert_eq!(rec.resolved_url.as_deref(), Some(derived));
}
