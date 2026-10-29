//! Per-type rules: the purl-spec type definitions this crate enforces, and the
//! fold of its accepted non-spec spellings onto spec form.

use super::{Purl, PurlError};

/// Whether a type's PURLs carry a namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Namespace {
    Required,
    Optional,
    Prohibited,
}

/// How a component's case is canonicalized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Case {
    Keep,
    Lower,
    Upper,
}

impl Case {
    fn apply(self, value: &mut String) {
        match (self, value.is_ascii()) {
            (Self::Keep, _) => {}
            (Self::Lower, true) => value.make_ascii_lowercase(),
            (Self::Upper, true) => value.make_ascii_uppercase(),
            (Self::Lower, false) => *value = value.to_lowercase(),
            (Self::Upper, false) => *value = value.to_uppercase(),
        }
    }
}

/// One type's definition.
#[derive(Debug, Clone, Copy)]
struct TypeRules {
    namespace: Namespace,
    namespace_case: Case,
    name_case: Case,
    version_case: Case,
    /// The qualifier keys the type's definition declares.
    qualifiers: &'static [&'static str],
    /// A qualifier every PURL of the type must carry.
    required_qualifier: Option<&'static str>,
    /// Qualifiers that select bytes within a release rather than name a
    /// release, beyond the `checksum` and `file_name` every type shares.
    artifact_qualifiers: &'static [&'static str],
}

const BASE: TypeRules = TypeRules {
    namespace: Namespace::Optional,
    namespace_case: Case::Keep,
    name_case: Case::Keep,
    version_case: Case::Keep,
    qualifiers: &[],
    required_qualifier: None,
    artifact_qualifiers: &[],
};

const REQUIRED: TypeRules = TypeRules {
    namespace: Namespace::Required,
    ..BASE
};

const PROHIBITED: TypeRules = TypeRules {
    namespace: Namespace::Prohibited,
    ..BASE
};

/// A distro type: vendor namespace and package name are case-insensitive.
const DISTRO: TypeRules = TypeRules {
    namespace: Namespace::Required,
    namespace_case: Case::Lower,
    name_case: Case::Lower,
    qualifiers: &["arch"],
    artifact_qualifiers: &["arch", "distro"],
    ..BASE
};

/// A forge or registry whose owner and name are both case-insensitive.
const LOWER_PATH: TypeRules = TypeRules {
    namespace_case: Case::Lower,
    name_case: Case::Lower,
    ..BASE
};

/// Every type this crate knows: the purl-spec registered types, and the
/// non-spec types its registries answer for. Any other type is valid with
/// [`BASE`] rules.
///
/// Two departures from the spec. `golang`'s namespace is optional: the spec
/// requires it, which leaves no spelling for a module whose path is a single
/// segment (`tailscale.com`, `gioui.org`, `goji.io`), and those are published
/// and fetched like any other. `terraform` has no spec definition: it is a
/// registry.terraform.io provider address, `pkg:terraform/<namespace>/<type>`,
/// resolved case-insensitively.
static TYPES: &[(&str, TypeRules)] = &[
    ("alpm", DISTRO),
    ("apk", DISTRO),
    (
        "bazel",
        TypeRules {
            qualifiers: &["repository_url"],
            ..PROHIBITED
        },
    ),
    (
        "bitbucket",
        TypeRules {
            namespace: Namespace::Required,
            ..LOWER_PATH
        },
    ),
    (
        "bitnami",
        TypeRules {
            name_case: Case::Lower,
            qualifiers: &["arch", "distro"],
            ..PROHIBITED
        },
    ),
    (
        "brew",
        TypeRules {
            qualifiers: &["repository_url"],
            ..LOWER_PATH
        },
    ),
    ("cargo", PROHIBITED),
    (
        "chrome-extension",
        TypeRules {
            name_case: Case::Lower,
            ..PROHIBITED
        },
    ),
    ("clawhub", BASE),
    ("clojars", BASE),
    ("cocoapods", PROHIBITED),
    ("comfyui", BASE),
    (
        "composer",
        TypeRules {
            namespace: Namespace::Required,
            ..LOWER_PATH
        },
    ),
    (
        "conan",
        TypeRules {
            qualifiers: &["user", "channel", "rrev", "prev"],
            artifact_qualifiers: &["prev"],
            ..BASE
        },
    ),
    (
        "conda",
        TypeRules {
            qualifiers: &["build", "channel", "subdir", "type"],
            artifact_qualifiers: &["build", "subdir", "type"],
            ..PROHIBITED
        },
    ),
    (
        "cpan",
        TypeRules {
            namespace_case: Case::Upper,
            qualifiers: &[
                "author",
                "distpath",
                "repository_url",
                "download_url",
                "vcs_url",
                "ext",
            ],
            ..BASE
        },
    ),
    ("cran", PROHIBITED),
    ("deb", DISTRO),
    ("dify", BASE),
    ("docker", BASE),
    ("firefox", BASE),
    ("freebsd", BASE),
    (
        "gem",
        TypeRules {
            qualifiers: &["platform"],
            artifact_qualifiers: &["platform"],
            ..PROHIBITED
        },
    ),
    (
        "generic",
        TypeRules {
            qualifiers: &["download_url", "checksum"],
            ..BASE
        },
    ),
    ("git", REQUIRED),
    (
        "github",
        TypeRules {
            namespace: Namespace::Required,
            ..LOWER_PATH
        },
    ),
    ("golang", BASE),
    ("hackage", PROHIBITED),
    ("hex", LOWER_PATH),
    (
        "huggingface",
        TypeRules {
            version_case: Case::Lower,
            ..REQUIRED
        },
    ),
    ("jetbrains", BASE),
    ("jsr", BASE),
    (
        "julia",
        TypeRules {
            qualifiers: &["uuid"],
            required_qualifier: Some("uuid"),
            ..PROHIBITED
        },
    ),
    (
        "luarocks",
        TypeRules {
            qualifiers: &["repository_url"],
            ..LOWER_PATH
        },
    ),
    (
        "maven",
        TypeRules {
            qualifiers: &["classifier", "type"],
            artifact_qualifiers: &["classifier", "type"],
            ..REQUIRED
        },
    ),
    (
        "mlflow",
        TypeRules {
            qualifiers: &["model_uuid", "run_id"],
            ..PROHIBITED
        },
    ),
    ("netbsd", BASE),
    ("npm", BASE),
    ("nuget", PROHIBITED),
    (
        "oci",
        TypeRules {
            name_case: Case::Lower,
            version_case: Case::Lower,
            qualifiers: &["arch", "repository_url", "tag"],
            artifact_qualifiers: &["arch"],
            ..PROHIBITED
        },
    ),
    ("opam", PROHIBITED),
    ("openbsd", BASE),
    (
        "otp",
        TypeRules {
            name_case: Case::Lower,
            qualifiers: &["repository_url", "platform", "arch"],
            artifact_qualifiers: &["arch", "platform"],
            ..PROHIBITED
        },
    ),
    (
        "pub",
        TypeRules {
            name_case: Case::Lower,
            ..PROHIBITED
        },
    ),
    (
        "pypi",
        TypeRules {
            version_case: Case::Lower,
            qualifiers: &["file_name"],
            artifact_qualifiers: &["kind"],
            ..PROHIBITED
        },
    ),
    (
        "qpkg",
        TypeRules {
            namespace_case: Case::Lower,
            ..REQUIRED
        },
    ),
    (
        "rpm",
        TypeRules {
            name_case: Case::Keep,
            qualifiers: &["epoch", "arch"],
            ..DISTRO
        },
    ),
    ("snap", BASE),
    (
        "swid",
        TypeRules {
            qualifiers: &[
                "tag_id",
                "tag_version",
                "patch",
                "tag_creator_name",
                "tag_creator_regid",
            ],
            required_qualifier: Some("tag_id"),
            ..BASE
        },
    ),
    ("swift", REQUIRED),
    (
        "terraform",
        TypeRules {
            namespace: Namespace::Required,
            ..LOWER_PATH
        },
    ),
    (
        "vcpkg",
        TypeRules {
            qualifiers: &["port_version", "repository_revision", "triplet"],
            artifact_qualifiers: &["triplet"],
            ..PROHIBITED
        },
    ),
    (
        "vscode-extension",
        TypeRules {
            namespace: Namespace::Required,
            version_case: Case::Lower,
            qualifiers: &["platform"],
            artifact_qualifiers: &["platform"],
            ..LOWER_PATH
        },
    ),
    ("wordpress", BASE),
    (
        "yocto",
        TypeRules {
            namespace_case: Case::Lower,
            qualifiers: &["repository_url", "layer_version"],
            ..BASE
        },
    ),
];

fn entry(typ: &str) -> Option<&'static (&'static str, TypeRules)> {
    TYPES.iter().find(|(known, _)| *known == typ)
}

fn rules(typ: &str) -> &'static TypeRules {
    entry(typ).map_or(&BASE, |(_, rules)| rules)
}

/// `typ` as a `'static` string when it is one this crate knows, for a label
/// whose set of values must stay bounded.
pub(crate) fn known_type(typ: &str) -> Option<&'static str> {
    entry(typ).map(|(known, _)| *known)
}

/// Whether the definition of `typ` declares qualifier `key`.
pub(super) fn defines_qualifier(typ: &str, key: &str) -> bool {
    rules(typ).qualifiers.contains(&key)
}

/// Whether qualifier `key` selects bytes within a release of `typ` rather
/// than naming the release.
pub(super) fn selects_artifact(typ: &str, key: &str) -> bool {
    matches!(key, "checksum" | "file_name") || rules(typ).artifact_qualifiers.contains(&key)
}

/// The origin [`fold_legacy`] gives `pkg:openvsx`.
const OPEN_VSX: &str = "https://open-vsx.org";

/// The host of the Arch User Repository, which is its own alpm namespace.
const AUR_HOST: &str = "aur.archlinux.org";

/// Fold the non-spec spellings [`normalize`](super::normalize) accepts onto
/// spec form. Runs before [`apply`], so the result is then held to the spec
/// type's rules.
pub(super) fn fold_legacy(purl: &mut Purl) {
    let alias = match purl.typ.as_str() {
        "chrome" => {
            // The extension id is the whole identity; any vendor path is noise.
            purl.namespace.clear();
            Some("chrome-extension")
        }
        "vscode" => Some("vscode-extension"),
        "openvsx" => {
            purl.qualifiers
                .entry("repository_url".to_owned())
                .or_insert_with(|| OPEN_VSX.to_owned());
            Some("vscode-extension")
        }
        "homebrew" => Some("brew"),
        other => distro_vendor(other).map(|(spec, vendor)| {
            purl.namespace = vec![vendor.to_owned()];
            spec
        }),
    };
    if let Some(alias) = alias {
        tracing::debug!(from = %purl.typ, to = alias, "folded a non-spec PURL type");
        alias.clone_into(&mut purl.typ);
    }

    if purl.typ == "alpm"
        && purl
            .qualifiers
            .get("repository_url")
            .is_some_and(|url| crate::fetch::url_host_is(url, AUR_HOST))
    {
        tracing::debug!("folded an AUR repository_url onto the aur namespace");
        purl.qualifiers.remove("repository_url");
        purl.namespace = vec!["aur".to_owned()];
    }

    if purl.namespace.is_empty()
        && matches!(purl.typ.as_str(), "deb" | "rpm" | "apk" | "alpm")
        && let Some(distro) = purl.qualifiers.get("distro")
    {
        // `distro=<vendor>-<release>`; a bare codename (`jessie`) names no
        // vendor and recovers nothing.
        let vendor = distro
            .split('-')
            .next()
            .unwrap_or(distro)
            .to_ascii_lowercase();
        if distro_vendor(&vendor).is_some_and(|(spec, _)| spec == purl.typ) {
            tracing::debug!(%vendor, "recovered a distro namespace from the distro qualifier");
            purl.namespace = vec![vendor];
        }
    }
}

/// The spec type and vendor namespace of a bare-distro type spelling.
fn distro_vendor(typ: &str) -> Option<(&'static str, &'static str)> {
    Some(match typ {
        "debian" => ("deb", "debian"),
        "ubuntu" => ("deb", "ubuntu"),
        "fedora" => ("rpm", "fedora"),
        "opensuse" => ("rpm", "opensuse"),
        "rpmfusion" => ("rpm", "rpmfusion"),
        "arch" => ("alpm", "arch"),
        "aur" => ("alpm", "aur"),
        "alpine" => ("apk", "alpine"),
        "wolfi" => ("apk", "wolfi"),
        _ => return None,
    })
}

/// Hold `purl` to its type's definition, canonicalizing component case.
/// Idempotent: applying it to its own output changes nothing.
pub(super) fn apply(purl: &mut Purl) -> Result<(), PurlError> {
    if purl.typ == "git" && purl.namespace.len() > 1 {
        // The host is the namespace; the repository path is the name.
        let mut name = purl.namespace.split_off(1);
        name.push(std::mem::take(&mut purl.name));
        purl.name = name.join("/");
    }
    let rules = rules(&purl.typ);
    match rules.namespace {
        Namespace::Required if purl.namespace.is_empty() => {
            return Err(PurlError::Type("namespace is required"));
        }
        Namespace::Prohibited if !purl.namespace.is_empty() => {
            return Err(PurlError::Type("namespace is not allowed"));
        }
        _ => {}
    }
    if let Some(required) = rules.required_qualifier
        && !purl.qualifiers.contains_key(required)
    {
        return Err(PurlError::Type("a required qualifier is missing"));
    }
    for segment in &mut purl.namespace {
        rules.namespace_case.apply(segment);
    }
    rules.name_case.apply(&mut purl.name);
    if let Some(version) = &mut purl.version {
        rules.version_case.apply(version);
    }
    type_specific(purl)?;
    canonical_qualifiers(purl)
}

/// The rules a type definition states in prose rather than as a case or
/// namespace requirement.
fn type_specific(purl: &mut Purl) -> Result<(), PurlError> {
    match purl.typ.as_str() {
        "cpan" if purl.name.contains("::") => {
            return Err(PurlError::Type("cpan name is a distribution, not a module"));
        }
        "chrome-extension" => chrome_extension(purl)?,
        "swid" => swid(purl)?,
        "pypi" => purl.name = normalize_pypi(&purl.name),
        "git" if purl.namespace.first().is_some_and(|host| host == "github") => {
            for segment in &mut purl.namespace {
                Case::Lower.apply(segment);
            }
            Case::Lower.apply(&mut purl.name);
        }
        "mlflow"
            if purl
                .qualifiers
                .get("repository_url")
                .is_some_and(|url| is_databricks(url)) =>
        {
            Case::Lower.apply(&mut purl.name);
        }
        "pub" => {
            purl.name = purl
                .name
                .chars()
                .map(|c| {
                    if c.is_ascii_lowercase() || c.is_ascii_digit() {
                        c
                    } else {
                        '_'
                    }
                })
                .collect();
        }
        _ => {}
    }
    Ok(())
}

/// A Chrome Web Store id is 32 letters `a`–`p`; a version is one to four
/// dot-separated integers.
fn chrome_extension(purl: &Purl) -> Result<(), PurlError> {
    if purl.name.len() != 32 || !purl.name.bytes().all(|byte| matches!(byte, b'a'..=b'p')) {
        return Err(PurlError::Type("chrome-extension id is not 32 letters a-p"));
    }
    let valid_version = |version: &str| {
        version.split('.').count() <= 4
            && version.split('.').all(|segment| {
                !segment.is_empty() && segment.bytes().all(|byte| byte.is_ascii_digit())
            })
    };
    if purl
        .version
        .as_deref()
        .is_some_and(|version| !valid_version(version))
    {
        return Err(PurlError::Type(
            "chrome-extension version is not 1-4 integers",
        ));
    }
    Ok(())
}

/// SWID: at most a two-segment namespace, typed `tag_version` and `patch`, and
/// a GUID `tag_id` in lowercase.
fn swid(purl: &mut Purl) -> Result<(), PurlError> {
    if purl.namespace.len() > 2 {
        return Err(PurlError::Type("swid namespace has more than two segments"));
    }
    if purl
        .qualifiers
        .get("tag_version")
        .is_some_and(|value| value.parse::<u64>().is_err())
    {
        return Err(PurlError::Type("swid tag_version is not an integer"));
    }
    if purl
        .qualifiers
        .get("patch")
        .is_some_and(|value| !matches!(value.as_str(), "true" | "false"))
    {
        return Err(PurlError::Type("swid patch is not a boolean"));
    }
    if let Some(tag_id) = purl.qualifiers.get_mut("tag_id")
        && is_guid(tag_id)
    {
        tag_id.make_ascii_lowercase();
    }
    Ok(())
}

fn is_guid(value: &str) -> bool {
    let mut groups = value.split('-');
    [8, 4, 4, 4, 12].into_iter().all(|size| {
        groups.next().is_some_and(|group| {
            group.len() == size && group.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    }) && groups.next().is_none()
}

/// Whether `url` is hosted by Databricks, whose MLflow model names are
/// case-insensitive.
fn is_databricks(url: &str) -> bool {
    url::Url::parse(url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_ascii_lowercase))
        .is_some_and(|host| {
            ["databricks.com", "azuredatabricks.net"]
                .iter()
                .any(|domain| {
                    host == *domain
                        || host
                            .strip_suffix(domain)
                            .is_some_and(|subdomain| subdomain.ends_with('.'))
                })
        })
}

/// Normalize a PyPI project name per PEP 503: lowercase, and collapse any run
/// of `-`, `_`, or `.` to a single `-`.
fn normalize_pypi(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut prev_sep = false;
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !prev_sep {
                out.push('-');
                prev_sep = true;
            }
        } else {
            out.push(c.to_ascii_lowercase());
            prev_sep = false;
        }
    }
    out
}

/// The qualifiers every type shares: a `version` and a `vers` range are
/// exclusive, `checksum` is a list of `algorithm:hex` (lowercased), and `vers`
/// is a well-formed version range.
fn canonical_qualifiers(purl: &mut Purl) -> Result<(), PurlError> {
    if purl.version.is_some() && purl.qualifiers.contains_key("vers") {
        return Err(PurlError::Type("version and vers range are exclusive"));
    }
    if let Some(checksum) = purl.qualifiers.get_mut("checksum") {
        *checksum = checksum
            .split(',')
            .map(canonical_checksum)
            .collect::<Option<Vec<_>>>()
            .ok_or(PurlError::Type("checksum is not a list of algorithm:hex"))?
            .join(",");
    }
    if purl
        .qualifiers
        .get("vers")
        .is_some_and(|range| !valid_version_range(range))
    {
        return Err(PurlError::Type("vers is not a version range"));
    }
    Ok(())
}

fn canonical_checksum(item: &str) -> Option<String> {
    let (algorithm, digest) = item.split_once(':')?;
    let algorithm = algorithm.to_ascii_lowercase().replace('_', "-");
    let digest = digest.to_ascii_lowercase();
    let valid = !algorithm.is_empty()
        && algorithm.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'+' | b'-')
        })
        && !digest.is_empty()
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'));
    valid.then(|| format!("{algorithm}:{digest}"))
}

/// A `vers:<scheme>/<constraints>` range: `*`, or `|`-separated constraints
/// of an optional comparator and a distinct, non-blank version.
fn valid_version_range(value: &str) -> bool {
    let Some((scheme, constraints)) = value
        .strip_prefix("vers:")
        .and_then(|body| body.split_once('/'))
    else {
        return false;
    };
    if scheme.is_empty()
        || !scheme.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_')
        })
        || constraints.is_empty()
    {
        return false;
    }
    if constraints == "*" {
        return true;
    }
    let mut versions = std::collections::BTreeSet::new();
    constraints.split('|').all(|constraint| {
        let version = [">=", "<=", "!=", ">", "<"]
            .into_iter()
            .find_map(|operator| constraint.strip_prefix(operator))
            .unwrap_or(constraint);
        constraint != "*"
            && !version.is_empty()
            && !matches!(
                version.as_bytes().first(),
                Some(b'=' | b'>' | b'<' | b'!' | b'^' | b'~')
            )
            && !version
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
            && versions.insert(version)
    })
}

#[cfg(test)]
mod tests {
    use super::super::{Purl, PurlError, identity, normalize};

    fn norm(raw: &str) -> String {
        normalize(raw).unwrap_or_else(|| panic!("{raw} must normalize"))
    }

    #[test]
    fn type_table_has_one_entry_per_type() {
        let mut seen = std::collections::BTreeSet::new();
        for (typ, _) in super::TYPES {
            assert!(seen.insert(typ), "{typ} listed twice");
        }
        assert_eq!(super::known_type("npm"), Some("npm"));
        assert_eq!(super::known_type("evil"), None);
    }

    #[test]
    fn cross_type_definition_edge_rules_are_covered() {
        let cases = [
            (
                "pkg:bitbucket/birKenfeld/pyGments-main@244fd47e",
                "pkg:bitbucket/birkenfeld/pygments-main@244fd47e",
            ),
            (
                "pkg:git/github/Package-url/purl-Spec@244fd47e",
                "pkg:git/github/package-url/purl-spec@244fd47e",
            ),
            (
                "pkg:hackage/AC-HalfInteger@1.2.1",
                "pkg:hackage/AC-HalfInteger@1.2.1",
            ),
            (
                "pkg:mlflow/CreditFraud@3?repository_url=https://adb-1.azuredatabricks.net/api/2.0/mlflow",
                "pkg:mlflow/creditfraud@3?repository_url=https:%2F%2Fadb-1.azuredatabricks.net%2Fapi%2F2.0%2Fmlflow",
            ),
            (
                "pkg:mlflow/CreditFraud@3?repository_url=https://westus.api.azureml.ms/mlflow",
                "pkg:mlflow/CreditFraud@3?repository_url=https:%2F%2Fwestus.api.azureml.ms%2Fmlflow",
            ),
            (
                "pkg:julia/Dates@1.9.0?uuid=ade2ca70-3891-5945-98fb-dc099432e06a",
                "pkg:julia/Dates@1.9.0?uuid=ade2ca70-3891-5945-98fb-dc099432e06a",
            ),
            // A Go module whose path is one segment has no namespace to give.
            (
                "pkg:golang/tailscale.com@v1.102.3",
                "pkg:golang/tailscale.com@v1.102.3",
            ),
            (
                "pkg:GOLANG/goji.io@v2.0.0%2Bincompatible",
                "pkg:golang/goji.io@v2.0.0%2Bincompatible",
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(norm(input), expected, "type rule {input}");
            assert_eq!(norm(expected), expected, "fixed point {expected}");
        }

        for invalid in [
            "pkg:cpan/GDT/URI::PackageURL",
            "pkg:julia/Dates@1.9.0",
            "pkg:swid/Fedora@29",
            "pkg:swift/github.com/Alamofire/@5.4.3",
            "pkg:pypi/namespace/name@1",
            "pkg:gem/namespace/name@1",
            "pkg:cargo/namespace/name@1",
        ] {
            assert_eq!(normalize(invalid), None, "type rule rejects {invalid}");
        }
    }

    /// Only a Databricks host, not the word `databricks` anywhere in the URL,
    /// makes an MLflow name case-insensitive.
    #[test]
    fn mlflow_lowercases_only_on_a_databricks_host() {
        for keep in [
            "pkg:mlflow/CreditFraud@3?repository_url=https://evil.example/databricks",
            "pkg:mlflow/CreditFraud@3?repository_url=https://databricks.evil.example",
            "pkg:mlflow/CreditFraud@3?repository_url=https://notazuredatabricks.net",
        ] {
            assert_eq!(Purl::parse(keep).unwrap().name(), "CreditFraud", "{keep}");
        }
        assert_eq!(
            Purl::parse("pkg:mlflow/CreditFraud?repository_url=https://x.cloud.databricks.com")
                .unwrap()
                .name(),
            "creditfraud"
        );
    }

    #[test]
    fn terraform_address_is_lowercased_and_requires_a_namespace() {
        assert_eq!(
            norm("pkg:Terraform/Kreuzwerker/Docker@3.0.2"),
            "pkg:terraform/kreuzwerker/docker@3.0.2"
        );
        assert_eq!(
            norm("pkg:terraform/kreuzwerker/docker@4.0.0-Beta2"),
            "pkg:terraform/kreuzwerker/docker@4.0.0-Beta2"
        );
        let purl = Purl::parse("pkg:terraform/GoCommunity-IO/DockerD").unwrap();
        assert_eq!(purl.namespace(), ["gocommunity-io"]);
        assert_eq!(purl.name(), "dockerd");
        assert_eq!(
            Purl::parse("pkg:terraform/docker@1"),
            Err(PurlError::Type("namespace is required"))
        );
    }

    #[test]
    fn folds_legacy_spellings_onto_canonical() {
        let pairs = [
            (
                "pkg:chrome/Dlpngalgnefjeiefhmpklpfiohadpglk",
                "pkg:chrome-extension/dlpngalgnefjeiefhmpklpfiohadpglk",
            ),
            (
                "pkg:chrome/Dlpngalgnefjeiefhmpklpfiohadpglk@25.7.1",
                "pkg:chrome-extension/dlpngalgnefjeiefhmpklpfiohadpglk@25.7.1",
            ),
            (
                "pkg:chrome/vendor/dlpngalgnefjeiefhmpklpfiohadpglk",
                "pkg:chrome-extension/dlpngalgnefjeiefhmpklpfiohadpglk",
            ),
            (
                "pkg:vscode/Saoudrizwan/Claude-Dev",
                "pkg:vscode-extension/saoudrizwan/claude-dev",
            ),
            (
                "pkg:openvsx/jinryx/crontally@1.0.3",
                "pkg:vscode-extension/jinryx/crontally@1.0.3?repository_url=https:%2F%2Fopen-vsx.org",
            ),
            ("pkg:pypi/Ruamel.Yaml@0.18.6", "pkg:pypi/ruamel-yaml@0.18.6"),
            (
                "pkg:pypi/backports__zoneinfo",
                "pkg:pypi/backports-zoneinfo",
            ),
            (
                "pkg:composer/Symfony/Console@6.4.0",
                "pkg:composer/symfony/console@6.4.0",
            ),
            ("pkg:debian/curl", "pkg:deb/debian/curl"),
            ("pkg:debian/Some/Curl", "pkg:deb/debian/curl"),
            ("pkg:arch/pacman@6.0", "pkg:alpm/arch/pacman@6.0"),
            ("pkg:fedora/curl", "pkg:rpm/fedora/curl"),
            ("pkg:rpmfusion/LibFoo", "pkg:rpm/rpmfusion/LibFoo"),
            ("pkg:alpine/musl", "pkg:apk/alpine/musl"),
            ("pkg:aur/yay", "pkg:alpm/aur/yay"),
            ("pkg:aur/yay@12.0.0-1", "pkg:alpm/aur/yay@12.0.0-1"),
            (
                "pkg:aur/yay?repository_url=https://aur.archlinux.org",
                "pkg:alpm/aur/yay",
            ),
            ("PKG:AUR/Yay@1.0-1", "pkg:alpm/aur/yay@1.0-1"),
            ("pkg:alpm/aur/Foo-Bar@1.0-1", "pkg:alpm/aur/foo-bar@1.0-1"),
            (
                "pkg:alpm/arch/yay@12.3.0-1?arch=x86_64&repository_url=https://aur.archlinux.org",
                "pkg:alpm/aur/yay@12.3.0-1?arch=x86_64",
            ),
            (
                "pkg:alpm/arch/yay@12.3.0-1?repository_url=https://aur.archlinux.org&arch=x86_64",
                "pkg:alpm/aur/yay@12.3.0-1?arch=x86_64",
            ),
            (
                "pkg:arch/yay?repository_url=https://aur.archlinux.org/packages/yay",
                "pkg:alpm/aur/yay",
            ),
        ];
        for (legacy, spec) in pairs {
            assert_eq!(norm(legacy), spec, "fold {legacy}");
            assert_eq!(norm(spec), spec, "idempotent {spec}");
        }
    }

    /// Only a `repository_url` hosted on `aur.archlinux.org` folds onto the
    /// AUR namespace. A foreign URL that merely mentions it keeps its
    /// qualifier, and so never shares the genuine AUR package's key.
    #[test]
    fn only_the_aur_host_folds_onto_the_aur_namespace() {
        for spoof in [
            "pkg:alpm/arch/foo?repository_url=https://evil.example/aur.archlinux.org",
            "pkg:alpm/arch/foo?repository_url=https://aur.archlinux.org.evil.example",
            "pkg:alpm/arch/foo?repository_url=https://aur.archlinux.org@evil.example",
            "pkg:arch/foo?repository_url=https://evil.example/aur.archlinux.org",
            "pkg:aur/foo?repository_url=https://evil.example/aur.archlinux.org",
        ] {
            let purl = Purl::parse(spoof).unwrap();
            assert!(purl.qualifier("repository_url").is_some(), "{spoof}");
            assert_ne!(
                identity(spoof).as_deref(),
                Some("pkg:alpm/aur/foo"),
                "{spoof}"
            );
        }
        assert_eq!(
            norm("pkg:alpm/arch/foo?repository_url=HTTPS://AUR.ARCHLINUX.ORG"),
            "pkg:alpm/aur/foo"
        );
    }

    #[test]
    fn distro_namespace_canonicalizes_and_recovers() {
        let cases = [
            (
                "pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25",
                "pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25",
            ),
            (
                "pkg:rpm/centerim@4.22.10-1.el6?arch=i686&epoch=1&distro=fedora-25",
                "pkg:rpm/fedora/centerim@4.22.10-1.el6?arch=i686&distro=fedora-25&epoch=1",
            ),
            ("pkg:rpm/Fedora/curl@1.0", "pkg:rpm/fedora/curl@1.0"),
            (
                "pkg:deb/curl@7.50.3-1?arch=amd64&distro=ubuntu-22.04",
                "pkg:deb/ubuntu/curl@7.50.3-1?arch=amd64&distro=ubuntu-22.04",
            ),
        ];
        for (input, want) in cases {
            assert_eq!(norm(input), want, "normalize {input}");
            assert_eq!(norm(want), want, "idempotent {want}");
        }
        // A codename alone names no vendor, so the required namespace stays
        // missing.
        assert_eq!(
            normalize("pkg:deb/curl@7.50.3-1?arch=i386&distro=jessie"),
            None
        );
        // A vendor of another distro type recovers nothing.
        assert_eq!(normalize("pkg:deb/curl?distro=fedora-25"), None);
        // Identity drops the artifact selectors but keeps the epoch, which
        // names a different release.
        assert_eq!(
            identity("pkg:rpm/centerim@4.22.10-1.el6?arch=i686&epoch=1&distro=fedora-25")
                .as_deref(),
            Some("pkg:rpm/fedora/centerim@4.22.10-1.el6?epoch=1")
        );
    }

    /// The vendor in a `distro` qualifier is case-insensitive.
    #[test]
    fn distro_vendor_recovery_is_case_insensitive() {
        assert_eq!(
            norm("pkg:rpm/curl?distro=Fedora-25"),
            "pkg:rpm/fedora/curl?distro=Fedora-25"
        );
    }

    /// The purl-spec registers `brew`; `pkg:homebrew` names the same
    /// packages and folds onto it.
    #[test]
    fn homebrew_folds_onto_the_spec_brew_type() {
        assert_eq!(norm("pkg:homebrew/wget"), "pkg:brew/wget");
        assert_eq!(norm("pkg:Homebrew/SQLite@3.43.2"), "pkg:brew/sqlite@3.43.2");
        assert_eq!(
            norm("pkg:homebrew/Homebrew/Core/sqlite"),
            "pkg:brew/homebrew/core/sqlite"
        );
        assert_eq!(
            norm("pkg:brew/node@20@20.10.0"),
            "pkg:brew/node%4020@20.10.0"
        );
    }

    #[test]
    fn chrome_extension_id_and_version_are_validated() {
        let id = "dlpngalgnefjeiefhmpklpfiohadpglk";
        assert_eq!(normalize("pkg:chrome-extension/dogs"), None);
        assert_eq!(
            normalize("pkg:chrome-extension/44444algnefjeiefhmpklpfiohadpglk"),
            None
        );
        assert!(normalize(&format!("pkg:chrome-extension/{id}@1.2.3.4")).is_some());
        for bad in ["1.2.3.4.5", "1.2-beta", "1..2", "1."] {
            assert_eq!(
                normalize(&format!("pkg:chrome-extension/{id}@{bad}")),
                None,
                "{bad}"
            );
        }
    }

    #[test]
    fn swid_rules_are_enforced() {
        assert!(normalize("pkg:swid/acme/example.com/app?tag_id=id").is_some());
        assert_eq!(normalize("pkg:swid/a/b/c/app?tag_id=id"), None);
        assert_eq!(normalize("pkg:swid/app?patch=maybe&tag_id=id"), None);
        assert_eq!(normalize("pkg:swid/app?tag_id=id&tag_version=nope"), None);
        assert_eq!(
            normalize("pkg:swid/app?tag_id=75B8C285-FA7B-485B-B199-4745E3004D0D"),
            Some("pkg:swid/app?tag_id=75b8c285-fa7b-485b-b199-4745e3004d0d".into())
        );
    }

    #[test]
    fn cpan_author_namespace_is_canonical_uppercase() {
        assert_eq!(
            normalize("pkg:cpan/drolsky/DateTime@1.55"),
            Some("pkg:cpan/DROLSKY/DateTime@1.55".into())
        );
    }

    #[test]
    fn checksum_qualifier_normalizes_valid_hex_and_rejects_malformed_values() {
        assert_eq!(
            normalize("pkg:npm/foo@1?checksum=SHA256:ABCDEF"),
            Some("pkg:npm/foo@1?checksum=sha256:abcdef".into())
        );
        assert_eq!(normalize("pkg:npm/foo@1?checksum=not-a-checksum"), None);
        assert_eq!(normalize("pkg:npm/foo@1?checksum=sha256:xyz"), None);
    }

    #[test]
    fn vers_qualifier_requires_version_range_syntax() {
        assert_eq!(normalize("pkg:npm/foo?vers=garbage"), None);
        assert!(normalize("pkg:npm/foo?vers=vers:npm%2F%3E%3D1.0.0%7C%3C2.0.0").is_some());
        assert!(normalize("pkg:npm/foo?vers=vers:npm%2F1.2.3").is_some());
        assert!(normalize("pkg:npm/foo?vers=vers:npm%2F*").is_some());
        for invalid in [
            "vers:npm%2F%3D1.0.0",
            "vers:npm%2F%3D%3D1.0.0",
            "vers:npm%2F%5E1.0.0",
            "vers:npm%2F~1.0.0",
            "vers:npm%2F%7C1.0.0",
            "vers:npm%2F1.0.0%7C",
            "vers:npm%2F1.0.0%7C1.0.0",
            "vers:npm%2F*%7C1.0.0",
            "vers:npm%2F%3E%3D1.0.0%20",
        ] {
            assert_eq!(normalize(&format!("pkg:npm/foo?vers={invalid}")), None);
        }
    }

    #[test]
    fn git_name_may_contain_repository_path_segments() {
        let parsed = Purl::parse_strict(
            "pkg:git/codeberg.org/forgejo/forgejo@a72d2c07cfca03b55371089de6aa230d8c951fa0",
        )
        .unwrap();
        assert_eq!(parsed.namespace(), ["codeberg.org"]);
        assert_eq!(parsed.name(), "forgejo/forgejo");
        assert_eq!(
            parsed.to_string(),
            "pkg:git/codeberg.org/forgejo/forgejo@a72d2c07cfca03b55371089de6aa230d8c951fa0"
        );
    }
}
