//! What limited, or decided, how much of a reference was analyzed.
//!
//! A [`super::FetchRecord`] says what was fetched; its [`Coverage`] says what
//! that left unexamined, and why. Each entry is one fact a consumer can act
//! on without reading prose; [`std::fmt::Display`] renders it for people.

use std::fmt;

/// One coverage fact about a reference. A record may carry several.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Coverage {
    /// No analysis of it exists.
    Unavailable {
        /// Why, when more than the fact is known.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// It was analyzed, but the analysis has gaps.
    Incomplete,
    /// Deferred to a later run.
    Pending {
        /// What it waits on.
        reason: String,
        /// The hop it was reached at.
        hop: u8,
    },
    /// The artifact already carries this code, so it was not fetched.
    Supplied {
        /// Where in the artifact.
        path: String,
        /// Whether the supplied archive matched the declared pin; `None` when
        /// there was no pin to check it against.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pin_verified: Option<bool>,
    },
    /// A development-only dependency, excluded by policy.
    DevelopmentExcluded,
    /// A transitive dependency, not followed because policy stops at the
    /// first hop.
    TransitiveNotFollowed,
    /// An import that a separately reported declared dependency answers for.
    CoveredByDeclaration,
    /// A candidate for what is installed, not evidence of it.
    Candidate {
        /// What made it a candidate.
        source: CandidateSource,
    },
    /// Severe findings in a candidate that was not accepted. They describe
    /// the candidate, never the artifact that named it.
    CandidateFlagged {
        /// The findings' trait ids.
        findings: Vec<String>,
    },
    /// The fetch budget ran out before it.
    BudgetExceeded {
        /// Which limit was reached.
        notice: String,
        /// Fetches the allowance granted.
        fetches: u64,
        /// Bytes the allowance granted.
        bytes: u64,
    },
    /// Work left unfinished could not be saved for a later run.
    BacklogUnsaved,
}

/// Why a reference is only a candidate for what is installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CandidateSource {
    /// A `package.json` peer dependency range.
    PeerDependency,
    /// An Arch repository package named by a PKGINFO.
    ArchRepository,
    /// A Python import whose namespace a fetched distribution provides.
    PythonImport,
}

impl fmt::Display for Coverage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable { reason: None } => f.write_str("analysis unavailable"),
            Self::Unavailable {
                reason: Some(reason),
            } => write!(f, "analysis unavailable: {reason}"),
            Self::Incomplete => f.write_str("analysis incomplete"),
            Self::Pending { reason, hop } => write!(f, "pending: {reason}; hop={hop}"),
            Self::Supplied { path, pin_verified } => {
                let pin = match pin_verified {
                    Some(true) => "archive pin verified",
                    Some(false) => "archive pin unverified",
                    None => "registry archive identity not verified",
                };
                write!(f, "supplied code already analyzed: {path}; {pin}")
            }
            Self::DevelopmentExcluded => f.write_str("development-only dependency excluded by policy"),
            Self::TransitiveNotFollowed => {
                f.write_str("transitive dependency not followed; see the declaring manifest's outcome")
            }
            Self::CoveredByDeclaration => f.write_str(
                "covered by a separately reported declared dependency; installed version unknown",
            ),
            Self::Candidate { source } => f.write_str(match source {
                CandidateSource::PeerDependency => {
                    "peer dependency candidate; installed version is unknown"
                }
                CandidateSource::ArchRepository => {
                    "Arch repository candidate; installed version and architecture are unknown"
                }
                CandidateSource::PythonImport => {
                    "Python import candidate; namespace present; installed distribution/version unknown"
                }
            }),
            Self::CandidateFlagged { findings } => {
                let shown: Vec<&str> = findings.iter().take(3).map(String::as_str).collect();
                write!(
                    f,
                    "candidate static issues: {} unique severe findings ({})",
                    findings.len(),
                    shown.join(", ")
                )
            }
            Self::BudgetExceeded {
                notice,
                fetches,
                bytes,
            } => write!(
                f,
                "budget exceeded: {notice}; request allowance={fetches}; byte allowance={bytes}"
            ),
            Self::BacklogUnsaved => f.write_str("unfinished work could not be persisted"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coverage_is_tagged_on_the_wire() {
        let facts = [
            Coverage::Unavailable { reason: None },
            Coverage::Pending {
                reason: "supplied code".into(),
                hop: 2,
            },
            Coverage::Candidate {
                source: CandidateSource::PeerDependency,
            },
        ];
        let json = serde_json::to_value(&facts).unwrap();
        assert_eq!(
            json,
            serde_json::json!([
                {"kind": "unavailable"},
                {"kind": "pending", "reason": "supplied code", "hop": 2},
                {"kind": "candidate", "source": "peer_dependency"},
            ])
        );
        let back: Vec<Coverage> = serde_json::from_value(json).unwrap();
        assert_eq!(back, facts);
    }

    #[test]
    fn flagged_candidates_name_three_findings_and_count_all() {
        let flagged = Coverage::CandidateFlagged {
            findings: ["a", "b", "c", "d"].map(String::from).to_vec(),
        };
        assert_eq!(
            flagged.to_string(),
            "candidate static issues: 4 unique severe findings (a, b, c)"
        );
    }
}
