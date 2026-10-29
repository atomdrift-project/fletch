//! Conformance tests against the package-url specification's test vectors.
//!
//! The vectors are vendored under `tests/data/purl-spec` (purl-spec commit
//! `7cd2d3442fb9c88155db17ada7c911b40ec22d41`, MIT-licensed, see its
//! `LICENSE`), so these always run. Set `PURL_SPEC_DIR` to another checkout to
//! test against it instead. The vendored corpus's size is pinned, after the
//! conformance report, so a vector silently dropped from it fails the run.

#![allow(clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

use fletch::purl::Purl;
use serde_json::Value;

/// The corpus root, and whether it is the vendored one.
fn root() -> (PathBuf, bool) {
    std::env::var_os("PURL_SPEC_DIR").map_or_else(
        || {
            (
                Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/purl-spec"),
                true,
            )
        },
        |dir| (PathBuf::from(dir), false),
    )
}

fn documents(root: &Path) -> Vec<PathBuf> {
    let mut documents = vec![root.join("tests/spec/specification-test.json")];
    let type_tests = fs::read_dir(root.join("tests/types")).expect("purl-spec type tests");
    documents.extend(type_tests.filter_map(|entry| {
        let path = entry.ok()?.path();
        (path.extension().and_then(|value| value.to_str()) == Some("json")).then_some(path)
    }));
    documents.sort();
    documents
}

/// Every case of `test_type`, with the file it came from.
fn cases(test_type: &str) -> (Vec<(String, Value)>, bool) {
    let (root, vendored) = root();
    let mut cases = Vec::new();
    for path in documents(&root) {
        let bytes = fs::read(&path).expect("purl-spec test document");
        let document: Value = serde_json::from_slice(&bytes).expect("valid purl-spec JSON");
        let file = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        for case in document["tests"].as_array().expect("tests array") {
            if case["test_type"].as_str() == Some(test_type) {
                cases.push((file.clone(), case.clone()));
            }
        }
    }
    (cases, vendored)
}

/// Fail with every mismatch, then, for the vendored corpus only, with a
/// changed corpus size.
fn report(failures: &[String], cases: usize, vendored: bool, vendored_cases: usize) {
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
    if vendored {
        assert_eq!(cases, vendored_cases, "vendored purl-spec corpus changed");
    }
}

#[test]
fn every_validate_vector_matches_purl_spec() {
    let (cases, vendored) = cases("validate");
    let mut failures = Vec::new();
    for (file, case) in &cases {
        let input = case["input"].as_str().expect("validate input");
        let expected = case["expected_output"].as_str().map(str::to_string);
        let actual = fletch::purl::normalize(input);
        if actual != expected {
            failures.push(format!(
                "{file}: {input}\n  expected {expected:?}\n  actual   {actual:?}"
            ));
        }
    }
    report(&failures, cases.len(), vendored, 204);
}

#[test]
fn every_parse_vector_matches_purl_spec() {
    let (cases, vendored) = cases("parse");
    let mut failures = Vec::new();
    for (file, case) in &cases {
        let input = case["input"].as_str().expect("parse input");
        let actual = Purl::parse_strict(input);
        if case["expected_failure"].as_bool().unwrap_or(false) {
            if actual.is_ok() {
                failures.push(format!("{file}: expected parse failure for {input}"));
            }
            continue;
        }
        let expected = &case["expected_output"];
        let expected_qualifiers = expected
            .get("qualifiers")
            .filter(|value| !value.is_null())
            .cloned();
        let joined = |segments: &[String]| (!segments.is_empty()).then(|| segments.join("/"));
        match actual {
            Ok(actual)
                if actual.typ() == expected["type"].as_str().unwrap_or_default()
                    && joined(actual.namespace()).as_deref() == expected["namespace"].as_str()
                    && actual.name() == expected["name"].as_str().unwrap_or_default()
                    && actual.version() == expected["version"].as_str()
                    && joined(actual.subpath()).as_deref() == expected["subpath"].as_str()
                    && ((actual.qualifiers().is_empty() && expected_qualifiers.is_none())
                        || serde_json::to_value(actual.qualifiers()).ok()
                            == expected_qualifiers) => {}
            other => failures.push(format!(
                "{file}: {input}\n  expected {expected}\n  actual   {other:?}"
            )),
        }
    }
    report(&failures, cases.len(), vendored, 206);
}

/// The build inputs go to the library exactly as the spec spells them.
#[test]
fn every_build_vector_matches_purl_spec() {
    let (cases, vendored) = cases("build");
    let mut failures = Vec::new();
    for (file, case) in &cases {
        let input = &case["input"];
        let text = |key: &str| input[key].as_str();
        let qualifiers = input["qualifiers"]
            .as_object()
            .into_iter()
            .flatten()
            .filter_map(|(key, value)| Some((key.as_str(), value.as_str()?)));
        let actual = Purl::build(
            text("type").unwrap_or_default(),
            text("namespace"),
            text("name").unwrap_or_default(),
            text("version"),
            qualifiers,
            text("subpath"),
        )
        .ok()
        .map(|purl| purl.to_string());
        let expected_failure = case["expected_failure"].as_bool().unwrap_or(false);
        let expected = case["expected_output"].as_str().map(str::to_string);
        if (expected_failure && actual.is_some()) || (!expected_failure && actual != expected) {
            failures.push(format!(
                "{file}: {}\n  expected {expected:?}\n  actual   {actual:?}",
                case["description"]
            ));
        }
    }
    report(&failures, cases.len(), vendored, 176);
}
