//! Optional conformance tests against a local package-url specification checkout.

#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use fletch::purl::{Purl, PurlComponents};

fn documents() -> Option<Vec<PathBuf>> {
    let root = match std::env::var_os("PURL_SPEC_DIR") {
        Some(root) => root,
        None if std::env::var_os("CI").is_some() => {
            panic!("PURL_SPEC_DIR is required in CI")
        }
        None => return None,
    };
    let root = Path::new(&root);
    let mut documents = vec![root.join("tests/spec/specification-test.json")];
    let type_tests = fs::read_dir(root.join("tests/types")).expect("purl-spec type tests");
    documents.extend(type_tests.filter_map(|entry| {
        let path = entry.ok()?.path();
        (path.extension().and_then(|value| value.to_str()) == Some("json")).then_some(path)
    }));
    documents.sort();
    Some(documents)
}

fn cases(test_type: &str) -> Option<Vec<(PathBuf, serde_json::Value)>> {
    let mut cases = Vec::new();
    for path in documents()? {
        let bytes = fs::read(&path).expect("purl-spec test document");
        let document: serde_json::Value =
            serde_json::from_slice(&bytes).expect("valid purl-spec JSON");
        for case in document["tests"].as_array().expect("tests array") {
            if case["test_type"].as_str() == Some(test_type) {
                cases.push((path.clone(), case.clone()));
            }
        }
    }
    Some(cases)
}

fn component_purl(input: &serde_json::Value) -> Option<Purl> {
    let typ = input.get("type")?.as_str()?.to_string();
    let name = input.get("name")?.as_str()?.to_string();
    let namespace = input
        .get("namespace")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .trim_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(str::to_string)
        .collect();
    let version = input
        .get("version")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let qualifiers = input
        .get("qualifiers")
        .and_then(serde_json::Value::as_object)
        .map(|values| {
            values
                .iter()
                .filter_map(|(key, value)| {
                    value.as_str().map(|value| (key.clone(), value.to_string()))
                })
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    let subpath = input
        .get("subpath")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .trim_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty() && !matches!(*segment, "." | ".."))
        .map(str::to_string)
        .collect();
    Purl::from_components(PurlComponents {
        typ,
        namespace,
        name,
        version,
        qualifiers,
        subpath,
    })
    .ok()
}

#[test]
fn every_validate_vector_matches_local_purl_spec() {
    let Some(cases) = cases("validate") else {
        return;
    };
    let mut failures = Vec::new();
    for (path, case) in &cases {
        let input = case["input"].as_str().expect("validate input");
        let expected = case["expected_output"].as_str().map(str::to_string);
        let actual = fletch::purl::normalize(input);
        if actual != expected {
            failures.push(format!(
                "{}: {input}\n  expected {expected:?}\n  actual   {actual:?}",
                path.file_name().unwrap_or_default().to_string_lossy()
            ));
        }
    }
    assert_eq!(cases.len(), 204, "purl-spec validate corpus changed");
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

#[test]
fn every_parse_vector_matches_local_purl_spec() {
    let Some(cases) = cases("parse") else {
        return;
    };
    let mut failures = Vec::new();
    for (path, case) in &cases {
        let input = case["input"].as_str().expect("parse input");
        let actual = Purl::parse_strict(input);
        if case["expected_failure"].as_bool().unwrap_or(false) {
            if actual.is_ok() {
                failures.push(format!(
                    "{}: expected parse failure for {input}",
                    path.display()
                ));
            }
            continue;
        }
        let expected = &case["expected_output"];
        let expected_qualifiers = expected
            .get("qualifiers")
            .filter(|value| !value.is_null())
            .cloned();
        match actual {
            Ok(actual)
                if actual.typ() == expected["type"].as_str().unwrap_or_default()
                    && actual.namespace_string().as_deref() == expected["namespace"].as_str()
                    && actual.name() == expected["name"].as_str().unwrap_or_default()
                    && actual.version() == expected["version"].as_str()
                    && actual.subpath_string().as_deref() == expected["subpath"].as_str()
                    && ((actual.qualifiers().is_empty() && expected_qualifiers.is_none())
                        || serde_json::to_value(actual.qualifiers()).ok()
                            == expected_qualifiers) => {}
            other => failures.push(format!(
                "{}: {input}\n  expected {expected}\n  actual   {other:?}",
                path.display()
            )),
        }
    }
    assert_eq!(cases.len(), 206, "purl-spec parse corpus changed");
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

#[test]
fn every_build_vector_matches_local_purl_spec() {
    let Some(cases) = cases("build") else {
        return;
    };
    let mut failures = Vec::new();
    for (path, case) in &cases {
        let actual = component_purl(&case["input"]).map(|purl| purl.canonical());
        let expected_failure = case["expected_failure"].as_bool().unwrap_or(false);
        let expected = case["expected_output"].as_str().map(str::to_string);
        if (expected_failure && actual.is_some()) || (!expected_failure && actual != expected) {
            failures.push(format!(
                "{}: {}\n  expected {expected:?}\n  actual   {actual:?}",
                path.display(),
                case["description"]
            ));
        }
    }
    assert_eq!(cases.len(), 176, "purl-spec build corpus changed");
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}
