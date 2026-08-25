//! Optional conformance test against a local package-url specification checkout.

#![allow(clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::Path;

#[test]
fn validate_vectors_match_local_purl_spec() {
    let Some(root) = std::env::var_os("PURL_SPEC_DIR") else {
        return;
    };
    let root = Path::new(&root);
    let mut documents = vec![root.join("tests/spec/specification-test.json")];
    let type_tests = fs::read_dir(root.join("tests/types")).expect("purl-spec type tests");
    documents.extend(type_tests.filter_map(|entry| {
        let path = entry.ok()?.path();
        (path.extension().and_then(|value| value.to_str()) == Some("json")).then_some(path)
    }));
    documents.sort();

    let mut failures = Vec::new();
    let mut checked = 0;
    for path in documents {
        let bytes = fs::read(&path).expect("purl-spec test document");
        let document: serde_json::Value = serde_json::from_slice(&bytes).expect("valid test JSON");
        for case in document["tests"].as_array().expect("tests array") {
            if case["test_type"].as_str() != Some("validate") {
                continue;
            }
            checked += 1;
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
    }
    assert!(checked > 0, "no purl-spec validate vectors found");
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}
