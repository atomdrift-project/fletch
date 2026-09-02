//! Postel's law has a second half: liberal in what it accepts, *consistent* in
//! what it emits. Every spelling of one coordinate must collapse to a single
//! canonical string, or downstream caches key the same artifact twice.
#![allow(clippy::panic)]

use fletch::purl::normalize;

/// Each group is one package written several legal ways. Normalizing any of
/// them must produce the same string, and that string must be a fixed point.
fn assert_agrees(group: &[&str]) {
    let mut canonical: Option<(String, String)> = None;
    for raw in group {
        let got = normalize(raw).unwrap_or_else(|| panic!("rejected {raw}"));
        assert_eq!(
            normalize(&got).as_deref(),
            Some(got.as_str()),
            "{raw} -> {got} is not a fixed point"
        );
        match &canonical {
            None => canonical = Some(((*raw).to_string(), got)),
            Some((first, want)) => assert_eq!(
                &got, want,
                "\n  {first} -> {want}\n  {raw} -> {got}\nsame coordinate, two canonical forms"
            ),
        }
    }
}

#[test]
fn go_plus_incompatible_has_one_canonical_form() {
    assert_agrees(&[
        "pkg:golang/github.com/gofrs/uuid@v4.4.0+incompatible",
        "pkg:golang/github.com/gofrs/uuid@v4.4.0%2Bincompatible",
        "pkg:golang/github.com/gofrs/uuid@v4.4.0%2bincompatible",
    ]);
}

#[test]
fn go_pseudo_version_with_plus_has_one_canonical_form() {
    assert_agrees(&[
        "pkg:golang/github.com/bagisto/bagisto@v2.4.11-0.20260901140043-20e535723f8d+incompatible",
        "pkg:golang/github.com/bagisto/bagisto@v2.4.11-0.20260901140043-20e535723f8d%2Bincompatible",
    ]);
}

#[test]
fn go_uppercase_module_path_has_one_canonical_form() {
    assert_agrees(&[
        "pkg:golang/github.com/BurntSushi/toml@v1.4.0",
        "pkg:GOLANG/github.com/BurntSushi/toml@v1.4.0",
    ]);
}

#[test]
fn go_scheme_and_slashes_have_one_canonical_form() {
    assert_agrees(&[
        "pkg:golang/google.golang.org/genproto#googleapis/api/annotations",
        "pkg:GOLANG/google.golang.org/genproto#/googleapis/api/annotations/",
    ]);
}
