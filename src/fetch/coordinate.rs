//! Coordinate helpers: a PURL's registry base, and the vetting that keeps a
//! coordinate from restructuring a registry URL.

use crate::purl::Purl;

/// Whether a URL names a web scheme this module's own client can carry.
/// Compared ASCII-case-insensitively, since schemes are.
pub(crate) fn is_web_scheme(url: &str) -> bool {
    let b = url.as_bytes();
    b.get(..7)
        .is_some_and(|p| p.eq_ignore_ascii_case(b"http://"))
        || b.get(..8)
            .is_some_and(|p| p.eq_ignore_ascii_case(b"https://"))
}

/// The registry base URL: the PURL's `repository_url` qualifier when it names
/// a web URL, `default` when it is absent, and `None` for any other scheme.
pub(crate) fn repository_base(purl: &Purl, default: &str) -> Option<String> {
    match purl.qualifier("repository_url") {
        Some(repository) if is_web_scheme(repository) => {
            Some(repository.trim_end_matches('/').to_string())
        }
        Some(_) => None,
        None => Some(default.to_string()),
    }
}

/// Whether a decoded PURL qualifier can safely be embedded as one artifact
/// filename component. Reject separators and URL delimiters instead of letting
/// a crafted classifier/type change the Maven repository path.
pub(crate) fn safe_filename_part(value: &str) -> bool {
    !value.is_empty()
        && !value
            .bytes()
            .any(|b| matches!(b, b'/' | b'\\' | b'?' | b'#'))
}

/// Whether a PURL's coordinate path or version may be interpolated into a
/// registry URL.
///
/// Every ecosystem builds its endpoint by `format!`-ing these straight into a
/// path or query, and they come from a scanned manifest — attacker-controlled.
/// The literal `https://host/` prefix means no value can move the *host*, but
/// it can still restructure the rest of the URL: `..` climbs out of the
/// intended path, `?`/`#` truncate it into a query or fragment, and `\` is a
/// path separator under the WHATWG rules the URL parser applies. The result is
/// a record whose bytes came from somewhere other than the coordinate it is
/// filed under — provenance the whole tool rests on.
///
/// Rejecting is safe: no registry issues a name or version containing these,
/// so a coordinate that does is not a package. It resolves to
/// [`Unresolved::UnsafeCoordinate`](crate::fetch::Unresolved::UnsafeCoordinate) and is recorded,
/// never silently dropped.
pub(crate) fn safe_coordinate(value: &str) -> bool {
    safe_coordinate_inner(value, false)
}

/// [`safe_coordinate`] over a PURL's coordinate path and version, as every
/// resolver that builds a URL from them applies it. Only a Maven version may
/// carry an encoded space.
pub(crate) fn safe_purl_coordinates(ty: &str, path: &str, version: Option<&str>) -> bool {
    safe_coordinate(path) && version.is_none_or(|v| safe_coordinate_inner(v, ty == "maven"))
}

fn safe_coordinate_inner(value: &str, allow_encoded_space: bool) -> bool {
    let decoded = percent_decode(value);
    value.bytes().filter(|byte| *byte == b'/').count()
        == decoded.bytes().filter(|byte| *byte == b'/').count()
        && !decoded
            .split('/')
            .any(|segment| segment == ".." || segment == ".")
        && !value
            .bytes()
            .any(|b| b.is_ascii_control() || matches!(b, b' ' | b'\\' | b'?' | b'#' | b'"'))
        && !decoded.bytes().any(|b| {
            b.is_ascii_control()
                || matches!(b, b'\\' | b'?' | b'#' | b'"')
                || (b == b' ' && !allow_encoded_space)
        })
}

/// Decode percent-escapes (`%2F` → '/'). Malformed escapes pass through
/// literally rather than failing — a best-effort mirror of how lenient purl
/// parsers treat them.
pub(crate) fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let decoded = (b[i] == b'%')
            .then(|| b.get(i + 1..i + 3).and_then(crate::purl::hex_pair))
            .flatten();
        match decoded {
            Some(c) => {
                out.push(c);
                i += 3;
            }
            None => {
                out.push(b[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}
