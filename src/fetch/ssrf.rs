//! The SSRF floor every request passes: the public-address rules, the literal-IP
//! host guard, and the DNS resolver that enforces them on every hop.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

use crate::fetch::transport::FetchError;

/// Whether an address must not be fetched — private, loopback, link-local
/// (incl. the 169.254.169.254 metadata endpoint), CGNAT, ULA, or reserved.
///
/// This is an allowlist-shaped problem solved with a denylist, because
/// `is_global` is still unstable. So it is written to fail closed on the
/// *spellings* of an internal address rather than on one canonical form: every
/// way v6 can carry a v4 destination is unwrapped and re-checked.
fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_v4(v4),
        IpAddr::V6(v6) => is_blocked_v6(v6),
    }
}

fn is_blocked_v4(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local() // 169.254.0.0/16, incl. the cloud metadata IP
        || v4.is_broadcast()
        || v4.is_documentation()
        || v4.is_unspecified()
        || v4.is_multicast() // 224.0.0.0/4
        || o[0] == 0 // 0.0.0.0/8
        || (o[0] == 100 && (64..=127).contains(&o[1])) // CGNAT 100.64.0.0/10
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // IETF protocol assignments
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // benchmarking 198.18.0.0/15
        || o[0] >= 240 // reserved 240.0.0.0/4
}

/// Whether an IPv6 address must not be fetched.
///
/// The transition mechanisms are the interesting part. Each one embeds an IPv4
/// destination that a translator or relay on the host's path will carry for
/// you, so each is a way to spell an internal v4 target in v6 — and a guard
/// that only understands `::ffff:a.b.c.d` waves the rest through. Rather than
/// ban the prefixes outright (which would break fletch on a NAT64-only
/// network, where reaching any public v4 host legitimately goes through
/// `64:ff9b::`), unwrap the embedded address and apply the v4 rules to it.
fn is_blocked_v6(v6: Ipv6Addr) -> bool {
    // Both v4-in-v6 forms: `::ffff:a.b.c.d` (mapped) and the deprecated
    // `::a.b.c.d` (compatible) that `to_ipv4_mapped` alone does not see. This
    // also subsumes `::1` and `::`, which unwrap into the blocked 0.0.0.0/8.
    if let Some(v4) = v6.to_ipv4() {
        return is_blocked_v4(v4);
    }
    let s = v6.segments();
    let embedded = |hi: u16, lo: u16| Ipv4Addr::from((u32::from(hi) << 16) | u32::from(lo));
    if s[0] == 0x2002 && is_blocked_v4(embedded(s[1], s[2])) {
        return true; // 6to4: 2002:<v4>::/48
    }
    if s[0] == 0x0064 && s[1] == 0xff9b && is_blocked_v4(embedded(s[6], s[7])) {
        return true; // NAT64 well-known prefix: 64:ff9b::<v4>/96
    }
    v6.is_loopback()
        || v6.is_unspecified()
        || v6.is_multicast() // ff00::/8
        || (s[0] & 0xfe00) == 0xfc00 // unique-local fc00::/7
        || (s[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
        || (s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0x0001) // NAT64 local-use /48
        || (s[0] == 0x2001 && s[1] == 0x0000) // Teredo 2001::/32
        || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation 2001:db8::/32
}

/// reqwest DNS resolver that resolves a host and returns only its globally
/// routable addresses, refusing the lookup if none remain. Installed on the
/// client, it runs for the initial request *and every redirect hop*, so an
/// attacker can't redirect into the internal network or DNS-rebind.
#[derive(Debug)]
pub(crate) struct SafeResolver;

/// [`SafeResolver`]'s refusal. A type of its own so `map_send_err` can pick
/// it out of reqwest's error chain, where it sits beside ordinary connect
/// failures (no such host, connection refused).
#[derive(Debug, thiserror::Error)]
#[error("refused non-public host: {0}")]
pub(crate) struct NonPublicHost(String);

impl reqwest::dns::Resolve for SafeResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        type BoxError = Box<dyn std::error::Error + Send + Sync>;
        let host = name.as_str().to_string();
        Box::pin(async move {
            // getaddrinfo blocks, and the blocking client drives every request
            // on one runtime thread, so resolve off it as reqwest's own
            // resolver does.
            let lookup = host.clone();
            let resolved =
                tokio::task::spawn_blocking(move || (lookup.as_str(), 0u16).to_socket_addrs())
                    .await
                    .map_err(BoxError::from)?
                    .map_err(BoxError::from)?;
            let safe: Vec<SocketAddr> = resolved.filter(|a| !is_blocked_ip(a.ip())).collect();
            if safe.is_empty() {
                return Err(BoxError::from(NonPublicHost(host)));
            }
            Ok(Box::new(safe.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// The pre-connect floor every request passes — each GET hop and the one POST:
/// https only, and refuse a literal-IP host the DNS resolver never sees (the
/// SSRF resolver guards hostname targets; a bare IP must be checked directly).
pub(crate) fn guard_host(url: &reqwest::Url) -> Result<(), FetchError> {
    if url.scheme() != "https" {
        return Err(FetchError::Refused(format!(
            "non-https scheme: {}",
            url.scheme()
        )));
    }
    match url.host_str() {
        Some(host) => {
            let bare = host
                .strip_prefix('[')
                .and_then(|s| s.strip_suffix(']'))
                .unwrap_or(host);
            if let Ok(ip) = bare.parse::<IpAddr>()
                && is_blocked_ip(ip)
            {
                return Err(FetchError::Refused(format!("non-public host: {host}")));
            }
            Ok(())
        }
        None => Err(FetchError::Refused("missing host".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssrf_blocks_internal_addresses() {
        let blocked = [
            "127.0.0.1",
            "10.0.0.5",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254", // cloud metadata
            "100.64.0.1",      // CGNAT
            "0.0.0.0",
            "240.0.0.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:127.0.0.1", // IPv4-mapped loopback
            "::ffff:10.0.0.1",  // IPv4-mapped private
            // Alternate spellings of an internal v4 target. Each of these
            // reaches the same place as an entry above, via a translator or
            // relay, and each passed a guard that only unwrapped `::ffff:`.
            "::127.0.0.1",        // deprecated IPv4-compatible loopback
            "::169.254.169.254",  // IPv4-compatible cloud metadata
            "2002:7f00:1::",      // 6to4 wrapping 127.0.0.1
            "2002:a9fe:a9fe::",   // 6to4 wrapping 169.254.169.254
            "64:ff9b::7f00:1",    // NAT64 wrapping 127.0.0.1
            "64:ff9b::a9fe:a9fe", // NAT64 wrapping 169.254.169.254
            "64:ff9b:1::1",       // NAT64 local-use prefix
            "2001:0:1234::1",     // Teredo
            "2001:db8::1",        // documentation
            "ff02::1",            // multicast
            "224.0.0.1",          // v4 multicast
            "198.18.0.1",         // benchmarking range
            "192.0.0.1",          // IETF protocol assignments
        ];
        for ip in blocked {
            assert!(
                is_blocked_ip(ip.parse().expect("ip")),
                "{ip} should be blocked"
            );
        }
        let allowed = [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "2606:4700:4700::1111",
            // A NAT64/6to4 wrapper around a *public* v4 stays reachable: on an
            // IPv6-only network that is the only route to it.
            "64:ff9b::8080:808", // NAT64 wrapping 8.8.8.8
            "2002:101:101::",    // 6to4 wrapping 1.1.1.1
        ];
        for ip in allowed {
            assert!(
                !is_blocked_ip(ip.parse().expect("ip")),
                "{ip} should be allowed"
            );
        }
    }
}
