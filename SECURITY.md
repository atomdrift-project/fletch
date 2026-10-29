# Security policy

fletch retrieves content named by files it is asked to analyze, so every input
it handles — the scanned file, registry responses, archives, container layers —
is treated as attacker-controlled. Reports of any way around that are welcome.

## Reporting a vulnerability

Please report privately through GitHub's
[private vulnerability reporting](https://github.com/atomdrift-project/fletch/security/advisories/new)
rather than a public issue. Include the input that triggers the problem and
what you observed. You should receive an acknowledgement within a few days.

## In scope

- Reaching a host or address the SSRF guard should refuse (private, loopback,
  link-local, metadata, non-global IPv6), including via redirects or DNS.
- Sending `GITHUB_TOKEN` anywhere other than a GitHub API URL fletch built.
- A pinned hash accepted for bytes that do not match it, or the reverse.
- Unbounded memory, CPU, or disk use driven by a scanned file or a response.
- Cache poisoning, or a cache entry readable or writable by another user.
- A record that attributes bytes or metadata to a package other than the one
  they came from.

## Known limitations

- Owner-only cache permissions and the sweep's ownership check apply on Unix;
  on Windows the cache inherits the parent directory's ACL.
- An operator-chosen NAT64 prefix inside 2000::/3 can embed an IPv4 address at
  an offset the guard cannot know; only the well-known 64:ff9b::/96 is unwrapped.
- The flattened container rootfs is an analysis artifact. It preserves symlinks
  and modes as the image declares them and must never be extracted to disk.
