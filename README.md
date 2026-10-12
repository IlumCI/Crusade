# Crusade

A self-hosted, no-API-key service search engine in the spirit of Shodan/Censys.
Crusade scans reachable hosts on the public internet, grabs and fingerprints
service banners, enriches results with geo/ASN, DNS and TLS-certificate data,
tags known vulnerabilities, and makes everything searchable through a
Shodan-style query language and a web UI — all from free, public data sources.

It **catalogues** services (connect-and-read only). It does not exploit,
brute-force, or attempt authentication against anything.

## Responsible use (read this first)

Crusade is a security-research tool. Scanning hosts you do not own or are not
explicitly authorised to scan may be unlawful in your jurisdiction and will
likely violate your ISP's or cloud provider's acceptable-use policy. **You are
responsible for how you use it.**

Built-in safeguards, on by default:

- **Mandatory blocklist.** Private/reserved ranges are hard-coded skips in code
  and can never be bypassed from the CLI. Add further opt-out networks to
  `blocklist.txt` (or `crusade blocklist add <cidr>`).
- **Connect-and-read only.** The only bytes Crusade sends are a benign HTTP
  `GET` and a TLS handshake. No exploit payloads, no auth attempts.
- **Conservative rate limits.** Targeted scans are gently rate-limited.
  IPv4-wide sweep mode is **scaffolded but intentionally not run from a normal
  machine**: it requires a sanctioned scanning VPS, an explicit high rate set in
  config, and a reachable abuse contact / opt-out page (the ZMap
  "good-internet-citizen" conventions). Enabling and running a sweep is the
  operator's responsibility.

Develop and test against the local docker rig (`docker/`) and your own hosts.

## Build

```
cargo build --release
cargo test        # unit tests across all crates
```

## Quick start (local test rig)

```
cd docker && docker compose up -d && cd ..
crusade update-data                      # fetch free GeoIP/ASN + CVE/KEV feeds
crusade scan 127.0.0.1 --allow-private   # scan your own test rig
crusade search 'product:nginx'
crusade serve                            # web UI at http://127.0.0.1:8088

# v2: deep probes, UDP, operations
crusade scan 203.0.113.0/24 --udp                 # + read-only UDP protocol probes
crusade scan 10.0.0.0/16 --discovery-masscan      # masscan front-end (blocklist-enforced)
crusade stats 'product:nginx'                     # faceted breakdown for a query
crusade export 'country:DE' --out de.jsonl        # JSON Lines, like `shodan download`
crusade monitor --interval 3600 --stale 86400     # rescan + alert on new ports/CVEs
```

Each probed service can carry a JARM fingerprint, favicon mmh3 hash, TLS
version/cipher, detected technologies and security headers, and (for SSH) the
HASSH, offered KEX algorithms and host-key type — all pivotable in the query
language.

## Layout

| Crate   | Responsibility |
|---------|----------------|
| `core`  | Data model + Shodan-style query language (parser → AST) |
| `store` | SQLite persistence, FTS5 search, faceting, query→SQL compiler |
| `scan`  | Blocklist/rate guardrails, TCP-connect scanner, masscan/zmap ingestion |
| `probe` | Banner grabbing, nmap-service-probes fingerprinting, TLS/HTTP parsing |
| `enrich`| GeoIP/ASN, reverse DNS, crt.sh; screenshot seam (v2) |
| `vuln`  | CPE→CVE matching (NVD + CISA KEV) and heuristic tags |
| `web`   | axum + askama read-only UI and JSON API |

## Query language

`port:443 country:DE product:nginx "default page" after:2026-01-01 -tag:honeypot`

Filters: `port asn org country city net product version hostname ssl.cn
transport jarm http.favicon.hash ssh.hostkey hassh tag vuln has_vuln
ics has_ics auth has_exploit has_screenshot before after`; a leading `-` negates; bare/quoted words are
full-text over banners, titles, technologies and SSH banners. Unknown keys fall
back to free text. `net:` accepts IPv4/IPv6 CIDRs; `http.favicon.hash:` takes
the signed mmh3 integer (the Shodan convention) for finding the same deployment.
`auth:open` surfaces services reachable WITHOUT credentials (databases, ICS,
VNC, admin panels) — a prime recon signal; `has_exploit:true` matches hosts
whose detected CVEs have a known public exploit (Exploit-DB / Metasploit). Auth
posture is observed from each service's own response — Crusade never submits
credentials or attempts to authenticate.

## Data sources (all free, no keys)

iptoasn.com ip2asn tables · DB-IP City Lite · nmap-service-probes (ships with
nmap) · NVD JSON CVE feeds · CISA KEV catalog · crt.sh certificate transparency.

## License

MIT. Provided for authorised security research and education.
