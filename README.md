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
  `GET` and a TLS handshake. No exploit payloads, no auth attempts. Protocols
  are identified on any port, not assumed from the port number: a silent
  service gets the GET after a 2 s wait, and a TLS handshake follows when the
  reply indicates TLS.
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
crusade alerts                                    # recent alerts (webhook/SMTP via [alert])
crusade enqueue 10.0.0.0/24 --ics && crusade worker   # distributed scan queue
crusade scan 198.51.100.0/24 --screenshot         # capture web-UI screenshots (needs Chrome)

# v5: honeypot-aware results
crusade search 'port:22 -honeypot:true'           # hide likely honeypots
crusade search -- -honeypot:true                  # `--` when a query starts with '-'
crusade rescore                                   # recompute honeypot scores offline

# v5: semantic search (CPU-only embedded model, fetched by update-data)
crusade similar router admin login page           # services similar in meaning
crusade similar --like 203.0.113.7:8080 --filter 'country:DE'
crusade embed                                     # backfill vectors for an existing index
```

### Service lifecycle

`monitor` rescans the default ports *and* every port already known on a host,
so services that go away are noticed. A probed port that stays silent is not
deleted on the first miss: it is marked **pending**, stays visible (greyed in
the web UI, listed by `crusade host`), and is evicted only after
`[lifecycle] evict_after_hours` (default 72 h). A host left with no services
is dropped after `forget_after_days` (default 60). Eviction raises a
`service-gone` alert. Ports a run did not probe are never touched. This
mirrors the policy Censys published (SIGCOMM 2025), where a single miss is
usually loss or throttling rather than a real change.

Semantic search uses the Model2Vec static embedding model `potion-base-8M`
(~30 MB, 256 dimensions, CPU-only). Every service is embedded at ingest from
its product, title, server, certificate names and banner; vectors are stored
int8-quantised in SQLite and ranked by exact cosine similarity. Static models
match vocabulary well ("ubuntu apache", "ssh server") and paraphrases less
well. Without the model the feature is simply off.

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
ics has_ics auth has_exploit has_screenshot honeypot before after`; a leading `-` negates; bare/quoted words are
full-text over banners, titles, technologies and SSH banners. Unknown keys fall
back to free text. `net:` accepts IPv4/IPv6 CIDRs; `http.favicon.hash:` takes
the signed mmh3 integer (the Shodan convention) for finding the same deployment.
`auth:open` surfaces services reachable WITHOUT credentials (databases, ICS,
VNC, admin panels) — a prime recon signal; `has_exploit:true` matches hosts
whose detected CVEs have a known public exploit (Exploit-DB / Metasploit). Auth
posture is observed from each service's own response — Crusade never submits
credentials or attempts to authenticate.

`honeypot:true|false` or `honeypot:<0-100>` filters on a passive honeypot
score. Each host is scored from data already collected: a signature pack for
default honeypot configurations (`crates/vuln/rules/honeypot-rules.toml`, overridable at
`<data dir>/honeypot-rules.toml`), SSH banners that claim an OpenSSH release
older than the key-exchange algorithms offered, implausible ICS/IT service
mixes, ICS on cloud ASNs, contradictory OS stacks, ports that accept but never
speak, and port pairs that almost never co-occur across the index. Scores and
their evidence appear in `crusade host` and the web UI; hosts at 50% or more
are tagged `honeypot`. Use `-honeypot:true` to keep honeypots out of exposure
statistics.

## Data sources (all free, no keys)

iptoasn.com ip2asn tables · DB-IP City Lite · nmap-service-probes (ships with
nmap) · NVD CVE JSON 2.0 feeds (fetched by `update-data`) · CISA KEV catalog ·
crt.sh certificate transparency.

## License

MIT. Provided for authorised security research and education.
