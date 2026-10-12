# Crusade — contributor & agent guide

Self-hosted, keyless Shodan-style service search engine. Scans reachable
services, fingerprints them, enriches (geo/ASN/DNS/TLS), tags vulns + exploits,
classifies auth posture, and makes it all searchable (CLI + web UI + JSON API).

## Non-negotiable constraints
- **Connect-and-read only.** Never exploit, brute-force, submit credentials, or
  attempt authentication. Auth posture is *observed* from a service's own
  response; ICS probes are identification reads only (no writes/control).
- **The blocklist is mandatory.** `crates/scan` hard-codes private/reserved
  ranges that cannot be bypassed from the CLI; `--allow-private` only unlocks
  them for the operator's OWN rig. Any new scan path must route through it.
- **IPv4-wide sweep mode is scaffolded, not run** from a normal machine — it
  needs a sanctioned VPS and is the operator's legal responsibility.

## Workspace
`crates/`: core (model + Shodan-style query parser), store (SQLite+FTS5, query→
SQL compiler, history/alerts/jobs), scan (blocklist/rate/TCP/UDP/masscan),
probe (fingerprint, TLS/JARM/favicon, SSH, UDP, ICS, auth posture), enrich
(geo/ASN/DNS/crt.sh/screenshots), vuln (CVE/KEV + exploit cross-ref + heuristic
tags), web (axum+askama UI + JSON API). Binary `src/`: CLI + pipeline + alerts.

Pipeline: targets → blocklist/rate gate → discovery → probe → enrich → vuln-tag
→ store → index.

## Build / test
```
cargo build --release
cargo test --workspace      # unit + integration tests
cargo clippy --workspace --all-targets
```
`crates/core` and `crates/store` are the shared contract — extend them first,
then the leaf crates. Model fields are additive (serde defaults) so stored JSON
round-trips; when you add one, update every struct literal (including test
fixtures) in the same change.

## Run
```
crusade update-data                      # free GeoIP/ASN, CVE/KEV, exploit feeds
crusade scan <ip|cidr> [--udp --ics --discovery-masscan] [--allow-private]
crusade search '<query>'   crusade stats '<query>'   crusade export '<query>'
crusade serve              crusade monitor            crusade alerts
crusade enqueue <t>...     crusade worker             crusade jobs
```
Local test rig: `cd docker && docker compose up -d` then
`crusade scan 127.0.0.1 --allow-private`.

Query filters: port asn org country city net product version hostname ssl.cn
transport jarm http.favicon.hash ssh.hostkey hassh tag vuln has_vuln ics has_ics
auth has_exploit has_screenshot before after. `-` negates; bare words = FTS.
