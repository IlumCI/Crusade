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
- **Connect-and-read, or a single SYN.** The only bytes Crusade sends are a
  benign HTTP `GET`, a TLS handshake, and (with `--discovery-syn`) one bare SYN
  per port that the kernel then RSTs, leaving no half-open connection on the
  target. No exploit payloads, no auth attempts, no source-address spoofing.
  Protocols are identified on any port, not assumed from the port number: a
  silent service gets the GET after a 2 s wait, and a TLS handshake follows when
  the reply indicates TLS.
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

The web UI exposes the same ranking at `/similar` (and `/api/similar`), with a
"similar services" pivot on every service of a host page.

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
ics has_ics auth has_exploit has_screenshot honeypot ja4ts before after`; a leading `-` negates; bare/quoted words are
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

## Continuous coverage

A one-shot scan picks a port list and runs. A map that stays current has to
cover 65,536 ports across every host, forever, without re-probing the same
ports and without storing a per-host bitmap of what has been tried.

```
crusade monitor --tiers --background 100   # continuous, tiered
crusade coverage                           # how far the index has got
crusade coverage --ip 203.0.113.7          # and what that host gets next
```

Three tiers, following Censys (Durumeric et al., SIGCOMM 2025):

| tier | ports | when |
|---|---|---|
| hot | ~95 common and high-interest ports | every pass |
| cloud | ~55 orchestration/metadata ports | hosts on cloud and hosting ASNs |
| background | N ports from that host's own permutation | every pass |

The background tier is the interesting part. Sampling random ports
independently each pass repeats some and leaves others uncovered forever (the
coupon-collector problem), while remembering what each host has seen costs
8 KiB of bitmap per host — 8 GiB at a million hosts. Instead each host walks a
**keyed permutation** of the port space: a four-round Feistel network over the
16-bit port, keyed by the host's address and an installation salt. That is a
bijection by construction, so one cycle visits every port exactly once with no
gaps, in a different order per host. The only state is a single integer cursor
per host, and the schedule is reproducible from (address, salt, cursor) — which
is what makes it resume after a restart rather than starting a different walk,
and what would let several workers agree without coordinating.

At 100 background ports per pass a host's full port space is covered in 656
passes; at 500, in 132. The cursor advances only after the probes actually go
out, so an interrupted pass re-probes that slice instead of skipping it.
Background results are also the training data for `--predict`, so the
bandwidth earns its keep twice.

The exhaustive test asserts the property the design rests on: for several
keys, all 65,536 positions produce all 65,536 ports with no repeat.

## IPv6

IPv4 can be enumerated; IPv6 cannot. A single /64 holds 18 quintillion
addresses, so there is no sweep to run — hosts must be predicted from
addresses already known, and the prediction *is* the scan.

```
crusade ipv6 --dealias --budget 512 --rounds 5
crusade ipv6 --seeds known-v6.txt --dry-run     # plan only, probe nothing
```

Seeds come from the IPv6 hosts already in the index, plus an optional file.
The pipeline, in the order the research says matters:

1. **Seed hygiene.** Duplicates and unroutable space (link-local,
   unique-local, multicast, documentation, IPv4-mapped) are dropped and
   reported. 6SEVEN (Kanipe et al., IMC 2026, arXiv:2609.08098) ported eight
   published generators into one framework and found seed composition and
   dealiasing moved results more than the choice of algorithm — so this comes
   first, and the generator is a deliberately replaceable baseline.
2. **Aliased-prefix dealiasing.** Some networks answer on *every* address in a
   prefix, which floods a generator with worthless hits. Detection is the
   nybble sweep from Gasser et al. (*Clusters in the Expanse*, IMC 2018):
   probe one address per value of the nybble past the prefix and see whether
   all of them answer. Such a prefix is **collapsed to one representative, not
   discarded** — *Rusty Clusters* (Zirngibl et al., IMC 2022) found over 98% of
   Fastly's announced IPv6 space reads as aliased, so dropping it throws away
   real infrastructure. Verdicts persist in the index and are reused for 90
   days, since the probe costs 16 requests per prefix and the answer is stable.
   Silence is recorded as inconclusive, never as aliased: assuming otherwise
   would silently hide real space.
3. **Generation.** Seeds are grouped by shared nybble prefixes; where several
   seeds share a prefix and the next nybble varies, a provider is handing out
   addresses, and candidates fill in values not yet seen. Densest regions
   first, round-robin so one region cannot starve the budget, and never a seed
   or a duplicate.
4. **Feedback.** Every candidate is reported back, hit or miss, so the next
   round concentrates on regions that answered — the closed loop 6Sense
   (Williams et al., USENIX Security 2024) found separates a usable generator
   from a published one.

Generated candidates are dealiased too, not just seeds, so a known aliased
prefix cannot soak up a round's budget.

**Caveat on testing.** The logic above is unit-tested (address arithmetic,
probe-set construction, alias classification, seed cleaning, generation,
feedback), and the CLI is exercised end to end with `--dry-run`. It has *not*
been run against live IPv6: the development container has no IPv6 stack at
all. Treat the generator's real-world hit rate as unmeasured.

## Predictive discovery

Probing every port of every host is unaffordable — 65,535 ports across a /16
is 4.3 billion probes — but services are not independent. A host with 3306
open probably also runs 22; a host with 102 open is industrial equipment and
almost certainly runs neither. `crusade scan --predict <n>` exploits that: a
cheap seed pass finds one service, then the index says where that host's other
services are likely to be, and only those get probed.

```
crusade scan 203.0.113.0/24 --predict 16
```

The model (`crates/core/src/ports.rs`) learns port and port-pair frequencies
from *your* index, so it describes the population you actually scan. Each
observed port contributes its own conditional and they combine with a
noisy-OR, so evidence accumulates: a port predicted by several observations
outranks one predicted by a single weak signal. Nothing is suggested without
at least 20 supporting hosts, and the whole phase is skipped below 200 indexed
hosts — the model says nothing rather than guessing. `--predict` is a cap, not
a quota: asking for 32 when only 12 ports have evidence costs 12 probes.

Evaluated with a train/test split over a synthetic population of archetypes
(`cargo run --release -p crusade-core --example predict_eval`):

| strategy | probes | recall |
|---|---|---|
| 8 seed ports only | 80,000 | 62.8% |
| seed + predict 16 | 149,033 | **84.8%** |
| every port | 655,350,000 | 100% |

Prediction adds 22 points of recall for 1.9x the seed probes, reaching 84.8%
of exhaustive recall with ~4,400x less bandwidth. The honest limit is the
first phase: 8,631 of 10,000 test hosts answered on a seed port at all, and
the rest are invisible to any two-phase scan however good the prediction is.
This follows GPS (Izhikevich et al., SIGCOMM 2022, arXiv:2303.00895), which
reports 92.5% of services at 131x less bandwidth against real IPv4.

## Discovery engines

| Engine | How | Needs |
|--------|-----|-------|
| connect (default) | full TCP handshake per port | nothing |
| `--discovery-syn` | one stateless SYN per port | `CAP_NET_RAW`, IPv4 |
| `--discovery-masscan` | shells out to `masscan` | `masscan` binary |
| `crusade sweep ingest` | masscan/zmap output from elsewhere | a sanctioned sweep host |

QUIC is probed by default on UDP/443: a host can serve its whole site over
HTTP/3 and look closed to a TCP-only scan. Identification needs one datagram
and no handshake — an Initial naming a reserved version forces the server to
reply with a Version Negotiation packet listing what it supports (RFC 9000
§6, the approach QScanner took in *It's over 9000*, IMC 2021). The reply is
unauthenticated, so the connection IDs are checked against the ones sent
before it is believed.

Ingesting zmap 4.4 output also carries its newer fields: SYN RTT is summarised
(a reply much faster than a network's other hosts usually came from a
middlebox in front of them), and the JA4TS stack fingerprint is stored and
pivotable with `ja4ts:` — the TCP-stack counterpart to `jarm:` and `hassh:`.

The connect scanner is bounded by `concurrency / timeout` whenever a target
does not answer — the common case on the open internet. At Crusade's defaults
(500 concurrent, 3 s timeout) that is ~167 ports/s, and measured 166. The
stateless SYN scanner (`crates/scan/src/syn.rs`) is bounded only by the send
rate, measuring ~83,000 probes/s from one thread on a 4-core container:

```
cargo run --release -p crusade-scan --example discovery_bench -- 40000 20000 1000000 50 50
connect:  120.14s        166 ports/s     # 20k unresponsive ports, 3s timeout
syn:        0.24s      83065 ports/s
```

That is the difference between ~258 days and ~12 hours for a single port
across routable IPv4. It follows ZMap (Durumeric et al., USENIX Security
2013): the SYN's sequence number is a keyed hash of the target tuple, so a
reply is validated from the packet itself and no per-target state is kept.
Discovery only finds open ports; banner grabbing is a separate ordinary
connection to the ports found, so app-layer work happens only where something
answered.

**Running a sweep is still an operational decision, not just a flag.** A host
whose provider permits scanning, a published abuse contact, reverse DNS
identity and a working opt-out are what make wide scanning legitimate; see
*Responsible use* above.

## Archiving and retention

Three things grow without bound: the scan timeline, the alert log, and the host
table itself as sweeps reach new address space. Crusade decides what is
expendable by measuring, not guessing: every host carries `last_seen` (when it
last answered) and `last_accessed` (when it was last surfaced to someone,
through a search page, a host view or the API). A host that has neither
answered nor been looked at is the first thing to go; a host someone keeps
opening is kept however old it is.

```
crusade archive --status     # where the space is going, and what qualifies
crusade archive --dry-run    # what would be removed, changing nothing
crusade archive              # archive, delete, reclaim
```

Hosts are written to a gzipped JSON Lines file under `<data dir>/archive/`
**before** they are deleted — the same format `crusade export` produces, so an
archive can be read back with the same tools. Nothing is deleted that was not
written out first.

With `[archive] max_db_mb` set, this happens on its own once the database
passes that size, after a scan or a monitor pass. It escalates cheapest-first
and stops as soon as the database is back under the limit:

1. expired and derived rows — facet cache, old delivered alerts, finished
   jobs, timeline entries past retention (the newest entry per service is
   always kept);
2. screenshots on disk that no service references any more;
3. stale, never-visited hosts, least useful first, in bounded batches.

Undelivered alerts hold their host back, so nothing is archived out from under
an alert nobody has seen. Progress is judged by live bytes (allocated minus
free pages) rather than file size, because deletes free pages for reuse without
shrinking the file; one `VACUUM` at the end returns the space, and only if
something was actually removed. A run that cannot find anything eligible says
so instead of silently doing nothing.

Measured on 30k synthetic hosts, 75% of them stale and unvisited:

```
archive --status   102.1 MiB, 30000 hosts, 27600 never viewed, 20100 eligible
archive            20100 hosts to 11 files; 102.1 MiB -> 35.9 MiB
auto (20 MiB cap)  6000 hosts in 3 batches; 35.9 MiB -> 13.5 MiB, then stops
```

## Lazy loading and caching

Nothing is read until something needs it, and expensive derived data is built
once rather than per run.

| | before | after |
|---|---|---|
| scan that finds no open ports | 7.58 s | **0.008 s** (nothing loads) |
| CVE data ready to query | 6,029 ms (parse ~470 MB JSON) | **1 ms** (open indexed cache) |
| facets over the whole index, repeat view | 2,422 ms | **0.1 ms** |

* **Datasets load on first use.** `Datasets` holds each dataset behind a
  `OnceLock`: nmap probes load when a banner needs fingerprinting, geo/ASN when
  a host needs enrichment, the embedding model only if embedding is on. A run
  that discovers nothing loads nothing.
* **CVE data is an indexed cache, not a parse.** `update-data` parses the feeds
  once into `data/cve-cache.db` (319k CVEs, 2.6M match rules) indexed by
  product; scans open it and query per product, so memory stays flat instead of
  holding every CVE. A `meta` fingerprint of the source feeds means a newly
  downloaded feed rebuilds the cache rather than being silently ignored. Delete
  the file and it rebuilds; without it, scans fall back to parsing the feeds.
* **An in-process memo** caches product lookups, since one scan meets the same
  few products repeatedly.
* **Facets are cached against a write generation.** Every write transaction
  bumps a counter, so a cached aggregate is served only while the data behind
  it is unchanged, and is recomputed otherwise — no staleness window to reason
  about.
* **Writes are batched.** The pipeline writes hosts 200 per transaction, and
  `Store::upsert_hosts` is the bulk entry point.

## Scale and performance

`cargo run --release -p crusade-store --example ingest_bench -- <hosts> <services> <batch>`
measures ingest and query cost against synthetic hosts on a real database.
On a 4-core container, 200k hosts x 3 services:

| | |
|---|---|
| ingest (batched) | ~4,800 hosts/s, ~14,400 services/s |
| on disk | ~5.8 KiB per host |
| page of 25 results | 0.5–3 ms (80–320 ms for `net:` and free-text, which sort large match sets) |
| exact count | 1.5–290 ms depending on selectivity |
| capped count | 0.4–200 ms, and never slower than exact |
| facets over the whole index | ~2.2 s |

Use `Store::upsert_hosts` for bulk ingest: one transaction per host is
dominated by commit cost, and batching is ~8x faster. `service_history`
records *changes* rather than passes — an unchanged rescan appends nothing —
so a monitor can run continuously without the timeline growing without bound.
Search pages use `count_capped` and render "10,000+" rather than scanning the
whole index for an exact total; the JSON API still reports exact counts.
Faceting the whole index is the remaining slow path.

## Data sources (all free, no keys)

iptoasn.com ip2asn tables · DB-IP City Lite · nmap-service-probes (ships with
nmap) · NVD CVE JSON 2.0 feeds (fetched by `update-data`) · CISA KEV catalog ·
crt.sh certificate transparency.

## License

MIT. Provided for authorised security research and education.
