# Crusade frontier plan (v5)

Research survey as of 2026-10-12 and the upgrade plan derived from it. Goal:
move Crusade from "keyless Shodan clone" to a keyless engine that tracks the
published state of the art in Internet-wide service measurement, with
honeypot-aware data quality and CPU-only embedded models. All scanning stays
connect-and-read and blocklist-gated; nothing below changes that contract.

Citations were checked against arXiv / venue pages at time of writing.
GitHub links could not be fetched from the research environment and are
unverified.

## 0. Primary reference

- Durumeric et al., *Censys: A Map of Internet Hosts and Services*, SIGCOMM
  2025, doi:10.1145/3718958.3754344. The most current published design of a
  production engine: tiered port selection, continuous scanning, predictive
  models, eviction state machine, delta-encoded journal. Most items in sections
  1 and 2 trace back to it.

## 1. Discovery

| # | Change | Basis | Crate |
|---|--------|-------|-------|
| D1 | Three-tier port scheduler: hot (~200 top/IANA ports, daily), cloud (~300 ports on cloud ranges), background (N random ports/IP/day, full 65K coverage over months). Background results double as prediction training data. | Censys SIGCOMM'25 | `scan` |
| D2 | Port prediction after first hit: learn `P(port_j \| port_i, ASN, /16, banner-class)` from co-occurrence counts in SQLite; probe high-probability ports next. No deep learning required; make it online (incremental counts). | GPS, arXiv:2303.00895; IPREDS, CoNEXT'24 | `scan`, `store` |
| D3 | Protocol-agnostic first exchange: wait for server-first banner, then IANA-expected protocol, then HTTP, then TLS. Discard SYN-ACK-only / respond-on-every-port hosts as artefacts. | LZR, arXiv:2301.04841 | `probe` |
| D4 | Service lifecycle: live -> pending (one failed scan, retry from a second vantage point) -> evicted after 72 h -> re-queued for 60 days. Store observations as deltas. | Censys SIGCOMM'25 s4.4 | `store`, `main` |
| D5 | Per-network-class revisit intervals (residential/cloud faster than stable hosting). | Padmanabhan IMC'16, CoNEXT'20; Richter IMC'16 | `scan` |
| D6 | IPv6: (a) aliased-prefix detection (16 random addrs, one per nybble branch); keep one representative per aliased prefix instead of dropping it (CDNs); (b) seed hygiene and GFW-injection filtering; (c) pluggable `TargetGenerator` trait, first impl 6Tree/6Gen-style space partitioning with 6Sense-style online feedback (bandit over prefixes/nybble patterns); (d) BGP announcements as seed signal. | Gasser arXiv:1806.01633; Zirngibl IMC'22; 6SEVEN arXiv:2609.08098; 6Sense USENIX Sec'24; arXiv:2508.07506, arXiv:2506.20383 | `scan` |
| D7 | Optional offline ML generators behind the trait: 6Vision (arXiv:2501.01683, few-seed prefixes), 6Diffusion (arXiv:2412.19243). | as cited | `scan` |
| D8 | QUIC: UDP/443 Initial probe (version negotiation), server-library fingerprint via `quinn`. | QScanner IMC'21; QUIC Hunter PAM'24 | `probe` |
| D9 | Ingest ZMap 4.4 output fields (SYN RTT, JA4TS on SYN-ACK, multi-port) as cheap middlebox/tarpit signals. | ZMap v4.4.0; *Ten Years of ZMap* arXiv:2406.15585 | `scan` |

Finding from 6SEVEN: seed composition, dealiasing and tabulation move IPv6
results more than the choice of generator. Build D6(a)(b) before D6(c)/D7.

No published Internet-scale stateless scanner exists in Rust; D1-D4 make
Crusade's engine novel in that respect.

### Good-citizen requirements (blocking for any non-local deployment)

- Honest User-Agent, rDNS and an info page on scan source IPs; WHOIS-verified
  opt-out with expiry (Censys: 1 year). Wu et al., NDSS'25, arXiv:2412.15696.
- Coverage comes from multiple vantage points and continuous low-rate
  scanning, not higher rate: aggressive scanners get blocked more (Wan et al.,
  IMC'20).

## 2. Vulnerability data

| # | Change | Crate |
|---|--------|-------|
| V1 | Replace the NVD 1.1 data-feed parser (retired by NVD) with NVD CVE API 2.0 / JSON 2.0 bulk feeds, fetched by `update-data`. Today CVE matching is empty on a fresh install. | `vuln`, `update` |
| V2 | CPE resolution via retrieval: embed the NVD CPE dictionary (see M2), take top-k nearest to a banner, accept only a candidate from that list. Never accept free-text CPEs. | `vuln` |

## 3. Honeypot scoring (`honeypot:` filter)

Output is a score in [0,1] plus an evidence list, stored per host, not a bare
boolean (staged design from Srinivasa et al., arXiv:2109.10652). Statistics
and search gain a default-off/on `-honeypot` toggle; a 2026 DICOM study
(arXiv:2607.15839) shows unfiltered exposure counts overstated by 39%.

Stage 1 - passive, from data already stored:

| Signal | Source |
|--------|--------|
| Versioned rule pack (TOML/regex): default banners, HTTP titles, cert subjects, ICS identities of common open-source honeypots | Morishita et al., IM'19 (20 signatures, 14 honeypots); Vetterl & Clayton, WOOT'18 |
| SSH banner vs. KEX/cipher list consistency (claimed OpenSSH version must match its expected algorithm set) | WOOT'18 |
| Port-set likelihood under the D2 co-occurrence model; implausible combinations (e.g. S7+Modbus+SMB+Redis on one host); respond-on-all-ports | GPS, LZR |
| OS/product contradictions across services on one host | SoK arXiv:2510.25939 |
| ICS services on cloud/hosting ASNs | - |
| Identical favicon hash / cert across many unrelated IPs | - |
| Banner frozen across scans while claiming a stale version | - |
| Exposed fake LLM APIs (e.g. Ollama) | arXiv:2609.29757 |

Stage 2 - new collection: per-service time-to-banner and response-time
variance. LLM-backed honeypots defeat static banner rules but leak through
latency and jitter (arXiv:2502.20589; LLM honeypots arXiv:2309.00155,
2409.08234, 2405.05999, 2605.29963).

Stage 3 - learned classifier: gradient-boosted trees or logistic regression
over the stage 1-2 features, bootstrapped from rule labels, trained offline,
weights shipped, scored in pure Rust. No peer-reviewed classifier on scan
records exists (gap), so this is novel ground.

## 4. Embedded models (CPU-only, in-binary, no keys)

| # | Capability | Design | Basis |
|---|-----------|--------|-------|
| M1 | Banner -> vendor/product | Small encoder (~22M params, int8 ONNX via `ort`, or `candle`); regexes remain authoritative for versions (model F1 drops to ~0.55 on versions). | arXiv:2404.00056 |
| M2 | Semantic search and clustering | Static embeddings (Model2Vec potion-base-8M, ~30 MB, `model2vec-rs`) on every banner/title at ingest; ANN via `sqlite-vec` or HNSW (`usearch`/`hnsw_rs`). New query form `like:<ip>:<port>` / `similar:"text"`. Optional re-rank tier: EmbeddingGemma 308M int8. | arXiv:2510.24793; arXiv:2509.20354 |
| M3 | Natural language -> Crusade query | GBNF/Lark grammar of the query language; 0.5-1.5B Q4 GGUF model via `llama-cpp-2`; token masking with `llguidance`; beam 2-4. Output parses by construction. Exposed as `crusade ask "..."` and a UI box. | arXiv:2307.09702, 2305.13971, 2411.15100, 2608.25761 |
| M4 | Host anomaly / change detection | Host vector (VAE-style over tags, or mean-pooled M2 service embeddings) + scan-to-scan deltas; isolation forest. Feeds `monitor` alerts (`kind = anomaly`). | Sarabi & Liu, IMC'18 |
| M5 | Screenshot clustering | pHash/dHash (`image_hasher`), Hamming buckets; `screenshot.hash:` filter. | arXiv:1909.00300, 2512.02243 |
| M6 | Infrastructure graph | Graph over cert / favicon / JARM / HASSH / ASN edges (`petgraph`): connected components + label propagation -> `cluster:` filter; GNN only after a baseline exists. Published work is industry-only (gap). | - |
| M7 | Analyst agent | Local LLM (M3 runtime) that plans multi-step queries over the index and explains pivots. | ArachNet arXiv:2511.10611 |

All models load lazily from `data/models/`, fetched by `update-data`, and every
feature degrades to a no-op when the model file is absent (same pattern as
GeoIP and screenshots today).

## 5. Ordering

1. V1 (correctness: CVE matching is currently non-functional). **Done.**
2. Honeypot stage 1 + D2 co-occurrence model (shared statistics; makes the
   existing `-tag:honeypot` README example real). **Honeypot stage 1 done**
   (`crates/vuln/src/honeypot.rs`, `honeypot:` filter, `crusade rescore`);
   the port co-occurrence statistics exist and are used for scoring, not yet
   for D2 port prediction.
3. D3, D4, D1 (engine core). **D3 done** (`grab::grab_adaptive`).
4. M2 + V2, then M3 (shared embedding/LLM runtime).
5. D6 IPv6 pipeline, D8 QUIC, D9 ZMap fields.
6. Honeypot stages 2-3, M4-M7.

## Open gaps in the literature

- Measured adaptive revisit policies (service lifetime vs. revisit interval).
- LLM-based IPv6 target generation (no peer-reviewed work found).
- Peer-reviewed honeypot classifiers over scan records.
- Peer-reviewed GNN pivoting over certificate/favicon/fingerprint graphs.

These are the points where Crusade can contribute rather than follow.
