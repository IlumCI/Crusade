# Crusade roadmap

Goal: a local, keyless engine with Shodan's **technology** — deep protocol
intelligence, fingerprint-based pivoting, and continuous operation — for
private use with the operator's own sorting/indexing. (Not Shodan's business or
UI; our web UI is our own.) All scanning stays connect-and-read, blocklist-gated.

## v1 — DONE
Workspace (core/store/scan/probe/enrich/vuln/web + CLI). Shodan-style query
language, SQLite+FTS5, TCP-connect scanner with mandatory blocklist, nmap
fingerprinting, TLS/HTTP parse, GeoIP/ASN + rDNS + crt.sh, NVD/KEV + heuristic
tags, web UI + JSON API. 98 tests; proven end-to-end.

## v2 — DONE
The iconic Shodan pivots + the other half of coverage (UDP) + operations.

- **TLS JARM** active fingerprint (10 Client-Hello probe) — flagship pivot.
- **HTTP favicon mmh3 hash** (Shodan `http.favicon.hash`), security headers,
  lightweight tech detection (Server/X-Powered-By/meta-generator/known paths).
- **SSH intelligence**: host-key SHA-256 fingerprint, KEX/host-key algorithms,
  HASSH.
- **UDP scanning** + read-only protocol probes: DNS, NTP, SNMP (public sysDescr),
  SSDP, mDNS, NetBIOS, IKE.
- **IPv6 targeted scanning** and **`net:` CIDR** targets; optional **masscan
  discovery front-end** for large TCP ranges.
- **Query + index growth**: `net: city: jarm: http.favicon.hash:/favicon:
  ssh.hostkey: hassh: vuln: has_vuln: transport:` filters; per-query faceted
  **stats**; new indexed columns.
- **Operations**: `crusade export` (JSON Lines, like `shodan download`),
  `crusade stats <query>`, and `crusade monitor` — a rescan scheduler that diffs
  against stored state and alerts on new ports/vulns (Shodan-Monitor-lite).

## v3 — IN PROGRESS
- **ICS/OT protocols — DONE**: read-only device identification for Modbus,
  Siemens S7, EtherNet/IP, BACnet (fully parsed) and DNP3 (confirm-only);
  `ics:`/`has_ics:` filters, `ics-exposed`/`ics-<proto>` tags, `--ics` scan
  flag, and a host-detail ICS panel. Strictly identification reads — never
  writes coils/registers or issues control commands.
- **Auth posture — DONE**: per-service `AuthState` (open / required / unknown)
  observed from the service's own response (HTTP 401·WWW-Authenticate, Redis
  -NOAUTH, Mongo/Memcached/Elasticsearch handshakes, VNC security types, ICS =
  no auth). `auth:` filter, `unauthenticated-access`/`unauth-<kind>` tags, web
  badges. Observe-only — never submits credentials or authenticates.
- **Exploit cross-ref — DONE**: CVE → public-exploit mapping from Exploit-DB
  (`files_exploits.csv`) and Metasploit (`modules_metadata_base.json`), both
  pulled by `update-data`. Emits `exploit-available` tags (cve + EDB/msf refs);
  `has_exploit:` filter; web highlighting. Records only that an exploit EXISTS —
  never downloads, runs, or verifies one.

## v3 — DONE (continued)
- **Alert transports**: webhook + SMTP email, persisted alert log, `crusade alerts`.
- **Screenshots**: headless-Chrome capture (graceful no-op without Chrome),
  served in the web UI.
- **History/trends**: per-host timeline + a trends page (alerts + facets).
- **Distributed queue**: `enqueue`/`worker`/`jobs` (single-host WAL MVP).
- **Deploy/CI**: Dockerfile + compose, GitHub Actions (CI, Pages, tagged
  release → binary + GHCR container), integration test, concurrency hardening.

## v4 — FUTURE
Cross-host distribution (networked job store, not single-host SQLite),
RDP/VNC screenshot protocols, more ICS/OT coverage, a client-side static demo
of the UI, alert transports beyond webhook/email (PagerDuty, etc.).

## v5 — IN PROGRESS
Done so far: NVD JSON 2.0 migration (CVE matching worked on no fresh install
before), passive honeypot scoring (`honeypot:` + `crusade rescore`),
protocol-agnostic probing on any port, CPU-only semantic search
(`crusade similar`/`embed`), the service lifecycle (pending → evicted →
forgotten, with `service-gone` alerts), a 25x faster store (quadratic FTS
delete fixed, batched ingest, delta history, capped counts), and a stateless
SYN discovery engine (`--discovery-syn`, ~500x the connect scanner against
unresponsive targets), plus lazy dataset loading and caching (a scan that
finds nothing went from 7.6s to 8ms; CVE lookup from a 6s parse to a 1ms
open), and retention/archiving (usage-aware selection, gzipped archives,
automatic cleanup at a size limit). See `docs/FRONTIER.md` for what remains.

## v5 — PLANNED
Frontier upgrade derived from a 2026 literature survey: tiered + predictive
port discovery, protocol-agnostic probing, service lifecycle/eviction, IPv6
dealiasing and target generation, QUIC, NVD API 2.0 migration, honeypot
scoring, and CPU-only embedded models (semantic search, NL->query, anomaly
detection, infrastructure graph). See `docs/FRONTIER.md`.
