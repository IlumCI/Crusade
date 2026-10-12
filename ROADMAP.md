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

## v3 — LATER
Screenshots (RDP/VNC/HTTP, the deferred seam), ICS/OT protocols (Modbus/S7/
BACnet/DNP3), exploit cross-ref (Exploit-DB/Metasploit), distributed workers,
trends-over-time views, alert transports (webhook/email).
