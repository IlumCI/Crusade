//! Ingestion of external sweep results.
//!
//! Large internet-wide sweeps are run out-of-band with a sanctioned `masscan` or
//! `zmap` deployment on a VPS the operator is authorised to scan from. This
//! module turns their output back into `(ip, port)` pairs. The parsers are
//! intentionally tolerant, since both tools emit slightly irregular files.
//!
//! The results are *not* implicitly trusted: the caller must pass them through
//! [`filter_blocked`] (or otherwise consult a [`Blocklist`]) before anything
//! downstream connects to them.

use std::net::IpAddr;

use crate::blocklist::Blocklist;

/// Parse masscan `-oJ` output into `(ip, port)` pairs.
///
/// masscan's JSON is an array of records like
/// `{ "ip": "1.2.3.4", "ports": [ { "port": 80, "proto": "tcp", ... } ] }`, but
/// in practice it often carries trailing commas and a `{ "finished": 1 }`
/// marker that make the document invalid JSON. We try a strict whole-document
/// parse first, then fall back to parsing each record line individually.
pub fn parse_masscan_json(s: &str) -> Vec<(IpAddr, u16)> {
    let mut out = Vec::new();

    if let Ok(serde_json::Value::Array(records)) = serde_json::from_str::<serde_json::Value>(s) {
        for rec in &records {
            collect_masscan_record(rec, &mut out);
        }
        return out;
    }

    // Tolerant fallback: one JSON object per line, ignoring array punctuation.
    for line in s.lines() {
        let line = line
            .trim()
            .trim_start_matches(',')
            .trim()
            .trim_end_matches(',')
            .trim();
        if !line.starts_with('{') || !line.ends_with('}') {
            continue;
        }
        if let Ok(rec) = serde_json::from_str::<serde_json::Value>(line) {
            collect_masscan_record(&rec, &mut out);
        }
    }
    out
}

/// Pull `(ip, port)` pairs out of one masscan record.
fn collect_masscan_record(rec: &serde_json::Value, out: &mut Vec<(IpAddr, u16)>) {
    let Some(ip) = rec.get("ip").and_then(|v| v.as_str()) else {
        return;
    };
    let Ok(ip) = ip.parse::<IpAddr>() else {
        return;
    };
    let Some(ports) = rec.get("ports").and_then(|v| v.as_array()) else {
        return;
    };
    for p in ports {
        if let Some(port) = p.get("port").and_then(|v| v.as_u64()) {
            if let Ok(port) = u16::try_from(port) {
                out.push((ip, port));
            }
        }
    }
}

/// Parse zmap CSV output into `(ip, port)` pairs.
///
/// zmap writes a header row naming its output fields; we locate the `saddr`
/// column for the address and, if present, a `sport`/`port`/`dport` column for
/// the port (defaulting to 0 when zmap was not configured to emit one). Rows
/// whose address does not parse are skipped.
/// One row of zmap output, with the extra signals zmap 4.4 can emit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZmapRecord {
    pub ip: IpAddr,
    pub port: u16,
    /// Round-trip time of the SYN/SYN-ACK exchange, in microseconds.
    ///
    /// zmap 4.4 reports this per probe. It is a cheap distance estimate and a
    /// middlebox hint: a reply far faster than the rest of a network's hosts
    /// usually came from something in front of them rather than the host.
    pub rtt_us: Option<u32>,
    /// JA4TS: a fingerprint of the SYN-ACK's TCP options, window and flags,
    /// which identifies the responding *stack* rather than the application.
    /// Pivotable like JARM and HASSH; present only when zmap was asked for it.
    pub ja4ts: Option<String>,
}

/// Parse zmap CSV output into rich records, keeping the fields zmap 4.4 adds.
///
/// Columns are located by name from the header, so a file with extra or
/// reordered columns still parses — zmap's output schema is configurable, and
/// positional parsing breaks the moment someone adds `--output-fields`.
pub fn parse_zmap_csv_rich(s: &str) -> Vec<ZmapRecord> {
    let mut out = Vec::new();
    let mut lines = s.lines().filter(|l| !l.trim().is_empty());

    let Some(header) = lines.next() else {
        return out;
    };
    let cols: Vec<&str> = header.split(',').map(|c| c.trim()).collect();
    let Some(saddr_idx) = cols.iter().position(|c| *c == "saddr") else {
        return out;
    };
    let port_idx = cols
        .iter()
        .position(|c| matches!(*c, "sport" | "port" | "dport"));
    // zmap has used several names for the timing field across versions.
    let rtt_idx = cols
        .iter()
        .position(|c| matches!(*c, "rtt_us" | "rtt" | "syn_rtt_us" | "latency_us"));
    let ja4ts_idx = cols
        .iter()
        .position(|c| matches!(*c, "ja4ts" | "ja4t" | "ja4ts_str"));
    // A failed probe is still a row; only successes are open ports.
    let success_idx = cols
        .iter()
        .position(|c| matches!(*c, "success" | "classification"));

    for line in lines {
        let fields: Vec<&str> = line.split(',').map(|f| f.trim()).collect();
        let Some(Ok(ip)) = fields.get(saddr_idx).map(|a| a.parse::<IpAddr>()) else {
            continue;
        };
        if let Some(field) = success_idx.and_then(|i| fields.get(i)) {
            // "0" and "rst" both mean the port is not open.
            if matches!(*field, "0" | "false" | "rst" | "icmp_unreach") {
                continue;
            }
        }
        let port = port_idx
            .and_then(|i| fields.get(i))
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(0);
        let rtt_us = rtt_idx
            .and_then(|i| fields.get(i))
            .and_then(|v| v.parse::<u32>().ok());
        let ja4ts = ja4ts_idx
            .and_then(|i| fields.get(i))
            .map(|v| v.to_string())
            .filter(|v| !v.is_empty() && v != "-");
        out.push(ZmapRecord {
            ip,
            port,
            rtt_us,
            ja4ts,
        });
    }
    out
}

/// Parse zmap CSV output into `(ip, port)` pairs.
pub fn parse_zmap_csv(s: &str) -> Vec<(IpAddr, u16)> {
    parse_zmap_csv_rich(s)
        .into_iter()
        .map(|r| (r.ip, r.port))
        .collect()
}

/// Drop every pair whose address the blocklist forbids. Callers MUST apply this
/// (or an equivalent check) to ingested sweep results before scanning them.
pub fn filter_blocked(pairs: Vec<(IpAddr, u16)>, bl: &Blocklist) -> Vec<(IpAddr, u16)> {
    pairs
        .into_iter()
        .filter(|(ip, _)| !bl.is_blocked(*ip))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn parse_masscan_strict_array() {
        let s = r#"[
            {"ip": "8.8.8.8", "timestamp": "1", "ports": [{"port": 443, "proto": "tcp", "status": "open"}]},
            {"ip": "1.1.1.1", "timestamp": "2", "ports": [{"port": 80, "proto": "tcp"}, {"port": 443, "proto": "tcp"}]}
        ]"#;
        let got = parse_masscan_json(s);
        assert_eq!(
            got,
            vec![
                (v4(8, 8, 8, 8), 443),
                (v4(1, 1, 1, 1), 80),
                (v4(1, 1, 1, 1), 443)
            ]
        );
    }

    #[test]
    fn parse_masscan_tolerant_fallback() {
        // Irregular real-world shape: trailing commas and a finished marker.
        let s = "[\n\
            {\"ip\": \"8.8.4.4\", \"ports\": [{\"port\": 53, \"proto\": \"tcp\"}]},\n\
            {\"ip\": \"9.9.9.9\", \"ports\": [{\"port\": 853, \"proto\": \"tcp\"}]},\n\
            {\"finished\": 1}\n\
            ]";
        let got = parse_masscan_json(s);
        assert_eq!(got, vec![(v4(8, 8, 4, 4), 53), (v4(9, 9, 9, 9), 853)]);
    }

    #[test]
    fn parse_masscan_empty_and_garbage() {
        assert!(parse_masscan_json("").is_empty());
        assert!(parse_masscan_json("not json at all").is_empty());
    }

    #[test]
    fn parse_zmap_with_saddr_and_sport() {
        let s = "saddr,sport,classification\n\
                 8.8.8.8,443,synack\n\
                 1.1.1.1,80,synack\n";
        let got = parse_zmap_csv(s);
        assert_eq!(got, vec![(v4(8, 8, 8, 8), 443), (v4(1, 1, 1, 1), 80)]);
    }

    #[test]
    fn parse_zmap_saddr_only_defaults_port_zero() {
        let s = "saddr\n8.8.8.8\n1.1.1.1\n";
        let got = parse_zmap_csv(s);
        assert_eq!(got, vec![(v4(8, 8, 8, 8), 0), (v4(1, 1, 1, 1), 0)]);
    }

    #[test]
    fn parse_zmap_column_order_and_bad_rows() {
        let s = "timestamp,sport,saddr\n\
                 1,22,8.8.8.8\n\
                 2,22,not-an-ip\n\
                 3,22,1.1.1.1\n";
        let got = parse_zmap_csv(s);
        assert_eq!(got, vec![(v4(8, 8, 8, 8), 22), (v4(1, 1, 1, 1), 22)]);
    }

    #[test]
    fn parse_zmap_no_saddr_column_is_empty() {
        assert!(parse_zmap_csv("foo,bar\n1,2\n").is_empty());
        assert!(parse_zmap_csv("").is_empty());
    }

    #[test]
    fn filter_blocked_removes_reserved_and_user_ranges() {
        let mut bl = Blocklist::new(false);
        bl.add("8.8.8.8/32".parse().unwrap());

        let pairs = vec![
            (v4(8, 8, 8, 8), 443),  // user-blocked
            (v4(127, 0, 0, 1), 80), // reserved loopback
            (v4(192, 0, 2, 5), 80), // reserved documentation
            (v4(1, 1, 1, 1), 443),  // public, kept
        ];
        let got = filter_blocked(pairs, &bl);
        assert_eq!(got, vec![(v4(1, 1, 1, 1), 443)]);
    }

    #[test]
    fn zmap_44_fields_are_parsed_by_name() {
        // Columns deliberately reordered and interleaved with ones we ignore,
        // since zmap's schema is configurable.
        let csv = "\
timestamp-str,ja4ts,saddr,classification,rtt_us,sport,repeat
2026-10-13T00:00:00Z,8192_2-4-8-1-3_1460_8,198.51.100.4,synack,14213,443,0
2026-10-13T00:00:01Z,-,198.51.100.5,synack,982,80,0
2026-10-13T00:00:02Z,,198.51.100.6,rst,55,22,0
";
        let rows = parse_zmap_csv_rich(csv);
        assert_eq!(rows.len(), 2, "the RST row is not an open port: {rows:?}");

        assert_eq!(rows[0].ip, "198.51.100.4".parse::<IpAddr>().unwrap());
        assert_eq!(rows[0].port, 443);
        assert_eq!(rows[0].rtt_us, Some(14_213));
        assert_eq!(rows[0].ja4ts.as_deref(), Some("8192_2-4-8-1-3_1460_8"));

        // "-" is zmap's empty marker, not a fingerprint.
        assert_eq!(rows[1].ja4ts, None);
        assert_eq!(rows[1].rtt_us, Some(982));

        // The simple API still works and ignores the extra fields.
        assert_eq!(
            parse_zmap_csv(csv),
            vec![
                ("198.51.100.4".parse::<IpAddr>().unwrap(), 443),
                ("198.51.100.5".parse::<IpAddr>().unwrap(), 80),
            ]
        );
    }

    #[test]
    fn zmap_output_without_the_new_fields_still_parses() {
        let csv = "saddr,sport\n203.0.113.1,8080\n";
        let rows = parse_zmap_csv_rich(csv);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].port, 8080);
        assert_eq!(rows[0].rtt_us, None);
        assert_eq!(rows[0].ja4ts, None);
    }

    #[test]
    fn zmap_success_column_variants_are_honoured() {
        let csv = "saddr,sport,success\n198.51.100.1,80,1\n198.51.100.2,80,0\n198.51.100.3,80,true\n198.51.100.4,80,false\n";
        let kept: Vec<String> = parse_zmap_csv_rich(csv)
            .into_iter()
            .map(|r| r.ip.to_string())
            .collect();
        assert_eq!(kept, vec!["198.51.100.1", "198.51.100.3"]);
    }

    #[test]
    fn zmap_garbage_is_skipped_not_fatal() {
        assert!(parse_zmap_csv_rich("").is_empty());
        assert!(parse_zmap_csv_rich("no_saddr_column,x\n1,2\n").is_empty());
        let csv = "saddr,sport\nnot-an-ip,80\n198.51.100.9,notaport\n";
        let rows = parse_zmap_csv_rich(csv);
        assert_eq!(rows.len(), 1, "the bad address is dropped");
        assert_eq!(rows[0].port, 0, "an unparseable port reads as unknown");
    }
}
