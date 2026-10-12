//! GeoIP / ASN lookup from free, no-key datasets.
//!
//! The primary source is the [iptoasn.com](https://iptoasn.com/) `ip2asn-v4.tsv`
//! / `ip2asn-v6.tsv` tables. Each line is tab-separated:
//!
//! ```text
//! range_start<TAB>range_end<TAB>AS_number<TAB>country_code<TAB>AS_description
//! ```
//!
//! IPs are dotted quads (v4) or colon-hex (v6). Ranges with AS number `0` mean
//! "not routed" and are skipped on load.
//!
//! An optional [DB-IP City Lite](https://db-ip.com/db/download/ip-to-city-lite)
//! CSV can be layered on top via [`GeoAsnDb::with_city_db`] to add
//! city / latitude / longitude, but the struct is fully functional without it.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use anyhow::Context;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

/// What an ASN lookup resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsnInfo {
    pub asn: u32,
    /// ISO 3166-1 alpha-2 country code.
    pub country: String,
    /// AS description / organisation name.
    pub org: String,
}

/// City-level geolocation resolved from the optional DB-IP City Lite dataset.
#[derive(Debug, Clone, PartialEq)]
pub struct CityInfo {
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

/// A single parsed ip2asn row, IP-version agnostic (IPs kept as [`IpAddr`]).
///
/// Produced by [`parse_ip2asn_tsv`] so loading can be exercised from an
/// in-memory string in unit tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawRange {
    pub start: IpAddr,
    pub end: IpAddr,
    pub asn: u32,
    pub country: String,
    pub org: String,
}

/// Internal v4 range, keyed on `start` as `u32` for binary search.
#[derive(Debug, Clone)]
struct V4Range {
    start: u32,
    end: u32,
    asn: u32,
    country: String,
    org: String,
}

/// Internal v6 range, keyed on `start` as `u128` for binary search.
#[derive(Debug, Clone)]
struct V6Range {
    start: u128,
    end: u128,
    asn: u32,
    country: String,
    org: String,
}

/// A city range from DB-IP City Lite.
#[derive(Debug, Clone)]
struct CityRange {
    start: u128,
    end: u128,
    city: Option<String>,
    lat: Option<f64>,
    lon: Option<f64>,
}

/// In-memory GeoIP / ASN database.
///
/// Ranges are stored sorted by start address so lookups are `O(log n)` binary
/// searches.
#[derive(Debug, Clone, Default)]
pub struct GeoAsnDb {
    v4: Vec<V4Range>,
    v6: Vec<V6Range>,
    city_v4: Vec<CityRange>,
    city_v6: Vec<CityRange>,
}

/// Parse an ip2asn TSV blob into [`RawRange`]s.
///
/// Malformed lines and rows with AS number `0` (not routed) are skipped. Both
/// v4 and v6 lines are accepted (the address version is inferred per line).
pub fn parse_ip2asn_tsv(data: &str) -> Vec<RawRange> {
    let mut out = Vec::new();
    for line in data.lines() {
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            continue;
        }
        let mut cols = line.split('\t');
        let (Some(start), Some(end), Some(asn)) = (cols.next(), cols.next(), cols.next()) else {
            continue;
        };
        let country = cols.next().unwrap_or("").trim().to_string();
        // The description may itself contain tabs in theory; join the rest.
        let org: String = {
            let rest: Vec<&str> = cols.collect();
            rest.join("\t").trim().to_string()
        };

        let asn: u32 = match asn.trim().parse() {
            Ok(n) => n,
            Err(_) => continue,
        };
        // AS 0 means "not routed" — skip.
        if asn == 0 {
            continue;
        }
        let (Ok(start), Ok(end)) = (start.trim().parse::<IpAddr>(), end.trim().parse::<IpAddr>())
        else {
            continue;
        };
        // Both endpoints must be the same IP version.
        match (start, end) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {}
            _ => continue,
        }
        out.push(RawRange { start, end, asn, country, org });
    }
    out
}

impl GeoAsnDb {
    /// Build a database from TSV blobs held in memory (used by tests and
    /// [`GeoAsnDb::load`]).
    pub fn from_tsv(v4: &str, v6: Option<&str>) -> Self {
        let mut db = GeoAsnDb::default();
        db.ingest(parse_ip2asn_tsv(v4));
        if let Some(v6) = v6 {
            db.ingest(parse_ip2asn_tsv(v6));
        }
        db.sort();
        db
    }

    /// Load the database from `ip2asn-v4.tsv` and optionally `ip2asn-v6.tsv`.
    pub fn load(v4_tsv: &Path, v6_tsv: Option<&Path>) -> anyhow::Result<Self> {
        let v4 = std::fs::read_to_string(v4_tsv)
            .with_context(|| format!("reading ip2asn v4 TSV from {}", v4_tsv.display()))?;
        let v6 = match v6_tsv {
            Some(p) => Some(
                std::fs::read_to_string(p)
                    .with_context(|| format!("reading ip2asn v6 TSV from {}", p.display()))?,
            ),
            None => None,
        };
        Ok(GeoAsnDb::from_tsv(&v4, v6.as_deref()))
    }

    /// Layer DB-IP City Lite CSV data on top for city/lat/lon resolution.
    ///
    /// The expected row layout is
    /// `ip_start,ip_end,continent,country,stateprov,city,latitude,longitude`.
    /// Unparseable rows are skipped. Returns `self` for chaining.
    pub fn with_city_db(mut self, path: &Path) -> anyhow::Result<Self> {
        let data = std::fs::read_to_string(path)
            .with_context(|| format!("reading DB-IP City Lite CSV from {}", path.display()))?;
        self.ingest_city_csv(&data);
        Ok(self)
    }

    fn ingest(&mut self, rows: Vec<RawRange>) {
        for r in rows {
            match (r.start, r.end) {
                (IpAddr::V4(s), IpAddr::V4(e)) => self.v4.push(V4Range {
                    start: u32::from(s),
                    end: u32::from(e),
                    asn: r.asn,
                    country: r.country,
                    org: r.org,
                }),
                (IpAddr::V6(s), IpAddr::V6(e)) => self.v6.push(V6Range {
                    start: u128::from(s),
                    end: u128::from(e),
                    asn: r.asn,
                    country: r.country,
                    org: r.org,
                }),
                _ => {}
            }
        }
    }

    fn ingest_city_csv(&mut self, data: &str) {
        for line in data.lines() {
            let line = line.trim_end_matches(['\r', '\n']);
            if line.is_empty() {
                continue;
            }
            let cols: Vec<&str> = line.split(',').map(|c| c.trim().trim_matches('"')).collect();
            if cols.len() < 8 {
                continue;
            }
            let (Ok(start), Ok(end)) =
                (cols[0].parse::<IpAddr>(), cols[1].parse::<IpAddr>())
            else {
                continue;
            };
            let city = {
                let c = cols[5];
                if c.is_empty() {
                    None
                } else {
                    Some(c.to_string())
                }
            };
            let lat = cols[6].parse::<f64>().ok();
            let lon = cols[7].parse::<f64>().ok();
            match (start, end) {
                (IpAddr::V4(s), IpAddr::V4(e)) => self.city_v4.push(CityRange {
                    start: u32::from(s) as u128,
                    end: u32::from(e) as u128,
                    city,
                    lat,
                    lon,
                }),
                (IpAddr::V6(s), IpAddr::V6(e)) => self.city_v6.push(CityRange {
                    start: u128::from(s),
                    end: u128::from(e),
                    city,
                    lat,
                    lon,
                }),
                _ => {}
            }
        }
        self.city_v4.sort_by_key(|r| r.start);
        self.city_v6.sort_by_key(|r| r.start);
    }

    fn sort(&mut self) {
        self.v4.sort_by_key(|r| r.start);
        self.v6.sort_by_key(|r| r.start);
    }

    /// Look up the ASN info for an IPv4 address.
    pub fn lookup_asn(&self, ip: Ipv4Addr) -> Option<AsnInfo> {
        let key = u32::from(ip);
        let idx = self.v4.partition_point(|r| r.start <= key);
        if idx == 0 {
            return None;
        }
        let r = &self.v4[idx - 1];
        if key <= r.end {
            Some(AsnInfo { asn: r.asn, country: r.country.clone(), org: r.org.clone() })
        } else {
            None
        }
    }

    /// Look up the ASN info for an IPv6 address.
    pub fn lookup_asn_v6(&self, ip: Ipv6Addr) -> Option<AsnInfo> {
        let key = u128::from(ip);
        let idx = self.v6.partition_point(|r| r.start <= key);
        if idx == 0 {
            return None;
        }
        let r = &self.v6[idx - 1];
        if key <= r.end {
            Some(AsnInfo { asn: r.asn, country: r.country.clone(), org: r.org.clone() })
        } else {
            None
        }
    }

    /// Version-agnostic ASN lookup.
    pub fn lookup(&self, ip: IpAddr) -> Option<AsnInfo> {
        match ip {
            IpAddr::V4(v4) => self.lookup_asn(v4),
            IpAddr::V6(v6) => self.lookup_asn_v6(v6),
        }
    }

    /// Look up city / lat / lon for an address, if a city DB was loaded.
    pub fn lookup_city(&self, ip: IpAddr) -> Option<CityInfo> {
        let (ranges, key) = match ip {
            IpAddr::V4(v4) => (&self.city_v4, u32::from(v4) as u128),
            IpAddr::V6(v6) => (&self.city_v6, u128::from(v6)),
        };
        let idx = ranges.partition_point(|r| r.start <= key);
        if idx == 0 {
            return None;
        }
        let r = &ranges[idx - 1];
        if key <= r.end {
            Some(CityInfo { city: r.city.clone(), latitude: r.lat, longitude: r.lon })
        } else {
            None
        }
    }

    /// Return the CIDR prefixes announced by an ASN.
    ///
    /// Every range in the table belonging to `asn` is decomposed into aligned
    /// CIDR blocks. This powers `asn:` scan targets.
    pub fn prefixes_for_asn(&self, asn: u32) -> Vec<IpNet> {
        let mut out = Vec::new();
        for r in self.v4.iter().filter(|r| r.asn == asn) {
            for (net, prefix) in range_to_cidr_blocks(r.start as u128, r.end as u128, 32) {
                let addr = Ipv4Addr::from(net as u32);
                out.push(IpNet::V4(Ipv4Net::new(addr, prefix).expect("valid v4 prefix")));
            }
        }
        for r in self.v6.iter().filter(|r| r.asn == asn) {
            for (net, prefix) in range_to_cidr_blocks(r.start, r.end, 128) {
                let addr = Ipv6Addr::from(net);
                out.push(IpNet::V6(Ipv6Net::new(addr, prefix).expect("valid v6 prefix")));
            }
        }
        out
    }

    /// Number of (v4, v6) ASN ranges held. Useful for diagnostics/tests.
    pub fn len(&self) -> (usize, usize) {
        (self.v4.len(), self.v6.len())
    }

    /// Whether the ASN tables are empty.
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }
}

/// Decompose an inclusive `[start, end]` address range into aligned CIDR
/// blocks, returning `(network_address, prefix_len)` pairs.
///
/// Works for both IPv4 (`bits = 32`) and IPv6 (`bits = 128`) by operating on
/// `u128`. The classic greedy algorithm: at each step take the largest block
/// that is both aligned to `start` and fits within the remaining range.
fn range_to_cidr_blocks(start: u128, end: u128, bits: u32) -> Vec<(u128, u8)> {
    let mut out = Vec::new();
    if start > end {
        return out;
    }
    let mut s = start;
    loop {
        // Largest block (in host bits) permitted by the alignment of `s`.
        let max_align = if s == 0 { bits } else { s.trailing_zeros().min(bits) };
        // Shrink until the block fits inside the remaining span `[s, end]`.
        let mut size = max_align;
        loop {
            let span = end - s; // safe: end >= s
            let block_minus_one =
                if size >= 128 { u128::MAX } else { (1u128 << size) - 1 };
            if block_minus_one <= span {
                break;
            }
            if size == 0 {
                break;
            }
            size -= 1;
        }
        let prefix = (bits - size) as u8;
        out.push((s, prefix));

        // Advance past this block; stop on overflow or once past `end`.
        if size >= 128 {
            break;
        }
        match s.checked_add(1u128 << size) {
            Some(next) if next <= end => s = next,
            _ => break,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_V4: &str = "\
1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n\
192.0.2.0\t192.0.2.255\t64500\tDE\tEXAMPLE-DOC-NET\n\
198.51.100.0\t198.51.100.63\t0\tNone\tNot routed\n\
203.0.113.0\t203.0.113.127\t64501\tFR\tTEST-NET-3\n";

    #[test]
    fn parse_skips_asn_zero_and_counts() {
        let rows = parse_ip2asn_tsv(FIXTURE_V4);
        // 4 lines, one with ASN 0 -> 3 kept.
        assert_eq!(rows.len(), 3);
        assert!(rows.iter().all(|r| r.asn != 0));
    }

    #[test]
    fn lookup_hit_returns_asn_country_org() {
        let db = GeoAsnDb::from_tsv(FIXTURE_V4, None);
        let info = db.lookup_asn("192.0.2.42".parse().unwrap()).expect("in range");
        assert_eq!(
            info,
            AsnInfo {
                asn: 64500,
                country: "DE".to_string(),
                org: "EXAMPLE-DOC-NET".to_string(),
            }
        );
        // boundaries inclusive
        assert!(db.lookup_asn("192.0.2.0".parse().unwrap()).is_some());
        assert!(db.lookup_asn("192.0.2.255".parse().unwrap()).is_some());
    }

    #[test]
    fn lookup_miss_returns_none() {
        let db = GeoAsnDb::from_tsv(FIXTURE_V4, None);
        // Between known ranges, not covered.
        assert!(db.lookup_asn("192.0.3.1".parse().unwrap()).is_none());
        // Below the lowest range.
        assert!(db.lookup_asn("0.0.0.1".parse().unwrap()).is_none());
    }

    #[test]
    fn asn_zero_range_not_resolvable() {
        let db = GeoAsnDb::from_tsv(FIXTURE_V4, None);
        // 198.51.100.x was ASN 0 and must have been skipped.
        assert!(db.lookup_asn("198.51.100.1".parse().unwrap()).is_none());
    }

    #[test]
    fn prefixes_aligned_range_is_single_cidr() {
        let db = GeoAsnDb::from_tsv(FIXTURE_V4, None);
        let prefixes = db.prefixes_for_asn(64500);
        assert_eq!(prefixes, vec!["192.0.2.0/24".parse::<IpNet>().unwrap()]);
    }

    #[test]
    fn prefixes_nonaligned_range_splits() {
        let db = GeoAsnDb::from_tsv(FIXTURE_V4, None);
        // 203.0.113.0 - 203.0.113.127 is exactly a /25.
        let prefixes = db.prefixes_for_asn(64501);
        assert_eq!(prefixes, vec!["203.0.113.0/25".parse::<IpNet>().unwrap()]);
    }

    #[test]
    fn range_decomposition_aligned_24() {
        // 192.0.2.0 - 192.0.2.255 -> /24
        let start = u32::from("192.0.2.0".parse::<Ipv4Addr>().unwrap()) as u128;
        let end = u32::from("192.0.2.255".parse::<Ipv4Addr>().unwrap()) as u128;
        let blocks = range_to_cidr_blocks(start, end, 32);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].1, 24);
    }

    #[test]
    fn range_decomposition_nonaligned_splits_into_multiple() {
        // 192.0.2.1 - 192.0.2.6 cannot be one CIDR.
        // Expected greedy split: .1/32, .2/31, .4/31, .6/32
        let start = u32::from("192.0.2.1".parse::<Ipv4Addr>().unwrap()) as u128;
        let end = u32::from("192.0.2.6".parse::<Ipv4Addr>().unwrap()) as u128;
        let blocks = range_to_cidr_blocks(start, end, 32);
        let as_nets: Vec<IpNet> = blocks
            .iter()
            .map(|(n, p)| IpNet::V4(Ipv4Net::new(Ipv4Addr::from(*n as u32), *p).unwrap()))
            .collect();
        assert_eq!(
            as_nets,
            vec![
                "192.0.2.1/32".parse::<IpNet>().unwrap(),
                "192.0.2.2/31".parse::<IpNet>().unwrap(),
                "192.0.2.4/31".parse::<IpNet>().unwrap(),
                "192.0.2.6/32".parse::<IpNet>().unwrap(),
            ]
        );
        // All blocks must exactly cover the range with no gaps/overlap.
        let covered: u128 = blocks.iter().map(|(_, p)| 1u128 << (32 - *p)).sum();
        assert_eq!(covered, end - start + 1);
    }

    #[test]
    fn range_decomposition_full_v4_space() {
        // 0.0.0.0 - 255.255.255.255 -> 0.0.0.0/0 (exercises the overflow path).
        let blocks = range_to_cidr_blocks(0, u32::MAX as u128, 32);
        assert_eq!(blocks, vec![(0u128, 0u8)]);
    }

    #[test]
    fn v6_lookup_and_prefixes() {
        let v6 = "2001:db8::\t2001:db8::ffff\t64502\tNL\tV6-DOC\n";
        let db = GeoAsnDb::from_tsv("", Some(v6));
        let info = db.lookup_asn_v6("2001:db8::5".parse().unwrap()).expect("in range");
        assert_eq!(info.asn, 64502);
        let prefixes = db.prefixes_for_asn(64502);
        assert_eq!(prefixes, vec!["2001:db8::/112".parse::<IpNet>().unwrap()]);
    }
}
