//! Compile a parsed [`Query`] AST into a parameterised SQL statement.
//!
//! The strategy: every query resolves to a set of host IPs. Filters that are
//! about a *service* (port, product, version, ssl.cn, has_screenshot) become
//! `EXISTS (SELECT 1 FROM services ...)` subqueries so a host matches if *any*
//! of its services matches. Host-level filters (country, asn, org, hostname)
//! and tag filters hit their own tables. Free text goes through the FTS index.
//!
//! All values are bound as parameters — we never interpolate user input into
//! SQL text — so the query language cannot be used for injection.

use crusade_core::query::{Field, FilterValue, Query};
use rusqlite::types::Value;

/// A compiled query: a WHERE-bearing SQL string selecting `ip`, plus the bound
/// parameter values in positional order.
pub struct Compiled {
    pub sql: String,
    pub params: Vec<Value>,
}

/// Build the SQL that selects matching host IPs, newest first.
pub fn compile(query: &Query) -> Compiled {
    compile_inner(query, true)
}

/// Like [`compile`], but without the `ORDER BY`.
///
/// Counting does not care about order, and leaving the sort in forces SQLite
/// to order every match before a `LIMIT` can be applied — which made capped
/// counts slower than exact ones on queries that are otherwise a plain index
/// range scan.
pub fn compile_count(query: &Query) -> Compiled {
    compile_inner(query, false)
}

fn compile_inner(query: &Query, ordered: bool) -> Compiled {
    let mut clauses: Vec<String> = Vec::new();
    let mut params: Vec<Value> = Vec::new();

    for filter in &query.filters {
        let neg = filter.negate;
        match filter.field {
            Field::Port => {
                push_service_exists(
                    &mut clauses,
                    &mut params,
                    neg,
                    "port = ?",
                    val(&filter.value),
                );
            }
            Field::Product => {
                push_service_exists(
                    &mut clauses,
                    &mut params,
                    neg,
                    "product LIKE ? COLLATE NOCASE",
                    like(&filter.value),
                );
            }
            Field::Version => {
                push_service_exists(
                    &mut clauses,
                    &mut params,
                    neg,
                    "version LIKE ? COLLATE NOCASE",
                    like(&filter.value),
                );
            }
            Field::SslCn => {
                push_service_exists(
                    &mut clauses,
                    &mut params,
                    neg,
                    "ssl_cn LIKE ? COLLATE NOCASE",
                    like(&filter.value),
                );
            }
            Field::HasScreenshot => {
                let want = matches!(filter.value, FilterValue::Bool(true));
                // has_screenshot filter: exists a service with the flag set.
                let inner = "has_screenshot = 1";
                if want == !neg {
                    clauses.push(format!(
                        "EXISTS (SELECT 1 FROM services s WHERE s.ip = hosts.ip AND {inner})"
                    ));
                } else {
                    clauses.push(format!(
                        "NOT EXISTS (SELECT 1 FROM services s WHERE s.ip = hosts.ip AND {inner})"
                    ));
                }
            }
            Field::Country => {
                push_host_col(
                    &mut clauses,
                    &mut params,
                    neg,
                    "country = ? COLLATE NOCASE",
                    val(&filter.value),
                );
            }
            Field::Asn => {
                push_host_col(
                    &mut clauses,
                    &mut params,
                    neg,
                    "asn = ?",
                    val(&filter.value),
                );
            }
            Field::Org => {
                push_host_col(
                    &mut clauses,
                    &mut params,
                    neg,
                    "org LIKE ? COLLATE NOCASE",
                    like(&filter.value),
                );
            }
            Field::Hostname => {
                push_host_col(
                    &mut clauses,
                    &mut params,
                    neg,
                    "hostnames LIKE ? COLLATE NOCASE",
                    like(&filter.value),
                );
            }
            Field::Tag => {
                let inner =
                    "SELECT 1 FROM tags t WHERE t.ip = hosts.ip AND t.name = ? COLLATE NOCASE";
                params.push(val(&filter.value));
                clauses.push(format!("{} EXISTS ({inner})", if neg { "NOT" } else { "" }));
            }
            Field::Before => {
                push_host_col(
                    &mut clauses,
                    &mut params,
                    neg,
                    "last_seen < ?",
                    val(&filter.value),
                );
            }
            Field::After => {
                push_host_col(
                    &mut clauses,
                    &mut params,
                    neg,
                    "last_seen >= ?",
                    val(&filter.value),
                );
            }
            // --- v2 ---
            Field::Net => match net_bounds(&filter.value) {
                Some((lo, hi)) => {
                    params.push(Value::Blob(lo.to_vec()));
                    params.push(Value::Blob(hi.to_vec()));
                    let cond = "hosts.ip_sort BETWEEN ? AND ?";
                    clauses.push(if neg {
                        format!("NOT ({cond})")
                    } else {
                        cond.to_string()
                    });
                }
                // Unparseable CIDR/IP: match nothing rather than erroring.
                None => clauses.push(if neg { "1=1".into() } else { "1=0".into() }),
            },
            Field::City => {
                push_host_col(
                    &mut clauses,
                    &mut params,
                    neg,
                    "city LIKE ? COLLATE NOCASE",
                    like(&filter.value),
                );
            }
            Field::Transport => {
                push_service_exists(
                    &mut clauses,
                    &mut params,
                    neg,
                    "transport = ?",
                    val(&filter.value),
                );
            }
            Field::Jarm => {
                push_service_exists(
                    &mut clauses,
                    &mut params,
                    neg,
                    "jarm = ?",
                    val(&filter.value),
                );
            }
            Field::Favicon => {
                push_service_exists(
                    &mut clauses,
                    &mut params,
                    neg,
                    "favicon_hash = ?",
                    val(&filter.value),
                );
            }
            Field::SshHostkey => {
                push_service_exists(
                    &mut clauses,
                    &mut params,
                    neg,
                    "ssh_hostkey LIKE ? COLLATE NOCASE",
                    like(&filter.value),
                );
            }
            Field::Hassh => {
                push_service_exists(
                    &mut clauses,
                    &mut params,
                    neg,
                    "hassh = ? COLLATE NOCASE",
                    val(&filter.value),
                );
            }
            Field::Vuln => {
                let inner =
                    "SELECT 1 FROM tags t WHERE t.ip = hosts.ip AND t.cve = ? COLLATE NOCASE";
                params.push(val(&filter.value));
                clauses.push(format!("{} EXISTS ({inner})", if neg { "NOT" } else { "" }));
            }
            Field::HasVuln => {
                let want = matches!(filter.value, FilterValue::Bool(true));
                let inner = "SELECT 1 FROM tags t WHERE t.ip = hosts.ip AND t.cve IS NOT NULL";
                let kw = if want == !neg { "EXISTS" } else { "NOT EXISTS" };
                clauses.push(format!("{kw} ({inner})"));
            }
            Field::Ics => {
                push_service_exists(
                    &mut clauses,
                    &mut params,
                    neg,
                    "ics_protocol = ? COLLATE NOCASE",
                    val(&filter.value),
                );
            }
            Field::HasIcs => {
                let want = matches!(filter.value, FilterValue::Bool(true));
                let inner =
                    "SELECT 1 FROM services s WHERE s.ip = hosts.ip AND s.ics_protocol IS NOT NULL";
                let kw = if want == !neg { "EXISTS" } else { "NOT EXISTS" };
                clauses.push(format!("{kw} ({inner})"));
            }
            Field::Auth => {
                push_service_exists(
                    &mut clauses,
                    &mut params,
                    neg,
                    "auth_state = ?",
                    val(&filter.value),
                );
            }
            Field::Ja4ts => {
                push_service_exists(
                    &mut clauses,
                    &mut params,
                    neg,
                    "ja4ts = ? COLLATE NOCASE",
                    val(&filter.value),
                );
            }
            Field::ScreenshotHash => {
                push_service_exists(
                    &mut clauses,
                    &mut params,
                    neg,
                    "screenshot_phash = ?",
                    val(&filter.value),
                );
            }
            Field::Cluster => {
                push_host_col(
                    &mut clauses,
                    &mut params,
                    neg,
                    "cluster = ? COLLATE NOCASE",
                    val(&filter.value),
                );
            }
            Field::Honeypot => {
                // Unscored hosts count as score 0, so `-honeypot:true` keeps them.
                let (cond, v) = match filter.value {
                    FilterValue::Bool(true) => ("COALESCE(hosts.honeypot, 0) >= ?", 0.5),
                    FilterValue::Bool(false) => ("COALESCE(hosts.honeypot, 0) < ?", 0.5),
                    FilterValue::Int(n) => ("COALESCE(hosts.honeypot, 0) >= ?", n as f64 / 100.0),
                    _ => ("COALESCE(hosts.honeypot, 0) >= ?", 0.5),
                };
                push_host_col(&mut clauses, &mut params, neg, cond, Value::Real(v));
            }
            Field::HasExploit => {
                // Exploit availability rides on an `exploit-available` tag emitted
                // by the vuln crate when a CVE maps to a known public exploit.
                let want = matches!(filter.value, FilterValue::Bool(true));
                let inner =
                    "SELECT 1 FROM tags t WHERE t.ip = hosts.ip AND t.name = 'exploit-available'";
                let kw = if want == !neg { "EXISTS" } else { "NOT EXISTS" };
                clauses.push(format!("{kw} ({inner})"));
            }
        }
    }

    // Free text -> FTS match. Combine all tokens into one MATCH expression.
    if !query.text.is_empty() {
        let fts = query
            .text
            .iter()
            .map(|t| format!("\"{}\"", t.replace('"', "\"\"")))
            .collect::<Vec<_>>()
            .join(" ");
        // Joined on rowid: banner_fts.ip is UNINDEXED, so matching on it would
        // not use an index.
        clauses.push(
            "hosts.rowid IN (SELECT rowid FROM banner_fts WHERE banner_fts MATCH ?)".to_string(),
        );
        params.push(Value::Text(fts));
    }

    let where_sql = if clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", clauses.join(" AND "))
    };

    let order = if ordered {
        " ORDER BY hosts.last_seen DESC"
    } else {
        ""
    };
    let sql = format!("SELECT hosts.ip FROM hosts {where_sql}{order}");

    Compiled { sql, params }
}

fn push_service_exists(
    clauses: &mut Vec<String>,
    params: &mut Vec<Value>,
    neg: bool,
    inner: &str,
    v: Value,
) {
    params.push(v);
    let kw = if neg { "NOT EXISTS" } else { "EXISTS" };
    clauses.push(format!(
        "{kw} (SELECT 1 FROM services s WHERE s.ip = hosts.ip AND {inner})"
    ));
}

fn push_host_col(
    clauses: &mut Vec<String>,
    params: &mut Vec<Value>,
    neg: bool,
    cond: &str,
    v: Value,
) {
    params.push(v);
    if neg {
        clauses.push(format!("NOT ({cond})"));
    } else {
        clauses.push(cond.to_string());
    }
}

fn val(v: &FilterValue) -> Value {
    match v {
        FilterValue::Int(i) => Value::Integer(*i),
        FilterValue::Timestamp(t) => Value::Integer(*t),
        FilterValue::Bool(b) => Value::Integer(*b as i64),
        FilterValue::Text(s) => Value::Text(s.clone()),
    }
}

fn like(v: &FilterValue) -> Value {
    match v {
        FilterValue::Text(s) => Value::Text(format!("%{s}%")),
        other => val(other),
    }
}

/// Compute the inclusive [first, last] 16-byte sort keys for a `net:` value.
/// Accepts a CIDR ("10.0.0.0/8", "2001:db8::/32") or a bare IP (treated as a
/// single-address range). Returns None if the value does not parse.
fn net_bounds(v: &FilterValue) -> Option<([u8; 16], [u8; 16])> {
    let text = match v {
        FilterValue::Text(s) => s.as_str(),
        _ => return None,
    };
    if let Ok(net) = text.parse::<ipnet::IpNet>() {
        return Some((
            crate::ip_sort_key(net.network()),
            crate::ip_sort_key(net.broadcast()),
        ));
    }
    if let Ok(ip) = text.parse::<std::net::IpAddr>() {
        let k = crate::ip_sort_key(ip);
        return Some((k, k));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crusade_core::query::parse;

    #[test]
    fn empty_query_selects_all() {
        let c = compile(&parse("").unwrap());
        assert!(!c.sql.contains("WHERE"));
        assert!(c.params.is_empty());
    }

    #[test]
    fn port_filter_uses_exists_and_binds_param() {
        let c = compile(&parse("port:22").unwrap());
        assert!(c.sql.contains("EXISTS"));
        assert!(c.sql.contains("port = ?"));
        assert_eq!(c.params.len(), 1);
        assert!(matches!(c.params[0], Value::Integer(22)));
    }

    #[test]
    fn product_uses_like_wildcards() {
        let c = compile(&parse("product:nginx").unwrap());
        match &c.params[0] {
            Value::Text(s) => assert_eq!(s, "%nginx%"),
            _ => panic!(),
        }
    }

    #[test]
    fn negation_becomes_not_exists() {
        let c = compile(&parse("-product:nginx").unwrap());
        assert!(c.sql.contains("NOT EXISTS"));
    }

    #[test]
    fn free_text_routes_through_fts() {
        let c = compile(&parse("admin panel").unwrap());
        assert!(c.sql.contains("banner_fts MATCH ?"));
        assert_eq!(c.params.len(), 1);
    }

    #[test]
    fn net_filter_uses_ip_sort_between() {
        let c = compile(&parse("net:10.0.0.0/8").unwrap());
        assert!(c.sql.contains("ip_sort BETWEEN ? AND ?"));
        assert_eq!(c.params.len(), 2);
        assert!(matches!(c.params[0], Value::Blob(_)));
    }

    #[test]
    fn bad_net_matches_nothing() {
        let c = compile(&parse("net:not-a-cidr").unwrap());
        assert!(c.sql.contains("1=0"));
    }

    #[test]
    fn favicon_binds_integer() {
        let c = compile(&parse("http.favicon.hash:-247388890").unwrap());
        assert!(c.sql.contains("favicon_hash = ?"));
        assert!(matches!(c.params[0], Value::Integer(-247388890)));
    }

    #[test]
    fn vuln_hits_tags_cve() {
        let c = compile(&parse("vuln:CVE-2021-44228").unwrap());
        assert!(c.sql.contains("t.cve = ?"));
    }

    #[test]
    fn has_vuln_negation() {
        let c = compile(&parse("-has_vuln:true").unwrap());
        assert!(c.sql.contains("NOT EXISTS"));
    }

    #[test]
    fn auth_and_has_exploit() {
        let c = compile(&parse("auth:open").unwrap());
        assert!(c.sql.contains("auth_state = ?"));
        let c = compile(&parse("has_exploit:true").unwrap());
        assert!(c.sql.contains("name = 'exploit-available'"));
        assert!(c.sql.contains("EXISTS"));
        let c = compile(&parse("-has_exploit:true").unwrap());
        assert!(c.sql.contains("NOT EXISTS"));
    }

    #[test]
    fn ics_filter_and_has_ics() {
        let c = compile(&parse("ics:modbus").unwrap());
        assert!(c.sql.contains("ics_protocol = ?"));
        let c = compile(&parse("has_ics:true").unwrap());
        assert!(c.sql.contains("ics_protocol IS NOT NULL"));
        assert!(c.sql.contains("EXISTS"));
    }

    #[test]
    fn no_raw_values_in_sql() {
        // The literal user value must never appear in the SQL text.
        let c = compile(&parse("org:\"Secret Corp\" port:8080").unwrap());
        assert!(!c.sql.contains("Secret"));
        assert!(!c.sql.contains("8080"));
    }
}
