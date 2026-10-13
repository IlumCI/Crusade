//! Shodan-style query language.
//!
//! A query is a space-separated list of terms. A term is either:
//!   * a `key:value` filter (e.g. `port:443`, `country:DE`, `product:nginx`),
//!   * a quoted or bare free-text token matched against banners.
//!
//! Quotes group a value containing spaces: `org:"Deutsche Telekom"` or a
//! free-text phrase `"default page"`. A leading `-` negates a filter.
//!
//! The parser is deliberately permissive: an unknown `key:` is treated as
//! free text so the UI never hard-errors on a typo. Compilation to SQL lives
//! in the `store` crate; this module only produces the AST.

use std::fmt;
use time::{Date, OffsetDateTime, Time, UtcOffset};

/// A fully parsed query: a set of structured filters plus free-text tokens.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Query {
    pub filters: Vec<Filter>,
    pub text: Vec<String>,
}

/// One structured `key:value` constraint.
#[derive(Debug, Clone, PartialEq)]
pub struct Filter {
    pub field: Field,
    pub value: FilterValue,
    pub negate: bool,
}

/// The recognised filter keys. `product`, `country`, etc. map 1:1 to columns
/// or joins in the store layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Port,
    Country,
    Asn,
    Org,
    Product,
    Version,
    Hostname,
    SslCn,
    Tag,
    HasScreenshot,
    Before,
    After,
    // --- v2 ---
    /// `net:` — a CIDR the host IP must fall within.
    Net,
    City,
    /// `transport:tcp|udp`.
    Transport,
    /// `jarm:` — JARM TLS fingerprint.
    Jarm,
    /// `http.favicon.hash:` / `favicon:` — mmh3 favicon hash (integer).
    Favicon,
    /// `ssh.hostkey:` — host-key SHA-256 fingerprint.
    SshHostkey,
    /// `hassh:` — SSH HASSH fingerprint.
    Hassh,
    /// `vuln:` — a specific CVE id attached to the host.
    Vuln,
    /// `has_vuln:` — whether the host carries any CVE tag.
    HasVuln,
    /// `ics:` — an ICS/OT protocol a service speaks (modbus, s7, bacnet, …).
    Ics,
    /// `has_ics:` — whether the host exposes any ICS/OT service.
    HasIcs,
    /// `auth:` — a service's observed auth posture (open | required | unknown).
    Auth,
    /// `has_exploit:` — whether any attached CVE has a known public exploit.
    HasExploit,
    Honeypot,
    Ja4ts,
}

impl Field {
    fn parse(key: &str) -> Option<Field> {
        Some(match key.to_ascii_lowercase().as_str() {
            "port" => Field::Port,
            "country" | "country_code" => Field::Country,
            "asn" => Field::Asn,
            "org" | "organization" => Field::Org,
            "product" => Field::Product,
            "version" => Field::Version,
            "hostname" | "host" => Field::Hostname,
            "ssl.cn" | "ssl" | "cn" => Field::SslCn,
            "tag" => Field::Tag,
            "has_screenshot" => Field::HasScreenshot,
            "before" => Field::Before,
            "after" => Field::After,
            "net" | "ip" => Field::Net,
            "city" => Field::City,
            "transport" | "proto" | "protocol" => Field::Transport,
            "jarm" | "ssl.jarm" => Field::Jarm,
            "favicon" | "http.favicon.hash" | "favicon.hash" => Field::Favicon,
            "ssh.hostkey" | "ssh.key" | "hostkey" => Field::SshHostkey,
            "hassh" | "ssh.hassh" => Field::Hassh,
            "vuln" | "cve" => Field::Vuln,
            "has_vuln" => Field::HasVuln,
            "ics" | "ics.protocol" => Field::Ics,
            "has_ics" => Field::HasIcs,
            "auth" => Field::Auth,
            "has_exploit" | "exploit" => Field::HasExploit,
            "honeypot" | "honeyscore" => Field::Honeypot,
            "ja4ts" | "ja4t" => Field::Ja4ts,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Field::Port => "port",
            Field::Country => "country",
            Field::Asn => "asn",
            Field::Org => "org",
            Field::Product => "product",
            Field::Version => "version",
            Field::Hostname => "hostname",
            Field::SslCn => "ssl.cn",
            Field::Tag => "tag",
            Field::HasScreenshot => "has_screenshot",
            Field::Before => "before",
            Field::After => "after",
            Field::Net => "net",
            Field::City => "city",
            Field::Transport => "transport",
            Field::Jarm => "jarm",
            Field::Favicon => "http.favicon.hash",
            Field::SshHostkey => "ssh.hostkey",
            Field::Hassh => "hassh",
            Field::Vuln => "vuln",
            Field::HasVuln => "has_vuln",
            Field::Ics => "ics",
            Field::HasIcs => "has_ics",
            Field::Auth => "auth",
            Field::HasExploit => "has_exploit",
            Field::Honeypot => "honeypot",
            Field::Ja4ts => "ja4ts",
        }
    }
}

/// The typed value a filter carries after parsing.
#[derive(Debug, Clone, PartialEq)]
pub enum FilterValue {
    Int(i64),
    Bool(bool),
    /// A date, stored as a UTC unix timestamp (seconds).
    Timestamp(i64),
    Text(String),
}

/// Errors a caller may want to surface. The parser only emits these for
/// malformed *typed* values (a bad port, asn, bool or date); unknown keys
/// never error.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ParseError {
    #[error("invalid number for `{field}`: {value:?}")]
    BadNumber { field: &'static str, value: String },
    #[error("invalid date for `{field}`: {value:?} (expected YYYY-MM-DD)")]
    BadDate { field: &'static str, value: String },
    #[error("invalid boolean for `{field}`: {value:?} (use true/false)")]
    BadBool { field: &'static str, value: String },
    #[error("invalid value for `{field}`: {value:?} (allowed: {allowed})")]
    BadEnum {
        field: &'static str,
        value: String,
        allowed: &'static str,
    },
}

impl fmt::Display for Query {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for filter in &self.filters {
            if !first {
                write!(f, " ")?;
            }
            first = false;
            if filter.negate {
                write!(f, "-")?;
            }
            write!(f, "{}:{}", filter.field.as_str(), filter.value)?;
        }
        for t in &self.text {
            if !first {
                write!(f, " ")?;
            }
            first = false;
            if t.contains(' ') {
                write!(f, "\"{t}\"")?;
            } else {
                write!(f, "{t}")?;
            }
        }
        Ok(())
    }
}

impl fmt::Display for FilterValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FilterValue::Int(i) => write!(f, "{i}"),
            FilterValue::Bool(b) => write!(f, "{b}"),
            FilterValue::Timestamp(ts) => write!(f, "{ts}"),
            FilterValue::Text(s) => {
                if s.contains(' ') {
                    write!(f, "\"{s}\"")
                } else {
                    write!(f, "{s}")
                }
            }
        }
    }
}

/// Parse a raw query string into a [`Query`].
pub fn parse(input: &str) -> Result<Query, ParseError> {
    let tokens = tokenize(input);
    let mut query = Query::default();

    for tok in tokens {
        // A negation prefix only applies to key:value filters.
        let (negate, body) = match tok.text.strip_prefix('-') {
            Some(rest) if rest.contains(':') && !tok.was_quoted => (true, rest.to_string()),
            _ => (false, tok.text.clone()),
        };

        // Split on the first ':' only if the token was not a quoted phrase.
        if !tok.was_quoted {
            if let Some((key, val)) = body.split_once(':') {
                if let Some(field) = Field::parse(key) {
                    let value = parse_value(field, val)?;
                    query.filters.push(Filter {
                        field,
                        value,
                        negate,
                    });
                    continue;
                }
            }
        }
        // Fall through: free text (including unknown key:value and phrases).
        if !tok.text.is_empty() {
            query.text.push(tok.text);
        }
    }

    Ok(query)
}

fn parse_value(field: Field, raw: &str) -> Result<FilterValue, ParseError> {
    match field {
        Field::Port | Field::Asn => raw
            .trim_start_matches("AS")
            .trim_start_matches("as")
            .parse::<i64>()
            .map(FilterValue::Int)
            .map_err(|_| ParseError::BadNumber {
                field: field.as_str(),
                value: raw.to_string(),
            }),
        Field::Favicon => {
            raw.parse::<i64>()
                .map(FilterValue::Int)
                .map_err(|_| ParseError::BadNumber {
                    field: field.as_str(),
                    value: raw.to_string(),
                })
        }
        Field::HasScreenshot | Field::HasVuln | Field::HasIcs | Field::HasExploit => {
            match raw.to_ascii_lowercase().as_str() {
                "true" | "1" | "yes" => Ok(FilterValue::Bool(true)),
                "false" | "0" | "no" => Ok(FilterValue::Bool(false)),
                _ => Err(ParseError::BadBool {
                    field: field.as_str(),
                    value: raw.to_string(),
                }),
            }
        }
        // `honeypot:true|false`, or `honeypot:N` = score at least N percent.
        Field::Honeypot => match raw.to_ascii_lowercase().as_str() {
            "true" | "yes" => Ok(FilterValue::Bool(true)),
            "false" | "no" => Ok(FilterValue::Bool(false)),
            other => match other.parse::<i64>() {
                Ok(n) if (0..=100).contains(&n) => Ok(FilterValue::Int(n)),
                _ => Err(ParseError::BadEnum {
                    field: field.as_str(),
                    value: raw.to_string(),
                    allowed: "true, false, or a score threshold 0-100",
                }),
            },
        },
        Field::Auth => match raw.to_ascii_lowercase().as_str() {
            "open" | "none" | "unauth" | "unauthenticated" | "no" => {
                Ok(FilterValue::Text("open".into()))
            }
            "required" | "auth" | "authenticated" | "yes" => {
                Ok(FilterValue::Text("required".into()))
            }
            "unknown" => Ok(FilterValue::Text("unknown".into())),
            _ => Err(ParseError::BadEnum {
                field: field.as_str(),
                value: raw.to_string(),
                allowed: "open, required, unknown",
            }),
        },
        Field::Transport => match raw.to_ascii_lowercase().as_str() {
            "tcp" => Ok(FilterValue::Text("tcp".into())),
            "udp" => Ok(FilterValue::Text("udp".into())),
            _ => Err(ParseError::BadEnum {
                field: field.as_str(),
                value: raw.to_string(),
                allowed: "tcp, udp",
            }),
        },
        Field::Before | Field::After => parse_date(field, raw).map(FilterValue::Timestamp),
        Field::Country => Ok(FilterValue::Text(raw.to_ascii_uppercase())),
        _ => Ok(FilterValue::Text(raw.to_string())),
    }
}

/// Parse `YYYY-MM-DD` into a unix timestamp at UTC midnight.
fn parse_date(field: Field, raw: &str) -> Result<i64, ParseError> {
    let bad = || ParseError::BadDate {
        field: field.as_str(),
        value: raw.to_string(),
    };
    let mut parts = raw.split('-');
    let y: i32 = parts.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    let m: u8 = parts.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    let d: u8 = parts.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    if parts.next().is_some() {
        return Err(bad());
    }
    let month = time::Month::try_from(m).map_err(|_| bad())?;
    let date = Date::from_calendar_date(y, month, d).map_err(|_| bad())?;
    let dt = OffsetDateTime::new_in_offset(date, Time::MIDNIGHT, UtcOffset::UTC);
    Ok(dt.unix_timestamp())
}

/// A tokenizer output item.
///
/// `was_quoted` is true only when the token *began* with a quote, i.e. it is a
/// pure free-text phrase like `"default page"`. A quote that appears mid-token
/// (as in `org:"Deutsche Telekom"`) wraps only the value and does NOT set this
/// flag, so such tokens are still eligible to be parsed as `key:value`.
struct Token {
    text: String,
    was_quoted: bool,
}

/// Split input into tokens, honoring double quotes. A `-` immediately before a
/// quote is kept attached so `-org:"x"` still works, but a leading phrase quote
/// like `"default page"` is preserved whole and flagged as free text.
fn tokenize(input: &str) -> Vec<Token> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut active = false; // a token is being built (covers empty `""`)
    let mut leading_quote = false; // token began with a quote

    for c in input.chars() {
        match c {
            '"' => {
                if in_quotes {
                    in_quotes = false;
                } else {
                    in_quotes = true;
                    // A quote at the very start of a token marks a phrase.
                    if !active {
                        leading_quote = true;
                    }
                }
                active = true;
            }
            c if c.is_whitespace() && !in_quotes => {
                if active {
                    out.push(Token {
                        text: std::mem::take(&mut cur),
                        was_quoted: leading_quote,
                    });
                    leading_quote = false;
                    active = false;
                }
            }
            _ => {
                cur.push(c);
                active = true;
            }
        }
    }
    if active {
        out.push(Token {
            text: cur,
            was_quoted: leading_quote,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(q: &Query, field: Field) -> &Filter {
        q.filters
            .iter()
            .find(|x| x.field == field)
            .expect("filter present")
    }

    #[test]
    fn plain_text() {
        let q = parse("default page").unwrap();
        assert!(q.filters.is_empty());
        assert_eq!(q.text, vec!["default".to_string(), "page".to_string()]);
    }

    #[test]
    fn quoted_phrase_is_single_text_token() {
        let q = parse("\"default page\"").unwrap();
        assert!(q.filters.is_empty());
        assert_eq!(q.text, vec!["default page".to_string()]);
    }

    #[test]
    fn port_is_int() {
        let q = parse("port:22").unwrap();
        assert_eq!(f(&q, Field::Port).value, FilterValue::Int(22));
    }

    #[test]
    fn asn_strips_as_prefix() {
        let q = parse("asn:AS3320").unwrap();
        assert_eq!(f(&q, Field::Asn).value, FilterValue::Int(3320));
    }

    #[test]
    fn country_is_uppercased() {
        let q = parse("country:de").unwrap();
        assert_eq!(f(&q, Field::Country).value, FilterValue::Text("DE".into()));
    }

    #[test]
    fn quoted_filter_value_with_space() {
        // org:"Deutsche Telekom" — the quote is inside the token.
        let q = parse("org:\"Deutsche Telekom\"").unwrap();
        assert_eq!(
            f(&q, Field::Org).value,
            FilterValue::Text("Deutsche Telekom".into())
        );
    }

    #[test]
    fn negation() {
        let q = parse("-product:nginx").unwrap();
        let filt = f(&q, Field::Product);
        assert!(filt.negate);
        assert_eq!(filt.value, FilterValue::Text("nginx".into()));
    }

    #[test]
    fn mixed_query() {
        let q =
            parse("port:443 country:DE product:nginx \"default page\" after:2026-01-01").unwrap();
        assert_eq!(q.filters.len(), 4);
        assert_eq!(q.text, vec!["default page".to_string()]);
        // after:2026-01-01 == 2026-01-01T00:00:00Z
        let ts = match f(&q, Field::After).value {
            FilterValue::Timestamp(t) => t,
            _ => panic!("expected timestamp"),
        };
        assert_eq!(ts, 1767225600);
    }

    #[test]
    fn unknown_key_is_free_text() {
        let q = parse("frobnicate:yes").unwrap();
        assert!(q.filters.is_empty());
        assert_eq!(q.text, vec!["frobnicate:yes".to_string()]);
    }

    #[test]
    fn bad_port_errors() {
        assert!(matches!(
            parse("port:notaport"),
            Err(ParseError::BadNumber { .. })
        ));
    }

    #[test]
    fn bad_date_errors() {
        assert!(matches!(
            parse("after:2026-13-40"),
            Err(ParseError::BadDate { .. })
        ));
    }

    #[test]
    fn has_screenshot_bool() {
        let q = parse("has_screenshot:true").unwrap();
        assert_eq!(f(&q, Field::HasScreenshot).value, FilterValue::Bool(true));
    }

    #[test]
    fn v2_net_filter() {
        let q = parse("net:10.0.0.0/8").unwrap();
        assert_eq!(
            f(&q, Field::Net).value,
            FilterValue::Text("10.0.0.0/8".into())
        );
    }

    #[test]
    fn v2_favicon_is_int() {
        let q = parse("http.favicon.hash:-247388890").unwrap();
        assert_eq!(f(&q, Field::Favicon).value, FilterValue::Int(-247388890));
        // short alias
        let q = parse("favicon:116323821").unwrap();
        assert_eq!(f(&q, Field::Favicon).value, FilterValue::Int(116323821));
    }

    #[test]
    fn v2_transport_enum() {
        let q = parse("transport:udp").unwrap();
        assert_eq!(
            f(&q, Field::Transport).value,
            FilterValue::Text("udp".into())
        );
        assert!(matches!(
            parse("transport:sctp"),
            Err(ParseError::BadEnum { .. })
        ));
    }

    #[test]
    fn v2_vuln_and_jarm_and_hassh() {
        let q =
            parse("vuln:CVE-2021-1234 jarm:abcd hassh:deadbeef ssh.hostkey:SHA256:xyz").unwrap();
        assert_eq!(
            f(&q, Field::Vuln).value,
            FilterValue::Text("CVE-2021-1234".into())
        );
        assert_eq!(f(&q, Field::Jarm).value, FilterValue::Text("abcd".into()));
        assert_eq!(
            f(&q, Field::Hassh).value,
            FilterValue::Text("deadbeef".into())
        );
        assert_eq!(
            f(&q, Field::SshHostkey).value,
            FilterValue::Text("SHA256:xyz".into())
        );
    }

    #[test]
    fn v3_auth_filter_aliases() {
        for alias in ["open", "none", "unauth", "unauthenticated"] {
            let q = parse(&format!("auth:{alias}")).unwrap();
            assert_eq!(f(&q, Field::Auth).value, FilterValue::Text("open".into()));
        }
        let q = parse("auth:required").unwrap();
        assert_eq!(
            f(&q, Field::Auth).value,
            FilterValue::Text("required".into())
        );
        assert!(matches!(
            parse("auth:banana"),
            Err(ParseError::BadEnum { .. })
        ));
    }

    #[test]
    fn v3_has_exploit_bool() {
        let q = parse("has_exploit:true").unwrap();
        assert_eq!(f(&q, Field::HasExploit).value, FilterValue::Bool(true));
    }

    #[test]
    fn v3_ics_filters() {
        let q = parse("ics:modbus has_ics:true").unwrap();
        assert_eq!(f(&q, Field::Ics).value, FilterValue::Text("modbus".into()));
        assert_eq!(f(&q, Field::HasIcs).value, FilterValue::Bool(true));
    }

    #[test]
    fn v2_has_vuln_bool() {
        let q = parse("has_vuln:true").unwrap();
        assert_eq!(f(&q, Field::HasVuln).value, FilterValue::Bool(true));
    }

    #[test]
    fn roundtrip_display() {
        let q = parse("port:443 product:nginx \"default page\"").unwrap();
        let s = q.to_string();
        let q2 = parse(&s).unwrap();
        assert_eq!(q, q2);
    }

    #[test]
    fn honeypot_filter_values() {
        let q = parse("-honeypot:true port:22").unwrap();
        let hp = f(&q, Field::Honeypot);
        assert!(hp.negate);
        assert_eq!(hp.value, FilterValue::Bool(true));
        let q = parse("honeyscore:80").unwrap();
        assert_eq!(f(&q, Field::Honeypot).value, FilterValue::Int(80));
        assert!(parse("honeypot:101").is_err());
        assert!(parse("honeypot:maybe").is_err());
    }
}
