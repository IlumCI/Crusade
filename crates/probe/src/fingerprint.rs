//! nmap-service-probes fingerprint engine.
//!
//! This module parses a workable *subset* of the Nmap `nmap-service-probes`
//! database and uses it to identify services from the bytes they emit.
//!
//! We load `Probe` blocks together with their `match`/`softmatch` lines, and
//! focus on the two probes that matter for a connect-and-read scanner:
//!
//! * the **NULL** probe — the service's unsolicited banner (nothing is sent);
//! * the **GetRequest** probe — the response to a minimal `GET / HTTP/1.0`.
//!
//! Each `match` line carries a Perl-ish regex (`m|...|flags`) plus template
//! fields (`p/product/`, `v/version/`, `cpe:/.../`). We compile the regex with
//! the Rust [`regex`] crate (byte mode). Nmap uses a few constructs Rust's
//! engine does not support — most notably backreferences. Those lines are
//! simply dropped rather than treated as errors. Atomic groups `(?>...)`, used
//! by Nmap purely for performance, are rewritten to ordinary non-capturing
//! groups `(?:...)` so the rule still matches.
//!
//! On a hit, `$1`, `$2`, … in the templates are substituted with the
//! corresponding capture groups.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::Context;
use regex::bytes::Regex;

/// Which probe produced the bytes being identified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProbeKind {
    /// The service spoke first; we sent nothing.
    Null,
    /// Response to a minimal HTTP `GET / HTTP/1.0` request.
    GetRequest,
}

/// The default on-disk location of the Nmap probe database.
pub const DEFAULT_PROBES_PATH: &str = "/usr/share/nmap/nmap-service-probes";

/// Outcome of a successful fingerprint lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceMatch {
    pub service: String,
    pub product: Option<String>,
    pub version: Option<String>,
    pub cpe: Option<String>,
}

/// A single compiled `match`/`softmatch` rule.
struct MatchRule {
    service: String,
    regex: Regex,
    product_tpl: Option<String>,
    version_tpl: Option<String>,
    cpe_tpl: Option<String>,
    soft: bool,
}

/// A loaded, compiled subset of the Nmap service-probes database.
pub struct Fingerprints {
    rules: HashMap<ProbeKind, Vec<MatchRule>>,
}

impl Fingerprints {
    /// Load and compile the database from the default path.
    pub fn load_default() -> anyhow::Result<Self> {
        Self::load(Path::new(DEFAULT_PROBES_PATH))
    }

    /// Load and compile the database from `path`.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading probe db {}", path.display()))?;
        Ok(Self::parse(&text))
    }

    /// Parse a probe database from an in-memory string. Lines whose regex
    /// cannot be compiled are silently dropped.
    pub fn parse(text: &str) -> Self {
        let mut rules: HashMap<ProbeKind, Vec<MatchRule>> = HashMap::new();
        rules.insert(ProbeKind::Null, Vec::new());
        rules.insert(ProbeKind::GetRequest, Vec::new());

        // Which probe block we are currently inside. `None` means a probe we
        // do not track, so its match lines are ignored.
        let mut current: Option<ProbeKind> = None;

        for line in text.lines() {
            let line = line.trim_end_matches(['\r', '\n']);
            if line.starts_with('#') {
                continue;
            }
            if let Some(rest) = line.strip_prefix("Probe ") {
                current = parse_probe_header(rest);
                continue;
            }
            let Some(kind) = current else { continue };

            let (soft, rest) = if let Some(r) = line.strip_prefix("match ") {
                (false, r)
            } else if let Some(r) = line.strip_prefix("softmatch ") {
                (true, r)
            } else {
                continue;
            };

            if let Some(rule) = parse_match_line(rest, soft) {
                rules.get_mut(&kind).expect("kind preallocated").push(rule);
            }
        }

        Fingerprints { rules }
    }

    /// Number of compiled rules for a probe (useful in tests).
    pub fn rule_count(&self, probe: ProbeKind) -> usize {
        self.rules.get(&probe).map(|v| v.len()).unwrap_or(0)
    }

    /// Identify the service that produced `data` under the given probe.
    ///
    /// Hard `match` lines win immediately. If only `softmatch` lines hit, the
    /// first soft match is returned. `port` is accepted for future
    /// port-priority heuristics but does not currently affect the result.
    pub fn identify(&self, _port: u16, probe: ProbeKind, data: &[u8]) -> Option<ServiceMatch> {
        let rules = self.rules.get(&probe)?;
        let mut soft_hit: Option<ServiceMatch> = None;

        for rule in rules {
            if let Some(caps) = rule.regex.captures(data) {
                let sm = ServiceMatch {
                    service: rule.service.clone(),
                    product: rule.product_tpl.as_deref().map(|t| subst(t, &caps)),
                    version: rule.version_tpl.as_deref().map(|t| subst(t, &caps)),
                    cpe: rule.cpe_tpl.as_deref().map(|t| subst(t, &caps)),
                };
                if rule.soft {
                    if soft_hit.is_none() {
                        soft_hit = Some(sm);
                    }
                } else {
                    return Some(sm);
                }
            }
        }
        soft_hit
    }
}

/// Parse the tail of a `Probe ` line, returning the kind if we track it.
///
/// Example: `TCP NULL q||` or `TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|`.
fn parse_probe_header(rest: &str) -> Option<ProbeKind> {
    let mut parts = rest.split_whitespace();
    let _proto = parts.next()?; // TCP / UDP
    let name = parts.next()?;
    match name {
        "NULL" => Some(ProbeKind::Null),
        "GetRequest" => Some(ProbeKind::GetRequest),
        _ => None,
    }
}

/// Parse one `match`/`softmatch` body (the text after the keyword).
fn parse_match_line(rest: &str, soft: bool) -> Option<MatchRule> {
    // <service> m<DELIM><regex><DELIM>[flags] <fields...>
    let rest = rest.trim_start();
    let sp = rest.find(char::is_whitespace)?;
    let service = rest[..sp].to_string();
    let after = rest[sp..].trim_start();

    let after = after.strip_prefix('m')?;
    let mut chars = after.char_indices();
    let (_, delim) = chars.next()?;
    let body_start = delim.len_utf8();
    let close_rel = after[body_start..].find(delim)?;
    let pattern = &after[body_start..body_start + close_rel];
    let after_pat = &after[body_start + close_rel + delim.len_utf8()..];

    // Flags run until whitespace.
    let flags_end = after_pat
        .find(char::is_whitespace)
        .unwrap_or(after_pat.len());
    let flags = &after_pat[..flags_end];
    let fields = after_pat[flags_end..].trim_start();

    let regex = compile_nmap_regex(pattern, flags)?;

    let product_tpl = extract_field(fields, 'p');
    let version_tpl = extract_field(fields, 'v');
    let cpe_tpl = extract_cpe(fields);

    Some(MatchRule {
        service,
        regex,
        product_tpl,
        version_tpl,
        cpe_tpl,
        soft,
    })
}

/// Translate an Nmap regex + flag string into a compiled Rust byte regex.
///
/// Returns `None` if the pattern cannot be compiled (e.g. backreferences).
fn compile_nmap_regex(pattern: &str, flags: &str) -> Option<Regex> {
    // Rewrite atomic groups `(?>` to ordinary non-capturing groups.
    let pattern = pattern.replace("(?>", "(?:");

    let case_insensitive = flags.contains('i');
    let dotall = flags.contains('s');

    // Byte regex, unicode disabled so `\xNN` and `.` operate on raw bytes.
    let mut prefix = String::from("(?-u)");
    if case_insensitive {
        prefix.push_str("(?i)");
    }
    if dotall {
        prefix.push_str("(?s)");
    }
    let full = format!("{prefix}{pattern}");
    Regex::new(&full).ok()
}

/// Extract a single-letter field such as `p/.../` from the fields tail.
fn extract_field(fields: &str, tag: char) -> Option<String> {
    // Scan for a `tag` that starts a token (preceded by whitespace or start)
    // and is immediately followed by a delimiter character.
    let bytes = fields.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let at_boundary = i == 0 || bytes[i - 1].is_ascii_whitespace();
        if at_boundary && bytes[i] == tag as u8 && i + 1 < bytes.len() {
            let delim = bytes[i + 1] as char;
            // A delimiter is punctuation, never alnum (guards against words).
            if !delim.is_ascii_alphanumeric() {
                let content_start = i + 2;
                if let Some(rel) = fields[content_start..].find(delim) {
                    return Some(fields[content_start..content_start + rel].to_string());
                }
            }
        }
        i += 1;
    }
    None
}

/// Extract the first `cpe:/.../` field.
fn extract_cpe(fields: &str) -> Option<String> {
    let idx = fields.find("cpe:")?;
    let after = &fields[idx + 4..];
    let delim = after.chars().next()?;
    let content = &after[delim.len_utf8()..];
    let rel = content.find(delim)?;
    Some(format!("cpe:/{}", content[..rel].trim_start_matches('/')))
}

/// Substitute `$1`, `$2`, … in a template with capture groups (lossy UTF-8).
fn subst(template: &str, caps: &regex::bytes::Captures) -> String {
    let mut out = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '$' {
            if let Some(d) = chars.peek().copied() {
                if d.is_ascii_digit() {
                    chars.next();
                    let idx = (d as u8 - b'0') as usize;
                    if let Some(m) = caps.get(idx) {
                        out.push_str(&String::from_utf8_lossy(m.as_bytes()));
                    }
                    continue;
                }
            }
            out.push('$');
        } else {
            out.push(c);
        }
    }
    out.trim().to_string()
}

/// A convenient default path as an owned [`PathBuf`].
pub fn default_path() -> PathBuf {
    PathBuf::from(DEFAULT_PROBES_PATH)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SNIPPET: &str = r#"
Probe TCP NULL q||
match ssh m|^SSH-([\d.]+)-OpenSSH_(?>([\w._-]+)[ -]{1,2}Ubuntu)[ -_]([^\r\n]+)\r?\n| p/OpenSSH/ v/$2 Ubuntu $3/ i/Ubuntu Linux; protocol $1/ cpe:/a:openbsd:openssh:$2/
match ssh m|^SSH-([\d.]+)-OpenSSH[_-]([\w.]+)\s*\r?\n|i p/OpenSSH/ v/$2/ i/protocol $1/ cpe:/a:openbsd:openssh:$2/
match bogus m|^(\1)$| p/should be dropped/

Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
match http m|^HTTP/1\.[01] \d\d\d| p/generic httpd/
"#;

    #[test]
    fn parses_and_drops_bad_regex() {
        let fp = Fingerprints::parse(SNIPPET);
        // The backreference rule must have been dropped.
        assert_eq!(fp.rule_count(ProbeKind::Null), 2);
        assert_eq!(fp.rule_count(ProbeKind::GetRequest), 1);
    }

    #[test]
    fn identifies_openssh_banner() {
        let fp = Fingerprints::parse(SNIPPET);
        let banner = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n";
        let m = fp
            .identify(22, ProbeKind::Null, banner)
            .expect("should identify");
        assert_eq!(m.service, "ssh");
        assert_eq!(m.product.as_deref(), Some("OpenSSH"));
        // Atomic-group rule wins: version carries the Ubuntu detail.
        assert_eq!(m.version.as_deref(), Some("8.9p1 Ubuntu 3"));
        assert_eq!(m.cpe.as_deref(), Some("cpe:/a:openbsd:openssh:8.9p1"));
    }

    #[test]
    fn identifies_from_default_db_if_present() {
        // The real database exists on this machine; exercise it end to end.
        if let Ok(fp) = Fingerprints::load_default() {
            let banner = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n";
            let m = fp.identify(22, ProbeKind::Null, banner);
            let m = m.expect("default db should identify OpenSSH");
            assert_eq!(m.service, "ssh");
            assert_eq!(m.product.as_deref(), Some("OpenSSH"));
        }
    }

    #[test]
    fn http_getrequest_match() {
        let fp = Fingerprints::parse(SNIPPET);
        let resp = b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n";
        let m = fp.identify(80, ProbeKind::GetRequest, resp).unwrap();
        assert_eq!(m.service, "http");
        // A NULL-probe lookup of the same bytes should not use GetRequest rules.
        assert!(fp.identify(80, ProbeKind::Null, resp).is_none());
    }
}
