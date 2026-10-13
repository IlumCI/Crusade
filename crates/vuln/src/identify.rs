//! Naming the software behind a banner that fingerprinting could not place.
//!
//! `nmap-service-probes` is 12,000 hand-written patterns and it is still a
//! fixed list: a banner it has no rule for yields no product, and no product
//! means no CVE, no `product:` filter and a host that shows up as an open port
//! and nothing else. That is the gap the plan proposed closing with a small
//! encoder (~22M parameters, arXiv:2404.00056).
//!
//! This module closes part of it without a model, because the pieces were
//! already here. [`crate::resolve`] matches a product *name* against the
//! `(vendor, product)` pairs the indexed CVE rules use — 121,603 of them, which
//! is a far larger vocabulary of real software names than any fingerprint list
//! — and a banner usually contains its product's name somewhere structural: in
//! a `Server:` header, after `SSH-2.0-`, in an FTP or SMTP greeting. So the
//! work is to pull the candidate names out of the banner's structure and let
//! resolution judge them.
//!
//! The bar is deliberately higher here than for resolving a name that
//! fingerprinting already produced. There, the name is known to be software and
//! the only question is what NVD calls it; here the question is whether this
//! fragment of text names software at all, and a wrong answer attaches someone
//! else's CVEs to a host. So the fuzzy tier is refused outright and only an
//! exact or rarity-weighted lexical match is accepted.
//!
//! Whether a neural encoder would do better is untested and stays that way
//! until there is labelled scan data to test it on: a 22M-parameter model
//! shipped on the strength of a paper's F1, with no measurement on this
//! index's banners, is a 22M-parameter guess. What this module does is
//! measurable today — `cargo run --example identify_precision` scores it
//! against nmap's own corpus — and it costs nothing to carry.

use crate::resolve::{ProductVocab, Resolution, Tier};

/// Longest banner prefix examined. A product names itself early; past this it
/// is page content, and page content is where false positives come from.
const SCAN_CHARS: usize = 400;

/// Header-ish fields whose value is a product name by convention.
const NAME_HEADERS: &[&str] = &[
    "server:",
    "x-powered-by:",
    "www-authenticate:",
    "x-generator:",
    "x-application-context:",
];

/// Words that appear where a product name would and are not one.
const NOT_NAMES: &[&str] = &[
    "http",
    "https",
    "ftp",
    "smtp",
    "ssh",
    "ready",
    "service",
    "server",
    "welcome",
    "login",
    "unauthorized",
    "forbidden",
    "basic",
    "realm",
    "ok",
    "error",
    "connection",
    "localhost",
    "unknown",
    "none",
    "null",
    "true",
    "false",
    "esmtp",
    "ftpd",
    "smtpd",
    "imapd",
    "pop3d",
];

/// Candidate product names in a banner, best-placed first.
///
/// Each comes from somewhere a product conventionally names itself, which is
/// what keeps this from being a search over every word in an HTML page.
pub fn candidate_names(banner: &str) -> Vec<String> {
    let head: String = banner.chars().take(SCAN_CHARS).collect();
    let mut out: Vec<String> = Vec::new();
    fn push(out: &mut Vec<String>, raw: &str) {
        let name = clean(raw);
        if name.is_empty() || NOT_NAMES.contains(&name.to_ascii_lowercase().as_str()) {
            return;
        }
        if !out.iter().any(|e| e.eq_ignore_ascii_case(&name)) {
            out.push(name);
        }
    }

    for line in head.lines() {
        let lower = line.to_ascii_lowercase();
        // `Server: nginx/1.18.0` and friends.
        if let Some(header) = NAME_HEADERS.iter().find(|h| lower.starts_with(**h)) {
            push(&mut out, &line[header.len()..]);
            continue;
        }
        // `SSH-2.0-OpenSSH_9.6p1 Debian-4`: the product is after the second
        // dash, and the suffix after `_` is a version.
        if let Some(rest) = line.strip_prefix("SSH-").and_then(|r| r.split_once('-')) {
            push(&mut out, rest.1.split('_').next().unwrap_or(rest.1));
            push(&mut out, rest.1);
            continue;
        }
        // A numeric-code greeting: `220 ProFTPD 1.3.5 Server ready`, or
        // `220 mail.example.com ESMTP Postfix (Debian)`.
        if let Some(rest) = line
            .split_once(' ')
            .filter(|(code, _)| code.len() == 3 && code.chars().all(|c| c.is_ascii_digit()))
            .map(|(_, rest)| rest)
        {
            for word in rest.split_whitespace().take(6) {
                push(&mut out, word);
            }
            continue;
        }
    }

    // Whatever the banner opens with, when nothing structural matched: a
    // server-first banner is usually its own name.
    if out.is_empty() {
        for word in head.split_whitespace().take(4) {
            push(&mut out, word);
        }
    }
    out
}

/// Strip decoration from a candidate name.
///
/// Versions, parenthesised build notes and trailing punctuation all go: the
/// vocabulary holds names, and the version is matched separately by the CVE
/// rules.
fn clean(raw: &str) -> String {
    let mut s = raw.trim();
    // Drop a parenthesised aside: `Postfix (Debian/GNU)`.
    if let Some(at) = s.find('(') {
        s = s[..at].trim_end();
    }
    // Drop everything from the first `/` or `_`, which separate name from
    // version in nearly every banner convention.
    let s = s
        .split(['/', '_'])
        .next()
        .unwrap_or(s)
        .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '.' && c != ' ');
    // A trailing bare version number is not part of the name.
    let words: Vec<&str> = s
        .split_whitespace()
        .take_while(|w| {
            !w.chars()
                .next()
                .is_some_and(|c| c.is_ascii_digit() && w.contains('.'))
        })
        .collect();
    words.join(" ").trim().to_string()
}

/// Name the software a banner describes, or nothing.
///
/// Only the exact and lexical tiers are accepted: see the module doc on why
/// the bar is higher here than for a name fingerprinting already produced.
pub fn identify(banner: &str, vocab: &ProductVocab) -> Option<Resolution> {
    let mut best: Option<Resolution> = None;
    for name in candidate_names(banner) {
        let Some(r) = vocab.resolve(&name) else {
            continue;
        };
        if !matches!(r.tier, Tier::Exact | Tier::Lexical) {
            continue;
        }
        if best.as_ref().is_none_or(|b| r.score > b.score) {
            best = Some(r);
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolve::Candidate;

    fn cand(vendor: &str, product: &str) -> Candidate {
        Candidate {
            vendor: vendor.into(),
            product: product.into(),
            rules: 10,
        }
    }

    fn vocab() -> ProductVocab {
        ProductVocab::new(vec![
            cand("f5", "nginx"),
            cand("apache", "http_server"),
            cand("apache", "tomcat"),
            cand("openbsd", "openssh"),
            cand("postfix", "postfix"),
            cand("proftpd", "proftpd"),
            cand("microsoft", "internet_information_services"),
            cand("isc", "bind"),
            cand("dovecot", "dovecot"),
            cand("lighttpd", "lighttpd"),
            cand("redis", "redis"),
            cand("mysql", "mysql"),
        ])
    }

    #[test]
    fn a_server_header_names_the_product() {
        let r = identify("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n", &vocab()).unwrap();
        assert_eq!(r.product, "nginx");
    }

    #[test]
    fn an_ssh_banner_names_the_product() {
        let r = identify("SSH-2.0-OpenSSH_9.6p1 Debian-4\r\n", &vocab()).unwrap();
        assert_eq!(r.product, "openssh");
    }

    #[test]
    fn a_greeting_names_the_product() {
        let r = identify(
            "220 ProFTPD 1.3.5 Server (Debian) [::ffff:10.0.0.1]",
            &vocab(),
        )
        .unwrap();
        assert_eq!(r.product, "proftpd");
        let r = identify("220 mail.example.com ESMTP Postfix (Debian/GNU)", &vocab()).unwrap();
        assert_eq!(r.product, "postfix");
    }

    /// The failure that matters: a banner naming no software must produce no
    /// product, because a wrong one attaches someone else's CVEs.
    #[test]
    fn a_banner_naming_no_software_identifies_nothing() {
        assert!(identify("HTTP/1.1 401 Unauthorized\r\n\r\n", &vocab()).is_none());
        assert!(identify("+OK ready\r\n", &vocab()).is_none());
        assert!(identify("", &vocab()).is_none());
        assert!(identify("\x00\x01\x02\x03binary garbage", &vocab()).is_none());
    }

    /// Only the strong tiers count here. `httpd` reaches `http_server`
    /// through the fuzzy tier, which is good enough to resolve a name
    /// fingerprinting produced and not good enough to invent one.
    #[test]
    fn the_fuzzy_tier_is_refused_for_identification() {
        let v = vocab();
        assert_eq!(
            v.resolve("Apache httpd").map(|r| r.tier),
            Some(Tier::Fuzzy),
            "precondition: this name only resolves fuzzily"
        );
        assert!(identify("Server: httpd\r\n", &v).is_none());
    }

    #[test]
    fn version_decoration_is_not_part_of_the_name() {
        assert_eq!(clean("nginx/1.18.0"), "nginx");
        assert_eq!(clean("Postfix (Debian/GNU)"), "Postfix");
        assert_eq!(clean("OpenSSH_9.6p1"), "OpenSSH");
        assert_eq!(clean("ProFTPD 1.3.5"), "ProFTPD");
        assert_eq!(clean("Microsoft-IIS/10.0"), "Microsoft-IIS");
    }

    /// Page content is where false positives live, so only the head of a
    /// banner is examined.
    #[test]
    fn only_the_head_of_a_banner_is_examined() {
        let mut banner = String::from("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n");
        banner.push_str(&"x".repeat(SCAN_CHARS));
        banner.push_str("\r\nServer: nginx\r\n");
        assert!(identify(&banner, &vocab()).is_none());
    }
}
