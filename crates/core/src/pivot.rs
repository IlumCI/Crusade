//! What to look at next, and why.
//!
//! An analyst with one interesting host wants the same thing every time: what
//! else belongs to whoever runs this, and what else looks like it. Crusade
//! already holds every pivot that answers those — shared certificates, host
//! keys, favicons, JARM and HASSH fingerprints, screenshot templates, the
//! cluster the linker assigned, the network and the autonomous system — and
//! answering means knowing which of them is worth running. This module ranks
//! them.
//!
//! The ranking is the whole point, because most pivots are useless on most
//! hosts and uselessness has two shapes. A pivot matching only this host
//! teaches nothing: the identifier is unique, so following it is a round trip
//! to where you started. A pivot matching a large fraction of the index
//! teaches nothing either: it is a default, and "every host running nginx" is
//! not a lead. What is worth a look is in between, and the most informative is
//! the *rarest* pivot that still matches something else — the same inverse
//! document frequency reasoning that decides which identifiers may join a
//! cluster in [`crate::graph`].
//!
//! Each candidate therefore carries the count it would return, and the
//! ranking is by surprisal: `-log2(matches / index size)`, discarded at both
//! ends. A pivot is not a guess that needs a model to make — it is a query
//! whose result size is a fact the index can be asked for.
//!
//! The plan proposed a local language model planning these steps (ArachNet,
//! arXiv:2511.10611). It is not built here, and the reason is measured rather
//! than assumed: the same model class, asked for a *single* query under a
//! grammar that made malformed output impossible, got 7 of 20 ordinary
//! questions right (see `crusade_core::nlq`). A planner is a sequence of such
//! decisions, each conditioned on the last, so the error compounds. What the
//! model cannot yet do reliably, counting can do exactly.

use std::fmt;

/// A pivot worth running, with the evidence for running it.
#[derive(Debug, Clone, PartialEq)]
pub struct Pivot {
    /// The query to run.
    pub query: String,
    /// What this pivot means, in a line.
    pub reason: &'static str,
    /// Hosts it matches, including the one it came from.
    pub matches: i64,
    /// How surprising a match is, in bits: `-log2(matches / index size)`.
    pub surprisal: f32,
}

impl fmt::Display for Pivot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:<48} {:>7} host(s)  {:>5.1} bits  {}",
            self.query, self.matches, self.surprisal, self.reason
        )
    }
}

/// A candidate pivot before its result size is known.
#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    pub query: String,
    pub reason: &'static str,
}

/// Fewer matches than this and the pivot only finds where you started.
pub const MIN_MATCHES: i64 = 2;
/// A pivot matching more than this fraction of the index is a default, not a
/// lead.
pub const MAX_SHARE: f64 = 0.20;

/// Every pivot a host suggests, before counting.
///
/// Ordered by what the identifier implies rather than by expected usefulness —
/// counting decides that — so key material comes first and coarse network
/// facts last. The order only matters for ties.
/// `cluster` is the id the linker assigned this host, which lives in the
/// index rather than in the host document, so the caller supplies it.
pub fn candidates(host: &crate::Host, cluster: Option<&str>) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = Vec::new();
    let mut push = |query: String, reason: &'static str| {
        if !out.iter().any(|c| c.query == query) {
            out.push(Candidate { query, reason });
        }
    };

    if let Some(cluster) = cluster {
        push(
            format!("cluster:{cluster}"),
            "the infrastructure cluster this host was linked into",
        );
    }

    for svc in &host.services {
        if let Some(tls) = &svc.tls {
            if let Some(fp) = &tls.fingerprint_sha256 {
                push(
                    format!("ssl.cn:{fp}"),
                    "the same certificate: someone installed one key on both",
                );
            }
            if let Some(cn) = &tls.subject_cn {
                if !cn.is_empty() {
                    push(
                        format!("ssl.cn:{}", quote(cn)),
                        "the same certificate subject",
                    );
                }
            }
        }
        if let Some(ssh) = &svc.ssh {
            if let Some(key) = &ssh.host_key_sha256 {
                push(
                    format!("ssh.hostkey:{key}"),
                    "the same SSH host key: the same machine, or a copied image",
                );
            }
            if let Some(hassh) = &ssh.hassh {
                push(
                    format!("hassh:{hassh}"),
                    "the same SSH client/server algorithm set: the same build",
                );
            }
        }
        if let Some(jarm) = &svc.jarm {
            push(format!("jarm:{jarm}"), "the same TLS stack configuration");
        }
        if let Some(hash) = svc.http.as_ref().and_then(|h| h.favicon_hash) {
            push(
                format!("favicon:{hash}"),
                "the same favicon: the same application or branding",
            );
        }
        if let Some(phash) = svc.screenshot_phash {
            push(
                format!("screenshot.hash:{phash}"),
                "the same landing page: the same software or deployment",
            );
        }
        if let Some(ja4ts) = &svc.ja4ts {
            push(
                format!("ja4ts:{ja4ts}"),
                "the same responding network stack",
            );
        }
        if let (Some(product), Some(version)) = (&svc.product, &svc.version) {
            push(
                format!("product:{} version:{}", quote(product), quote(version)),
                "the same software at the same version",
            );
        }
        if let Some(ics) = &svc.ics {
            push(
                format!("ics:{}", ics.protocol),
                "the same industrial protocol",
            );
        }
    }

    for tag in &host.tags {
        if let Some(cve) = &tag.cve {
            push(
                format!("vuln:{cve}"),
                "everything else carrying this vulnerability",
            );
        }
    }

    if let Some(asn) = host.asn {
        push(format!("asn:{asn}"), "the same autonomous system");
    }
    if let std::net::IpAddr::V4(v4) = host.ip {
        let o = v4.octets();
        push(
            format!("net:{}.{}.{}.0/24", o[0], o[1], o[2]),
            "the neighbouring addresses",
        );
    }
    out
}

/// Rank counted candidates, most informative first.
///
/// `counts` is each candidate's result size, in the same order.
pub fn rank(candidates: &[Candidate], counts: &[i64], index_size: i64) -> Vec<Pivot> {
    let size = index_size.max(1) as f64;
    let cap = ((size * MAX_SHARE).ceil() as i64).max(MIN_MATCHES);
    let mut out: Vec<Pivot> = candidates
        .iter()
        .zip(counts)
        .filter(|(_, n)| **n >= MIN_MATCHES && **n <= cap)
        .map(|(c, n)| Pivot {
            query: c.query.clone(),
            reason: c.reason,
            matches: *n,
            surprisal: -((*n as f64 / size).log2()) as f32,
        })
        .collect();
    // Most surprising first; ties by the query text so the order is stable.
    out.sort_by(|a, b| {
        b.surprisal
            .total_cmp(&a.surprisal)
            .then(a.query.cmp(&b.query))
    });
    out
}

/// Quote a value containing spaces, so the query parser keeps it whole.
fn quote(value: &str) -> String {
    if value.contains(' ') {
        format!("\"{value}\"")
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HttpInfo, Service, SshInfo, Tag, TlsCert, Transport};
    use std::net::IpAddr;

    fn host() -> crate::Host {
        crate::Host::new("198.51.100.7".parse::<IpAddr>().unwrap())
    }

    fn tls_service(port: u16, fp: &str, cn: &str) -> Service {
        let mut s = Service::new(port, Transport::Tcp);
        s.tls = Some(TlsCert {
            subject_cn: Some(cn.into()),
            issuer_cn: None,
            san: Vec::new(),
            not_before: None,
            not_after: None,
            cipher: None,
            self_signed: true,
            fingerprint_sha256: Some(fp.into()),
            version: None,
        });
        s
    }

    #[test]
    fn key_material_and_fingerprints_become_pivots() {
        let mut h = host();
        h.services
            .push(tls_service(443, "aa11", "mail.example.com"));
        let mut ssh = Service::new(22, Transport::Tcp);
        ssh.ssh = Some(SshInfo {
            banner: None,
            host_key_type: None,
            host_key_sha256: Some("bb22".into()),
            kex_algorithms: Vec::new(),
            hassh: Some("cc33".into()),
        });
        h.services.push(ssh);
        h.asn = Some(64496);

        let queries: Vec<String> = candidates(&h, None).into_iter().map(|c| c.query).collect();
        assert!(queries.contains(&"ssl.cn:aa11".to_string()), "{queries:?}");
        assert!(
            queries.contains(&"ssh.hostkey:bb22".to_string()),
            "{queries:?}"
        );
        assert!(queries.contains(&"hassh:cc33".to_string()), "{queries:?}");
        assert!(queries.contains(&"asn:64496".to_string()), "{queries:?}");
        assert!(
            queries.contains(&"net:198.51.100.0/24".to_string()),
            "{queries:?}"
        );
    }

    #[test]
    fn a_value_with_spaces_is_quoted_so_it_parses() {
        let mut h = host();
        let mut svc = Service::new(80, Transport::Tcp);
        svc.product = Some("Apache httpd".into());
        svc.version = Some("2.4.50".into());
        h.services.push(svc);
        let c = candidates(&h, None);
        let q = c
            .iter()
            .find(|c| c.query.starts_with("product:"))
            .expect("a product pivot");
        let parsed = crate::query::parse(&q.query).expect("the pivot has to parse");
        assert_eq!(parsed.filters.len(), 2, "{:?}", parsed);
    }

    /// Every pivot has to be a query the parser accepts, or the whole thing
    /// is a list of strings nobody can run.
    #[test]
    fn every_pivot_parses() {
        let mut h = host();
        h.services
            .push(tls_service(443, "aa11", "a name with spaces"));
        let mut web = Service::new(8080, Transport::Tcp);
        web.http = Some(HttpInfo {
            status: None,
            title: None,
            server: None,
            favicon_hash: Some(-123456),
            headers: Default::default(),
            technologies: Vec::new(),
            security_headers: Vec::new(),
        });
        web.screenshot_phash = Some(42);
        web.jarm = Some("29d".into());
        web.ja4ts = Some("1024_2-4-8".into());
        h.services.push(web);

        h.tags.push(Tag {
            name: "cve".into(),
            cve: Some("CVE-2021-44228".into()),
            detail: None,
        });
        for c in candidates(&h, Some("c-abc123")) {
            let parsed =
                crate::query::parse(&c.query).unwrap_or_else(|e| panic!("{}: {e}", c.query));
            assert!(
                !parsed.filters.is_empty(),
                "{} parsed as free text, not a filter",
                c.query
            );
        }
    }

    /// The two shapes of useless pivot: one that finds only this host, and one
    /// that finds most of the index.
    #[test]
    fn pivots_that_teach_nothing_are_discarded() {
        let c = vec![
            Candidate {
                query: "ssl.cn:unique".into(),
                reason: "",
            },
            Candidate {
                query: "asn:everything".into(),
                reason: "",
            },
            Candidate {
                query: "jarm:useful".into(),
                reason: "",
            },
        ];
        let ranked = rank(&c, &[1, 900, 12], 1000);
        assert_eq!(ranked.len(), 1, "{ranked:?}");
        assert_eq!(ranked[0].query, "jarm:useful");
    }

    #[test]
    fn the_rarest_pivot_comes_first() {
        let c = vec![
            Candidate {
                query: "a".into(),
                reason: "",
            },
            Candidate {
                query: "b".into(),
                reason: "",
            },
            Candidate {
                query: "c".into(),
                reason: "",
            },
        ];
        let ranked = rank(&c, &[100, 3, 30], 10_000);
        let order: Vec<&str> = ranked.iter().map(|p| p.query.as_str()).collect();
        assert_eq!(order, ["b", "c", "a"]);
        // Surprisal in bits: 3 of 10,000 is about 11.7.
        assert!((ranked[0].surprisal - 11.7).abs() < 0.1, "{:?}", ranked[0]);
    }

    /// On a small index the share cap would exclude everything, so it has a
    /// floor: with 4 hosts indexed, a pivot matching 2 is still a lead.
    #[test]
    fn a_small_index_still_yields_pivots() {
        let c = vec![Candidate {
            query: "jarm:x".into(),
            reason: "",
        }];
        assert_eq!(rank(&c, &[2], 4).len(), 1);
        assert!(rank(&c, &[1], 4).is_empty());
    }

    #[test]
    fn a_host_with_nothing_distinctive_suggests_little() {
        let h = host();
        let c = candidates(&h, None);
        // Only the /24: no services, no ASN, no cluster.
        assert_eq!(c.len(), 1, "{c:?}");
        assert!(c[0].query.starts_with("net:"));
    }
}
