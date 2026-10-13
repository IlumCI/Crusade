//! Passive honeypot scoring.
//!
//! Every signal here is computed from data Crusade has *already* collected
//! (banners, SSH algorithm lists, ICS identities, port sets, ASN); scoring sends
//! nothing on the wire. Signals combine with a noisy-OR into a score in
//! `[0, 1]`, stored with its evidence so an analyst can see why a host scored.
//! Hosts at or above [`HONEYPOT_TAG_THRESHOLD`] also get a `honeypot` tag.
//!
//! Signal families (see `docs/FRONTIER.md` section 3):
//! * signature rules for default honeypot configurations (TOML rule pack);
//! * SSH banner vs. offered key-exchange algorithms: a server claiming an
//!   OpenSSH release that predates an algorithm it offers is emulating;
//! * implausible service mixes: several ICS protocols on one host, ICS next to
//!   ordinary IT services, ICS on cloud/hosting ASNs, Windows and Linux service
//!   stacks on one address;
//! * port-set likelihood under a co-occurrence model learned from the index
//!   (pairs of ports that almost never appear together elsewhere);
//! * hosts that accept connections on many ports but say nothing on them.

use std::collections::BTreeSet;

use anyhow::Context;
use crusade_core::{
    HoneypotAssessment, HoneypotEvidence, Host, PortModel, Service, Tag, Transport,
};
use serde::Deserialize;

use crate::cve::version_cmp;

/// Score at or above which a host is tagged `honeypot` (and matches
/// `honeypot:true`).
pub const HONEYPOT_TAG_THRESHOLD: f32 = 0.5;

/// Built-in signature pack, overridable by `<data dir>/honeypot-rules.toml`.
pub const BUILTIN_RULES: &str = include_str!("../rules/honeypot-rules.toml");

// ---------------------------------------------------------------------------
// Signature rules
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RuleField {
    #[serde(rename = "ssh.banner")]
    SshBanner,
    Banner,
    #[serde(rename = "http.title")]
    HttpTitle,
    #[serde(rename = "http.server")]
    HttpServer,
    #[serde(rename = "tls.subject_cn")]
    TlsSubjectCn,
    #[serde(rename = "tls.issuer_cn")]
    TlsIssuerCn,
    Ics,
    Product,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MatchKind {
    Exact,
    Contains,
    Prefix,
}

#[derive(Debug, Clone, Deserialize)]
struct Rule {
    id: String,
    honeypot: String,
    field: RuleField,
    #[serde(rename = "match")]
    kind: MatchKind,
    pattern: String,
    weight: f32,
    #[serde(default)]
    #[allow(dead_code)]
    source: String,
}

impl Rule {
    fn matches(&self, value: &str) -> bool {
        let v = value.trim().to_lowercase();
        let p = self.pattern.to_lowercase();
        match self.kind {
            MatchKind::Exact => v == p,
            MatchKind::Contains => v.contains(&p),
            MatchKind::Prefix => v.starts_with(&p),
        }
    }
}

#[derive(Deserialize)]
struct RuleFile {
    #[serde(default, rename = "rule")]
    rules: Vec<Rule>,
}

/// A parsed honeypot signature pack.
#[derive(Debug, Clone, Default)]
pub struct HoneypotRules {
    rules: Vec<Rule>,
}

impl HoneypotRules {
    /// The pack compiled into the binary.
    pub fn builtin() -> Self {
        Self::parse(BUILTIN_RULES).expect("built-in honeypot rules are valid")
    }

    /// Parse a TOML rule pack. Weights are clamped to `[0, 1)`.
    pub fn parse(toml_text: &str) -> anyhow::Result<Self> {
        let file: RuleFile = toml::from_str(toml_text).context("invalid honeypot rule pack")?;
        let rules = file
            .rules
            .into_iter()
            .map(|mut r| {
                r.weight = r.weight.clamp(0.0, 0.99);
                r
            })
            .collect();
        Ok(HoneypotRules { rules })
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

/// The values of `field` on one service.
fn field_values(svc: &Service, field: RuleField) -> Vec<&str> {
    let mut out: Vec<&str> = Vec::new();
    match field {
        RuleField::SshBanner => out.extend(svc.ssh.as_ref().and_then(|s| s.banner.as_deref())),
        RuleField::Banner => out.extend(svc.banner.as_deref()),
        RuleField::HttpTitle => out.extend(svc.http.as_ref().and_then(|h| h.title.as_deref())),
        RuleField::HttpServer => out.extend(svc.http.as_ref().and_then(|h| h.server.as_deref())),
        RuleField::TlsSubjectCn => {
            out.extend(svc.tls.as_ref().and_then(|t| t.subject_cn.as_deref()))
        }
        RuleField::TlsIssuerCn => out.extend(svc.tls.as_ref().and_then(|t| t.issuer_cn.as_deref())),
        RuleField::Product => out.extend(svc.product.as_deref()),
        RuleField::Ics => {
            if let Some(ics) = &svc.ics {
                out.extend(ics.vendor.as_deref());
                out.extend(ics.product.as_deref());
                out.extend(ics.device_id.as_deref());
                out.extend(ics.extra.iter().map(|(_, v)| v.as_str()));
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Port co-occurrence model
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Scorer
// ---------------------------------------------------------------------------

/// Key-exchange algorithms and the first OpenSSH release that offers each.
/// Only algorithms distributions are not known to backport to older releases
/// are listed (e.g. `kex-strict-*`, the Terrapin fix, is excluded for that
/// reason).
const OPENSSH_KEX_SINCE: &[(&str, &str)] = &[
    ("ecdh-sha2-nistp256", "5.7"),
    ("curve25519-sha256@libssh.org", "6.5"),
    ("diffie-hellman-group14-sha256", "7.3"),
    ("diffie-hellman-group16-sha512", "7.3"),
    ("diffie-hellman-group18-sha512", "7.3"),
    ("curve25519-sha256", "7.4"),
    ("sntrup4591761x25519-sha512@tinyssh.org", "8.0"),
    ("sntrup761x25519-sha512@openssh.com", "8.5"),
    ("sntrup761x25519-sha512", "9.9"),
    ("mlkem768x25519-sha256", "9.9"),
];

/// Ports whose presence marks an ordinary IT service stack.
const IT_PORTS: &[u16] = &[
    21, 22, 23, 25, 110, 143, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017,
];

const LINUX_MARKERS: &[&str] = &[
    "debian", "ubuntu", "raspbian", "centos", "red hat", "fedora",
];
const WINDOWS_MARKERS: &[&str] = &[
    "microsoft iis",
    "microsoft-iis",
    "microsoft-httpapi",
    "microsoft windows",
    "microsoft sql server",
    "microsoft-ds",
    "windows server",
];

/// Combines the signature pack and (optionally) port statistics into a host
/// score.
#[derive(Debug, Clone, Default)]
pub struct HoneypotScorer {
    rules: HoneypotRules,
    ports: Option<PortModel>,
    /// Weights fitted on an operator's own index, when they have any (see
    /// [`crate::calibrate`]). Without them the noisy-OR over the weights in
    /// this file applies, which is a prior rather than a measurement.
    calibration: Option<crate::calibrate::Calibration>,
}

impl HoneypotScorer {
    pub fn new(rules: HoneypotRules) -> Self {
        HoneypotScorer {
            rules,
            ports: None,
            calibration: None,
        }
    }

    /// Use fitted weights for the behavioural signals.
    pub fn with_calibration(mut self, c: crate::calibrate::Calibration) -> Self {
        self.calibration = Some(c);
        self
    }

    /// Enable the port co-occurrence signal.
    pub fn with_port_stats(mut self, stats: PortModel) -> Self {
        self.ports = Some(stats);
        self
    }

    /// Score `host` without modifying it.
    pub fn assess(&self, host: &Host) -> HoneypotAssessment {
        let mut ev: Vec<HoneypotEvidence> = Vec::new();
        self.rule_signals(host, &mut ev);
        ssh_kex_signal(host, &mut ev);
        ics_signals(host, &mut ev);
        os_contradiction_signal(host, &mut ev);
        silent_ports_signal(host, &mut ev);
        latency_signals(host, &mut ev);
        if let Some(stats) = &self.ports {
            port_pair_signal(host, stats, &mut ev);
        }
        // A rule hit is an exact artefact of known honeypot software, so it
        // keeps its own weight whatever a fit says; the behavioural signals
        // are the guesses worth replacing. When weights have been fitted, the
        // two are combined as independent evidence, which is what the
        // noisy-OR already assumes.
        let (rules_ev, behaviour_ev): (Vec<&HoneypotEvidence>, Vec<&HoneypotEvidence>) =
            ev.iter().partition(|e| e.signal.starts_with("rule:"));
        let keep_rules: f32 = rules_ev.iter().map(|e| 1.0 - e.weight).product();
        let keep_behaviour: f32 = match &self.calibration {
            Some(c) => {
                let present: Vec<f32> = crate::calibrate::FEATURES
                    .iter()
                    .map(|f| {
                        if behaviour_ev.iter().any(|e| e.signal == *f) {
                            1.0
                        } else {
                            0.0
                        }
                    })
                    .collect();
                // The fit's score at no signals at all is the index's base
                // rate, not zero, so subtracting it keeps "nothing observed"
                // meaning "no evidence".
                let base = c.score(&vec![0.0; crate::calibrate::FEATURES.len()]);
                let p = c.score(&present);
                1.0 - ((p - base) / (1.0 - base).max(1e-6)).clamp(0.0, 1.0)
            }
            None => behaviour_ev.iter().map(|e| 1.0 - e.weight).product(),
        };
        let keep = keep_rules * keep_behaviour;
        HoneypotAssessment {
            score: ((1.0 - keep) * 1000.0).round() / 1000.0,
            evidence: ev,
        }
    }

    /// Score `host`, store the assessment on it, and keep the `honeypot` tag
    /// in sync with the threshold. Safe to re-run (rescoring).
    pub fn apply(&self, host: &mut Host) {
        let a = self.assess(host);
        host.tags.retain(|t| t.name != "honeypot");
        if a.score >= HONEYPOT_TAG_THRESHOLD {
            let mut names: Vec<&str> = a.evidence.iter().map(|e| e.signal.as_str()).collect();
            names.dedup();
            host.tags.push(Tag {
                name: "honeypot".to_string(),
                cve: None,
                detail: Some(format!("score {:.2}: {}", a.score, names.join(", "))),
            });
        }
        host.honeypot = Some(a);
    }

    fn rule_signals(&self, host: &Host, ev: &mut Vec<HoneypotEvidence>) {
        for rule in &self.rules.rules {
            let hit = host.services.iter().find_map(|svc| {
                field_values(svc, rule.field)
                    .into_iter()
                    .find(|v| rule.matches(v))
                    .map(|v| (svc.port, v.to_string()))
            });
            if let Some((port, value)) = hit {
                ev.push(HoneypotEvidence {
                    signal: format!("rule:{}", rule.id),
                    weight: rule.weight,
                    detail: format!(
                        "{} default artefact on port {port}: {value:?}",
                        rule.honeypot
                    ),
                });
            }
        }
    }
}

/// `OpenSSH_6.0p1 Debian-4` -> `6.0`.
fn openssh_version(banner: &str) -> Option<String> {
    let rest = &banner[banner.find("OpenSSH_")? + "OpenSSH_".len()..];
    let v: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    (!v.is_empty()).then_some(v)
}

fn ssh_kex_signal(host: &Host, ev: &mut Vec<HoneypotEvidence>) {
    for svc in &host.services {
        let Some(ssh) = &svc.ssh else { continue };
        let Some(claimed) = ssh.banner.as_deref().and_then(openssh_version) else {
            continue;
        };
        let anachronisms: Vec<String> = OPENSSH_KEX_SINCE
            .iter()
            .filter(|(alg, since)| {
                ssh.kex_algorithms.iter().any(|k| k == alg)
                    && version_cmp(&claimed, since) == std::cmp::Ordering::Less
            })
            .map(|(alg, since)| format!("{alg} (OpenSSH {since}+)"))
            .collect();
        if !anachronisms.is_empty() {
            ev.push(HoneypotEvidence {
                signal: "ssh-kex-anachronism".to_string(),
                weight: 0.7,
                detail: format!(
                    "port {} claims OpenSSH {claimed} but offers {}",
                    svc.port,
                    anachronisms.join(", ")
                ),
            });
            return;
        }
    }
}

fn ics_signals(host: &Host, ev: &mut Vec<HoneypotEvidence>) {
    let protocols: BTreeSet<String> = host
        .services
        .iter()
        .filter_map(|s| s.ics.as_ref().map(|i| i.protocol.to_lowercase()))
        .collect();
    if protocols.is_empty() {
        return;
    }
    let list = protocols.iter().cloned().collect::<Vec<_>>().join(", ");
    if protocols.len() >= 3 {
        ev.push(HoneypotEvidence {
            signal: "ics-multi-protocol".to_string(),
            weight: 0.6,
            detail: format!("{} ICS protocols on one address: {list}", protocols.len()),
        });
    } else if protocols.len() == 2 {
        ev.push(HoneypotEvidence {
            signal: "ics-multi-protocol".to_string(),
            weight: 0.25,
            detail: format!("2 ICS protocols on one address: {list}"),
        });
    }

    let it: BTreeSet<u16> = host
        .services
        .iter()
        .filter(|s| s.ics.is_none() && IT_PORTS.contains(&s.port))
        .map(|s| s.port)
        .collect();
    if it.len() >= 3 {
        ev.push(HoneypotEvidence {
            signal: "ics-with-it-stack".to_string(),
            weight: 0.25,
            detail: format!("ICS ({list}) alongside IT services on ports {it:?}"),
        });
    }

    if let Some((asn, name)) = host
        .asn
        .and_then(|a| crusade_core::cloud_asn(a).map(|name| (a, name)))
    {
        ev.push(HoneypotEvidence {
            signal: "ics-on-cloud".to_string(),
            weight: 0.4,
            detail: format!("ICS ({list}) hosted on AS{asn} ({name})"),
        });
    }
}

/// Lower-cased text a service reveals about its platform.
fn platform_text(svc: &Service) -> String {
    let mut parts: Vec<&str> = Vec::new();
    parts.extend(svc.product.as_deref());
    parts.extend(svc.version.as_deref());
    parts.extend(svc.ssh.as_ref().and_then(|s| s.banner.as_deref()));
    parts.extend(svc.http.as_ref().and_then(|h| h.server.as_deref()));
    if svc.ssh.is_none() {
        parts.extend(
            svc.banner
                .as_deref()
                .map(|b| b.lines().next().unwrap_or("")),
        );
    }
    parts.join(" ").to_lowercase()
}

fn os_contradiction_signal(host: &Host, ev: &mut Vec<HoneypotEvidence>) {
    let mut linux: Option<(u16, &str)> = None;
    let mut windows: Option<(u16, &str)> = None;
    for svc in &host.services {
        let text = platform_text(svc);
        if linux.is_none() {
            linux = LINUX_MARKERS
                .iter()
                .find(|m| text.contains(*m))
                .map(|m| (svc.port, *m));
        }
        if windows.is_none() {
            windows = WINDOWS_MARKERS
                .iter()
                .find(|m| text.contains(*m))
                .map(|m| (svc.port, *m));
        }
    }
    if let (Some((lp, lm)), Some((wp, wm))) = (linux, windows) {
        if lp != wp {
            ev.push(HoneypotEvidence {
                signal: "os-contradiction".to_string(),
                weight: 0.35,
                detail: format!("port {lp} reports {lm:?}, port {wp} reports {wm:?}"),
            });
        }
    }
}

/// Many open TCP ports that never identify themselves: tarpits, middleboxes
/// and low-interaction honeypots that accept every connection (LZR,
/// Izhikevich et al., USENIX Security 2021).
fn silent_ports_signal(host: &Host, ev: &mut Vec<HoneypotEvidence>) {
    let tcp: Vec<&Service> = host
        .services
        .iter()
        .filter(|s| s.transport == Transport::Tcp)
        .collect();
    if tcp.len() < 16 {
        return;
    }
    let silent = tcp
        .iter()
        .filter(|s| {
            s.banner.as_deref().is_none_or(|b| b.trim().is_empty())
                && s.product.is_none()
                && s.http.is_none()
                && s.tls.is_none()
                && s.ssh.is_none()
                && s.ics.is_none()
        })
        .count();
    if silent * 2 >= tcp.len() {
        ev.push(HoneypotEvidence {
            signal: "accepts-everything".to_string(),
            weight: 0.45,
            detail: format!("{} open TCP ports, {silent} return no data", tcp.len()),
        });
    }
}

/// Minimum answer-to-round-trip ratio counted as the service thinking rather
/// than the network being slow. Three round trips covers a fork, a TLS
/// handshake behind a proxy and an unlucky scheduler.
const SLOW_RATIO: f32 = 5.0;
/// Below this there is no room for inference whatever the ratio says: a 20 ms
/// answer on a 2 ms link is process startup, not a language model. The floor
/// matters more than the ratio, because the ratio is unbounded on fast links.
const SLOW_FLOOR_MS: u32 = 250;
/// Coefficient of variation above which a service's answer time is erratic.
///
/// The question this threshold answers is "does the answer time vary more
/// than the network can explain". Jitter on a stable path is a small
/// fraction of the round trip, so a standard deviation of 40% of the mean is
/// already far outside it — while generated text, whose duration follows how
/// much the model chose to produce, routinely swings by a factor of several.
/// The gap between those two regimes is wide, which is why the threshold does
/// not have to be precise.
const JITTER_CV: f32 = 0.40;

/// Time-to-answer and its variability.
///
/// This is the signal the current generation of honeypots cannot remove. A
/// honeypot that generates its banners with a language model defeats every
/// signature in the rule pack — the banner is novel, plausible and
/// inconsistent with nothing — but it has to run inference before it can
/// answer, and inference is slow and variable in a way that writing a
/// constant string is not (arXiv:2502.20589; LLM honeypots arXiv:2309.00155,
/// 2409.08234, 2405.05999).
///
/// Both halves are needed. Latency alone flags a loaded server; jitter alone
/// flags a congested path. Neither is weighted as heavily as a rule hit,
/// because a real service under real load does look like this — which is why
/// the detail says what was measured, so the judgement can be checked.
fn latency_signals(host: &Host, ev: &mut Vec<HoneypotEvidence>) {
    let mut slow: Vec<String> = Vec::new();
    let mut erratic: Vec<String> = Vec::new();
    for svc in &host.services {
        let Some(l) = &svc.latency else { continue };
        if l.banner_ms >= SLOW_FLOOR_MS && l.ratio() >= SLOW_RATIO {
            slow.push(format!(
                "port {}: {} ms to answer on a {} ms round trip ({:.0}x)",
                svc.port,
                l.banner_ms,
                l.connect_ms.max(1),
                l.ratio()
            ));
        }
        if let Some(cv) = l.jitter() {
            if cv >= JITTER_CV {
                erratic.push(format!(
                    "port {}: answer time varies by {:.0}% over {} scans",
                    svc.port,
                    cv * 100.0,
                    l.samples
                ));
            }
        }
    }
    if !slow.is_empty() {
        ev.push(HoneypotEvidence {
            signal: "slow-to-answer".to_string(),
            weight: 0.35,
            detail: format!(
                "answering takes far longer than reaching it, as generating a \
                 reply would: {}",
                slow.join("; ")
            ),
        });
    }
    if !erratic.is_empty() {
        ev.push(HoneypotEvidence {
            signal: "erratic-answer-time".to_string(),
            weight: 0.40,
            detail: format!(
                "a constant banner takes the same time every scan; this does not: {}",
                erratic.join("; ")
            ),
        });
    }
}

fn port_pair_signal(host: &Host, stats: &PortModel, ev: &mut Vec<HoneypotEvidence>) {
    let ports: Vec<u16> = host
        .services
        .iter()
        .filter(|s| s.transport == Transport::Tcp)
        .map(|s| s.port)
        .collect();
    let pairs = stats.implausible_pairs(&ports);
    if pairs.len() < 2 {
        return;
    }
    let weight = (0.3 + 0.05 * (pairs.len() - 2) as f32).min(0.5);
    let shown: Vec<String> = pairs
        .iter()
        .take(6)
        .map(|(a, b)| format!("{a}+{b}"))
        .collect();
    ev.push(HoneypotEvidence {
        signal: "implausible-port-set".to_string(),
        weight,
        detail: format!(
            "{} port pairs rarely co-occur across {} indexed hosts: {}",
            pairs.len(),
            stats.hosts(),
            shown.join(", ")
        ),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calibrate as crusade_vuln_calibrate;
    use crusade_core::{IcsInfo, SshInfo};
    use std::net::IpAddr;

    fn host() -> Host {
        Host::new("198.51.100.7".parse::<IpAddr>().unwrap())
    }

    fn ssh_service(port: u16, banner: &str, kex: &[&str]) -> Service {
        let mut s = Service::new(port, Transport::Tcp);
        s.product = Some("OpenSSH".into());
        s.ssh = Some(SshInfo {
            banner: Some(banner.into()),
            host_key_type: None,
            host_key_sha256: None,
            kex_algorithms: kex.iter().map(|k| k.to_string()).collect(),
            hassh: None,
        });
        s
    }

    fn ics_service(port: u16, proto: &str) -> Service {
        let mut s = Service::new(port, Transport::Tcp);
        s.ics = Some(IcsInfo::new(proto));
        s
    }

    fn timed_service(port: u16, connect_ms: u32, banner_ms: &[u32]) -> Service {
        let mut s = Service::new(port, Transport::Tcp);
        s.banner = Some("SSH-2.0-OpenSSH_9.6".into());
        let mut l = crusade_core::Latency::observe(connect_ms, banner_ms[0]);
        for ms in &banner_ms[1..] {
            l.accumulate(connect_ms, *ms);
        }
        s.latency = Some(l);
        s
    }

    /// A real daemon on a slow link: 300 ms to answer, but 280 ms of that is
    /// the distance. Nothing to see.
    #[test]
    fn a_distant_but_honest_service_is_not_flagged() {
        let mut h = host();
        h.services
            .push(timed_service(22, 280, &[300, 305, 295, 302]));
        let a = HoneypotScorer::new(HoneypotRules::builtin()).assess(&h);
        assert!(
            !a.evidence
                .iter()
                .any(|e| e.signal.contains("answer") || e.signal.contains("slow")),
            "{:?}",
            a.evidence
        );
    }

    /// Inference before answering: two orders of magnitude over the round
    /// trip, and a different duration every scan.
    #[test]
    fn a_generated_answer_shows_in_time_and_variance() {
        let mut h = host();
        h.services
            .push(timed_service(22, 11, &[900, 2600, 500, 1800, 1200]));
        let a = HoneypotScorer::new(HoneypotRules::builtin()).assess(&h);
        let signals: Vec<&str> = a.evidence.iter().map(|e| e.signal.as_str()).collect();
        assert!(signals.contains(&"slow-to-answer"), "{signals:?}");
        assert!(signals.contains(&"erratic-answer-time"), "{signals:?}");
        assert!(a.score > 0.5, "{}", a.score);
    }

    /// A fast link makes the ratio enormous for a delay far too short to be
    /// inference. The absolute floor is what stops that being a finding.
    #[test]
    fn a_short_delay_on_a_fast_link_is_not_inference() {
        let mut h = host();
        h.services.push(timed_service(22, 1, &[30, 30, 31, 29]));
        let a = HoneypotScorer::new(HoneypotRules::builtin()).assess(&h);
        assert!(
            !a.evidence.iter().any(|e| e.signal == "slow-to-answer"),
            "{:?}",
            a.evidence
        );
    }

    /// Slow but consistent is load, not generation, so only the latency
    /// signal fires and the score stays below the tagging threshold.
    #[test]
    fn a_consistently_slow_service_is_weaker_evidence() {
        let mut h = host();
        h.services
            .push(timed_service(22, 10, &[800, 810, 795, 805, 802]));
        let a = HoneypotScorer::new(HoneypotRules::builtin()).assess(&h);
        let signals: Vec<&str> = a.evidence.iter().map(|e| e.signal.as_str()).collect();
        assert!(signals.contains(&"slow-to-answer"), "{signals:?}");
        assert!(!signals.contains(&"erratic-answer-time"), "{signals:?}");
        assert!(a.score < HONEYPOT_TAG_THRESHOLD, "{}", a.score);
    }

    /// Fitted weights must replace the behavioural guesses without touching
    /// the rule hits, which are exact artefacts rather than inferences.
    #[test]
    fn a_calibration_replaces_only_the_behavioural_weights() {
        use crusade_vuln_calibrate::Calibration;
        let mut h = host();
        h.services
            .push(timed_service(22, 10, &[900, 2600, 500, 1800, 1200]));
        let plain = HoneypotScorer::new(HoneypotRules::builtin()).assess(&h);
        assert!(plain.score > 0.0);

        // A fit that says the behavioural signals mean nothing.
        let flat = Calibration {
            weights: vec![0.0; crusade_vuln_calibrate::FEATURES.len()],
            bias: -1.0,
            hosts: 500,
            labelled: 100,
            auc: 0.8,
        };
        let scored = HoneypotScorer::new(HoneypotRules::builtin())
            .with_calibration(flat)
            .assess(&h);
        assert_eq!(
            scored.score, 0.0,
            "weights of zero should leave no behavioural evidence: {:?}",
            scored.evidence
        );
        assert!(
            !scored.evidence.is_empty(),
            "the evidence is still reported, only its weight changed"
        );

        // A fit that says they mean a great deal.
        let strong = Calibration {
            weights: vec![6.0; crusade_vuln_calibrate::FEATURES.len()],
            bias: -6.0,
            hosts: 500,
            labelled: 100,
            auc: 0.9,
        };
        let scored = HoneypotScorer::new(HoneypotRules::builtin())
            .with_calibration(strong)
            .assess(&h);
        assert!(
            scored.score > plain.score,
            "{} vs {}",
            scored.score,
            plain.score
        );
    }

    #[test]
    fn builtin_rules_parse() {
        assert!(HoneypotRules::builtin().len() >= 5);
    }

    #[test]
    fn clean_host_scores_zero() {
        let mut h = host();
        h.services.push(ssh_service(
            22,
            "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5",
            &["curve25519-sha256", "sntrup761x25519-sha512@openssh.com"],
        ));
        let s = HoneypotScorer::new(HoneypotRules::builtin());
        let a = s.assess(&h);
        assert_eq!(a.score, 0.0);
        assert!(a.evidence.is_empty());
    }

    #[test]
    fn cowrie_default_banner_with_modern_kex() {
        let mut h = host();
        h.services.push(ssh_service(
            22,
            "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2",
            &["curve25519-sha256", "diffie-hellman-group14-sha1"],
        ));
        let scorer = HoneypotScorer::new(HoneypotRules::builtin());
        scorer.apply(&mut h);
        let a = h.honeypot.as_ref().unwrap();
        let sigs: Vec<&str> = a.evidence.iter().map(|e| e.signal.as_str()).collect();
        assert_eq!(sigs, vec!["rule:cowrie-default-ssh", "ssh-kex-anachronism"]);
        // 1 - (0.4 * 0.3)
        assert!((a.score - 0.88).abs() < 1e-3, "{}", a.score);
        assert!(h.tags.iter().any(|t| t.name == "honeypot"));
    }

    #[test]
    fn kex_check_respects_release_order() {
        let mut ok = host();
        ok.services.push(ssh_service(
            22,
            "SSH-2.0-OpenSSH_7.4",
            &["curve25519-sha256", "diffie-hellman-group16-sha512"],
        ));
        let mut bad = host();
        bad.services.push(ssh_service(
            22,
            "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10",
            &["curve25519-sha256"],
        ));
        let s = HoneypotScorer::default();
        assert!(s.assess(&ok).evidence.is_empty());
        assert_eq!(s.assess(&bad).evidence[0].signal, "ssh-kex-anachronism");
    }

    #[test]
    fn conpot_defaults_and_ics_mix() {
        let mut h = host();
        h.asn = Some(14061);
        let mut s7 = ics_service(102, "s7");
        s7.ics.as_mut().unwrap().device_id = Some("Technodrome".into());
        s7.ics
            .as_mut()
            .unwrap()
            .extra
            .push(("component_0x0003".into(), "Mouser Factory".into()));
        h.services.push(s7);
        h.services.push(ics_service(502, "modbus"));
        h.services.push(ics_service(47808, "bacnet"));
        let a = HoneypotScorer::new(HoneypotRules::builtin()).assess(&h);
        let sigs: Vec<&str> = a.evidence.iter().map(|e| e.signal.as_str()).collect();
        assert!(sigs.contains(&"rule:conpot-s7-system-name"));
        assert!(sigs.contains(&"rule:conpot-s7-plant-id"));
        assert!(sigs.contains(&"ics-multi-protocol"));
        assert!(sigs.contains(&"ics-on-cloud"));
        assert!(a.score > 0.99);
    }

    #[test]
    fn os_contradiction_needs_two_services() {
        let mut h = host();
        h.services.push(ssh_service(
            22,
            "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3",
            &[],
        ));
        let mut iis = Service::new(80, Transport::Tcp);
        iis.product = Some("Microsoft IIS httpd".into());
        h.services.push(iis);
        let a = HoneypotScorer::default().assess(&h);
        assert_eq!(a.evidence.len(), 1);
        assert_eq!(a.evidence[0].signal, "os-contradiction");
        assert!(a.score < HONEYPOT_TAG_THRESHOLD);
    }

    #[test]
    fn silent_ports() {
        let mut h = host();
        for p in 1000..1020 {
            h.services.push(Service::new(p, Transport::Tcp));
        }
        let a = HoneypotScorer::default().assess(&h);
        assert_eq!(a.evidence[0].signal, "accepts-everything");
    }

    #[test]
    fn port_stats_flag_rare_pairs_only_with_enough_data() {
        // 300 web hosts (80+443), 100 ssh hosts (22), 30 s7 hosts (102).
        let mut sets: Vec<Vec<u16>> = Vec::new();
        sets.extend(std::iter::repeat_n(vec![80, 443], 300));
        sets.extend(std::iter::repeat_n(vec![22], 100));
        sets.extend(std::iter::repeat_n(vec![102], 30));
        let stats = PortModel::from_port_sets(&sets);
        assert_eq!(stats.hosts(), 430);
        assert!(stats.implausible_pairs(&[80, 443]).is_empty());
        assert_eq!(stats.implausible_pairs(&[22, 102, 443]).len(), 3);

        let small = PortModel::from_port_sets(&sets[..50]);
        assert!(small.implausible_pairs(&[22, 102]).is_empty());

        let mut h = host();
        for p in [22, 102, 443] {
            h.services.push(Service::new(p, Transport::Tcp));
        }
        let a = HoneypotScorer::default().with_port_stats(stats).assess(&h);
        assert_eq!(a.evidence[0].signal, "implausible-port-set");
    }

    #[test]
    fn rescoring_replaces_tag() {
        let mut h = host();
        h.tags.push(Tag::simple("honeypot"));
        HoneypotScorer::default().apply(&mut h);
        assert!(h.tags.iter().all(|t| t.name != "honeypot"));
        assert_eq!(h.honeypot.as_ref().unwrap().score, 0.0);
    }

    #[test]
    fn rule_pack_override_parses() {
        let pack = r#"
            [[rule]]
            id = "x"
            honeypot = "Test"
            field = "http.title"
            match = "contains"
            pattern = "Honey"
            weight = 1.5
        "#;
        let rules = HoneypotRules::parse(pack).unwrap();
        assert_eq!(rules.len(), 1);
        let mut h = host();
        let mut s = Service::new(80, Transport::Tcp);
        s.http = Some(crusade_core::HttpInfo {
            status: Some(200),
            server: None,
            title: Some("My honeyPOT".into()),
            headers: vec![],
            favicon_hash: None,
            technologies: vec![],
            security_headers: vec![],
        });
        h.services.push(s);
        let a = HoneypotScorer::new(rules).assess(&h);
        assert_eq!(a.evidence[0].weight, 0.99);
    }
}
