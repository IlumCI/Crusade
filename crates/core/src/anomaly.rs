//! Finding the hosts that do not look like the others.
//!
//! An index of a million hosts is mostly web servers, and reading it top to
//! bottom tells you nothing. What is worth an analyst's attention is the host
//! that is *unlike* its population: the one running an industrial protocol in
//! a datacentre, the database open to the world next to a thousand closed
//! ones, the odd combination nobody deploys on purpose.
//!
//! Rather than train a model, this scores hosts by **surprisal**. Each feature
//! a host presents (a port, a product, a tag, an auth posture) occurs in some
//! fraction `p` of the population; observing it carries `-log2(p)` bits of
//! information. A host's score is the total over its features, so a host built
//! entirely from common parts scores low however many parts it has, and one
//! rare feature can lift a host on its own.
//!
//! Two properties matter more here than raw accuracy:
//!
//! * **It explains itself.** The score decomposes exactly into per-feature
//!   contributions, so the output is "unusual *because* port 102 appears on
//!   0.01% of hosts" rather than a number from a black box. An unexplained
//!   anomaly score is not actionable.
//! * **It needs no training.** The population *is* the model, so it works on
//!   the operator's own index from the first scan, and cannot drift away from
//!   the data it describes.
//!
//! Sarabi & Liu (*Characterizing the Internet Host Population Using Deep
//! Learning*, IMC 2018) take the learned route — a VAE over binary tags — and
//! get compact embeddings. That is the better basis for clustering; for "show
//! me what is weird, and say why", surprisal is both cheaper and clearer.

use std::collections::BTreeMap;

use crate::model::{AuthState, Host, Transport};

/// One observable property of a host.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Feature {
    /// An open port, with its transport.
    Port(u16, &'static str),
    /// A product name, lower-cased.
    Product(String),
    /// A tag the host carries.
    Tag(String),
    /// An industrial protocol.
    Ics(String),
    /// A service reachable without credentials.
    OpenAuth,
    /// Unusually many services for one host.
    ManyServices(u8),
}

impl Feature {
    /// A short description, for explaining a score.
    pub fn describe(&self) -> String {
        match self {
            Feature::Port(p, t) => format!("port {p}/{t}"),
            Feature::Product(p) => format!("product {p}"),
            Feature::Tag(t) => format!("tag {t}"),
            Feature::Ics(p) => format!("ICS protocol {p}"),
            Feature::OpenAuth => "reachable without credentials".to_string(),
            Feature::ManyServices(n) => format!("{}+ services on one host", 1u16 << n),
        }
    }
}

/// Everything observable about one host, as features.
///
/// Deliberately coarse: counts and exact versions would make almost every
/// host unique, which would score them all as anomalous and say nothing.
pub fn features(host: &Host) -> Vec<Feature> {
    let mut out: Vec<Feature> = Vec::new();
    for svc in &host.services {
        let transport = match svc.transport {
            Transport::Tcp => "tcp",
            Transport::Udp => "udp",
        };
        out.push(Feature::Port(svc.port, transport));
        if let Some(product) = &svc.product {
            out.push(Feature::Product(product.to_lowercase()));
        }
        if let Some(ics) = &svc.ics {
            out.push(Feature::Ics(ics.protocol.to_lowercase()));
        }
        if svc.auth == Some(AuthState::Open) {
            out.push(Feature::OpenAuth);
        }
    }
    for tag in &host.tags {
        // CVE ids would make every host unique; the fact of a vuln tag is the
        // feature, not which CVE it was.
        out.push(Feature::Tag(tag.name.to_lowercase()));
    }
    // Service count bucketed by powers of two, so "lots of ports" is a feature
    // without every exact count being its own.
    let count = host.services.len();
    if count >= 8 {
        let bucket = (usize::BITS - 1 - count.leading_zeros()) as u8;
        out.push(Feature::ManyServices(bucket));
    }
    out.sort();
    out.dedup();
    out
}

/// How common each feature is across a population of hosts.
#[derive(Debug, Clone, Default)]
pub struct Population {
    hosts: u64,
    counts: BTreeMap<Feature, u64>,
}

impl Population {
    /// Minimum hosts before scores are meaningful. Below this almost
    /// everything looks rare.
    pub const MIN_HOSTS: u64 = 50;

    /// Learn from an iterator of hosts' features.
    pub fn from_feature_sets<I>(sets: I) -> Self
    where
        I: IntoIterator<Item = Vec<Feature>>,
    {
        let mut pop = Population::default();
        for set in sets {
            pop.hosts += 1;
            for f in set {
                *pop.counts.entry(f).or_default() += 1;
            }
        }
        pop
    }

    /// Learn directly from hosts.
    pub fn from_hosts<'a, I: IntoIterator<Item = &'a Host>>(hosts: I) -> Self {
        Population::from_feature_sets(hosts.into_iter().map(features))
    }

    pub fn hosts(&self) -> u64 {
        self.hosts
    }

    pub fn is_usable(&self) -> bool {
        self.hosts >= Self::MIN_HOSTS
    }

    /// Distinct features seen.
    pub fn distinct_features(&self) -> usize {
        self.counts.len()
    }

    /// How many hosts carry `feature`.
    pub fn support(&self, feature: &Feature) -> u64 {
        self.counts.get(feature).copied().unwrap_or(0)
    }

    /// Information content of observing `feature`, in bits.
    ///
    /// A feature on every host carries no information (0 bits); a feature on
    /// one host in a thousand carries about 10. Laplace smoothing keeps a
    /// feature absent from the population finite rather than infinite, since a
    /// single unseen value should not dominate a score outright.
    pub fn surprisal(&self, feature: &Feature) -> f64 {
        let p = (self.support(feature) as f64 + 0.5) / (self.hosts as f64 + 1.0);
        -p.log2()
    }
}

/// Why a host scored as it did.
#[derive(Debug, Clone, PartialEq)]
pub struct Anomaly {
    /// Total surprisal in bits.
    pub score: f64,
    /// Per-feature contributions, largest first.
    pub contributions: Vec<(Feature, f64)>,
}

impl Anomaly {
    /// The handful of reasons worth showing.
    pub fn top_reasons(&self, n: usize) -> Vec<String> {
        self.contributions
            .iter()
            .take(n)
            .map(|(f, bits)| format!("{} ({bits:.1} bits)", f.describe()))
            .collect()
    }
}

/// Score one host against a population.
///
/// Returns `None` when the population is too small to judge against, rather
/// than emitting scores nobody should act on.
pub fn score(host: &Host, population: &Population) -> Option<Anomaly> {
    if !population.is_usable() {
        return None;
    }
    let mut contributions: Vec<(Feature, f64)> = features(host)
        .into_iter()
        .map(|f| {
            let bits = population.surprisal(&f);
            (f, bits)
        })
        .collect();
    contributions.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
    Some(Anomaly {
        score: contributions.iter().map(|(_, b)| *b).sum(),
        contributions,
    })
}

/// A change between two observations of the same host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    Appeared(Feature),
    Disappeared(Feature),
}

impl Change {
    pub fn describe(&self) -> String {
        match self {
            Change::Appeared(f) => format!("gained {}", f.describe()),
            Change::Disappeared(f) => format!("lost {}", f.describe()),
        }
    }

    fn feature(&self) -> &Feature {
        match self {
            Change::Appeared(f) | Change::Disappeared(f) => f,
        }
    }
}

/// What changed between two observations, and how surprising it is.
///
/// Scored by the surprisal of what appeared or vanished, so a host that
/// started speaking Modbus outranks one that started serving HTTP. This is the
/// signal worth alerting on: an unusual *host* may always have been unusual,
/// but an unusual *change* just happened.
pub fn diff(before: &Host, after: &Host, population: &Population) -> Vec<(Change, f64)> {
    let old = features(before);
    let new = features(after);
    let mut changes: Vec<(Change, f64)> = Vec::new();
    for f in &new {
        if !old.contains(f) {
            changes.push((Change::Appeared(f.clone()), 0.0));
        }
    }
    for f in &old {
        if !new.contains(f) {
            changes.push((Change::Disappeared(f.clone()), 0.0));
        }
    }
    for entry in &mut changes {
        entry.1 = population.surprisal(entry.0.feature());
    }
    changes.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.feature().cmp(b.0.feature())));
    changes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{IcsInfo, Service};
    use std::net::IpAddr;

    fn host(ip: &str, ports: &[(u16, &str)]) -> Host {
        let mut h = Host::new(ip.parse::<IpAddr>().unwrap());
        for (port, product) in ports {
            let mut s = Service::new(*port, Transport::Tcp);
            s.product = Some((*product).to_string());
            h.services.push(s);
        }
        h
    }

    /// 100 ordinary web servers.
    fn web_population() -> Population {
        Population::from_feature_sets((0..100).map(|i| {
            features(&host(
                &format!("10.0.0.{i}"),
                &[(80, "nginx"), (443, "nginx")],
            ))
        }))
    }

    #[test]
    fn features_are_coarse_enough_to_be_shared() {
        let mut h = host("192.0.2.1", &[(80, "nginx")]);
        h.tags.push(crate::model::Tag {
            name: "cve".into(),
            cve: Some("CVE-2026-0001".into()),
            detail: None,
        });
        h.tags.push(crate::model::Tag {
            name: "cve".into(),
            cve: Some("CVE-2026-0002".into()),
            detail: None,
        });
        let f = features(&h);
        // Two CVE tags collapse to one feature: the CVE ids would make every
        // host unique and so score every host as anomalous.
        assert_eq!(f.iter().filter(|x| matches!(x, Feature::Tag(_))).count(), 1);
        assert!(f.contains(&Feature::Port(80, "tcp")));
        assert!(f.contains(&Feature::Product("nginx".into())));
        // Product case does not create separate features.
        let upper = host("192.0.2.2", &[(80, "NGINX")]);
        assert!(features(&upper).contains(&Feature::Product("nginx".into())));
    }

    #[test]
    fn many_services_is_bucketed_not_counted() {
        let mut few = Host::new("192.0.2.1".parse::<IpAddr>().unwrap());
        for p in 0..7u16 {
            few.services.push(Service::new(1000 + p, Transport::Tcp));
        }
        assert!(!features(&few)
            .iter()
            .any(|f| matches!(f, Feature::ManyServices(_))));

        let mut many = Host::new("192.0.2.2".parse::<IpAddr>().unwrap());
        for p in 0..9u16 {
            many.services.push(Service::new(1000 + p, Transport::Tcp));
        }
        assert!(features(&many).contains(&Feature::ManyServices(3)), "8..15");

        let mut lots = Host::new("192.0.2.3".parse::<IpAddr>().unwrap());
        for p in 0..20u16 {
            lots.services.push(Service::new(1000 + p, Transport::Tcp));
        }
        assert!(
            features(&lots).contains(&Feature::ManyServices(4)),
            "16..31"
        );
    }

    #[test]
    fn a_typical_host_scores_far_below_an_odd_one() {
        let pop = web_population();
        assert!(pop.is_usable());

        let typical = score(&host("192.0.2.1", &[(80, "nginx"), (443, "nginx")]), &pop).unwrap();

        let mut odd = host("192.0.2.2", &[(102, "Siemens S7")]);
        odd.services[0].ics = Some(IcsInfo::new("s7"));
        odd.services[0].auth = Some(AuthState::Open);
        let unusual = score(&odd, &pop).unwrap();

        assert!(
            unusual.score > typical.score * 2.0,
            "typical {:.1} vs unusual {:.1}",
            typical.score,
            unusual.score
        );
        // And it says why, strongest first.
        let reasons = unusual.top_reasons(3).join("; ");
        assert!(
            reasons.contains("ICS protocol s7") || reasons.contains("port 102/tcp"),
            "{reasons}"
        );
    }

    #[test]
    fn a_common_feature_carries_almost_no_information() {
        let pop = web_population();
        // On every host: close to zero bits.
        assert!(pop.surprisal(&Feature::Port(80, "tcp")) < 0.1);
        // Never seen: finite, thanks to smoothing, but large.
        let rare = pop.surprisal(&Feature::Ics("modbus".into()));
        assert!(rare > 6.0 && rare.is_finite(), "{rare}");
    }

    #[test]
    fn more_common_parts_do_not_make_a_host_anomalous() {
        // A host with many *ordinary* services should not outrank one with a
        // single genuinely rare service.
        let pop = Population::from_feature_sets((0..100).map(|i| {
            features(&host(
                &format!("10.0.0.{i}"),
                &[(80, "nginx"), (443, "nginx"), (22, "openssh")],
            ))
        }));
        let busy = score(
            &host(
                "192.0.2.1",
                &[(80, "nginx"), (443, "nginx"), (22, "openssh")],
            ),
            &pop,
        )
        .unwrap();
        let mut weird = host("192.0.2.2", &[(502, "Modbus")]);
        weird.services[0].ics = Some(IcsInfo::new("modbus"));
        let weird = score(&weird, &pop).unwrap();
        assert!(
            weird.score > busy.score,
            "{} vs {}",
            weird.score,
            busy.score
        );
    }

    #[test]
    fn a_small_population_is_refused_rather_than_guessed_at() {
        let tiny = Population::from_feature_sets(
            (0..10).map(|i| features(&host(&format!("10.0.0.{i}"), &[(80, "nginx")]))),
        );
        assert!(!tiny.is_usable());
        assert!(score(&host("192.0.2.1", &[(80, "nginx")]), &tiny).is_none());
        assert!(
            !diff(
                &host("192.0.2.1", &[(80, "nginx")]),
                &host("192.0.2.1", &[(80, "nginx"), (102, "s7")]),
                &tiny
            )
            .is_empty(),
            "a diff is still computable, just not calibrated"
        );
    }

    #[test]
    fn diff_reports_both_directions_ranked_by_surprise() {
        let pop = web_population();
        let before = host("192.0.2.1", &[(80, "nginx"), (443, "nginx")]);
        let mut after = host("192.0.2.1", &[(80, "nginx")]);
        let mut ics = Service::new(502, Transport::Tcp);
        ics.ics = Some(IcsInfo::new("modbus"));
        after.services.push(ics);

        let changes = diff(&before, &after, &pop);
        let described: Vec<String> = changes.iter().map(|(c, _)| c.describe()).collect();
        assert!(
            described
                .iter()
                .any(|d| d.contains("gained ICS protocol modbus")),
            "{described:?}"
        );
        assert!(
            described.iter().any(|d| d.contains("lost port 443/tcp")),
            "{described:?}"
        );
        // The rare gain outranks the ordinary loss.
        assert!(
            changes[0].0.describe().contains("gained"),
            "{:?}",
            changes[0]
        );
        assert!(changes[0].1 > changes[changes.len() - 1].1);
    }

    #[test]
    fn an_unchanged_host_has_no_diff() {
        let pop = web_population();
        let h = host("192.0.2.1", &[(80, "nginx")]);
        assert!(diff(&h, &h, &pop).is_empty());
        // A change in something features() deliberately ignores is not a change.
        let mut same_shape = h.clone();
        same_shape.services[0].version = Some("9.9".into());
        assert!(diff(&h, &same_shape, &pop).is_empty());
    }

    #[test]
    fn scoring_is_deterministic() {
        let pop = web_population();
        let h = host("192.0.2.1", &[(80, "nginx"), (102, "s7")]);
        assert_eq!(score(&h, &pop), score(&h, &pop));
        assert_eq!(pop.hosts(), 100);
        assert!(pop.distinct_features() >= 2);
    }
}
