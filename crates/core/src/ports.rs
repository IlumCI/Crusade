//! What ports occur together, and what that predicts.
//!
//! Probing every port of every host is unaffordable: 65,535 ports across even
//! a /16 is 4.3 billion probes. But services are not independent — a host with
//! 3306 open is far more likely to also run 22 than 102, and a host with 102
//! open is probably industrial equipment rather than a database server.
//!
//! GPS (Izhikevich, Teixeira & Durumeric, *Predicting IPv4 Services Across All
//! Ports*, SIGCOMM 2022, arXiv:2303.00895) exploits exactly that: find one
//! service per host cheaply, then predict where its other services are. They
//! report finding 92.5% of services with 131x less bandwidth than an
//! exhaustive scan.
//!
//! This model is the same conditional statistics in both directions:
//!
//! * [`PortModel::predict`] ranks unprobed ports by how likely they are, given
//!   what a host already answered — which ports to try next.
//! * [`PortModel::implausible_pairs`] finds combinations real hosts
//!   essentially never have, which is a honeypot signal rather than a
//!   prediction (see `crusade_vuln::honeypot`).
//!
//! It is learned from the operator's own index, so it describes the population
//! they actually scan. Nothing here does any IO.

use std::collections::{BTreeSet, HashMap};

/// Minimum indexed hosts before the model is trusted at all.
pub const MIN_HOSTS: u64 = 200;
/// Minimum hosts carrying a port before its conditionals are trusted. Below
/// this, a single odd host would dominate the estimate.
pub const MIN_SUPPORT: u64 = 20;
/// A pair is implausible when each port co-occurs with the other on fewer than
/// this fraction of the hosts that carry it.
const PAIR_MAX_COND: f64 = 0.02;

/// Port and port-pair frequencies over a population of hosts.
#[derive(Debug, Clone, Default)]
pub struct PortModel {
    hosts: u64,
    single: HashMap<u16, u64>,
    pairs: HashMap<(u16, u16), u64>,
}

impl PortModel {
    /// Learn from one port list per host. Hosts with no ports are ignored.
    pub fn from_port_sets<I, P>(sets: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: AsRef<[u16]>,
    {
        let mut model = PortModel::default();
        for set in sets {
            let ports: BTreeSet<u16> = set.as_ref().iter().copied().collect();
            if ports.is_empty() {
                continue;
            }
            model.hosts += 1;
            let v: Vec<u16> = ports.into_iter().collect();
            for (i, &a) in v.iter().enumerate() {
                *model.single.entry(a).or_default() += 1;
                // Pairs are stored once, with the lower port first.
                for &b in &v[i + 1..] {
                    *model.pairs.entry((a, b)).or_default() += 1;
                }
            }
        }
        model
    }

    /// Hosts the model was learned from.
    pub fn hosts(&self) -> u64 {
        self.hosts
    }

    /// Whether there is enough data to say anything.
    pub fn is_usable(&self) -> bool {
        self.hosts >= MIN_HOSTS
    }

    /// Distinct ports seen.
    pub fn distinct_ports(&self) -> usize {
        self.single.len()
    }

    /// How many hosts carried `port`.
    pub fn support(&self, port: u16) -> u64 {
        self.single.get(&port).copied().unwrap_or(0)
    }

    /// P(port) across the population.
    pub fn marginal(&self, port: u16) -> f64 {
        if self.hosts == 0 {
            return 0.0;
        }
        self.support(port) as f64 / self.hosts as f64
    }

    fn pair_count(&self, a: u16, b: u16) -> u64 {
        let key = if a <= b { (a, b) } else { (b, a) };
        self.pairs.get(&key).copied().unwrap_or(0)
    }

    /// P(`target` open | `given` open), or `None` when `given` has too little
    /// support for the estimate to mean anything.
    pub fn conditional(&self, target: u16, given: u16) -> Option<f64> {
        if target == given {
            return None;
        }
        let n = self.support(given);
        if n < MIN_SUPPORT {
            return None;
        }
        Some(self.pair_count(given, target) as f64 / n as f64)
    }

    /// Rank ports by how likely they are to be open, given what `observed`
    /// already answered.
    ///
    /// Each observed port contributes its own conditional, combined with a
    /// noisy-OR — evidence accumulates rather than competing, so a port
    /// predicted by several observations outranks one predicted by a single
    /// weak signal. Ports in `observed` are excluded, as are ports with too
    /// little support to estimate. Falls back to population marginals for a
    /// host whose observed ports are all unknown to the model.
    ///
    /// Returns at most `top_k` entries, highest score first. Empty when the
    /// model has seen too few hosts to be worth trusting.
    pub fn predict(&self, observed: &[u16], top_k: usize) -> Vec<(u16, f64)> {
        if !self.is_usable() || top_k == 0 {
            return Vec::new();
        }
        let seen: BTreeSet<u16> = observed.iter().copied().collect();

        let mut scored: Vec<(u16, f64)> = self
            .single
            .keys()
            .copied()
            .filter(|p| !seen.contains(p) && self.support(*p) >= MIN_SUPPORT)
            .filter_map(|candidate| {
                // Noisy-OR over every observed port that has an opinion.
                let mut keep_closed = 1.0f64;
                let mut informed = false;
                for &given in &seen {
                    if let Some(p) = self.conditional(candidate, given) {
                        keep_closed *= 1.0 - p;
                        informed = true;
                    }
                }
                let score = if informed {
                    1.0 - keep_closed
                } else {
                    // Nothing observed tells us anything: fall back to how
                    // common the port is overall.
                    self.marginal(candidate)
                };
                (score > 0.0).then_some((candidate, score))
            })
            .collect();

        // Ties broken by port number, so the output is deterministic.
        scored.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
        scored.truncate(top_k);
        scored
    }

    /// The ports most worth probing first on a host nothing is known about.
    ///
    /// This is the seed set for a two-phase scan: cheap, population-wide, and
    /// learned rather than hard-coded.
    pub fn most_common(&self, top_k: usize) -> Vec<(u16, f64)> {
        let mut v: Vec<(u16, f64)> = self
            .single
            .iter()
            .map(|(&p, &n)| (p, n as f64 / self.hosts.max(1) as f64))
            .collect();
        v.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
        v.truncate(top_k);
        v
    }

    /// Pairs in `ports` that the population says almost never co-occur.
    /// Empty when the population is too small to say.
    pub fn implausible_pairs(&self, ports: &[u16]) -> Vec<(u16, u16)> {
        if !self.is_usable() {
            return Vec::new();
        }
        let v: Vec<u16> = ports
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let mut out = Vec::new();
        for (i, &a) in v.iter().enumerate() {
            for &b in &v[i + 1..] {
                let (na, nb) = (self.support(a), self.support(b));
                if na < MIN_SUPPORT || nb < MIN_SUPPORT {
                    continue;
                }
                let both = self.pair_count(a, b) as f64;
                if both / (na as f64) < PAIR_MAX_COND && both / (nb as f64) < PAIR_MAX_COND {
                    out.push((a, b));
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A population with three clear host archetypes, plus enough volume that
    /// the model is usable.
    fn population() -> PortModel {
        let mut sets: Vec<Vec<u16>> = Vec::new();
        // 300 web servers: 80 + 443, half also 22.
        for i in 0..300 {
            let mut v = vec![80, 443];
            if i % 2 == 0 {
                v.push(22);
            }
            sets.push(v);
        }
        // 200 database hosts: 3306 + 22.
        for _ in 0..200 {
            sets.push(vec![22, 3306]);
        }
        // 100 industrial hosts: 102 + 502, never with IT ports.
        for _ in 0..100 {
            sets.push(vec![102, 502]);
        }
        // 10 hosts with a rare port: deliberately below MIN_SUPPORT (20), so
        // the model refuses to draw conclusions from it.
        for _ in 0..10 {
            sets.push(vec![9999]);
        }
        PortModel::from_port_sets(&sets)
    }

    #[test]
    fn learns_counts_and_marginals() {
        let m = population();
        assert_eq!(m.hosts(), 610);
        assert!(m.is_usable());
        assert_eq!(m.support(80), 300);
        assert_eq!(m.support(22), 350, "150 web + 200 database");
        assert!((m.marginal(80) - 300.0 / 610.0).abs() < 1e-9);
        assert_eq!(m.support(1234), 0);
        assert_eq!(m.marginal(1234), 0.0);
    }

    #[test]
    fn conditionals_are_directional() {
        let m = population();
        // Every host with 80 also has 443.
        assert_eq!(m.conditional(443, 80), Some(1.0));
        // Only half the hosts with 80 have 22.
        assert!((m.conditional(22, 80).unwrap() - 0.5).abs() < 1e-9);
        // But 22 appears on database hosts too, so the reverse is weaker.
        let web_given_ssh = m.conditional(80, 22).unwrap();
        assert!(web_given_ssh < 0.5, "{web_given_ssh}");
        // Industrial and IT never mix.
        assert_eq!(m.conditional(102, 80), Some(0.0));
        // A port carried by too few hosts yields no estimate.
        assert_eq!(m.conditional(80, 9999), None);
        assert_eq!(m.conditional(80, 80), None, "a port cannot predict itself");
    }

    #[test]
    fn predicts_the_rest_of_a_hosts_services() {
        let m = population();

        // Seeing 80 should suggest 443 first, and 22 next.
        let p = m.predict(&[80], 3);
        assert_eq!(p[0].0, 443);
        assert!((p[0].1 - 1.0).abs() < 1e-9);
        assert_eq!(p[1].0, 22);
        assert!(!p.iter().any(|(port, _)| *port == 80), "excludes observed");

        // Seeing an industrial port suggests the other one, not IT ports.
        let p = m.predict(&[102], 3);
        assert_eq!(p[0].0, 502);
        assert!(p[0].1 > 0.99);
        let it_score = p.iter().find(|(port, _)| *port == 80).map(|(_, s)| *s);
        assert!(
            it_score.is_none_or(|s| s < 0.01),
            "industrial hosts should not predict web ports: {it_score:?}"
        );

        // Evidence accumulates: 80 and 3306 together both point at 22.
        let both = m.predict(&[80, 3306], 1);
        assert_eq!(both[0].0, 22);
        assert!(
            both[0].1 > m.conditional(22, 80).unwrap(),
            "two signals should outrank one"
        );
    }

    #[test]
    fn unknown_observations_fall_back_to_how_common_ports_are() {
        let m = population();
        // 9999 has too little support to condition on, so the ranking is just
        // the population's most common ports.
        let p = m.predict(&[9999], 2);
        let common = m.most_common(2);
        assert_eq!(
            p.iter().map(|(x, _)| *x).collect::<Vec<_>>(),
            common.iter().map(|(x, _)| *x).collect::<Vec<_>>()
        );
    }

    #[test]
    fn respects_top_k_and_is_deterministic() {
        let m = population();
        assert_eq!(m.predict(&[80], 2).len(), 2);
        assert!(m.predict(&[80], 0).is_empty());
        assert_eq!(m.predict(&[80], 100), m.predict(&[80], 100));
        // Rare ports are never suggested, however many are asked for.
        assert!(!m.predict(&[80], 100).iter().any(|(p, _)| *p == 9999));
    }

    #[test]
    fn says_nothing_without_enough_hosts() {
        let small = PortModel::from_port_sets(vec![vec![80, 443], vec![22]]);
        assert!(!small.is_usable());
        assert!(small.predict(&[80], 5).is_empty());
        assert!(small.implausible_pairs(&[80, 22]).is_empty());
        // Marginals are still computable; they are just not used for ranking.
        assert!((small.marginal(80) - 0.5).abs() < 1e-9);
        assert!(PortModel::default().predict(&[80], 5).is_empty());
    }

    #[test]
    fn most_common_ranks_by_frequency() {
        let m = population();
        let top = m.most_common(3);
        assert_eq!(top[0].0, 22, "22 is on 350 of 610 hosts");
        let ports: Vec<u16> = top.iter().map(|(p, _)| *p).collect();
        assert!(ports.contains(&80) && ports.contains(&443));
        assert!(top[0].1 >= top[1].1);
    }

    #[test]
    fn implausible_pairs_flag_combinations_that_do_not_occur() {
        let m = population();
        // IT and industrial never share a host.
        assert_eq!(m.implausible_pairs(&[80, 102]), vec![(80, 102)]);
        // Ports that really do co-occur are not flagged.
        assert!(m.implausible_pairs(&[80, 443]).is_empty());
        assert!(m.implausible_pairs(&[22, 3306]).is_empty());
        // A whole implausible set yields every bad pair.
        let flagged = m.implausible_pairs(&[80, 102, 3306]);
        assert_eq!(flagged.len(), 3, "{flagged:?}");
        // Under-supported ports are not judged.
        assert!(m.implausible_pairs(&[80, 9999]).is_empty());
        assert!(m.implausible_pairs(&[80]).is_empty());
    }

    #[test]
    fn port_order_in_a_set_does_not_matter() {
        let a = PortModel::from_port_sets(vec![vec![443, 80], vec![80, 443]]);
        let b = PortModel::from_port_sets(vec![vec![80, 443], vec![443, 80]]);
        assert_eq!(a.pair_count(80, 443), 2);
        assert_eq!(a.pair_count(443, 80), b.pair_count(80, 443));
        // Duplicates within one host count once.
        let dup = PortModel::from_port_sets(vec![vec![80, 80, 443]]);
        assert_eq!(dup.support(80), 1);
        assert_eq!(dup.pair_count(80, 443), 1);
    }
}
