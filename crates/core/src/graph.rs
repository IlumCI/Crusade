//! Grouping hosts that belong to the same deployment.
//!
//! Two hosts presenting the same TLS certificate, or the same SSH host key,
//! are not coincidentally similar — someone installed the same key material on
//! both. The same goes, more weakly, for an unusual favicon or an identical
//! JARM fingerprint. Following those links turns a list of addresses into the
//! infrastructure behind them, which is the pivot an analyst actually wants:
//! *what else belongs to whoever runs this?*
//!
//! The trap is that the strength of a shared identifier depends entirely on how
//! rare it is. Two hosts sharing a self-signed certificate is a finding; two
//! hosts sharing nginx's default favicon is nothing at all, and treating it as
//! an edge collapses the whole index into one meaningless cluster. So every
//! identifier is weighed by how many hosts carry it, and anything common is
//! discarded before a single edge is drawn ([`Linker::MAX_SHARE`]) — the same
//! reasoning behind inverse document frequency, and behind the honeypot
//! signal for a favicon seen across unrelated networks.
//!
//! Published work here is industry rather than peer-reviewed (GNN-based
//! pivoting over certificate and fingerprint graphs), so this stays at the
//! baseline my own survey recommended: rarity-weighted edges and connected
//! components, which are explainable and cheap. Anything learned belongs on
//! top of this, not instead of it.

use std::collections::{BTreeMap, BTreeSet};

/// What kind of thing two hosts share.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LinkKind {
    /// The same TLS certificate. Someone deployed one key pair to both.
    Certificate,
    /// The same SSH host key. As strong as a certificate.
    SshHostKey,
    /// The same favicon. Suggests the same application, or the same operator's
    /// branding.
    Favicon,
    /// The same JARM: the same TLS stack and configuration.
    Jarm,
    /// The same HASSH: the same SSH client/server algorithm set.
    Hassh,
}

impl LinkKind {
    /// How much this kind of link is worth, before rarity is considered.
    ///
    /// Key material means shared administration. A fingerprint only means
    /// shared software, which is far weaker evidence of a shared operator.
    pub fn weight(self) -> f64 {
        match self {
            LinkKind::Certificate | LinkKind::SshHostKey => 1.0,
            LinkKind::Favicon => 0.6,
            LinkKind::Jarm | LinkKind::Hassh => 0.3,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            LinkKind::Certificate => "cert",
            LinkKind::SshHostKey => "ssh-hostkey",
            LinkKind::Favicon => "favicon",
            LinkKind::Jarm => "jarm",
            LinkKind::Hassh => "hassh",
        }
    }
}

/// One identifier observed on a host.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Identifier {
    pub kind: LinkKind,
    pub value: String,
}

impl Identifier {
    pub fn new(kind: LinkKind, value: impl Into<String>) -> Self {
        Identifier {
            kind,
            value: value.into(),
        }
    }
}

/// A group of hosts joined by shared identifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cluster {
    /// Stable id: the lowest-sorting member, so the same input always yields
    /// the same ids without a counter or any stored state.
    pub id: String,
    pub members: Vec<String>,
    /// The identifiers that actually joined members together, strongest first.
    pub evidence: Vec<(Identifier, usize)>,
}

impl Cluster {
    pub fn len(&self) -> usize {
        self.members.len()
    }
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }
}

/// Builds clusters from host identifiers.
#[derive(Debug, Clone, Default)]
pub struct Linker {
    /// host -> identifiers.
    hosts: BTreeMap<String, BTreeSet<Identifier>>,
}

impl Linker {
    /// An identifier carried by more than this fraction of hosts is treated as
    /// a property of the software rather than of an operator, and ignored.
    pub const MAX_SHARE: f64 = 0.10;
    /// ...and never joins more than this many hosts regardless of the
    /// fraction, so a small index cannot be collapsed by one popular value.
    pub const MAX_MEMBERS: usize = 1_000;
    /// Below this combined weight a pair is not linked at all.
    pub const MIN_WEIGHT: f64 = 0.3;

    pub fn new() -> Self {
        Linker::default()
    }

    /// Record the identifiers seen on one host.
    pub fn add(
        &mut self,
        host: impl Into<String>,
        identifiers: impl IntoIterator<Item = Identifier>,
    ) {
        let entry = self.hosts.entry(host.into()).or_default();
        for id in identifiers {
            if !id.value.trim().is_empty() {
                entry.insert(id);
            }
        }
    }

    pub fn hosts(&self) -> usize {
        self.hosts.len()
    }

    /// Identifiers rare enough to mean something, with the hosts carrying each.
    fn useful_identifiers(&self) -> BTreeMap<Identifier, Vec<String>> {
        let mut by_id: BTreeMap<Identifier, Vec<String>> = BTreeMap::new();
        for (host, ids) in &self.hosts {
            for id in ids {
                by_id.entry(id.clone()).or_default().push(host.clone());
            }
        }
        let total = self.hosts.len().max(1);
        by_id.retain(|_, carriers| {
            // A value on one host links nothing; a value on many is a property
            // of the software, not the operator.
            carriers.len() > 1
                && carriers.len() <= Self::MAX_MEMBERS
                && (carriers.len() as f64 / total as f64) <= Self::MAX_SHARE
        });
        by_id
    }

    /// Group hosts into clusters.
    ///
    /// Hosts joined by identifiers whose combined weight reaches
    /// [`Linker::MIN_WEIGHT`] end up in the same cluster, transitively.
    /// Singletons are omitted: a cluster of one is just a host.
    pub fn clusters(&self) -> Vec<Cluster> {
        let useful = self.useful_identifiers();

        // Union-find over host names.
        let names: Vec<&String> = self.hosts.keys().collect();
        let index: BTreeMap<&String, usize> =
            names.iter().enumerate().map(|(i, n)| (*n, i)).collect();
        let mut parent: Vec<usize> = (0..names.len()).collect();

        fn find(parent: &mut [usize], mut x: usize) -> usize {
            while parent[x] != x {
                parent[x] = parent[parent[x]];
                x = parent[x];
            }
            x
        }

        // Accumulate per-pair weight first, so two weak links can combine into
        // one that counts while a single weak link does not.
        let mut pair_weight: BTreeMap<(usize, usize), f64> = BTreeMap::new();
        for (id, carriers) in &useful {
            for (i, a) in carriers.iter().enumerate() {
                for b in &carriers[i + 1..] {
                    let (x, y) = (index[a], index[b]);
                    let key = if x < y { (x, y) } else { (y, x) };
                    *pair_weight.entry(key).or_insert(0.0) += id.kind.weight();
                }
            }
        }
        for ((x, y), weight) in &pair_weight {
            if *weight >= Self::MIN_WEIGHT {
                let (rx, ry) = (find(&mut parent, *x), find(&mut parent, *y));
                if rx != ry {
                    parent[rx] = ry;
                }
            }
        }

        // Collect members per root.
        let mut groups: BTreeMap<usize, Vec<String>> = BTreeMap::new();
        for (i, name) in names.iter().enumerate() {
            let root = find(&mut parent, i);
            groups.entry(root).or_default().push((*name).clone());
        }

        let mut out: Vec<Cluster> = groups
            .into_values()
            .filter(|members| members.len() > 1)
            .map(|mut members| {
                members.sort();
                let set: BTreeSet<&String> = members.iter().collect();
                // The identifiers that are actually shared inside this cluster.
                let mut evidence: Vec<(Identifier, usize)> = useful
                    .iter()
                    .filter_map(|(id, carriers)| {
                        let inside = carriers.iter().filter(|c| set.contains(c)).count();
                        (inside > 1).then(|| (id.clone(), inside))
                    })
                    .collect();
                evidence.sort_by(|a, b| {
                    b.0.kind
                        .weight()
                        .total_cmp(&a.0.kind.weight())
                        .then(b.1.cmp(&a.1))
                        .then(a.0.cmp(&b.0))
                });
                Cluster {
                    id: members[0].clone(),
                    members,
                    evidence,
                }
            })
            .collect();
        // Biggest first, then by id so the output is stable.
        out.sort_by(|a, b| b.len().cmp(&a.len()).then(a.id.cmp(&b.id)));
        out
    }

    /// Identifiers that were ignored for being too common, with their counts.
    ///
    /// Worth surfacing: it explains why two hosts an operator expected to be
    /// linked are not, and it is a decent list of default installations.
    pub fn ignored_as_common(&self) -> Vec<(Identifier, usize)> {
        let mut by_id: BTreeMap<Identifier, usize> = BTreeMap::new();
        for ids in self.hosts.values() {
            for id in ids {
                *by_id.entry(id.clone()).or_insert(0) += 1;
            }
        }
        let total = self.hosts.len().max(1);
        let mut out: Vec<(Identifier, usize)> = by_id
            .into_iter()
            .filter(|(_, n)| {
                *n > 1 && (*n > Self::MAX_MEMBERS || (*n as f64 / total as f64) > Self::MAX_SHARE)
            })
            .collect();
        out.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(kind: LinkKind, v: &str) -> Identifier {
        Identifier::new(kind, v)
    }

    /// 40 unrelated hosts, so shares of 10% are 4 hosts.
    fn background(linker: &mut Linker) {
        for i in 0..40 {
            linker.add(
                format!("10.0.0.{i}"),
                [id(LinkKind::Jarm, &format!("unique-jarm-{i}"))],
            );
        }
    }

    #[test]
    fn a_shared_certificate_links_hosts() {
        let mut l = Linker::new();
        background(&mut l);
        l.add("192.0.2.1", [id(LinkKind::Certificate, "sha256:aaa")]);
        l.add("192.0.2.2", [id(LinkKind::Certificate, "sha256:aaa")]);

        let clusters = l.clusters();
        assert_eq!(clusters.len(), 1, "{clusters:?}");
        assert_eq!(clusters[0].members, vec!["192.0.2.1", "192.0.2.2"]);
        assert_eq!(clusters[0].id, "192.0.2.1", "id is the lowest member");
        assert_eq!(clusters[0].evidence[0].0.kind, LinkKind::Certificate);
    }

    #[test]
    fn links_are_transitive() {
        let mut l = Linker::new();
        background(&mut l);
        // A-B share a cert; B-C share an SSH key. All three are one estate.
        l.add("192.0.2.1", [id(LinkKind::Certificate, "sha256:aaa")]);
        l.add(
            "192.0.2.2",
            [
                id(LinkKind::Certificate, "sha256:aaa"),
                id(LinkKind::SshHostKey, "key:bbb"),
            ],
        );
        l.add("192.0.2.3", [id(LinkKind::SshHostKey, "key:bbb")]);

        let clusters = l.clusters();
        assert_eq!(clusters.len(), 1);
        assert_eq!(
            clusters[0].members,
            vec!["192.0.2.1", "192.0.2.2", "192.0.2.3"]
        );
    }

    #[test]
    fn a_universal_favicon_does_not_collapse_the_index() {
        // The failure mode this design exists to prevent: every host serving
        // nginx's default favicon must not become one cluster.
        let mut l = Linker::new();
        for i in 0..40 {
            l.add(
                format!("10.0.0.{i}"),
                [id(LinkKind::Favicon, "default-nginx")],
            );
        }
        assert!(
            l.clusters().is_empty(),
            "a favicon on every host links nothing: {:?}",
            l.clusters()
        );
        // And it is reported as ignored, so the operator can see why.
        let ignored = l.ignored_as_common();
        assert_eq!(ignored.len(), 1);
        assert_eq!(ignored[0].0.value, "default-nginx");
        assert_eq!(ignored[0].1, 40);
    }

    #[test]
    fn a_rare_favicon_still_links() {
        let mut l = Linker::new();
        background(&mut l);
        l.add("192.0.2.1", [id(LinkKind::Favicon, "custom-brand")]);
        l.add("192.0.2.2", [id(LinkKind::Favicon, "custom-brand")]);
        let clusters = l.clusters();
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].evidence[0].0.kind, LinkKind::Favicon);
    }

    #[test]
    fn one_weak_link_is_not_enough_but_two_are() {
        let mut l = Linker::new();
        background(&mut l);
        // A single JARM match (0.3) sits exactly at the threshold...
        l.add("192.0.2.1", [id(LinkKind::Jarm, "rare-jarm")]);
        l.add("192.0.2.2", [id(LinkKind::Jarm, "rare-jarm")]);
        assert_eq!(l.clusters().len(), 1, "0.3 meets MIN_WEIGHT");

        // ...and a JARM plus a HASSH match is stronger still.
        let mut l2 = Linker::new();
        background(&mut l2);
        l2.add(
            "192.0.2.3",
            [
                id(LinkKind::Jarm, "rare-jarm"),
                id(LinkKind::Hassh, "rare-hassh"),
            ],
        );
        l2.add(
            "192.0.2.4",
            [
                id(LinkKind::Jarm, "rare-jarm"),
                id(LinkKind::Hassh, "rare-hassh"),
            ],
        );
        let c = l2.clusters();
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].evidence.len(), 2, "both links are reported");
    }

    #[test]
    fn separate_estates_stay_separate() {
        let mut l = Linker::new();
        background(&mut l);
        l.add("192.0.2.1", [id(LinkKind::Certificate, "sha256:aaa")]);
        l.add("192.0.2.2", [id(LinkKind::Certificate, "sha256:aaa")]);
        l.add("198.51.100.1", [id(LinkKind::Certificate, "sha256:bbb")]);
        l.add("198.51.100.2", [id(LinkKind::Certificate, "sha256:bbb")]);

        let clusters = l.clusters();
        assert_eq!(clusters.len(), 2);
        // Biggest first, then by id: both are size 2, so sorted by id.
        assert_eq!(clusters[0].id, "192.0.2.1");
        assert_eq!(clusters[1].id, "198.51.100.1");
        for c in &clusters {
            assert_eq!(c.len(), 2);
        }
    }

    #[test]
    fn singletons_and_empty_values_are_ignored() {
        let mut l = Linker::new();
        background(&mut l);
        // An identifier only this host has.
        l.add("192.0.2.9", [id(LinkKind::Certificate, "sha256:unique")]);
        // Blank values are not identifiers.
        l.add(
            "192.0.2.10",
            [id(LinkKind::Certificate, ""), id(LinkKind::Jarm, "   ")],
        );
        assert!(l.clusters().is_empty());
        assert_eq!(l.hosts(), 42);
    }

    #[test]
    fn clustering_is_deterministic() {
        let build = || {
            let mut l = Linker::new();
            background(&mut l);
            for (host, cert) in [
                ("192.0.2.3", "c1"),
                ("192.0.2.1", "c1"),
                ("192.0.2.2", "c1"),
            ] {
                l.add(host, [id(LinkKind::Certificate, cert)]);
            }
            l.clusters()
        };
        let first = build();
        assert_eq!(first, build());
        // Members sorted, id the lowest.
        assert_eq!(
            first[0].members,
            vec!["192.0.2.1", "192.0.2.2", "192.0.2.3"]
        );
        assert_eq!(first[0].id, "192.0.2.1");
    }

    #[test]
    fn an_empty_index_yields_nothing() {
        let l = Linker::new();
        assert!(l.clusters().is_empty());
        assert!(l.ignored_as_common().is_empty());
        assert_eq!(l.hosts(), 0);
    }

    #[test]
    fn key_material_outweighs_fingerprints_in_the_evidence() {
        let mut l = Linker::new();
        background(&mut l);
        for host in ["192.0.2.1", "192.0.2.2"] {
            l.add(
                host,
                [
                    id(LinkKind::Jarm, "rare-jarm"),
                    id(LinkKind::Certificate, "sha256:aaa"),
                    id(LinkKind::Favicon, "rare-icon"),
                ],
            );
        }
        let kinds: Vec<LinkKind> = l.clusters()[0]
            .evidence
            .iter()
            .map(|(i, _)| i.kind)
            .collect();
        assert_eq!(
            kinds,
            vec![LinkKind::Certificate, LinkKind::Favicon, LinkKind::Jarm],
            "the strongest reason should be listed first"
        );
    }
}
