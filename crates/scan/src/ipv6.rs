//! IPv6 target generation and dealiasing.
//!
//! IPv4 can be enumerated; IPv6 cannot. A single /64 holds 18 quintillion
//! addresses, so there is no sweep to run — hosts must be *predicted* from
//! addresses already known, and the prediction is the scan.
//!
//! Two findings shape what is built here, both from measurement papers rather
//! than intuition:
//!
//! * **Seed hygiene and dealiasing matter more than the generator.** 6SEVEN
//!   (Kanipe, Rye, Levin & Beverly, IMC 2026, arXiv:2609.08098) ported eight
//!   published generators into one framework and found that seed composition,
//!   dealiasing and tabulation moved the results more than the choice of
//!   algorithm. So [`clean_seeds`] and [`Dealiaser`] come first, and
//!   [`TargetGenerator`] is deliberately a simple, replaceable baseline.
//!
//! * **Aliased prefixes must be collapsed, not dropped.** Some networks answer
//!   on *every* address in a prefix, which floods a generator with worthless
//!   hits. The standard detection is Gasser et al., *Clusters in the Expanse*
//!   (IMC 2018, arXiv:1806.01633): probe one address per value of the nybble
//!   just past the prefix and see whether they all answer. But discarding
//!   those prefixes throws away real infrastructure — *Rusty Clusters*
//!   (Zirngibl et al., IMC 2022) found over 98% of Fastly's announced IPv6
//!   space reads as aliased. [`Dealiaser::collapse`] therefore keeps one
//!   representative per aliased prefix instead of removing it.
//!
//! Probing is injected rather than performed here ([`Dealiaser::classify`]
//! takes the results), so the policy is testable without a network and the
//! caller chooses the engine.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv6Addr;

use ipnet::Ipv6Net;

/// Nybbles in an IPv6 address.
pub const NYBBLES: usize = 32;
/// One probe per possible value of a nybble.
pub const ALIAS_PROBES: usize = 16;
/// Fraction of alias probes that must answer before a prefix is called
/// aliased. Below 1.0 because a real aliased network can still drop a packet.
const ALIAS_THRESHOLD: f64 = 0.9;

/// Read an address as 32 nybbles, most significant first.
pub fn nybbles(addr: Ipv6Addr) -> [u8; NYBBLES] {
    let mut out = [0u8; NYBBLES];
    for (i, byte) in addr.octets().iter().enumerate() {
        out[i * 2] = byte >> 4;
        out[i * 2 + 1] = byte & 0x0f;
    }
    out
}

/// Rebuild an address from 32 nybbles.
pub fn from_nybbles(n: &[u8; NYBBLES]) -> Ipv6Addr {
    let mut octets = [0u8; 16];
    for i in 0..16 {
        octets[i] = (n[i * 2] << 4) | (n[i * 2 + 1] & 0x0f);
    }
    Ipv6Addr::from(octets)
}

/// Deterministic generator, so a scan is reproducible and reviewable.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn nybble(&mut self) -> u8 {
        (self.next() & 0x0f) as u8
    }
}

/// Whether an address is worth probing at all.
///
/// Scanning is only legitimate against globally routable space; link-local,
/// unique-local, multicast, loopback and the documentation prefix are never
/// targets. The mandatory [`crate::Blocklist`] enforces this too — this is the
/// cheaper check that keeps them out of seed sets and generator output in the
/// first place.
pub fn is_scannable(addr: Ipv6Addr) -> bool {
    if addr.is_loopback() || addr.is_multicast() || addr.is_unspecified() {
        return false;
    }
    let s = addr.segments();
    // fe80::/10 link-local, fc00::/7 unique-local, 2001:db8::/32 documentation.
    if s[0] & 0xffc0 == 0xfe80 || s[0] & 0xfe00 == 0xfc00 {
        return false;
    }
    if s[0] == 0x2001 && s[1] == 0x0db8 {
        return false;
    }
    // ::ffff:0:0/96 IPv4-mapped — scan those as IPv4 instead.
    if s[0..5] == [0, 0, 0, 0, 0] && s[5] == 0xffff {
        return false;
    }
    true
}

/// The addresses to probe when testing `prefix` for aliasing.
///
/// One per value of the nybble immediately after the prefix, with the
/// remaining bits randomised: if every branch answers, the network is
/// responding to addresses rather than to hosts. `seed` makes the choice
/// reproducible.
///
/// Returns nothing for a prefix with no room left to vary (/128).
pub fn alias_probes(prefix: Ipv6Net, seed: u64) -> Vec<Ipv6Addr> {
    let len = prefix.prefix_len() as usize;
    if len >= 128 {
        return Vec::new();
    }
    // The nybble the probe varies: the first one not fully inside the prefix.
    let vary = len / 4;
    if vary >= NYBBLES {
        return Vec::new();
    }
    let base = nybbles(prefix.network());
    let mut rng = Rng(seed ^ u128::from(prefix.network()) as u64);
    (0..ALIAS_PROBES as u8)
        .map(|value| {
            let mut n = base;
            // Preserve any bits of this nybble that belong to the prefix.
            let kept_bits = len % 4;
            if kept_bits == 0 {
                n[vary] = value;
            } else {
                let mask = 0xffu8 << (4 - kept_bits);
                n[vary] = (base[vary] & mask & 0x0f) | (value & (0x0f >> kept_bits));
            }
            for slot in n.iter_mut().skip(vary + 1) {
                *slot = rng.nybble();
            }
            from_nybbles(&n)
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// What an alias probe concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alias {
    /// Nearly every probed address answered: the network answers for the
    /// whole prefix.
    Aliased,
    /// Some answered, some did not: these are hosts.
    Hosts,
    /// Nothing answered, so nothing can be concluded. Treated as not aliased,
    /// because assuming otherwise would silently hide real space.
    Silent,
}

/// Known aliased prefixes, and how to apply them to a target list.
#[derive(Debug, Clone, Default)]
pub struct Dealiaser {
    aliased: Vec<Ipv6Net>,
}

impl Dealiaser {
    pub fn new() -> Self {
        Dealiaser::default()
    }

    /// Classify a prefix from its probe results.
    ///
    /// `responses` is one flag per address returned by [`alias_probes`], in
    /// the same order.
    pub fn classify(responses: &[bool]) -> Alias {
        if responses.is_empty() {
            return Alias::Silent;
        }
        let answered = responses.iter().filter(|r| **r).count();
        if answered == 0 {
            Alias::Silent
        } else if answered as f64 / responses.len() as f64 >= ALIAS_THRESHOLD {
            Alias::Aliased
        } else {
            Alias::Hosts
        }
    }

    /// Record a verdict. Only `Aliased` changes anything.
    pub fn record(&mut self, prefix: Ipv6Net, verdict: Alias) {
        if verdict == Alias::Aliased && !self.aliased.contains(&prefix) {
            self.aliased.push(prefix);
        }
    }

    /// Prefixes recorded as aliased.
    pub fn aliased(&self) -> &[Ipv6Net] {
        &self.aliased
    }

    /// The aliased prefix containing `addr`, if any.
    pub fn covering(&self, addr: Ipv6Addr) -> Option<Ipv6Net> {
        self.aliased.iter().copied().find(|net| net.contains(&addr))
    }

    /// Replace every run of addresses inside an aliased prefix with a single
    /// representative, keeping everything else.
    ///
    /// This is the difference between *dealiasing* and *discarding*: an
    /// aliased prefix is usually real infrastructure (a CDN edge, for
    /// instance), so it stays in the scan — once, rather than a million times.
    /// Order is preserved, and the representative is the first address seen in
    /// that prefix, so the result is deterministic.
    pub fn collapse(&self, targets: &[Ipv6Addr]) -> Vec<Ipv6Addr> {
        let mut seen_prefix: BTreeSet<Ipv6Net> = BTreeSet::new();
        let mut out = Vec::with_capacity(targets.len());
        for &addr in targets {
            match self.covering(addr) {
                Some(net) => {
                    if seen_prefix.insert(net) {
                        out.push(addr);
                    }
                }
                None => out.push(addr),
            }
        }
        out
    }
}

/// What [`clean_seeds`] discarded, and why.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SeedReport {
    pub kept: usize,
    pub duplicates: usize,
    pub not_scannable: usize,
    /// Addresses folded into a representative of their aliased prefix.
    pub collapsed: usize,
}

/// Prepare a seed set: drop unroutable addresses and duplicates, then collapse
/// aliased prefixes.
///
/// Worth doing carefully, because 6SEVEN found seed composition dominates the
/// outcome — a seed list full of one CDN's aliased space produces a generator
/// that predicts only that CDN.
pub fn clean_seeds(seeds: &[Ipv6Addr], dealiaser: &Dealiaser) -> (Vec<Ipv6Addr>, SeedReport) {
    let mut report = SeedReport::default();
    let mut unique: Vec<Ipv6Addr> = Vec::with_capacity(seeds.len());
    let mut seen: BTreeSet<Ipv6Addr> = BTreeSet::new();
    for &addr in seeds {
        if !is_scannable(addr) {
            report.not_scannable += 1;
            continue;
        }
        if !seen.insert(addr) {
            report.duplicates += 1;
            continue;
        }
        unique.push(addr);
    }
    let before = unique.len();
    let collapsed = dealiaser.collapse(&unique);
    report.collapsed = before - collapsed.len();
    report.kept = collapsed.len();
    (collapsed, report)
}

// ---------------------------------------------------------------------------
// Target generation
// ---------------------------------------------------------------------------

/// A dense region of address space: a shared nybble prefix, the nybble that
/// varies within it, and which values have been seen there.
#[derive(Debug, Clone)]
struct Region {
    /// Nybbles fixed across the seeds in this region.
    prefix: Vec<u8>,
    /// A full seed from the region, supplying the nybbles after the varying
    /// one. Real deployments reuse suffixes, so copying one is a better guess
    /// than randomising.
    exemplar: [u8; NYBBLES],
    /// Nybble values already known at position `prefix.len()`.
    seen_values: BTreeSet<u8>,
    /// Seeds that fell in this region: the density estimate.
    weight: u32,
    /// Responsive addresses this region has produced, from feedback.
    hits: u32,
    /// Candidates generated from this region so far.
    tried: u32,
}

impl Region {
    /// How much this region is worth probing next.
    ///
    /// Seed density to begin with, then observed yield once there is feedback
    /// — the closed loop 6Sense (Williams et al., USENIX Security 2024) found
    /// matters more than the generator's opening guess.
    fn score(&self) -> f64 {
        let density = f64::from(self.weight);
        if self.tried == 0 {
            return density;
        }
        let yield_rate = f64::from(self.hits) / f64::from(self.tried);
        // Keep density in the term so an unproductive region decays rather
        // than being abandoned after one miss.
        density * (0.25 + yield_rate)
    }
}

/// A source of IPv6 candidates.
///
/// IPv6 cannot be swept, so the generator *is* the scan: whatever it proposes
/// is what gets probed, and everything else in the address space is never
/// looked at. That makes it the one component most worth replacing, which is
/// why it is a trait.
///
/// The contract is the online loop every published generator fits:
/// propose a budget of addresses, be told which answered, and let that change
/// what comes next. 6Sense (USENIX Sec 2024) and 6SEVEN (arXiv:2609.08098)
/// both work this way, as does the space-partitioning baseline here.
///
/// A generator must never propose the same address twice and never propose a
/// seed, because a budget spent re-probing a known address is a budget not
/// spent discovering anything.
pub trait Generator {
    /// Propose up to `budget` fresh addresses. Fewer is correct when the
    /// generator has nothing left worth guessing; padding with noise is not.
    fn generate(&mut self, budget: usize) -> Vec<Ipv6Addr>;

    /// Record whether a proposed address answered.
    fn reward(&mut self, addr: Ipv6Addr, responsive: bool);

    /// A short description for the operator, since which generator ran
    /// determines what the results mean.
    fn describe(&self) -> String;
}

/// Generates IPv6 candidates from a seed set.
///
/// Seeds are grouped by shared nybble prefixes; a prefix that several seeds
/// share, and where the next nybble varies between them, marks a region where
/// a provider is handing out addresses. Candidates fill in values not yet seen
/// at that position. This is the space-partitioning idea behind 6Gen and
/// 6Tree, kept simple on purpose: 6SEVEN found the surrounding pipeline
/// matters more, and [`TargetGenerator`] is meant to be replaceable.
#[derive(Debug, Clone, Default)]
pub struct TargetGenerator {
    regions: Vec<Region>,
    produced: BTreeSet<Ipv6Addr>,
    seeds: BTreeSet<Ipv6Addr>,
}

impl TargetGenerator {
    /// Shortest shared prefix considered a region. Below this, "shared" means
    /// little: everything shares the first few nybbles of 2000::/3.
    const MIN_PREFIX_NYBBLES: usize = 6;
    /// A region needs at least this many seeds to be believed.
    const MIN_SEEDS: u32 = 2;

    /// Learn regions from cleaned seeds (see [`clean_seeds`]).
    pub fn from_seeds(seeds: &[Ipv6Addr]) -> Self {
        let mut gen = TargetGenerator {
            seeds: seeds.iter().copied().collect(),
            ..Default::default()
        };

        // Group seeds by every prefix length worth considering, and keep the
        // groups where the next nybble actually varies.
        let mut groups: BTreeMap<Vec<u8>, Vec<[u8; NYBBLES]>> = BTreeMap::new();
        for &addr in seeds {
            let n = nybbles(addr);
            for len in Self::MIN_PREFIX_NYBBLES..NYBBLES {
                groups.entry(n[..len].to_vec()).or_default().push(n);
            }
        }

        for (prefix, members) in groups {
            if members.len() < Self::MIN_SEEDS as usize {
                continue;
            }
            let at = prefix.len();
            let seen_values: BTreeSet<u8> = members.iter().map(|m| m[at]).collect();
            // A region is interesting only where the next nybble varies and
            // there is still something unseen to guess at.
            if seen_values.len() < 2 || seen_values.len() == 16 {
                continue;
            }
            gen.regions.push(Region {
                prefix,
                exemplar: members[0],
                seen_values,
                weight: members.len() as u32,
                hits: 0,
                tried: 0,
            });
        }

        // Densest first, and prefer the more specific prefix on a tie so
        // candidates stay close to observed deployments.
        gen.regions.sort_by(|a, b| {
            b.score()
                .total_cmp(&a.score())
                .then(b.prefix.len().cmp(&a.prefix.len()))
        });
        gen
    }

    /// Regions learned.
    pub fn regions(&self) -> usize {
        self.regions.len()
    }

    /// Generate up to `budget` fresh candidate addresses.
    ///
    /// Candidates are drawn from the highest-scoring regions first, never
    /// repeat, and never return a seed. Returns fewer than asked when the
    /// regions are exhausted, rather than padding with noise.
    pub fn generate(&mut self, budget: usize) -> Vec<Ipv6Addr> {
        if budget == 0 || self.regions.is_empty() {
            return Vec::new();
        }
        self.regions.sort_by(|a, b| {
            b.score()
                .total_cmp(&a.score())
                .then(b.prefix.len().cmp(&a.prefix.len()))
        });

        let mut out: Vec<Ipv6Addr> = Vec::with_capacity(budget);
        // Round-robin across regions so one dense region cannot starve the
        // rest of the budget.
        let mut progress = true;
        while out.len() < budget && progress {
            progress = false;
            for region in &mut self.regions {
                if out.len() >= budget {
                    break;
                }
                let at = region.prefix.len();
                let next = (0u8..16).find(|v| !region.seen_values.contains(v));
                let Some(value) = next else { continue };

                let mut n = region.exemplar;
                n[..at].copy_from_slice(&region.prefix);
                n[at] = value;
                let candidate = from_nybbles(&n);

                region.seen_values.insert(value);
                region.tried += 1;
                if !is_scannable(candidate)
                    || self.seeds.contains(&candidate)
                    || !self.produced.insert(candidate)
                {
                    continue;
                }
                out.push(candidate);
                progress = true;
            }
        }
        out
    }

    /// Tell the generator how a candidate turned out, so productive regions
    /// get more of the next budget.
    pub fn reward(&mut self, addr: Ipv6Addr, responsive: bool) {
        if !responsive {
            return;
        }
        let n = nybbles(addr);
        for region in &mut self.regions {
            if n[..region.prefix.len()] == region.prefix[..] {
                region.hits += 1;
            }
        }
    }
}

impl Generator for TargetGenerator {
    fn generate(&mut self, budget: usize) -> Vec<Ipv6Addr> {
        TargetGenerator::generate(self, budget)
    }

    fn reward(&mut self, addr: Ipv6Addr, responsive: bool) {
        TargetGenerator::reward(self, addr, responsive)
    }

    fn describe(&self) -> String {
        format!(
            "space partitioning over {} learned region(s) (6Gen/6Tree-style)",
            self.regions()
        )
    }
}

#[cfg(test)]
mod tests {
    /// A generator that proposes a fixed list, for checking that the trait is
    /// enough to drive the pipeline — the property that makes it worth having.
    struct Fixed {
        queue: Vec<Ipv6Addr>,
        rewarded: Vec<(Ipv6Addr, bool)>,
    }

    impl Generator for Fixed {
        fn generate(&mut self, budget: usize) -> Vec<Ipv6Addr> {
            let take = budget.min(self.queue.len());
            self.queue.drain(..take).collect()
        }

        fn reward(&mut self, addr: Ipv6Addr, responsive: bool) {
            self.rewarded.push((addr, responsive));
        }

        fn describe(&self) -> String {
            "fixed list".to_string()
        }
    }

    #[test]
    fn the_trait_is_enough_to_drive_a_generator() {
        let addrs: Vec<Ipv6Addr> = ["2001:db8::1", "2001:db8::2", "2001:db8::3"]
            .iter()
            .map(|a| a.parse().unwrap())
            .collect();
        let mut g: Box<dyn Generator> = Box::new(Fixed {
            queue: addrs.clone(),
            rewarded: Vec::new(),
        });
        let first = g.generate(2);
        assert_eq!(first, addrs[..2]);
        for a in &first {
            g.reward(*a, true);
        }
        assert_eq!(g.generate(5).len(), 1, "a generator may return fewer");
        assert!(g.generate(5).is_empty(), "and nothing when exhausted");
        assert_eq!(g.describe(), "fixed list");
    }

    #[test]
    fn the_space_partitioner_satisfies_the_trait() {
        // A real provider prefix: 2001:db8::/32 is documentation space and
        // is filtered as unscannable, so candidates from it never survive.
        let seeds: Vec<Ipv6Addr> = [
            "2a00:1450:4001:801::1",
            "2a00:1450:4001:802::1",
            "2a00:1450:4001:803::1",
            "2a00:1450:4001:804::1",
        ]
        .iter()
        .map(|a| a.parse().unwrap())
        .collect();
        let mut g: Box<dyn Generator> = Box::new(TargetGenerator::from_seeds(&seeds));
        assert!(g.describe().contains("region"), "{}", g.describe());
        let produced = g.generate(8);
        assert!(!produced.is_empty());
        for a in &produced {
            assert!(!seeds.contains(a), "{a} is a seed");
            g.reward(*a, false);
        }
        let again = g.generate(8);
        for a in &again {
            assert!(!produced.contains(a), "{a} was proposed twice");
        }
    }

    use super::*;
    use std::str::FromStr;

    fn a(s: &str) -> Ipv6Addr {
        Ipv6Addr::from_str(s).unwrap()
    }
    fn net(s: &str) -> Ipv6Net {
        Ipv6Net::from_str(s).unwrap()
    }

    #[test]
    fn nybbles_round_trip() {
        for s in [
            "2001:db9::1",
            "2a00:1450:4001:80e::200e",
            "::1",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        ] {
            let addr = a(s);
            assert_eq!(from_nybbles(&nybbles(addr)), addr, "{s}");
        }
        // Most significant nybble first.
        assert_eq!(nybbles(a("2001::"))[..4], [2, 0, 0, 1]);
    }

    #[test]
    fn only_globally_routable_addresses_are_scannable() {
        assert!(is_scannable(a("2a00:1450:4001::1")));
        assert!(is_scannable(a("2606:4700::1")));
        // Never.
        assert!(!is_scannable(a("::1")), "loopback");
        assert!(!is_scannable(a("::")), "unspecified");
        assert!(!is_scannable(a("fe80::1")), "link-local");
        assert!(!is_scannable(a("fd00::1")), "unique-local");
        assert!(!is_scannable(a("fc00::1")), "unique-local");
        assert!(!is_scannable(a("ff02::1")), "multicast");
        assert!(!is_scannable(a("2001:db8::1")), "documentation");
        assert!(!is_scannable(a("::ffff:192.0.2.1")), "IPv4-mapped");
    }

    #[test]
    fn alias_probes_cover_every_branch_of_the_next_nybble() {
        let probes = alias_probes(net("2a00:1450:4001:80e::/64"), 42);
        assert_eq!(probes.len(), ALIAS_PROBES, "one per nybble value");

        // All inside the prefix.
        let prefix = net("2a00:1450:4001:80e::/64");
        assert!(probes.iter().all(|p| prefix.contains(p)));

        // The varying nybble (position 16, just past a /64) takes every value.
        let values: BTreeSet<u8> = probes.iter().map(|p| nybbles(*p)[16]).collect();
        assert_eq!(values.len(), 16, "every branch is probed: {values:?}");

        // Reproducible for a given seed, different for another.
        assert_eq!(probes, alias_probes(prefix, 42));
        assert_ne!(probes, alias_probes(prefix, 43));
    }

    #[test]
    fn alias_probes_respect_a_prefix_that_splits_a_nybble() {
        // /66 leaves two bits of nybble 16 fixed.
        let prefix = net("2a00:1450:4001:80e:4000::/66");
        let probes = alias_probes(prefix, 7);
        assert!(!probes.is_empty());
        assert!(
            probes.iter().all(|p| prefix.contains(p)),
            "a probe must never leave the prefix it is testing"
        );
    }

    #[test]
    fn alias_probes_of_a_single_address_are_empty() {
        assert!(alias_probes(net("2a00::1/128"), 1).is_empty());
    }

    #[test]
    fn classification_distinguishes_aliased_hosts_and_silence() {
        assert_eq!(Dealiaser::classify(&[true; 16]), Alias::Aliased);
        // One dropped packet should not change the verdict.
        let mut almost = [true; 16];
        almost[3] = false;
        assert_eq!(Dealiaser::classify(&almost), Alias::Aliased);
        // Half answering is a real host population.
        let mut half = [false; 16];
        half.iter_mut().take(8).for_each(|v| *v = true);
        assert_eq!(Dealiaser::classify(&half), Alias::Hosts);
        assert_eq!(Dealiaser::classify(&[false; 16]), Alias::Silent);
        assert_eq!(Dealiaser::classify(&[]), Alias::Silent);
    }

    #[test]
    fn aliased_prefixes_are_collapsed_to_one_target_not_dropped() {
        let mut d = Dealiaser::new();
        let cdn = net("2606:4700::/32");
        d.record(cdn, Alias::Aliased);
        // Only an aliased verdict is recorded.
        d.record(net("2a00:1450::/32"), Alias::Hosts);
        d.record(net("2a02::/16"), Alias::Silent);
        assert_eq!(d.aliased(), &[cdn]);
        // Recording twice does not duplicate.
        d.record(cdn, Alias::Aliased);
        assert_eq!(d.aliased().len(), 1);

        let targets = vec![
            a("2606:4700::1"),
            a("2606:4700::2"),
            a("2606:4700:10::99"),
            a("2a00:1450:4001::1"),
            a("2a00:1450:4001::2"),
        ];
        let kept = d.collapse(&targets);
        assert_eq!(
            kept,
            vec![
                a("2606:4700::1"),
                a("2a00:1450:4001::1"),
                a("2a00:1450:4001::2"),
            ],
            "one representative of the CDN survives; real hosts are untouched"
        );
        assert_eq!(d.covering(a("2606:4700::5")), Some(cdn));
        assert_eq!(d.covering(a("2a00:1450::1")), None);
    }

    #[test]
    fn seed_cleaning_reports_what_it_removed() {
        let mut d = Dealiaser::new();
        d.record(net("2606:4700::/32"), Alias::Aliased);

        let seeds = vec![
            a("2a00:1450:4001::1"),
            a("2a00:1450:4001::1"), // duplicate
            a("fe80::1"),           // link-local
            a("::1"),               // loopback
            a("2001:db8::5"),       // documentation
            a("2606:4700::1"),      // aliased
            a("2606:4700::2"),      // aliased, same prefix
            a("2a00:1450:4001::2"),
        ];
        let (kept, report) = clean_seeds(&seeds, &d);
        assert_eq!(report.duplicates, 1);
        assert_eq!(report.not_scannable, 3);
        assert_eq!(report.collapsed, 1, "two aliased seeds become one");
        assert_eq!(report.kept, 3);
        assert_eq!(kept.len(), report.kept);
        assert!(kept.contains(&a("2606:4700::1")));
        assert!(!kept.contains(&a("fe80::1")));
    }

    /// Seeds from one provider's /48, varying in the fourth group: the
    /// generator should guess further values in that position.
    fn provider_seeds() -> Vec<Ipv6Addr> {
        vec![
            a("2a00:1450:4001:801::1"),
            a("2a00:1450:4001:802::1"),
            a("2a00:1450:4001:803::1"),
            a("2a00:1450:4001:804::1"),
        ]
    }

    #[test]
    fn generates_unseen_addresses_in_a_dense_region() {
        let seeds = provider_seeds();
        let mut gen = TargetGenerator::from_seeds(&seeds);
        assert!(gen.regions() > 0, "a varying nybble should form a region");

        let candidates = gen.generate(8);
        assert!(!candidates.is_empty());
        for c in &candidates {
            assert!(
                net("2a00:1450:4001::/48").contains(c),
                "{c} left the observed region"
            );
            assert!(!seeds.contains(c), "{c} is a seed, not a prediction");
            assert!(is_scannable(*c));
        }
        // Never repeats across calls.
        let more = gen.generate(8);
        assert!(more.iter().all(|c| !candidates.contains(c)));
    }

    #[test]
    fn generation_is_deterministic_and_bounded() {
        let seeds = provider_seeds();
        let a1 = TargetGenerator::from_seeds(&seeds).generate(5);
        let a2 = TargetGenerator::from_seeds(&seeds).generate(5);
        assert_eq!(a1, a2, "same seeds must give the same plan");
        assert!(a1.len() <= 5);
        assert!(TargetGenerator::from_seeds(&seeds).generate(0).is_empty());
        // Exhaustion returns fewer rather than padding with noise.
        let huge = TargetGenerator::from_seeds(&seeds).generate(100_000);
        assert!(huge.len() < 100_000);
        assert_eq!(
            huge.iter().collect::<BTreeSet<_>>().len(),
            huge.len(),
            "no duplicates"
        );
    }

    #[test]
    fn too_few_or_too_uniform_seeds_produce_nothing() {
        // One seed: no variation to learn from.
        assert_eq!(TargetGenerator::from_seeds(&[a("2a00::1")]).regions(), 0);
        assert!(TargetGenerator::from_seeds(&[]).generate(5).is_empty());
        // Identical seeds: nothing varies.
        let same = vec![a("2a00:1450::1"), a("2a00:1450::1")];
        assert!(TargetGenerator::from_seeds(&same).generate(5).is_empty());
    }

    #[test]
    fn feedback_moves_budget_toward_regions_that_answer() {
        // Two provider blocks, equally dense.
        let seeds = vec![
            a("2a00:1450:1:1::1"),
            a("2a00:1450:1:2::1"),
            a("2a00:1450:1:3::1"),
            a("2620:11:1:1::1"),
            a("2620:11:1:2::1"),
            a("2620:11:1:3::1"),
        ];
        let mut gen = TargetGenerator::from_seeds(&seeds);
        let first = gen.generate(6);
        assert!(!first.is_empty());

        // Report every hit in the 2a00:: block and every miss in the other.
        for c in &first {
            let hit = net("2a00::/16").contains(c);
            gen.reward(*c, hit);
        }
        let next = gen.generate(4);
        let rewarded = next
            .iter()
            .filter(|c| net("2a00::/16").contains(*c))
            .count();
        assert!(
            rewarded * 2 >= next.len(),
            "the productive region should get at least half the budget: {next:?}"
        );
    }

    #[test]
    fn reward_only_credits_the_regions_containing_the_address() {
        let seeds = vec![
            a("2a00:1450:1:1::1"),
            a("2a00:1450:1:2::1"),
            a("2620:11:1:1::1"),
            a("2620:11:1:2::1"),
        ];
        let mut gen = TargetGenerator::from_seeds(&seeds);
        let before: Vec<u32> = gen.regions.iter().map(|r| r.hits).collect();
        gen.reward(a("2a00:1450:1:9::1"), true);
        let after: Vec<u32> = gen.regions.iter().map(|r| r.hits).collect();
        assert_ne!(before, after, "some region should be credited");
        for (i, region) in gen.regions.iter().enumerate() {
            let inside = nybbles(a("2a00:1450:1:9::1"))[..region.prefix.len()] == region.prefix[..];
            assert_eq!(
                region.hits > before[i],
                inside,
                "only containing regions are credited"
            );
        }
        // A miss changes nothing.
        let snapshot: Vec<u32> = gen.regions.iter().map(|r| r.hits).collect();
        gen.reward(a("2a00:1450:1:a::1"), false);
        assert_eq!(
            gen.regions.iter().map(|r| r.hits).collect::<Vec<_>>(),
            snapshot
        );
    }

    #[test]
    fn generated_candidates_never_include_unroutable_space() {
        // Seeds that vary in a position where filling the nybble could walk
        // into reserved space.
        let seeds = vec![a("fe80::1"), a("fe80::2"), a("2a00::1"), a("2a00::2")];
        let (clean, _) = clean_seeds(&seeds, &Dealiaser::new());
        let mut gen = TargetGenerator::from_seeds(&clean);
        assert!(gen.generate(32).iter().all(|c| is_scannable(*c)));
    }
}
