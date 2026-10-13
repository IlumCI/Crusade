//! Continuous scanning: which ports does *this* host get *today*?
//!
//! A one-shot scan picks a port list and runs. A map that stays current has a
//! harder problem: cover 65,536 ports across every host, forever, without
//! re-probing the same ports and without storing a per-host bitmap of what has
//! been tried.
//!
//! Censys (Durumeric et al., SIGCOMM 2025) solves the coverage half with
//! tiers: roughly 100 popular ports plus 100 IANA ports of interest every day,
//! a few hundred cloud-infrastructure ports on cloud ranges, and a background
//! sample of ~100 random ports per host per day that reaches the whole port
//! space in about nine months. That background sample is also where the
//! training data for prediction comes from (see [`crate::ports`]), so it earns
//! its bandwidth twice.
//!
//! "Random" is the part worth getting right. Sampling independently each day
//! repeats ports and leaves gaps forever (the coupon-collector problem), while
//! remembering what each host has seen costs 8 KiB of bitmap per host — 8 GiB
//! at a million hosts. Instead each host walks a *keyed permutation* of the
//! port space: a different order per host, every port exactly once per cycle,
//! derived from the host's address and a campaign salt. The only state is one
//! integer cursor, and any node can recompute the same schedule from the same
//! inputs — which is what makes it resumable after a restart and consistent
//! across several workers.

use std::net::IpAddr;

/// Ports in the 16-bit space.
pub const PORT_SPACE: u32 = 65_536;

/// A keyed permutation of all 65,536 ports.
///
/// A four-round Feistel network over the two halves of a 16-bit value. The
/// Feistel construction is a bijection whatever the round function does, so
/// every port appears exactly once per cycle by construction rather than by
/// luck — [`PortPermutation::nth`] can never collide within a cycle, and the
/// exhaustive test asserts it.
#[derive(Debug, Clone, Copy)]
pub struct PortPermutation {
    key: u64,
}

impl PortPermutation {
    /// Rounds. Four is the standard minimum for a Feistel network to mix both
    /// halves thoroughly; more would not change the bijection, only the
    /// apparent randomness.
    const ROUNDS: u32 = 4;

    /// A permutation keyed by an arbitrary value.
    pub fn with_key(key: u64) -> Self {
        PortPermutation { key }
    }

    /// The permutation for one host in one campaign.
    ///
    /// `salt` separates campaigns: changing it gives every host a fresh order,
    /// which is how an operator restarts coverage without re-probing in the
    /// same sequence.
    pub fn for_target(ip: IpAddr, salt: u64) -> Self {
        let mut key = salt.wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(31);
        let bytes = match ip {
            IpAddr::V4(a) => a.octets().to_vec(),
            IpAddr::V6(a) => a.octets().to_vec(),
        };
        for b in bytes {
            key ^= u64::from(b);
            key = key.wrapping_mul(0x1000_0000_01b3);
        }
        PortPermutation { key }
    }

    /// Round function: any mixing will do, since the Feistel structure
    /// supplies invertibility.
    fn round(&self, half: u8, round: u32) -> u8 {
        let mut x = u64::from(half) ^ (self.key.rotate_left(round * 7));
        x ^= x >> 13;
        x = x.wrapping_mul(0xff51_afd7_ed55_8ccd);
        x ^= x >> 17;
        (x & 0xff) as u8
    }

    /// The port at position `index` in this host's order.
    ///
    /// `index` wraps at [`PORT_SPACE`], so a cursor may run on forever: it
    /// simply starts the cycle again.
    pub fn nth(&self, index: u64) -> u16 {
        let value = (index % u64::from(PORT_SPACE)) as u16;
        let mut left = (value >> 8) as u8;
        let mut right = (value & 0xff) as u8;
        for r in 0..Self::ROUNDS {
            let next = left ^ self.round(right, r);
            left = right;
            right = next;
        }
        (u16::from(left) << 8) | u16::from(right)
    }

    /// `count` ports starting at `cursor`, in this host's order.
    ///
    /// No deduplication is needed or done: [`PortPermutation::nth`] is
    /// injective over one cycle, so any window of at most [`PORT_SPACE`]
    /// consecutive positions yields distinct ports. Asking for more than a
    /// full cycle returns a full cycle, since repeating it adds nothing.
    pub fn slice(&self, cursor: u64, count: usize) -> Vec<u16> {
        let count = count.min(PORT_SPACE as usize);
        (0..count as u64).map(|i| self.nth(cursor + i)).collect()
    }
}

/// Which schedule a batch of probes belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// The ports most services actually live on. Every pass.
    Hot,
    /// Ports that matter on cloud and hosting networks specifically.
    Cloud,
    /// A slice of the host's permutation, so coverage creeps across the whole
    /// port space and feeds the prediction model.
    Background,
}

impl Tier {
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Hot => "hot",
            Tier::Cloud => "cloud",
            Tier::Background => "background",
        }
    }
}

/// Ports worth probing on nearly every host: the common services, plus the
/// ones that are interesting out of proportion to how often they appear
/// (industrial protocols, databases, remote access).
pub const HOT_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465, 514, 587, 631, 636,
    873, 902, 989, 990, 993, 995, 1025, 1080, 1099, 1433, 1521, 1723, 1883, 2049, 2082, 2181, 2375,
    2376, 2404, 3000, 3128, 3306, 3389, 4444, 4786, 4840, 5000, 5006, 5007, 5432, 5555, 5601, 5672,
    5900, 5901, 5984, 6000, 6379, 6443, 7001, 7777, 8000, 8008, 8009, 8080, 8081, 8086, 8088, 8089,
    8443, 8500, 8888, 9000, 9001, 9042, 9090, 9092, 9100, 9200, 9300, 9418, 9443, 9600, 10000,
    11211, 15672, 16992, 20000, 27017, 27018, 44818, 47808, 50070, 61616,
];

/// Ports that matter specifically on cloud and hosting networks: orchestration,
/// metadata, service meshes and managed datastores.
pub const CLOUD_PORTS: &[u16] = &[
    2379, 2380, 4001, 4140, 4243, 5984, 6443, 6782, 6783, 7946, 8001, 8060, 8080, 8181, 8200, 8300,
    8301, 8302, 8500, 8501, 8600, 9001, 9080, 9090, 9093, 9099, 9115, 9121, 9187, 9273, 9411,
    10249, 10250, 10251, 10252, 10255, 10256, 10257, 10259, 15000, 15001, 15006, 15020, 15021,
    15090, 16686, 18080, 19999, 20001, 25000, 26257, 30000, 32768,
];

/// Large cloud and hosting networks.
///
/// Two things key off this: the cloud port tier applies on these networks, and
/// honeypot scoring treats industrial equipment hosted here as implausible.
/// Far from exhaustive — a short list of the operators whose address space is
/// unambiguously rented rather than physical.
pub const CLOUD_ASNS: &[(u32, &str)] = &[
    (16509, "Amazon"),
    (14618, "Amazon"),
    (15169, "Google"),
    (396982, "Google Cloud"),
    (8075, "Microsoft"),
    (14061, "DigitalOcean"),
    (16276, "OVH"),
    (24940, "Hetzner"),
    (63949, "Akamai/Linode"),
    (20473, "Vultr"),
    (45102, "Alibaba"),
    (132203, "Tencent"),
    (31898, "Oracle"),
    (51167, "Contabo"),
    (12876, "Scaleway"),
];

/// The operator of `asn`, when it is a known cloud or hosting network.
pub fn cloud_asn(asn: u32) -> Option<&'static str> {
    CLOUD_ASNS
        .iter()
        .find(|(candidate, _)| *candidate == asn)
        .map(|(_, name)| *name)
}

/// How many ports each tier contributes, and how far the background tier has
/// walked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TierBudget {
    /// Background ports per pass. Zero disables the background tier.
    pub background: usize,
    /// Whether this host is on a cloud/hosting network.
    pub cloud: bool,
}

impl Default for TierBudget {
    fn default() -> Self {
        TierBudget {
            background: 100,
            cloud: false,
        }
    }
}

/// One host's port plan for one pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Every port to probe, deduplicated and sorted.
    pub ports: Vec<u16>,
    /// Which tier contributed each port, for reporting and accounting.
    pub by_tier: Vec<(Tier, Vec<u16>)>,
    /// Where the background cursor should resume next pass.
    pub next_cursor: u64,
}

/// Build the plan for `ip` at background position `cursor`.
///
/// The hot tier always applies; the cloud tier only on cloud networks; the
/// background tier contributes `budget.background` ports from this host's own
/// permutation. Ports already covered by a higher tier are not probed twice,
/// but the cursor still advances past them — the walk is over the whole port
/// space, and skipping would make "covered" and "cursor" disagree.
pub fn plan(ip: IpAddr, cursor: u64, salt: u64, budget: &TierBudget) -> Plan {
    let mut by_tier: Vec<(Tier, Vec<u16>)> = Vec::new();
    let mut seen: Vec<u16> = Vec::new();

    let hot: Vec<u16> = HOT_PORTS.to_vec();
    seen.extend(&hot);
    by_tier.push((Tier::Hot, hot));

    if budget.cloud {
        let cloud: Vec<u16> = CLOUD_PORTS
            .iter()
            .copied()
            .filter(|p| !seen.contains(p))
            .collect();
        seen.extend(&cloud);
        by_tier.push((Tier::Cloud, cloud));
    }

    if budget.background > 0 {
        let perm = PortPermutation::for_target(ip, salt);
        let walked = perm.slice(cursor, budget.background);
        let fresh: Vec<u16> = walked
            .iter()
            .copied()
            .filter(|p| !seen.contains(p))
            .collect();
        seen.extend(&fresh);
        by_tier.push((Tier::Background, fresh));
    }

    seen.sort_unstable();
    seen.dedup();
    Plan {
        ports: seen,
        by_tier,
        next_cursor: cursor + budget.background as u64,
    }
}

/// How far background coverage has got, and when it will finish.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Coverage {
    /// Ports of the permutation walked so far, capped at the space size.
    pub covered: u32,
    /// Fraction of the port space covered, in `[0, 1]`.
    pub fraction: f64,
    /// Passes still needed for a full cycle at this budget, if it is non-zero.
    pub passes_remaining: Option<u64>,
}

/// Describe background progress for a host at `cursor`.
pub fn coverage(cursor: u64, per_pass: usize) -> Coverage {
    let covered = cursor.min(u64::from(PORT_SPACE)) as u32;
    let remaining = u64::from(PORT_SPACE).saturating_sub(cursor);
    Coverage {
        covered,
        fraction: f64::from(covered) / f64::from(PORT_SPACE),
        passes_remaining: (per_pass > 0).then(|| remaining.div_ceil(per_pass as u64)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::net::Ipv4Addr;

    const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));

    #[test]
    fn permutation_covers_every_port_exactly_once() {
        // The property the whole design rests on: one cycle visits all 65,536
        // ports with no repeat and no gap. Checked exhaustively.
        for key in [0u64, 1, 0xdead_beef, u64::MAX] {
            let perm = PortPermutation::with_key(key);
            let mut seen = vec![false; PORT_SPACE as usize];
            for i in 0..u64::from(PORT_SPACE) {
                let port = perm.nth(i);
                assert!(
                    !seen[port as usize],
                    "port {port} repeated within a cycle (key {key})"
                );
                seen[port as usize] = true;
            }
            assert!(seen.iter().all(|&v| v), "key {key} left ports unvisited");
        }
    }

    #[test]
    fn cycle_wraps_rather_than_running_out() {
        let perm = PortPermutation::with_key(99);
        assert_eq!(perm.nth(0), perm.nth(u64::from(PORT_SPACE)));
        assert_eq!(perm.nth(5), perm.nth(u64::from(PORT_SPACE) + 5));
        // A slice longer than the space is capped at one full cycle, and a
        // window of a whole cycle still holds every port exactly once.
        let whole = perm.slice(0, PORT_SPACE as usize + 500);
        assert_eq!(whole.len(), PORT_SPACE as usize);
        let distinct: HashSet<u16> = whole.iter().copied().collect();
        assert_eq!(distinct.len(), PORT_SPACE as usize);

        // A window that straddles the cycle boundary is still duplicate-free.
        let straddle = perm.slice(u64::from(PORT_SPACE) - 50, 100);
        let distinct: HashSet<u16> = straddle.iter().copied().collect();
        assert_eq!(distinct.len(), straddle.len(), "{straddle:?}");
    }

    #[test]
    fn different_hosts_walk_different_orders() {
        let a = PortPermutation::for_target(IP, 1);
        let b = PortPermutation::for_target(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 8)), 1);
        let first_a: Vec<u16> = (0..32).map(|i| a.nth(i)).collect();
        let first_b: Vec<u16> = (0..32).map(|i| b.nth(i)).collect();
        assert_ne!(
            first_a, first_b,
            "neighbouring addresses must not be probed in lockstep"
        );
        // IPv6 is keyed too.
        let v6 = PortPermutation::for_target("2a00:1450::1".parse().unwrap(), 1);
        assert_ne!((0..32).map(|i| v6.nth(i)).collect::<Vec<_>>(), first_a);
    }

    #[test]
    fn the_salt_reshuffles_a_host() {
        let first = PortPermutation::for_target(IP, 1);
        let second = PortPermutation::for_target(IP, 2);
        assert_ne!(
            (0..64).map(|i| first.nth(i)).collect::<Vec<_>>(),
            (0..64).map(|i| second.nth(i)).collect::<Vec<_>>(),
            "a new campaign salt should give a fresh order"
        );
    }

    #[test]
    fn the_schedule_is_reproducible() {
        // The property that makes it resumable after a restart, and consistent
        // across workers: same inputs, same plan. No stored state needed.
        let p1 = plan(IP, 1_200, 7, &TierBudget::default());
        let p2 = plan(IP, 1_200, 7, &TierBudget::default());
        assert_eq!(p1, p2);
        let perm = PortPermutation::for_target(IP, 7);
        assert_eq!(perm.slice(1_200, 4), perm.slice(1_200, 4));
    }

    #[test]
    fn consecutive_passes_do_not_re_probe_the_background() {
        let budget = TierBudget {
            background: 100,
            cloud: false,
        };
        let first = plan(IP, 0, 3, &budget);
        let second = plan(IP, first.next_cursor, 3, &budget);
        assert_eq!(first.next_cursor, 100);
        assert_eq!(second.next_cursor, 200);

        let bg = |p: &Plan| -> Vec<u16> {
            p.by_tier
                .iter()
                .find(|(t, _)| *t == Tier::Background)
                .map(|(_, ports)| ports.clone())
                .unwrap_or_default()
        };
        let a: HashSet<u16> = bg(&first).into_iter().collect();
        let b: HashSet<u16> = bg(&second).into_iter().collect();
        assert!(
            a.is_disjoint(&b),
            "the second pass must probe different ports: {:?}",
            a.intersection(&b).collect::<Vec<_>>()
        );
    }

    #[test]
    fn tiers_contribute_without_overlapping() {
        let budget = TierBudget {
            background: 200,
            cloud: true,
        };
        let p = plan(IP, 0, 1, &budget);

        // Every port appears once overall.
        let mut all = p.ports.clone();
        all.dedup();
        assert_eq!(all.len(), p.ports.len(), "the plan has duplicates");

        // And once across the tiers: a hot port is not re-probed as cloud.
        let mut from_tiers: Vec<u16> = p.by_tier.iter().flat_map(|(_, v)| v.clone()).collect();
        from_tiers.sort_unstable();
        let before = from_tiers.len();
        from_tiers.dedup();
        assert_eq!(before, from_tiers.len(), "tiers overlap");
        assert_eq!(from_tiers, p.ports);

        // 8080 is in both lists, so it must be credited to the hot tier only.
        let cloud = p
            .by_tier
            .iter()
            .find(|(t, _)| *t == Tier::Cloud)
            .map(|(_, v)| v.clone())
            .unwrap();
        assert!(HOT_PORTS.contains(&8080) && CLOUD_PORTS.contains(&8080));
        assert!(!cloud.contains(&8080));
    }

    #[test]
    fn cloud_tier_applies_only_to_cloud_networks() {
        let plain = plan(IP, 0, 1, &TierBudget::default());
        assert!(plain.by_tier.iter().all(|(t, _)| *t != Tier::Cloud));
        let cloud = plan(
            IP,
            0,
            1,
            &TierBudget {
                background: 0,
                cloud: true,
            },
        );
        assert!(cloud.by_tier.iter().any(|(t, _)| *t == Tier::Cloud));
        assert!(cloud.ports.len() > plain.ports.len() - HOT_PORTS.len());
    }

    #[test]
    fn a_zero_background_budget_probes_only_the_fixed_tiers() {
        let p = plan(
            IP,
            0,
            1,
            &TierBudget {
                background: 0,
                cloud: false,
            },
        );
        assert!(p.by_tier.iter().all(|(t, _)| *t == Tier::Hot));
        let mut expect = HOT_PORTS.to_vec();
        expect.sort_unstable();
        expect.dedup();
        assert_eq!(p.ports, expect);
        assert_eq!(p.next_cursor, 0, "the cursor must not move");
    }

    #[test]
    fn coverage_reports_progress_and_completion() {
        let c = coverage(0, 100);
        assert_eq!(c.covered, 0);
        assert_eq!(c.fraction, 0.0);
        assert_eq!(c.passes_remaining, Some(656), "65536 / 100, rounded up");

        let c = coverage(32_768, 100);
        assert_eq!(c.covered, 32_768);
        assert!((c.fraction - 0.5).abs() < 1e-9);
        assert_eq!(c.passes_remaining, Some(328));

        // Done, and not over-reported past a full cycle.
        let c = coverage(u64::from(PORT_SPACE), 100);
        assert_eq!(c.covered, PORT_SPACE);
        assert_eq!(c.fraction, 1.0);
        assert_eq!(c.passes_remaining, Some(0));
        assert_eq!(coverage(999_999, 100).covered, PORT_SPACE);
        assert_eq!(coverage(999_999, 100).fraction, 1.0);

        // No background tier, no completion estimate to give.
        assert_eq!(coverage(0, 0).passes_remaining, None);
    }

    #[test]
    fn hot_and_cloud_lists_are_sane() {
        for list in [HOT_PORTS, CLOUD_PORTS] {
            let mut sorted = list.to_vec();
            sorted.sort_unstable();
            let before = sorted.len();
            sorted.dedup();
            assert_eq!(before, sorted.len(), "duplicate port in a tier list");
            assert!(sorted.iter().all(|p| *p > 0), "port 0 is not scannable");
        }
        // The hot list is meant to be the daily sweep, so keep it bounded.
        assert!(HOT_PORTS.len() <= 200, "hot tier has grown too large");
    }

    #[test]
    fn cloud_asns_are_looked_up_by_number() {
        assert_eq!(cloud_asn(16509), Some("Amazon"));
        assert_eq!(cloud_asn(24940), Some("Hetzner"));
        assert_eq!(cloud_asn(3320), None, "a telco is not a cloud network");
        // No duplicate entries, which would make the first silently win.
        let mut numbers: Vec<u32> = CLOUD_ASNS.iter().map(|(n, _)| *n).collect();
        numbers.sort_unstable();
        let before = numbers.len();
        numbers.dedup();
        assert_eq!(before, numbers.len());
    }
}
