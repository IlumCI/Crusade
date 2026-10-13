//! How often to come back to a host.
//!
//! A single interval for the whole index is wrong in both directions at once.
//! A cloud instance can be a different machine by tomorrow, so a weekly
//! revisit records fiction; a colocated mail server has looked the same for
//! three years, so a daily revisit spends bandwidth to learn nothing. Richter
//! et al. (IMC 2016) and Padmanabhan et al. (IMC 2016, CoNEXT 2020) measure
//! how differently address blocks churn depending on what they are for, which
//! is the signal this module turns into a schedule.
//!
//! Two inputs, in order of authority:
//!
//! 1. **What the host did.** Whether the last few scans found it changed is
//!    direct evidence about this host, and it beats any inference from its
//!    address. A host is watched more often while it keeps changing and less
//!    often the longer it stays the same, bounded at both ends.
//! 2. **What kind of network it is in.** Until there is scan history there is
//!    nothing else to go on, so the network class supplies the starting
//!    interval: a prior, not a verdict.
//!
//! The adaptation is deliberately asymmetric. Backing off happens slowly, one
//! step per unchanged scan, because a host that has been quiet for a month may
//! still change tomorrow. Coming back happens immediately, in one step to the
//! minimum, because the moment a host is seen changing, everything recorded
//! about it is suspect. Treating the two directions the same would mean either
//! trusting stale records for days after a change or never saving any
//! bandwidth at all.

use std::time::Duration;

/// What kind of network an address sits in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkClass {
    /// Cloud or hosting: instances come and go, and an address is reassigned
    /// to an unrelated tenant without notice.
    Cloud,
    /// Residential or mobile access networks, where the address is leased to
    /// a subscriber and moves between them.
    Residential,
    /// Everything else: colocation, enterprise, academic. Stable by default
    /// because most of the index is, and because being wrong here costs a
    /// stale record rather than a wasted scan.
    Stable,
}

impl NetworkClass {
    pub fn as_str(self) -> &'static str {
        match self {
            NetworkClass::Cloud => "cloud",
            NetworkClass::Residential => "residential",
            NetworkClass::Stable => "stable",
        }
    }

    /// The interval to start a host at, before it has any scan history.
    pub fn initial(self) -> Duration {
        match self {
            NetworkClass::Cloud => Duration::from_secs(12 * 3600),
            NetworkClass::Residential => Duration::from_secs(24 * 3600),
            NetworkClass::Stable => Duration::from_secs(72 * 3600),
        }
    }
}

/// Substrings in a reverse-DNS name that mark an access network.
///
/// These are the conventions access providers use in generated PTR records —
/// the only hint available about a block's purpose without a routing dataset.
/// Matching is on the name's labels so `dsl` in `handsless.example.com` does
/// not count.
const RESIDENTIAL_MARKERS: &[&str] = &[
    "dsl",
    "adsl",
    "vdsl",
    "dyn",
    "dynamic",
    "dial",
    "pool",
    "cable",
    "cpe",
    "broadband",
    "subscriber",
    "client",
    "customer",
    "res",
    "retail",
    "mobile",
    "lte",
    "gprs",
    "umts",
    "wifi",
    "fibre",
    "fiber",
    "ftth",
    "docsis",
    "bbcust",
];

/// Substrings that mark hosting or cloud, where a name is available.
const HOSTING_MARKERS: &[&str] = &[
    "compute",
    "cloud",
    "vps",
    "server",
    "srv",
    "host",
    "hosted",
    "hosting",
    "colo",
    "dedi",
    "dedicated",
    "instance",
    "node",
];

/// Classify a host from its ASN and reverse-DNS name.
///
/// The ASN decides when it is a known cloud, because that is a fact rather
/// than a guess. Otherwise the name is read, and in the common case where
/// there is neither a known ASN nor a name, the host is treated as stable —
/// the conservative direction, since the cost of being wrong is a record that
/// goes stale rather than scans nobody asked for.
pub fn classify(asn: Option<u32>, hostname: Option<&str>) -> NetworkClass {
    if asn.and_then(crate::schedule::cloud_asn).is_some() {
        return NetworkClass::Cloud;
    }
    if let Some(name) = hostname {
        let labels: Vec<String> = name
            .to_ascii_lowercase()
            .split('.')
            .map(|l| l.to_string())
            .collect();
        // Access-network markers first: a name can carry both ("dsl" inside a
        // hosting provider's domain), and what the address is *used for*
        // decides how fast it turns over.
        if labels
            .iter()
            .any(|l| RESIDENTIAL_MARKERS.iter().any(|m| label_marks(l, m)))
        {
            return NetworkClass::Residential;
        }
        if labels
            .iter()
            .any(|l| HOSTING_MARKERS.iter().any(|m| label_marks(l, m)))
        {
            return NetworkClass::Cloud;
        }
    }
    NetworkClass::Stable
}

/// Whether a DNS label marks a provider convention.
///
/// A label counts when the marker is the whole label, or is separated from the
/// rest by a non-letter — `dsl`, `dsl-12-34`, `host12`. Requiring a boundary
/// is what keeps `res` out of `research` and `dyn` out of `dynamics`.
fn label_marks(label: &str, marker: &str) -> bool {
    let Some(at) = label.find(marker) else {
        return false;
    };
    let before_ok = at == 0
        || !label[..at]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_ascii_alphabetic());
    let after = at + marker.len();
    let after_ok = after == label.len()
        || !label[after..]
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic());
    before_ok && after_ok
}

/// Interval bounds, so adaptation cannot run away in either direction.
pub const MIN_INTERVAL: Duration = Duration::from_secs(6 * 3600);
pub const MAX_INTERVAL: Duration = Duration::from_secs(21 * 86_400);
/// How much the interval grows per scan that found nothing new.
const BACKOFF: f64 = 1.5;

/// Decide a host's next interval from its class and what the last scan found.
///
/// `current` is what the host was on, or `None` for a host with no history.
pub fn next_interval(class: NetworkClass, current: Option<Duration>, changed: bool) -> Duration {
    let Some(current) = current else {
        return class.initial().clamp(MIN_INTERVAL, MAX_INTERVAL);
    };
    if changed {
        // Straight back to the floor. Something moved, so every other record
        // about this host is now a guess about a machine that has changed.
        return MIN_INTERVAL;
    }
    let grown = Duration::from_secs_f64(current.as_secs_f64() * BACKOFF);
    grown.clamp(MIN_INTERVAL, MAX_INTERVAL)
}

/// How many unchanged scans it takes to reach the ceiling from a class's
/// starting interval. Useful for explaining the schedule to an operator.
pub fn scans_to_ceiling(class: NetworkClass) -> u32 {
    let mut interval = class.initial().clamp(MIN_INTERVAL, MAX_INTERVAL);
    let mut n = 0;
    while interval < MAX_INTERVAL {
        interval = next_interval(class, Some(interval), false);
        n += 1;
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_known_cloud_asn_is_cloud_whatever_it_is_called() {
        assert_eq!(classify(Some(16509), None), NetworkClass::Cloud);
        assert_eq!(
            classify(Some(16509), Some("mail.example.com")),
            NetworkClass::Cloud
        );
    }

    #[test]
    fn provider_naming_conventions_are_read() {
        assert_eq!(
            classify(None, Some("dsl-1-2-3-4.example.net")),
            NetworkClass::Residential
        );
        assert_eq!(
            classify(None, Some("pool-72-93-1-2.bstnma.east.example")),
            NetworkClass::Residential
        );
        assert_eq!(
            classify(None, Some("vps1234.hosting.example")),
            NetworkClass::Cloud
        );
    }

    /// The marker has to be a label of its own, or bounded inside one. A word
    /// that merely contains it is not evidence.
    #[test]
    fn a_marker_inside_a_word_does_not_count() {
        assert_eq!(
            classify(None, Some("research.university.example")),
            NetworkClass::Stable
        );
        assert_eq!(
            classify(None, Some("dynamics-crm.example.com")),
            NetworkClass::Stable
        );
        assert_eq!(
            classify(None, Some("hostel.example.com")),
            NetworkClass::Stable
        );
    }

    #[test]
    fn nothing_known_means_stable() {
        assert_eq!(classify(None, None), NetworkClass::Stable);
        assert_eq!(
            classify(Some(64496), Some("a.example")),
            NetworkClass::Stable
        );
    }

    /// An access network inside a hosting provider's domain is still an
    /// access network: what the address is used for decides its churn.
    #[test]
    fn access_markers_win_over_hosting_markers() {
        assert_eq!(
            classify(None, Some("dsl-5-6.servers.example")),
            NetworkClass::Residential
        );
    }

    #[test]
    fn a_new_host_starts_at_its_classs_interval() {
        assert_eq!(
            next_interval(NetworkClass::Cloud, None, false),
            Duration::from_secs(12 * 3600)
        );
        assert_eq!(
            next_interval(NetworkClass::Stable, None, false),
            Duration::from_secs(72 * 3600)
        );
    }

    #[test]
    fn an_unchanged_host_is_visited_less_often() {
        let first = next_interval(NetworkClass::Cloud, None, false);
        let second = next_interval(NetworkClass::Cloud, Some(first), false);
        assert!(second > first, "{second:?} vs {first:?}");
    }

    /// Backing off is slow and returning is immediate: the asymmetry is the
    /// point, since a host seen changing makes every record about it suspect.
    #[test]
    fn a_change_resets_to_the_floor_in_one_step() {
        let mut interval = NetworkClass::Stable.initial();
        for _ in 0..10 {
            interval = next_interval(NetworkClass::Stable, Some(interval), false);
        }
        assert_eq!(interval, MAX_INTERVAL);
        assert_eq!(
            next_interval(NetworkClass::Stable, Some(interval), true),
            MIN_INTERVAL
        );
    }

    #[test]
    fn intervals_stay_within_their_bounds() {
        for class in [
            NetworkClass::Cloud,
            NetworkClass::Residential,
            NetworkClass::Stable,
        ] {
            let mut interval = class.initial();
            for _ in 0..100 {
                interval = next_interval(class, Some(interval), false);
                assert!(
                    interval >= MIN_INTERVAL && interval <= MAX_INTERVAL,
                    "{interval:?}"
                );
            }
            let hit = next_interval(class, Some(MIN_INTERVAL), true);
            assert_eq!(hit, MIN_INTERVAL);
        }
    }

    /// A cloud host reaches the ceiling later than a stable one, because it
    /// starts closer to the floor — the class is a prior on churn, and the
    /// schedule inherits it for as long as nothing contradicts it.
    #[test]
    fn a_cloud_host_takes_longer_to_be_trusted() {
        assert!(
            scans_to_ceiling(NetworkClass::Cloud) > scans_to_ceiling(NetworkClass::Stable),
            "{} vs {}",
            scans_to_ceiling(NetworkClass::Cloud),
            scans_to_ceiling(NetworkClass::Stable)
        );
    }
}
