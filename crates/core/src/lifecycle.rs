//! Service lifecycle across rescans: live -> pending -> evicted.
//!
//! Follows the state machine Censys published (Durumeric et al., SIGCOMM 2025,
//! s4.4): a service that stops answering is not dropped on the first miss, since
//! packet loss, rate limiting and transient outages are common. It is marked
//! *pending* and kept visible; if it is still silent after
//! [`Lifecycle::evict_after`] it is *evicted* from the host's current state.
//! A host with no services left whose last answer is older than
//! [`Lifecycle::forget_after`] can be removed from the index altogether.
//!
//! Only ports the rescan actually probed can become pending: a scan of port 80
//! says nothing about a previously seen port 22.

use std::collections::BTreeSet;

use time::{Duration, OffsetDateTime};

use crate::model::{Host, Service, Transport};

/// Eviction policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lifecycle {
    /// How long a probed-but-silent service stays pending before eviction.
    pub evict_after: Duration,
    /// How long a host with no services is kept after its last answer.
    pub forget_after: Duration,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Lifecycle {
            evict_after: Duration::hours(72),
            forget_after: Duration::days(60),
        }
    }
}

/// The ports a scan run actually probed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Scope {
    pub tcp: BTreeSet<u16>,
    pub udp: BTreeSet<u16>,
}

impl Scope {
    pub fn new(tcp: impl IntoIterator<Item = u16>, udp: impl IntoIterator<Item = u16>) -> Self {
        Scope {
            tcp: tcp.into_iter().collect(),
            udp: udp.into_iter().collect(),
        }
    }

    pub fn covers(&self, port: u16, transport: Transport) -> bool {
        match transport {
            Transport::Tcp => self.tcp.contains(&port),
            Transport::Udp => self.udp.contains(&port),
        }
    }
}

/// What happened to a previously known service during a merge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    /// Probed, silent for the first time: now pending.
    Pending { port: u16, transport: Transport },
    /// Pending for longer than `evict_after`: removed.
    Evicted { port: u16, transport: Transport },
}

/// Merge a rescan result into the prior state of the same host.
///
/// `after` holds only the services that answered in this run. Prior services
/// that did not answer are kept unchanged when their port was not probed,
/// kept as pending when probed (preserving the original pending time), or
/// evicted once pending for at least `policy.evict_after`. A service that
/// answers again is live again (it arrives in `after` without `pending_since`).
pub fn merge(
    before: &Host,
    mut after: Host,
    scope: &Scope,
    now: OffsetDateTime,
    policy: &Lifecycle,
) -> (Host, Vec<Change>) {
    let mut changes = Vec::new();
    let seen: BTreeSet<(u16, Transport)> = after
        .services
        .iter()
        .map(|s| (s.port, s.transport))
        .collect();
    for prior in &before.services {
        if seen.contains(&(prior.port, prior.transport)) {
            continue;
        }
        if !scope.covers(prior.port, prior.transport) {
            after.services.push(prior.clone());
            continue;
        }
        let since = prior.pending_since.unwrap_or(now);
        if now - since >= policy.evict_after {
            changes.push(Change::Evicted {
                port: prior.port,
                transport: prior.transport,
            });
            continue;
        }
        if prior.pending_since.is_none() {
            changes.push(Change::Pending {
                port: prior.port,
                transport: prior.transport,
            });
        }
        let mut kept: Service = prior.clone();
        kept.pending_since = Some(since);
        after.services.push(kept);
    }
    after
        .services
        .sort_by_key(|s| (s.transport == Transport::Udp, s.port));

    // Enrichment that the rescan could not redo (e.g. no reverse DNS answer)
    // falls back to what was known.
    if after.hostnames.is_empty() {
        after.hostnames = before.hostnames.clone();
    }
    if after.domains.is_empty() {
        after.domains = before.domains.clone();
    }
    (after, changes)
}

/// Last time any service on the host was observed answering.
pub fn last_alive(host: &Host) -> Option<OffsetDateTime> {
    host.services.iter().map(|s| s.observed_at).max()
}

/// Whether a host whose merged state has no services should leave the index.
pub fn should_forget(
    before: &Host,
    merged: &Host,
    now: OffsetDateTime,
    policy: &Lifecycle,
) -> bool {
    merged.services.is_empty()
        && now - last_alive(before).unwrap_or(before.last_seen) >= policy.forget_after
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn at(h: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000 + h * 3600).unwrap()
    }

    fn host(ports: &[(u16, Transport)], seen: OffsetDateTime) -> Host {
        let mut h = Host::new("192.0.2.1".parse::<IpAddr>().unwrap());
        for &(p, t) in ports {
            let mut s = Service::new(p, t);
            s.observed_at = seen;
            h.services.push(s);
        }
        h
    }

    const TCP: Transport = Transport::Tcp;
    const UDP: Transport = Transport::Udp;

    fn ports_of(h: &Host) -> Vec<(u16, Transport)> {
        h.services.iter().map(|s| (s.port, s.transport)).collect()
    }

    fn svc(h: &Host, port: u16, transport: Transport) -> Option<&Service> {
        h.services
            .iter()
            .find(|s| s.port == port && s.transport == transport)
    }

    #[test]
    fn unprobed_ports_are_untouched() {
        let before = host(&[(22, TCP), (80, TCP)], at(0));
        let after = host(&[(80, TCP)], at(10));
        let (m, ch) = merge(
            &before,
            after,
            &Scope::new([80], []),
            at(10),
            &Lifecycle::default(),
        );
        assert!(ch.is_empty(), "port 22 was never probed");
        assert_eq!(ports_of(&m), vec![(22, TCP), (80, TCP)]);
        assert!(m.services.iter().all(|s| s.pending_since.is_none()));
    }

    #[test]
    fn probed_and_silent_becomes_pending_then_evicted() {
        let policy = Lifecycle::default();
        let scope = Scope::new([22, 80], []);
        let before = host(&[(22, TCP), (80, TCP)], at(0));

        // First miss: pending, still listed.
        let (pending, ch) = merge(&before, host(&[(80, TCP)], at(1)), &scope, at(1), &policy);
        assert_eq!(
            ch,
            vec![Change::Pending {
                port: 22,
                transport: TCP
            }]
        );
        let p22 = svc(&pending, 22, TCP).unwrap();
        assert_eq!(p22.pending_since, Some(at(1)));
        assert_eq!(p22.observed_at, at(0), "last answer time is preserved");

        // Still silent 2 h later: pending time is not refreshed, no new change.
        let (still, ch) = merge(&pending, host(&[(80, TCP)], at(3)), &scope, at(3), &policy);
        assert!(ch.is_empty());
        assert_eq!(svc(&still, 22, TCP).unwrap().pending_since, Some(at(1)));

        // Past the 72 h window: evicted.
        let (gone, ch) = merge(&still, host(&[(80, TCP)], at(73)), &scope, at(73), &policy);
        assert_eq!(
            ch,
            vec![Change::Evicted {
                port: 22,
                transport: TCP
            }]
        );
        assert_eq!(ports_of(&gone), vec![(80, TCP)]);
    }

    #[test]
    fn answering_again_clears_pending() {
        let scope = Scope::new([22], []);
        let mut before = host(&[(22, TCP)], at(0));
        before.services[0].pending_since = Some(at(1));
        let (m, ch) = merge(
            &before,
            host(&[(22, TCP)], at(5)),
            &scope,
            at(5),
            &Lifecycle::default(),
        );
        assert!(ch.is_empty());
        let s = svc(&m, 22, TCP).unwrap();
        assert_eq!(s.pending_since, None);
        assert_eq!(s.observed_at, at(5));
    }

    #[test]
    fn transport_is_part_of_identity() {
        let scope = Scope::new([53], [53]);
        let before = host(&[(53, TCP), (53, UDP)], at(0));
        let (m, ch) = merge(
            &before,
            host(&[(53, UDP)], at(1)),
            &scope,
            at(1),
            &Lifecycle::default(),
        );
        assert_eq!(
            ch,
            vec![Change::Pending {
                port: 53,
                transport: TCP
            }]
        );
        assert_eq!(svc(&m, 53, UDP).unwrap().pending_since, None);
        assert_eq!(svc(&m, 53, TCP).unwrap().pending_since, Some(at(1)));
        // TCP sorts before UDP so the host page lists them predictably.
        assert_eq!(ports_of(&m), vec![(53, TCP), (53, UDP)]);
    }

    #[test]
    fn enrichment_falls_back_to_prior_values() {
        let mut before = host(&[(80, TCP)], at(0));
        before.hostnames = vec!["a.example.com".into()];
        before.domains = vec!["example.com".into()];

        let (m, _) = merge(
            &before,
            host(&[(80, TCP)], at(1)),
            &Scope::new([80], []),
            at(1),
            &Lifecycle::default(),
        );
        assert_eq!(m.hostnames, vec!["a.example.com"]);
        assert_eq!(m.domains, vec!["example.com"]);

        let mut fresh = host(&[(80, TCP)], at(1));
        fresh.hostnames = vec!["b.example.com".into()];
        let (m, _) = merge(
            &before,
            fresh,
            &Scope::new([80], []),
            at(1),
            &Lifecycle::default(),
        );
        assert_eq!(m.hostnames, vec!["b.example.com"], "a new answer wins");
    }

    #[test]
    fn forget_only_after_the_window_with_nothing_left() {
        let policy = Lifecycle::default();
        let scope = Scope::new([80], []);
        let before = host(&[(80, TCP)], at(0));

        // Evicted at +73 h, but the host is kept: it answered recently.
        let mut pending = before.clone();
        pending.services[0].pending_since = Some(at(1));
        let (empty, _) = merge(&pending, host(&[], at(73)), &scope, at(73), &policy);
        assert!(empty.services.is_empty());
        assert!(!should_forget(&pending, &empty, at(73), &policy));

        // Past 60 days with no services: forgettable.
        let far = at(24 * 61);
        assert!(should_forget(&pending, &empty, far, &policy));

        // A host that still has services is never forgotten.
        let (live, _) = merge(&before, host(&[(80, TCP)], far), &scope, far, &policy);
        assert!(!should_forget(&before, &live, far, &policy));
    }

    #[test]
    fn last_alive_is_the_newest_observation() {
        let mut h = host(&[(22, TCP), (80, TCP)], at(0));
        h.services[1].observed_at = at(9);
        assert_eq!(last_alive(&h), Some(at(9)));
        assert_eq!(last_alive(&host(&[], at(0))), None);
    }

    #[test]
    fn scope_covers_only_its_own_transport() {
        let s = Scope::new([80], [53]);
        assert!(s.covers(80, TCP));
        assert!(!s.covers(80, UDP));
        assert!(s.covers(53, UDP));
        assert!(!s.covers(53, TCP));
        assert!(!Scope::default().covers(80, TCP));
    }
}
