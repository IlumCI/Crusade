//! UDP recon plumbing (no sockets here).
//!
//! UDP scanning is "send a protocol-specific probe, see whether a reply comes
//! back"; the probes themselves live in the sibling `probe` crate. This module
//! provides only the target/port plumbing: the common recon ports and a helper
//! that turns a set of hosts and ports into a blocklist-clean `(ip, port)`
//! worklist.
//!
//! The mandatory blocklist applies here exactly as it does to TCP: the worklist
//! builder drops every address the [`Blocklist`] forbids, so a UDP probe is
//! never aimed at a blocked host. (`filter_blocked` is proto-agnostic and works
//! on a UDP worklist unchanged.)

use std::net::IpAddr;

use crate::blocklist::Blocklist;

/// The common UDP ports worth a recon probe: DNS (53), NTP (123), NetBIOS (137),
/// SNMP (161), IKE (500), SSDP/UPnP (1900) and mDNS (5353). These are the
/// services that typically answer an unsolicited UDP probe and are frequently
/// found exposed.
pub fn default_udp_ports() -> Vec<u16> {
    vec![53, 123, 137, 161, 500, 1900, 5353]
}

/// Build a UDP `(ip, port)` worklist for `ips` × `ports`, with every blocklisted
/// address removed up front. The result can be fed to the `probe` crate's UDP
/// probing; it carries only addresses the blocklist permits.
pub fn udp_worklist(ips: &[IpAddr], ports: &[u16], bl: &Blocklist) -> Vec<(IpAddr, u16)> {
    let mut out = Vec::new();
    for &ip in ips {
        if bl.is_blocked(ip) {
            continue;
        }
        for &port in ports {
            out.push((ip, port));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sweep::filter_blocked;
    use std::net::Ipv4Addr;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn default_udp_ports_are_the_common_recon_set() {
        let ports = default_udp_ports();
        assert_eq!(ports, vec![53, 123, 137, 161, 500, 1900, 5353]);
    }

    #[test]
    fn udp_worklist_honours_the_blocklist() {
        let bl = Blocklist::new(false); // loopback/private/reserved all blocked
        let ips = vec![v4(1, 1, 1, 1), v4(127, 0, 0, 1), v4(10, 0, 0, 1)];
        let work = udp_worklist(&ips, &[53, 161], &bl);
        // Only the public address survives, once per port.
        assert_eq!(work, vec![(v4(1, 1, 1, 1), 53), (v4(1, 1, 1, 1), 161)]);

        // filter_blocked is proto-agnostic: it re-applies cleanly to a UDP list.
        let again = filter_blocked(work.clone(), &bl);
        assert_eq!(again, work);
    }
}
