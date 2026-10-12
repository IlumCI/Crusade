//! Target expansion for single IPs and CIDR ranges (IPv4 and IPv6).
//!
//! ASN and domain expansion deliberately live in the `enrich` crate; this module
//! handles only the forms it can resolve without any network lookup, and strips
//! anything the [`Blocklist`] forbids before returning.
//!
//! IPv6 support is deliberately narrow: a bare IPv6 address is fine, but an IPv6
//! CIDR is only accepted when it is small enough to enumerate ([`MIN_V6_PREFIX`]
//! and smaller host counts). Anything wider is astronomically large and is
//! refused outright rather than attempting to materialise it.

use std::net::IpAddr;

use ipnet::IpNet;

use crate::blocklist::Blocklist;

/// The shortest (widest) IPv6 prefix [`expand_targets`] will enumerate. A `/112`
/// is 2^16 = 65 536 addresses; anything wider (a numerically smaller prefix) is
/// refused, because enumerating it would be hopeless. IPv4 has no such cap — its
/// whole space is enumerable.
pub const MIN_V6_PREFIX: u8 = 112;

/// Expand a target specification into concrete host addresses, with every
/// blocklisted address removed.
///
/// Accepts a single IP — IPv4 (`"192.0.2.1"`) or IPv6 (`"2606:4700::1111"`) — or
/// a CIDR (`"198.51.100.0/24"`, `"2606:4700::/120"`). Anything else — notably an
/// ASN (`"AS15169"`) or a domain — is an error here, since that expansion
/// belongs to the `enrich` crate.
///
/// For an IPv4 CIDR the network and broadcast addresses are excluded (via
/// [`IpNet::hosts`]); for a `/31` or `/32` the usable addresses are returned
/// as-is. An IPv6 CIDR is enumerated only when its prefix is at least
/// [`MIN_V6_PREFIX`]; a wider v6 range is an error, since v6 ranges are far too
/// large to materialise.
pub fn expand_targets(spec: &str, bl: &Blocklist) -> anyhow::Result<Vec<IpAddr>> {
    let spec = spec.trim();
    if spec.is_empty() {
        anyhow::bail!("empty target specification");
    }

    let addrs: Vec<IpAddr> = if spec.contains('/') {
        let net: IpNet = spec
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid CIDR {spec:?}: {e}"))?;
        if let IpNet::V6(v6) = net {
            if v6.prefix_len() < MIN_V6_PREFIX {
                anyhow::bail!(
                    "IPv6 CIDR {spec:?} is too large to enumerate: prefix /{} is wider \
                     than the safety cap /{MIN_V6_PREFIX} (an IPv6 range this size has an \
                     astronomical host count; narrow it to /{MIN_V6_PREFIX} or smaller)",
                    v6.prefix_len()
                );
            }
        }
        net.hosts().collect()
    } else {
        let ip: IpAddr = spec.parse().map_err(|_| {
            anyhow::anyhow!(
                "target {spec:?} is not an IP or CIDR \
                 (ASN and domain targets are handled by the enrich crate)"
            )
        })?;
        vec![ip]
    };

    // The guardrail: never emit an address the blocklist forbids.
    Ok(addrs.into_iter().filter(|ip| !bl.is_blocked(*ip)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn single_public_ip_passes_through() {
        let bl = Blocklist::new(false);
        let got = expand_targets("9.9.9.9", &bl).unwrap();
        assert_eq!(got, vec![v4(9, 9, 9, 9)]);
    }

    #[test]
    fn cidr_expands_to_hosts_without_network_or_broadcast() {
        let bl = Blocklist::new(false);
        // 8.8.8.0/29 is public; /29 yields 6 usable hosts (.1 ..= .6).
        let got = expand_targets("8.8.8.0/29", &bl).unwrap();
        assert_eq!(got.len(), 6);
        assert!(got.contains(&v4(8, 8, 8, 1)));
        assert!(got.contains(&v4(8, 8, 8, 6)));
        assert!(!got.contains(&v4(8, 8, 8, 0)));
        assert!(!got.contains(&v4(8, 8, 8, 7)));
    }

    #[test]
    fn blocklisted_and_reserved_addresses_are_never_returned() {
        let mut bl = Blocklist::new(false);
        bl.add("8.8.8.4/32".parse().unwrap());

        // A user-blocked address is stripped from an otherwise public CIDR.
        let got = expand_targets("8.8.8.0/29", &bl).unwrap();
        assert!(!got.contains(&v4(8, 8, 8, 4)));
        assert_eq!(got.len(), 5);

        // A reserved (documentation) range expands to nothing.
        assert!(expand_targets("192.0.2.0/24", &bl).unwrap().is_empty());
        // A private range expands to nothing by default.
        assert!(expand_targets("10.0.0.0/30", &bl).unwrap().is_empty());
        // A single reserved / loopback IP is dropped.
        assert!(expand_targets("127.0.0.1", &bl).unwrap().is_empty());
    }

    #[test]
    fn allow_private_permits_loopback_target() {
        let bl = Blocklist::new(true);
        let got = expand_targets("127.0.0.1", &bl).unwrap();
        assert_eq!(got, vec![v4(127, 0, 0, 1)]);
    }

    #[test]
    fn asn_and_domain_targets_are_rejected() {
        let bl = Blocklist::new(false);
        assert!(expand_targets("AS15169", &bl).is_err());
        assert!(expand_targets("example.com", &bl).is_err());
        assert!(expand_targets("", &bl).is_err());
    }

    #[test]
    fn bare_v6_ip_expands_to_itself() {
        let bl = Blocklist::new(false);
        // A public IPv6 address (Cloudflare resolver) passes straight through.
        let got = expand_targets("2606:4700:4700::1111", &bl).unwrap();
        assert_eq!(got, vec!["2606:4700:4700::1111".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn huge_v6_cidr_is_refused() {
        let bl = Blocklist::new(false);
        // A /32 IPv6 block holds 2^96 addresses — far wider than the /112 cap.
        let err = expand_targets("2606:4700::/32", &bl).unwrap_err();
        assert!(err.to_string().contains("too large to enumerate"), "{err}");
        // The cap boundary: one bit too wide is still refused.
        assert!(expand_targets("2606:4700::/111", &bl).is_err());
    }

    #[test]
    fn small_v6_cidr_expands_within_cap() {
        let bl = Blocklist::new(false);
        // A /120 is 256 addresses; the public 2606:4700::/120 block is allowed.
        let got = expand_targets("2606:4700::/120", &bl).unwrap();
        assert!(!got.is_empty());
        assert!(got.len() <= 256, "expected <=256 addrs, got {}", got.len());
        // Exactly the /112 cap boundary is permitted (2^16 addresses).
        assert!(expand_targets("2606:4700::/112", &bl).is_ok());
    }

    #[test]
    fn blocklisted_v6_addresses_are_removed() {
        let bl = Blocklist::new(false);
        // IPv6 documentation range 2001:db8::/32 is reserved; a /120 inside it
        // expands to nothing because every address is blocklisted.
        assert!(expand_targets("2001:db8::/120", &bl).unwrap().is_empty());
        // A single reserved v6 address (loopback) is dropped too.
        assert!(expand_targets("::1", &bl).unwrap().is_empty());

        // A user-blocked v6 range is stripped from an otherwise public v6 net.
        let mut bl = Blocklist::new(false);
        bl.add("2606:4700::/122".parse().unwrap());
        let got = expand_targets("2606:4700::/120", &bl).unwrap();
        assert!(got.iter().all(|ip| {
            let blocked: IpNet = "2606:4700::/122".parse().unwrap();
            !blocked.contains(ip)
        }));
        assert!(!got.is_empty());
    }
}
