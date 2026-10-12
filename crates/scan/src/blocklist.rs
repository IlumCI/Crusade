//! The mandatory responsible-scanning guardrail.
//!
//! A [`Blocklist`] answers one question — [`Blocklist::is_blocked`] — and every
//! code path that is about to touch the network must ask it first. Three sources
//! feed the answer:
//!
//!   1. **User-supplied ranges** loaded from disk or added at runtime. These are
//!      blocked unconditionally and are never lifted by any toggle.
//!   2. **Special ranges** (`0.0.0.0/8`, multicast, broadcast and the
//!      documentation blocks). These are never legitimate scan targets and are
//!      always blocked.
//!   3. **Private ranges** (RFC1918, loopback, link-local, CGNAT, IPv6 ULA).
//!      Always blocked unless `allow_private` is set, which an operator does
//!      only to scan their own loopback / LAN test rig.

use std::net::IpAddr;
use std::path::Path;
use std::sync::OnceLock;

use anyhow::Context;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

/// RFC1918 / loopback / link-local / CGNAT / ULA ranges. These are lifted when
/// `allow_private` is true so an operator can scan their own test rig.
fn private_ranges() -> &'static [IpNet] {
    static RANGES: OnceLock<Vec<IpNet>> = OnceLock::new();
    RANGES.get_or_init(|| {
        [
            // IPv4 RFC1918 private.
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            // IPv4 loopback.
            "127.0.0.0/8",
            // IPv4 link-local.
            "169.254.0.0/16",
            // IPv4 CGNAT (RFC6598).
            "100.64.0.0/10",
            // IPv6 loopback.
            "::1/128",
            // IPv6 link-local.
            "fe80::/10",
            // IPv6 unique local addresses (ULA).
            "fc00::/7",
        ]
        .iter()
        .map(|s| s.parse().expect("hard-coded private CIDR is valid"))
        .collect()
    })
}

/// Ranges that are never a legitimate scan target under any configuration.
fn special_ranges() -> &'static [IpNet] {
    static RANGES: OnceLock<Vec<IpNet>> = OnceLock::new();
    RANGES.get_or_init(|| {
        [
            // IPv4 "this host / this network" and unspecified.
            "0.0.0.0/8",
            // IPv4 multicast and reserved/future-use (includes the broadcast
            // address 255.255.255.255).
            "224.0.0.0/4",
            "240.0.0.0/4",
            // IPv4 documentation ranges (TEST-NET-1/2/3).
            "192.0.2.0/24",
            "198.51.100.0/24",
            "203.0.113.0/24",
            // IPv6 unspecified.
            "::/128",
            // IPv6 multicast.
            "ff00::/8",
            // IPv6 documentation.
            "2001:db8::/32",
        ]
        .iter()
        .map(|s| s.parse().expect("hard-coded special CIDR is valid"))
        .collect()
    })
}

/// The set of ranges Crusade refuses to scan.
///
/// See the [module docs](self) for the three contributing sources. Construct one
/// with [`Blocklist::new`] (empty user list) or [`Blocklist::load`] (read a
/// file).
#[derive(Debug, Clone)]
pub struct Blocklist {
    /// Operator-supplied ranges, blocked unconditionally.
    user: Vec<IpNet>,
    /// When true, the built-in private/loopback ranges are not treated as
    /// blocked. The special ranges and the user list are unaffected.
    allow_private: bool,
}

impl Blocklist {
    /// Create an empty blocklist. The hard-coded reserved ranges are always in
    /// effect; `allow_private` lifts only the private/loopback group.
    pub fn new(allow_private: bool) -> Self {
        Blocklist {
            user: Vec::new(),
            allow_private,
        }
    }

    /// True if `ip` must not be connected to. This is the single guardrail every
    /// network path consults.
    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        if self.user.iter().any(|net| net.contains(&ip)) {
            return true;
        }
        if special_ranges().iter().any(|net| net.contains(&ip)) {
            return true;
        }
        if !self.allow_private && private_ranges().iter().any(|net| net.contains(&ip)) {
            return true;
        }
        false
    }

    /// Whether the private/loopback ranges are currently permitted.
    pub fn allow_private(&self) -> bool {
        self.allow_private
    }

    /// Add a user-supplied range. It is blocked unconditionally thereafter.
    pub fn add(&mut self, net: IpNet) {
        self.user.push(net);
    }

    /// The operator-supplied ranges, in insertion order.
    pub fn user_ranges(&self) -> &[IpNet] {
        &self.user
    }

    /// Every range an external discovery tool (e.g. `masscan`) must be told to
    /// skip so it, too, honours the mandatory blocklist: all built-in special
    /// and private ranges — regardless of `allow_private`, since a bulk SYN
    /// sweep is never the mechanism for a sanctioned loopback/LAN test — plus
    /// the operator's own ranges. This is intentionally a superset of what
    /// [`Blocklist::is_blocked`] forbids: excluding extra ground is safe,
    /// excluding too little is not.
    pub fn exclude_ranges(&self) -> Vec<IpNet> {
        special_ranges()
            .iter()
            .chain(private_ranges().iter())
            .chain(self.user.iter())
            .copied()
            .collect()
    }

    /// Load user ranges from a text file (one CIDR or bare IP per line; blank
    /// lines and `#` comments ignored). A missing file is not an error — it
    /// yields an empty user list. `allow_private` defaults to false; use
    /// [`Blocklist::load_with`] to change it.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        Self::load_with(path, false)
    }

    /// Like [`Blocklist::load`] but lets the caller set `allow_private`.
    pub fn load_with(path: &Path, allow_private: bool) -> anyhow::Result<Self> {
        let mut bl = Blocklist::new(allow_private);
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            // Missing file == empty user list, by contract.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(bl),
            Err(e) => {
                return Err(
                    anyhow::Error::from(e).context(format!("reading blocklist {}", path.display()))
                );
            }
        };
        for (idx, raw) in text.lines().enumerate() {
            let line = strip_comment(raw).trim();
            if line.is_empty() {
                continue;
            }
            let net = parse_net_entry(line).with_context(|| {
                format!(
                    "blocklist {}:{}: invalid entry {raw:?}",
                    path.display(),
                    idx + 1
                )
            })?;
            bl.add(net);
        }
        Ok(bl)
    }

    /// Write the user-supplied ranges back to `path`, one CIDR per line. The
    /// hard-coded ranges are not written — they are intrinsic to every
    /// blocklist.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let mut out = String::from("# Crusade blocklist: user-supplied blocked ranges.\n");
        for net in &self.user {
            out.push_str(&net.to_string());
            out.push('\n');
        }
        std::fs::write(path, out).with_context(|| format!("writing blocklist {}", path.display()))
    }
}

/// Drop a trailing `#` comment from a line, leaving any leading content.
fn strip_comment(line: &str) -> &str {
    match line.find('#') {
        Some(i) => &line[..i],
        None => line,
    }
}

/// Parse one blocklist entry: either a CIDR (`10.0.0.0/8`) or a bare IP, which
/// is treated as a single-host range (`/32` or `/128`).
fn parse_net_entry(s: &str) -> anyhow::Result<IpNet> {
    if let Ok(net) = s.parse::<IpNet>() {
        return Ok(net);
    }
    let ip: IpAddr = s
        .parse()
        .map_err(|_| anyhow::anyhow!("not a CIDR or IP address: {s:?}"))?;
    Ok(match ip {
        IpAddr::V4(a) => IpNet::V4(Ipv4Net::new(a, 32).expect("/32 is valid")),
        IpAddr::V6(a) => IpNet::V6(Ipv6Net::new(a, 128).expect("/128 is valid")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn default_blocks_private_and_reserved() {
        let bl = Blocklist::new(false);
        // RFC1918
        assert!(bl.is_blocked(v4(10, 0, 0, 1)));
        assert!(bl.is_blocked(v4(172, 16, 5, 9)));
        assert!(bl.is_blocked(v4(192, 168, 1, 1)));
        // loopback
        assert!(bl.is_blocked(v4(127, 0, 0, 1)));
        assert!(bl.is_blocked(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        // link-local
        assert!(bl.is_blocked(v4(169, 254, 1, 1)));
        // CGNAT
        assert!(bl.is_blocked(v4(100, 64, 0, 1)));
        // special: unspecified, multicast, broadcast, documentation
        assert!(bl.is_blocked(v4(0, 0, 0, 0)));
        assert!(bl.is_blocked(v4(224, 0, 0, 1)));
        assert!(bl.is_blocked(v4(255, 255, 255, 255)));
        assert!(bl.is_blocked(v4(192, 0, 2, 1)));
        assert!(bl.is_blocked(v4(203, 0, 113, 50)));
        // IPv6 ULA, link-local, documentation
        assert!(bl.is_blocked("fc00::1".parse().unwrap()));
        assert!(bl.is_blocked("fe80::1".parse().unwrap()));
        assert!(bl.is_blocked("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn public_addresses_are_allowed_by_default() {
        let bl = Blocklist::new(false);
        assert!(!bl.is_blocked(v4(8, 8, 8, 8)));
        assert!(!bl.is_blocked(v4(1, 1, 1, 1)));
        assert!(!bl.is_blocked("2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn allow_private_lifts_only_private_ranges() {
        let bl = Blocklist::new(true);
        // Private/loopback/link-local now permitted for a sanctioned test rig.
        assert!(!bl.is_blocked(v4(127, 0, 0, 1)));
        assert!(!bl.is_blocked(v4(192, 168, 0, 10)));
        assert!(!bl.is_blocked(v4(10, 1, 2, 3)));
        assert!(!bl.is_blocked("fc00::1".parse().unwrap()));
        // Special ranges remain blocked even with allow_private.
        assert!(bl.is_blocked(v4(0, 0, 0, 0)));
        assert!(bl.is_blocked(v4(224, 0, 0, 1)));
        assert!(bl.is_blocked(v4(192, 0, 2, 1)));
    }

    #[test]
    fn user_ranges_are_always_blocked() {
        let mut bl = Blocklist::new(true);
        bl.add("8.8.8.0/24".parse().unwrap());
        // A public address inside a user range is blocked despite allow_private.
        assert!(bl.is_blocked(v4(8, 8, 8, 8)));
        assert!(!bl.is_blocked(v4(8, 8, 9, 9)));
    }

    #[test]
    fn load_missing_file_is_empty_not_error() {
        let bl = Blocklist::load(Path::new("/nonexistent/crusade-blocklist.txt")).unwrap();
        assert!(bl.user_ranges().is_empty());
    }

    #[test]
    fn load_parses_cidrs_and_bare_ips_and_ignores_comments() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("crusade-bl-{}.txt", std::process::id()));
        std::fs::write(
            &path,
            "# comment line\n\n8.8.8.0/24\n9.9.9.9   # inline comment\n2001:4860::/32\n",
        )
        .unwrap();
        let bl = Blocklist::load(&path).unwrap();
        assert_eq!(bl.user_ranges().len(), 3);
        assert!(bl.is_blocked(v4(8, 8, 8, 1)));
        assert!(bl.is_blocked(v4(9, 9, 9, 9)));
        assert!(!bl.is_blocked(v4(9, 9, 9, 10)));

        // Round-trip through save/load.
        let path2 = dir.join(format!("crusade-bl2-{}.txt", std::process::id()));
        bl.save(&path2).unwrap();
        let reloaded = Blocklist::load(&path2).unwrap();
        assert_eq!(reloaded.user_ranges().len(), 3);
        assert!(reloaded.is_blocked(v4(8, 8, 8, 1)));

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&path2);
    }

    #[test]
    fn load_rejects_garbage_entries() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("crusade-bl-bad-{}.txt", std::process::id()));
        std::fs::write(&path, "not-an-ip\n").unwrap();
        assert!(Blocklist::load(&path).is_err());
        let _ = std::fs::remove_file(&path);
    }
}
