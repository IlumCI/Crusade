//! Crusade scan: the TCP connect scanner and its responsible-use guardrails.
//!
//! This crate performs the actual network reach-out for Crusade. Its design is
//! deliberately conservative, because a scanner is only a legitimate
//! security-research tool when it refuses to misbehave:
//!
//!   * **Connect-and-read, or a single SYN.** [`TcpScanner`] opens ordinary TCP
//!     connections with [`tokio::net::TcpStream`] and notes whether the
//!     handshake completes. [`SynScanner`] instead sends one bare SYN per port
//!     for fast discovery and lets the kernel RST the reply, so no half-open
//!     connection is left on the target. Neither spoofs a source address,
//!     floods, or sends a payload — banner and protocol probing lives in the
//!     sibling `probe` crate and also only reads.
//!   * **The blocklist is mandatory.** Every address, whether it arrives through
//!     [`expand_targets`] or is handed straight to [`TcpScanner::scan`], is
//!     checked against a [`Blocklist`] that *always* contains the reserved,
//!     private, loopback, link-local, CGNAT, multicast, broadcast and
//!     documentation ranges for both IPv4 and IPv6. A blocked address is never
//!     connected to. Operators add their own ranges on top; those are blocked
//!     unconditionally and can never be lifted.
//!   * **Conservative rates.** A token-bucket [`RateLimiter`] caps new
//!     connections per second and a semaphore bounds in-flight connections, so
//!     the default behaviour is gentle on both the network and the targets.
//!
//! Wide discovery has three routes: the built-in [`SynScanner`] (stateless,
//! needs `CAP_NET_RAW`, IPv4 only), the external [`masscan_discover`]
//! front-end, or ingesting a sweep run elsewhere. All three re-apply the
//! blocklist. Sweeps run out-of-band with a sanctioned `masscan`/`zmap`
//! deployment; this crate ingests their output via
//! [`parse_masscan_json`] / [`parse_zmap_csv`] and re-applies the blocklist with
//! [`filter_blocked`] before anything downstream touches the results. For bulk
//! SYN discovery the [`masscan_discover`] front-end shells out to the system
//! `masscan` — and it, too, honours the mandatory blocklist, both by refusing to
//! hand it any blocked target and by handing masscan an `--excludefile` built
//! from the full blocklist so the external tool refuses those ranges itself.
//!
//! Targeted scanning covers both IPv4 and IPv6: [`expand_targets`] accepts a
//! bare IPv6 address and small IPv6 CIDRs, but refuses an IPv6 range wider than
//! a safety cap, since such ranges are astronomically large. IPv6 at scale is
//! not enumeration but prediction — see the [`ipv6`] module for seed hygiene,
//! aliased-prefix dealiasing and target generation. UDP recon is kept
//! to plumbing here — [`default_udp_ports`] and [`udp_worklist`] produce a
//! blocklist-clean `(ip, port)` worklist for the `probe` crate's UDP probes to
//! consume; the mandatory blocklist governs that worklist exactly as it does TCP
//! (no UDP sockets are opened in this crate).

mod blocklist;
mod discovery;
mod ipv6;
mod rate;
mod scanner;
mod sweep;
mod syn;
mod targets;
mod udp;

pub use blocklist::Blocklist;
pub use discovery::{masscan_discover, MasscanConfig};
pub use ipv6::{
    alias_probes, clean_seeds, is_scannable, Alias, Dealiaser, Generator, SeedReport,
    TargetGenerator,
};
pub use rate::{RateLimiter, RateLimiterParams};
pub use scanner::{ScanConfig, TcpScanner};
pub use sweep::{
    filter_blocked, parse_masscan_json, parse_zmap_csv, parse_zmap_csv_rich, ZmapRecord,
};
pub use syn::{PortState, Reply, SynConfig, SynScanner};
pub use targets::{expand_targets, MIN_V6_PREFIX};
pub use udp::{default_udp_ports, udp_worklist};
