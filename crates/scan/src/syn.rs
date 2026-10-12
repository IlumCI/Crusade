//! Stateless SYN discovery (IPv4).
//!
//! The connect scanner completes a full handshake per port, which bounds it at
//! a few hundred probes a second and holds state for every outstanding attempt.
//! Internet-wide discovery needs the ZMap design (Durumeric et al., USENIX
//! Security 2013): send a bare SYN, never track it, and recognise the reply
//! from the packet itself.
//!
//! The trick is a **cookie**. The initial sequence number of each SYN is a
//! keyed hash of `(source ip, destination ip, destination port, source port)`.
//! A real reply acknowledges `cookie + 1`, so a SYN-ACK can be validated
//! without remembering what was sent: memory is constant no matter how many
//! targets are in flight, and replies that were not solicited (stale,
//! off-target, or spoofed without seeing our traffic) are rejected.
//!
//! What this module does on the wire, and nothing else:
//! * one SYN per `(ip, port)`, rate-limited;
//! * read replies: SYN-ACK means open, RST means closed.
//!
//! It never completes the handshake. The kernel answers an unsolicited SYN-ACK
//! on an unbound port with a RST, which tears the half-open connection down
//! immediately — the same courtesy ZMap relies on. Banner grabbing is a
//! separate, ordinary connection to the ports found here, so the expensive
//! app-layer work only happens where something answered.
//!
//! Requires `CAP_NET_RAW`. [`SynScanner::new`] fails without it, and callers
//! are expected to fall back to the connect scanner.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::{AsRawFd, RawFd};
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::unix::AsyncFd;

use crate::blocklist::Blocklist;
use crate::rate::{RateLimiter, RateLimiterParams};

/// Bytes of a TCP header with no options.
const TCP_HEADER_LEN: usize = 20;
/// SYN flag.
const FLAG_SYN: u8 = 0x02;
/// ACK flag.
const FLAG_ACK: u8 = 0x10;
/// RST flag.
const FLAG_RST: u8 = 0x04;
/// Receive buffer we ask the kernel for. Replies arrive in bursts, and a small
/// buffer silently drops SYN-ACKs — which would read as "port closed".
const RECV_BUFFER: usize = 32 * 1024 * 1024;
/// Window advertised in our SYN. Nothing is ever read on these connections.
const WINDOW: u16 = 65535;

/// What a reply said about a port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    Open,
    Closed,
}

/// A validated reply to one of our probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reply {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub state: PortState,
}

/// Configuration for a [`SynScanner`].
#[derive(Debug, Clone)]
pub struct SynConfig {
    /// Probe pacing. Only the token bucket (`conn_per_sec`, `burst`) applies:
    /// a stateless SYN holds no connection, so there is no concurrency to cap.
    pub rate: RateLimiterParams,
    /// Source port on our side. Left unbound on purpose: the kernel then RSTs
    /// the SYN-ACK and the target is not left with a half-open connection.
    pub source_port: u16,
    /// How long to keep reading replies after the last SYN goes out.
    pub linger: Duration,
    /// Permit the built-in private/reserved ranges (own test rig only).
    pub allow_private: bool,
}

impl Default for SynConfig {
    fn default() -> Self {
        SynConfig {
            rate: RateLimiterParams::default(),
            source_port: 61000,
            linger: Duration::from_secs(3),
            allow_private: false,
        }
    }
}

/// A stateless SYN scanner.
pub struct SynScanner {
    config: SynConfig,
    blocklist: Blocklist,
    /// Key for the reply cookie. Random per scanner, so replies to a previous
    /// run (or another scanner) never validate.
    key: u64,
    send: Socket,
    recv: AsyncFd<RecvSocket>,
}

/// Owns the receive socket's fd for [`AsyncFd`].
struct RecvSocket(Socket);

impl AsRawFd for RecvSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl SynScanner {
    /// Open the raw sockets. Fails without `CAP_NET_RAW`.
    pub fn new(config: SynConfig, blocklist: Blocklist) -> io::Result<Self> {
        let send = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP))?;
        let recv = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP))?;
        recv.set_nonblocking(true)?;
        // Best-effort: a smaller buffer still works, it just drops more.
        let _ = recv.set_recv_buffer_size(RECV_BUFFER);
        Ok(SynScanner {
            config,
            blocklist,
            key: random_key(),
            send,
            recv: AsyncFd::new(RecvSocket(recv))?,
        })
    }

    /// The blocklist this scanner enforces.
    pub fn blocklist(&self) -> &Blocklist {
        &self.blocklist
    }

    /// Probe every `(ip, port)` pair and return the open ones.
    ///
    /// Blocked addresses are skipped and never sent a packet. Closed ports are
    /// observed too (a RST is a definite answer) but only open ports are
    /// returned, matching [`crate::TcpScanner::scan`].
    pub async fn scan(
        &self,
        targets: &[Ipv4Addr],
        ports: &[u16],
    ) -> io::Result<Vec<(IpAddr, u16)>> {
        let replies = self.probe(targets, ports).await?;
        Ok(replies
            .into_iter()
            .filter(|r| r.state == PortState::Open)
            .map(|r| (IpAddr::V4(r.ip), r.port))
            .collect())
    }

    /// Like [`SynScanner::scan`], but reports closed ports as well.
    pub async fn probe(&self, targets: &[Ipv4Addr], ports: &[u16]) -> io::Result<Vec<Reply>> {
        let mut jobs: Vec<(Ipv4Addr, u16)> = Vec::new();
        for &ip in targets {
            if self.blocklist.is_blocked(IpAddr::V4(ip)) {
                tracing::warn!(%ip, "refusing to scan blocklisted address");
                continue;
            }
            for &port in ports {
                jobs.push((ip, port));
            }
        }
        if jobs.is_empty() {
            return Ok(Vec::new());
        }

        let limiter = RateLimiter::new(self.config.rate);
        let mut replies = Vec::new();
        let mut sent = 0usize;
        let mut blocked_locally = 0usize;

        // Send and receive are interleaved on one task: replies to early
        // probes arrive while later ones are still going out, and the kernel
        // receive buffer is finite.
        for (ip, port) in jobs {
            // Pace sends. The permit is released at once: nothing is held open
            // for a stateless probe, so only the token bucket matters here.
            drop(limiter.acquire().await);
            let source = source_address_for(ip)?;
            let cookie = self.cookie(source, ip, port);
            let packet = build_syn(source, ip, self.config.source_port, port, cookie);
            let dst = SocketAddr::V4(SocketAddrV4::new(ip, port));
            match self.send.send_to(&packet, &dst.into()) {
                Ok(_) => sent += 1,
                // A local firewall rule makes the kernel reject the send with
                // EPERM per packet. Lacking CAP_NET_RAW fails earlier, when the
                // socket is opened, so this is never a capability problem and
                // must not abort the sweep.
                Err(e) if e.raw_os_error() == Some(libc::EPERM) => {
                    blocked_locally += 1;
                    continue;
                }
                // Nor must a single unroutable target.
                Err(_) => continue,
            }
            self.drain(&mut replies);
        }

        if blocked_locally > 0 {
            tracing::warn!(
                blocked_locally,
                "local firewall rejected some probes; those ports are unknown, not closed"
            );
        }
        tracing::debug!(
            sent,
            blocked_locally,
            "SYN probes sent; waiting for replies"
        );

        // Then wait out the stragglers.
        let deadline = tokio::time::Instant::now() + self.config.linger;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                break;
            }
            match tokio::time::timeout(left, self.recv.readable()).await {
                Ok(Ok(mut guard)) => {
                    guard.clear_ready();
                    self.drain(&mut replies);
                }
                Ok(Err(e)) => return Err(e),
                Err(_) => break,
            }
        }
        Ok(replies)
    }

    /// Read whatever has already arrived, without blocking.
    fn drain(&self, out: &mut Vec<Reply>) {
        let mut buf = [0u8; 2048];
        loop {
            // SAFETY: recv_from writes initialised bytes into the prefix it
            // reports, and we only read that prefix.
            let n = match self.recv.get_ref().0.recv(unsafe {
                &mut *(buf.as_mut_slice() as *mut [u8] as *mut [std::mem::MaybeUninit<u8>])
            }) {
                Ok(n) => n,
                Err(_) => return,
            };
            if let Some(reply) = self.parse_reply(&buf[..n]) {
                out.push(reply);
            }
        }
    }

    /// Validate one received packet against our cookie.
    fn parse_reply(&self, packet: &[u8]) -> Option<Reply> {
        let (src, dst, tcp) = parse_ipv4_tcp(packet)?;
        let seg = parse_tcp(tcp)?;
        if seg.dst_port != self.config.source_port {
            return None;
        }
        // The reply must acknowledge the cookie we derived for this target.
        if seg.ack != self.cookie(dst, src, seg.src_port).wrapping_add(1) {
            return None;
        }
        let state = if seg.flags & FLAG_SYN != 0 && seg.flags & FLAG_ACK != 0 {
            PortState::Open
        } else if seg.flags & FLAG_RST != 0 {
            PortState::Closed
        } else {
            return None;
        };
        Some(Reply {
            ip: src,
            port: seg.src_port,
            state,
        })
    }

    fn cookie(&self, source: Ipv4Addr, target: Ipv4Addr, port: u16) -> u32 {
        syn_cookie(self.key, source, target, self.config.source_port, port)
    }
}

/// Keyed cookie placed in the SYN's sequence number.
///
/// Any stable keyed function works; this is FNV-1a over the tuple, which is
/// cheap enough to run per packet at line rate. It is a validation token, not
/// a security boundary: an attacker who can observe our probes can forge a
/// reply either way, which is equally true of ZMap.
pub fn syn_cookie(
    key: u64,
    source: Ipv4Addr,
    target: Ipv4Addr,
    source_port: u16,
    target_port: u16,
) -> u32 {
    let mut hash = key ^ 0xcbf2_9ce4_8422_2325;
    let mut feed = |bytes: &[u8]| {
        for b in bytes {
            hash ^= u64::from(*b);
            hash = hash.wrapping_mul(0x1000_0000_01b3);
        }
    };
    feed(&source.octets());
    feed(&target.octets());
    feed(&source_port.to_be_bytes());
    feed(&target_port.to_be_bytes());
    // Fold to 32 bits so both halves contribute.
    ((hash >> 32) ^ (hash & 0xffff_ffff)) as u32
}

/// Build a SYN segment (TCP header only; the kernel supplies the IP header).
pub fn build_syn(
    source: Ipv4Addr,
    target: Ipv4Addr,
    source_port: u16,
    target_port: u16,
    seq: u32,
) -> Vec<u8> {
    let mut tcp = Vec::with_capacity(TCP_HEADER_LEN);
    tcp.extend_from_slice(&source_port.to_be_bytes());
    tcp.extend_from_slice(&target_port.to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&0u32.to_be_bytes()); // ack
                                                // Data offset 5 words, no options; flags = SYN.
    tcp.push(5 << 4);
    tcp.push(FLAG_SYN);
    tcp.extend_from_slice(&WINDOW.to_be_bytes());
    tcp.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    tcp.extend_from_slice(&0u16.to_be_bytes()); // urgent pointer

    let sum = tcp_checksum(source, target, &tcp);
    tcp[16..18].copy_from_slice(&sum.to_be_bytes());
    tcp
}

/// TCP checksum over the IPv4 pseudo-header plus the segment.
pub fn tcp_checksum(source: Ipv4Addr, target: Ipv4Addr, tcp: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut add = |bytes: &[u8]| {
        let mut chunks = bytes.chunks_exact(2);
        for c in &mut chunks {
            sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
        }
        if let [last] = chunks.remainder() {
            sum += u32::from(u16::from_be_bytes([*last, 0]));
        }
    };
    add(&source.octets());
    add(&target.octets());
    add(&[0, 6]); // zero + protocol
    add(&(tcp.len() as u16).to_be_bytes());
    add(tcp);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// One parsed TCP header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
}

/// Split an IPv4 packet into `(source, destination, tcp bytes)`.
pub fn parse_ipv4_tcp(packet: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr, &[u8])> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len || packet[9] != 6 {
        return None;
    }
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    Some((src, dst, &packet[header_len..]))
}

/// Parse a TCP header.
pub fn parse_tcp(tcp: &[u8]) -> Option<Segment> {
    if tcp.len() < TCP_HEADER_LEN {
        return None;
    }
    Some(Segment {
        src_port: u16::from_be_bytes([tcp[0], tcp[1]]),
        dst_port: u16::from_be_bytes([tcp[2], tcp[3]]),
        seq: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
        ack: u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]),
        flags: tcp[13],
    })
}

/// Which local address would be used to reach `target`.
///
/// A connected UDP socket makes the kernel run its route lookup without
/// sending anything.
fn source_address_for(target: Ipv4Addr) -> io::Result<Ipv4Addr> {
    let probe = std::net::UdpSocket::bind("0.0.0.0:0")?;
    probe.connect(SocketAddrV4::new(target, 9))?;
    match probe.local_addr()? {
        SocketAddr::V4(a) => Ok(*a.ip()),
        SocketAddr::V6(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected an IPv4 source address",
        )),
    }
}

/// Random cookie key, from the OS.
fn random_key() -> u64 {
    let mut buf = [0u8; 8];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut buf))
        .is_err()
    {
        // Fall back to the clock; the key only needs to be unpredictable
        // enough that replies from an earlier run do not validate.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x5bad_c0de);
        return nanos.rotate_left(17) ^ 0x9e37_79b9_7f4a_7c15;
    }
    u64::from_be_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    const DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);

    #[test]
    fn checksum_matches_a_known_good_segment() {
        // A segment whose checksum field already holds the correct value sums
        // to zero over the pseudo-header — the standard verification property.
        let syn = build_syn(SRC, DST, 61000, 443, 0x1234_5678);
        assert_eq!(syn.len(), TCP_HEADER_LEN);
        assert_eq!(tcp_checksum(SRC, DST, &syn), 0);
    }

    #[test]
    fn built_syn_has_the_right_header_fields() {
        let syn = build_syn(SRC, DST, 61000, 443, 0xdead_beef);
        let seg = parse_tcp(&syn).unwrap();
        assert_eq!(seg.src_port, 61000);
        assert_eq!(seg.dst_port, 443);
        assert_eq!(seg.seq, 0xdead_beef);
        assert_eq!(seg.ack, 0);
        assert_eq!(seg.flags, FLAG_SYN);
        assert_eq!(syn[12] >> 4, 5, "data offset is 5 words");
    }

    #[test]
    fn cookie_depends_on_every_part_of_the_tuple() {
        let base = syn_cookie(7, SRC, DST, 61000, 443);
        assert_ne!(base, syn_cookie(8, SRC, DST, 61000, 443), "key");
        assert_ne!(
            base,
            syn_cookie(7, Ipv4Addr::new(192, 0, 2, 2), DST, 61000, 443),
            "source"
        );
        assert_ne!(
            base,
            syn_cookie(7, SRC, Ipv4Addr::new(198, 51, 100, 8), 61000, 443),
            "target"
        );
        assert_ne!(base, syn_cookie(7, SRC, DST, 61001, 443), "source port");
        assert_ne!(base, syn_cookie(7, SRC, DST, 61000, 444), "target port");
        // Stable for the same tuple: this is what makes validation stateless.
        assert_eq!(base, syn_cookie(7, SRC, DST, 61000, 443));
    }

    #[test]
    fn cookies_differ_across_ports_of_one_host() {
        // Every port of a host must get a distinct cookie, or a reply from one
        // port would validate as another.
        let mut seen = std::collections::HashSet::new();
        for port in 1..=2000u16 {
            assert!(
                seen.insert(syn_cookie(42, SRC, DST, 61000, port)),
                "cookie collision at port {port}"
            );
        }
    }

    #[test]
    fn parse_rejects_malformed_and_non_tcp_packets() {
        assert!(parse_ipv4_tcp(&[]).is_none());
        assert!(parse_ipv4_tcp(&[0u8; 19]).is_none());
        let mut pkt = [0u8; 40];
        pkt[0] = 0x45;
        pkt[9] = 6;
        assert!(parse_ipv4_tcp(&pkt).is_some());
        pkt[9] = 17; // UDP
        assert!(parse_ipv4_tcp(&pkt).is_none());
        pkt[9] = 6;
        pkt[0] = 0x65; // header length 20 bytes but claims 5 words of a v6?
        assert!(parse_ipv4_tcp(&pkt).is_none(), "version must be 4");
        pkt[0] = 0x43; // header shorter than 20 bytes
        assert!(parse_ipv4_tcp(&pkt).is_none());
        assert!(parse_tcp(&[0u8; 19]).is_none());
    }

    #[test]
    fn ipv4_header_length_is_honoured() {
        // 24-byte IP header (6 words) with options, then the TCP header.
        let mut pkt = vec![0x46, 0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0];
        pkt.extend_from_slice(&SRC.octets());
        pkt.extend_from_slice(&DST.octets());
        pkt.extend_from_slice(&[0, 0, 0, 0]); // IP options
        pkt.extend_from_slice(&build_syn(SRC, DST, 61000, 443, 1));
        let (src, dst, tcp) = parse_ipv4_tcp(&pkt).unwrap();
        assert_eq!((src, dst), (SRC, DST));
        assert_eq!(parse_tcp(tcp).unwrap().dst_port, 443);
    }

    #[test]
    fn source_address_for_loopback_is_loopback() {
        let a = source_address_for(Ipv4Addr::LOCALHOST).unwrap();
        assert_eq!(a, Ipv4Addr::LOCALHOST);
    }

    #[test]
    fn random_key_is_not_constant() {
        assert_ne!(random_key(), random_key());
    }

    /// End-to-end against loopback: a listening port must answer SYN-ACK and a
    /// closed one RST. Skipped without `CAP_NET_RAW`.
    #[tokio::test]
    async fn loopback_syn_scan_distinguishes_open_from_closed() {
        let cfg = SynConfig {
            source_port: 61017,
            linger: Duration::from_secs(2),
            allow_private: true,
            ..SynConfig::default()
        };
        let scanner = match SynScanner::new(cfg, Blocklist::new(true)) {
            Ok(s) => s,
            // No CAP_NET_RAW in this environment; the connect scanner covers it.
            Err(_) => return,
        };

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let open = listener.local_addr().unwrap().port();
        // A port nothing is bound to: bind then drop to get a free number.
        let closed = {
            let s = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            s.local_addr().unwrap().port()
        };

        let replies = scanner
            .probe(&[Ipv4Addr::LOCALHOST], &[open, closed])
            .await
            .unwrap();

        let state = |port: u16| replies.iter().find(|r| r.port == port).map(|r| r.state);
        assert_eq!(state(open), Some(PortState::Open), "replies: {replies:?}");
        assert_eq!(
            state(closed),
            Some(PortState::Closed),
            "replies: {replies:?}"
        );

        // scan() reports only the open port.
        let found = scanner
            .scan(&[Ipv4Addr::LOCALHOST], &[open, closed])
            .await
            .unwrap();
        assert_eq!(found, vec![(IpAddr::V4(Ipv4Addr::LOCALHOST), open)]);
    }

    /// The blocklist is enforced before anything is sent.
    #[tokio::test]
    async fn blocked_addresses_are_never_probed() {
        let scanner = match SynScanner::new(SynConfig::default(), Blocklist::new(false)) {
            Ok(s) => s,
            Err(_) => return,
        };
        // Default blocklist refuses private space, so this sends no packets.
        let replies = scanner
            .probe(&[Ipv4Addr::new(10, 0, 0, 1)], &[80])
            .await
            .unwrap();
        assert!(replies.is_empty());
    }
}
