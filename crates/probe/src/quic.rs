//! QUIC identification by forced version negotiation.
//!
//! HTTP/3 runs over QUIC on UDP, so a TCP-only scan misses it entirely — a
//! host can serve its whole site over UDP/443 and look closed. Identifying it
//! takes one packet and no handshake.
//!
//! The trick is in RFC 9000 §6: a server that receives a long-header packet
//! naming a QUIC version it does not support must reply with a **Version
//! Negotiation** packet listing the versions it *does* support. That reply is
//! unencrypted and unauthenticated by design, so it can be read without any
//! cryptographic state. Sending a deliberately reserved version
//! ([`FORCE_VN_VERSION`], one of the `0x?a?a?a?a` values RFC 9000 §15 sets
//! aside to exercise exactly this path) makes every compliant server answer.
//!
//! This is the approach taken by QScanner (Zirngibl et al., *It's over 9000*,
//! IMC 2021). Deeper library fingerprinting (QUIC Hunter, PAM 2024) needs a
//! real handshake and TLS inside QUIC; the version list alone already
//! identifies the server and often its stack generation.
//!
//! Strictly connect-and-read: one UDP datagram out, one read, no handshake, no
//! connection established, nothing retained on the server.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;

use crusade_core::{Service, Transport};

/// A reserved version that must force version negotiation. RFC 9000 §15
/// reserves every version of the form `0x?a?a?a?a` so implementations can be
/// tested against this path.
pub const FORCE_VN_VERSION: u32 = 0x1a2a_3a4a;

/// Minimum size of a client Initial datagram (RFC 9000 §14.1). Smaller
/// datagrams may be dropped without reply, which would read as "no QUIC".
const MIN_INITIAL_DATAGRAM: usize = 1200;

/// Connection ID length we use in both directions. 8 bytes is the common
/// choice and well within the 20-byte maximum.
const CID_LEN: usize = 8;

/// A QUIC server's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicInfo {
    /// Versions the server advertised, in the order it listed them.
    pub versions: Vec<u32>,
}

impl QuicInfo {
    /// Names for the versions we recognise, for display and search.
    pub fn version_names(&self) -> Vec<String> {
        self.versions.iter().map(|v| version_name(*v)).collect()
    }

    /// The newest standard version offered, if any.
    pub fn newest_standard(&self) -> Option<u32> {
        // 0x00000001 is RFC 9000 (QUIC v1); 0x6b3343cf is QUIC v2 (RFC 9369).
        // Draft versions (0xff00_00xx) are older than either.
        [0x6b33_43cf, 0x0000_0001]
            .into_iter()
            .find(|v| self.versions.contains(v))
    }
}

/// A human-readable name for a QUIC version number.
pub fn version_name(version: u32) -> String {
    match version {
        0x0000_0001 => "QUICv1".to_string(),
        0x6b33_43cf => "QUICv2".to_string(),
        0x5100_0000..=0x5100_ffff => format!("facebook-mvfst-{:#x}", version & 0xffff),
        0x0a0a_0a0a | 0x1a2a_3a4a => format!("reserved-{version:#010x}"),
        v if v & 0xffff_ff00 == 0xff00_0000 => format!("draft-{:02}", v & 0xff),
        v => format!("{v:#010x}"),
    }
}

/// Encode a QUIC variable-length integer (RFC 9000 §16).
fn varint(value: u64, out: &mut Vec<u8>) {
    match value {
        v if v < 1 << 6 => out.push(v as u8),
        v if v < 1 << 14 => out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes()),
        v if v < 1 << 30 => out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes()),
        v => out.extend_from_slice(&(v | 0xc000_0000_0000_0000).to_be_bytes()),
    }
}

/// Build a client Initial packet naming `version`, padded to the minimum
/// datagram size.
///
/// The payload is not real crypto — it does not need to be. A server checks
/// the version before it can decrypt anything, and answers an unsupported
/// version with a Version Negotiation packet, so the bytes after the header
/// are only there to make the datagram long enough to be processed.
pub fn build_initial(version: u32, dcid: &[u8], scid: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(MIN_INITIAL_DATAGRAM);
    // Long header: header form (1), fixed bit (1), type Initial (00),
    // reserved (00), packet-number length (00 = 1 byte).
    pkt.push(0b1100_0000);
    pkt.extend_from_slice(&version.to_be_bytes());
    pkt.push(dcid.len() as u8);
    pkt.extend_from_slice(dcid);
    pkt.push(scid.len() as u8);
    pkt.extend_from_slice(scid);
    varint(0, &mut pkt); // token length: none for an Initial
    let remaining = MIN_INITIAL_DATAGRAM.saturating_sub(pkt.len() + 2 + 1);
    varint((remaining + 1) as u64, &mut pkt); // length: packet number + payload
    pkt.push(0); // packet number
    pkt.resize(MIN_INITIAL_DATAGRAM, 0); // PADDING frames are zero bytes
    pkt
}

/// Parse a Version Negotiation reply, checking it answers our packet.
///
/// Returns `None` for anything that is not a Version Negotiation packet whose
/// connection IDs echo ours. That check matters: the reply is unauthenticated,
/// so without it any UDP datagram arriving on our socket would read as a QUIC
/// server.
pub fn parse_version_negotiation(
    packet: &[u8],
    sent_dcid: &[u8],
    sent_scid: &[u8],
) -> Option<QuicInfo> {
    // Long header form, and version 0 marks Version Negotiation.
    if packet.len() < 7 || packet[0] & 0x80 == 0 {
        return None;
    }
    if u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]) != 0 {
        return None;
    }
    let mut at = 5;
    // The server echoes our source CID as its destination, and vice versa.
    let dcid_len = usize::from(*packet.get(at)?);
    at += 1;
    let dcid = packet.get(at..at + dcid_len)?;
    at += dcid_len;
    let scid_len = usize::from(*packet.get(at)?);
    at += 1;
    let scid = packet.get(at..at + scid_len)?;
    at += scid_len;
    if dcid != sent_scid || scid != sent_dcid {
        return None;
    }

    let rest = packet.get(at..)?;
    if rest.is_empty() || !rest.len().is_multiple_of(4) {
        return None;
    }
    let versions: Vec<u32> = rest
        .chunks_exact(4)
        .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
        // A server may include a reserved version to exercise our handling of
        // unknown ones; that is not something it actually speaks.
        .filter(|v| v & 0x0f0f_0f0f != 0x0a0a_0a0a)
        .collect();
    (!versions.is_empty()).then_some(QuicInfo { versions })
}

/// Probe one UDP port for QUIC.
pub async fn probe_quic(ip: IpAddr, port: u16, timeout: Duration) -> Option<Service> {
    let info = quic_info(ip, port, timeout).await?;
    let mut svc = Service::new(port, Transport::Udp);
    svc.service = Some("quic".to_string());
    svc.product = Some("QUIC".to_string());
    svc.version = info.newest_standard().map(version_name);
    svc.banner = Some(format!(
        "QUIC version negotiation: {}",
        info.version_names().join(", ")
    ));
    Some(svc)
}

/// Send the forced-negotiation Initial and read the reply.
pub async fn quic_info(ip: IpAddr, port: u16, timeout: Duration) -> Option<QuicInfo> {
    let bind: SocketAddr = if ip.is_ipv4() {
        "0.0.0.0:0".parse().ok()?
    } else {
        "[::]:0".parse().ok()?
    };
    let socket = UdpSocket::bind(bind).await.ok()?;
    socket.connect(SocketAddr::new(ip, port)).await.ok()?;

    // Connection IDs are only used to match the reply to this probe.
    let dcid: Vec<u8> = (0..CID_LEN as u8)
        .map(|i| i.wrapping_mul(37).wrapping_add(11))
        .collect();
    let scid: Vec<u8> = (0..CID_LEN as u8)
        .map(|i| i.wrapping_mul(53).wrapping_add(7))
        .collect();

    let packet = build_initial(FORCE_VN_VERSION, &dcid, &scid);
    tokio::time::timeout(timeout, socket.send(&packet))
        .await
        .ok()?
        .ok()?;

    let mut buf = vec![0u8; 2048];
    let n = tokio::time::timeout(timeout, socket.recv(&mut buf))
        .await
        .ok()?
        .ok()?;
    parse_version_negotiation(&buf[..n], &dcid, &scid)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DCID: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];
    const SCID: &[u8] = &[9, 10, 11, 12, 13, 14, 15, 16];

    /// Build the reply a compliant server would send.
    fn vn_packet(dcid: &[u8], scid: &[u8], versions: &[u32]) -> Vec<u8> {
        let mut p = vec![0b1100_0000];
        p.extend_from_slice(&0u32.to_be_bytes()); // version 0 = negotiation
                                                  // Echoed with the roles swapped.
        p.push(scid.len() as u8);
        p.extend_from_slice(scid);
        p.push(dcid.len() as u8);
        p.extend_from_slice(dcid);
        for v in versions {
            p.extend_from_slice(&v.to_be_bytes());
        }
        p
    }

    #[test]
    fn initial_packet_has_a_valid_long_header() {
        let pkt = build_initial(FORCE_VN_VERSION, DCID, SCID);
        assert_eq!(
            pkt.len(),
            MIN_INITIAL_DATAGRAM,
            "a short Initial may be dropped without a reply"
        );
        assert_eq!(pkt[0] & 0x80, 0x80, "long header form");
        assert_eq!(pkt[0] & 0x40, 0x40, "fixed bit");
        assert_eq!(pkt[0] & 0x30, 0x00, "Initial packet type");
        assert_eq!(
            u32::from_be_bytes([pkt[1], pkt[2], pkt[3], pkt[4]]),
            FORCE_VN_VERSION
        );
        assert_eq!(pkt[5] as usize, DCID.len());
        assert_eq!(&pkt[6..6 + DCID.len()], DCID);
        let at = 6 + DCID.len();
        assert_eq!(pkt[at] as usize, SCID.len());
        assert_eq!(&pkt[at + 1..at + 1 + SCID.len()], SCID);
    }

    #[test]
    fn the_forced_version_is_a_reserved_one() {
        // RFC 9000 reserves 0x?a?a?a?a precisely to force negotiation. Using a
        // real version would get a handshake instead of a version list.
        assert_eq!(FORCE_VN_VERSION & 0x0f0f_0f0f, 0x0a0a_0a0a);
    }

    #[test]
    fn varint_encodes_each_width() {
        let enc = |v: u64| {
            let mut out = Vec::new();
            varint(v, &mut out);
            out
        };
        assert_eq!(enc(0), vec![0x00]);
        assert_eq!(enc(37), vec![0x25]);
        assert_eq!(enc(63), vec![0x3f], "largest 1-byte value");
        assert_eq!(enc(64), vec![0x40, 0x40], "first 2-byte value");
        assert_eq!(enc(16_383), vec![0x7f, 0xff]);
        assert_eq!(enc(16_384)[0] & 0xc0, 0x80, "4-byte form");
        assert_eq!(enc(1 << 30)[0] & 0xc0, 0xc0, "8-byte form");
    }

    #[test]
    fn parses_a_version_list() {
        let reply = vn_packet(DCID, SCID, &[0x0000_0001, 0x6b33_43cf, 0xff00_001d]);
        let info = parse_version_negotiation(&reply, DCID, SCID).expect("valid negotiation");
        assert_eq!(info.versions, vec![0x0000_0001, 0x6b33_43cf, 0xff00_001d]);
        assert_eq!(info.version_names(), vec!["QUICv1", "QUICv2", "draft-29"]);
        assert_eq!(info.newest_standard(), Some(0x6b33_43cf), "v2 beats v1");
    }

    #[test]
    fn a_reply_for_someone_elses_probe_is_rejected() {
        // The reply is unauthenticated, so the connection IDs are the only
        // thing tying it to our packet.
        let reply = vn_packet(DCID, SCID, &[1]);
        assert!(parse_version_negotiation(&reply, b"different", SCID).is_none());
        assert!(parse_version_negotiation(&reply, DCID, b"different").is_none());
        assert!(
            parse_version_negotiation(&reply, DCID, SCID).is_some(),
            "the matching case must still pass"
        );
    }

    #[test]
    fn non_negotiation_packets_are_rejected() {
        // Short header.
        assert!(parse_version_negotiation(&[0x40, 0, 0, 0, 0, 0, 0], DCID, SCID).is_none());
        // Long header but a real version: that is a handshake, not a version list.
        let mut handshake = vn_packet(DCID, SCID, &[1]);
        handshake[1..5].copy_from_slice(&1u32.to_be_bytes());
        assert!(parse_version_negotiation(&handshake, DCID, SCID).is_none());
        // Truncated, empty, and ragged version lists.
        assert!(parse_version_negotiation(&[], DCID, SCID).is_none());
        assert!(parse_version_negotiation(&vn_packet(DCID, SCID, &[]), DCID, SCID).is_none());
        let mut ragged = vn_packet(DCID, SCID, &[1]);
        ragged.pop();
        assert!(parse_version_negotiation(&ragged, DCID, SCID).is_none());
        // A header claiming a longer CID than the packet holds.
        let mut lying = vn_packet(DCID, SCID, &[1]);
        lying[5] = 200;
        assert!(parse_version_negotiation(&lying, DCID, SCID).is_none());
    }

    #[test]
    fn reserved_versions_in_a_reply_are_not_reported_as_spoken() {
        // Servers may advertise a reserved version to check that clients
        // ignore unknown ones. It is not a version they speak.
        let reply = vn_packet(DCID, SCID, &[0x0a0a_0a0a, 0x0000_0001]);
        let info = parse_version_negotiation(&reply, DCID, SCID).unwrap();
        assert_eq!(info.versions, vec![0x0000_0001]);
        // A reply holding nothing but reserved versions says nothing.
        let only_reserved = vn_packet(DCID, SCID, &[0x0a0a_0a0a]);
        assert!(parse_version_negotiation(&only_reserved, DCID, SCID).is_none());
    }

    #[test]
    fn version_names_cover_the_families_in_the_wild() {
        assert_eq!(version_name(0x0000_0001), "QUICv1");
        assert_eq!(version_name(0x6b33_43cf), "QUICv2");
        assert_eq!(version_name(0xff00_001d), "draft-29");
        assert_eq!(version_name(0xff00_0020), "draft-32");
        assert!(version_name(0x5100_004b).starts_with("facebook-mvfst"));
        assert_eq!(version_name(0x1234_5678), "0x12345678");
    }

    /// Nothing is listening, so this must fail quietly rather than hang or
    /// report a service.
    #[tokio::test]
    async fn a_silent_port_yields_nothing() {
        let out = quic_info(
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            1,
            Duration::from_millis(250),
        )
        .await;
        assert!(out.is_none());
    }

    /// A fake server that answers one datagram with a version list.
    #[tokio::test]
    async fn end_to_end_against_a_fake_quic_server() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            let Ok((n, from)) = server.recv_from(&mut buf).await else {
                return;
            };
            // Echo back the CIDs the client sent, roles swapped.
            let dcid_len = usize::from(buf[5]);
            let dcid = buf[6..6 + dcid_len].to_vec();
            let scid_len = usize::from(buf[6 + dcid_len]);
            let scid = buf[7 + dcid_len..7 + dcid_len + scid_len].to_vec();
            assert_eq!(n, MIN_INITIAL_DATAGRAM, "client must pad its Initial");
            let reply = vn_packet(&dcid, &scid, &[0x0000_0001, 0x6b33_43cf]);
            let _ = server.send_to(&reply, from).await;
        });

        let svc = probe_quic(
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            port,
            Duration::from_secs(2),
        )
        .await
        .expect("the fake server should be identified");
        assert_eq!(svc.service.as_deref(), Some("quic"));
        assert_eq!(svc.product.as_deref(), Some("QUIC"));
        assert_eq!(svc.version.as_deref(), Some("QUICv2"));
        assert_eq!(svc.transport, Transport::Udp);
        assert!(
            svc.banner.as_deref().unwrap().contains("QUICv1, QUICv2"),
            "{:?}",
            svc.banner
        );
    }
}
