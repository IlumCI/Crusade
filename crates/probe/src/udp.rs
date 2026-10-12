//! UDP service probes.
//!
//! Some of the most interesting services on the Internet speak UDP and never
//! say a word until asked the right question. For each protocol we know, we
//! send exactly **one** small, standards-shaped, read-only request and read a
//! single reply — never a second packet, never anything that could be used to
//! amplify traffic at a third party. The payloads are the same ones an
//! ordinary client would send (a DNS `version.bind` query, an NTP client
//! request, an SNMP `sysDescr.0` GET with the `public` community, an SSDP
//! `M-SEARCH`, a NetBIOS node-status request).
//!
//! Each probe parses the reply into a [`Service`] with `transport = Udp`. The
//! parsers are pure and unit-tested on captured bytes; the socket I/O is a thin
//! best-effort wrapper around them.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;

use crusade_core::{Service, Transport};

/// Maximum reply bytes we read from a single datagram exchange.
const MAX_UDP_REPLY: usize = 4096;

/// Probe a UDP `(ip, port)` using the protocol appropriate to that port.
///
/// Returns `None` for ports we have no probe for, or when no usable reply
/// arrives. Exactly one request is sent and one reply read.
pub async fn probe_udp_service(ip: IpAddr, port: u16, timeout: Duration) -> Option<Service> {
    match port {
        53 => probe_dns(ip, port, timeout).await,
        123 => probe_ntp(ip, port, timeout).await,
        137 => probe_netbios(ip, port, timeout).await,
        161 => probe_snmp(ip, port, timeout).await,
        1900 => probe_ssdp(ip, port, timeout).await,
        _ => None,
    }
}

/// Send `payload` to `ip:port` over UDP and read a single reply.
async fn udp_roundtrip(
    ip: IpAddr,
    port: u16,
    payload: &[u8],
    timeout: Duration,
) -> Option<Vec<u8>> {
    let bind: SocketAddr = match ip {
        IpAddr::V4(_) => "0.0.0.0:0".parse().ok()?,
        IpAddr::V6(_) => "[::]:0".parse().ok()?,
    };
    let sock = UdpSocket::bind(bind).await.ok()?;
    sock.connect((ip, port)).await.ok()?;
    sock.send(payload).await.ok()?;

    let mut buf = vec![0u8; MAX_UDP_REPLY];
    let n = tokio::time::timeout(timeout, sock.recv(&mut buf))
        .await
        .ok()?
        .ok()?;
    buf.truncate(n);
    if buf.is_empty() {
        None
    } else {
        Some(buf)
    }
}

// --- DNS (version.bind) ----------------------------------------------------

/// Build a `version.bind` CHAOS/TXT query (the classic BIND version probe).
pub fn build_dns_version_query() -> Vec<u8> {
    let mut q = Vec::new();
    q.extend_from_slice(&[0x13, 0x37]); // transaction id
    q.extend_from_slice(&[0x01, 0x00]); // flags: standard query, RD
    q.extend_from_slice(&[0x00, 0x01]); // qdcount = 1
    q.extend_from_slice(&[0x00, 0x00]); // ancount
    q.extend_from_slice(&[0x00, 0x00]); // nscount
    q.extend_from_slice(&[0x00, 0x00]); // arcount
    // QNAME: "version" "bind" 0
    q.push(7);
    q.extend_from_slice(b"version");
    q.push(4);
    q.extend_from_slice(b"bind");
    q.push(0);
    q.extend_from_slice(&[0x00, 0x10]); // QTYPE = TXT
    q.extend_from_slice(&[0x00, 0x03]); // QCLASS = CHAOS
    q
}

/// Extract the first answer TXT string from a `version.bind` response.
pub fn parse_dns_version_bind(resp: &[u8]) -> Option<String> {
    if resp.len() < 12 {
        return None;
    }
    let ancount = u16::from_be_bytes([resp[6], resp[7]]);
    if ancount == 0 {
        return None;
    }
    // Skip the question.
    let mut off = skip_dns_name(resp, 12)?;
    off += 4; // qtype + qclass
    // First answer RR.
    off = skip_dns_name(resp, off)?;
    // type(2) class(2) ttl(4) rdlength(2)
    let rdlength = u16::from_be_bytes([*resp.get(off + 8)?, *resp.get(off + 9)?]) as usize;
    let rdata_start = off + 10;
    let rdata = resp.get(rdata_start..rdata_start + rdlength)?;
    // TXT rdata: one-byte length + string.
    let txt_len = *rdata.first()? as usize;
    let txt = rdata.get(1..1 + txt_len)?;
    let s = String::from_utf8_lossy(txt).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Advance past a DNS name at `off`, handling labels and 0xC0 compression
/// pointers. Returns the offset just past the name in the packet.
fn skip_dns_name(buf: &[u8], mut off: usize) -> Option<usize> {
    loop {
        let len = *buf.get(off)? as usize;
        if len == 0 {
            return Some(off + 1);
        }
        if len & 0xc0 == 0xc0 {
            // Compression pointer: two bytes, name ends here.
            return Some(off + 2);
        }
        off += 1 + len;
    }
}

async fn probe_dns(ip: IpAddr, port: u16, timeout: Duration) -> Option<Service> {
    let resp = udp_roundtrip(ip, port, &build_dns_version_query(), timeout).await?;
    let mut svc = Service::new(port, Transport::Udp);
    svc.service = Some("dns".to_string());
    if let Some(version) = parse_dns_version_bind(&resp) {
        svc.product = Some("DNS".to_string());
        svc.version = Some(version.clone());
        svc.banner = Some(version);
    } else {
        // A reply that is not a usable version.bind answer still confirms DNS.
        svc.product = Some("DNS".to_string());
    }
    Some(svc)
}

// --- NTP --------------------------------------------------------------------

/// Build a 48-byte NTPv3 mode-3 (client) request. Benign and non-amplifying.
pub fn build_ntp_client_request() -> Vec<u8> {
    let mut p = vec![0u8; 48];
    // LI = 0, VN = 3, Mode = 3 (client).
    p[0] = 0x1b;
    p
}

/// Summarise an NTP reply (version, mode, stratum) if it looks like one.
pub fn parse_ntp(resp: &[u8]) -> Option<String> {
    if resp.len() < 4 {
        return None;
    }
    let vn = (resp[0] >> 3) & 0x07;
    let mode = resp[0] & 0x07;
    // Mode 4 = server reply; anything else is still an NTP-shaped datagram.
    let stratum = resp[1];
    Some(format!("NTPv{vn} mode {mode} stratum {stratum}"))
}

async fn probe_ntp(ip: IpAddr, port: u16, timeout: Duration) -> Option<Service> {
    let resp = udp_roundtrip(ip, port, &build_ntp_client_request(), timeout).await?;
    let mut svc = Service::new(port, Transport::Udp);
    svc.service = Some("ntp".to_string());
    svc.product = Some("NTP".to_string());
    svc.banner = parse_ntp(&resp);
    Some(svc)
}

// --- SNMP (v2c sysDescr.0) --------------------------------------------------

/// Build an SNMP v2c `GET sysDescr.0` request with the `public` community.
pub fn build_snmp_get_sysdescr(community: &str) -> Vec<u8> {
    // sysDescr.0 = 1.3.6.1.2.1.1.1.0
    let oid: &[u8] = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];
    let null: &[u8] = &[0x05, 0x00];

    let varbind = ber_seq(0x30, &[oid, null].concat());
    let varbindlist = ber_seq(0x30, &varbind);
    let request_id = &[0x02, 0x04, 0x01, 0x02, 0x03, 0x04]; // INTEGER request-id
    let error_status = &[0x02, 0x01, 0x00];
    let error_index = &[0x02, 0x01, 0x00];
    let mut pdu_body = Vec::new();
    pdu_body.extend_from_slice(request_id);
    pdu_body.extend_from_slice(error_status);
    pdu_body.extend_from_slice(error_index);
    pdu_body.extend_from_slice(&varbindlist);
    let pdu = ber_seq(0xa0, &pdu_body); // GetRequest PDU

    let version = &[0x02, 0x01, 0x01]; // v2c
    let mut community_tlv = vec![0x04, community.len() as u8];
    community_tlv.extend_from_slice(community.as_bytes());

    let mut msg_body = Vec::new();
    msg_body.extend_from_slice(version);
    msg_body.extend_from_slice(&community_tlv);
    msg_body.extend_from_slice(&pdu);
    ber_seq(0x30, &msg_body)
}

/// Wrap `body` in a BER TLV with the given `tag` (short/long length form).
fn ber_seq(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = body.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = (len as u32).to_be_bytes();
        let first = bytes.iter().position(|&b| b != 0).unwrap_or(3);
        let sig = &bytes[first..];
        out.push(0x80 | sig.len() as u8);
        out.extend_from_slice(sig);
    }
    out.extend_from_slice(body);
    out
}

/// Read one BER TLV from `buf`, returning `(tag, value, rest)`.
fn read_tlv(buf: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *buf.first()?;
    let b1 = *buf.get(1)? as usize;
    let (len, hdr) = if b1 & 0x80 == 0 {
        (b1, 2)
    } else {
        let n = b1 & 0x7f;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | (*buf.get(2 + i)? as usize);
        }
        (len, 2 + n)
    };
    let value = buf.get(hdr..hdr + len)?;
    let rest = &buf[hdr + len..];
    Some((tag, value, rest))
}

/// Extract the `sysDescr.0` OCTET STRING from an SNMP GET-response.
pub fn parse_snmp_sysdescr(resp: &[u8]) -> Option<String> {
    let (tag, msg, _) = read_tlv(resp)?;
    if tag != 0x30 {
        return None;
    }
    // version INTEGER
    let (_, _, rest) = read_tlv(msg).filter(|(t, ..)| *t == 0x02)?;
    // community OCTET STRING
    let (_, _, rest) = read_tlv(rest).filter(|(t, ..)| *t == 0x04)?;
    // PDU (context-specific: GetResponse is 0xa2, but accept any 0xa0..=0xbf)
    let (ptag, pdu, _) = read_tlv(rest)?;
    if !(0xa0..=0xbf).contains(&ptag) {
        return None;
    }
    // request-id, error-status, error-index
    let (_, _, rest) = read_tlv(pdu)?;
    let (_, _, rest) = read_tlv(rest)?;
    let (_, _, rest) = read_tlv(rest)?;
    // varbindlist SEQUENCE
    let (_, vbl, _) = read_tlv(rest).filter(|(t, ..)| *t == 0x30)?;
    // first varbind SEQUENCE
    let (_, vb, _) = read_tlv(vbl).filter(|(t, ..)| *t == 0x30)?;
    // OID, then the value
    let (_, _, after_oid) = read_tlv(vb).filter(|(t, ..)| *t == 0x06)?;
    let (vtag, value, _) = read_tlv(after_oid)?;
    if vtag != 0x04 {
        return None;
    }
    let s = String::from_utf8_lossy(value).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

async fn probe_snmp(ip: IpAddr, port: u16, timeout: Duration) -> Option<Service> {
    let resp = udp_roundtrip(ip, port, &build_snmp_get_sysdescr("public"), timeout).await?;
    let mut svc = Service::new(port, Transport::Udp);
    svc.service = Some("snmp".to_string());
    if let Some(descr) = parse_snmp_sysdescr(&resp) {
        svc.product = Some("SNMP".to_string());
        svc.banner = Some(descr);
    } else {
        svc.product = Some("SNMP".to_string());
    }
    Some(svc)
}

// --- SSDP (UPnP) ------------------------------------------------------------

/// Build a unicast SSDP `M-SEARCH` request (sent only to the target host).
pub fn build_ssdp_msearch() -> Vec<u8> {
    let req = "M-SEARCH * HTTP/1.1\r\n\
               HOST: 239.255.255.250:1900\r\n\
               MAN: \"ssdp:discover\"\r\n\
               MX: 1\r\n\
               ST: ssdp:all\r\n\r\n";
    req.as_bytes().to_vec()
}

/// Pull the `SERVER:` header value out of an SSDP reply.
pub fn parse_ssdp_server(resp: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(resp);
    for line in text.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("server") {
                let v = v.trim().to_string();
                if !v.is_empty() {
                    return Some(v);
                }
            }
        }
    }
    None
}

async fn probe_ssdp(ip: IpAddr, port: u16, timeout: Duration) -> Option<Service> {
    let resp = udp_roundtrip(ip, port, &build_ssdp_msearch(), timeout).await?;
    let mut svc = Service::new(port, Transport::Udp);
    svc.service = Some("upnp".to_string());
    if let Some(server) = parse_ssdp_server(&resp) {
        svc.product = Some(server.clone());
        svc.banner = Some(server);
    } else {
        svc.banner = Some(
            String::from_utf8_lossy(&resp)
                .lines()
                .next()
                .unwrap_or("")
                .trim()
                .to_string(),
        );
    }
    Some(svc)
}

// --- NetBIOS name service ---------------------------------------------------

/// Build a NetBIOS node-status (NBSTAT) request for the wildcard name `*`.
pub fn build_netbios_nodestatus() -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&[0x43, 0x72]); // transaction id
    p.extend_from_slice(&[0x00, 0x00]); // flags
    p.extend_from_slice(&[0x00, 0x01]); // qdcount
    p.extend_from_slice(&[0x00, 0x00]); // ancount
    p.extend_from_slice(&[0x00, 0x00]); // nscount
    p.extend_from_slice(&[0x00, 0x00]); // arcount
    // Encoded name "*" (0x2a then 15 nulls) -> first-level encoding.
    p.push(0x20); // 32-byte encoded name
    p.extend_from_slice(&encode_netbios_name(b"*"));
    p.push(0x00); // name terminator
    p.extend_from_slice(&[0x00, 0x21]); // QTYPE = NBSTAT
    p.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN
    p
}

/// First-level encode a (up to 16-byte) NetBIOS name, zero-padded to 16 bytes.
fn encode_netbios_name(name: &[u8]) -> Vec<u8> {
    let mut padded = [0u8; 16];
    for (i, b) in name.iter().take(16).enumerate() {
        padded[i] = *b;
    }
    let mut out = Vec::with_capacity(32);
    for b in padded {
        out.push(b'A' + (b >> 4));
        out.push(b'A' + (b & 0x0f));
    }
    out
}

/// Parse the registered NetBIOS names out of a node-status response.
pub fn parse_netbios_names(resp: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    let mut parse = || -> Option<()> {
        // Header is 12 bytes; then the (echoed) question.
        let mut off = skip_dns_name(resp, 12)?;
        off += 4; // qtype + qclass
        // Answer RR header.
        off = skip_dns_name(resp, off)?;
        let rdlength = u16::from_be_bytes([*resp.get(off + 8)?, *resp.get(off + 9)?]) as usize;
        let rdata_start = off + 10;
        let rdata = resp.get(rdata_start..rdata_start + rdlength)?;
        let num = *rdata.first()? as usize;
        for i in 0..num {
            let base = 1 + i * 18;
            let entry = rdata.get(base..base + 16)?;
            let name = String::from_utf8_lossy(&entry[..15])
                .trim_end_matches([' ', '\0'])
                .trim()
                .to_string();
            if !name.is_empty() {
                names.push(name);
            }
        }
        Some(())
    };
    let _ = parse();
    names.dedup();
    names
}

async fn probe_netbios(ip: IpAddr, port: u16, timeout: Duration) -> Option<Service> {
    let resp = udp_roundtrip(ip, port, &build_netbios_nodestatus(), timeout).await?;
    let names = parse_netbios_names(&resp);
    let mut svc = Service::new(port, Transport::Udp);
    svc.service = Some("netbios-ns".to_string());
    svc.product = Some("NetBIOS".to_string());
    if !names.is_empty() {
        svc.banner = Some(names.join(", "));
    }
    Some(svc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_query_is_well_formed() {
        let q = build_dns_version_query();
        assert_eq!(&q[4..6], &[0x00, 0x01]); // qdcount
        // Ends with TXT/CHAOS.
        assert_eq!(&q[q.len() - 4..], &[0x00, 0x10, 0x00, 0x03]);
        assert!(q.windows(7).any(|w| w == b"version"));
    }

    #[test]
    fn parses_version_bind_response() {
        // Header: id, flags(response), qd=1, an=1.
        let mut r: Vec<u8> = vec![0x13, 0x37, 0x84, 0x00, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 0];
        // Question: version.bind TXT CHAOS.
        r.push(7);
        r.extend_from_slice(b"version");
        r.push(4);
        r.extend_from_slice(b"bind");
        r.push(0);
        r.extend_from_slice(&[0x00, 0x10, 0x00, 0x03]);
        // Answer: name pointer to 0x0c, TXT, CHAOS, ttl, rdlength, rdata.
        r.extend_from_slice(&[0xc0, 0x0c]); // name pointer
        r.extend_from_slice(&[0x00, 0x10]); // type TXT
        r.extend_from_slice(&[0x00, 0x03]); // class CHAOS
        r.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ttl
        let txt = b"9.18.1-Debian";
        let rdata_len = (1 + txt.len()) as u16;
        r.extend_from_slice(&rdata_len.to_be_bytes());
        r.push(txt.len() as u8);
        r.extend_from_slice(txt);

        assert_eq!(parse_dns_version_bind(&r).as_deref(), Some("9.18.1-Debian"));
    }

    #[test]
    fn snmp_request_round_trips_through_parser() {
        // Build a GET, then hand-craft a matching GET-response and parse it.
        let get = build_snmp_get_sysdescr("public");
        // Sanity: it's a SEQUENCE and contains the community string.
        assert_eq!(get[0], 0x30);
        assert!(get.windows(6).any(|w| w == b"public"));

        // Craft a response: SEQUENCE { INTEGER 1, OCTET "public",
        //   a2 { INTEGER id, INTEGER 0, INTEGER 0,
        //        SEQ { SEQ { OID sysDescr.0, OCTET "Linux router" } } } }
        let descr = b"Linux router";
        let value = {
            let mut v = vec![0x04, descr.len() as u8];
            v.extend_from_slice(descr);
            v
        };
        let oid: &[u8] = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];
        let vb = ber_seq(0x30, &[oid, &value].concat());
        let vbl = ber_seq(0x30, &vb);
        let mut pdu_body = vec![0x02, 0x04, 0x01, 0x02, 0x03, 0x04];
        pdu_body.extend_from_slice(&[0x02, 0x01, 0x00, 0x02, 0x01, 0x00]);
        pdu_body.extend_from_slice(&vbl);
        let pdu = ber_seq(0xa2, &pdu_body);
        let mut body = vec![0x02, 0x01, 0x01, 0x04, 0x06];
        body.extend_from_slice(b"public");
        body.extend_from_slice(&pdu);
        let resp = ber_seq(0x30, &body);

        assert_eq!(parse_snmp_sysdescr(&resp).as_deref(), Some("Linux router"));
    }

    #[test]
    fn ber_length_long_form() {
        let body = vec![0u8; 200];
        let tlv = ber_seq(0x04, &body);
        // 0x04, 0x81, 0xc8, <200 bytes>.
        assert_eq!(&tlv[..3], &[0x04, 0x81, 0xc8]);
        assert_eq!(tlv.len(), 3 + 200);
    }

    #[test]
    fn ssdp_server_header_extracted() {
        let resp = b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nSERVER: Linux/3.14 UPnP/1.0 MiniUPnPd/1.9\r\n\r\n";
        assert_eq!(
            parse_ssdp_server(resp).as_deref(),
            Some("Linux/3.14 UPnP/1.0 MiniUPnPd/1.9")
        );
    }

    #[test]
    fn netbios_name_encoding() {
        // "*" encodes to "CK" followed by 30 'A's.
        let enc = encode_netbios_name(b"*");
        assert_eq!(enc.len(), 32);
        assert_eq!(&enc[..2], b"CK");
        assert!(enc[2..].iter().all(|&b| b == b'A'));
    }

    #[test]
    fn parses_netbios_node_status() {
        let mut r: Vec<u8> = vec![0x43, 0x72, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0, 0, 0, 0];
        // Echoed question name (encoded "*") + type/class.
        r.push(0x20);
        r.extend_from_slice(&encode_netbios_name(b"*"));
        r.push(0x00);
        r.extend_from_slice(&[0x00, 0x21, 0x00, 0x01]);
        // Answer RR: name pointer, type NBSTAT, class IN, ttl, rdlength, rdata.
        r.extend_from_slice(&[0xc0, 0x0c]);
        r.extend_from_slice(&[0x00, 0x21, 0x00, 0x01]);
        r.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // rdata: 1 name entry.
        let mut rdata = vec![0x01u8];
        let mut name = *b"FILESERVER     "; // 15 bytes, space-padded
        name[14] = b' ';
        rdata.extend_from_slice(&name);
        rdata.push(0x00); // suffix (16th name byte)
        rdata.extend_from_slice(&[0x04, 0x00]); // name flags
        r.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        r.extend_from_slice(&rdata);

        let names = parse_netbios_names(&r);
        assert_eq!(names, vec!["FILESERVER"]);
    }
}
