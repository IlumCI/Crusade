//! SSH intelligence: identification banner, host-key type, offered key
//! exchange algorithms and the HASSH server fingerprint.
//!
//! The exchange is strictly connect-and-read in spirit: we send our own
//! identification string and a client `KEXINIT` (the two messages any SSH
//! client must send to make the server reveal its algorithm preferences), then
//! read and parse the server's identification and `KEXINIT`. No authentication
//! is attempted and the key exchange is never completed, so no credentials or
//! session material ever change hands.
//!
//! HASSH (Salesforce, 2018) is an MD5 over the server's key-exchange,
//! encryption, MAC and compression name-lists (server-to-client direction),
//! joined with semicolons — a compact, implementation-revealing fingerprint
//! that pivots the same way Shodan's `ssh.hassh` does.

use std::net::IpAddr;
use std::time::Duration;

use md5::{Digest as _, Md5};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crusade_core::SshInfo;

/// Our identification string (RFC 4253 §4.2). Benign and honest.
const CLIENT_ID: &[u8] = b"SSH-2.0-Crusade_0.1\r\n";

/// SSH message number for `KEXINIT`.
const SSH_MSG_KEXINIT: u8 = 20;

/// Maximum bytes we will buffer while hunting for the server `KEXINIT`.
const MAX_SSH_READ: usize = 64 * 1024;

/// A parsed `SSH_MSG_KEXINIT` payload: the ten algorithm name-lists.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KexInit {
    pub kex_algorithms: Vec<String>,
    pub server_host_key_algorithms: Vec<String>,
    pub encryption_c2s: Vec<String>,
    pub encryption_s2c: Vec<String>,
    pub mac_c2s: Vec<String>,
    pub mac_s2c: Vec<String>,
    pub compression_c2s: Vec<String>,
    pub compression_s2c: Vec<String>,
}

/// Parse a `KEXINIT` payload (first byte must be [`SSH_MSG_KEXINIT`]).
///
/// Layout: `byte msg; byte[16] cookie;` then ten `name-list`s (each a
/// `uint32 length` followed by comma-separated ASCII). We decode the eight
/// lists HASSH and host-key detection need; the two trailing language lists
/// and the boolean/reserved tail are ignored.
pub fn parse_kexinit(payload: &[u8]) -> Option<KexInit> {
    if payload.first().copied()? != SSH_MSG_KEXINIT {
        return None;
    }
    // Skip message type (1) + cookie (16).
    let mut off = 17usize;
    let mut next = || -> Option<Vec<String>> {
        let list = read_name_list(payload, off)?;
        off = list.1;
        Some(list.0)
    };
    Some(KexInit {
        kex_algorithms: next()?,
        server_host_key_algorithms: next()?,
        encryption_c2s: next()?,
        encryption_s2c: next()?,
        mac_c2s: next()?,
        mac_s2c: next()?,
        compression_c2s: next()?,
        compression_s2c: next()?,
    })
}

/// Read a single `name-list` at `off`, returning the entries and the new
/// offset (one past the list).
fn read_name_list(buf: &[u8], off: usize) -> Option<(Vec<String>, usize)> {
    let len_bytes = buf.get(off..off + 4)?;
    let len = u32::from_be_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
    let start = off + 4;
    let body = buf.get(start..start + len)?;
    let text = std::str::from_utf8(body).ok()?;
    let entries = if text.is_empty() {
        Vec::new()
    } else {
        text.split(',').map(|s| s.to_string()).collect()
    };
    Some((entries, start + len))
}

/// Compute a HASSH-style MD5 (hex) over four semicolon-joined name-list
/// strings. Each argument is the comma-separated list exactly as offered.
pub fn hassh(kex: &str, encryption: &str, mac: &str, compression: &str) -> String {
    let joined = format!("{kex};{encryption};{mac};{compression}");
    let mut hasher = Md5::new();
    hasher.update(joined.as_bytes());
    hex::encode(hasher.finalize())
}

/// The HASSH *server* fingerprint for a parsed `KEXINIT` (server-to-client
/// algorithm directions).
pub fn hassh_server(k: &KexInit) -> String {
    hassh(
        &k.kex_algorithms.join(","),
        &k.encryption_s2c.join(","),
        &k.mac_s2c.join(","),
        &k.compression_s2c.join(","),
    )
}

/// Frame a payload into an unencrypted SSH binary packet (RFC 4253 §6).
///
/// `packet_length || padding_length || payload || random padding`, padded so
/// the whole packet is a multiple of 8 bytes with at least 4 padding bytes.
fn frame_packet(payload: &[u8]) -> Vec<u8> {
    // 4 (length) is excluded from the block-size alignment; the aligned span is
    // padding_length(1) + payload + padding, per the spec's note about the
    // packet_length field.
    let base = 1 + payload.len();
    let mut pad = 8 - (base % 8);
    if pad < 4 {
        pad += 8;
    }
    let packet_len = (base + pad) as u32;
    let mut out = Vec::with_capacity(4 + packet_len as usize);
    out.extend_from_slice(&packet_len.to_be_bytes());
    out.push(pad as u8);
    out.extend_from_slice(payload);
    out.resize(out.len() + pad, 0u8); // fixed padding; keys never derived
    out
}

/// Build a minimal, honest client `KEXINIT` payload advertising common,
/// standards-track algorithms. Its contents do not affect what the server
/// reports; we send it only because the protocol requires a client `KEXINIT`.
fn client_kexinit() -> Vec<u8> {
    const KEX: &str = "curve25519-sha256,ecdh-sha2-nistp256,diffie-hellman-group14-sha256";
    const HOSTKEY: &str = "ssh-ed25519,rsa-sha2-512,rsa-sha2-256";
    const ENC: &str = "chacha20-poly1305@openssh.com,aes128-ctr,aes256-ctr";
    const MAC: &str = "hmac-sha2-256,hmac-sha2-512";
    const COMP: &str = "none";

    let mut p = Vec::new();
    p.push(SSH_MSG_KEXINIT);
    p.extend_from_slice(&[0u8; 16]); // cookie (fixed; no key material derived)
    for list in [KEX, HOSTKEY, ENC, ENC, MAC, MAC, COMP, COMP, "", ""] {
        let bytes = list.as_bytes();
        p.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        p.extend_from_slice(bytes);
    }
    p.push(0); // first_kex_packet_follows = false
    p.extend_from_slice(&[0u8; 4]); // reserved
    p
}

/// Collect SSH metadata from `ip:port`.
///
/// Returns `None` only if we never obtained a server identification banner.
/// The `KEXINIT`-derived fields are best-effort and left empty/`None` when the
/// server does not reach that stage in time. Host-key SHA-256 is not computed
/// (it needs a completed key exchange) and is always `None`.
pub async fn ssh_info(ip: IpAddr, port: u16, timeout: Duration) -> Option<SshInfo> {
    let fut = collect(ip, port);
    tokio::time::timeout(timeout, fut).await.ok()?
}

async fn collect(ip: IpAddr, port: u16) -> Option<SshInfo> {
    let mut stream = TcpStream::connect((ip, port)).await.ok()?;

    // Read the server identification line (and any binary that trails it).
    let (banner, mut leftover) = read_identification(&mut stream).await?;

    // Send our identification and client KEXINIT.
    stream.write_all(CLIENT_ID).await.ok()?;
    let _ = stream.write_all(&frame_packet(&client_kexinit())).await;

    let mut info = SshInfo {
        banner: Some(banner),
        host_key_type: None,
        host_key_sha256: None,
        kex_algorithms: Vec::new(),
        hassh: None,
    };

    // Accumulate until we can parse a server packet whose payload is KEXINIT.
    let mut chunk = [0u8; 8192];
    loop {
        if let Some(payload) = extract_first_payload(&leftover) {
            if let Some(kex) = parse_kexinit(&payload) {
                info.kex_algorithms = kex.kex_algorithms.clone();
                info.host_key_type = kex.server_host_key_algorithms.first().cloned();
                info.hassh = Some(hassh_server(&kex));
                break;
            }
        }
        if leftover.len() >= MAX_SSH_READ {
            break;
        }
        match stream.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => leftover.extend_from_slice(&chunk[..n]),
            Err(_) => break,
        }
    }

    Some(info)
}

/// Read bytes until a line beginning `SSH-` arrives; return the trimmed banner
/// and any bytes that followed the line's terminator (the start of the binary
/// protocol).
async fn read_identification(stream: &mut TcpStream) -> Option<(String, Vec<u8>)> {
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    let mut chunk = [0u8; 1024];
    loop {
        // RFC 4253 allows pre-banner lines; scan for an "SSH-" line with a \n.
        if let Some((banner, rest)) = split_banner(&buf) {
            return Some((banner, rest));
        }
        if buf.len() >= 8 * 1024 {
            return None;
        }
        match stream.read(&mut chunk).await {
            Ok(0) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => return None,
        }
    }
}

/// If `buf` contains a complete `SSH-...\n` identification line, return the
/// trimmed banner and the bytes after that line.
fn split_banner(buf: &[u8]) -> Option<(String, Vec<u8>)> {
    let mut start = 0usize;
    while start < buf.len() {
        let nl = buf[start..].iter().position(|&b| b == b'\n')? + start;
        let line = &buf[start..nl];
        if line.starts_with(b"SSH-") {
            let banner = String::from_utf8_lossy(line)
                .trim_end_matches(['\r', '\n'])
                .to_string();
            return Some((banner, buf[nl + 1..].to_vec()));
        }
        start = nl + 1;
    }
    None
}

/// Parse the first complete unencrypted SSH binary packet in `buf` and return
/// its payload (message type byte first), or `None` if incomplete.
fn extract_first_payload(buf: &[u8]) -> Option<Vec<u8>> {
    let len_bytes = buf.get(0..4)?;
    let packet_len =
        u32::from_be_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
    // Sanity bound: reject absurd lengths (corrupt / not SSH).
    if !(2..=MAX_SSH_READ).contains(&packet_len) {
        return None;
    }
    let total = 4 + packet_len;
    if buf.len() < total {
        return None;
    }
    let padding_len = buf[4] as usize;
    if padding_len + 1 > packet_len {
        return None;
    }
    let payload_len = packet_len - padding_len - 1;
    buf.get(5..5 + payload_len).map(|p| p.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a name-list as it appears on the wire.
    fn nl(s: &str) -> Vec<u8> {
        let mut v = (s.len() as u32).to_be_bytes().to_vec();
        v.extend_from_slice(s.as_bytes());
        v
    }

    fn sample_kexinit() -> Vec<u8> {
        let mut p = vec![SSH_MSG_KEXINIT];
        p.extend_from_slice(&[0u8; 16]); // cookie
        p.extend(nl("curve25519-sha256,diffie-hellman-group14-sha256"));
        p.extend(nl("ssh-ed25519,rsa-sha2-512"));
        p.extend(nl("aes128-ctr,aes256-ctr")); // enc c2s
        p.extend(nl("aes128-ctr")); // enc s2c
        p.extend(nl("hmac-sha2-512")); // mac c2s
        p.extend(nl("hmac-sha2-256")); // mac s2c
        p.extend(nl("none")); // comp c2s
        p.extend(nl("none")); // comp s2c
        p.extend(nl("")); // lang c2s
        p.extend(nl("")); // lang s2c
        p.push(0);
        p.extend_from_slice(&[0u8; 4]);
        p
    }

    #[test]
    fn parses_kexinit_name_lists() {
        let kex = parse_kexinit(&sample_kexinit()).expect("valid kexinit");
        assert_eq!(
            kex.kex_algorithms,
            vec!["curve25519-sha256", "diffie-hellman-group14-sha256"]
        );
        assert_eq!(
            kex.server_host_key_algorithms,
            vec!["ssh-ed25519", "rsa-sha2-512"]
        );
        assert_eq!(kex.encryption_s2c, vec!["aes128-ctr"]);
        assert_eq!(kex.mac_s2c, vec!["hmac-sha2-256"]);
        assert_eq!(kex.compression_s2c, vec!["none"]);
    }

    #[test]
    fn rejects_non_kexinit_payload() {
        assert!(parse_kexinit(&[21, 0, 0]).is_none());
        assert!(parse_kexinit(&[]).is_none());
    }

    #[test]
    fn hassh_matches_known_md5() {
        // Cross-checked against Python hashlib.md5.
        assert_eq!(hassh("a", "b", "c", "d"), "845425be4f77f4097e014a6591497010");
        assert_eq!(
            hassh("curve25519-sha256", "aes128-ctr", "hmac-sha2-256", "none"),
            "e97d07603350d1111ec2b64bf25413c9"
        );
    }

    #[test]
    fn hassh_server_uses_s2c_directions() {
        let kex = parse_kexinit(&sample_kexinit()).unwrap();
        let expected = hassh(
            "curve25519-sha256,diffie-hellman-group14-sha256",
            "aes128-ctr",
            "hmac-sha2-256",
            "none",
        );
        assert_eq!(hassh_server(&kex), expected);
    }

    #[test]
    fn frames_packet_to_block_multiple() {
        let framed = frame_packet(&[SSH_MSG_KEXINIT, 1, 2, 3]);
        let packet_len =
            u32::from_be_bytes([framed[0], framed[1], framed[2], framed[3]]) as usize;
        assert_eq!(framed.len(), 4 + packet_len);
        // padding_length + payload + padding must be a multiple of 8.
        assert_eq!((framed.len() - 4) % 8, 0);
        assert!(framed[4] >= 4); // at least 4 padding bytes
    }

    #[test]
    fn extracts_payload_from_framed_packet() {
        let payload = sample_kexinit();
        let framed = frame_packet(&payload);
        let got = extract_first_payload(&framed).expect("complete packet");
        assert_eq!(got, payload);
        // A truncated buffer yields None.
        assert!(extract_first_payload(&framed[..framed.len() - 3]).is_none());
    }

    #[test]
    fn splits_banner_with_trailing_binary() {
        let mut buf = b"SSH-2.0-OpenSSH_9.6\r\n".to_vec();
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x0c]); // start of a packet
        let (banner, rest) = split_banner(&buf).expect("banner present");
        assert_eq!(banner, "SSH-2.0-OpenSSH_9.6");
        assert_eq!(rest, vec![0x00, 0x00, 0x00, 0x0c]);
    }

    #[test]
    fn splits_banner_after_preamble_lines() {
        let buf = b"hello from server\r\nSSH-2.0-dropbear\r\nXX".to_vec();
        let (banner, rest) = split_banner(&buf).unwrap();
        assert_eq!(banner, "SSH-2.0-dropbear");
        assert_eq!(rest, b"XX".to_vec());
    }
}
