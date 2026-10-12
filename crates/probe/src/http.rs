//! HTTP intelligence: favicon hashing, technology and security-header
//! detection.
//!
//! The flagship capability here is the Shodan-compatible `http.favicon.hash`.
//! Shodan computes it as `mmh3.hash(base64.encodebytes(favicon_bytes))` — that
//! is, the favicon is first base64-encoded using Python's `base64.encodebytes`
//! convention (a newline every 76 output characters **and** a trailing
//! newline), and the resulting ASCII is run through MurmurHash3 x86 32-bit with
//! seed 0, returned as a *signed* 32-bit integer. Matching this exactly lets a
//! captured hash be pivoted directly against Shodan/Censys corpora.
//!
//! Fetching a favicon is pure connect-and-read: we send a single benign
//! `GET /favicon.ico` and read the reply. Nothing else is written.

use std::net::IpAddr;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use once_cell::sync::Lazy;
use regex::Regex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// Maximum favicon size we will read before giving up (plenty for an icon).
const MAX_FAVICON: usize = 512 * 1024;

/// MurmurHash3 x86 32-bit, the variant Shodan uses for favicon hashes.
///
/// This is the canonical construction from Austin Appleby's reference
/// implementation: little-endian 4-byte blocks, the `0xcc9e2d51`/`0x1b873593`
/// constants, a 13-bit rotate in the body and the standard finalizer. The
/// result is an *unsigned* 32-bit value; callers that want Shodan's signed form
/// simply reinterpret it with `as i32`.
pub fn murmur3_x86_32(data: &[u8], seed: u32) -> u32 {
    const C1: u32 = 0xcc9e_2d51;
    const C2: u32 = 0x1b87_3593;

    let mut h1 = seed;
    let nblocks = data.len() / 4;

    // Body: process whole 4-byte little-endian blocks.
    for i in 0..nblocks {
        let b = &data[i * 4..i * 4 + 4];
        let mut k1 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        k1 = k1.wrapping_mul(C1);
        k1 = k1.rotate_left(15);
        k1 = k1.wrapping_mul(C2);

        h1 ^= k1;
        h1 = h1.rotate_left(13);
        h1 = h1.wrapping_mul(5).wrapping_add(0xe654_6b64);
    }

    // Tail: the 0..3 trailing bytes.
    let tail = &data[nblocks * 4..];
    let mut k1: u32 = 0;
    if tail.len() == 3 {
        k1 ^= (tail[2] as u32) << 16;
    }
    if tail.len() >= 2 {
        k1 ^= (tail[1] as u32) << 8;
    }
    if !tail.is_empty() {
        k1 ^= tail[0] as u32;
        k1 = k1.wrapping_mul(C1);
        k1 = k1.rotate_left(15);
        k1 = k1.wrapping_mul(C2);
        h1 ^= k1;
    }

    // Finalization.
    h1 ^= data.len() as u32;
    h1 ^= h1 >> 16;
    h1 = h1.wrapping_mul(0x85eb_ca6b);
    h1 ^= h1 >> 13;
    h1 = h1.wrapping_mul(0xc2b2_ae35);
    h1 ^= h1 >> 16;
    h1
}

/// Encode `data` exactly as Python's `base64.encodebytes` does: standard
/// base64 broken into 76-character lines, each line (including the last)
/// terminated by a `\n`.
pub fn base64_encodebytes(data: &[u8]) -> Vec<u8> {
    let encoded = B64.encode(data);
    let bytes = encoded.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() + bytes.len() / 76 + 2);
    for chunk in bytes.chunks(76) {
        out.extend_from_slice(chunk);
        out.push(b'\n');
    }
    out
}

/// Compute Shodan's `http.favicon.hash` for a favicon's raw bytes.
///
/// `mmh3.hash(base64.encodebytes(bytes))`, returned as a signed `i32`.
pub fn favicon_hash(bytes: &[u8]) -> i32 {
    let encoded = base64_encodebytes(bytes);
    murmur3_x86_32(&encoded, 0) as i32
}

/// Fetch `/favicon.ico` from a plaintext HTTP service and hash it.
///
/// Returns `None` if the connection fails, the response is not a `200`, or the
/// body is empty. Strictly a single GET and one read.
pub async fn fetch_favicon_hash_plain(ip: IpAddr, port: u16, timeout: Duration) -> Option<i32> {
    let connect = TcpStream::connect((ip, port));
    let mut stream = tokio::time::timeout(timeout, connect).await.ok()?.ok()?;
    favicon_over(&mut stream, ip, timeout).await
}

/// Fetch `/favicon.ico` over an already-established stream (TLS or plaintext)
/// and hash it. `host` is used only to form the `Host:` header.
pub async fn favicon_over<S>(stream: &mut S, host: IpAddr, timeout: Duration) -> Option<i32>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let req = format!(
        "GET /favicon.ico HTTP/1.0\r\nHost: {host}\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    tokio::time::timeout(timeout, stream.write_all(req.as_bytes()))
        .await
        .ok()?
        .ok()?;

    let raw = read_response(stream, timeout).await?;
    let (status, body) = split_response(&raw)?;
    if status != 200 || body.is_empty() {
        return None;
    }
    Some(favicon_hash(body))
}

/// Read a whole HTTP response (up to [`MAX_FAVICON`]) until EOF or timeout.
async fn read_response<S>(stream: &mut S, timeout: Duration) -> Option<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(8192);
    let mut chunk = [0u8; 8192];
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() >= MAX_FAVICON {
                    break;
                }
            }
            Ok(Err(_)) => break,
            Err(_) => break,
        }
    }
    if buf.is_empty() {
        None
    } else {
        Some(buf)
    }
}

/// Split a raw HTTP response into `(status_code, body_bytes)`.
///
/// We request with HTTP/1.0 and `Connection: close`, so the body runs to EOF
/// and no de-chunking is required.
fn split_response(raw: &[u8]) -> Option<(u16, &[u8])> {
    // Locate the header/body boundary on the raw bytes (favicon is binary).
    let sep = find_subslice(raw, b"\r\n\r\n")
        .map(|i| (i, 4))
        .or_else(|| find_subslice(raw, b"\n\n").map(|i| (i, 2)))?;
    let (head_end, sep_len) = sep;
    let head = &raw[..head_end];
    let body = &raw[head_end + sep_len..];

    let head_str = String::from_utf8_lossy(head);
    let mut lines = head_str.lines();
    let status_line = lines.next()?;
    if !status_line.starts_with("HTTP/") {
        return None;
    }
    let status = status_line.split_whitespace().nth(1)?.parse::<u16>().ok()?;

    Some((status, body))
}

/// Find the first index of `needle` within `haystack`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// The security-relevant response headers we report presence of, mapped from
/// their lowercase form to a canonical display name.
const SECURITY_HEADERS: &[(&str, &str)] = &[
    ("strict-transport-security", "Strict-Transport-Security"),
    ("content-security-policy", "Content-Security-Policy"),
    (
        "content-security-policy-report-only",
        "Content-Security-Policy-Report-Only",
    ),
    ("x-frame-options", "X-Frame-Options"),
    ("x-content-type-options", "X-Content-Type-Options"),
    ("referrer-policy", "Referrer-Policy"),
    ("permissions-policy", "Permissions-Policy"),
    ("cross-origin-opener-policy", "Cross-Origin-Opener-Policy"),
    (
        "cross-origin-resource-policy",
        "Cross-Origin-Resource-Policy",
    ),
    (
        "cross-origin-embedder-policy",
        "Cross-Origin-Embedder-Policy",
    ),
    ("x-xss-protection", "X-XSS-Protection"),
];

/// Return the canonical names of the security headers present in `headers`
/// (which must have lowercase keys), in a stable order.
pub fn detect_security_headers(headers: &[(String, String)]) -> Vec<String> {
    let mut out = Vec::new();
    for (lc, canonical) in SECURITY_HEADERS {
        if headers.iter().any(|(k, _)| k == lc) && !out.iter().any(|v| v == canonical) {
            out.push((*canonical).to_string());
        }
    }
    out
}

static META_GENERATOR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)<meta[^>]+name\s*=\s*["']?generator["']?[^>]*content\s*=\s*["']([^"'>]+)["']"#,
    )
    .expect("valid generator regex")
});

/// Lightweight, rule-based technology detection from response headers and body.
///
/// We surface what a server volunteers (`Server`, `X-Powered-By`,
/// `X-Generator`, `<meta name=generator>`) plus a handful of unmistakable
/// fingerprints in the HTML. This is intentionally conservative — it reports
/// what is plainly stated rather than guessing.
pub fn detect_technologies(headers: &[(String, String)], body: &str) -> Vec<String> {
    let mut techs: Vec<String> = Vec::new();
    let mut add = |t: String| {
        let t = t.trim().to_string();
        if !t.is_empty() && !techs.iter().any(|e| e.eq_ignore_ascii_case(&t)) {
            techs.push(t);
        }
    };

    for (k, v) in headers {
        match k.as_str() {
            "server"
            | "x-powered-by"
            | "x-generator"
            | "x-aspnet-version"
            | "x-aspnetmvc-version" => add(v.clone()),
            _ => {}
        }
    }

    if let Some(c) = META_GENERATOR_RE.captures(body) {
        if let Some(m) = c.get(1) {
            add(m.as_str().to_string());
        }
    }

    // Unmistakable in-body markers.
    const MARKERS: &[(&str, &str)] = &[
        ("/wp-content/", "WordPress"),
        ("/wp-includes/", "WordPress"),
        ("sites/all/modules", "Drupal"),
        ("Drupal.settings", "Drupal"),
        ("/media/jui/", "Joomla"),
        ("content=\"Joomla", "Joomla"),
        ("__NEXT_DATA__", "Next.js"),
        ("ng-version=", "Angular"),
        ("data-reactroot", "React"),
    ];
    for (needle, name) in MARKERS {
        if body.contains(needle) {
            add((*name).to_string());
        }
    }

    techs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn murmur3_known_vectors() {
        // Cross-checked against Python's `mmh3.hash(..., 0)` (signed).
        assert_eq!(murmur3_x86_32(b"", 0) as i32, 0);
        assert_eq!(murmur3_x86_32(b"foo", 0) as i32, -156908512);
        assert_eq!(murmur3_x86_32(b"hello", 0) as i32, 613153351);
        assert_eq!(murmur3_x86_32(b"The quick brown fox", 0) as i32, 1621279277);
    }

    #[test]
    fn encodebytes_matches_python_convention() {
        // 60 bytes -> 80 base64 chars -> "76 chars\n4 chars\n".
        let out = base64_encodebytes(&[b'A'; 60]);
        let s = String::from_utf8(out).unwrap();
        assert!(s.ends_with('\n'));
        let lines: Vec<&str> = s.trim_end_matches('\n').split('\n').collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].len(), 76);
        assert_eq!(lines[1].len(), 4);
        // Empty input encodes to a single (empty) terminated line? No: zero
        // chunks means no output at all, matching base64.encodebytes(b"").
        assert_eq!(base64_encodebytes(b""), b"");
    }

    #[test]
    fn favicon_hash_matches_reference() {
        // Reference value computed with the independent Python implementation.
        let mut fav = b"\x89PNG\r\n\x1a\n".to_vec();
        fav.extend_from_slice(&[b'A'; 200]);
        assert_eq!(favicon_hash(&fav), 1002319295);
    }

    #[test]
    fn security_headers_detected_canonically() {
        let headers = vec![
            (
                "strict-transport-security".to_string(),
                "max-age=31536000".to_string(),
            ),
            ("content-type".to_string(), "text/html".to_string()),
            ("x-frame-options".to_string(), "DENY".to_string()),
        ];
        let found = detect_security_headers(&headers);
        assert_eq!(found, vec!["Strict-Transport-Security", "X-Frame-Options"]);
    }

    #[test]
    fn technologies_from_headers_and_body() {
        let headers = vec![
            ("server".to_string(), "nginx/1.24.0".to_string()),
            ("x-powered-by".to_string(), "PHP/8.2.0".to_string()),
        ];
        let body = r#"<html><head><meta name="generator" content="WordPress 6.4"></head>
            <body><img src="/wp-content/uploads/x.png"></body></html>"#;
        let techs = detect_technologies(&headers, body);
        assert!(techs.iter().any(|t| t == "nginx/1.24.0"));
        assert!(techs.iter().any(|t| t == "PHP/8.2.0"));
        assert!(techs.iter().any(|t| t == "WordPress 6.4"));
        assert!(techs.iter().any(|t| t == "WordPress"));
    }

    #[test]
    fn split_response_parses_status_and_body() {
        let raw = b"HTTP/1.0 200 OK\r\nContent-Type: image/x-icon\r\n\r\n\x00\x01\x02\x03";
        let (status, body) = split_response(raw).unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, &[0, 1, 2, 3]);
    }
}
