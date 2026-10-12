//! Banner grabbing and HTTP response parsing.
//!
//! All network activity here is strictly connect-and-read: we open a TCP
//! connection and read whatever the service sends. For well-known HTTP ports
//! we first send a single, benign `GET / HTTP/1.0` request so the server has a
//! reason to speak. No authentication is attempted and no exploit payload is
//! ever written — the only bytes we transmit are that plain GET.

use std::net::IpAddr;
use std::time::Duration;

use once_cell::sync::Lazy;
use regex::Regex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crusade_core::HttpInfo;

/// Maximum number of banner bytes we retain.
pub const MAX_BANNER: usize = 8 * 1024;

/// Ports we treat as plaintext HTTP (so we send a GET to elicit a response).
pub fn is_http_port(port: u16) -> bool {
    matches!(
        port,
        80 | 81 | 591 | 2080 | 8000 | 8008 | 8080 | 8081 | 8088 | 8888 | 9080 | 5000 | 3000
    )
}

/// Connect to `ip:port`, optionally send a benign HTTP GET, and return the
/// first chunk of bytes the service sends (capped at [`MAX_BANNER`]).
///
/// Returns `None` on connect/read timeout, connection failure, or empty reply.
pub async fn grab_banner(ip: IpAddr, port: u16, timeout: Duration) -> Option<Vec<u8>> {
    let connect = TcpStream::connect((ip, port));
    let mut stream = tokio::time::timeout(timeout, connect).await.ok()?.ok()?;

    if is_http_port(port) {
        let req = format!("GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n");
        let _ = tokio::time::timeout(timeout, stream.write_all(req.as_bytes()))
            .await
            .ok()?;
    }

    read_capped(&mut stream, timeout).await
}

/// Read up to [`MAX_BANNER`] bytes, stopping at the timeout or on EOF.
async fn read_capped(stream: &mut TcpStream, timeout: Duration) -> Option<Vec<u8>> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => break,        // clean EOF
            Ok(Ok(n)) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() >= MAX_BANNER {
                    buf.truncate(MAX_BANNER);
                    break;
                }
            }
            Ok(Err(_)) => break, // read error
            Err(_) => break,     // timed out
        }
    }

    if buf.is_empty() {
        None
    } else {
        Some(buf)
    }
}

static TITLE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?is)<title[^>]*>(.*?)</title>").expect("valid title regex"));

/// Parse a raw HTTP response into [`HttpInfo`] (status, `Server`, `<title>`).
///
/// Returns `None` if the bytes are not a plausible HTTP response.
pub fn parse_http(raw: &[u8]) -> Option<HttpInfo> {
    let text = String::from_utf8_lossy(raw);

    // Split headers from body at the first blank line.
    let (head, body) = match text.find("\r\n\r\n") {
        Some(i) => (&text[..i], &text[i + 4..]),
        None => match text.find("\n\n") {
            Some(i) => (&text[..i], &text[i + 2..]),
            None => (text.as_ref(), ""),
        },
    };

    let mut lines = head.lines();
    let status_line = lines.next()?;
    if !status_line.starts_with("HTTP/") {
        return None;
    }
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok());

    let mut server = None;
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim().to_string();
            if key == "server" {
                server = Some(val.clone());
            }
            headers.push((key, val));
        }
    }

    let title = TITLE_RE.captures(body).and_then(|c| c.get(1)).map(|m| {
        let t = m.as_str().trim();
        // Collapse internal whitespace for a tidy title.
        t.split_whitespace().collect::<Vec<_>>().join(" ")
    });

    // Passive enrichment from the headers and body we already have. The
    // favicon hash is a separate network fetch, so it is left `None` here and
    // populated by the orchestrator (see [`crate::http::favicon_over`]).
    let security_headers = crate::http::detect_security_headers(&headers);
    let technologies = crate::http::detect_technologies(&headers, body);

    Some(HttpInfo {
        status,
        server,
        title,
        headers,
        favicon_hash: None,
        technologies,
        security_headers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_http_response() {
        let raw = b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html\r\n\r\n<html><head><title>  Hello  World </title></head></html>";
        let info = parse_http(raw).expect("valid http");
        assert_eq!(info.status, Some(200));
        assert_eq!(info.server.as_deref(), Some("nginx/1.24.0"));
        assert_eq!(info.title.as_deref(), Some("Hello World"));
        assert!(info
            .headers
            .iter()
            .any(|(k, v)| k == "content-type" && v == "text/html"));
    }

    #[test]
    fn non_http_is_rejected() {
        assert!(parse_http(b"SSH-2.0-OpenSSH_8.9p1\r\n").is_none());
    }

    #[test]
    fn http_without_title_ok() {
        let raw = b"HTTP/1.0 404 Not Found\r\nServer: Apache\r\n\r\nnope";
        let info = parse_http(raw).unwrap();
        assert_eq!(info.status, Some(404));
        assert_eq!(info.server.as_deref(), Some("Apache"));
        assert_eq!(info.title, None);
    }

    #[test]
    fn http_port_classification() {
        assert!(is_http_port(80));
        assert!(is_http_port(8080));
        assert!(!is_http_port(22));
        assert!(!is_http_port(443));
    }
}
