//! Banner grabbing and HTTP response parsing.
//!
//! All network activity here is strictly connect-and-read: we open a TCP
//! connection and read whatever the service sends. For well-known HTTP ports
//! we first send a single, benign `GET / HTTP/1.0` request so the server has a
//! reason to speak. No authentication is attempted and no exploit payload is
//! ever written — the only bytes we transmit are that plain GET.
//!
//! [`grab_adaptive`] identifies the protocol instead of trusting the port
//! number, following LZR (Izhikevich et al., USENIX Security 2021: only ~3% of
//! HTTP runs on port 80): wait briefly for a server-first banner, and if the
//! service stays silent, send the same benign GET on that connection; a TLS
//! record in reply (or no reply at all) hints that the caller should try a
//! TLS handshake.

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

/// How long a silent service gets to speak first before we send a GET.
pub const SERVER_FIRST_WAIT: Duration = Duration::from_secs(2);

/// What [`grab_adaptive`] learned about a port.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Grab {
    /// Bytes the service sent (server-first banner or reply to our GET).
    /// TLS records are not kept here.
    pub raw: Option<Vec<u8>>,
    /// Whether `raw` answers a GET we sent (selects the fingerprint ruleset).
    pub sent_get: bool,
    /// The service appears to speak TLS (TLS record in reply, an HTTP server
    /// complaining about plaintext on a TLS port, or total silence).
    pub tls_hint: bool,
    /// Milliseconds the TCP handshake took: one round trip, with no
    /// application in the path.
    pub connect_ms: u32,
    /// Milliseconds from the established connection to the first byte of the
    /// answer. `None` when nothing was said. Compared against `connect_ms`
    /// this separates how far away a service is from how long it thought
    /// (see `crusade_core::Latency`).
    pub banner_ms: Option<u32>,
}

/// Protocol-agnostic first exchange (see module docs).
///
/// Known HTTP ports get the GET immediately, as [`grab_banner`] does. Every
/// other port is given [`SERVER_FIRST_WAIT`] to send a banner; if it does not,
/// the GET is sent on the same connection.
pub async fn grab_adaptive(ip: IpAddr, port: u16, timeout: Duration) -> Grab {
    let started = std::time::Instant::now();
    let connect = TcpStream::connect((ip, port));
    let Ok(Ok(mut stream)) = tokio::time::timeout(timeout, connect).await else {
        return Grab::default();
    };
    // The handshake is the one exchange the application never sees, so its
    // duration is the round trip to compare everything else against.
    let connect_ms = started.elapsed().as_millis().min(u128::from(u32::MAX)) as u32;
    let get = format!("GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n");

    // Timed from the established connection, not from the start: the clock
    // measures how long the service took to answer, not how long it took to
    // reach.
    let spoke = std::time::Instant::now();
    let since = |t: &std::time::Instant| t.elapsed().as_millis().min(u128::from(u32::MAX)) as u32;

    if !is_http_port(port) {
        if let Some(raw) = read_capped(&mut stream, timeout.min(SERVER_FIRST_WAIT)).await {
            let ms = since(&spoke);
            return Grab {
                connect_ms,
                banner_ms: Some(ms),
                ..classify(raw, false)
            };
        }
    }
    if tokio::time::timeout(timeout, stream.write_all(get.as_bytes()))
        .await
        .map_or(true, |r| r.is_err())
    {
        return Grab {
            sent_get: true,
            tls_hint: true,
            connect_ms,
            ..Grab::default()
        };
    }
    // The GET's own flight time is part of the wait, so the request is sent
    // before the clock the answer is measured against.
    let asked = std::time::Instant::now();
    match read_capped(&mut stream, timeout).await {
        Some(raw) => Grab {
            connect_ms,
            banner_ms: Some(since(&asked)),
            ..classify(raw, true)
        },
        None => Grab {
            raw: None,
            sent_get: true,
            tls_hint: !is_http_port(port),
            connect_ms,
            banner_ms: None,
        },
    }
}

/// Sort a reply into banner bytes vs. a TLS indication.
fn classify(raw: Vec<u8>, sent_get: bool) -> Grab {
    if is_tls_record(&raw) {
        return Grab {
            raw: None,
            sent_get,
            tls_hint: true,
            ..Grab::default()
        };
    }
    let text = String::from_utf8_lossy(&raw[..raw.len().min(2048)]).to_ascii_lowercase();
    let tls_hint = text.contains("plain http request was sent to https port")
        || text.contains("speaking plain http to an ssl-enabled server")
        || text.contains("client sent an http request to an https server");
    Grab {
        raw: Some(raw),
        sent_get,
        tls_hint,
        ..Grab::default()
    }
}

/// A TLS record header: content type alert (21) or handshake (22), version 3.x.
fn is_tls_record(raw: &[u8]) -> bool {
    raw.len() >= 5 && matches!(raw[0], 0x15 | 0x16) && raw[1] == 0x03 && raw[2] <= 0x04
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
            Ok(Ok(0)) => break, // clean EOF
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

    use tokio::net::TcpListener;

    /// Serve one connection with `f`, return the local port.
    async fn serve<F, Fut>(f: F) -> u16
    where
        F: FnOnce(TcpStream) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((s, _)) = l.accept().await {
                f(s).await;
            }
        });
        port
    }

    const LO: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
    const T: Duration = Duration::from_secs(4);

    #[tokio::test]
    async fn adaptive_server_first_banner() {
        let port = serve(|mut s| async move {
            let _ = s.write_all(b"220 ftp ready\r\n").await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        })
        .await;
        let g = grab_adaptive(LO, port, T).await;
        assert_eq!(g.raw.as_deref(), Some(&b"220 ftp ready\r\n"[..]));
        assert!(!g.sent_get && !g.tls_hint);
    }

    #[tokio::test]
    async fn adaptive_finds_http_on_unexpected_port() {
        let port = serve(|mut s| async move {
            let mut buf = [0u8; 512];
            let n = s.read(&mut buf).await.unwrap_or(0);
            if buf[..n].starts_with(b"GET / ") {
                let _ = s
                    .write_all(b"HTTP/1.0 200 OK\r\nServer: nginx/1.18.0\r\n\r\n<title>x</title>")
                    .await;
            }
        })
        .await;
        let g = grab_adaptive(LO, port, T).await;
        assert!(g.sent_get && !g.tls_hint);
        let http = parse_http(g.raw.as_deref().unwrap()).unwrap();
        assert_eq!(http.server.as_deref(), Some("nginx/1.18.0"));
    }

    #[tokio::test]
    async fn adaptive_tls_alert_is_hint_not_banner() {
        let port = serve(|mut s| async move {
            let mut buf = [0u8; 512];
            let _ = s.read(&mut buf).await;
            let _ = s
                .write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x46])
                .await;
        })
        .await;
        let g = grab_adaptive(LO, port, T).await;
        assert!(g.raw.is_none() && g.sent_get && g.tls_hint);
    }

    #[test]
    fn plaintext_on_tls_port_message_is_hint() {
        let g = classify(
            b"HTTP/1.1 400 Bad Request\r\n\r\nThe plain HTTP request was sent to HTTPS port"
                .to_vec(),
            true,
        );
        assert!(g.tls_hint && g.raw.is_some());
    }

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
