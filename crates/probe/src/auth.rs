//! Authentication-posture detection ("AUTH-POSTURE").
//!
//! # Policy: observe, never authenticate
//!
//! This module determines whether a service is reachable **without
//! credentials** purely by *observing the service's own response* to a
//! standard, read-only status / hello / ping request. Sending a protocol's
//! ordinary unauthenticated status command and reading the reply is
//! *observation*, not an authentication attempt. We therefore **never**:
//!
//! * submit credentials of any kind;
//! * send an `AUTH` command carrying a password;
//! * attempt to authenticate, log in or bypass authentication;
//! * complete a challenge the service issues.
//!
//! The recon signal we are after is [`AuthState::Open`] — the service answered
//! a benign status request with no credentials. [`AuthState::Required`] means
//! the service itself told us (401, a `WWW-Authenticate` challenge, Redis
//! `-NOAUTH`, a VNC security list offering only authenticated types) that
//! credentials are needed. When we cannot tell — or when classifying would
//! require submitting credentials (e.g. an anonymous FTP *login*) — we leave it
//! [`AuthState::Unknown`] (or `None` when the posture was not assessed at all)
//! rather than guess or probe further.
//!
//! The request builders and response classifiers are pure, public functions so
//! they can be unit-tested on captured bytes without a socket. The async probe
//! wrappers are thin, time-bounded and never panic.

use std::net::IpAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crusade_core::{AuthState, HttpInfo};

/// TCP ports for which we run a read-only authentication-posture probe.
pub fn auth_posture_ports() -> &'static [u16] {
    &[6379, 27017, 9200, 11211, 5900, 5901]
}

/// Whether [`posture_probe`] has a probe for `port`.
pub fn is_auth_posture_port(port: u16) -> bool {
    auth_posture_ports().contains(&port)
}

/// Run the read-only posture probe matching `port`, returning the observed
/// [`AuthState`] or `None` when the port has no probe or did not respond.
pub async fn posture_probe(ip: IpAddr, port: u16, timeout: Duration) -> Option<AuthState> {
    match port {
        6379 => probe_redis(ip, port, timeout).await,
        27017 => probe_mongodb(ip, port, timeout).await,
        9200 => probe_elasticsearch(ip, port, timeout).await,
        11211 => probe_memcached(ip, port, timeout).await,
        5900 | 5901 => probe_vnc(ip, port, timeout).await,
        _ => None,
    }
}

// ===========================================================================
// HTTP (pure classifier)
// ===========================================================================

/// Classify a web service's authentication posture from its HTTP response.
///
/// * status `401`/`407`, or a `WWW-Authenticate`/`Proxy-Authenticate` header
///   present → [`AuthState::Required`] (the server challenged us);
/// * a reachable status (`200`/`204`/any `3xx`) → [`AuthState::Open`];
/// * anything else → [`AuthState::Unknown`].
///
/// Header keys in [`HttpInfo::headers`] are lowercase.
pub fn classify_http_auth(http: &HttpInfo) -> AuthState {
    let challenged = http
        .headers
        .iter()
        .any(|(k, _)| k == "www-authenticate" || k == "proxy-authenticate");
    if challenged {
        return AuthState::Required;
    }
    match http.status {
        Some(401) | Some(407) => AuthState::Required,
        Some(200) | Some(204) => AuthState::Open,
        Some(s) if (300..=399).contains(&s) => AuthState::Open,
        _ => AuthState::Unknown,
    }
}

// ===========================================================================
// Shared, time-bounded socket helpers (best-effort, never panic).
// ===========================================================================

/// Connect to `ip:port` within `timeout`.
async fn connect(ip: IpAddr, port: u16, timeout: Duration) -> Option<TcpStream> {
    tokio::time::timeout(timeout, TcpStream::connect((ip, port)))
        .await
        .ok()?
        .ok()
}

/// Read a single chunk (one successful `read`) within `timeout`.
///
/// One read is enough to classify the line/framed status replies these probes
/// elicit, and — unlike reading to EOF — it does not stall on services (Redis,
/// MongoDB, VNC) that keep the connection open after answering.
async fn read_once(stream: &mut TcpStream, timeout: Duration) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 8192];
    let n = tokio::time::timeout(timeout, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    if n == 0 {
        return None;
    }
    buf.truncate(n);
    Some(buf)
}

/// Connect, write `payload`, and read a single reply chunk.
async fn tcp_request(ip: IpAddr, port: u16, payload: &[u8], timeout: Duration) -> Option<Vec<u8>> {
    let mut stream = connect(ip, port, timeout).await?;
    tokio::time::timeout(timeout, stream.write_all(payload))
        .await
        .ok()?
        .ok()?;
    read_once(&mut stream, timeout).await
}

/// Find the first index of `needle` within `haystack`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Lowercase the ASCII bytes of `data` (bytes >= 0x80 are left untouched).
fn ascii_lower(data: &[u8]) -> Vec<u8> {
    data.iter().map(|b| b.to_ascii_lowercase()).collect()
}

// ===========================================================================
// Redis (port 6379) — PING / INFO status request.
// ===========================================================================

/// The read-only Redis status request we send (a RESP inline `PING`). We never
/// send `AUTH`.
pub const REDIS_PING: &[u8] = b"PING\r\n";

/// Classify a Redis reply to our `PING`.
///
/// * a valid RESP reply (`+PONG`, a bulk string, array or integer) → the server
///   answered without credentials → [`AuthState::Open`];
/// * an error reply mentioning auth (`-NOAUTH Authentication required.`,
///   `-ERR ... auth ...`) → [`AuthState::Required`];
/// * anything else → [`AuthState::Unknown`].
pub fn classify_redis_reply(reply: &[u8]) -> AuthState {
    match reply.first() {
        Some(b'-') => {
            // Error reply. An auth-related error means we were challenged.
            if find_subslice(&ascii_lower(reply), b"auth").is_some() {
                AuthState::Required
            } else {
                AuthState::Unknown
            }
        }
        // Any other valid RESP type is a genuine answer to an unauthenticated
        // PING/INFO: simple string, bulk string, array or integer.
        Some(b'+') | Some(b'$') | Some(b'*') | Some(b':') => AuthState::Open,
        _ => AuthState::Unknown,
    }
}

async fn probe_redis(ip: IpAddr, port: u16, timeout: Duration) -> Option<AuthState> {
    let reply = tcp_request(ip, port, REDIS_PING, timeout).await?;
    Some(classify_redis_reply(&reply))
}

// ===========================================================================
// MongoDB (port 27017) — unauthenticated isMaster / hello handshake.
// ===========================================================================

/// Build the BSON document `{ isMaster: 1 }`.
fn bson_ismaster() -> Vec<u8> {
    let key = b"isMaster\0";
    let mut doc = Vec::new();
    doc.push(0x10); // element type: int32
    doc.extend_from_slice(key);
    doc.extend_from_slice(&1i32.to_le_bytes());
    doc.push(0x00); // document terminator
    let total = (4 + doc.len()) as i32;
    let mut out = total.to_le_bytes().to_vec();
    out.extend_from_slice(&doc);
    out
}

/// Build a MongoDB wire-protocol `OP_QUERY` carrying the standard
/// unauthenticated `isMaster` handshake command against `admin.$cmd`.
///
/// `isMaster`/`hello` is the handshake every MongoDB client issues before
/// anything else; it is always answerable without credentials and is *not* a
/// login. We never send `saslStart`/`authenticate` or any credential.
pub fn build_mongo_ismaster() -> Vec<u8> {
    let bson = bson_ismaster();
    let collection: &[u8] = b"admin.$cmd\0";

    let mut body = Vec::new();
    body.extend_from_slice(&0i32.to_le_bytes()); // flags
    body.extend_from_slice(collection); // fullCollectionName
    body.extend_from_slice(&0i32.to_le_bytes()); // numberToSkip
    body.extend_from_slice(&(-1i32).to_le_bytes()); // numberToReturn (one doc)
    body.extend_from_slice(&bson); // query document

    let total = 16 + body.len();
    let mut msg = Vec::with_capacity(total);
    msg.extend_from_slice(&(total as i32).to_le_bytes()); // messageLength
    msg.extend_from_slice(&1i32.to_le_bytes()); // requestID
    msg.extend_from_slice(&0i32.to_le_bytes()); // responseTo
    msg.extend_from_slice(&2004i32.to_le_bytes()); // opCode = OP_QUERY
    msg.extend_from_slice(&body);
    msg
}

/// Classify a MongoDB reply to our `isMaster`/`hello` handshake.
///
/// * an auth-required error document (`not authorized`, `Unauthorized`,
///   `requires authentication`) → [`AuthState::Required`];
/// * a normal handshake document (`ismaster`, `isWritablePrimary`,
///   `maxWireVersion`) → [`AuthState::Open`];
/// * anything else / too short → [`AuthState::Unknown`].
///
/// Auth markers are checked first because an error document may itself contain
/// the field name `isMaster`.
pub fn classify_mongo_reply(reply: &[u8]) -> AuthState {
    // A valid wire message has at least the 16-byte standard header.
    if reply.len() < 16 {
        return AuthState::Unknown;
    }
    let lower = ascii_lower(reply);
    let has = |needle: &[u8]| find_subslice(&lower, needle).is_some();

    if has(b"not authorized")
        || has(b"unauthorized")
        || has(b"requires authentication")
        || has(b"authentication failed")
    {
        return AuthState::Required;
    }
    if has(b"ismaster") || has(b"iswritableprimary") || has(b"maxwireversion") || has(b"hellook") {
        return AuthState::Open;
    }
    AuthState::Unknown
}

async fn probe_mongodb(ip: IpAddr, port: u16, timeout: Duration) -> Option<AuthState> {
    let reply = tcp_request(ip, port, &build_mongo_ismaster(), timeout).await?;
    Some(classify_mongo_reply(&reply))
}

// ===========================================================================
// Elasticsearch (port 9200, plain HTTP) — GET /.
// ===========================================================================

async fn probe_elasticsearch(ip: IpAddr, port: u16, timeout: Duration) -> Option<AuthState> {
    let req = format!("GET / HTTP/1.0\r\nHost: {ip}\r\nAccept: */*\r\nConnection: close\r\n\r\n");
    let raw = tcp_request(ip, port, req.as_bytes(), timeout).await?;
    let http = crate::grab::parse_http(&raw)?;
    Some(classify_http_auth(&http))
}

// ===========================================================================
// Memcached (port 11211) — version status request.
// ===========================================================================

/// The read-only Memcached status request we send.
pub const MEMCACHED_VERSION: &[u8] = b"version\r\n";

/// Classify a Memcached reply to our `version` request.
///
/// A `VERSION ...` reply → the server answered without credentials →
/// [`AuthState::Open`] (Memcached has no authentication by default). Anything
/// else (an `ERROR`, a SASL-gated server, no reply) → [`AuthState::Unknown`];
/// we never attempt SASL, so we never claim `Required` here.
pub fn classify_memcached_reply(reply: &[u8]) -> AuthState {
    let start = reply
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(reply.len());
    if reply[start..].starts_with(b"VERSION") {
        AuthState::Open
    } else {
        AuthState::Unknown
    }
}

async fn probe_memcached(ip: IpAddr, port: u16, timeout: Duration) -> Option<AuthState> {
    let reply = tcp_request(ip, port, MEMCACHED_VERSION, timeout).await?;
    Some(classify_memcached_reply(&reply))
}

// ===========================================================================
// VNC / RFB (ports 5900, 5901) — passive security-type handshake.
// ===========================================================================

/// Pick the RFB ProtocolVersion string we echo back, never exceeding the
/// server's offered minor version. Echoing a version is part of the normal
/// handshake (like the SSH identification string) — we never choose a security
/// type or send any authentication response.
fn vnc_client_version(server_minor: u32) -> &'static [u8] {
    if server_minor >= 8 {
        b"RFB 003.008\n"
    } else if server_minor == 7 {
        b"RFB 003.007\n"
    } else {
        b"RFB 003.003\n"
    }
}

/// Parse an RFB minor version out of a 12-byte `"RFB 003.00X\n"` greeting.
fn vnc_minor(greeting: &[u8]) -> Option<u32> {
    if greeting.len() < 12 || &greeting[..4] != b"RFB " {
        return None;
    }
    std::str::from_utf8(&greeting[8..11])
        .ok()?
        .parse::<u32>()
        .ok()
}

/// Classify a VNC/RFB handshake from the server's `ProtocolVersion` greeting
/// followed by the security handshake bytes.
///
/// `data` is the 12-byte `"RFB 003.00X\n"` greeting concatenated with the
/// security handshake the server sent after we echoed our version:
///
/// * RFB 3.7/3.8: a `U8` count then that many `U8` security types. If security
///   type `1` (**None**) is offered → [`AuthState::Open`]; if only
///   authenticated types (VNC auth `2`, etc.) are offered → [`AuthState::Required`].
/// * RFB 3.3: a single `U32` security type (`1` = None → Open, `2`+ → Required,
///   `0` = connection failed → Unknown).
///
/// Reading the offered list is passive; we do not proceed to authenticate.
pub fn classify_vnc_security(data: &[u8]) -> AuthState {
    let minor = match vnc_minor(data) {
        Some(m) => m,
        None => return AuthState::Unknown,
    };
    let rest = &data[12..];

    if minor >= 7 {
        let count = match rest.first() {
            Some(c) => *c as usize,
            None => return AuthState::Unknown,
        };
        if count == 0 {
            // A zero count is a SecurityResult failure (reason string follows),
            // not an offer we can read a posture from.
            return AuthState::Unknown;
        }
        let types = match rest.get(1..1 + count) {
            Some(t) => t,
            None => return AuthState::Unknown,
        };
        classify_vnc_types(types)
    } else {
        // RFB 3.3: a single big-endian U32 security type.
        let b = match rest.get(0..4) {
            Some(b) => b,
            None => return AuthState::Unknown,
        };
        match u32::from_be_bytes([b[0], b[1], b[2], b[3]]) {
            1 => AuthState::Open,
            0 => AuthState::Unknown, // 0 = connection failed
            _ => AuthState::Required,
        }
    }
}

/// Classify an RFB 3.7/3.8 offered security-type list.
fn classify_vnc_types(types: &[u8]) -> AuthState {
    if types.contains(&1) {
        // Security type 1 = None: reachable with no authentication.
        AuthState::Open
    } else if types.iter().any(|&t| t != 0) {
        // Only authenticated types (VNC auth = 2, Tight = 16, TLS/VeNCrypt, …).
        AuthState::Required
    } else {
        AuthState::Unknown
    }
}

async fn probe_vnc(ip: IpAddr, port: u16, timeout: Duration) -> Option<AuthState> {
    let mut stream = connect(ip, port, timeout).await?;

    // 1. Read the server's 12-byte ProtocolVersion greeting.
    let mut greeting = [0u8; 12];
    tokio::time::timeout(timeout, stream.read_exact(&mut greeting))
        .await
        .ok()?
        .ok()?;
    let minor = vnc_minor(&greeting)?;

    // 2. Echo a ProtocolVersion back (part of the handshake, not a login).
    tokio::time::timeout(timeout, stream.write_all(vnc_client_version(minor)))
        .await
        .ok()?
        .ok()?;

    // 3. Read the offered security handshake and classify it passively.
    let sec = read_once(&mut stream, timeout).await.unwrap_or_default();
    let mut data = greeting.to_vec();
    data.extend_from_slice(&sec);
    Some(classify_vnc_security(&data))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn http(status: Option<u16>, headers: &[(&str, &str)]) -> HttpInfo {
        HttpInfo {
            status,
            server: None,
            title: None,
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            favicon_hash: None,
            technologies: Vec::new(),
            security_headers: Vec::new(),
        }
    }

    // --- HTTP --------------------------------------------------------------

    #[test]
    fn http_401_is_required() {
        assert_eq!(
            classify_http_auth(&http(Some(401), &[])),
            AuthState::Required
        );
        assert_eq!(
            classify_http_auth(&http(Some(407), &[])),
            AuthState::Required
        );
    }

    #[test]
    fn http_www_authenticate_header_is_required() {
        let h = http(Some(200), &[("www-authenticate", "Basic realm=\"x\"")]);
        assert_eq!(classify_http_auth(&h), AuthState::Required);
        let h = http(Some(200), &[("proxy-authenticate", "Basic")]);
        assert_eq!(classify_http_auth(&h), AuthState::Required);
    }

    #[test]
    fn http_reachable_is_open() {
        assert_eq!(classify_http_auth(&http(Some(200), &[])), AuthState::Open);
        assert_eq!(classify_http_auth(&http(Some(204), &[])), AuthState::Open);
        assert_eq!(classify_http_auth(&http(Some(302), &[])), AuthState::Open);
    }

    #[test]
    fn http_other_is_unknown() {
        assert_eq!(
            classify_http_auth(&http(Some(500), &[])),
            AuthState::Unknown
        );
        assert_eq!(classify_http_auth(&http(None, &[])), AuthState::Unknown);
    }

    // --- Redis -------------------------------------------------------------

    #[test]
    fn redis_pong_is_open() {
        assert_eq!(classify_redis_reply(b"+PONG\r\n"), AuthState::Open);
    }

    #[test]
    fn redis_info_bulk_is_open() {
        assert_eq!(
            classify_redis_reply(b"$23\r\n# Server\r\nredis_version:7\r\n"),
            AuthState::Open
        );
    }

    #[test]
    fn redis_noauth_is_required() {
        assert_eq!(
            classify_redis_reply(b"-NOAUTH Authentication required.\r\n"),
            AuthState::Required
        );
        assert_eq!(
            classify_redis_reply(b"-ERR operation not permitted, auth needed\r\n"),
            AuthState::Required
        );
    }

    #[test]
    fn redis_other_error_is_unknown() {
        assert_eq!(
            classify_redis_reply(b"-ERR unknown command\r\n"),
            AuthState::Unknown
        );
    }

    #[test]
    fn redis_empty_is_unknown() {
        assert_eq!(classify_redis_reply(b""), AuthState::Unknown);
    }

    // --- MongoDB -----------------------------------------------------------

    /// Wrap a BSON document in an OP_REPLY (opcode 1) wire message.
    fn mongo_op_reply(doc: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0i32.to_le_bytes()); // responseFlags
        body.extend_from_slice(&0i64.to_le_bytes()); // cursorID
        body.extend_from_slice(&0i32.to_le_bytes()); // startingFrom
        body.extend_from_slice(&1i32.to_le_bytes()); // numberReturned
        body.extend_from_slice(doc);
        let total = 16 + body.len();
        let mut msg = Vec::new();
        msg.extend_from_slice(&(total as i32).to_le_bytes());
        msg.extend_from_slice(&7i32.to_le_bytes()); // requestID
        msg.extend_from_slice(&1i32.to_le_bytes()); // responseTo
        msg.extend_from_slice(&1i32.to_le_bytes()); // opCode = OP_REPLY
        msg.extend_from_slice(&body);
        msg
    }

    /// A tiny BSON document: a single bool field `{ <key>: true }`.
    fn bson_bool(key: &str, val: bool) -> Vec<u8> {
        let mut doc = Vec::new();
        doc.push(0x08); // bool
        doc.extend_from_slice(key.as_bytes());
        doc.push(0x00);
        doc.push(if val { 1 } else { 0 });
        doc.push(0x00); // terminator
        let total = (4 + doc.len()) as i32;
        let mut out = total.to_le_bytes().to_vec();
        out.extend_from_slice(&doc);
        out
    }

    fn bson_errmsg(msg: &str) -> Vec<u8> {
        let mut doc = Vec::new();
        doc.push(0x02); // string
        doc.extend_from_slice(b"errmsg\0");
        let s = format!("{msg}\0");
        doc.extend_from_slice(&(s.len() as i32).to_le_bytes());
        doc.extend_from_slice(s.as_bytes());
        doc.push(0x00);
        let total = (4 + doc.len()) as i32;
        let mut out = total.to_le_bytes().to_vec();
        out.extend_from_slice(&doc);
        out
    }

    #[test]
    fn mongo_ismaster_request_is_well_formed() {
        let req = build_mongo_ismaster();
        // messageLength field equals the actual length.
        assert_eq!(
            i32::from_le_bytes([req[0], req[1], req[2], req[3]]) as usize,
            req.len()
        );
        // opCode OP_QUERY at bytes 12..16.
        assert_eq!(
            i32::from_le_bytes([req[12], req[13], req[14], req[15]]),
            2004
        );
        assert!(find_subslice(&req, b"admin.$cmd").is_some());
        assert!(find_subslice(&req, b"isMaster").is_some());
    }

    #[test]
    fn mongo_hello_document_is_open() {
        let reply = mongo_op_reply(&bson_bool("ismaster", true));
        assert_eq!(classify_mongo_reply(&reply), AuthState::Open);
    }

    #[test]
    fn mongo_auth_error_is_required() {
        let reply = mongo_op_reply(&bson_errmsg("command requires authentication"));
        assert_eq!(classify_mongo_reply(&reply), AuthState::Required);
    }

    #[test]
    fn mongo_short_is_unknown() {
        assert_eq!(classify_mongo_reply(&[0u8; 4]), AuthState::Unknown);
        assert_eq!(classify_mongo_reply(b""), AuthState::Unknown);
    }

    // --- Memcached ---------------------------------------------------------

    #[test]
    fn memcached_version_is_open() {
        assert_eq!(
            classify_memcached_reply(b"VERSION 1.6.21\r\n"),
            AuthState::Open
        );
    }

    #[test]
    fn memcached_error_is_unknown() {
        assert_eq!(classify_memcached_reply(b"ERROR\r\n"), AuthState::Unknown);
        assert_eq!(classify_memcached_reply(b""), AuthState::Unknown);
    }

    // --- VNC / RFB ---------------------------------------------------------

    #[test]
    fn vnc_none_offered_is_open() {
        // RFB 3.8, offering [None(1), VNC(2)].
        let mut data = b"RFB 003.008\n".to_vec();
        data.push(0x02); // count
        data.extend_from_slice(&[0x01, 0x02]);
        assert_eq!(classify_vnc_security(&data), AuthState::Open);
    }

    #[test]
    fn vnc_auth_only_is_required() {
        // RFB 3.8, offering only [VNC(2), Tight(16)].
        let mut data = b"RFB 003.008\n".to_vec();
        data.push(0x02);
        data.extend_from_slice(&[0x02, 0x10]);
        assert_eq!(classify_vnc_security(&data), AuthState::Required);
    }

    #[test]
    fn vnc_33_single_type() {
        // RFB 3.3: None (1) → Open.
        let mut open = b"RFB 003.003\n".to_vec();
        open.extend_from_slice(&1u32.to_be_bytes());
        assert_eq!(classify_vnc_security(&open), AuthState::Open);
        // RFB 3.3: VNC auth (2) → Required.
        let mut req = b"RFB 003.003\n".to_vec();
        req.extend_from_slice(&2u32.to_be_bytes());
        assert_eq!(classify_vnc_security(&req), AuthState::Required);
    }

    #[test]
    fn vnc_zero_count_is_unknown() {
        // A zero count is a failure (reason follows) — not an offer.
        let mut data = b"RFB 003.008\n".to_vec();
        data.push(0x00);
        assert_eq!(classify_vnc_security(&data), AuthState::Unknown);
    }

    #[test]
    fn vnc_malformed_is_unknown() {
        assert_eq!(classify_vnc_security(b""), AuthState::Unknown);
        assert_eq!(classify_vnc_security(b"RFB 003.008\n"), AuthState::Unknown);
        assert_eq!(
            classify_vnc_security(b"NOTR 003.008\n\x01\x01"),
            AuthState::Unknown
        );
        // Count larger than the bytes present must not panic.
        let mut data = b"RFB 003.008\n".to_vec();
        data.push(0x05);
        data.extend_from_slice(&[0x01]);
        assert_eq!(classify_vnc_security(&data), AuthState::Unknown);
    }

    // --- Port table --------------------------------------------------------

    #[test]
    fn posture_port_table() {
        assert!(is_auth_posture_port(6379));
        assert!(is_auth_posture_port(27017));
        assert!(is_auth_posture_port(9200));
        assert!(is_auth_posture_port(11211));
        assert!(is_auth_posture_port(5900));
        assert!(is_auth_posture_port(5901));
        assert!(!is_auth_posture_port(80));
    }
}
