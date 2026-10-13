//! Crusade probe: turn an open `(ip, port)` into a populated [`Service`].
//!
//! This crate performs the *service detection* half of the scanner. Given a
//! port that a prior stage found open, it:
//!
//! 1. grabs the service banner (and, for HTTP ports, a `GET /` response) —
//!    see [`grab`];
//! 2. identifies the service with a subset of the Nmap service-probes
//!    database — see [`fingerprint`];
//! 3. for TLS ports, collects and parses the presented certificate (with the
//!    negotiated version and cipher) — see [`tls`];
//! 4. computes Shodan-compatible HTTP intelligence — the `http.favicon.hash`
//!    pivot, technology and security-header detection — see [`http`];
//! 5. derives the active [`jarm`] TLS fingerprint and, for SSH services,
//!    the host-key type, offered KEX algorithms and [`ssh`] HASSH fingerprint.
//!
//! A parallel [`udp`] path probes connectionless services (DNS, NTP, SNMP,
//! SSDP, NetBIOS) with a single standards-shaped request each.
//!
//! Everything is strictly **connect-and-read**. The only bytes ever written to
//! a target are benign, standards-shaped requests (an HTTP `GET`, the TLS
//! handshakes JARM and certificate collection require, an SSH identification
//! string and client `KEXINIT`, and the single UDP protocol queries). No
//! authentication is attempted, no key exchange is completed and no exploit
//! payload is ever sent — this is a cataloguing tool, not an attack tool.

pub mod auth;
pub mod fingerprint;
pub mod grab;
pub mod http;
pub mod ics;
pub mod jarm;
pub mod quic;
pub mod ssh;
pub mod tls;
pub mod udp;

use std::net::IpAddr;
use std::time::Duration;

use time::OffsetDateTime;

use crusade_core::{AuthState, HttpInfo, Service, Transport};

pub use auth::{classify_http_auth, is_auth_posture_port, posture_probe};
pub use fingerprint::{Fingerprints, ProbeKind, ServiceMatch};
pub use ics::{ics_ports_tcp, ics_ports_udp, probe_ics_service};
pub use jarm::jarm;
pub use quic::{probe_quic, quic_info, QuicInfo};
pub use ssh::ssh_info;
pub use udp::probe_udp_service;

/// Tunables for a single service probe.
#[derive(Debug, Clone)]
pub struct ProbeConfig {
    /// Per-operation timeout (connect, read, handshake).
    pub timeout: Duration,
    /// Whether to attempt a TLS handshake to collect a certificate.
    pub tls: bool,
    /// Optional SNI to present during the TLS handshake.
    pub sni: Option<String>,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        ProbeConfig {
            timeout: Duration::from_secs(6),
            tls: true,
            sni: None,
        }
    }
}

/// Common TLS-wrapped ports we attempt a handshake on when `cfg.tls` is set.
fn is_tls_port(port: u16) -> bool {
    matches!(
        port,
        443 | 465 | 563 | 636 | 853 | 989 | 990 | 993 | 995 | 8443 | 9443 | 4433 | 10443
    )
}

/// Probe one open `(ip, port)` and assemble a [`Service`].
///
/// The returned `Service` always has `observed_at` set to now and `transport`
/// = TCP. Any field we could not determine is simply left as `None`.
pub async fn probe_service(ip: IpAddr, port: u16, fp: &Fingerprints, cfg: &ProbeConfig) -> Service {
    let mut svc = Service::new(port, Transport::Tcp);

    // 1. Protocol-agnostic first exchange: server-first banner, else a benign
    //    GET on the same connection (LZR-style; see `grab::grab_adaptive`).
    let first = grab::grab_adaptive(ip, port, cfg.timeout).await;
    if let Some(raw) = &first.raw {
        // Record a (lossy, trimmed) textual banner.
        let banner = String::from_utf8_lossy(raw);
        let trimmed = banner.trim_end_matches(['\r', '\n', '\0']).to_string();
        if !trimmed.is_empty() {
            svc.banner = Some(trimmed);
        }

        // HTTP metadata, if this looks like an HTTP response.
        if let Some(http) = grab::parse_http(raw) {
            svc.http = Some(http);
        }

        // Fingerprint with the GetRequest ruleset when the bytes answer our
        // GET, otherwise the NULL/banner ruleset.
        let kind = if first.sent_get {
            ProbeKind::GetRequest
        } else {
            ProbeKind::Null
        };
        apply_match(&mut svc, fp.identify(port, kind, raw));

        // If the GetRequest ruleset found nothing, fall back to NULL rules.
        if svc.service.is_none() && kind == ProbeKind::GetRequest {
            apply_match(&mut svc, fp.identify(port, ProbeKind::Null, raw));
        }
    }

    // 2. TLS certificate collection: on TLS ports, and on any port whose first
    //    exchange hinted at TLS (TLS record, HTTPS-port complaint, silence).
    let tls_attempt = cfg.tls && (is_tls_port(port) || first.tls_hint);
    if tls_attempt {
        let sni = cfg.sni.as_deref();
        if let Some(cert) = tls::grab_cert(ip, port, sni, cfg.timeout).await {
            svc.tls = Some(cert);
            if svc.service.is_none() {
                svc.service = Some("ssl".to_string());
            }
        }
    }
    let tls_active = cfg.tls && (is_tls_port(port) || svc.tls.is_some());

    // 3. JARM active TLS fingerprint (ports that speak TLS).
    if tls_active {
        svc.jarm = jarm::jarm(ip, port, cfg.timeout).await;
    }

    // 4. Favicon hash (the Shodan `http.favicon.hash` pivot) over whichever
    //    transport this port speaks.
    if tls_active || grab::is_http_port(port) || svc.http.is_some() {
        if let Some(hash) = fetch_favicon(ip, port, tls_active, cfg).await {
            svc.http.get_or_insert_with(empty_http).favicon_hash = Some(hash);
        }
    }

    // 5. SSH intelligence (port 22, or anything that greeted us with "SSH-").
    let looks_ssh = port == 22
        || svc
            .banner
            .as_deref()
            .map(|b| b.starts_with("SSH-"))
            .unwrap_or(false);
    if looks_ssh {
        if let Some(ssh) = ssh::ssh_info(ip, port, cfg.timeout).await {
            svc.ssh = Some(ssh);
            if svc.service.is_none() {
                svc.service = Some("ssh".to_string());
            }
        }
    }

    // 6. ICS/OT device identification (read-only) for known TCP ICS ports.
    //    Attempted after the normal banner/fingerprint so it only enriches.
    if ics::ics_ports_tcp().contains(&port) {
        if let Some(ics_svc) = ics::probe_ics_service(ip, port, cfg.timeout).await {
            if ics_svc.ics.is_some() {
                svc.ics = ics_svc.ics;
            }
            if svc.service.is_none() {
                svc.service = ics_svc.service;
            }
            if svc.product.is_none() {
                svc.product = ics_svc.product;
            }
            if svc.version.is_none() {
                svc.version = ics_svc.version;
            }
        }
    }

    // 7. Authentication posture (observed, never credentialed). Determined from
    //    the service's own response to a standard read-only request — see the
    //    `auth` module for the strict observe-don't-authenticate policy.
    svc.auth = assess_auth(ip, port, &svc, cfg.timeout).await;

    svc.observed_at = OffsetDateTime::now_utc();
    svc
}

/// Determine a service's [`AuthState`] by observation only.
///
/// Precedence: an HTTP response classifies via its status / challenge headers;
/// an ICS service is [`AuthState::Open`] (these OT protocols have no
/// authentication at all); an SNMP service that answered the public-community
/// query is `Open`; otherwise, for the services with a read-only posture probe
/// (Redis, MongoDB, Elasticsearch, Memcached, VNC) we run that probe. Any other
/// service is left unassessed (`None`).
async fn assess_auth(ip: IpAddr, port: u16, svc: &Service, timeout: Duration) -> Option<AuthState> {
    if let Some(http) = &svc.http {
        return Some(auth::classify_http_auth(http));
    }
    if svc.ics.is_some() {
        return Some(AuthState::Open);
    }
    if svc.service.as_deref() == Some("snmp") && svc.banner.is_some() {
        return Some(AuthState::Open);
    }
    auth::posture_probe(ip, port, timeout).await
}

/// Fetch and hash `/favicon.ico` over the transport the port speaks.
async fn fetch_favicon(ip: IpAddr, port: u16, tls_active: bool, cfg: &ProbeConfig) -> Option<i32> {
    if tls_active {
        let mut stream = tls::connect(ip, port, cfg.sni.as_deref(), cfg.timeout).await?;
        http::favicon_over(&mut stream, ip, cfg.timeout).await
    } else {
        http::fetch_favicon_hash_plain(ip, port, cfg.timeout).await
    }
}

/// An empty [`HttpInfo`] used when a favicon hash is the only HTTP datum we
/// obtained (e.g. a bare HTTPS endpoint we did not otherwise parse).
fn empty_http() -> HttpInfo {
    HttpInfo {
        status: None,
        server: None,
        title: None,
        headers: Vec::new(),
        favicon_hash: None,
        technologies: Vec::new(),
        security_headers: Vec::new(),
    }
}

/// Fold a fingerprint result into the service, without clobbering existing data.
fn apply_match(svc: &mut Service, m: Option<ServiceMatch>) {
    if let Some(m) = m {
        if svc.service.is_none() {
            svc.service = Some(m.service);
        }
        if svc.product.is_none() {
            svc.product = non_empty(m.product);
        }
        if svc.version.is_none() {
            svc.version = non_empty(m.version);
        }
        if svc.cpe.is_none() {
            svc.cpe = non_empty(m.cpe);
        }
    }
}

fn non_empty(s: Option<String>) -> Option<String> {
    s.filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_match_populates_and_preserves() {
        let mut svc = Service::new(22, Transport::Tcp);
        apply_match(
            &mut svc,
            Some(ServiceMatch {
                service: "ssh".into(),
                product: Some("OpenSSH".into()),
                version: Some("8.9p1".into()),
                cpe: Some("cpe:/a:openbsd:openssh:8.9p1".into()),
            }),
        );
        assert_eq!(svc.service.as_deref(), Some("ssh"));
        assert_eq!(svc.product.as_deref(), Some("OpenSSH"));

        // A second (weaker) match must not overwrite existing fields.
        apply_match(
            &mut svc,
            Some(ServiceMatch {
                service: "other".into(),
                product: None,
                version: None,
                cpe: None,
            }),
        );
        assert_eq!(svc.service.as_deref(), Some("ssh"));
        assert_eq!(svc.product.as_deref(), Some("OpenSSH"));
    }

    #[test]
    fn default_config_sane() {
        let cfg = ProbeConfig::default();
        assert!(cfg.tls);
        assert_eq!(cfg.timeout, Duration::from_secs(6));
    }

    #[test]
    fn tls_port_detection() {
        assert!(is_tls_port(443));
        assert!(is_tls_port(8443));
        assert!(!is_tls_port(80));
    }
}
