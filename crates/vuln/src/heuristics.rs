//! Feed-free heuristic tags derived purely from observed service metadata.
//!
//! These rules look at data Crusade already captured (TLS certificates, HTTP
//! titles, open ports, and the passively observed authentication posture) and
//! attach short, human-readable [`Tag`]s describing notable conditions — a
//! self-signed or expired certificate, a default landing page, plaintext HTTP,
//! an exposed database/management port, or an unauthenticated database / ICS
//! device / remote-access service reachable without credentials.
//!
//! The authentication posture ([`crusade_core::AuthState`]) is set upstream by
//! the probe crate from the service's own response; this module only READS it
//! and never attempts to authenticate.
//!
//! Every tag is INFORMATIONAL only. Nothing here connects to, probes, or
//! otherwise interacts with a host; it merely labels what the scanner saw.

use crusade_core::{AuthState, Host, Service, Tag};
use time::OffsetDateTime;

/// Substrings that identify a stock "it's working" landing page left in place
/// by a freshly installed web server.
const DEFAULT_PAGE_NEEDLES: &[&str] = &[
    "Welcome to nginx",
    "Apache2 Ubuntu Default Page",
    "Apache2 Debian Default Page",
    "Test Page for the Apache",
    "IIS Windows",
    "It works!",
];

/// Ports that commonly expose a TLS-wrapped service; plaintext-HTTP checks skip
/// these so we do not flag an HTTPS endpoint whose certificate we failed to
/// parse.
const TLS_PORTS: &[u16] = &[443, 8443];

/// Ports we treat as plaintext HTTP when a web service is present.
const HTTP_PORTS: &[u16] = &[80, 8000, 8008, 8080];

/// Produce the heuristic tags for a host (de-duplicated by name).
pub fn heuristic_tags(host: &Host) -> Vec<Tag> {
    let now = OffsetDateTime::now_utc();
    let mut tags: Vec<Tag> = Vec::new();

    let mut self_signed = false;
    let mut expired = false;
    let mut default_page = false;
    let mut http_no_tls = false;

    for svc in &host.services {
        if let Some(tls) = &svc.tls {
            if tls.self_signed {
                self_signed = true;
            }
            if let Some(not_after) = tls.not_after {
                if not_after < now {
                    expired = true;
                }
            }
        }

        if let Some(http) = &svc.http {
            if let Some(title) = &http.title {
                if is_default_page(title) {
                    default_page = true;
                }
            }
        }

        if is_plaintext_http(svc) && svc.tls.is_none() {
            http_no_tls = true;
        }

        // An ICS/OT device reachable on the public internet is noteworthy in
        // its own right — surface it with a protocol-specific tag.
        if let Some(ics) = &svc.ics {
            let detail = [ics.vendor.as_deref(), ics.product.as_deref()]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" ");
            tags.push(Tag {
                name: "ics-exposed".to_string(),
                cve: None,
                detail: (!detail.is_empty()).then_some(detail),
            });
            tags.push(Tag::simple(format!("ics-{}", ics.protocol)));
        }
    }

    if self_signed {
        tags.push(Tag {
            name: "self-signed-certificate".to_string(),
            cve: None,
            detail: Some("a service presents a self-signed TLS certificate".to_string()),
        });
    }
    if expired {
        tags.push(Tag {
            name: "expired-certificate".to_string(),
            cve: None,
            detail: Some("a service presents an expired TLS certificate".to_string()),
        });
    }
    if default_page {
        tags.push(Tag {
            name: "default-page".to_string(),
            cve: None,
            detail: Some("a web service is serving a default/placeholder landing page".to_string()),
        });
    }
    if http_no_tls {
        tags.push(Tag {
            name: "http-no-tls".to_string(),
            cve: None,
            detail: Some("a web service is served over plaintext HTTP without TLS".to_string()),
        });
    }

    // Port/service-of-interest tags.
    for svc in &host.services {
        if let Some(tag) = port_of_interest(svc) {
            tags.push(tag);
        }
    }

    // Auth-posture tags: a sensitive service answering WITHOUT credentials is
    // the core recon signal "exposed unauthenticated device/DB/ICS".
    for svc in &host.services {
        if let Some((kind, detail)) = unauthenticated_signal(svc) {
            tags.push(Tag {
                name: "unauthenticated-access".to_string(),
                cve: None,
                detail: Some(detail),
            });
            tags.push(Tag::simple(format!("unauth-{kind}")));
        }
    }

    dedup_by_name(&mut tags);
    tags
}

/// If `svc` is a SENSITIVE service that is reachable without authentication,
/// return `(kind, detail)` for the `unauth-<kind>` + `unauthenticated-access`
/// tags. Returns `None` otherwise.
///
/// Databases, VNC/RDP, and admin/device web panels only qualify when the
/// observed [`AuthState`] is [`AuthState::Open`] (we saw it answer without
/// credentials). ICS/OT devices always qualify: those protocols have no
/// authentication at all.
fn unauthenticated_signal(svc: &Service) -> Option<(String, String)> {
    // ICS/OT protocols (Modbus, S7, BACnet, …) have no authentication concept,
    // so an identified ICS device is unauthenticated by construction.
    if let Some(ics) = &svc.ics {
        return Some((
            "ics".to_string(),
            format!(
                "{} ICS/OT device on {} (no authentication)",
                ics.protocol, svc.port
            ),
        ));
    }

    // Everything else must have been observed answering open.
    if svc.auth != Some(AuthState::Open) {
        return None;
    }

    if let Some(kind) = database_kind(svc) {
        return Some((kind.to_string(), format!("{kind} on {}", svc.port)));
    }
    if let Some(kind) = remote_access_kind(svc) {
        return Some((kind.to_string(), format!("{kind} on {}", svc.port)));
    }
    if is_admin_panel(svc) {
        return Some((
            "http-panel".to_string(),
            format!("admin/device web panel on {}", svc.port),
        ));
    }
    None
}

/// Identify a well-known database by service name first, then port.
fn database_kind(svc: &Service) -> Option<&'static str> {
    if let Some(name) = svc.service.as_deref() {
        match name.to_ascii_lowercase().as_str() {
            "redis" => return Some("redis"),
            "mongodb" | "mongo" => return Some("mongodb"),
            "elasticsearch" | "elastic" => return Some("elasticsearch"),
            "memcached" | "memcache" => return Some("memcached"),
            "mysql" | "mariadb" => return Some("mysql"),
            "postgresql" | "postgres" => return Some("postgres"),
            "mssql" | "ms-sql" | "ms-sql-s" | "sqlserver" => return Some("mssql"),
            _ => {}
        }
    }
    match svc.port {
        6379 => Some("redis"),
        27017 => Some("mongodb"),
        9200 => Some("elasticsearch"),
        11211 => Some("memcached"),
        3306 => Some("mysql"),
        5432 => Some("postgres"),
        1433 => Some("mssql"),
        _ => None,
    }
}

/// Identify a remote-access service (VNC / RDP) by port, then service name.
fn remote_access_kind(svc: &Service) -> Option<&'static str> {
    match svc.port {
        5900 | 5901 => return Some("vnc"),
        3389 => return Some("rdp"),
        _ => {}
    }
    match svc
        .service
        .as_deref()
        .map(|s| s.to_ascii_lowercase())
        .as_deref()
    {
        Some("vnc") => Some("vnc"),
        Some("rdp") | Some("ms-wbt-server") => Some("rdp"),
        _ => None,
    }
}

/// Simple markers that an HTTP service is an admin/management or device panel
/// rather than an ordinary public website (checked against title + server).
const ADMIN_PANEL_NEEDLES: &[&str] = &[
    "login",
    "sign in",
    "admin",
    "dashboard",
    "control panel",
    "management console",
    "webmin",
    "phpmyadmin",
    "router",
    "gateway",
    "ip camera",
    "webcam",
    "nas",
    "printer",
    "nvr",
    "dvr",
];

/// Conservative check: only treat an open HTTP service as sensitive when its
/// title or server header clearly marks it as an admin/device panel. This keeps
/// us from flagging every open public website.
fn is_admin_panel(svc: &Service) -> bool {
    let Some(http) = &svc.http else {
        return false;
    };
    let hay = |s: &str| {
        let lower = s.to_ascii_lowercase();
        ADMIN_PANEL_NEEDLES
            .iter()
            .any(|needle| lower.contains(needle))
    };
    http.title.as_deref().is_some_and(hay) || http.server.as_deref().is_some_and(hay)
}

/// True if `title` looks like a stock server default landing page.
fn is_default_page(title: &str) -> bool {
    DEFAULT_PAGE_NEEDLES
        .iter()
        .any(|needle| title.contains(needle))
}

/// True if a service looks like plaintext HTTP (not HTTPS).
fn is_plaintext_http(svc: &Service) -> bool {
    if TLS_PORTS.contains(&svc.port) {
        return false;
    }
    if svc.service.as_deref() == Some("https") {
        return false;
    }
    svc.service.as_deref() == Some("http") || svc.http.is_some() || HTTP_PORTS.contains(&svc.port)
}

/// Label notable exposed ports (databases, remote access, file sharing).
fn port_of_interest(svc: &Service) -> Option<Tag> {
    let (name, detail) = match svc.port {
        3306 | 5432 | 27017 | 6379 | 9200 => (
            "database-exposed",
            "a database service is reachable on a well-known database port",
        ),
        3389 => ("rdp", "Remote Desktop Protocol is exposed"),
        445 => ("smb", "SMB file sharing is exposed"),
        _ => return None,
    };
    Some(Tag {
        name: name.to_string(),
        cve: None,
        detail: Some(detail.to_string()),
    })
}

/// Keep the first tag for each distinct name.
fn dedup_by_name(tags: &mut Vec<Tag>) {
    let mut seen: Vec<String> = Vec::new();
    tags.retain(|t| {
        if seen.iter().any(|n| n == &t.name) {
            false
        } else {
            seen.push(t.name.clone());
            true
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crusade_core::{HttpInfo, Service, TlsCert, Transport};
    use std::net::{IpAddr, Ipv4Addr};
    use time::Duration;

    fn host() -> Host {
        Host::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
    }

    fn tls(self_signed: bool, not_after: Option<OffsetDateTime>) -> TlsCert {
        TlsCert {
            subject_cn: Some("example".to_string()),
            issuer_cn: Some("example".to_string()),
            san: Vec::new(),
            not_before: None,
            not_after,
            self_signed,
            fingerprint_sha256: None,
            version: None,
            cipher: None,
        }
    }

    #[test]
    fn flags_self_signed_expired_and_default_page() {
        let now = OffsetDateTime::now_utc();
        let mut svc = Service::new(443, Transport::Tcp);
        svc.service = Some("https".to_string());
        svc.tls = Some(tls(true, Some(now - Duration::days(30))));
        svc.http = Some(HttpInfo {
            status: Some(200),
            server: Some("nginx".to_string()),
            title: Some("Welcome to nginx!".to_string()),
            headers: Vec::new(),
            favicon_hash: None,
            technologies: Vec::new(),
            security_headers: Vec::new(),
        });

        let mut h = host();
        h.services.push(svc);

        let tags = heuristic_tags(&h);
        let names: Vec<&str> = tags.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"self-signed-certificate"), "{names:?}");
        assert!(names.contains(&"expired-certificate"), "{names:?}");
        assert!(names.contains(&"default-page"), "{names:?}");
    }

    #[test]
    fn healthy_host_gets_no_bad_tags() {
        let now = OffsetDateTime::now_utc();
        let mut svc = Service::new(443, Transport::Tcp);
        svc.service = Some("https".to_string());
        svc.tls = Some(tls(false, Some(now + Duration::days(365))));
        svc.http = Some(HttpInfo {
            status: Some(200),
            server: Some("nginx".to_string()),
            title: Some("Example Corp — Home".to_string()),
            headers: Vec::new(),
            favicon_hash: None,
            technologies: Vec::new(),
            security_headers: Vec::new(),
        });

        let mut h = host();
        h.services.push(svc);

        let tags = heuristic_tags(&h);
        let names: Vec<&str> = tags.iter().map(|t| t.name.as_str()).collect();
        assert!(!names.contains(&"self-signed-certificate"), "{names:?}");
        assert!(!names.contains(&"expired-certificate"), "{names:?}");
        assert!(!names.contains(&"default-page"), "{names:?}");
        assert!(!names.contains(&"http-no-tls"), "{names:?}");
    }

    #[test]
    fn flags_plaintext_http_and_database_port() {
        let mut web = Service::new(80, Transport::Tcp);
        web.service = Some("http".to_string());
        web.http = Some(HttpInfo {
            status: Some(200),
            server: None,
            title: None,
            headers: Vec::new(),
            favicon_hash: None,
            technologies: Vec::new(),
            security_headers: Vec::new(),
        });

        let db = Service::new(5432, Transport::Tcp);

        let mut h = host();
        h.services.push(web);
        h.services.push(db);

        let tags = heuristic_tags(&h);
        let names: Vec<&str> = tags.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"http-no-tls"), "{names:?}");
        assert!(names.contains(&"database-exposed"), "{names:?}");
    }

    #[test]
    fn database_tags_dedup_by_name() {
        let mut h = host();
        h.services.push(Service::new(3306, Transport::Tcp));
        h.services.push(Service::new(6379, Transport::Tcp));
        let count = heuristic_tags(&h)
            .iter()
            .filter(|t| t.name == "database-exposed")
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn open_redis_is_flagged_unauthenticated() {
        let mut redis = Service::new(6379, Transport::Tcp);
        redis.service = Some("redis".to_string());
        redis.auth = Some(AuthState::Open);

        let mut h = host();
        h.services.push(redis);

        let tags = heuristic_tags(&h);
        let names: Vec<&str> = tags.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"unauthenticated-access"), "{names:?}");
        assert!(names.contains(&"unauth-redis"), "{names:?}");
        let detail = tags
            .iter()
            .find(|t| t.name == "unauthenticated-access")
            .and_then(|t| t.detail.clone())
            .unwrap_or_default();
        assert!(
            detail.contains("redis") && detail.contains("6379"),
            "{detail}"
        );
    }

    #[test]
    fn ics_service_is_flagged_unauthenticated_regardless_of_auth() {
        use crusade_core::IcsInfo;
        let mut plc = Service::new(502, Transport::Tcp);
        plc.service = Some("modbus".to_string());
        plc.ics = Some(IcsInfo::new("modbus"));
        // auth left as None — ICS has no authentication concept.

        let mut h = host();
        h.services.push(plc);

        let tags = heuristic_tags(&h);
        let names: Vec<&str> = tags.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"unauthenticated-access"), "{names:?}");
        assert!(names.contains(&"unauth-ics"), "{names:?}");
    }

    #[test]
    fn open_public_website_is_not_flagged_unauthenticated() {
        let mut web = Service::new(80, Transport::Tcp);
        web.service = Some("http".to_string());
        web.auth = Some(AuthState::Open);
        web.http = Some(HttpInfo {
            status: Some(200),
            server: Some("nginx".to_string()),
            title: Some("Example Corp — Home".to_string()),
            headers: Vec::new(),
            favicon_hash: None,
            technologies: Vec::new(),
            security_headers: Vec::new(),
        });

        let mut h = host();
        h.services.push(web);

        let tags = heuristic_tags(&h);
        let names: Vec<&str> = tags.iter().map(|t| t.name.as_str()).collect();
        assert!(!names.contains(&"unauthenticated-access"), "{names:?}");
        assert!(!names.iter().any(|n| n.starts_with("unauth-")), "{names:?}");
    }

    #[test]
    fn open_admin_panel_is_flagged_unauthenticated() {
        let mut web = Service::new(8080, Transport::Tcp);
        web.service = Some("http".to_string());
        web.auth = Some(AuthState::Open);
        web.http = Some(HttpInfo {
            status: Some(200),
            server: Some("lighttpd".to_string()),
            title: Some("Router Admin Login".to_string()),
            headers: Vec::new(),
            favicon_hash: None,
            technologies: Vec::new(),
            security_headers: Vec::new(),
        });

        let mut h = host();
        h.services.push(web);

        let names: Vec<String> = heuristic_tags(&h).into_iter().map(|t| t.name).collect();
        assert!(
            names.iter().any(|n| n == "unauthenticated-access"),
            "{names:?}"
        );
        assert!(names.iter().any(|n| n == "unauth-http-panel"), "{names:?}");
    }

    #[test]
    fn auth_required_database_is_not_flagged() {
        let mut db = Service::new(6379, Transport::Tcp);
        db.service = Some("redis".to_string());
        db.auth = Some(AuthState::Required);

        let mut h = host();
        h.services.push(db);

        let names: Vec<String> = heuristic_tags(&h).into_iter().map(|t| t.name).collect();
        assert!(
            !names.iter().any(|n| n == "unauthenticated-access"),
            "{names:?}"
        );
        assert!(!names.iter().any(|n| n == "unauth-redis"), "{names:?}");
    }
}
