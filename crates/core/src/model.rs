//! Core data model shared across all crates.
//!
//! A [`Host`] is one IP address we have observed. It carries zero or more
//! [`Service`]s (one per open port we successfully probed), plus enrichment
//! data (geo/ASN, reverse DNS) and derived [`Tag`]s. Everything is designed to
//! round-trip through JSON so the store and web layers can share it directly.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use time::OffsetDateTime;

/// A single observed host (one IP address).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub ip: IpAddr,
    /// Reverse-DNS name(s), if any resolved.
    #[serde(default)]
    pub hostnames: Vec<String>,
    /// Forward DNS names that pointed here (from domain targets / crt.sh).
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    /// ISO 3166-1 alpha-2 country code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latitude: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub longitude: Option<f64>,
    #[serde(default)]
    pub services: Vec<Service>,
    #[serde(default)]
    pub tags: Vec<Tag>,
    /// When this host was most recently scanned.
    #[serde(with = "time::serde::rfc3339")]
    pub last_seen: OffsetDateTime,
}

impl Host {
    pub fn new(ip: IpAddr) -> Self {
        Host {
            ip,
            hostnames: Vec::new(),
            domains: Vec::new(),
            asn: None,
            org: None,
            country: None,
            city: None,
            latitude: None,
            longitude: None,
            services: Vec::new(),
            tags: Vec::new(),
            last_seen: OffsetDateTime::now_utc(),
        }
    }

    /// All distinct product names across services, for faceting/search.
    pub fn products(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self
            .services
            .iter()
            .filter_map(|s| s.product.as_deref())
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    }
}

/// Transport protocol a service was reached over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Tcp,
    Udp,
}

/// One open port and whatever we learned by probing it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    pub port: u16,
    pub transport: Transport,
    /// Service name as fingerprinted (e.g. "http", "ssh").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// CPE string if the fingerprint supplied one (for vuln matching).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpe: Option<String>,
    /// Raw banner text (truncated at capture time). Searchable full-text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    /// Parsed TLS certificate, for TLS-wrapped services.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsCert>,
    /// Parsed HTTP metadata, for web services.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpInfo>,
    /// Parsed SSH metadata, for SSH services.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh: Option<SshInfo>,
    /// JARM active TLS fingerprint (62-char hex), for TLS services.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jarm: Option<String>,
    /// Industrial control system / OT device identification, when the service
    /// speaks an ICS protocol (Modbus, S7, BACnet, DNP3, EtherNet/IP, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ics: Option<IcsInfo>,
    /// Observed authentication posture: whether the service answered a standard
    /// read-only request without requiring credentials. Determined by observing
    /// the service's own response (HTTP 401 / WWW-Authenticate, Redis -NOAUTH,
    /// a VNC handshake's offered security types, ICS protocols having no auth) —
    /// Crusade never submits credentials or attempts to authenticate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<AuthState>,
    #[serde(with = "time::serde::rfc3339")]
    pub observed_at: OffsetDateTime,
}

/// A service's authentication posture, as passively observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthState {
    /// Reachable and answering without any credentials — the key recon signal.
    Open,
    /// The service challenged for or required authentication.
    Required,
    /// Could not be determined.
    Unknown,
}

impl Service {
    pub fn new(port: u16, transport: Transport) -> Self {
        Service {
            port,
            transport,
            service: None,
            product: None,
            version: None,
            cpe: None,
            banner: None,
            tls: None,
            http: None,
            ssh: None,
            jarm: None,
            ics: None,
            auth: None,
            observed_at: OffsetDateTime::now_utc(),
        }
    }
}

/// A TLS certificate as presented by a service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsCert {
    /// Subject common name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_cn: Option<String>,
    /// Issuer common name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_cn: Option<String>,
    #[serde(default)]
    pub san: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_rfc3339")]
    pub not_before: Option<OffsetDateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_rfc3339")]
    pub not_after: Option<OffsetDateTime>,
    pub self_signed: bool,
    /// SHA-256 fingerprint, lowercase hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint_sha256: Option<String>,
    /// Negotiated TLS protocol version (e.g. "TLS 1.3").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Negotiated cipher suite.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cipher: Option<String>,
}

/// HTTP metadata captured from a web service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Selected response headers, lowercased keys.
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    /// MurmurHash3 (32-bit signed) of the base64-encoded favicon, à la Shodan's
    /// `http.favicon.hash` — a strong pivot for finding the same deployment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub favicon_hash: Option<i32>,
    /// Detected technologies (server software, frameworks, CMS, etc.).
    #[serde(default)]
    pub technologies: Vec<String>,
    /// Names of security headers that are present (HSTS, CSP, …).
    #[serde(default)]
    pub security_headers: Vec<String>,
}

/// SSH metadata captured from an SSH service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshInfo {
    /// Banner / identification string (e.g. "SSH-2.0-OpenSSH_8.9").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    /// Host-key type (e.g. "ssh-ed25519", "rsa-sha2-512").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_key_type: Option<String>,
    /// SHA-256 fingerprint of the host key, base64 (OpenSSH style).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_key_sha256: Option<String>,
    /// Offered key-exchange algorithms.
    #[serde(default)]
    pub kex_algorithms: Vec<String>,
    /// HASSH fingerprint (md5 over the client/server KEX fields).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hassh: Option<String>,
}

/// Industrial-control-system / OT device identification.
///
/// Populated by read-only identification requests to a device speaking an ICS
/// protocol (e.g. Modbus function 43/14 "Read Device Identification", S7comm
/// SZL read, EtherNet/IP ListIdentity, BACnet ReadProperty, DNP3). We only ask
/// for the device's own self-description — never write coils/registers or issue
/// control commands.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcsInfo {
    /// Protocol spoken: "modbus", "s7", "bacnet", "dnp3", "ethernetip", …
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Device/module name or serial, when the protocol exposes one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    /// Any further protocol-specific attributes (label, value).
    #[serde(default)]
    pub extra: Vec<(String, String)>,
}

impl IcsInfo {
    pub fn new(protocol: impl Into<String>) -> Self {
        IcsInfo {
            protocol: protocol.into(),
            vendor: None,
            product: None,
            version: None,
            device_id: None,
            extra: Vec::new(),
        }
    }
}

/// A derived label attached to a host or service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tag {
    pub name: String,
    /// Optional CVE/KEV id when the tag records a known vulnerability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cve: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl Tag {
    pub fn simple(name: impl Into<String>) -> Self {
        Tag { name: name.into(), cve: None, detail: None }
    }
}

/// Serde helper for `Option<OffsetDateTime>` as rfc3339.
mod opt_rfc3339 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use time::OffsetDateTime;

    pub fn serialize<S: Serializer>(
        v: &Option<OffsetDateTime>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match v {
            Some(dt) => time::serde::rfc3339::serialize(dt, s),
            None => None::<String>.serialize(s),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<OffsetDateTime>, D::Error> {
        let opt = Option::<String>::deserialize(d)?;
        match opt {
            Some(s) => OffsetDateTime::parse(
                &s,
                &time::format_description::well_known::Rfc3339,
            )
            .map(Some)
            .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}
