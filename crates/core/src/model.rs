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
    /// Passive honeypot/deception assessment; `None` until scored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub honeypot: Option<HoneypotAssessment>,
    /// When this host was most recently scanned.
    #[serde(with = "time::serde::rfc3339")]
    pub last_seen: OffsetDateTime,
}

/// How likely a host is to be a honeypot, with the evidence behind the score.
///
/// Scores combine independent signals with a noisy-OR, so each piece of
/// evidence carries its own weight in `[0, 1]` and the overall score is
/// `1 - prod(1 - weight)`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HoneypotAssessment {
    pub score: f32,
    #[serde(default)]
    pub evidence: Vec<HoneypotEvidence>,
}

/// One signal that contributed to a [`HoneypotAssessment`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HoneypotEvidence {
    /// Stable signal id, e.g. `rule:cowrie-default-ssh` or `ssh-kex-anachronism`.
    pub signal: String,
    pub weight: f32,
    pub detail: String,
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
            honeypot: None,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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
    /// JA4TS: a fingerprint of the SYN-ACK's TCP options, window and flags,
    /// identifying the responding network stack rather than the application.
    /// Populated from zmap 4.4 sweep output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ja4ts: Option<String>,
    /// Filename (under the data screenshots dir) of a captured screenshot of
    /// this service's web UI, when screenshotting is enabled and succeeds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub screenshot: Option<String>,
    /// Perceptual hash of the screenshot (dHash), for finding the same page
    /// across hosts. `None` when there is no capture, or the page was too
    /// uniform to fingerprint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub screenshot_phash: Option<i64>,
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
    /// Timing of the first exchange, and its variability across scans. The
    /// signal an LLM-backed honeypot cannot hide (see [`Latency`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency: Option<Latency>,
    /// Set when a rescan probed this port and got no answer: the service is
    /// pending eviction (see [`crate::lifecycle`]). `None` = live.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_rfc3339")]
    pub pending_since: Option<OffsetDateTime>,
    /// Last time the service was actually observed answering.
    #[serde(with = "time::serde::rfc3339")]
    pub observed_at: OffsetDateTime,
}

/// How long a service took to answer, and how much that varies.
///
/// A static daemon writes a banner it already has: the first byte arrives
/// about one round trip after the connection is established, every time. A
/// service that *generates* its reply has to do the work first, and an
/// LLM-backed honeypot has to run inference — hundreds of milliseconds at
/// best, seconds on CPU, and a different duration for every reply, because
/// the duration depends on how much text the model decided to produce.
/// Latency and jitter are therefore what distinguishes the current generation
/// of honeypots, which defeat banner rules by generating plausible banners
/// (arXiv:2502.20589; LLM honeypots arXiv:2309.00155, 2409.08234, 2405.05999).
///
/// The measurement is normalised against the connect time, which is the one
/// round trip Crusade can observe without the application in the path. A host
/// in Australia answers slowly because it is far away, not because it is
/// thinking; the *ratio* of application time to network time cancels the
/// distance out. Variance accumulates across rescans by Welford's method, so
/// nothing but five numbers is stored however long a service is watched.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Latency {
    /// Milliseconds to complete the TCP handshake: one round trip.
    pub connect_ms: u32,
    /// Milliseconds from the established connection to the first byte of the
    /// answer: one round trip plus however long the service took to decide.
    pub banner_ms: u32,
    /// Scans that contributed to the statistics below.
    pub samples: u32,
    /// Mean of `banner_ms / connect_ms` over those scans.
    pub mean_ratio: f32,
    /// Welford's sum of squared deviations, for the variance of the ratio.
    pub m2: f32,
}

impl Latency {
    /// Samples needed before jitter means anything. Two points always have a
    /// variance; it just is not evidence of anything.
    pub const MIN_SAMPLES: u32 = 4;

    /// Record one observation.
    pub fn observe(connect_ms: u32, banner_ms: u32) -> Latency {
        let mut l = Latency {
            connect_ms,
            banner_ms,
            samples: 0,
            mean_ratio: 0.0,
            m2: 0.0,
        };
        l.accumulate(connect_ms, banner_ms);
        l
    }

    /// This observation's ratio of answer time to round-trip time.
    ///
    /// The connect time is floored at a millisecond: on a LAN or loopback it
    /// rounds to zero, and dividing by it would turn any delay into infinity.
    pub fn ratio_of(connect_ms: u32, banner_ms: u32) -> f32 {
        banner_ms as f32 / connect_ms.max(1) as f32
    }

    pub fn ratio(&self) -> f32 {
        Latency::ratio_of(self.connect_ms, self.banner_ms)
    }

    /// Fold one observation into the running statistics (Welford).
    pub fn accumulate(&mut self, connect_ms: u32, banner_ms: u32) {
        let x = Latency::ratio_of(connect_ms, banner_ms);
        self.samples += 1;
        let delta = x - self.mean_ratio;
        self.mean_ratio += delta / self.samples as f32;
        self.m2 += delta * (x - self.mean_ratio);
    }

    /// Carry an earlier service's statistics into this fresh observation.
    pub fn absorb(&mut self, prior: &Latency) {
        // The prior's own last observation is already in its statistics, so
        // only the accumulated state moves across; this observation was added
        // by `observe`.
        if prior.samples == 0 {
            return;
        }
        let (n_a, n_b) = (prior.samples as f32, self.samples as f32);
        let total = n_a + n_b;
        let delta = self.mean_ratio - prior.mean_ratio;
        // Chan et al.'s parallel variance combination: exact, and independent
        // of the order scans happened to arrive in.
        self.m2 = prior.m2 + self.m2 + delta * delta * n_a * n_b / total;
        self.mean_ratio = (prior.mean_ratio * n_a + self.mean_ratio * n_b) / total;
        self.samples += prior.samples;
    }

    /// Coefficient of variation of the ratio, once there are enough samples.
    ///
    /// Relative rather than absolute, so a slow-but-consistent service is not
    /// mistaken for an erratic one.
    pub fn jitter(&self) -> Option<f32> {
        if self.samples < Latency::MIN_SAMPLES || self.mean_ratio <= 0.0 {
            return None;
        }
        let variance = self.m2 / (self.samples - 1) as f32;
        Some(variance.sqrt() / self.mean_ratio)
    }
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
            ja4ts: None,
            screenshot: None,
            screenshot_phash: None,
            ics: None,
            auth: None,
            latency: None,
            pending_since: None,
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
        Tag {
            name: name.into(),
            cve: None,
            detail: None,
        }
    }
}

/// Serde helper for `Option<OffsetDateTime>` as rfc3339.
mod opt_rfc3339 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use time::OffsetDateTime;

    pub fn serialize<S: Serializer>(v: &Option<OffsetDateTime>, s: S) -> Result<S::Ok, S::Error> {
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
            Some(s) => OffsetDateTime::parse(&s, &time::format_description::well_known::Rfc3339)
                .map(Some)
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fast_answer_on_a_slow_link_is_not_slow() {
        // 300 ms to answer sounds slow until you see the 280 ms round trip.
        let l = Latency::observe(280, 300);
        assert!(l.ratio() < 2.0, "{}", l.ratio());
    }

    #[test]
    fn a_slow_answer_on_a_fast_link_shows_in_the_ratio() {
        let l = Latency::observe(12, 900);
        assert!(l.ratio() > 50.0, "{}", l.ratio());
    }

    /// Connect time rounds to zero on a LAN; dividing by it must not produce
    /// infinity, or every local service looks like it is thinking.
    #[test]
    fn a_zero_round_trip_does_not_divide_by_zero() {
        let l = Latency::observe(0, 40);
        assert!(l.ratio().is_finite());
        assert_eq!(l.ratio(), 40.0);
    }

    #[test]
    fn jitter_needs_enough_scans_to_mean_anything() {
        let mut l = Latency::observe(10, 20);
        assert_eq!(l.jitter(), None);
        l.accumulate(10, 22);
        assert_eq!(l.jitter(), None, "two samples is not evidence");
        l.accumulate(10, 21);
        l.accumulate(10, 20);
        assert!(l.jitter().is_some());
    }

    #[test]
    fn a_constant_service_has_almost_no_jitter() {
        let mut l = Latency::observe(10, 21);
        for _ in 0..5 {
            l.accumulate(10, 20);
        }
        assert!(l.jitter().unwrap() < 0.1, "{:?}", l.jitter());
    }

    #[test]
    fn a_service_whose_answer_time_swings_has_jitter() {
        let mut l = Latency::observe(10, 200);
        for ms in [1800, 400, 2600, 700] {
            l.accumulate(10, ms);
        }
        assert!(l.jitter().unwrap() > 0.6, "{:?}", l.jitter());
    }

    /// Statistics carried across rescans must come out the same as if every
    /// observation had been made in one pass — otherwise the variance depends
    /// on when the scans happened to be split.
    #[test]
    fn absorbing_earlier_scans_matches_one_pass() {
        let samples = [(10u32, 30u32), (10, 90), (12, 40), (9, 300), (11, 60)];
        let mut one = Latency::observe(samples[0].0, samples[0].1);
        for (c, b) in &samples[1..] {
            one.accumulate(*c, *b);
        }

        let mut prior = Latency::observe(samples[0].0, samples[0].1);
        prior.accumulate(samples[1].0, samples[1].1);
        prior.accumulate(samples[2].0, samples[2].1);
        let mut later = Latency::observe(samples[3].0, samples[3].1);
        later.accumulate(samples[4].0, samples[4].1);
        later.absorb(&prior);

        assert_eq!(later.samples, one.samples);
        assert!(
            (later.mean_ratio - one.mean_ratio).abs() < 1e-3,
            "{} vs {}",
            later.mean_ratio,
            one.mean_ratio
        );
        assert!(
            (later.jitter().unwrap() - one.jitter().unwrap()).abs() < 1e-3,
            "{:?} vs {:?}",
            later.jitter(),
            one.jitter()
        );
    }
}
