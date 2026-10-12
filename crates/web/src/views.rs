//! Askama template structs and the view models that feed them.
//!
//! Each page has a `*Template` struct deriving [`askama::Template`]; the
//! smaller view types (`HostRow`, `ServiceView`, `TagView`) are plain data
//! shaped so the HTML templates stay logic-light.

use askama::Template;
use crusade_core::model::{Host, HttpInfo, Service, SshInfo, Tag, TlsCert};
use crusade_store::Facet;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Format a timestamp for display, falling back to a raw debug string.
fn fmt_time(dt: OffsetDateTime) -> String {
    dt.format(&Rfc3339).unwrap_or_else(|_| dt.to_string())
}

/// Format a unix-seconds timestamp for display, falling back to the raw number.
fn fmt_unix(secs: i64) -> String {
    OffsetDateTime::from_unix_timestamp(secs)
        .ok()
        .and_then(|dt| dt.format(&Rfc3339).ok())
        .unwrap_or_else(|| secs.to_string())
}

/// A screenshot filename is safe to serve only when it is a bare filename with
/// no path separators (so it can't escape the screenshots directory). Returns
/// the filename when safe, else `None`.
fn safe_screenshot(file: Option<&str>) -> Option<String> {
    file.filter(|f| !f.is_empty() && !f.contains('/') && !f.contains('\\'))
        .map(str::to_string)
}

/// Percent-encode a query-string component (same rules as the pager links in
/// `handlers`), used to build safe `/?q=...` pivot URLs from raw fingerprint
/// values that may contain `:`, `+`, `/` or `=`.
fn encode_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Build a `/?q=<field>:<value>` pivot search URL with the value encoded.
fn pivot(field: &str, value: &str) -> String {
    format!("/?q={}", encode_component(&format!("{field}:{value}")))
}

/// Does a tag describe a vulnerability / known-exploited issue worth flagging?
fn tag_is_vuln(tag: &Tag) -> bool {
    if tag.cve.is_some() {
        return true;
    }
    let n = tag.name.to_ascii_lowercase();
    [
        "vuln",
        "cve",
        "kev",
        "exploit",
        "known-exploited",
        "insecure",
        "cwe",
        "unauth",
    ]
    .iter()
    .any(|needle| n.contains(needle))
}

/// Lowercase string form of an auth posture (matches the serde `rename_all`
/// representation, e.g. `Open` -> `"open"`), used for the display badge.
fn auth_label(a: crusade_core::AuthState) -> String {
    serde_json::to_value(a)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

/// A tag as rendered: the raw name plus whether it should be highlighted and,
/// for CVE-bearing tags, a pivot URL to every host carrying the same CVE.
pub struct TagView {
    pub name: String,
    pub cve: Option<String>,
    /// `/?q=vuln:<cve>` when the tag records a specific CVE.
    pub cve_url: Option<String>,
    pub detail: Option<String>,
    pub highlight: bool,
}

impl From<&Tag> for TagView {
    fn from(t: &Tag) -> Self {
        TagView {
            name: t.name.clone(),
            cve: t.cve.clone(),
            cve_url: t.cve.as_deref().map(|c| pivot("vuln", c)),
            detail: t.detail.clone(),
            highlight: tag_is_vuln(t),
        }
    }
}

/// One host as shown in a search-results row.
pub struct HostRow {
    pub ip: String,
    pub hostname: Option<String>,
    pub country: Option<String>,
    pub asn: Option<u32>,
    pub org: Option<String>,
    pub ports: Vec<u16>,
    pub products: Vec<String>,
    pub tags: Vec<TagView>,
    pub last_seen: String,
    /// True if any service carries a JARM fingerprint (hint badge).
    pub has_jarm: bool,
    /// First favicon hash seen across services, for a clickable hint badge.
    pub favicon_hash: Option<i32>,
    /// `/?q=http.favicon.hash:<hash>` pivot for the favicon badge.
    pub favicon_url: Option<String>,
    /// Detected technologies across all services (deduped), for hint chips.
    pub technologies: Vec<String>,
    /// True when any service was observed reachable without credentials
    /// (`auth == Open`) — surfaces an "open/no-auth" hint badge on the row.
    pub has_open_auth: bool,
}

impl From<&Host> for HostRow {
    fn from(h: &Host) -> Self {
        let mut ports: Vec<u16> = h.services.iter().map(|s| s.port).collect();
        ports.sort_unstable();
        ports.dedup();

        let has_jarm = h.services.iter().any(|s| s.jarm.is_some());
        let has_open_auth = h
            .services
            .iter()
            .any(|s| matches!(s.auth, Some(crusade_core::AuthState::Open)));
        let favicon_hash = h
            .services
            .iter()
            .find_map(|s| s.http.as_ref().and_then(|x| x.favicon_hash));
        let mut technologies: Vec<String> = h
            .services
            .iter()
            .filter_map(|s| s.http.as_ref())
            .flat_map(|x| x.technologies.iter().cloned())
            .collect();
        technologies.sort_unstable();
        technologies.dedup();

        HostRow {
            ip: h.ip.to_string(),
            hostname: h.hostnames.first().cloned(),
            country: h.country.clone(),
            asn: h.asn,
            org: h.org.clone(),
            ports,
            products: h.products().into_iter().map(|p| p.to_string()).collect(),
            tags: h.tags.iter().map(TagView::from).collect(),
            last_seen: fmt_time(h.last_seen),
            has_jarm,
            favicon_hash,
            favicon_url: favicon_hash.map(|v| pivot("http.favicon.hash", &v.to_string())),
            technologies,
            has_open_auth,
        }
    }
}

/// SSH metadata as shown on the host-detail page, with pivot URLs precomputed.
pub struct SshView {
    pub banner: Option<String>,
    pub host_key_type: Option<String>,
    pub host_key_sha256: Option<String>,
    /// `/?q=ssh.hostkey:<sha256>` pivot.
    pub host_key_url: Option<String>,
    pub kex_algorithms: Vec<String>,
    pub hassh: Option<String>,
    /// `/?q=hassh:<hassh>` pivot.
    pub hassh_url: Option<String>,
}

impl From<&SshInfo> for SshView {
    fn from(s: &SshInfo) -> Self {
        SshView {
            banner: s.banner.clone(),
            host_key_type: s.host_key_type.clone(),
            host_key_sha256: s.host_key_sha256.clone(),
            host_key_url: s
                .host_key_sha256
                .as_deref()
                .map(|k| pivot("ssh.hostkey", k)),
            kex_algorithms: s.kex_algorithms.clone(),
            hassh: s.hassh.clone(),
            hassh_url: s.hassh.as_deref().map(|h| pivot("hassh", h)),
        }
    }
}

/// One service as shown on the host-detail page.
pub struct ServiceView {
    pub port: u16,
    pub transport: String,
    pub service: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub cpe: Option<String>,
    pub banner: Option<String>,
    pub tls: Option<TlsCert>,
    pub http: Option<HttpInfo>,
    pub ssh: Option<SshView>,
    /// JARM fingerprint and its `/?q=jarm:<value>` pivot.
    pub jarm: Option<String>,
    pub jarm_url: Option<String>,
    /// Favicon hash (from `http`) hoisted up with a pivot URL for the template.
    pub favicon_hash: Option<i32>,
    pub favicon_url: Option<String>,
    /// ICS/OT device identification, with a `/?q=ics:<proto>` pivot.
    pub ics: Option<IcsView>,
    /// Observed auth posture, lowercased ("open"/"required"/"unknown"), or
    /// `None` when not determined.
    pub auth: Option<String>,
    /// True when `auth` is `Open` — the notable "reachable without credentials"
    /// recon signal the template styles as a warning badge.
    pub auth_open: bool,
    /// Sanitized screenshot filename (no path separators), served at
    /// `/screens/<file>`. `None` when absent or unsafe to serve.
    pub screenshot: Option<String>,
    /// Set when the port was probed and stayed silent: the service is pending
    /// eviction and is shown greyed out rather than as live.
    pub pending_since: Option<String>,
    pub observed_at: String,
}

/// ICS/OT device identification as shown on the host-detail page.
pub struct IcsView {
    pub protocol: String,
    pub protocol_url: String,
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub device_id: Option<String>,
    pub extra: Vec<(String, String)>,
}

impl From<&crusade_core::IcsInfo> for IcsView {
    fn from(i: &crusade_core::IcsInfo) -> Self {
        IcsView {
            protocol: i.protocol.clone(),
            protocol_url: pivot("ics", &i.protocol),
            vendor: i.vendor.clone(),
            product: i.product.clone(),
            version: i.version.clone(),
            device_id: i.device_id.clone(),
            extra: i.extra.clone(),
        }
    }
}

impl From<&Service> for ServiceView {
    fn from(s: &Service) -> Self {
        let transport = serde_json::to_value(s.transport)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_else(|| "tcp".to_string());
        let favicon_hash = s.http.as_ref().and_then(|h| h.favicon_hash);
        let auth = s.auth.map(auth_label);
        let auth_open = matches!(s.auth, Some(crusade_core::AuthState::Open));
        ServiceView {
            port: s.port,
            transport,
            service: s.service.clone(),
            product: s.product.clone(),
            version: s.version.clone(),
            cpe: s.cpe.clone(),
            banner: s.banner.clone(),
            tls: s.tls.clone(),
            http: s.http.clone(),
            ssh: s.ssh.as_ref().map(SshView::from),
            jarm: s.jarm.clone(),
            jarm_url: s.jarm.as_deref().map(|j| pivot("jarm", j)),
            favicon_hash,
            favicon_url: favicon_hash.map(|v| pivot("http.favicon.hash", &v.to_string())),
            ics: s.ics.as_ref().map(IcsView::from),
            auth,
            auth_open,
            screenshot: safe_screenshot(s.screenshot.as_deref()),
            pending_since: s.pending_since.map(fmt_time),
            observed_at: fmt_time(s.observed_at),
        }
    }
}

/// The search / landing page.
#[derive(Template)]
#[template(path = "index.html")]
pub struct IndexTemplate {
    pub q: String,
    pub error: Option<String>,
    pub searched: bool,
    pub total: i64,
    pub page: usize,
    pub results: Vec<HostRow>,
    pub has_prev: bool,
    pub has_next: bool,
    pub prev_url: String,
    pub next_url: String,
}

/// The host-detail page.
#[derive(Template)]
#[template(path = "similar.html")]
pub struct SimilarTemplate {
    /// Free-text query, if any.
    pub q: String,
    /// `ip:port/transport` of the service used as the query, if any.
    pub like: String,
    /// Crusade query the results were restricted to, if any.
    pub filter: String,
    /// Set when no embedding model is installed.
    pub unavailable: bool,
    /// Number of vectors indexed under the active model.
    pub indexed: i64,
    pub hits: Vec<SimilarRow>,
}

/// One row of the similarity results.
pub struct SimilarRow {
    pub ip: String,
    pub port: u16,
    pub transport: String,
    /// Similarity as a percentage, for the bar width.
    pub pct: u32,
    pub score: String,
    pub text: String,
}

#[derive(Template)]
#[template(path = "host.html")]
pub struct HostTemplate {
    pub ip: String,
    pub hostnames: Vec<String>,
    pub domains: Vec<String>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub asn: Option<u32>,
    pub org: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub last_seen: String,
    pub tags: Vec<TagView>,
    pub services: Vec<ServiceView>,
    /// Honeypot score as a percentage, when the host has been scored.
    pub honeypot_pct: Option<u32>,
    pub honeypot_flagged: bool,
    /// (signal, weight %, detail) for each piece of honeypot evidence.
    pub honeypot_evidence: Vec<(String, u32, String)>,
}

impl From<&Host> for HostTemplate {
    fn from(h: &Host) -> Self {
        let hp = h.honeypot.as_ref();
        HostTemplate {
            honeypot_pct: hp.map(|a| (a.score * 100.0).round() as u32),
            // The scorer tags hosts at or above its threshold.
            honeypot_flagged: h.tags.iter().any(|t| t.name == "honeypot"),
            honeypot_evidence: hp
                .map(|a| {
                    a.evidence
                        .iter()
                        .map(|e| {
                            (
                                e.signal.clone(),
                                (e.weight * 100.0).round() as u32,
                                e.detail.clone(),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default(),
            ip: h.ip.to_string(),
            hostnames: h.hostnames.clone(),
            domains: h.domains.clone(),
            country: h.country.clone(),
            city: h.city.clone(),
            asn: h.asn,
            org: h.org.clone(),
            latitude: h.latitude,
            longitude: h.longitude,
            last_seen: fmt_time(h.last_seen),
            tags: h.tags.iter().map(TagView::from).collect(),
            services: h.services.iter().map(ServiceView::from).collect(),
        }
    }
}

/// The stats / facets page.
#[derive(Template)]
#[template(path = "stats.html")]
pub struct StatsTemplate {
    /// Hosts in scope: the whole index, or the matches when `scoped`.
    pub host_count: i64,
    /// The raw `?q=` echoed back (empty when unscoped).
    pub q: String,
    /// True when the facets are restricted to a search (`facets_for_query`).
    pub scoped: bool,
    pub ports: Vec<Facet>,
    pub ports_max: i64,
    pub products: Vec<Facet>,
    pub products_max: i64,
    pub countries: Vec<Facet>,
    pub countries_max: i64,
    pub asns: Vec<Facet>,
    pub asns_max: i64,
    pub tags: Vec<Facet>,
    pub tags_max: i64,
}

/// The 404 page.
#[derive(Template)]
#[template(path = "not_found.html")]
pub struct NotFoundTemplate {
    pub message: String,
}

/// One point in time in a host's scan history: every service snapshot that
/// shares the same `observed_at`.
pub struct HistorySnapshot {
    pub time: String,
    pub services: Vec<ServiceView>,
}

/// The per-host history / timeline page.
#[derive(Template)]
#[template(path = "history.html")]
pub struct HistoryTemplate {
    pub ip: String,
    /// Reverse-chronological snapshots (newest first). Empty when no history.
    pub snapshots: Vec<HistorySnapshot>,
}

impl HistoryTemplate {
    /// Build a timeline from raw `(observed_at unix secs, Service)` rows that
    /// `Store::service_history` returns newest-first. Consecutive rows sharing
    /// a timestamp are grouped into one snapshot.
    pub fn from_history(ip: String, rows: Vec<(i64, crusade_core::Service)>) -> Self {
        let mut snapshots: Vec<HistorySnapshot> = Vec::new();
        let mut cur_ts: Option<i64> = None;
        for (ts, svc) in rows {
            let view = ServiceView::from(&svc);
            if cur_ts == Some(ts) {
                if let Some(last) = snapshots.last_mut() {
                    last.services.push(view);
                    continue;
                }
            }
            cur_ts = Some(ts);
            snapshots.push(HistorySnapshot {
                time: fmt_unix(ts),
                services: vec![view],
            });
        }
        HistoryTemplate { ip, snapshots }
    }
}

/// One alert row as shown on the trends page.
pub struct AlertView {
    pub time: String,
    pub ip: String,
    pub kind: String,
    pub detail: String,
    pub delivered: bool,
}

impl From<&crusade_store::Alert> for AlertView {
    fn from(a: &crusade_store::Alert) -> Self {
        AlertView {
            time: fmt_unix(a.ts),
            ip: a.ip.clone(),
            kind: a.kind.clone(),
            detail: a.detail.clone(),
            delivered: a.delivered,
        }
    }
}

/// The trends / alerts overview page.
#[derive(Template)]
#[template(path = "trends.html")]
pub struct TrendsTemplate {
    /// Total hosts in the index.
    pub host_count: i64,
    /// Most recent alerts, newest first.
    pub alerts: Vec<AlertView>,
    pub ports: Vec<Facet>,
    pub ports_max: i64,
    pub products: Vec<Facet>,
    pub products_max: i64,
    pub countries: Vec<Facet>,
    pub countries_max: i64,
    pub tags: Vec<Facet>,
    pub tags_max: i64,
}

/// Largest count in a facet list, floored at 1 so bar math never divides by 0.
pub fn facet_max(facets: &[Facet]) -> i64 {
    facets.iter().map(|f| f.count).max().unwrap_or(1).max(1)
}
