//! Configuration loaded from `crusade.toml` (falling back to sane defaults).

use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub database: Database,
    pub scan: Scan,
    pub sweep: Sweep,
    pub web: Web,
    pub data: Data,
    pub alert: Alert,
    pub screenshot: Screenshot,
    pub lifecycle: LifecycleCfg,
    pub vuln: VulnCfg,
    pub archive: ArchiveCfg,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Database {
    pub path: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Scan {
    pub connect_timeout_ms: u64,
    pub max_concurrent: usize,
    pub rate_per_sec: f64,
    pub default_ports: Vec<u16>,
    pub allow_private: bool,
    pub blocklist_path: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Sweep {
    pub enabled: bool,
    pub rate_per_sec: f64,
    pub source_identity: String,
    pub abuse_contact: String,
    pub optout_url: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Web {
    pub bind: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Data {
    pub dir: PathBuf,
    pub nmap_probes: PathBuf,
}

/// CVE matching behaviour.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct VulnCfg {
    /// Resolve a product name to a CPE that NVD actually uses when the name
    /// matches no rule literally. On by default: exact matching alone misses
    /// a large share of real services, because `Apache httpd` and
    /// `apache:http_server` are the same software under different names. Every
    /// CVE found this way says so in its detail, with the tier and score.
    pub resolve_cpe: bool,
}

impl Default for VulnCfg {
    fn default() -> Self {
        VulnCfg { resolve_cpe: true }
    }
}

/// How long a service that stops answering is kept. Mirrors the published
/// Censys policy (SIGCOMM 2025): one missed scan marks a service pending
/// rather than deleting it, since a single miss is usually loss or throttling.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LifecycleCfg {
    /// Hours a probed-but-silent service stays pending before eviction.
    pub evict_after_hours: i64,
    /// Days a host with no services is kept before being dropped.
    pub forget_after_days: i64,
}

impl Default for LifecycleCfg {
    fn default() -> Self {
        LifecycleCfg {
            evict_after_hours: 72,
            forget_after_days: 60,
        }
    }
}

impl LifecycleCfg {
    pub fn policy(&self) -> crusade_core::lifecycle::Lifecycle {
        crusade_core::lifecycle::Lifecycle {
            evict_after: time::Duration::hours(self.evict_after_hours.max(0)),
            forget_after: time::Duration::days(self.forget_after_days.max(0)),
        }
    }
}

impl Config {
    /// Load from `path` if it exists, else return defaults.
    pub fn load(path: &Path) -> anyhow::Result<Config> {
        if path.exists() {
            let text = std::fs::read_to_string(path)?;
            Ok(toml::from_str(&text)?)
        } else {
            Ok(Config::default())
        }
    }

    pub fn connect_timeout(&self) -> Duration {
        Duration::from_millis(self.scan.connect_timeout_ms)
    }
}

impl Default for Database {
    fn default() -> Self {
        Database {
            path: "crusade.db".into(),
        }
    }
}
impl Default for Scan {
    fn default() -> Self {
        Scan {
            connect_timeout_ms: 3000,
            max_concurrent: 50,
            rate_per_sec: 100.0,
            default_ports: vec![
                21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443,
                9200, 27017,
            ],
            allow_private: false,
            blocklist_path: "blocklist.txt".into(),
        }
    }
}
impl Default for Sweep {
    fn default() -> Self {
        Sweep {
            enabled: false,
            rate_per_sec: 0.0,
            source_identity: "crusade-scanner".into(),
            abuse_contact: String::new(),
            optout_url: String::new(),
        }
    }
}
impl Default for Web {
    fn default() -> Self {
        Web {
            bind: "127.0.0.1:8088".into(),
        }
    }
}
impl Default for Data {
    fn default() -> Self {
        Data {
            dir: "data".into(),
            nmap_probes: "/usr/share/nmap/nmap-service-probes".into(),
        }
    }
}

/// Retention and automatic archiving.
///
/// Data that has neither answered nor been looked at for a long time is
/// written to a gzipped archive under `<data dir>/archive/` and then deleted.
/// With `max_db_mb` set, that happens on its own once the database grows past
/// the limit, rather than only when `crusade archive` is run.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ArchiveCfg {
    /// Drop timeline entries older than this many days. The newest entry per
    /// service is always kept.
    pub history_days: i64,
    /// Drop delivered alerts older than this. Undelivered ones are kept.
    pub alerts_days: i64,
    /// Drop finished jobs older than this.
    pub jobs_days: i64,
    /// A host must have gone unseen this long to be archivable.
    pub host_stale_days: i64,
    /// ...and unvisited this long (never visited counts as forever).
    pub host_unaccessed_days: i64,
    /// Archive automatically once the database exceeds this many MiB.
    /// `0` (the default) disables automatic archiving entirely.
    pub max_db_mb: u64,
}

impl Default for ArchiveCfg {
    fn default() -> Self {
        ArchiveCfg {
            history_days: 180,
            alerts_days: 90,
            jobs_days: 30,
            host_stale_days: 180,
            host_unaccessed_days: 90,
            max_db_mb: 0,
        }
    }
}

impl ArchiveCfg {
    /// The size limit in bytes, or `None` when automatic archiving is off.
    pub fn max_db_bytes(&self) -> Option<u64> {
        (self.max_db_mb > 0).then(|| self.max_db_mb * 1024 * 1024)
    }
}

/// Headless-Chrome screenshots of web services. Off by default; needs a Chrome
/// binary (auto-detected on PATH, or set `chrome_path`).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Screenshot {
    pub enabled: bool,
    pub chrome_path: Option<String>,
}

/// Alert transports used by `crusade monitor`. All optional; empty = log only.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Alert {
    /// Generic JSON webhook URLs (Slack/Discord/Teams-compatible POST).
    pub webhooks: Vec<String>,
    /// SMTP relay host; email is sent only when this is set.
    pub smtp_host: Option<String>,
    pub smtp_port: Option<u16>,
    pub smtp_user: Option<String>,
    pub smtp_pass: Option<String>,
    /// From / To addresses for alert email.
    pub email_from: Option<String>,
    pub email_to: Vec<String>,
}
