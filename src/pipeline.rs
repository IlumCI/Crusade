//! The scan → probe → enrich → vuln-tag → store pipeline.
//!
//! Given a set of discovered `(ip, open_port)` pairs, this groups them by host,
//! probes every open port for a banner/fingerprint/cert, enriches the host with
//! geo/ASN and reverse DNS, applies vulnerability and heuristic tags, and
//! upserts the result into the store.

use crate::config::Config;
use anyhow::Result;
use crusade_core::model::Host;
use crusade_embed::Embedder;
use crusade_enrich::{enrich_host, EnrichConfig, GeoAsnDb, Screenshotter};
use crusade_probe::{Fingerprints, ProbeConfig};
use crusade_store::Store;
use crusade_vuln::{HoneypotRules, HoneypotScorer, PortStats, VulnDb};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use tracing::{info, warn};

/// Loadable reference data shared by every host in a run.
pub struct Datasets {
    pub fingerprints: Fingerprints,
    pub geo: GeoAsnDb,
    pub vulns: VulnDb,
    pub honeypot_rules: HoneypotRules,
    /// Embedding model for semantic search; `None` when not installed.
    pub embedder: Option<Embedder>,
}

impl Datasets {
    /// Load fingerprints (required), plus geo/ASN and CVE feeds (best-effort:
    /// missing feeds degrade gracefully rather than failing the scan).
    pub fn load(cfg: &Config) -> Result<Datasets> {
        let fingerprints = Fingerprints::load(&cfg.data.nmap_probes).unwrap_or_else(|e| {
            warn!("could not load nmap probes ({e}); fingerprinting disabled");
            Fingerprints::parse("")
        });

        let dir = &cfg.data.dir;
        let geo = load_geo(dir).unwrap_or_else(|e| {
            warn!("geo/ASN data unavailable ({e}); run `crusade update-data`");
            GeoAsnDb::default()
        });
        let vulns = load_vulns(dir).unwrap_or_else(|e| {
            warn!("vuln feeds unavailable ({e}); only heuristic tags will apply");
            VulnDb::new()
        });

        let honeypot_rules = load_honeypot_rules(dir);
        let embedder = load_embedder(dir);

        Ok(Datasets {
            fingerprints,
            geo,
            vulns,
            honeypot_rules,
            embedder,
        })
    }
}

/// The default embedding model under `<data dir>/models/`, if installed.
pub fn load_embedder(dir: &Path) -> Option<Embedder> {
    let model_dir = dir.join("models").join(crusade_embed::DEFAULT_MODEL_DIR);
    if !crusade_embed::MODEL_FILES
        .iter()
        .all(|f| model_dir.join(f).exists())
    {
        return None;
    }
    match Embedder::load(&model_dir) {
        Ok(e) => Some(e),
        Err(e) => {
            warn!("embedding model unavailable ({e:#}); semantic search disabled");
            None
        }
    }
}

/// Embed every service of `host` that has something to say.
pub fn embed_host(embedder: &Embedder, host: &Host) -> Vec<(u16, String, Vec<i8>)> {
    let (keys, texts): (Vec<(u16, String)>, Vec<String>) = host
        .services
        .iter()
        .filter_map(|svc| {
            let transport = match svc.transport {
                crusade_core::Transport::Tcp => "tcp",
                crusade_core::Transport::Udp => "udp",
            };
            crusade_embed::service_text(svc).map(|t| ((svc.port, transport.to_string()), t))
        })
        .unzip();
    if texts.is_empty() {
        return Vec::new();
    }
    keys.into_iter()
        .zip(embedder.embed(&texts))
        .map(|((port, transport), v)| (port, transport, v))
        .collect()
}

/// `<data dir>/honeypot-rules.toml` when present and valid, else the built-in
/// pack.
pub fn load_honeypot_rules(dir: &Path) -> HoneypotRules {
    let path = dir.join("honeypot-rules.toml");
    match std::fs::read_to_string(&path) {
        Ok(text) => HoneypotRules::parse(&text).unwrap_or_else(|e| {
            warn!(
                "{} invalid ({e:#}); using built-in honeypot rules",
                path.display()
            );
            HoneypotRules::builtin()
        }),
        Err(_) => HoneypotRules::builtin(),
    }
}

/// A scorer over the given rules, with port co-occurrence statistics learned
/// from the current index.
pub fn honeypot_scorer(rules: &HoneypotRules, store: &Store) -> HoneypotScorer {
    let scorer = HoneypotScorer::new(rules.clone());
    match store.tcp_port_sets() {
        Ok(sets) => scorer.with_port_stats(PortStats::from_port_sets(&sets)),
        Err(e) => {
            warn!("port statistics unavailable ({e:#}); skipping port-set signal");
            scorer
        }
    }
}

fn load_geo(dir: &Path) -> Result<GeoAsnDb> {
    let v4 = dir.join("ip2asn-v4.tsv");
    let v6 = dir.join("ip2asn-v6.tsv");
    let v6opt = v6.exists().then_some(v6);
    let db = GeoAsnDb::load(&v4, v6opt.as_deref())?;
    let city = dir.join("dbip-city-lite.csv");
    if city.exists() {
        Ok(db.with_city_db(&city)?)
    } else {
        Ok(db)
    }
}

fn load_vulns(dir: &Path) -> Result<VulnDb> {
    // Any file named nvdcve-*.json in data/ is an NVD feed (JSON 2.0 or the
    // retired 1.1 schema). Files load in name order and later CVE ids win, so
    // 2.0 feeds supersede 1.1 ones and `nvdcve-2.0-modified` comes last.
    let mut paths: Vec<_> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| {
                    let name = p.file_name().unwrap_or_default().to_string_lossy();
                    name.starts_with("nvdcve-") && name.ends_with(".json")
                })
                .collect()
        })
        .unwrap_or_default();
    paths.sort();
    let mut entries = Vec::new();
    for path in &paths {
        let parsed = std::fs::read_to_string(path)
            .map_err(anyhow::Error::from)
            .and_then(|txt| crusade_vuln::load_nvd(&txt));
        match parsed {
            Ok(e) => entries.extend(e),
            Err(e) => warn!("skipping NVD feed {} ({e:#})", path.display()),
        }
    }
    let kev = match std::fs::read_to_string(dir.join("known_exploited_vulnerabilities.json")) {
        Ok(txt) => crusade_vuln::load_kev(&txt)?,
        Err(_) => Default::default(),
    };
    let mut db = VulnDb::from_entries(entries, kev);

    // Exploit cross-reference feeds (best-effort; absent feeds are fine).
    let edb = std::fs::read_to_string(dir.join("files_exploits.csv")).ok();
    let msf = std::fs::read_to_string(dir.join("modules_metadata_base.json")).ok();
    if edb.is_some() || msf.is_some() {
        if let Err(e) = db.load_exploits(edb.as_deref(), msf.as_deref()) {
            warn!("exploit feeds failed to load ({e}); exploit tags disabled");
        }
    }
    Ok(db)
}

/// Probe, enrich, tag and store every discovered host. Returns the hosts.
///
/// `tcp_ports` are probed with the full TCP app-layer stack (banner, fingerprint,
/// TLS/JARM/favicon, SSH); `udp_ports` are probed with the read-only UDP protocol
/// probes. Services from both are merged onto the same host by IP.
pub async fn process(
    tcp_ports: Vec<(IpAddr, u16)>,
    udp_ports: Vec<(IpAddr, u16)>,
    datasets: Arc<Datasets>,
    cfg: &Config,
    store: &mut Store,
    screenshot: bool,
) -> Result<Vec<Host>> {
    // Build the screenshotter once (if enabled). Capture is best-effort and
    // returns None when no Chrome binary is available.
    let shots: Option<crusade_enrich::ChromeScreenshotter> = if screenshot {
        let mut s = crusade_enrich::ChromeScreenshotter::new();
        if let Some(path) = &cfg.screenshot.chrome_path {
            s = s.with_chrome_path(path.clone());
        }
        Some(s)
    } else {
        None
    };
    let screens_dir = cfg.data.dir.join("screens");
    // Group both worklists by host: (tcp ports, udp ports).
    let mut by_host: BTreeMap<IpAddr, (Vec<u16>, Vec<u16>)> = BTreeMap::new();
    for (ip, port) in tcp_ports {
        by_host.entry(ip).or_default().0.push(port);
    }
    for (ip, port) in udp_ports {
        by_host.entry(ip).or_default().1.push(port);
    }

    let probe_cfg = ProbeConfig {
        timeout: cfg.connect_timeout(),
        tls: true,
        sni: None,
    };
    let enrich_cfg = EnrichConfig {
        geo: true,
        reverse_dns: true,
    };
    let timeout = cfg.connect_timeout();
    let honeypot = honeypot_scorer(&datasets.honeypot_rules, store);

    let mut hosts = Vec::new();
    for (ip, (mut tcp, mut udp)) in by_host {
        tcp.sort_unstable();
        tcp.dedup();
        udp.sort_unstable();
        udp.dedup();
        let mut host = Host::new(ip);

        // Probe TCP ports concurrently (full app-layer stack).
        let mut tcp_tasks = Vec::new();
        for port in tcp {
            let ds = datasets.clone();
            let pc = probe_cfg.clone();
            tcp_tasks.push(async move {
                Some(crusade_probe::probe_service(ip, port, &ds.fingerprints, &pc).await)
            });
        }
        // Probe UDP ports concurrently (protocol probes; may yield nothing).
        let mut udp_tasks = Vec::new();
        for port in udp {
            udp_tasks
                .push(async move { crusade_probe::probe_udp_service(ip, port, timeout).await });
        }

        let (tcp_res, udp_res) = futures::join!(
            futures::future::join_all(tcp_tasks),
            futures::future::join_all(udp_tasks)
        );
        host.services = tcp_res.into_iter().chain(udp_res).flatten().collect();

        // Enrich (geo/ASN + reverse DNS), then tag.
        enrich_host(&mut host, &datasets.geo, &enrich_cfg).await;
        datasets.vulns.tag_host(&mut host);
        honeypot.apply(&mut host);

        // Screenshots of web services (best-effort), saved under data/screens.
        if let Some(shotter) = &shots {
            capture_screenshots(&mut host, shotter, &screens_dir).await;
        }

        info!(ip = %ip, services = host.services.len(), tags = host.tags.len(), "host processed");
        store.upsert_host(&host)?;
        if let Some(embedder) = &datasets.embedder {
            let vecs = embed_host(embedder, &host);
            store.set_service_vectors(&ip.to_string(), embedder.name(), &vecs)?;
        }
        hosts.push(host);
    }

    Ok(hosts)
}

/// Capture a screenshot of each web-ish service on the host and record the
/// saved filename on the service. Best-effort: failures are ignored.
async fn capture_screenshots(
    host: &mut Host,
    shotter: &crusade_enrich::ChromeScreenshotter,
    screens_dir: &Path,
) {
    use crusade_core::Transport;
    let ip = host.ip;
    for svc in &mut host.services {
        if svc.transport != Transport::Tcp {
            continue;
        }
        // Treat a service as web if it has HTTP info or sits on a common web port.
        let is_tls = svc.tls.is_some() || matches!(svc.port, 443 | 8443 | 9443);
        let is_web =
            svc.http.is_some() || matches!(svc.port, 80 | 443 | 8080 | 8443 | 8000 | 8888 | 9443);
        if !is_web {
            continue;
        }
        let scheme = if is_tls { "https" } else { "http" };
        let url = format!("{scheme}://{ip}:{}/", svc.port);
        if let Ok(Some(png)) = shotter.capture(&url).await {
            if std::fs::create_dir_all(screens_dir).is_err() {
                continue;
            }
            let file = format!(
                "{}_{}.png",
                ip.to_string().replace([':', '.'], "-"),
                svc.port
            );
            if std::fs::write(screens_dir.join(&file), &png).is_ok() {
                svc.screenshot = Some(file);
            }
        }
    }
}
