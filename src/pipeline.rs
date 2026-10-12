//! The scan → probe → enrich → vuln-tag → store pipeline.
//!
//! Given a set of discovered `(ip, open_port)` pairs, this groups them by host,
//! probes every open port for a banner/fingerprint/cert, enriches the host with
//! geo/ASN and reverse DNS, applies vulnerability and heuristic tags, and
//! upserts the result into the store.

use crate::config::Config;
use anyhow::Result;
use crusade_core::model::Host;
use crusade_enrich::{enrich_host, EnrichConfig, GeoAsnDb};
use crusade_probe::{Fingerprints, ProbeConfig};
use crusade_store::Store;
use crusade_vuln::VulnDb;
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
}

impl Datasets {
    /// Load fingerprints (required), plus geo/ASN and CVE feeds (best-effort:
    /// missing feeds degrade gracefully rather than failing the scan).
    pub fn load(cfg: &Config) -> Result<Datasets> {
        let fingerprints = Fingerprints::load(&cfg.data.nmap_probes)
            .unwrap_or_else(|e| {
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

        Ok(Datasets { fingerprints, geo, vulns })
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
    // Any file named nvdcve-*.json in data/ is treated as an NVD 1.1 feed.
    let mut nvd = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("nvdcve-") && name.ends_with(".json") {
                if let Ok(txt) = std::fs::read_to_string(entry.path()) {
                    nvd.push(txt);
                }
            }
        }
    }
    let kev_path = dir.join("known_exploited_vulnerabilities.json");
    let kev = std::fs::read_to_string(&kev_path).ok();
    VulnDb::from_feeds(&nvd, kev.as_deref())
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
) -> Result<Vec<Host>> {
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
    let enrich_cfg = EnrichConfig { geo: true, reverse_dns: true };
    let timeout = cfg.connect_timeout();

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
            udp_tasks.push(async move { crusade_probe::probe_udp_service(ip, port, timeout).await });
        }

        let (tcp_res, udp_res) =
            futures::join!(futures::future::join_all(tcp_tasks), futures::future::join_all(udp_tasks));
        host.services = tcp_res.into_iter().chain(udp_res).flatten().collect();

        // Enrich (geo/ASN + reverse DNS), then tag.
        enrich_host(&mut host, &datasets.geo, &enrich_cfg).await;
        datasets.vulns.tag_host(&mut host);

        info!(ip = %ip, services = host.services.len(), tags = host.tags.len(), "host processed");
        store.upsert_host(&host)?;
        hosts.push(host);
    }

    Ok(hosts)
}
