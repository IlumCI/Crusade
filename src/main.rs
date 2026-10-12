//! Crusade CLI — a self-hosted, keyless service search engine.
//!
//! Subcommands: `scan`, `sweep`, `search`, `host`, `serve`, `update-data`,
//! `blocklist`. Everything is connect-and-read only and gated by the mandatory
//! blocklist in `crusade-scan`.

mod config;
mod pipeline;
mod update;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use config::Config;
use crusade_core::query;
use crusade_scan::{expand_targets, filter_blocked, parse_masscan_json, parse_zmap_csv, Blocklist, ScanConfig, TcpScanner, RateLimiterParams};
use crusade_store::Store;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Parser)]
#[command(name = "crusade", version, about = "A self-hosted, keyless service search engine")]
struct Cli {
    /// Path to the config file.
    #[arg(long, default_value = "crusade.toml", global = true)]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a target (IP or CIDR), probe open ports, enrich, tag and index.
    Scan {
        /// Target: an IPv4/IPv6 address or CIDR ("192.0.2.0/24", "2001:db8::1").
        target: String,
        /// Override the TCP ports to probe (comma-separated).
        #[arg(long, value_delimiter = ',')]
        ports: Option<Vec<u16>>,
        /// Also run read-only UDP protocol probes.
        #[arg(long)]
        udp: bool,
        /// Also probe common ICS/OT ports (Modbus, S7, EtherNet/IP, DNP3, BACnet).
        #[arg(long)]
        ics: bool,
        /// Override the UDP ports (comma-separated); implies --udp.
        #[arg(long, value_delimiter = ',')]
        udp_ports: Option<Vec<u16>>,
        /// Use masscan for fast TCP discovery instead of the built-in scanner
        /// (needs the `masscan` binary; still honors the blocklist).
        #[arg(long)]
        discovery_masscan: bool,
        /// masscan packets/sec when --discovery-masscan is set.
        #[arg(long, default_value_t = 1000)]
        masscan_rate: u32,
        /// Permit the built-in private/loopback ranges (for your OWN test rig).
        #[arg(long)]
        allow_private: bool,
    },
    /// Ingest masscan/zmap sweep output (sweeps run on a sanctioned VPS, not here).
    Sweep {
        #[command(subcommand)]
        action: SweepAction,
    },
    /// Search the index with a Shodan-style query.
    Search {
        /// The query, e.g. 'port:443 product:nginx country:DE'.
        query: Vec<String>,
        #[arg(long, default_value_t = 25)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// Show everything known about one host.
    Host {
        ip: String,
        #[arg(long)]
        json: bool,
    },
    /// Serve the read-only web UI and JSON API.
    Serve {
        /// Override the bind address (host:port).
        #[arg(long)]
        bind: Option<String>,
    },
    /// Download the free GeoIP/ASN and CVE/KEV datasets into the data dir.
    UpdateData,
    /// Rescan already-known hosts on a schedule and alert on changes
    /// (new ports / new CVEs). A local, Shodan-Monitor-style watch.
    Monitor {
        /// Seconds between passes.
        #[arg(long, default_value_t = 3600)]
        interval: u64,
        /// Only rescan hosts not seen for at least this many seconds.
        #[arg(long, default_value_t = 86400)]
        stale: u64,
        /// Max hosts to rescan per pass.
        #[arg(long, default_value_t = 100)]
        batch: usize,
        /// Run a single pass and exit.
        #[arg(long)]
        once: bool,
        /// Permit private/loopback ranges (for a local test rig).
        #[arg(long)]
        allow_private: bool,
    },
    /// Export matching hosts as JSON Lines (one Host per line) to stdout or a file.
    Export {
        /// Optional query; empty = whole dataset.
        query: Vec<String>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Print a faceted breakdown (top ports/products/countries/ASNs/tags) for a query.
    Stats {
        query: Vec<String>,
        #[arg(long, default_value_t = 15)]
        top: usize,
    },
    /// Manage the opt-out blocklist.
    Blocklist {
        #[command(subcommand)]
        action: BlocklistAction,
    },
}

#[derive(Subcommand)]
enum SweepAction {
    /// Ingest a results file, then probe/enrich/tag/index the discovered hosts.
    Ingest {
        file: PathBuf,
        #[arg(long, value_parser = ["masscan", "zmap"])]
        format: String,
        #[arg(long)]
        allow_private: bool,
    },
}

#[derive(Subcommand)]
enum BlocklistAction {
    /// Add an IP or CIDR to the opt-out list.
    Add { cidr: String },
    /// List the user-supplied opt-out entries.
    List,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "crusade=info,warn".into()),
        )
        .init();

    let cli = Cli::parse();
    let cfg = Config::load(&cli.config).context("loading config")?;

    match cli.command {
        Command::Scan { target, ports, udp, ics, udp_ports, discovery_masscan, masscan_rate, allow_private } => {
            cmd_scan(&cfg, &target, ScanOpts { ports, udp, ics, udp_ports, discovery_masscan, masscan_rate, allow_private }).await
        }
        Command::Sweep { action } => match action {
            SweepAction::Ingest { file, format, allow_private } => {
                cmd_sweep_ingest(&cfg, &file, &format, allow_private).await
            }
        },
        Command::Search { query, limit, json } => cmd_search(&cfg, &query.join(" "), limit, json),
        Command::Host { ip, json } => cmd_host(&cfg, &ip, json),
        Command::Serve { bind } => cmd_serve(&cfg, bind).await,
        Command::UpdateData => update::update_data(&cfg).await,
        Command::Monitor { interval, stale, batch, once, allow_private } => {
            cmd_monitor(&cfg, interval, stale, batch, once, allow_private).await
        }
        Command::Export { query, out } => cmd_export(&cfg, &query.join(" "), out),
        Command::Stats { query, top } => cmd_stats(&cfg, &query.join(" "), top),
        Command::Blocklist { action } => cmd_blocklist(&cfg, action),
    }
}

fn load_blocklist(cfg: &Config, allow_private: bool) -> Result<Blocklist> {
    let path = &cfg.scan.blocklist_path;
    let mut bl = if path.exists() {
        Blocklist::load(path)?
    } else {
        Blocklist::new(allow_private)
    };
    // `Blocklist::load` fixes allow_private=false; rebuild if the operator asked
    // to permit private ranges for their own rig while still honoring the file.
    if allow_private {
        let mut permissive = Blocklist::new(true);
        for net in bl.user_ranges() {
            permissive.add(*net);
        }
        bl = permissive;
    }
    Ok(bl)
}

struct ScanOpts {
    ports: Option<Vec<u16>>,
    udp: bool,
    ics: bool,
    udp_ports: Option<Vec<u16>>,
    discovery_masscan: bool,
    masscan_rate: u32,
    allow_private: bool,
}

async fn cmd_scan(cfg: &Config, target: &str, opts: ScanOpts) -> Result<()> {
    let bl = load_blocklist(cfg, opts.allow_private)?;
    let targets = expand_targets(target, &bl)?;
    if targets.is_empty() {
        println!("No scannable addresses (all blocked/reserved, or empty target).");
        return Ok(());
    }
    let mut tcp_ports = opts.ports.unwrap_or_else(|| cfg.scan.default_ports.clone());
    if opts.ics {
        tcp_ports.extend_from_slice(crusade_probe::ics_ports_tcp());
        tcp_ports.sort_unstable();
        tcp_ports.dedup();
    }
    eprintln!("Scanning {} address(es)…", targets.len());

    // TCP discovery: built-in connect scanner, or the masscan front-end.
    let open = if opts.discovery_masscan {
        let mcfg = crusade_scan::MasscanConfig { rate: opts.masscan_rate, extra_args: vec![] };
        crusade_scan::masscan_discover(&targets, &tcp_ports, &mcfg, &bl)
            .await
            .context("masscan discovery")?
    } else {
        let scan_cfg = ScanConfig {
            ports: tcp_ports,
            connect_timeout: cfg.connect_timeout(),
            rate: RateLimiterParams {
                conn_per_sec: cfg.scan.rate_per_sec,
                burst: cfg.scan.rate_per_sec,
                concurrency: cfg.scan.max_concurrent,
            },
            allow_private: opts.allow_private,
        };
        TcpScanner::new(scan_cfg, bl.clone()).scan(&targets).await
    };
    eprintln!("Found {} open TCP port(s); probing…", open.len());

    // UDP worklist (if --udp, explicit --udp-ports, or ICS UDP ports via --ics).
    let udp = if opts.udp || opts.udp_ports.is_some() || opts.ics {
        let mut uports = opts.udp_ports.unwrap_or_else(|| {
            if opts.udp { crusade_scan::default_udp_ports() } else { Vec::new() }
        });
        if opts.ics {
            uports.extend_from_slice(crusade_probe::ics_ports_udp());
        }
        uports.sort_unstable();
        uports.dedup();
        let wl = crusade_scan::udp_worklist(&targets, &uports, &bl);
        eprintln!("Probing {} UDP (ip,port) pair(s)…", wl.len());
        wl
    } else {
        Vec::new()
    };

    let datasets = Arc::new(pipeline::Datasets::load(cfg)?);
    let mut store = Store::open(&cfg.database.path)?;
    let hosts = pipeline::process(open, udp, datasets, cfg, &mut store).await?;
    println!("Indexed {} host(s). Total in store: {}.", hosts.len(), store.host_count()?);
    Ok(())
}

async fn cmd_sweep_ingest(cfg: &Config, file: &PathBuf, format: &str, allow_private: bool) -> Result<()> {
    let text = std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
    let pairs = match format {
        "masscan" => parse_masscan_json(&text),
        "zmap" => parse_zmap_csv(&text),
        _ => unreachable!("clap restricts format"),
    };
    let bl = load_blocklist(cfg, allow_private)?;
    let pairs = filter_blocked(pairs, &bl);
    eprintln!("Ingested {} open port(s) after blocklist filtering; probing…", pairs.len());

    let datasets = Arc::new(pipeline::Datasets::load(cfg)?);
    let mut store = Store::open(&cfg.database.path)?;
    let hosts = pipeline::process(pairs, Vec::new(), datasets, cfg, &mut store).await?;
    println!("Indexed {} host(s). Total in store: {}.", hosts.len(), store.host_count()?);
    Ok(())
}

fn cmd_search(cfg: &Config, raw: &str, limit: usize, json: bool) -> Result<()> {
    let q = query::parse(raw).map_err(|e| anyhow::anyhow!("{e}"))?;
    let store = Store::open(&cfg.database.path)?;
    let total = store.count(&q)?;
    let hosts = store.search(&q, limit, 0)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&hosts)?);
    } else {
        println!("{total} match(es); showing {}:\n", hosts.len());
        for h in &hosts {
            let ports: Vec<String> = h.services.iter().map(|s| s.port.to_string()).collect();
            let products = h.products().join(", ");
            let loc = h.country.as_deref().unwrap_or("??");
            println!(
                "{:<16} [{}] {:<28} ports: {}",
                h.ip.to_string(),
                loc,
                if products.is_empty() { "-".into() } else { products },
                ports.join(",")
            );
            if !h.tags.is_empty() {
                let tags: Vec<&str> = h.tags.iter().map(|t| t.name.as_str()).collect();
                println!("                 tags: {}", tags.join(", "));
            }
        }
    }
    Ok(())
}

fn cmd_host(cfg: &Config, ip: &str, json: bool) -> Result<()> {
    let _: IpAddr = ip.parse().with_context(|| format!("invalid IP: {ip}"))?;
    let store = Store::open(&cfg.database.path)?;
    match store.get_host(ip)? {
        None => {
            println!("No record for {ip}.");
            Ok(())
        }
        Some(h) => {
            if json {
                println!("{}", serde_json::to_string_pretty(&h)?);
            } else {
                println!("Host {}", h.ip);
                if !h.hostnames.is_empty() {
                    println!("  hostnames: {}", h.hostnames.join(", "));
                }
                if let Some(asn) = h.asn {
                    println!("  asn: AS{asn} {}", h.org.as_deref().unwrap_or(""));
                }
                if let Some(c) = &h.country {
                    println!("  country: {c}");
                }
                for s in &h.services {
                    let prod = s.product.as_deref().unwrap_or("-");
                    let ver = s.version.as_deref().unwrap_or("");
                    println!("  :{:<6} {:<10} {} {}", s.port, s.service.as_deref().unwrap_or("?"), prod, ver);
                    if let Some(b) = &s.banner {
                        let first = b.lines().next().unwrap_or("");
                        println!("          banner: {}", first.chars().take(100).collect::<String>());
                    }
                }
                if !h.tags.is_empty() {
                    println!("  tags:");
                    for t in &h.tags {
                        match &t.cve {
                            Some(cve) => println!("    - {} ({})", t.name, cve),
                            None => println!("    - {}", t.name),
                        }
                    }
                }
            }
            Ok(())
        }
    }
}

async fn cmd_serve(cfg: &Config, bind: Option<String>) -> Result<()> {
    let addr: std::net::SocketAddr = bind
        .unwrap_or_else(|| cfg.web.bind.clone())
        .parse()
        .context("invalid bind address")?;
    let store = Store::open(&cfg.database.path)?;
    let shared = Arc::new(Mutex::new(store));
    println!("Crusade web UI on http://{addr}");
    crusade_web::serve(addr, shared).await
}

async fn cmd_monitor(
    cfg: &Config,
    interval: u64,
    stale: u64,
    batch: usize,
    once: bool,
    allow_private: bool,
) -> Result<()> {
    let datasets = Arc::new(pipeline::Datasets::load(cfg)?);
    let tcp_ports = cfg.scan.default_ports.clone();
    loop {
        let bl = load_blocklist(cfg, allow_private)?;
        let cutoff = time::OffsetDateTime::now_utc().unix_timestamp() - stale as i64;
        let stale_ips = {
            let store = Store::open(&cfg.database.path)?;
            store.stale_host_ips(cutoff, batch)?
        };
        if stale_ips.is_empty() {
            eprintln!("monitor: nothing stale (older than {stale}s).");
        } else {
            eprintln!("monitor: rescanning {} stale host(s)…", stale_ips.len());
        }

        for ip_str in stale_ips {
            let ip: IpAddr = match ip_str.parse() {
                Ok(ip) => ip,
                Err(_) => continue,
            };
            if bl.is_blocked(ip) {
                continue;
            }
            // Snapshot the prior state for diffing.
            let before = {
                let store = Store::open(&cfg.database.path)?;
                store.get_host(&ip_str)?
            };

            let scan_cfg = ScanConfig {
                ports: tcp_ports.clone(),
                connect_timeout: cfg.connect_timeout(),
                rate: RateLimiterParams {
                    conn_per_sec: cfg.scan.rate_per_sec,
                    burst: cfg.scan.rate_per_sec,
                    concurrency: cfg.scan.max_concurrent,
                },
                allow_private,
            };
            let open = TcpScanner::new(scan_cfg, bl.clone()).scan(&[ip]).await;
            let mut store = Store::open(&cfg.database.path)?;
            let hosts = pipeline::process(open, Vec::new(), datasets.clone(), cfg, &mut store).await?;
            if let Some(after) = hosts.into_iter().next() {
                report_changes(before.as_ref(), &after);
            }
        }

        if once {
            return Ok(());
        }
        eprintln!("monitor: sleeping {interval}s…");
        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
    }
}

/// Print a one-line alert for each newly-appeared port or CVE on a host.
fn report_changes(before: Option<&crusade_core::Host>, after: &crusade_core::Host) {
    use std::collections::BTreeSet;
    let old_ports: BTreeSet<u16> =
        before.map(|h| h.services.iter().map(|s| s.port).collect()).unwrap_or_default();
    let new_ports: BTreeSet<u16> = after.services.iter().map(|s| s.port).collect();
    for p in new_ports.difference(&old_ports) {
        println!("[ALERT] {} new open port {}", after.ip, p);
    }

    let old_cves: BTreeSet<&str> = before
        .map(|h| h.tags.iter().filter_map(|t| t.cve.as_deref()).collect())
        .unwrap_or_default();
    for t in &after.tags {
        if let Some(cve) = &t.cve {
            if !old_cves.contains(cve.as_str()) {
                println!("[ALERT] {} new vulnerability {}", after.ip, cve);
            }
        }
    }
}

fn cmd_export(cfg: &Config, raw: &str, out: Option<PathBuf>) -> Result<()> {
    use std::io::Write;
    let q = query::parse(raw).map_err(|e| anyhow::anyhow!("{e}"))?;
    let store = Store::open(&cfg.database.path)?;
    let ips = store.matching_ips(&q)?;
    let mut writer: Box<dyn Write> = match out {
        Some(path) => Box::new(std::io::BufWriter::new(std::fs::File::create(path)?)),
        None => Box::new(std::io::BufWriter::new(std::io::stdout())),
    };
    let mut n = 0u64;
    for ip in ips {
        if let Some(h) = store.get_host(&ip)? {
            serde_json::to_writer(&mut writer, &h)?;
            writer.write_all(b"\n")?;
            n += 1;
        }
    }
    writer.flush()?;
    eprintln!("Exported {n} host(s).");
    Ok(())
}

fn cmd_stats(cfg: &Config, raw: &str, top: usize) -> Result<()> {
    let q = query::parse(raw).map_err(|e| anyhow::anyhow!("{e}"))?;
    let store = Store::open(&cfg.database.path)?;
    let total = store.count(&q)?;
    let facets = store.facets_for_query(&q, top)?;
    println!("Stats for {:?} — {total} host(s)\n", if raw.is_empty() { "*" } else { raw });
    print_facet("Top ports", &facets.ports);
    print_facet("Top products", &facets.products);
    print_facet("Top countries", &facets.countries);
    print_facet("Top ASNs", &facets.asns);
    print_facet("Top tags", &facets.tags);
    Ok(())
}

fn print_facet(title: &str, rows: &[crusade_store::Facet]) {
    if rows.is_empty() {
        return;
    }
    println!("{title}:");
    for r in rows {
        println!("  {:>8}  {}", r.count, r.value);
    }
    println!();
}

fn cmd_blocklist(cfg: &Config, action: BlocklistAction) -> Result<()> {
    let path = &cfg.scan.blocklist_path;
    match action {
        BlocklistAction::Add { cidr } => {
            let net: ipnet::IpNet = cidr
                .parse()
                .or_else(|_| cidr.parse::<IpAddr>().map(|ip| ip.into()))
                .with_context(|| format!("invalid CIDR/IP: {cidr}"))?;
            let mut bl = if path.exists() { Blocklist::load(path)? } else { Blocklist::new(false) };
            bl.add(net);
            bl.save(path)?;
            println!("Added {net} to {}.", path.display());
            Ok(())
        }
        BlocklistAction::List => {
            let bl = if path.exists() { Blocklist::load(path)? } else { Blocklist::new(false) };
            if bl.user_ranges().is_empty() {
                println!("(no user entries; built-in reserved/private ranges are always blocked)");
            } else {
                for net in bl.user_ranges() {
                    println!("{net}");
                }
            }
            Ok(())
        }
    }
}
