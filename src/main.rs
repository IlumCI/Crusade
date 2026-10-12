//! Crusade CLI — a self-hosted, keyless service search engine.
//!
//! Subcommands: `scan`, `sweep`, `search`, `host`, `serve`, `update-data`,
//! `blocklist`. Everything is connect-and-read only and gated by the mandatory
//! blocklist in `crusade-scan`.

mod alert;
mod archive;
mod config;
mod pipeline;
mod update;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use config::Config;
use crusade_core::query;
use crusade_scan::{
    expand_targets, filter_blocked, parse_masscan_json, parse_zmap_csv, Blocklist,
    RateLimiterParams, ScanConfig, TcpScanner,
};
use crusade_store::Store;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Parser)]
#[command(
    name = "crusade",
    version,
    about = "A self-hosted, keyless service search engine"
)]
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
        /// Capture a screenshot of web services (needs a Chrome binary).
        #[arg(long)]
        screenshot: bool,
        /// Override the UDP ports (comma-separated); implies --udp.
        #[arg(long, value_delimiter = ',')]
        udp_ports: Option<Vec<u16>>,
        /// Use masscan for fast TCP discovery instead of the built-in scanner
        /// (needs the `masscan` binary; still honors the blocklist).
        #[arg(long)]
        discovery_masscan: bool,
        /// Use the built-in stateless SYN scanner for discovery: one bare SYN
        /// per port, no handshake, ~500x the connect scanner against hosts
        /// that do not answer. Needs CAP_NET_RAW and IPv4 targets.
        #[arg(long, conflicts_with = "discovery_masscan")]
        discovery_syn: bool,
        /// SYN probes/sec when --discovery-syn is set.
        #[arg(long, default_value_t = 20_000.0)]
        syn_rate: f64,
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
    /// List recent alerts, or send a test alert through configured transports.
    Alerts {
        #[arg(long, default_value_t = 20)]
        limit: usize,
        /// Record + dispatch a synthetic alert to verify webhook/email config.
        #[arg(long)]
        test: bool,
    },
    /// Manage the opt-out blocklist.
    Blocklist {
        #[command(subcommand)]
        action: BlocklistAction,
    },
    /// Add a scan job to the shared queue (for `crusade worker` to process).
    Enqueue {
        /// Target: an IP or CIDR. Repeatable, or use --file.
        targets: Vec<String>,
        /// Read targets (one per line) from a file.
        #[arg(long)]
        file: Option<PathBuf>,
        #[arg(long, value_delimiter = ',')]
        ports: Option<Vec<u16>>,
        #[arg(long)]
        udp: bool,
        #[arg(long)]
        ics: bool,
    },
    /// Pull jobs from the queue and scan them. Run many for scale-out.
    Worker {
        /// Worker id recorded on claimed jobs (default: hostname-pid).
        #[arg(long)]
        id: Option<String>,
        /// Process the queue until empty, then exit.
        #[arg(long)]
        once: bool,
        /// Seconds to wait when the queue is empty before polling again.
        #[arg(long, default_value_t = 10)]
        poll: u64,
        /// Permit private/loopback ranges (for your own rig).
        #[arg(long)]
        allow_private: bool,
    },
    /// Find services similar in meaning to a text, or to an indexed service.
    /// Needs the embedding model (`update-data`) and embedded services.
    Similar {
        /// Free text, e.g. "router admin login page".
        text: Vec<String>,
        /// Use this indexed service as the query: IP:PORT or IP:PORT/udp.
        #[arg(long)]
        like: Option<String>,
        /// Restrict to hosts matching this Crusade query.
        #[arg(long)]
        filter: Option<String>,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// Compute embedding vectors for indexed services (backfill; no network).
    Embed {
        /// Optional query; empty = whole index.
        query: Vec<String>,
    },
    /// Recompute honeypot scores for indexed hosts (no network traffic).
    /// Run after editing `<data dir>/honeypot-rules.toml` or as the index grows.
    Rescore {
        /// Optional query; empty = whole index.
        query: Vec<String>,
    },
    /// Archive and delete data that is old and has never been looked at,
    /// then reclaim the space. Writes a gzipped JSONL archive first.
    Archive {
        /// Report what would be removed without touching anything.
        #[arg(long)]
        dry_run: bool,
        /// Show where the space is going and stop.
        #[arg(long)]
        status: bool,
    },
    /// Show scan-queue status (counts + recent jobs).
    Jobs {
        #[arg(long, default_value_t = 20)]
        limit: usize,
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
        Command::Scan {
            target,
            ports,
            udp,
            ics,
            screenshot,
            udp_ports,
            discovery_masscan,
            masscan_rate,
            discovery_syn,
            syn_rate,
            allow_private,
        } => {
            cmd_scan(
                &cfg,
                &target,
                ScanOpts {
                    ports,
                    udp,
                    ics,
                    screenshot,
                    udp_ports,
                    discovery_masscan,
                    masscan_rate,
                    discovery_syn,
                    syn_rate,
                    allow_private,
                },
            )
            .await
        }
        Command::Sweep { action } => match action {
            SweepAction::Ingest {
                file,
                format,
                allow_private,
            } => cmd_sweep_ingest(&cfg, &file, &format, allow_private).await,
        },
        Command::Search { query, limit, json } => cmd_search(&cfg, &query.join(" "), limit, json),
        Command::Host { ip, json } => cmd_host(&cfg, &ip, json),
        Command::Serve { bind } => cmd_serve(&cfg, bind).await,
        Command::UpdateData => update::update_data(&cfg).await,
        Command::Monitor {
            interval,
            stale,
            batch,
            once,
            allow_private,
        } => cmd_monitor(&cfg, interval, stale, batch, once, allow_private).await,
        Command::Export { query, out } => cmd_export(&cfg, &query.join(" "), out),
        Command::Stats { query, top } => cmd_stats(&cfg, &query.join(" "), top),
        Command::Alerts { limit, test } => cmd_alerts(&cfg, limit, test).await,
        Command::Blocklist { action } => cmd_blocklist(&cfg, action),
        Command::Enqueue {
            targets,
            file,
            ports,
            udp,
            ics,
        } => cmd_enqueue(&cfg, targets, file, ports, udp, ics),
        Command::Worker {
            id,
            once,
            poll,
            allow_private,
        } => cmd_worker(&cfg, id, once, poll, allow_private).await,
        Command::Jobs { limit } => cmd_jobs(&cfg, limit),
        Command::Archive { dry_run, status } => cmd_archive(&cfg, dry_run, status),
        Command::Rescore { query } => cmd_rescore(&cfg, &query.join(" ")),
        Command::Similar {
            text,
            like,
            filter,
            limit,
            json,
        } => cmd_similar(&cfg, &text.join(" "), like, filter, limit, json),
        Command::Embed { query } => cmd_embed(&cfg, &query.join(" ")),
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
    screenshot: bool,
    udp_ports: Option<Vec<u16>>,
    discovery_masscan: bool,
    masscan_rate: u32,
    discovery_syn: bool,
    syn_rate: f64,
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

    // TCP discovery: stateless SYN, the masscan front-end, or the built-in
    // connect scanner.
    let open = if opts.discovery_syn {
        syn_discover(&targets, &tcp_ports, opts.syn_rate, &bl, opts.allow_private).await?
    } else if opts.discovery_masscan {
        let mcfg = crusade_scan::MasscanConfig {
            rate: opts.masscan_rate,
            extra_args: vec![],
        };
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
            if opts.udp {
                crusade_scan::default_udp_ports()
            } else {
                Vec::new()
            }
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
    let hosts = pipeline::process(
        open,
        udp,
        datasets,
        cfg,
        &mut store,
        opts.screenshot || cfg.screenshot.enabled,
    )
    .await?;
    report_auto_archive(cfg, &mut store);
    println!(
        "Indexed {} host(s). Total in store: {}.",
        hosts.len(),
        store.host_count()?
    );
    Ok(())
}

/// Scan one target with pre-loaded datasets/store. Shared by `scan` and the
/// job `worker`. Returns the number of hosts indexed.
async fn run_scan_once(
    cfg: &Config,
    target: &str,
    opts: &ScanOpts,
    datasets: Arc<pipeline::Datasets>,
    store: &mut Store,
) -> Result<usize> {
    let bl = load_blocklist(cfg, opts.allow_private)?;
    let targets = expand_targets(target, &bl)?;
    if targets.is_empty() {
        return Ok(0);
    }
    let mut tcp_ports = opts
        .ports
        .clone()
        .unwrap_or_else(|| cfg.scan.default_ports.clone());
    if opts.ics {
        tcp_ports.extend_from_slice(crusade_probe::ics_ports_tcp());
        tcp_ports.sort_unstable();
        tcp_ports.dedup();
    }
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
    let open = TcpScanner::new(scan_cfg, bl.clone()).scan(&targets).await;

    let udp = if opts.udp || opts.ics {
        let mut uports = if opts.udp {
            crusade_scan::default_udp_ports()
        } else {
            Vec::new()
        };
        if opts.ics {
            uports.extend_from_slice(crusade_probe::ics_ports_udp());
        }
        uports.sort_unstable();
        uports.dedup();
        crusade_scan::udp_worklist(&targets, &uports, &bl)
    } else {
        Vec::new()
    };

    let hosts = pipeline::process(
        open,
        udp,
        datasets,
        cfg,
        store,
        opts.screenshot || cfg.screenshot.enabled,
    )
    .await?;
    Ok(hosts.len())
}

/// Stateless SYN discovery, falling back to nothing: the caller gets a clear
/// error rather than a silent slow path, since the two engines differ by
/// orders of magnitude and a silent downgrade would be misleading.
async fn syn_discover(
    targets: &[IpAddr],
    ports: &[u16],
    rate: f64,
    bl: &Blocklist,
    allow_private: bool,
) -> Result<Vec<(IpAddr, u16)>> {
    let v4: Vec<std::net::Ipv4Addr> = targets
        .iter()
        .filter_map(|ip| match ip {
            IpAddr::V4(a) => Some(*a),
            IpAddr::V6(_) => None,
        })
        .collect();
    let skipped = targets.len() - v4.len();
    if skipped > 0 {
        eprintln!("--discovery-syn is IPv4-only; skipping {skipped} IPv6 target(s)");
    }
    if v4.is_empty() {
        return Ok(Vec::new());
    }
    let cfg = crusade_scan::SynConfig {
        rate: RateLimiterParams {
            conn_per_sec: rate,
            burst: rate,
            concurrency: 1,
        },
        allow_private,
        ..Default::default()
    };
    let scanner = crusade_scan::SynScanner::new(cfg, bl.clone()).context(
        "opening raw sockets for --discovery-syn (needs CAP_NET_RAW: run as root or \
         grant it with `setcap cap_net_raw+ep $(which crusade)`)",
    )?;
    eprintln!(
        "SYN discovery: {} address(es) x {} port(s) at {rate:.0}/s",
        v4.len(),
        ports.len()
    );
    Ok(scanner.scan(&v4, ports).await?)
}

async fn cmd_sweep_ingest(
    cfg: &Config,
    file: &PathBuf,
    format: &str,
    allow_private: bool,
) -> Result<()> {
    let text =
        std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
    let pairs = match format {
        "masscan" => parse_masscan_json(&text),
        "zmap" => parse_zmap_csv(&text),
        _ => unreachable!("clap restricts format"),
    };
    let bl = load_blocklist(cfg, allow_private)?;
    let pairs = filter_blocked(pairs, &bl);
    eprintln!(
        "Ingested {} open port(s) after blocklist filtering; probing…",
        pairs.len()
    );

    let datasets = Arc::new(pipeline::Datasets::load(cfg)?);
    let mut store = Store::open(&cfg.database.path)?;
    let hosts = pipeline::process(
        pairs,
        Vec::new(),
        datasets,
        cfg,
        &mut store,
        cfg.screenshot.enabled,
    )
    .await?;
    report_auto_archive(cfg, &mut store);
    println!(
        "Indexed {} host(s). Total in store: {}.",
        hosts.len(),
        store.host_count()?
    );
    Ok(())
}

fn cmd_search(cfg: &Config, raw: &str, limit: usize, json: bool) -> Result<()> {
    let q = query::parse(raw).map_err(|e| anyhow::anyhow!("{e}"))?;
    let store = Store::open(&cfg.database.path)?;
    let total = store.count(&q)?;
    let hosts = store.search(&q, limit, 0)?;
    // Surfacing a host in results counts as using it: retention then keeps the
    // hosts people actually look at, however old they are.
    store.touch_hosts(&hosts.iter().map(|h| h.ip.to_string()).collect::<Vec<_>>());
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
                if products.is_empty() {
                    "-".into()
                } else {
                    products
                },
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
            // Viewing a host counts as using it, which keeps it out of the
            // archive selection.
            store.touch_hosts(&[h.ip.to_string()]);
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
                    println!(
                        "  :{:<6} {:<10} {} {}",
                        s.port,
                        s.service.as_deref().unwrap_or("?"),
                        prod,
                        ver
                    );
                    if let Some(b) = &s.banner {
                        let first = b.lines().next().unwrap_or("");
                        println!(
                            "          banner: {}",
                            first.chars().take(100).collect::<String>()
                        );
                    }
                }
                let pending: Vec<String> = h
                    .services
                    .iter()
                    .filter(|s| s.pending_since.is_some())
                    .map(|s| {
                        format!(
                            "{}/{}",
                            s.port,
                            match s.transport {
                                crusade_core::Transport::Tcp => "tcp",
                                crusade_core::Transport::Udp => "udp",
                            }
                        )
                    })
                    .collect();
                if !pending.is_empty() {
                    println!("  pending eviction: {}", pending.join(", "));
                }
                if let Some(a) = &h.honeypot {
                    println!("  honeypot score: {:.0}%", a.score * 100.0);
                    for e in &a.evidence {
                        println!(
                            "    - {} ({:.0}%): {}",
                            e.signal,
                            e.weight * 100.0,
                            e.detail
                        );
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
    let screens = cfg.data.dir.join("screens");
    // Semantic similarity is served only when the model is installed.
    let embedder = pipeline::load_embedder(&cfg.data.dir).map(Arc::new);
    if embedder.is_none() {
        eprintln!("(no embedding model; /similar disabled — run `crusade update-data`)");
    }
    println!("Crusade web UI on http://{addr}");
    crusade_web::serve_with_embedder(addr, shared, Some(screens), embedder).await
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

            // Rescan the default ports *and* every port already known on this
            // host, so a service that has gone away is actually re-probed and
            // can move through pending to eviction.
            let mut ports = tcp_ports.clone();
            let mut udp_ports: Vec<u16> = Vec::new();
            if let Some(h) = &before {
                for svc in &h.services {
                    match svc.transport {
                        crusade_core::Transport::Tcp => ports.push(svc.port),
                        crusade_core::Transport::Udp => udp_ports.push(svc.port),
                    }
                }
            }
            ports.sort_unstable();
            ports.dedup();
            udp_ports.sort_unstable();
            udp_ports.dedup();
            let udp = crusade_scan::udp_worklist(&[ip], &udp_ports, &bl);
            let scope = std::collections::BTreeMap::from([(
                ip,
                crusade_core::lifecycle::Scope::new(
                    ports.iter().copied(),
                    udp_ports.iter().copied(),
                ),
            )]);

            let scan_cfg = ScanConfig {
                ports,
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
            let hosts = pipeline::process_scoped(
                open,
                udp,
                scope,
                datasets.clone(),
                cfg,
                &mut store,
                cfg.screenshot.enabled,
            )
            .await?;
            if let Some(after) = hosts.into_iter().next() {
                record_changes(&store, before.as_ref(), &after)?;
            }
        }

        // Deliver anything newly recorded through configured transports.
        {
            let store = Store::open(&cfg.database.path)?;
            alert::flush_undelivered(cfg, &store).await?;
        }

        // A monitor runs indefinitely, so it is the natural place to enforce
        // the size limit: once per pass, after alerts have been delivered (an
        // undelivered alert holds its host back from archiving).
        {
            let mut store = Store::open(&cfg.database.path)?;
            report_auto_archive(cfg, &mut store);
        }

        if once {
            return Ok(());
        }
        eprintln!("monitor: sleeping {interval}s…");
        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
    }
}

/// Record an alert for each newly-appeared port, CVE, or exposure on a host.
/// Alerts are persisted (and echoed to the console); delivery happens later.
fn record_changes(
    store: &Store,
    before: Option<&crusade_core::Host>,
    after: &crusade_core::Host,
) -> Result<()> {
    use std::collections::BTreeSet;
    let ip = after.ip.to_string();

    let old_ports: BTreeSet<u16> = before
        .map(|h| h.services.iter().map(|s| s.port).collect())
        .unwrap_or_default();
    let new_ports: BTreeSet<u16> = after.services.iter().map(|s| s.port).collect();
    for p in new_ports.difference(&old_ports) {
        let detail = format!("new open port {p}");
        println!("[ALERT] {ip} {detail}");
        store.record_alert(&ip, "new-port", &detail)?;
    }

    for p in old_ports.difference(&new_ports) {
        let detail = format!("port {p} no longer listening (evicted)");
        println!("[ALERT] {ip} {detail}");
        store.record_alert(&ip, "service-gone", &detail)?;
    }

    let old_cves: BTreeSet<&str> = before
        .map(|h| h.tags.iter().filter_map(|t| t.cve.as_deref()).collect())
        .unwrap_or_default();
    for t in &after.tags {
        if let Some(cve) = &t.cve {
            if !old_cves.contains(cve.as_str()) {
                let detail = format!("new vulnerability {cve}");
                println!("[ALERT] {ip} {detail}");
                store.record_alert(&ip, "new-vuln", &detail)?;
            }
        }
    }

    // New unauthenticated exposure (auth:open sensitive service) is alert-worthy.
    let old_exposed = before.map(host_is_exposed).unwrap_or(false);
    if !old_exposed && host_is_exposed(after) {
        let detail = "unauthenticated exposure detected".to_string();
        println!("[ALERT] {ip} {detail}");
        store.record_alert(&ip, "new-exposure", &detail)?;
    }
    Ok(())
}

fn host_is_exposed(h: &crusade_core::Host) -> bool {
    h.tags.iter().any(|t| t.name == "unauthenticated-access")
}

async fn cmd_alerts(cfg: &Config, limit: usize, test: bool) -> Result<()> {
    let store = Store::open(&cfg.database.path)?;
    if test {
        store.record_alert("0.0.0.0", "test", "crusade alert transport test")?;
        alert::flush_undelivered(cfg, &store).await?;
        let transports = cfg.alert.webhooks.len() + usize::from(cfg.alert.smtp_host.is_some());
        println!("Recorded a test alert and flushed. Configured transports: {transports}.");
        return Ok(());
    }
    let alerts = store.recent_alerts(limit)?;
    if alerts.is_empty() {
        println!("No alerts recorded yet. Run `crusade monitor` to generate them.");
        return Ok(());
    }
    for a in alerts {
        let when = time::OffsetDateTime::from_unix_timestamp(a.ts)
            .map(|t| t.to_string())
            .unwrap_or_else(|_| a.ts.to_string());
        let mark = if a.delivered { "✓" } else { "·" };
        println!("{mark} {when}  {:<13} {:<16} {}", a.kind, a.ip, a.detail);
    }
    Ok(())
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

/// Parse `IP:PORT`, `IP:PORT/udp`, `[v6]:PORT` into (ip, port, transport).
fn parse_service_ref(s: &str) -> Result<(String, u16, String)> {
    let (addr, transport) = match s.rsplit_once('/') {
        Some((a, t)) if t == "tcp" || t == "udp" => (a, t.to_string()),
        _ => (s, "tcp".to_string()),
    };
    let sock: std::net::SocketAddr = addr
        .parse()
        .with_context(|| format!("expected IP:PORT (or [IPv6]:PORT), got {addr:?}"))?;
    Ok((sock.ip().to_string(), sock.port(), transport))
}

fn cmd_similar(
    cfg: &Config,
    text: &str,
    like: Option<String>,
    filter: Option<String>,
    limit: usize,
    json: bool,
) -> Result<()> {
    let embedder = pipeline::load_embedder(&cfg.data.dir)
        .context("no embedding model installed; run `crusade update-data`")?;
    let store = Store::open(&cfg.database.path)?;
    let model = embedder.name().to_string();
    let query_vec = match &like {
        Some(r) => {
            let (ip, port, transport) = parse_service_ref(r)?;
            store
                .service_vector(&model, &ip, port, &transport)?
                .with_context(|| format!("no vector for {r}; run `crusade embed`"))?
        }
        None if !text.trim().is_empty() => embedder.embed_one(text),
        None => anyhow::bail!("give a text or --like IP:PORT"),
    };
    let restrict = filter
        .as_deref()
        .map(query::parse)
        .transpose()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let hits = store.similar_services(&model, &query_vec, restrict.as_ref(), limit)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&hits)?);
        return Ok(());
    }
    if hits.is_empty() {
        println!(
            "No embedded services ({} vectors indexed).",
            store.vector_count(&model)?
        );
    }
    for h in hits {
        let svc = store.get_host(&h.ip)?.and_then(|host| {
            host.services
                .into_iter()
                .find(|s| s.port == h.port)
                .and_then(|s| crusade_embed::service_text(&s))
        });
        let mut text = svc
            .unwrap_or_default()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        if text.chars().count() > 90 {
            text = text.chars().take(89).collect::<String>() + "…";
        }
        let addr = std::net::SocketAddr::new(h.ip.parse()?, h.port);
        println!(
            "{:.3}  {:<28} {}",
            h.score,
            format!("{addr}/{}", h.transport),
            text
        );
    }
    Ok(())
}

fn cmd_embed(cfg: &Config, raw: &str) -> Result<()> {
    let q = query::parse(raw).map_err(|e| anyhow::anyhow!("{e}"))?;
    let embedder = pipeline::load_embedder(&cfg.data.dir)
        .context("no embedding model installed; run `crusade update-data`")?;
    let mut store = Store::open(&cfg.database.path)?;
    let (mut hosts, mut vectors) = (0u64, 0usize);
    let started = std::time::Instant::now();
    for ip in store.matching_ips(&q)? {
        if let Some(h) = store.get_host(&ip)? {
            let vecs = pipeline::embed_host(&embedder, &h);
            vectors += vecs.len();
            store.set_service_vectors(&ip, embedder.name(), &vecs)?;
            hosts += 1;
        }
    }
    println!(
        "Embedded {vectors} service(s) on {hosts} host(s) in {:.2}s with {}.",
        started.elapsed().as_secs_f64(),
        embedder.name()
    );
    Ok(())
}

fn cmd_archive(cfg: &Config, dry_run: bool, status: bool) -> Result<()> {
    use archive::human_bytes;
    let mut store = Store::open(&cfg.database.path)?;

    if status {
        let r = store.storage_report()?;
        println!(
            "database {}  (allocated {}, reusable {})",
            human_bytes(r.file_bytes),
            human_bytes(r.allocated_bytes),
            human_bytes(r.free_bytes)
        );
        println!(
            "{} hosts, {} services, {} history entries, {} alerts; {} hosts never viewed",
            r.hosts, r.services, r.history_rows, r.alerts, r.never_accessed
        );
        match cfg.archive.max_db_bytes() {
            Some(limit) => println!(
                "auto-archive at {} ({}% used)",
                human_bytes(limit),
                (r.file_bytes as f64 / limit as f64 * 100.0).round()
            ),
            None => println!("auto-archive off (set [archive] max_db_mb to enable)"),
        }
        println!("\nlargest tables and indexes:");
        for t in r.tables.iter().take(12) {
            let rows = if t.rows > 0 {
                format!("{} rows", t.rows)
            } else {
                "-".to_string()
            };
            println!("  {:<24} {:>10}  {rows}", t.name, human_bytes(t.bytes));
        }
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let eligible = store
            .archivable_hosts(now, &archive::retention(cfg), usize::MAX)?
            .len();
        println!("\n{eligible} host(s) currently eligible for archiving");
        return Ok(());
    }

    let out = archive::run(cfg, &mut store, dry_run)?;
    if dry_run {
        println!(
            "Would archive {} host(s) and prune expired history/alerts/jobs. \
             Nothing was changed.",
            out.hosts_archived
        );
        return Ok(());
    }
    if !out.removed_anything() {
        println!("Nothing to archive: everything is within its retention window.");
        return Ok(());
    }
    println!(
        "Archived {} host(s) to {} file(s); pruned {} history, {} alert(s), {} job(s); \
         removed {} orphaned screenshot(s).",
        out.hosts_archived,
        out.files.len(),
        out.pruned.history_rows,
        out.pruned.alerts,
        out.pruned.jobs,
        out.screenshots_removed
    );
    for f in &out.files {
        println!("  → {}", f.display());
    }
    println!(
        "Database {} → {} ({} reclaimed{}).",
        human_bytes(out.bytes_before),
        human_bytes(out.bytes_after),
        human_bytes(out.reclaimed()),
        if out.vacuumed { "" } else { ", not vacuumed" }
    );
    Ok(())
}

/// Run automatic archiving if the database is over its configured limit, and
/// say so when it does something. Never fails the caller's command.
fn report_auto_archive(cfg: &Config, store: &mut Store) {
    match archive::auto_archive(cfg, store) {
        Ok(Some(out)) => {
            eprintln!(
                "auto-archive: {} host(s) archived, {} row(s) pruned, {} reclaimed ({} → {}){}",
                out.hosts_archived,
                out.pruned.total(),
                archive::human_bytes(out.reclaimed()),
                archive::human_bytes(out.bytes_before),
                archive::human_bytes(out.bytes_after),
                if out.hit_batch_limit {
                    "; stopped at the batch limit, run `crusade archive` to continue"
                } else {
                    ""
                }
            );
        }
        Ok(None) => {}
        Err(e) => eprintln!("auto-archive skipped: {e:#}"),
    }
}

fn cmd_rescore(cfg: &Config, raw: &str) -> Result<()> {
    let q = query::parse(raw).map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut store = Store::open(&cfg.database.path)?;
    let rules = pipeline::load_honeypot_rules(&cfg.data.dir);
    let scorer = pipeline::honeypot_scorer(&rules, &store);
    let (mut n, mut flagged) = (0u64, 0u64);
    for ip in store.matching_ips(&q)? {
        if let Some(mut h) = store.get_host(&ip)? {
            scorer.apply(&mut h);
            if h.honeypot
                .as_ref()
                .is_some_and(|a| a.score >= crusade_vuln::HONEYPOT_TAG_THRESHOLD)
            {
                flagged += 1;
            }
            store.update_derived(&h)?;
            n += 1;
        }
    }
    println!(
        "Rescored {n} host(s) with {} rule(s); {flagged} at or above the honeypot threshold.",
        rules.len()
    );
    Ok(())
}

fn cmd_stats(cfg: &Config, raw: &str, top: usize) -> Result<()> {
    let q = query::parse(raw).map_err(|e| anyhow::anyhow!("{e}"))?;
    let store = Store::open(&cfg.database.path)?;
    let total = store.count(&q)?;
    // Cached: faceting the whole index is a full scan, and `stats` is the
    // command most likely to be run repeatedly against an unchanged dataset.
    let facets = store.facets_cached(&q, top)?;
    println!(
        "Stats for {:?} — {total} host(s)\n",
        if raw.is_empty() { "*" } else { raw }
    );
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

fn ports_csv(ports: &Option<Vec<u16>>) -> Option<String> {
    ports.as_ref().map(|p| {
        p.iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(",")
    })
}

fn cmd_enqueue(
    cfg: &Config,
    mut targets: Vec<String>,
    file: Option<PathBuf>,
    ports: Option<Vec<u16>>,
    udp: bool,
    ics: bool,
) -> Result<()> {
    if let Some(path) = file {
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        targets.extend(
            text.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(String::from),
        );
    }
    if targets.is_empty() {
        anyhow::bail!("no targets given (pass targets or --file)");
    }
    let csv = ports_csv(&ports);
    let store = Store::open(&cfg.database.path)?;
    let mut n = 0;
    for t in targets {
        store.enqueue_job(&t, csv.as_deref(), udp, ics)?;
        n += 1;
    }
    println!("Enqueued {n} job(s).");
    Ok(())
}

async fn cmd_worker(
    cfg: &Config,
    id: Option<String>,
    once: bool,
    poll: u64,
    allow_private: bool,
) -> Result<()> {
    let worker_id = id.unwrap_or_else(|| {
        let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "worker".into());
        format!("{host}-{}", std::process::id())
    });
    eprintln!("worker {worker_id} starting (poll {poll}s, once={once})…");
    let datasets = Arc::new(pipeline::Datasets::load(cfg)?);
    loop {
        // Claim one job (own short-lived connection for the atomic claim).
        let job = {
            let mut store = Store::open(&cfg.database.path)?;
            store.claim_next_job(&worker_id)?
        };
        let Some(job) = job else {
            if once {
                eprintln!("worker {worker_id}: queue empty, exiting.");
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_secs(poll)).await;
            continue;
        };

        let ports = job.ports.as_ref().map(|csv| {
            csv.split(',')
                .filter_map(|x| x.trim().parse::<u16>().ok())
                .collect::<Vec<_>>()
        });
        let opts = ScanOpts {
            ports,
            udp: job.udp,
            ics: job.ics,
            screenshot: cfg.screenshot.enabled,
            udp_ports: None,
            discovery_masscan: false,
            masscan_rate: 1000,
            // Workers use the connect scanner: they are meant to run several
            // to a host, and raw sockets need a capability a worker may lack.
            discovery_syn: false,
            syn_rate: 20_000.0,
            allow_private,
        };
        eprintln!("worker {worker_id}: job {} → {}", job.id, job.target);
        let mut store = Store::open(&cfg.database.path)?;
        match run_scan_once(cfg, &job.target, &opts, datasets.clone(), &mut store).await {
            Ok(n) => {
                store.finish_job(job.id, true, &format!("{n} host(s) indexed"))?;
                println!("job {} done: {n} host(s)", job.id);
            }
            Err(e) => {
                store.finish_job(job.id, false, &format!("{e}"))?;
                eprintln!("job {} failed: {e}", job.id);
            }
        }
    }
}

fn cmd_jobs(cfg: &Config, limit: usize) -> Result<()> {
    let store = Store::open(&cfg.database.path)?;
    let (p, r, d, f) = store.job_counts()?;
    println!("Jobs — pending {p}, running {r}, done {d}, failed {f}\n");
    for j in store.recent_jobs(limit)? {
        let flags = format!(
            "{}{}",
            if j.udp { "u" } else { "-" },
            if j.ics { "i" } else { "-" }
        );
        println!(
            "#{:<5} {:<9} [{}] {:<22} {}",
            j.id,
            j.status,
            flags,
            j.target,
            j.note.as_deref().unwrap_or("")
        );
    }
    Ok(())
}

fn cmd_blocklist(cfg: &Config, action: BlocklistAction) -> Result<()> {
    let path = &cfg.scan.blocklist_path;
    match action {
        BlocklistAction::Add { cidr } => {
            let net: ipnet::IpNet = cidr
                .parse()
                .or_else(|_| cidr.parse::<IpAddr>().map(|ip| ip.into()))
                .with_context(|| format!("invalid CIDR/IP: {cidr}"))?;
            let mut bl = if path.exists() {
                Blocklist::load(path)?
            } else {
                Blocklist::new(false)
            };
            bl.add(net);
            bl.save(path)?;
            println!("Added {net} to {}.", path.display());
            Ok(())
        }
        BlocklistAction::List => {
            let bl = if path.exists() {
                Blocklist::load(path)?
            } else {
                Blocklist::new(false)
            };
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
