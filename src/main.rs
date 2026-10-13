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
    expand_targets, filter_blocked, parse_masscan_json, Blocklist, RateLimiterParams, ScanConfig,
    TcpScanner,
};
use crusade_store::Store;
use std::collections::BTreeMap;
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
        /// After the first pass, probe this many further ports per host,
        /// chosen by what the index says co-occurs with what the host already
        /// answered. 0 disables the predictive phase.
        #[arg(long, default_value_t = 0)]
        predict: usize,
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
        /// Use the tiered schedule instead of the configured default ports:
        /// the hot list every pass, cloud ports on cloud networks, and a slice
        /// of each host's own port permutation so coverage creeps across the
        /// whole 65k space.
        #[arg(long)]
        tiers: bool,
        /// Background ports per host per pass when --tiers is set.
        #[arg(long, default_value_t = 100)]
        background: usize,
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
    /// List the hosts least like the rest of the index, with the reason for
    /// each. Reads the index only; sends nothing.
    Anomalies {
        /// Optional query to restrict both the population and the candidates.
        query: Vec<String>,
        #[arg(long, default_value_t = 20)]
        top: usize,
    },
    /// Group hosts into infrastructure clusters by shared certificates,
    /// host keys, favicons and fingerprints, then make them searchable with
    /// `cluster:<id>`. Reads the index only; sends nothing.
    Cluster {
        /// Show the largest clusters and stop, without storing anything.
        #[arg(long)]
        dry_run: bool,
        /// How many clusters to list.
        #[arg(long, default_value_t = 15)]
        top: usize,
    },
    /// Group web services by the look of their landing page, so one default
    /// install appears once instead of ten thousand times. Reads the index
    /// only; sends nothing.
    Screenshots {
        /// How many template groups to list.
        #[arg(long, default_value_t = 20)]
        top: usize,
        /// Show every member of each listed group, not just a sample.
        #[arg(long)]
        members: bool,
    },
    /// Report how far background port coverage has advanced, and what a host
    /// is scheduled to be probed on next.
    Coverage {
        /// Show the next scheduled ports for one host.
        #[arg(long)]
        ip: Option<String>,
        /// Background ports per pass, for the completion estimate.
        #[arg(long, default_value_t = 100)]
        background: usize,
    },
    /// IPv6 discovery: learn from the addresses already indexed, then predict
    /// and probe new ones. IPv6 cannot be swept, so the prediction *is* the
    /// scan.
    Ipv6 {
        /// Extra seed addresses, one per line (merged with the index).
        #[arg(long)]
        seeds: Option<PathBuf>,
        /// Candidates to generate per round.
        #[arg(long, default_value_t = 256)]
        budget: usize,
        /// Rounds of generate, scan, then feed the results back.
        #[arg(long, default_value_t = 3)]
        rounds: usize,
        /// TCP ports to probe on each candidate.
        #[arg(long, value_delimiter = ',')]
        ports: Option<Vec<u16>>,
        /// Test each seed's /64 for aliasing first, so a network that answers
        /// on every address is collapsed to one target instead of flooding
        /// the generator.
        #[arg(long)]
        dealias: bool,
        /// Plan only: show the candidates and probe nothing.
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        allow_private: bool,
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
            predict,
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
                    predict,
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
            tiers,
            background,
            allow_private,
        } => {
            cmd_monitor(
                &cfg,
                MonitorOpts {
                    interval,
                    stale,
                    batch,
                    once,
                    tiers,
                    background,
                    allow_private,
                },
            )
            .await
        }
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
        Command::Anomalies { query, top } => cmd_anomalies(&cfg, &query.join(" "), top),
        Command::Cluster { dry_run, top } => cmd_cluster(&cfg, dry_run, top),
        Command::Screenshots { top, members } => cmd_screenshots(&cfg, top, members),
        Command::Coverage { ip, background } => cmd_coverage(&cfg, ip, background),
        Command::Ipv6 {
            seeds,
            budget,
            rounds,
            ports,
            dealias,
            dry_run,
            allow_private,
        } => {
            cmd_ipv6(
                &cfg,
                Ipv6Opts {
                    seeds,
                    budget,
                    rounds,
                    ports,
                    dealias,
                    dry_run,
                    allow_private,
                },
            )
            .await
        }
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
    predict: usize,
    allow_private: bool,
}

async fn cmd_scan(cfg: &Config, target: &str, opts: ScanOpts) -> Result<()> {
    let bl = load_blocklist(cfg, opts.allow_private)?;
    let targets = expand_targets(target, &bl)?;
    if targets.is_empty() {
        println!("No scannable addresses (all blocked/reserved, or empty target).");
        return Ok(());
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
    eprintln!("Scanning {} address(es)…", targets.len());

    // TCP discovery: stateless SYN, the masscan front-end, or the built-in
    // connect scanner.
    let mut open = discover_tcp(cfg, &targets, &tcp_ports, &opts, &bl).await?;
    eprintln!("Found {} open TCP port(s); probing…", open.len());

    // Predictive second phase: ask the index which other ports a host like
    // this tends to have, and probe only those.
    if opts.predict > 0 && !open.is_empty() {
        let extra = predict_phase(cfg, &open, &tcp_ports, opts.predict, &opts, &bl).await?;
        if !extra.is_empty() {
            eprintln!("Prediction found {} further open port(s).", extra.len());
            open.extend(extra);
            open.sort_unstable();
            open.dedup();
        }
    }

    // UDP worklist (if --udp, explicit --udp-ports, or ICS UDP ports via --ics).
    let udp = if opts.udp || opts.udp_ports.is_some() || opts.ics {
        let mut uports = opts.udp_ports.clone().unwrap_or_else(|| {
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

/// One TCP discovery pass with whichever engine the options select.
async fn discover_tcp(
    cfg: &Config,
    targets: &[IpAddr],
    ports: &[u16],
    opts: &ScanOpts,
    bl: &Blocklist,
) -> Result<Vec<(IpAddr, u16)>> {
    if ports.is_empty() || targets.is_empty() {
        return Ok(Vec::new());
    }
    if opts.discovery_syn {
        return syn_discover(targets, ports, opts.syn_rate, bl, opts.allow_private).await;
    }
    if opts.discovery_masscan {
        let mcfg = crusade_scan::MasscanConfig {
            rate: opts.masscan_rate,
            extra_args: vec![],
        };
        return crusade_scan::masscan_discover(targets, ports, &mcfg, bl)
            .await
            .context("masscan discovery");
    }
    let scan_cfg = ScanConfig {
        ports: ports.to_vec(),
        connect_timeout: cfg.connect_timeout(),
        rate: RateLimiterParams {
            conn_per_sec: cfg.scan.rate_per_sec,
            burst: cfg.scan.rate_per_sec,
            concurrency: cfg.scan.max_concurrent,
        },
        allow_private: opts.allow_private,
    };
    Ok(TcpScanner::new(scan_cfg, bl.clone()).scan(targets).await)
}

/// Probe the ports the model expects, given what each host already answered.
///
/// This is the second phase of the GPS design (Izhikevich et al., SIGCOMM
/// 2022): a cheap seed scan finds one service, then prediction says where the
/// host's other services are, so the expensive breadth is spent only where
/// something is actually listening. Each host gets its own predicted set, and
/// hosts are grouped by that set so a shared prediction costs one pass.
async fn predict_phase(
    cfg: &Config,
    found: &[(IpAddr, u16)],
    already: &[u16],
    top_k: usize,
    opts: &ScanOpts,
    bl: &Blocklist,
) -> Result<Vec<(IpAddr, u16)>> {
    let model = {
        let store = Store::open(&cfg.database.path)?;
        crusade_core::PortModel::from_port_sets(&store.tcp_port_sets()?)
    };
    if !model.is_usable() {
        eprintln!(
            "--predict needs a larger index to learn from ({} hosts so far, {} needed); \
             skipping the predictive phase",
            model.hosts(),
            crusade_core::ports::MIN_HOSTS
        );
        return Ok(Vec::new());
    }

    // What each host answered in the seed phase.
    let mut by_host: BTreeMap<IpAddr, Vec<u16>> = BTreeMap::new();
    for (ip, port) in found {
        by_host.entry(*ip).or_default().push(*port);
    }

    // Group hosts whose observations predict the same ports, so one pass
    // covers all of them.
    let mut groups: BTreeMap<Vec<u16>, Vec<IpAddr>> = BTreeMap::new();
    for (ip, observed) in &by_host {
        let predicted: Vec<u16> = model
            .predict(observed, top_k)
            .into_iter()
            .map(|(port, _)| port)
            .filter(|p| !already.contains(p))
            .collect();
        if !predicted.is_empty() {
            groups.entry(predicted).or_default().push(*ip);
        }
    }
    if groups.is_empty() {
        return Ok(Vec::new());
    }

    // Report what was actually predicted, not the budget: `top_k` is a cap,
    // and the model only offers candidates it has evidence for, so asking for
    // more than it knows costs nothing.
    let probes: usize = groups
        .iter()
        .map(|(ports, ips)| ports.len() * ips.len())
        .sum();
    let widest = groups.keys().map(|p| p.len()).max().unwrap_or(0);
    eprintln!(
        "Predicting up to {widest} port(s) per host over {} host(s) \
         ({probes} extra probes, vs {} to sweep every port)",
        by_host.len(),
        by_host.len() * 65_535
    );

    let mut extra = Vec::new();
    for (ports, ips) in groups {
        extra.extend(discover_tcp(cfg, &ips, &ports, opts, bl).await?);
    }
    Ok(extra)
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
    // zmap 4.4 can carry a JA4TS stack fingerprint and SYN RTT per row; keep
    // them alongside the (ip, port) pairs so they are not thrown away.
    let mut stack_fingerprints: BTreeMap<(IpAddr, u16), String> = BTreeMap::new();
    let mut rtts: Vec<u32> = Vec::new();
    let pairs = match format {
        "masscan" => parse_masscan_json(&text),
        "zmap" => {
            let rows = crusade_scan::parse_zmap_csv_rich(&text);
            for row in &rows {
                if let Some(fp) = &row.ja4ts {
                    stack_fingerprints.insert((row.ip, row.port), fp.clone());
                }
                if let Some(rtt) = row.rtt_us {
                    rtts.push(rtt);
                }
            }
            rows.into_iter().map(|r| (r.ip, r.port)).collect()
        }
        _ => unreachable!("clap restricts format"),
    };
    let bl = load_blocklist(cfg, allow_private)?;
    let pairs = filter_blocked(pairs, &bl);
    eprintln!(
        "Ingested {} open port(s) after blocklist filtering; probing…",
        pairs.len()
    );
    if !rtts.is_empty() {
        rtts.sort_unstable();
        eprintln!(
            "  SYN RTT: median {:.1}ms, min {:.1}ms, max {:.1}ms over {} probe(s)",
            f64::from(rtts[rtts.len() / 2]) / 1000.0,
            f64::from(rtts[0]) / 1000.0,
            f64::from(rtts[rtts.len() - 1]) / 1000.0,
            rtts.len()
        );
    }
    if !stack_fingerprints.is_empty() {
        eprintln!(
            "  {} JA4TS stack fingerprint(s) carried through",
            stack_fingerprints.len()
        );
    }

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

    // Apply the sweep's stack fingerprints. Done after probing rather than
    // threaded through the pipeline: they come from the sweep tool, not from
    // anything Crusade observed, and only this path has them.
    if !stack_fingerprints.is_empty() {
        let mut annotated: Vec<crusade_core::Host> = Vec::new();
        for mut host in hosts.clone() {
            let mut touched = false;
            for svc in &mut host.services {
                if let Some(fp) = stack_fingerprints.get(&(host.ip, svc.port)) {
                    svc.ja4ts = Some(fp.clone());
                    touched = true;
                }
            }
            if touched {
                annotated.push(host);
            }
        }
        if !annotated.is_empty() {
            store.upsert_hosts(&annotated)?;
            eprintln!("  recorded JA4TS on {} host(s)", annotated.len());
        }
    }

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

struct MonitorOpts {
    interval: u64,
    stale: u64,
    batch: usize,
    once: bool,
    tiers: bool,
    background: usize,
    allow_private: bool,
}

async fn cmd_monitor(cfg: &Config, opts: MonitorOpts) -> Result<()> {
    let MonitorOpts {
        interval,
        stale,
        batch,
        once,
        tiers,
        background,
        allow_private,
    } = opts;
    let datasets = Arc::new(pipeline::Datasets::load(cfg)?);
    let tcp_ports = cfg.scan.default_ports.clone();
    // One salt for the installation: it keys every host's port order, so
    // keeping it fixed is what makes coverage resume rather than restart.
    let salt = {
        let store = Store::open(&cfg.database.path)?;
        store.scan_salt()?
    };
    if tiers {
        eprintln!(
            "monitor: tiered schedule ({} hot port(s), {} cloud port(s) on cloud networks, \
             {background} background port(s)/host/pass -> full 65k coverage in {} passes)",
            crusade_core::schedule::HOT_PORTS.len(),
            crusade_core::schedule::CLOUD_PORTS.len(),
            crusade_core::schedule::coverage(0, background)
                .passes_remaining
                .map_or("no".to_string(), |n| n.to_string())
        );
    }
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

            // Rescan the configured or scheduled ports *and* every port
            // already known on this host, so a service that has gone away is
            // actually re-probed and can move through pending to eviction.
            let mut plan = None;
            let mut ports = if tiers {
                let store = Store::open(&cfg.database.path)?;
                let cursor = store.background_cursor(&ip_str)?;
                let budget = crusade_core::TierBudget {
                    background,
                    cloud: before
                        .as_ref()
                        .and_then(|h| h.asn)
                        .and_then(crusade_core::cloud_asn)
                        .is_some(),
                };
                let p = crusade_core::schedule::plan(ip, cursor, salt, &budget);
                let selected = p.ports.clone();
                plan = Some(p);
                selected
            } else {
                tcp_ports.clone()
            };
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

            // Advance the walk only after the probes actually went out, so an
            // interrupted pass re-probes rather than skipping that slice.
            if let Some(p) = &plan {
                store.set_background_cursor(&ip_str, p.next_cursor)?;
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

/// How long a recorded aliasing verdict is reused before being re-probed.
/// Long, because the answer is stable, but not forever: a network can change.
const ALIAS_MAX_AGE_SECS: i64 = 90 * 86_400;

/// Rank hosts by how unlike the population they are.
fn cmd_anomalies(cfg: &Config, raw: &str, top: usize) -> Result<()> {
    use crusade_core::anomaly::{score, Population};
    let q = query::parse(raw).map_err(|e| anyhow::anyhow!("{e}"))?;
    let store = Store::open(&cfg.database.path)?;

    // The population and the candidates are the same set: a host is unusual
    // relative to the hosts it is being compared with, so scoring against a
    // different population would answer a different question.
    let ips = store.matching_ips(&q)?;
    let mut hosts = Vec::with_capacity(ips.len());
    for ip in &ips {
        if let Some(h) = store.get_host(ip)? {
            hosts.push(h);
        }
    }
    if hosts.is_empty() {
        println!("No hosts match.");
        return Ok(());
    }

    let population = Population::from_hosts(hosts.iter());
    if !population.is_usable() {
        println!(
            "Only {} host(s) to compare against; at least {} are needed before \
             \"unusual\" means anything.",
            population.hosts(),
            crusade_core::anomaly::Population::MIN_HOSTS
        );
        return Ok(());
    }

    let mut scored: Vec<(&crusade_core::Host, crusade_core::Anomaly)> = hosts
        .iter()
        .filter_map(|h| score(h, &population).map(|a| (h, a)))
        .collect();
    scored.sort_by(|a, b| b.1.score.total_cmp(&a.1.score).then(a.0.ip.cmp(&b.0.ip)));

    println!(
        "{} host(s), {} distinct feature(s); most unusual first:\n",
        population.hosts(),
        population.distinct_features()
    );
    for (host, anomaly) in scored.iter().take(top) {
        println!(
            "{:<40} {:>7.1} bits  {}",
            host.ip.to_string(),
            anomaly.score,
            anomaly.top_reasons(3).join(", ")
        );
    }
    Ok(())
}

/// Build infrastructure clusters from shared identifiers.
/// Group the indexed screenshots into page templates.
///
/// A sweep of the web finds the same few thousand default pages on millions of
/// hosts. Grouping by perceptual hash turns that into a short list an analyst
/// can actually read, and makes the long tail — the pages that look like
/// nothing else — visible.
fn cmd_screenshots(cfg: &Config, top: usize, show_members: bool) -> Result<()> {
    let store = Store::open(&cfg.database.path)?;
    let hashes = store.screenshot_hashes()?;
    if hashes.is_empty() {
        println!("No screenshot fingerprints indexed. Scan with --screenshots first.");
        return Ok(());
    }

    let by_label: std::collections::HashMap<&str, u64> =
        hashes.iter().map(|(l, h)| (l.as_str(), *h)).collect();
    let groups = crusade_enrich::group(&hashes);
    let unique = groups.iter().filter(|g| g.len() == 1).count();
    println!(
        "{} screenshot(s): {} template(s), {unique} page(s) unlike any other",
        hashes.len(),
        groups.len()
    );

    for g in groups.iter().take(top) {
        let hash = by_label.get(g[0].as_str()).copied().unwrap_or(0);
        println!("\n  {:016x}  {:>5} page(s)", hash, g.len());
        let shown = if show_members {
            g.len()
        } else {
            5.min(g.len())
        };
        for label in &g[..shown] {
            println!("    {label}");
        }
        if shown < g.len() {
            println!("    … and {} more", g.len() - shown);
        }
    }
    if groups.len() > top {
        println!("\n… and {} more template(s)", groups.len() - top);
    }
    Ok(())
}

fn cmd_cluster(cfg: &Config, dry_run: bool, top: usize) -> Result<()> {
    let mut store = Store::open(&cfg.database.path)?;
    let identifiers = store.link_identifiers()?;
    if identifiers.is_empty() {
        println!("No hosts indexed yet.");
        return Ok(());
    }

    let mut linker = crusade_core::Linker::new();
    for (ip, ids) in identifiers {
        linker.add(ip, ids);
    }
    let clusters = linker.clusters();
    let grouped: usize = clusters.iter().map(|c| c.len()).sum();
    println!(
        "{} host(s): {} cluster(s) covering {grouped} host(s)",
        linker.hosts(),
        clusters.len()
    );

    for c in clusters.iter().take(top) {
        let why: Vec<String> = c
            .evidence
            .iter()
            .take(3)
            .map(|(id, n)| {
                let value = if id.value.chars().count() > 40 {
                    format!("{}…", id.value.chars().take(39).collect::<String>())
                } else {
                    id.value.clone()
                };
                format!("{}={value} ({n} hosts)", id.kind.as_str())
            })
            .collect();
        println!("  {:<24} {:>5} host(s)  {}", c.id, c.len(), why.join(", "));
    }
    if clusters.len() > top {
        println!("  … and {} more", clusters.len() - top);
    }

    // Identifiers too common to mean anything are worth seeing: they explain
    // why hosts an operator expected to be linked are not.
    let ignored = linker.ignored_as_common();
    if !ignored.is_empty() {
        println!(
            "\nignored {} identifier(s) as too common to imply shared ownership:",
            ignored.len()
        );
        for (id, n) in ignored.iter().take(5) {
            println!("  {:<12} on {n} host(s): {}", id.kind.as_str(), id.value);
        }
    }

    if dry_run {
        println!("\nNothing was stored.");
        return Ok(());
    }
    let assignments: Vec<(String, String)> = clusters
        .iter()
        .flat_map(|c| c.members.iter().map(|m| (m.clone(), c.id.clone())))
        .collect();
    store.set_clusters(&assignments)?;
    println!("\nStored. Search a cluster with `crusade search cluster:<id>`.");
    Ok(())
}

/// Report background coverage: how much of the port space each host has been
/// through, and what comes next.
fn cmd_coverage(cfg: &Config, ip: Option<String>, background: usize) -> Result<()> {
    use crusade_core::schedule;
    let store = Store::open(&cfg.database.path)?;
    let salt = store.scan_salt()?;

    if let Some(ip) = ip {
        let addr: IpAddr = ip.parse().with_context(|| format!("invalid IP: {ip}"))?;
        let host = store.get_host(&ip)?;
        let cursor = store.background_cursor(&ip)?;
        let cov = schedule::coverage(cursor, background);
        println!("{ip}");
        println!(
            "  background: {} of {} port(s) covered ({:.1}%)",
            cov.covered,
            schedule::PORT_SPACE,
            cov.fraction * 100.0
        );
        match cov.passes_remaining {
            Some(0) => println!("  the port space has been covered once; the cycle repeats"),
            Some(n) => println!("  {n} more pass(es) at {background}/pass to finish the cycle"),
            None => println!("  no background budget, so no completion estimate"),
        }
        let cloud = host
            .as_ref()
            .and_then(|h| h.asn)
            .and_then(crusade_core::cloud_asn);
        if let Some(name) = cloud {
            println!("  on {name}: the cloud port tier applies");
        }
        let plan = schedule::plan(
            addr,
            cursor,
            salt,
            &crusade_core::TierBudget {
                background,
                cloud: cloud.is_some(),
            },
        );
        for (tier, ports) in &plan.by_tier {
            let shown: Vec<String> = ports.iter().take(12).map(|p| p.to_string()).collect();
            println!(
                "  next {:<11} {} port(s): {}{}",
                tier.as_str(),
                ports.len(),
                shown.join(", "),
                if ports.len() > shown.len() {
                    ", …"
                } else {
                    ""
                }
            );
        }
        return Ok(());
    }

    // Whole-index summary.
    let hosts = store.all_host_ips()?;
    if hosts.is_empty() {
        println!("No hosts indexed yet.");
        return Ok(());
    }
    let mut started = 0usize;
    let mut complete = 0usize;
    let mut total_cursor: u64 = 0;
    for host_ip in &hosts {
        let cursor = store.background_cursor(host_ip)?;
        if cursor > 0 {
            started += 1;
        }
        if cursor >= u64::from(schedule::PORT_SPACE) {
            complete += 1;
        }
        total_cursor += cursor.min(u64::from(schedule::PORT_SPACE));
    }
    let space = u64::from(schedule::PORT_SPACE);
    println!("{} host(s) indexed", hosts.len());
    println!(
        "background coverage: {started} started, {complete} through a full cycle, \
         {:.2}% of all host-port pairs probed",
        100.0 * total_cursor as f64 / (hosts.len() as u64 * space) as f64
    );
    if started == 0 {
        println!("Run `crusade monitor --tiers` to begin background coverage.");
    }
    Ok(())
}

struct Ipv6Opts {
    seeds: Option<PathBuf>,
    budget: usize,
    rounds: usize,
    ports: Option<Vec<u16>>,
    dealias: bool,
    dry_run: bool,
    allow_private: bool,
}

/// IPv6 discovery: clean the seeds, optionally dealias, then generate, probe
/// and learn.
///
/// The loop is the point. A one-shot generator has no idea which of its
/// guesses were any good; feeding hits back lets the next round concentrate on
/// the regions that answered, which is what 6Sense (USENIX Security 2024)
/// found separates a usable generator from a published one.
async fn cmd_ipv6(cfg: &Config, opts: Ipv6Opts) -> Result<()> {
    let bl = load_blocklist(cfg, opts.allow_private)?;
    let ports = opts
        .ports
        .clone()
        .unwrap_or_else(|| cfg.scan.default_ports.clone());

    // Seeds: the index, plus anything the operator supplies.
    let mut raw: Vec<std::net::Ipv6Addr> = {
        let store = Store::open(&cfg.database.path)?;
        store.ipv6_host_ips(100_000)?
    };
    let from_index = raw.len();
    if let Some(path) = &opts.seeds {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading seeds from {}", path.display()))?;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match line.parse::<std::net::Ipv6Addr>() {
                Ok(addr) => raw.push(addr),
                Err(_) => eprintln!("  (skipping unparseable seed {line:?})"),
            }
        }
    }
    eprintln!(
        "{} seed address(es) ({from_index} from the index, {} from file)",
        raw.len(),
        raw.len() - from_index
    );
    if raw.is_empty() {
        println!(
            "No IPv6 seeds. Scan some IPv6 hosts first, or pass --seeds <file>: \
             IPv6 cannot be swept, so there is nothing to predict from."
        );
        return Ok(());
    }

    // Start from what previous runs already established: the alias probe costs
    // 16 requests per prefix and the answer rarely changes.
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let mut dealiaser = crusade_scan::Dealiaser::new();
    {
        let store = Store::open(&cfg.database.path)?;
        let known = store.aliased_prefixes(now, ALIAS_MAX_AGE_SECS)?;
        for prefix in &known {
            if let Ok(net) = prefix.parse::<ipnet::Ipv6Net>() {
                dealiaser.record(net, crusade_scan::Alias::Aliased);
            }
        }
        if !known.is_empty() {
            eprintln!(
                "{} known aliased prefix(es) reused from the index",
                known.len()
            );
        }
    }
    if opts.dealias && !opts.dry_run {
        dealias_seeds(cfg, &raw, &ports, &mut dealiaser, &opts, &bl, now).await?;
    }

    let (seeds, report) = crusade_scan::clean_seeds(&raw, &dealiaser);
    eprintln!(
        "seeds: {} kept, {} duplicate, {} unroutable, {} folded into an aliased prefix",
        report.kept, report.duplicates, report.not_scannable, report.collapsed
    );
    if seeds.is_empty() {
        println!("No usable seeds after cleaning.");
        return Ok(());
    }

    let mut generator = crusade_scan::TargetGenerator::from_seeds(&seeds);
    eprintln!(
        "learned {} dense region(s) from {} seed(s)",
        generator.regions(),
        seeds.len()
    );
    if generator.regions() == 0 {
        println!(
            "The seeds share no varying prefix, so there is nothing to generalise \
             from. More seeds, from more networks, would help."
        );
        return Ok(());
    }

    let datasets = Arc::new(pipeline::Datasets::load(cfg)?);
    let mut total_found = 0usize;
    let mut total_probed = 0usize;

    for round in 1..=opts.rounds.max(1) {
        let raw_candidates = generator.generate(opts.budget);
        if raw_candidates.is_empty() {
            eprintln!("round {round}: the generator is exhausted");
            break;
        }
        // Generated addresses go through dealiasing too, not just seeds: a
        // prefix that answers on every address would otherwise soak up the
        // whole budget and teach the model nothing.
        let candidates = dealiaser.collapse(&raw_candidates);
        if candidates.len() < raw_candidates.len() {
            eprintln!(
                "round {round}: {} candidate(s) folded into a known aliased prefix",
                raw_candidates.len() - candidates.len()
            );
        }
        total_probed += candidates.len();

        if opts.dry_run {
            println!("round {round}: {} candidate(s)", candidates.len());
            for c in candidates.iter().take(20) {
                println!("  {c}");
            }
            if candidates.len() > 20 {
                println!("  … and {} more", candidates.len() - 20);
            }
            continue;
        }

        let targets: Vec<IpAddr> = candidates.iter().map(|a| IpAddr::V6(*a)).collect();
        let scan_cfg = ScanConfig {
            ports: ports.clone(),
            connect_timeout: cfg.connect_timeout(),
            rate: RateLimiterParams {
                conn_per_sec: cfg.scan.rate_per_sec,
                burst: cfg.scan.rate_per_sec,
                concurrency: cfg.scan.max_concurrent,
            },
            allow_private: opts.allow_private,
        };
        let open = TcpScanner::new(scan_cfg, bl.clone()).scan(&targets).await;

        // Feed every candidate back, hit or miss, so the model learns from
        // both. A miss is as informative as a hit for steering the budget.
        let responsive: std::collections::BTreeSet<IpAddr> =
            open.iter().map(|(ip, _)| *ip).collect();
        for c in &candidates {
            generator.reward(*c, responsive.contains(&IpAddr::V6(*c)));
        }

        eprintln!(
            "round {round}: {} candidate(s) probed, {} responded",
            candidates.len(),
            responsive.len()
        );
        total_found += responsive.len();

        if !open.is_empty() {
            let mut store = Store::open(&cfg.database.path)?;
            pipeline::process(
                open,
                Vec::new(),
                datasets.clone(),
                cfg,
                &mut store,
                cfg.screenshot.enabled,
            )
            .await?;
        }
    }

    if opts.dry_run {
        println!("\nPlanned {total_probed} probe(s). Nothing was sent.");
    } else {
        println!(
            "Probed {total_probed} generated address(es); {total_found} responded ({:.2}% hit rate).",
            if total_probed == 0 {
                0.0
            } else {
                100.0 * total_found as f64 / total_probed as f64
            }
        );
    }
    Ok(())
}

/// Probe each seed's /64 for aliasing and record the verdicts.
///
/// A network that answers on every address in a prefix would otherwise swamp
/// the generator with meaningless hits. Detection is the nybble sweep from
/// Gasser et al. (IMC 2018); an aliased prefix is collapsed to one
/// representative rather than discarded, because it is usually real
/// infrastructure.
async fn dealias_seeds(
    cfg: &Config,
    seeds: &[std::net::Ipv6Addr],
    ports: &[u16],
    dealiaser: &mut crusade_scan::Dealiaser,
    opts: &Ipv6Opts,
    bl: &Blocklist,
    now: i64,
) -> Result<()> {
    // One test per distinct /64, which is the usual assignment boundary.
    let prefixes: std::collections::BTreeSet<ipnet::Ipv6Net> = seeds
        .iter()
        .filter(|a| crusade_scan::is_scannable(**a))
        .filter_map(|a| ipnet::Ipv6Net::new(*a, 64).ok().map(|n| n.trunc()))
        .collect();
    eprintln!("dealiasing {} distinct /64 prefix(es)…", prefixes.len());

    let scan_cfg = ScanConfig {
        ports: ports.to_vec(),
        connect_timeout: cfg.connect_timeout(),
        rate: RateLimiterParams {
            conn_per_sec: cfg.scan.rate_per_sec,
            burst: cfg.scan.rate_per_sec,
            concurrency: cfg.scan.max_concurrent,
        },
        allow_private: opts.allow_private,
    };
    let scanner = TcpScanner::new(scan_cfg, bl.clone());

    let mut aliased = 0usize;
    for prefix in prefixes {
        // Already established: do not spend 16 probes confirming it.
        if dealiaser.covering(prefix.network()).is_some() {
            continue;
        }
        let probes = crusade_scan::alias_probes(prefix, 0x_c0ffee);
        if probes.is_empty() {
            continue;
        }
        let targets: Vec<IpAddr> = probes.iter().map(|a| IpAddr::V6(*a)).collect();
        let open = scanner.scan(&targets).await;
        let answered: std::collections::BTreeSet<IpAddr> = open.iter().map(|(ip, _)| *ip).collect();
        let responses: Vec<bool> = targets.iter().map(|t| answered.contains(t)).collect();
        let verdict = crusade_scan::Dealiaser::classify(&responses);
        if verdict == crusade_scan::Alias::Aliased {
            aliased += 1;
            eprintln!("  {prefix} answers on every probed address; collapsing to one target");
            // Persist, so later runs skip the probe.
            let store = Store::open(&cfg.database.path)?;
            store.record_aliased_prefix(&prefix.to_string(), now)?;
        }
        dealiaser.record(prefix, verdict);
    }
    eprintln!("{aliased} aliased prefix(es) found");
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
            predict: 0,
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
