//! Compare discovery throughput: connect scanner vs stateless SYN.
//!
//! Probes a range of loopback ports (one listening, the rest closed) with both
//! engines at the same configured rate, so the difference is the engine rather
//! than the pacing.
//!
//! ```text
//! cargo run --release -p crusade-scan --example discovery_bench -- \
//!     [base] [ports] [rate] [connect_timeout_ms] [syn_linger_ms]
//! ```
//!
//! Needs `CAP_NET_RAW` for the SYN half; it says so and skips if absent.
//!
//! **Read the numbers carefully.** On loopback, closed ports answer RST
//! instantly and there is no round trip, which is the best possible case for
//! connect scanning and tells you little about the internet. What actually
//! separates the two engines is a port that answers *nothing*: a connect
//! attempt then waits out its whole timeout while holding a slot, so the
//! connect scanner is bounded by `concurrency / timeout`, whereas a stateless
//! SYN is bounded only by the send rate. To see that, drop traffic to the
//! probed range before running:
//!
//! ```text
//! iptables -I OUTPUT -p tcp --dport <base+1>:<base+ports> -j DROP
//! ```
//!
//! Use the OUTPUT chain, not INPUT. Linux picks ephemeral source ports from
//! roughly 32768-60999, so an INPUT rule over a high port range also drops the
//! connect scanner's own *replies* and every port then looks filtered,
//! including the one that is open. Dropping our outbound SYNs reproduces an
//! unresponsive target without touching the return path.
//!
//! The base port is explicit so the rule and the probed range line up; the
//! listener sits on `base` itself and is left reachable.

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use crusade_scan::{Blocklist, RateLimiterParams, ScanConfig, SynConfig, SynScanner, TcpScanner};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let base: u16 = args.next().and_then(|a| a.parse().ok()).unwrap_or(40_000);
    let count: u16 = args.next().and_then(|a| a.parse().ok()).unwrap_or(2000);
    let rate: f64 = args.next().and_then(|a| a.parse().ok()).unwrap_or(20_000.0);
    let timeout_ms: u64 = args.next().and_then(|a| a.parse().ok()).unwrap_or(3000);
    // Lower the linger to isolate send throughput; keep it realistic (seconds)
    // when measuring whether replies are actually collected.
    let linger_ms: u64 = args.next().and_then(|a| a.parse().ok()).unwrap_or(2000);

    // One real listener at the base of the range, so both engines must find
    // exactly one open port.
    let listener = std::net::TcpListener::bind(("127.0.0.1", base))?;
    let open = listener.local_addr()?.port();
    std::thread::spawn(move || {
        // Accept and drop, so the connect scanner's handshakes complete.
        while let Ok((stream, _)) = listener.accept() {
            drop(stream);
        }
    });

    let ports: Vec<u16> = (base..base.saturating_add(count)).collect();
    let target = Ipv4Addr::LOCALHOST;
    println!(
        "probing {} loopback ports {}..{} (open: {open}) at {rate:.0}/s, \
         connect timeout {timeout_ms}ms\n",
        ports.len(),
        base,
        base.saturating_add(count)
    );

    let pacing = RateLimiterParams {
        conn_per_sec: rate,
        burst: rate,
        concurrency: 500,
    };

    let t = Instant::now();
    let connect = TcpScanner::new(
        ScanConfig {
            ports: ports.clone(),
            connect_timeout: Duration::from_millis(timeout_ms),
            rate: pacing,
            allow_private: true,
        },
        Blocklist::new(true),
    )
    .scan(&[IpAddr::V4(target)])
    .await;
    let connect_secs = t.elapsed().as_secs_f64();
    println!(
        "connect: {:>7.2}s  {:>9.0} ports/s  found {} open",
        connect_secs,
        ports.len() as f64 / connect_secs,
        connect.len()
    );

    let syn = SynScanner::new(
        SynConfig {
            rate: pacing,
            source_port: 61019,
            linger: Duration::from_millis(linger_ms),
            allow_private: true,
        },
        Blocklist::new(true),
    );
    match syn {
        Ok(scanner) => {
            let t = Instant::now();
            let found = scanner.scan(&[target], &ports).await?;
            let secs = t.elapsed().as_secs_f64();
            println!(
                "syn:     {:>7.2}s  {:>9.0} ports/s  found {} open",
                secs,
                ports.len() as f64 / secs,
                found.len()
            );
            println!(
                "\nspeedup: {:.1}x (the syn figure includes a fixed {linger_ms}ms linger)",
                connect_secs / secs
            );
            println!(
                "connect is bounded by concurrency/timeout = {:.0} ports/s when \
                 nothing answers;\nsyn is bounded by the send rate.",
                500.0 / (timeout_ms as f64 / 1000.0)
            );
        }
        Err(e) => println!("syn:     unavailable ({e}); needs CAP_NET_RAW"),
    }
    Ok(())
}
