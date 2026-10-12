//! Store throughput benchmark: how fast can Crusade absorb and query scan
//! results?
//!
//! Scanning rate is pointless if indexing is the bottleneck, so this measures
//! the ingest and read paths against synthetic hosts on a real on-disk
//! database (WAL, same settings as production).
//!
//! ```text
//! cargo run --release -p crusade-store --example ingest_bench -- [hosts] [services_per_host]
//! ```

use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;

use crusade_core::model::{Host, HttpInfo, Service, Tag, Transport};
use crusade_core::query::parse;
use crusade_store::Store;
use time::OffsetDateTime;

const PRODUCTS: &[&str] = &[
    "nginx",
    "Apache httpd",
    "OpenSSH",
    "MySQL",
    "Microsoft IIS",
    "lighttpd",
    "Postfix smtpd",
    "Redis",
];
const PORTS: &[u16] = &[22, 25, 80, 443, 3306, 6379, 8080, 8443];

fn synth(i: u32, services: usize) -> Host {
    let ip = IpAddr::V4(Ipv4Addr::from(0x0b00_0000 + i));
    let mut h = Host::new(ip);
    h.asn = Some(3320 + (i % 500));
    h.org = Some(format!("Example Org {}", i % 500));
    h.country = Some(["DE", "US", "FR", "JP", "BR"][(i % 5) as usize].into());
    h.city = Some(["Berlin", "Ashburn", "Paris", "Tokyo", "Sao Paulo"][(i % 5) as usize].into());
    h.hostnames = vec![format!("host-{i}.example.com")];
    h.last_seen = OffsetDateTime::from_unix_timestamp(1_760_000_000 + i as i64).unwrap();
    for k in 0..services {
        let idx = (i as usize + k) % PORTS.len();
        let mut s = Service::new(PORTS[idx], Transport::Tcp);
        let product = PRODUCTS[idx];
        s.service = Some("http".into());
        s.product = Some(product.into());
        s.version = Some(format!("1.{}.{}", i % 20, k));
        s.cpe = Some(format!("cpe:/a:vendor:{}:1.0", product.replace(' ', "_")));
        s.banner = Some(format!(
            "HTTP/1.1 200 OK\r\nServer: {product}\r\n\r\n<html><title>Host {i} service {k} default page</title></html>"
        ));
        s.http = Some(HttpInfo {
            status: Some(200),
            server: Some(product.into()),
            title: Some(format!("Host {i} index")),
            headers: vec![("server".into(), product.into())],
            favicon_hash: Some(i as i32),
            technologies: vec!["PHP".into()],
            security_headers: vec!["strict-transport-security".into()],
        });
        s.observed_at = h.last_seen;
        h.services.push(s);
    }
    h.tags.push(Tag::simple("default-page"));
    h.tags.push(Tag {
        name: "cve".into(),
        cve: Some(format!("CVE-2026-{:05}", i % 1000)),
        detail: Some("synthetic".into()),
    });
    h
}

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let hosts: u32 = args.next().and_then(|a| a.parse().ok()).unwrap_or(20_000);
    let per_host: usize = args.next().and_then(|a| a.parse().ok()).unwrap_or(3);
    let batch: usize = args.next().and_then(|a| a.parse().ok()).unwrap_or(1);

    let path = std::env::temp_dir().join(format!("crusade-bench-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let mut store = Store::open(&path)?;

    println!("ingesting {hosts} hosts x {per_host} services, batch {batch}…");
    let t0 = Instant::now();
    let mut last = Instant::now();
    let mut pending: Vec<Host> = Vec::with_capacity(batch);
    for i in 0..hosts {
        if batch <= 1 {
            store.upsert_host(&synth(i, per_host))?;
        } else {
            pending.push(synth(i, per_host));
            if pending.len() == batch {
                store.upsert_hosts(&pending)?;
                pending.clear();
            }
        }
        if (i + 1) % 5_000 == 0 {
            println!(
                "  {:>8} hosts  {:>8.0} hosts/s (recent)",
                i + 1,
                5_000.0 / last.elapsed().as_secs_f64()
            );
            last = Instant::now();
        }
    }
    if !pending.is_empty() {
        store.upsert_hosts(&pending)?;
    }
    let secs = t0.elapsed().as_secs_f64();
    let services = hosts as f64 * per_host as f64;
    println!(
        "ingest: {hosts} hosts in {secs:.1}s = {:.0} hosts/s, {:.0} services/s",
        hosts as f64 / secs,
        services / secs
    );
    let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    println!(
        "db size: {:.1} MiB = {:.0} bytes/host",
        size as f64 / 1_048_576.0,
        size as f64 / hosts as f64
    );

    for q in [
        "",
        "port:443",
        "product:nginx",
        "country:DE product:nginx",
        "has_vuln:true",
        "net:11.0.0.0/16",
        "\"default page\"",
    ] {
        let parsed = parse(q)?;
        let t = Instant::now();
        let n = store.count(&parsed)?;
        let count_ms = t.elapsed().as_secs_f64() * 1000.0;
        let t = Instant::now();
        let (capped, exact) = store.count_capped(&parsed, 10_000)?;
        let capped_ms = t.elapsed().as_secs_f64() * 1000.0;
        let t = Instant::now();
        let page = store.search(&parsed, 25, 0)?.len();
        let search_ms = t.elapsed().as_secs_f64() * 1000.0;
        println!(
            "query {:<28} count {n:>9} in {count_ms:>8.1}ms   capped {capped:>6}{} in {capped_ms:>6.1}ms   page({page}) in {search_ms:>7.1}ms",
            if q.is_empty() { "<all>" } else { q },
            if exact { " " } else { "+" }
        );
    }

    let t = Instant::now();
    let f = store.facets_for_query(&parse("")?, 15)?;
    println!(
        "facets (all): {} ports, {} products in {:.0}ms",
        f.ports.len(),
        f.products.len(),
        t.elapsed().as_secs_f64() * 1000.0
    );

    // A second, unchanged pass: history should not grow, and re-ingest is the
    // common case for a monitor.
    let t = Instant::now();
    let rescan: Vec<Host> = (0..1000).map(|i| synth(i, per_host)).collect();
    store.upsert_hosts(&rescan)?;
    println!(
        "unchanged rescan of 1000 hosts in {:.2}s = {:.0} hosts/s",
        t.elapsed().as_secs_f64(),
        1000.0 / t.elapsed().as_secs_f64()
    );

    let t = Instant::now();
    let sets = store.tcp_port_sets()?;
    println!(
        "port sets: {} hosts in {:.0}ms",
        sets.len(),
        t.elapsed().as_secs_f64() * 1000.0
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}
