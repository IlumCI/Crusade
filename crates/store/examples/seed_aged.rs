//! Seed a database with hosts of controlled age and access history, to
//! exercise retention and archiving against something realistic.
//!
//! ```text
//! cargo run --release -p crusade-store --example seed_aged -- <db> <hosts> <stale_pct> <days_old>
//! ```
//!
//! `stale_pct` of the hosts are given a `last_seen` `days_old` days in the
//! past and no access record, which is exactly what retention selects; the
//! rest are current. A tenth of the stale ones are marked as recently viewed,
//! so a run can show that visited hosts are held back.

use std::net::{IpAddr, Ipv4Addr};

use crusade_core::model::{Host, HttpInfo, Service, Tag, Transport};
use crusade_store::Store;
use time::OffsetDateTime;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let path = args.next().unwrap_or_else(|| "seeded.db".into());
    let count: u32 = args.next().and_then(|a| a.parse().ok()).unwrap_or(20_000);
    let stale_pct: u32 = args.next().and_then(|a| a.parse().ok()).unwrap_or(75);
    let days_old: i64 = args.next().and_then(|a| a.parse().ok()).unwrap_or(250);

    let now = OffsetDateTime::now_utc();
    let old = now - time::Duration::days(days_old);
    let mut store = Store::open(&path)?;

    let mut batch: Vec<Host> = Vec::with_capacity(500);
    let mut visited: Vec<String> = Vec::new();
    let mut stale = 0u32;

    for i in 0..count {
        let is_stale = i % 100 < stale_pct;
        let seen = if is_stale { old } else { now };
        let ip = IpAddr::V4(Ipv4Addr::from(0x0b00_0000 + i));
        let mut h = Host::new(ip);
        h.last_seen = seen;
        h.country = Some("DE".into());
        h.asn = Some(3320);
        let mut s = Service::new(80, Transport::Tcp);
        s.product = Some("nginx".into());
        s.version = Some("1.18.0".into());
        // A chunky banner, since banner text is most of what the index stores.
        s.banner = Some(format!(
            "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n<html><title>host {i}</title>{}</html>",
            "filler ".repeat(60)
        ));
        s.http = Some(HttpInfo {
            status: Some(200),
            server: Some("nginx/1.18.0".into()),
            title: Some(format!("host {i}")),
            headers: vec![],
            favicon_hash: None,
            technologies: vec![],
            security_headers: vec![],
        });
        s.observed_at = seen;
        h.services.push(s);
        h.tags.push(Tag::simple("default-page"));

        if is_stale {
            stale += 1;
            // Every tenth stale host has been looked at recently.
            if i % 10 == 0 {
                visited.push(ip.to_string());
            }
        }
        batch.push(h);
        if batch.len() == 500 {
            store.upsert_hosts(&batch)?;
            batch.clear();
        }
    }
    store.upsert_hosts(&batch)?;
    store.touch_hosts(&visited);

    let r = store.storage_report()?;
    println!(
        "seeded {} hosts into {path} ({} stale, {} marked recently viewed); \
         file {:.1} MiB, {} never viewed",
        r.hosts,
        stale,
        visited.len(),
        r.file_bytes as f64 / 1_048_576.0,
        r.never_accessed
    );
    Ok(())
}
