//! End-to-end integration test: the real scan → probe → store → search path,
//! plus the mandatory-blocklist guardrail. Binds a loopback HTTP server and
//! scans it (loopback requires allow_private, as a real run of one's own rig
//! would). Exercised by `cargo test` in CI.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use crusade_core::query::parse;
use crusade_core::Transport;
use crusade_scan::{expand_targets, Blocklist, RateLimiterParams, ScanConfig, TcpScanner};
use crusade_store::Store;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A tiny HTTP server that answers one request with a titled page, then stops.
async fn spawn_http() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                // Send the response immediately on connect so even a banner
                // (NULL-probe) read — not just an HTTP GET on a well-known port —
                // captures it. The <title> then lands in the indexed banner.
                let body = "<html><head><title>Crusade Integration Rig</title></head><body>ok</body></html>";
                let resp = format!(
                    "HTTP/1.0 200 OK\r\nServer: crusade-itest/1.0\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(), body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.flush().await;
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
            });
        }
    });
    port
}

#[tokio::test]
async fn scan_probe_store_search_roundtrip() {
    let port = spawn_http().await;
    let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

    // Discover the open port (allow_private: we are scanning our own rig).
    let cfg = ScanConfig {
        ports: vec![port],
        connect_timeout: Duration::from_secs(2),
        rate: RateLimiterParams::default(),
        allow_private: true,
    };
    let scanner = TcpScanner::new(cfg, Blocklist::new(true));
    let open = scanner.scan(&[ip]).await;
    assert!(
        open.iter().any(|(_, p)| *p == port),
        "scanner should find the open port"
    );

    // Probe it with the real app-layer stack.
    let fp = crusade_probe::Fingerprints::load_default()
        .unwrap_or_else(|_| crusade_probe::Fingerprints::parse(""));
    let pcfg = crusade_probe::ProbeConfig {
        timeout: Duration::from_secs(3),
        tls: false,
        sni: None,
    };
    let svc = crusade_probe::probe_service(ip, port, &fp, &pcfg).await;
    assert_eq!(svc.transport, Transport::Tcp);

    // Store and search.
    let mut store = Store::open_in_memory().unwrap();
    let mut host = crusade_core::Host::new(ip);
    host.services.push(svc);
    store.upsert_host(&host).unwrap();

    // Found by port filter.
    let by_port = store
        .search(&parse(&format!("port:{port}")).unwrap(), 10, 0)
        .unwrap();
    assert_eq!(by_port.len(), 1, "host should be found by its open port");

    // Found by full-text over the HTTP title.
    let by_fts = store
        .search(&parse("\"Crusade Integration Rig\"").unwrap(), 10, 0)
        .unwrap();
    assert_eq!(
        by_fts.len(),
        1,
        "host should be found by its HTTP title via FTS"
    );
}

#[tokio::test]
async fn blocklist_guardrail_blocks_reserved_and_private() {
    // Reserved/documentation and private ranges never expand to targets with
    // the default blocklist (allow_private = false).
    let bl = Blocklist::new(false);
    assert!(
        expand_targets("192.0.2.0/24", &bl).unwrap().is_empty(),
        "TEST-NET-1 must be blocked"
    );
    assert!(
        expand_targets("10.0.0.0/30", &bl).unwrap().is_empty(),
        "RFC1918 must be blocked"
    );
    assert!(
        expand_targets("127.0.0.1", &bl).unwrap().is_empty(),
        "loopback blocked without allow_private"
    );

    // And the scanner never dispatches a blocked address even if handed one.
    let cfg = ScanConfig {
        ports: vec![9],
        connect_timeout: Duration::from_millis(200),
        rate: RateLimiterParams::default(),
        allow_private: false,
    };
    let scanner = TcpScanner::new(cfg, Blocklist::new(false));
    let open = scanner.scan(&[IpAddr::V4(Ipv4Addr::LOCALHOST)]).await;
    assert!(
        open.is_empty(),
        "scanner must skip a blocklisted (loopback) address"
    );

    let _ = SocketAddr::from(([127, 0, 0, 1], 0)); // silence unused import on some cfgs
}
