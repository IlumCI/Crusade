use super::*;
use crusade_core::model::{Host, HttpInfo, Service, Tag, TlsCert, Transport};
use crusade_core::query::parse;
use std::net::IpAddr;
use time::OffsetDateTime;

fn host_with(ip: &str, port: u16, product: &str) -> Host {
    let mut h = Host::new(ip.parse::<IpAddr>().unwrap());
    h.country = Some("DE".into());
    h.asn = Some(3320);
    h.org = Some("Example Org".into());
    h.hostnames = vec![format!("host-{port}.example.com")];
    h.last_seen = OffsetDateTime::from_unix_timestamp(1_760_000_000).unwrap();
    let mut s = Service::new(port, Transport::Tcp);
    s.product = Some(product.into());
    s.version = Some("1.0".into());
    s.service = Some("http".into());
    s.banner = Some(format!("Welcome to {product} default page"));
    s.http = Some(HttpInfo { status: Some(200), server: Some(product.into()), title: Some("Index".into()), headers: vec![], favicon_hash: None, technologies: vec![], security_headers: vec![] });
    s.observed_at = h.last_seen;
    h.services.push(s);
    h.tags.push(Tag::simple("default-page"));
    h
}

#[test]
fn roundtrip_upsert_and_get() {
    let mut store = Store::open_in_memory().unwrap();
    let h = host_with("192.0.2.1", 80, "nginx");
    store.upsert_host(&h).unwrap();
    let got = store.get_host("192.0.2.1").unwrap().unwrap();
    assert_eq!(got.ip, h.ip);
    assert_eq!(got.services.len(), 1);
    assert_eq!(got.services[0].product.as_deref(), Some("nginx"));
}

#[test]
fn upsert_is_idempotent_on_current_state() {
    let mut store = Store::open_in_memory().unwrap();
    let h = host_with("192.0.2.2", 443, "nginx");
    store.upsert_host(&h).unwrap();
    store.upsert_host(&h).unwrap();
    assert_eq!(store.host_count().unwrap(), 1);
    // but history accumulates
    let n: i64 = store.conn.query_row("SELECT COUNT(*) FROM service_history WHERE ip='192.0.2.2'", [], |r| r.get(0)).unwrap();
    assert_eq!(n, 2);
}

#[test]
fn search_by_port_and_product() {
    let mut store = Store::open_in_memory().unwrap();
    store.upsert_host(&host_with("192.0.2.10", 22, "OpenSSH")).unwrap();
    store.upsert_host(&host_with("192.0.2.11", 80, "nginx")).unwrap();
    let r = store.search(&parse("port:80").unwrap(), 10, 0).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].ip.to_string(), "192.0.2.11");
    let r = store.search(&parse("product:ssh").unwrap(), 10, 0).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].ip.to_string(), "192.0.2.10");
}

#[test]
fn search_free_text_via_fts() {
    let mut store = Store::open_in_memory().unwrap();
    store.upsert_host(&host_with("192.0.2.20", 80, "nginx")).unwrap();
    let r = store.search(&parse("\"default page\"").unwrap(), 10, 0).unwrap();
    assert_eq!(r.len(), 1);
    let r = store.search(&parse("nonexistentword").unwrap(), 10, 0).unwrap();
    assert_eq!(r.len(), 0);
}

#[test]
fn negation_excludes() {
    let mut store = Store::open_in_memory().unwrap();
    store.upsert_host(&host_with("192.0.2.30", 80, "nginx")).unwrap();
    store.upsert_host(&host_with("192.0.2.31", 80, "apache")).unwrap();
    let r = store.search(&parse("-product:nginx").unwrap(), 10, 0).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].ip.to_string(), "192.0.2.31");
}

#[test]
fn facets_count_distinct_hosts() {
    let mut store = Store::open_in_memory().unwrap();
    store.upsert_host(&host_with("192.0.2.40", 80, "nginx")).unwrap();
    store.upsert_host(&host_with("192.0.2.41", 80, "nginx")).unwrap();
    store.upsert_host(&host_with("192.0.2.42", 22, "OpenSSH")).unwrap();
    let f = store.facets(10).unwrap();
    let port80 = f.ports.iter().find(|x| x.value == "80").unwrap();
    assert_eq!(port80.count, 2);
    let de = f.countries.iter().find(|x| x.value == "DE").unwrap();
    assert_eq!(de.count, 3);
}

#[test]
fn tls_cn_is_searchable() {
    let mut store = Store::open_in_memory().unwrap();
    let mut h = host_with("192.0.2.50", 443, "nginx");
    h.services[0].tls = Some(TlsCert {
        subject_cn: Some("secure.example.com".into()),
        issuer_cn: None, san: vec![], not_before: None, not_after: None,
        self_signed: true, fingerprint_sha256: None, version: None, cipher: None,
    });
    store.upsert_host(&h).unwrap();
    let r = store.search(&parse("ssl.cn:secure.example.com").unwrap(), 10, 0).unwrap();
    assert_eq!(r.len(), 1);
}
