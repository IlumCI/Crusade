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
    s.http = Some(HttpInfo {
        status: Some(200),
        server: Some(product.into()),
        title: Some("Index".into()),
        headers: vec![],
        favicon_hash: None,
        technologies: vec![],
        security_headers: vec![],
    });
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

    let history = |store: &Store| -> i64 {
        store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM service_history WHERE ip='192.0.2.2'",
                [],
                |r| r.get(0),
            )
            .unwrap()
    };

    // An unchanged rescan does not duplicate the timeline: history records
    // changes, not passes. Re-observing at a later time is not a change.
    assert_eq!(history(&store), 1);
    let mut again = h.clone();
    again.services[0].observed_at = h.services[0].observed_at + time::Duration::hours(1);
    store.upsert_host(&again).unwrap();
    assert_eq!(history(&store), 1);

    // A real change appends.
    let mut changed = h.clone();
    changed.services[0].version = Some("2.0".into());
    store.upsert_host(&changed).unwrap();
    assert_eq!(history(&store), 2);

    // And so does going back to the previous banner.
    store.upsert_host(&h).unwrap();
    assert_eq!(history(&store), 3);
}

#[test]
fn search_by_port_and_product() {
    let mut store = Store::open_in_memory().unwrap();
    store
        .upsert_host(&host_with("192.0.2.10", 22, "OpenSSH"))
        .unwrap();
    store
        .upsert_host(&host_with("192.0.2.11", 80, "nginx"))
        .unwrap();
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
    store
        .upsert_host(&host_with("192.0.2.20", 80, "nginx"))
        .unwrap();
    let r = store
        .search(&parse("\"default page\"").unwrap(), 10, 0)
        .unwrap();
    assert_eq!(r.len(), 1);
    let r = store
        .search(&parse("nonexistentword").unwrap(), 10, 0)
        .unwrap();
    assert_eq!(r.len(), 0);
}

#[test]
fn negation_excludes() {
    let mut store = Store::open_in_memory().unwrap();
    store
        .upsert_host(&host_with("192.0.2.30", 80, "nginx"))
        .unwrap();
    store
        .upsert_host(&host_with("192.0.2.31", 80, "apache"))
        .unwrap();
    let r = store
        .search(&parse("-product:nginx").unwrap(), 10, 0)
        .unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].ip.to_string(), "192.0.2.31");
}

#[test]
fn facets_count_distinct_hosts() {
    let mut store = Store::open_in_memory().unwrap();
    store
        .upsert_host(&host_with("192.0.2.40", 80, "nginx"))
        .unwrap();
    store
        .upsert_host(&host_with("192.0.2.41", 80, "nginx"))
        .unwrap();
    store
        .upsert_host(&host_with("192.0.2.42", 22, "OpenSSH"))
        .unwrap();
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
        issuer_cn: None,
        san: vec![],
        not_before: None,
        not_after: None,
        self_signed: true,
        fingerprint_sha256: None,
        version: None,
        cipher: None,
    });
    store.upsert_host(&h).unwrap();
    let r = store
        .search(&parse("ssl.cn:secure.example.com").unwrap(), 10, 0)
        .unwrap();
    assert_eq!(r.len(), 1);
}

#[test]
fn ics_service_is_stored_and_searchable() {
    use crusade_core::model::IcsInfo;
    let mut store = Store::open_in_memory().unwrap();
    let mut h = Host::new("192.0.2.77".parse().unwrap());
    h.last_seen = OffsetDateTime::from_unix_timestamp(1_760_000_000).unwrap();
    let mut s = Service::new(502, Transport::Tcp);
    s.service = Some("modbus".into());
    let mut ics = IcsInfo::new("modbus");
    ics.vendor = Some("Schneider Electric".into());
    ics.product = Some("BMXP34".into());
    s.ics = Some(ics);
    s.observed_at = h.last_seen;
    h.services.push(s);
    store.upsert_host(&h).unwrap();

    // ics: protocol filter
    let r = store.search(&parse("ics:modbus").unwrap(), 10, 0).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(
        r[0].services[0].ics.as_ref().unwrap().vendor.as_deref(),
        Some("Schneider Electric")
    );
    // has_ics boolean
    assert_eq!(
        store
            .search(&parse("has_ics:true").unwrap(), 10, 0)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store
            .search(&parse("has_ics:false").unwrap(), 10, 0)
            .unwrap()
            .len(),
        0
    );
    // vendor is full-text searchable
    assert_eq!(
        store
            .search(&parse("Schneider").unwrap(), 10, 0)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn auth_state_and_exploit_tag_searchable() {
    use crusade_core::model::{AuthState, Tag};
    let mut store = Store::open_in_memory().unwrap();
    let mut h = Host::new("192.0.2.88".parse().unwrap());
    h.last_seen = OffsetDateTime::from_unix_timestamp(1_760_000_000).unwrap();
    let mut s = Service::new(6379, Transport::Tcp);
    s.service = Some("redis".into());
    s.auth = Some(AuthState::Open);
    s.observed_at = h.last_seen;
    h.services.push(s);
    h.tags.push(Tag {
        name: "exploit-available".into(),
        cve: Some("CVE-2022-0543".into()),
        detail: Some("EDB-50124".into()),
    });
    store.upsert_host(&h).unwrap();

    assert_eq!(
        store
            .search(&parse("auth:open").unwrap(), 10, 0)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store
            .search(&parse("auth:required").unwrap(), 10, 0)
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        store
            .search(&parse("has_exploit:true").unwrap(), 10, 0)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store
            .search(&parse("-has_exploit:true").unwrap(), 10, 0)
            .unwrap()
            .len(),
        0
    );
    // round-trip preserves auth
    let got = store.get_host("192.0.2.88").unwrap().unwrap();
    assert_eq!(got.services[0].auth, Some(AuthState::Open));
}

#[test]
fn job_queue_enqueue_claim_finish() {
    let mut store = Store::open_in_memory().unwrap();
    store
        .enqueue_job("192.0.2.0/30", Some("80,443"), false, true)
        .unwrap();
    store
        .enqueue_job("198.51.100.5", None, true, false)
        .unwrap();
    assert_eq!(store.job_counts().unwrap(), (2, 0, 0, 0));

    let j1 = store.claim_next_job("w1").unwrap().unwrap();
    assert_eq!(j1.target, "192.0.2.0/30");
    assert_eq!(j1.ports.as_deref(), Some("80,443"));
    assert!(j1.ics && !j1.udp);
    assert_eq!(j1.status, "running");
    assert_eq!(store.job_counts().unwrap(), (1, 1, 0, 0)); // one claimed

    let j2 = store.claim_next_job("w2").unwrap().unwrap();
    assert_eq!(j2.target, "198.51.100.5");
    assert!(store.claim_next_job("w3").unwrap().is_none()); // queue drained

    store.finish_job(j1.id, true, "2 hosts").unwrap();
    store.finish_job(j2.id, false, "timeout").unwrap();
    assert_eq!(store.job_counts().unwrap(), (0, 0, 1, 1));
}

#[test]
fn honeypot_filter_and_port_sets() {
    use crusade_core::model::{HoneypotAssessment, HoneypotEvidence};
    let mut store = Store::open_in_memory().unwrap();
    let mut hp = host_with("192.0.2.10", 22, "OpenSSH");
    hp.honeypot = Some(HoneypotAssessment {
        score: 0.9,
        evidence: vec![HoneypotEvidence {
            signal: "rule:test".into(),
            weight: 0.9,
            detail: "test".into(),
        }],
    });
    let mut weak = host_with("192.0.2.11", 22, "OpenSSH");
    weak.honeypot = Some(HoneypotAssessment {
        score: 0.3,
        evidence: vec![],
    });
    let plain = host_with("192.0.2.12", 22, "OpenSSH");
    for h in [&hp, &weak, &plain] {
        store.upsert_host(h).unwrap();
    }
    let ips = |q: &str| -> Vec<String> {
        let mut v: Vec<String> = store
            .search(&parse(q).unwrap(), 10, 0)
            .unwrap()
            .into_iter()
            .map(|h| h.ip.to_string())
            .collect();
        v.sort();
        v
    };
    assert_eq!(ips("honeypot:true"), vec!["192.0.2.10"]);
    assert_eq!(ips("-honeypot:true"), vec!["192.0.2.11", "192.0.2.12"]);
    assert_eq!(ips("honeypot:false"), vec!["192.0.2.11", "192.0.2.12"]);
    assert_eq!(ips("honeypot:25"), vec!["192.0.2.10", "192.0.2.11"]);

    let back = store.get_host("192.0.2.10").unwrap().unwrap();
    assert_eq!(back.honeypot, hp.honeypot);
    assert_eq!(store.tcp_port_sets().unwrap().len(), 3);
}

#[test]
fn migrate_adds_honeypot_column_to_old_db() {
    let dir = std::env::temp_dir().join(format!("crusade-migrate-{}", std::process::id()));
    let _ = std::fs::remove_file(&dir);
    {
        let conn = rusqlite::Connection::open(&dir).unwrap();
        conn.execute_batch(
            "CREATE TABLE hosts (ip TEXT PRIMARY KEY, asn INTEGER, org TEXT, country TEXT,
             city TEXT, latitude REAL, longitude REAL, hostnames TEXT, ip_sort BLOB,
             last_seen INTEGER NOT NULL, doc TEXT NOT NULL);",
        )
        .unwrap();
    }
    let mut store = Store::open(&dir).unwrap();
    store
        .upsert_host(&host_with("192.0.2.20", 80, "nginx"))
        .unwrap();
    assert_eq!(
        store
            .search(&parse("-honeypot:true").unwrap(), 5, 0)
            .unwrap()
            .len(),
        1
    );
    drop(store);
    let _ = std::fs::remove_file(&dir);
}

#[test]
fn service_vectors_rank_and_follow_host_rewrites() {
    let mut store = Store::open_in_memory().unwrap();
    for (ip, port) in [("192.0.2.30", 80), ("192.0.2.31", 22), ("198.51.100.5", 80)] {
        store.upsert_host(&host_with(ip, port, "x")).unwrap();
    }
    let v = |a: i8, b: i8| vec![a, b];
    store
        .set_service_vectors("192.0.2.30", "m", &[(80, "tcp".into(), v(127, 0))])
        .unwrap();
    store
        .set_service_vectors("192.0.2.31", "m", &[(22, "tcp".into(), v(0, 127))])
        .unwrap();
    store
        .set_service_vectors("198.51.100.5", "m", &[(80, "tcp".into(), v(90, 90))])
        .unwrap();
    assert_eq!(store.vector_count("m").unwrap(), 3);

    let hits = store.similar_services("m", &v(127, 0), None, 10).unwrap();
    let order: Vec<&str> = hits.iter().map(|h| h.ip.as_str()).collect();
    assert_eq!(order, vec!["192.0.2.30", "198.51.100.5", "192.0.2.31"]);
    assert!((hits[0].score - 1.0).abs() < 1e-6);

    let only = parse("net:198.51.100.0/24").unwrap();
    let hits = store
        .similar_services("m", &v(127, 0), Some(&only), 10)
        .unwrap();
    assert_eq!(hits.len(), 1);
    assert!(store
        .similar_services("other", &v(127, 0), None, 10)
        .unwrap()
        .is_empty());
    assert_eq!(
        store.service_vector("m", "192.0.2.31", 22, "tcp").unwrap(),
        Some(v(0, 127))
    );

    // Re-indexing a host drops its now-stale vectors.
    store
        .upsert_host(&host_with("192.0.2.30", 80, "x"))
        .unwrap();
    assert_eq!(store.vector_count("m").unwrap(), 2);
}

#[test]
fn free_text_search_survives_the_fts_rekey_migration() {
    // An old database: banner_fts rows keyed by their own rowids (the schema-1
    // layout), deliberately offset from hosts.rowid so a stale index would be
    // detectable.
    let path = std::env::temp_dir().join(format!("crusade-fts-mig-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);
    {
        let mut store = Store::open(&path).unwrap();
        for i in 0..5u16 {
            store
                .upsert_host(&host_with(&format!("192.0.2.{}", 40 + i), 80 + i, "nginx"))
                .unwrap();
        }
        // Simulate schema 1: forget the version marker and rewrite the index
        // with mismatched rowids.
        store
            .conn
            .execute("DELETE FROM meta WHERE key = 'schema_version'", [])
            .unwrap();
        store.conn.execute_batch("DELETE FROM banner_fts").unwrap();
        let mut stmt = store
            .conn
            .prepare("SELECT rowid, ip FROM hosts ORDER BY rowid")
            .unwrap();
        let rows: Vec<(i64, String)> = stmt
            .query_map([], |r| Ok((r.get(0).unwrap(), r.get(1).unwrap())))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        drop(stmt);
        for (rowid, ip) in rows {
            store
                .conn
                .execute(
                    "INSERT INTO banner_fts (rowid, ip, body) VALUES (?1, ?2, ?3)",
                    rusqlite::params![rowid + 1000, ip, "Welcome to nginx default page"],
                )
                .unwrap();
        }
        // Stale index: the rowid join finds nothing.
        assert_eq!(
            store
                .search(&parse("\"default page\"").unwrap(), 10, 0)
                .unwrap()
                .len(),
            0
        );
    }

    // Reopening runs the migration and rebuilds the index.
    let store = Store::open(&path).unwrap();
    let hits = store
        .search(&parse("\"default page\"").unwrap(), 10, 0)
        .unwrap();
    assert_eq!(hits.len(), 5, "every host should be findable again");
    let version: String = store
        .conn
        .query_row(
            "SELECT value FROM meta WHERE key = 'schema_version'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(version, "2");
    drop(store);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn batch_upsert_matches_one_at_a_time_and_is_atomic() {
    let hosts: Vec<Host> = (0..20)
        .map(|i| host_with(&format!("198.51.100.{i}"), 80, "nginx"))
        .collect();

    let mut batched = Store::open_in_memory().unwrap();
    batched.upsert_hosts(&hosts).unwrap();
    let mut single = Store::open_in_memory().unwrap();
    for h in &hosts {
        single.upsert_host(h).unwrap();
    }

    let q = parse("product:nginx \"default page\"").unwrap();
    assert_eq!(batched.count(&q).unwrap(), 20);
    assert_eq!(batched.count(&q).unwrap(), single.count(&q).unwrap());
    assert_eq!(batched.host_count().unwrap(), single.host_count().unwrap());

    // Re-batching the same hosts replaces rather than duplicates.
    batched.upsert_hosts(&hosts).unwrap();
    assert_eq!(batched.count(&q).unwrap(), 20);
    assert!(batched.upsert_hosts(&[]).is_ok());
}

#[test]
fn capped_count_reports_whether_it_is_exact() {
    let mut store = Store::open_in_memory().unwrap();
    let hosts: Vec<Host> = (0..30)
        .map(|i| host_with(&format!("203.0.113.{i}"), 80, "nginx"))
        .collect();
    store.upsert_hosts(&hosts).unwrap();

    let all = parse("port:80").unwrap();
    assert_eq!(store.count(&all).unwrap(), 30);
    // Under the cap: exact.
    assert_eq!(store.count_capped(&all, 100).unwrap(), (30, true));
    // At or over the cap: a floor, flagged inexact.
    assert_eq!(store.count_capped(&all, 10).unwrap(), (10, false));
    assert_eq!(store.count_capped(&all, 30).unwrap(), (30, false));
    // No matches is always exact.
    let none = parse("port:9999").unwrap();
    assert_eq!(store.count_capped(&none, 10).unwrap(), (0, true));
}

#[test]
fn facet_cache_serves_repeats_and_invalidates_on_write() {
    let mut store = Store::open_in_memory().unwrap();
    store
        .upsert_host(&host_with("192.0.2.60", 80, "nginx"))
        .unwrap();
    store
        .upsert_host(&host_with("192.0.2.61", 443, "nginx"))
        .unwrap();

    let all = parse("").unwrap();
    let gen1 = store.write_generation();
    assert!(gen1 > 0, "writes bump the generation");

    let first = store.facets_cached(&all, 10).unwrap();
    assert_eq!(first.ports.len(), 2);
    // Served from cache: same generation, same answer.
    let second = store.facets_cached(&all, 10).unwrap();
    assert_eq!(
        second
            .ports
            .iter()
            .map(|f| f.value.clone())
            .collect::<Vec<_>>(),
        first
            .ports
            .iter()
            .map(|f| f.value.clone())
            .collect::<Vec<_>>()
    );
    let cached: i64 = store
        .conn
        .query_row("SELECT count(*) FROM facet_cache", [], |r| r.get(0))
        .unwrap();
    assert_eq!(cached, 1);

    // A new host must not be served a stale aggregate.
    store
        .upsert_host(&host_with("192.0.2.62", 22, "OpenSSH"))
        .unwrap();
    assert!(store.write_generation() > gen1);
    let third = store.facets_cached(&all, 10).unwrap();
    assert_eq!(third.ports.len(), 3, "cache was recomputed after the write");
    assert!(third.products.iter().any(|f| f.value == "OpenSSH"));

    // A scoped query is cached separately from the whole dataset.
    let scoped = parse("port:80").unwrap();
    let s = store.facets_cached(&scoped, 10).unwrap();
    assert_eq!(s.ports.len(), 1);
    let keys: i64 = store
        .conn
        .query_row("SELECT count(*) FROM facet_cache", [], |r| r.get(0))
        .unwrap();
    assert_eq!(keys, 2);

    // Deleting a host invalidates too.
    let gen = store.write_generation();
    store.delete_host("192.0.2.62").unwrap();
    assert!(store.write_generation() > gen);
    assert_eq!(store.facets_cached(&all, 10).unwrap().ports.len(), 2);

    // Re-scoring (tags only) invalidates, since tags are faceted.
    let mut h = store.get_host("192.0.2.60").unwrap().unwrap();
    h.tags.push(crusade_core::model::Tag::simple("honeypot"));
    let gen = store.write_generation();
    store.update_derived(&h).unwrap();
    assert!(store.write_generation() > gen);
    assert!(store
        .facets_cached(&all, 10)
        .unwrap()
        .tags
        .iter()
        .any(|f| f.value == "honeypot"));
}

#[test]
fn ipv6_seeds_exclude_ipv4_hosts() {
    let mut store = Store::open_in_memory().unwrap();
    let mut v6 = host_with("192.0.2.1", 80, "nginx");
    v6.ip = "2a00:1450:4001::1".parse().unwrap();
    let mut v6b = host_with("192.0.2.2", 443, "nginx");
    v6b.ip = "2606:4700::1".parse().unwrap();
    store
        .upsert_host(&host_with("198.51.100.1", 80, "nginx"))
        .unwrap();
    store.upsert_host(&v6).unwrap();
    store.upsert_host(&v6b).unwrap();

    let seeds = store.ipv6_host_ips(10).unwrap();
    assert_eq!(seeds.len(), 2, "only IPv6 hosts are seeds: {seeds:?}");
    assert!(seeds.contains(&"2a00:1450:4001::1".parse().unwrap()));
    assert_eq!(store.ipv6_host_ips(1).unwrap().len(), 1, "limit applies");
}

#[test]
fn aliased_prefixes_persist_and_age_out() {
    let store = Store::open_in_memory().unwrap();
    const NOW: i64 = 1_800_000_000;
    const DAY: i64 = 86_400;

    store
        .record_aliased_prefix("2606:4700::/32", NOW - 10 * DAY)
        .unwrap();
    store
        .record_aliased_prefix("2a00:1450::/32", NOW - 200 * DAY)
        .unwrap();

    // Fresh enough to reuse.
    let recent = store.aliased_prefixes(NOW, 30 * DAY).unwrap();
    assert_eq!(recent, vec!["2606:4700::/32"], "the old one has aged out");
    // A longer window includes both.
    assert_eq!(store.aliased_prefixes(NOW, 365 * DAY).unwrap().len(), 2);
    // Zero window trusts nothing.
    assert!(store.aliased_prefixes(NOW, 0).unwrap().is_empty());

    // Re-checking refreshes rather than duplicating.
    store.record_aliased_prefix("2a00:1450::/32", NOW).unwrap();
    assert_eq!(
        store.aliased_prefixes(NOW, DAY).unwrap(),
        vec!["2a00:1450::/32"]
    );
    let total: i64 = store
        .conn
        .query_row("SELECT count(*) FROM aliased_prefix", [], |r| r.get(0))
        .unwrap();
    assert_eq!(total, 2, "no duplicate rows");
}

#[test]
fn scan_salt_is_stable_and_background_cursor_advances() {
    let path = std::env::temp_dir().join(format!("crusade-sched-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);

    let salt = {
        let mut store = Store::open(&path).unwrap();
        let salt = store.scan_salt().unwrap();
        assert_ne!(salt, 0);
        // Stable within a session: a second call must not reshuffle coverage.
        assert_eq!(store.scan_salt().unwrap(), salt);

        store
            .upsert_host(&host_with("192.0.2.70", 80, "nginx"))
            .unwrap();
        assert_eq!(store.background_cursor("192.0.2.70").unwrap(), 0);
        store.set_background_cursor("192.0.2.70", 300).unwrap();
        assert_eq!(store.background_cursor("192.0.2.70").unwrap(), 300);
        // An unknown host reads as not started rather than failing.
        assert_eq!(store.background_cursor("203.0.113.9").unwrap(), 0);
        salt
    };

    // Stable across reopen: this is what makes coverage resumable.
    let store = Store::open(&path).unwrap();
    assert_eq!(store.scan_salt().unwrap(), salt);
    assert_eq!(store.background_cursor("192.0.2.70").unwrap(), 300);
    drop(store);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn rescanning_a_host_preserves_its_background_cursor() {
    let mut store = Store::open_in_memory().unwrap();
    let host = host_with("192.0.2.71", 80, "nginx");
    store.upsert_host(&host).unwrap();
    store.set_background_cursor("192.0.2.71", 1200).unwrap();
    // A normal upsert must not reset coverage progress.
    store.upsert_host(&host).unwrap();
    assert_eq!(store.background_cursor("192.0.2.71").unwrap(), 1200);
}

#[test]
fn clustering_reads_identifiers_and_stores_assignments() {
    use crusade_core::{LinkKind, Linker};
    let mut store = Store::open_in_memory().unwrap();

    // Two hosts sharing a certificate subject, plus background noise so the
    // rarity filter has a population to judge against.
    for i in 0..40u8 {
        let mut h = host_with(&format!("10.0.0.{i}"), 443, "nginx");
        h.services[0].jarm = Some(format!("jarm-{i}"));
        store.upsert_host(&h).unwrap();
    }
    for ip in ["192.0.2.1", "192.0.2.2"] {
        let mut h = host_with(ip, 443, "nginx");
        h.services[0].tls = Some(crusade_core::model::TlsCert {
            subject_cn: Some("shared.example.com".into()),
            issuer_cn: None,
            san: vec![],
            not_before: None,
            not_after: None,
            self_signed: true,
            fingerprint_sha256: Some("sha256:aaa".into()),
            version: None,
            cipher: None,
        });
        store.upsert_host(&h).unwrap();
    }

    let ids = store.link_identifiers().unwrap();
    assert_eq!(ids.len(), 42, "one entry per host");
    let shared: Vec<&(String, Vec<crusade_core::Identifier>)> = ids
        .iter()
        .filter(|(ip, _)| ip.starts_with("192.0.2."))
        .collect();
    assert_eq!(shared.len(), 2);
    assert!(shared[0]
        .1
        .iter()
        .any(|i| i.kind == LinkKind::Certificate && i.value == "shared.example.com"));

    let mut linker = Linker::new();
    for (ip, identifiers) in ids {
        linker.add(ip, identifiers);
    }
    let clusters = linker.clusters();
    assert_eq!(clusters.len(), 1, "{clusters:?}");
    assert_eq!(clusters[0].members, vec!["192.0.2.1", "192.0.2.2"]);

    // Persist and search.
    let assignments: Vec<(String, String)> = clusters
        .iter()
        .flat_map(|c| c.members.iter().map(|m| (m.clone(), c.id.clone())))
        .collect();
    store.set_clusters(&assignments).unwrap();
    assert_eq!(
        store.cluster_members("192.0.2.1").unwrap(),
        vec!["192.0.2.1", "192.0.2.2"]
    );
    let found = store
        .search(&parse("cluster:192.0.2.1").unwrap(), 10, 0)
        .unwrap();
    assert_eq!(found.len(), 2);
    // Re-clustering replaces rather than accumulating.
    store.set_clusters(&[]).unwrap();
    assert!(store.cluster_members("192.0.2.1").unwrap().is_empty());
    assert_eq!(
        store
            .search(&parse("cluster:192.0.2.1").unwrap(), 10, 0)
            .unwrap()
            .len(),
        0
    );
}
