//! Crusade store: SQLite persistence, FTS search, and faceting.
//!
//! A [`Store`] wraps a single SQLite connection opened in WAL mode. Hosts are
//! written whole via [`Store::upsert_host`], which also appends to the
//! append-only service history and refreshes the FTS index. Reads come back as
//! fully reconstructed [`Host`] values from the stored JSON `doc`.

mod compile;

use anyhow::{Context, Result};
use crusade_core::model::Host;
use crusade_core::query::Query;
use rusqlite::{params, Connection, OptionalExtension};
use std::net::IpAddr;
use std::path::Path;

pub use compile::{compile, Compiled};

/// A handle to the Crusade database.
pub struct Store {
    conn: Connection,
}

/// One row in a facet (e.g. a port and how many hosts expose it).
#[derive(Debug, Clone, serde::Serialize)]
pub struct Facet {
    pub value: String,
    pub count: i64,
}

/// The faceted breakdown shown on the stats page.
#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct Facets {
    pub ports: Vec<Facet>,
    pub products: Vec<Facet>,
    pub countries: Vec<Facet>,
    pub asns: Vec<Facet>,
    pub tags: Vec<Facet>,
}

impl Store {
    /// Open (creating if needed) the database at `path` and apply the schema.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path).context("opening sqlite database")?;
        Self::init(conn)
    }

    /// Open an in-memory database (used by tests).
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().context("opening in-memory database")?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch(include_str!("schema.sql"))
            .context("applying schema")?;
        Ok(Store { conn })
    }

    /// Insert or update a host and all of its services atomically.
    ///
    /// Current-state rows in `hosts`/`services`/`tags` are replaced; every
    /// service is also appended to `service_history`; the FTS index for this
    /// IP is rebuilt from the host's banners, titles and cert names.
    pub fn upsert_host(&mut self, host: &Host) -> Result<()> {
        let ip = host.ip.to_string();
        let ip_sort = ip_sort_key(host.ip);
        let last_seen = host.last_seen.unix_timestamp();
        let doc = serde_json::to_string(host)?;
        let hostnames = host.hostnames.join(" ");

        let tx = self.conn.transaction()?;

        tx.execute(
            "INSERT INTO hosts (ip, asn, org, country, city, latitude, longitude, hostnames, ip_sort, last_seen, doc)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)
             ON CONFLICT(ip) DO UPDATE SET
               asn=excluded.asn, org=excluded.org, country=excluded.country,
               city=excluded.city, latitude=excluded.latitude, longitude=excluded.longitude,
               hostnames=excluded.hostnames, ip_sort=excluded.ip_sort,
               last_seen=excluded.last_seen, doc=excluded.doc",
            params![
                ip, host.asn, host.org, host.country, host.city,
                host.latitude, host.longitude, hostnames, ip_sort, last_seen, doc
            ],
        )?;

        // Replace current services for this host, and append history.
        tx.execute("DELETE FROM services WHERE ip = ?1", params![ip])?;
        let mut fts_body = String::new();
        for svc in &host.services {
            let transport = serde_json::to_value(svc.transport)?
                .as_str()
                .unwrap_or("tcp")
                .to_string();
            let ssl_cn = svc.tls.as_ref().and_then(|t| t.subject_cn.clone());
            let tls_version = svc.tls.as_ref().and_then(|t| t.version.clone());
            let has_shot = 0i64; // screenshots deferred to v3
            let (ssh_hostkey, hassh) = match &svc.ssh {
                Some(s) => (s.host_key_sha256.clone(), s.hassh.clone()),
                None => (None, None),
            };
            let favicon = svc.http.as_ref().and_then(|h| h.favicon_hash);
            let ics_protocol = svc.ics.as_ref().map(|i| i.protocol.clone());
            tx.execute(
                "INSERT INTO services
                   (ip, port, transport, service, product, version, cpe, ssl_cn,
                    jarm, favicon_hash, ssh_hostkey, hassh, tls_version, ics_protocol,
                    has_screenshot, observed_at, banner)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
                params![
                    ip, svc.port, transport, svc.service, svc.product, svc.version,
                    svc.cpe, ssl_cn, svc.jarm, favicon, ssh_hostkey, hassh, tls_version,
                    ics_protocol, has_shot, svc.observed_at.unix_timestamp(), svc.banner
                ],
            )?;
            tx.execute(
                "INSERT INTO service_history (ip, port, transport, observed_at, doc)
                 VALUES (?1,?2,?3,?4,?5)",
                params![
                    ip, svc.port, transport, svc.observed_at.unix_timestamp(),
                    serde_json::to_string(svc)?
                ],
            )?;

            // Collect searchable text.
            if let Some(b) = &svc.banner {
                fts_body.push_str(b);
                fts_body.push('\n');
            }
            if let Some(http) = &svc.http {
                if let Some(t) = &http.title {
                    fts_body.push_str(t);
                    fts_body.push('\n');
                }
                if let Some(s) = &http.server {
                    fts_body.push_str(s);
                    fts_body.push('\n');
                }
                for tech in &http.technologies {
                    fts_body.push_str(tech);
                    fts_body.push('\n');
                }
            }
            if let Some(ssh) = &svc.ssh {
                if let Some(b) = &ssh.banner {
                    fts_body.push_str(b);
                    fts_body.push('\n');
                }
            }
            if let Some(ics) = &svc.ics {
                for field in [&ics.vendor, &ics.product, &ics.device_id].into_iter().flatten() {
                    fts_body.push_str(field);
                    fts_body.push('\n');
                }
            }
            if let Some(cn) = &ssl_cn {
                fts_body.push_str(cn);
                fts_body.push('\n');
            }
        }

        // Replace tags.
        tx.execute("DELETE FROM tags WHERE ip = ?1", params![ip])?;
        for tag in &host.tags {
            tx.execute(
                "INSERT OR IGNORE INTO tags (ip, name, cve, detail) VALUES (?1,?2,?3,?4)",
                params![ip, tag.name, tag.cve, tag.detail],
            )?;
        }

        // Rebuild FTS for this IP.
        tx.execute("DELETE FROM banner_fts WHERE ip = ?1", params![ip])?;
        if !fts_body.is_empty() {
            tx.execute(
                "INSERT INTO banner_fts (ip, body) VALUES (?1, ?2)",
                params![ip, fts_body],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    /// Fetch one host by IP string, reconstructed from its stored JSON.
    pub fn get_host(&self, ip: &str) -> Result<Option<Host>> {
        let doc: Option<String> = self
            .conn
            .query_row("SELECT doc FROM hosts WHERE ip = ?1", params![ip], |r| r.get(0))
            .optional()?;
        match doc {
            Some(d) => Ok(Some(serde_json::from_str(&d)?)),
            None => Ok(None),
        }
    }

    /// Run a parsed query and return matching hosts (capped by `limit`).
    pub fn search(&self, query: &Query, limit: usize, offset: usize) -> Result<Vec<Host>> {
        let Compiled { sql, params } = compile(query);
        let sql = format!("{sql} LIMIT {limit} OFFSET {offset}");
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |r| {
            r.get::<_, String>(0)
        })?;

        let mut hosts = Vec::new();
        for ip in rows {
            let ip = ip?;
            if let Some(h) = self.get_host(&ip)? {
                hosts.push(h);
            }
        }
        Ok(hosts)
    }

    /// Count hosts matching a query (ignores limit/offset).
    pub fn count(&self, query: &Query) -> Result<i64> {
        let Compiled { sql, params } = compile(query);
        let sql = format!("SELECT COUNT(*) FROM ({sql})");
        let n: i64 = self
            .conn
            .query_row(&sql, rusqlite::params_from_iter(params.iter()), |r| r.get(0))?;
        Ok(n)
    }

    /// Compute the top-N facets across the whole dataset.
    pub fn facets(&self, top_n: usize) -> Result<Facets> {
        Ok(Facets {
            ports: self.facet_int("SELECT port, COUNT(DISTINCT ip) FROM services GROUP BY port ORDER BY 2 DESC LIMIT ?1", top_n)?,
            products: self.facet_text("SELECT product, COUNT(DISTINCT ip) FROM services WHERE product IS NOT NULL GROUP BY product ORDER BY 2 DESC LIMIT ?1", top_n)?,
            countries: self.facet_text("SELECT country, COUNT(*) FROM hosts WHERE country IS NOT NULL GROUP BY country ORDER BY 2 DESC LIMIT ?1", top_n)?,
            asns: self.facet_int("SELECT asn, COUNT(*) FROM hosts WHERE asn IS NOT NULL GROUP BY asn ORDER BY 2 DESC LIMIT ?1", top_n)?,
            tags: self.facet_text("SELECT name, COUNT(DISTINCT ip) FROM tags GROUP BY name ORDER BY 2 DESC LIMIT ?1", top_n)?,
        })
    }

    fn facet_text(&self, sql: &str, top_n: usize) -> Result<Vec<Facet>> {
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map(params![top_n as i64], |r| {
            Ok(Facet { value: r.get::<_, String>(0)?, count: r.get(1)? })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    fn facet_int(&self, sql: &str, top_n: usize) -> Result<Vec<Facet>> {
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map(params![top_n as i64], |r| {
            Ok(Facet { value: r.get::<_, i64>(0)?.to_string(), count: r.get(1)? })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Total number of hosts in the store.
    pub fn host_count(&self) -> Result<i64> {
        Ok(self.conn.query_row("SELECT COUNT(*) FROM hosts", [], |r| r.get(0))?)
    }

    /// All matching host IPs for a query (no limit) — used by export/stats.
    pub fn matching_ips(&self, query: &Query) -> Result<Vec<String>> {
        let Compiled { sql, params } = compile(query);
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |r| {
            r.get::<_, String>(0)
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Faceted breakdown restricted to the hosts matching `query`.
    pub fn facets_for_query(&self, query: &Query, top_n: usize) -> Result<Facets> {
        let Compiled { sql, params } = compile(query);
        // `sql` ends with "ORDER BY hosts.last_seen DESC"; strip it so the
        // select can be embedded as an IN (...) subquery.
        let sub = sql.split(" ORDER BY ").next().unwrap_or(&sql).to_string();
        Ok(Facets {
            ports: self.facet_sub_int(&format!("SELECT port, COUNT(DISTINCT s.ip) FROM services s WHERE s.ip IN ({sub}) GROUP BY port ORDER BY 2 DESC LIMIT ?"), &params, top_n)?,
            products: self.facet_sub_text(&format!("SELECT product, COUNT(DISTINCT s.ip) FROM services s WHERE product IS NOT NULL AND s.ip IN ({sub}) GROUP BY product ORDER BY 2 DESC LIMIT ?"), &params, top_n)?,
            countries: self.facet_sub_text(&format!("SELECT country, COUNT(*) FROM hosts WHERE country IS NOT NULL AND ip IN ({sub}) GROUP BY country ORDER BY 2 DESC LIMIT ?"), &params, top_n)?,
            asns: self.facet_sub_int(&format!("SELECT asn, COUNT(*) FROM hosts WHERE asn IS NOT NULL AND ip IN ({sub}) GROUP BY asn ORDER BY 2 DESC LIMIT ?"), &params, top_n)?,
            tags: self.facet_sub_text(&format!("SELECT name, COUNT(DISTINCT ip) FROM tags WHERE ip IN ({sub}) GROUP BY name ORDER BY 2 DESC LIMIT ?"), &params, top_n)?,
        })
    }

    fn facet_sub_text(&self, sql: &str, params: &[rusqlite::types::Value], top_n: usize) -> Result<Vec<Facet>> {
        let mut stmt = self.conn.prepare(sql)?;
        let mut binds: Vec<rusqlite::types::Value> = params.to_vec();
        binds.push(rusqlite::types::Value::Integer(top_n as i64));
        let rows = stmt.query_map(rusqlite::params_from_iter(binds.iter()), |r| {
            Ok(Facet { value: r.get::<_, String>(0)?, count: r.get(1)? })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    fn facet_sub_int(&self, sql: &str, params: &[rusqlite::types::Value], top_n: usize) -> Result<Vec<Facet>> {
        let mut stmt = self.conn.prepare(sql)?;
        let mut binds: Vec<rusqlite::types::Value> = params.to_vec();
        binds.push(rusqlite::types::Value::Integer(top_n as i64));
        let rows = stmt.query_map(rusqlite::params_from_iter(binds.iter()), |r| {
            Ok(Facet { value: r.get::<_, i64>(0)?.to_string(), count: r.get(1)? })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Host IPs not scanned since `cutoff` (unix seconds), oldest first — the
    /// rescan queue for `crusade monitor`.
    pub fn stale_host_ips(&self, cutoff: i64, limit: usize) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT ip FROM hosts WHERE last_seen < ?1 ORDER BY last_seen ASC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![cutoff, limit as i64], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Every host IP in the store (for a full rescan sweep).
    pub fn all_host_ips(&self) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare("SELECT ip FROM hosts ORDER BY last_seen ASC")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }
}

/// Produce a 16-byte big-endian sort key for an IP (IPv4 mapped into the IPv6
/// space) so lexicographic BLOB comparison matches numeric address order —
/// this backs `net:`/range queries for both families.
pub fn ip_sort_key(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

#[cfg(test)]
mod tests;
