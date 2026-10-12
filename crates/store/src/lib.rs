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

pub use compile::{compile, compile_count, Compiled};

/// Bring databases created by older versions up to the current schema.
/// `CREATE TABLE IF NOT EXISTS` never adds columns, so new ones go here.
fn migrate(conn: &Connection) -> Result<()> {
    let has_column = |table: &str, col: &str| -> Result<bool> {
        let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
        let names = stmt.query_map([], |r| r.get::<_, String>(1))?;
        for n in names {
            if n? == col {
                return Ok(true);
            }
        }
        Ok(false)
    };
    if !has_column("hosts", "honeypot")? {
        conn.execute_batch("ALTER TABLE hosts ADD COLUMN honeypot REAL")?;
    }
    if !has_column("services", "pending_since")? {
        conn.execute_batch("ALTER TABLE services ADD COLUMN pending_since INTEGER")?;
    }
    if !has_column("services", "content_hash")? {
        conn.execute_batch("ALTER TABLE services ADD COLUMN content_hash INTEGER")?;
    }
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_services_pending ON services(pending_since)",
    )?;
    conn.execute_batch("CREATE INDEX IF NOT EXISTS idx_hosts_honeypot ON hosts(honeypot)")?;

    // Schema 2 re-keyed banner_fts by hosts.rowid. Rows written by an earlier
    // version carry unrelated rowids, so free-text search would silently miss
    // or mismatch them: rebuild the index once from the stored host documents.
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    )?;
    let version: i64 = conn
        .query_row(
            "SELECT value FROM meta WHERE key = 'schema_version'",
            [],
            |r| r.get::<_, String>(0),
        )
        .optional()?
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    if version < 2 {
        let hosts: i64 = conn.query_row("SELECT count(*) FROM hosts", [], |r| r.get(0))?;
        if hosts > 0 {
            conn.execute_batch("DELETE FROM banner_fts")?;
            let mut stmt = conn.prepare("SELECT rowid, ip, doc FROM hosts")?;
            let rows: Vec<(i64, String, String)> = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<std::result::Result<_, _>>()?;
            drop(stmt);
            let mut insert =
                conn.prepare("INSERT INTO banner_fts (rowid, ip, body) VALUES (?1, ?2, ?3)")?;
            for (rowid, ip, doc) in rows {
                let Ok(host) = serde_json::from_str::<Host>(&doc) else {
                    continue;
                };
                let body = fts_body(&host);
                if !body.is_empty() {
                    insert.execute(params![rowid, ip, body])?;
                }
            }
        }
        conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', '2')",
            [],
        )?;
    }
    Ok(())
}

/// Note that the data behind cached aggregates has changed.
///
/// Bumped once per write transaction rather than per host: a batch of 500
/// hosts invalidates the cache exactly as a single host does, and one extra
/// statement per batch is free.
fn bump_generation(tx: &rusqlite::Transaction<'_>) -> Result<()> {
    tx.execute(
        "INSERT INTO meta (key, value) VALUES ('write_generation', '1')
         ON CONFLICT(key) DO UPDATE SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT)",
        [],
    )?;
    Ok(())
}

/// Write one host's current state, scan history, tags and FTS row inside an
/// existing transaction. Shared by [`Store::upsert_host`] and
/// [`Store::upsert_hosts`].
fn write_host(tx: &rusqlite::Transaction<'_>, host: &Host) -> Result<()> {
    let ip = host.ip.to_string();
    let ip_sort = ip_sort_key(host.ip);
    let last_seen = host.last_seen.unix_timestamp();
    let doc = serde_json::to_string(host)?;
    let hostnames = host.hostnames.join(" ");

    tx.prepare_cached(
        "INSERT INTO hosts (ip, asn, org, country, city, latitude, longitude, hostnames, ip_sort, last_seen, doc, honeypot)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)
         ON CONFLICT(ip) DO UPDATE SET
           asn=excluded.asn, org=excluded.org, country=excluded.country,
           city=excluded.city, latitude=excluded.latitude, longitude=excluded.longitude,
           hostnames=excluded.hostnames, ip_sort=excluded.ip_sort,
           last_seen=excluded.last_seen, doc=excluded.doc, honeypot=excluded.honeypot",
    )?
    .execute(
        params![
            ip, host.asn, host.org, host.country, host.city,
            host.latitude, host.longitude, hostnames, ip_sort, last_seen, doc,
            host.honeypot.as_ref().map(|h| f64::from(h.score))
        ],
    )?;

    // What we already knew about this host's services, so history only grows
    // when something actually changed.
    let mut prior: std::collections::HashMap<(u16, String), i64> = std::collections::HashMap::new();
    {
        let mut stmt =
            tx.prepare_cached("SELECT port, transport, content_hash FROM services WHERE ip = ?1")?;
        let rows = stmt.query_map(params![ip], |r| {
            Ok((
                r.get::<_, u16>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<i64>>(2)?,
            ))
        })?;
        for row in rows {
            let (port, transport, hash) = row?;
            if let Some(hash) = hash {
                prior.insert((port, transport), hash);
            }
        }
    }

    // Replace current services for this host, and append history. Their
    // embedding vectors describe the old services, so they go too.
    tx.prepare_cached("DELETE FROM services WHERE ip = ?1")?
        .execute(params![ip])?;
    tx.prepare_cached("DELETE FROM service_vec WHERE ip = ?1")?
        .execute(params![ip])?;
    let mut fts_body = String::new();
    for svc in &host.services {
        let transport = serde_json::to_value(svc.transport)?
            .as_str()
            .unwrap_or("tcp")
            .to_string();
        let ssl_cn = svc.tls.as_ref().and_then(|t| t.subject_cn.clone());
        let tls_version = svc.tls.as_ref().and_then(|t| t.version.clone());
        let has_shot = i64::from(svc.screenshot.is_some());
        let (ssh_hostkey, hassh) = match &svc.ssh {
            Some(s) => (s.host_key_sha256.clone(), s.hassh.clone()),
            None => (None, None),
        };
        let favicon = svc.http.as_ref().and_then(|h| h.favicon_hash);
        let ics_protocol = svc.ics.as_ref().map(|i| i.protocol.clone());
        let auth_state = svc
            .auth
            .and_then(|a| serde_json::to_value(a).ok())
            .and_then(|v| v.as_str().map(str::to_string));
        let content_hash = service_content_hash(svc);
        tx.prepare_cached(
            "INSERT INTO services
               (ip, port, transport, service, product, version, cpe, ssl_cn,
                jarm, favicon_hash, ssh_hostkey, hassh, tls_version, ics_protocol,
                auth_state, screenshot, has_screenshot, pending_since, observed_at, banner,
                content_hash)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21)",
        )?
        .execute(params![
            ip,
            svc.port,
            transport,
            svc.service,
            svc.product,
            svc.version,
            svc.cpe,
            ssl_cn,
            svc.jarm,
            favicon,
            ssh_hostkey,
            hassh,
            tls_version,
            ics_protocol,
            auth_state,
            svc.screenshot,
            has_shot,
            svc.pending_since.map(|t| t.unix_timestamp()),
            svc.observed_at.unix_timestamp(),
            svc.banner,
            content_hash
        ])?;
        // Append to the timeline only when this observation differs from the
        // last one: an unchanged rescan would otherwise duplicate the whole
        // service document on every pass.
        if prior.get(&(svc.port, transport.clone())) != Some(&content_hash) {
            tx.prepare_cached(
                "INSERT INTO service_history (ip, port, transport, observed_at, doc)
             VALUES (?1,?2,?3,?4,?5)",
            )?
            .execute(params![
                ip,
                svc.port,
                transport,
                svc.observed_at.unix_timestamp(),
                serde_json::to_string(svc)?
            ])?;
        }

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
            for field in [&ics.vendor, &ics.product, &ics.device_id]
                .into_iter()
                .flatten()
            {
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
    tx.prepare_cached("DELETE FROM tags WHERE ip = ?1")?
        .execute(params![ip])?;
    for tag in &host.tags {
        tx.prepare_cached(
            "INSERT OR IGNORE INTO tags (ip, name, cve, detail) VALUES (?1,?2,?3,?4)",
        )?
        .execute(params![ip, tag.name, tag.cve, tag.detail])?;
    }

    // Rebuild the FTS row for this host, keyed by its rowid. `ip` is an
    // UNINDEXED FTS5 column, so deleting by it scans the whole index and
    // makes bulk ingest quadratic.
    let rowid: i64 = tx
        .prepare_cached("SELECT rowid FROM hosts WHERE ip = ?1")?
        .query_row(params![ip], |r| r.get(0))?;
    tx.prepare_cached("DELETE FROM banner_fts WHERE rowid = ?1")?
        .execute(params![rowid])?;
    if !fts_body.is_empty() {
        tx.prepare_cached("INSERT INTO banner_fts (rowid, ip, body) VALUES (?1, ?2, ?3)")?
            .execute(params![rowid, ip, fts_body])?;
    }

    Ok(())
}

/// A stable 64-bit hash (FNV-1a) of a service with its volatile timestamps
/// cleared, so re-observing an unchanged service produces the same value.
///
/// Rescans mostly see no change, and appending an identical snapshot to
/// `service_history` on every pass is the single largest source of write
/// amplification and disk growth. Comparing hashes lets the history stay a
/// record of *changes* (the delta-encoding idea from Censys, SIGCOMM 2025)
/// while the timeline keeps its exact meaning.
fn service_content_hash(svc: &crusade_core::Service) -> i64 {
    let mut stable = svc.clone();
    stable.observed_at = time::OffsetDateTime::UNIX_EPOCH;
    stable.pending_since = None;
    let json = serde_json::to_string(&stable).unwrap_or_default();
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in json.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x1000_0000_01b3);
    }
    hash as i64
}

/// The searchable text of a host: banners, HTTP titles/servers/technologies,
/// SSH banners, ICS identity and TLS subject names. Used to (re)build the FTS
/// index, including when migrating an older database.
fn fts_body(host: &Host) -> String {
    let mut body = String::new();
    let mut push = |s: &str| {
        body.push_str(s);
        body.push('\n');
    };
    for svc in &host.services {
        if let Some(b) = &svc.banner {
            push(b);
        }
        if let Some(http) = &svc.http {
            if let Some(t) = &http.title {
                push(t);
            }
            if let Some(s) = &http.server {
                push(s);
            }
            for tech in &http.technologies {
                push(tech);
            }
        }
        if let Some(ssh) = &svc.ssh {
            if let Some(b) = &ssh.banner {
                push(b);
            }
        }
        if let Some(ics) = &svc.ics {
            for field in [&ics.vendor, &ics.product, &ics.device_id]
                .into_iter()
                .flatten()
            {
                push(field);
            }
        }
        if let Some(cn) = svc.tls.as_ref().and_then(|t| t.subject_cn.as_deref()) {
            push(cn);
        }
    }
    body
}

/// A handle to the Crusade database.
pub struct Store {
    conn: Connection,
}

/// One row in a facet (e.g. a port and how many hosts expose it).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Facet {
    pub value: String,
    pub count: i64,
}

/// The faceted breakdown shown on the stats page.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct Facets {
    pub ports: Vec<Facet>,
    pub products: Vec<Facet>,
    pub countries: Vec<Facet>,
    pub asns: Vec<Facet>,
    pub tags: Vec<Facet>,
}

/// A queued scan job claimed by a `crusade worker`.
/// One service ranked by embedding similarity.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SimilarHit {
    pub ip: String,
    pub port: u16,
    pub transport: String,
    pub score: f32,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Job {
    pub id: i64,
    pub target: String,
    pub ports: Option<String>,
    pub udp: bool,
    pub ics: bool,
    pub status: String,
    pub worker: Option<String>,
    pub note: Option<String>,
}

/// An alert row raised by the monitor and (optionally) delivered to transports.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Alert {
    pub id: i64,
    pub ts: i64,
    pub ip: String,
    pub kind: String,
    pub detail: String,
    pub delivered: bool,
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
        // Tolerate concurrent writers (multiple workers + web + monitor on the
        // same WAL database) instead of failing immediately on a locked DB.
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute_batch(include_str!("schema.sql"))
            .context("applying schema")?;
        migrate(&conn).context("migrating schema")?;
        Ok(Store { conn })
    }

    /// Rewrite a host's derived data (doc, honeypot score, tags) without
    /// touching services or appending history. Used when re-scoring.
    pub fn update_derived(&mut self, host: &Host) -> Result<()> {
        let ip = host.ip.to_string();
        let doc = serde_json::to_string(host)?;
        let tx = self.conn.transaction()?;
        tx.execute(
            "UPDATE hosts SET doc = ?2, honeypot = ?3 WHERE ip = ?1",
            params![ip, doc, host.honeypot.as_ref().map(|h| f64::from(h.score))],
        )?;
        tx.execute("DELETE FROM tags WHERE ip = ?1", params![ip])?;
        for tag in &host.tags {
            tx.execute(
                "INSERT OR IGNORE INTO tags (ip, name, cve, detail) VALUES (?1,?2,?3,?4)",
                params![ip, tag.name, tag.cve, tag.detail],
            )?;
        }
        bump_generation(&tx)?;
        tx.commit()?;
        Ok(())
    }

    /// Remove a host and everything attached to it (services, tags, vectors,
    /// history). Used when a host has had nothing listening for a long time.
    pub fn delete_host(&mut self, ip: &str) -> Result<()> {
        let tx = self.conn.transaction()?;
        // FTS rows are keyed by the host rowid, so drop them before the host.
        let rowid: Option<i64> = tx
            .query_row("SELECT rowid FROM hosts WHERE ip = ?1", params![ip], |r| {
                r.get(0)
            })
            .optional()?;
        if let Some(rowid) = rowid {
            tx.execute("DELETE FROM banner_fts WHERE rowid = ?1", params![rowid])?;
        }
        for table in ["services", "service_vec", "tags", "service_history"] {
            tx.execute(&format!("DELETE FROM {table} WHERE ip = ?1"), params![ip])?;
        }
        tx.execute("DELETE FROM hosts WHERE ip = ?1", params![ip])?;
        bump_generation(&tx)?;
        tx.commit()?;
        Ok(())
    }

    /// Replace the embedding vectors of one host's services.
    /// `vecs` holds `(port, transport, int8 vector)`.
    pub fn set_service_vectors(
        &mut self,
        ip: &str,
        model: &str,
        vecs: &[(u16, String, Vec<i8>)],
    ) -> Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM service_vec WHERE ip = ?1", params![ip])?;
        for (port, transport, v) in vecs {
            let blob: Vec<u8> = v.iter().map(|&x| x as u8).collect();
            tx.execute(
                "INSERT OR REPLACE INTO service_vec (ip, port, transport, model, vec)
                 VALUES (?1,?2,?3,?4,?5)",
                params![ip, port, transport, model, blob],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// The stored vector of one service under `model`.
    pub fn service_vector(
        &self,
        model: &str,
        ip: &str,
        port: u16,
        transport: &str,
    ) -> Result<Option<Vec<i8>>> {
        let blob: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT vec FROM service_vec WHERE ip=?1 AND port=?2 AND transport=?3 AND model=?4",
                params![ip, port, transport, model],
                |r| r.get(0),
            )
            .optional()?;
        Ok(blob.map(|b| b.into_iter().map(|x| x as i8).collect()))
    }

    /// Number of stored vectors under `model`.
    pub fn vector_count(&self, model: &str) -> Result<i64> {
        Ok(self.conn.query_row(
            "SELECT count(*) FROM service_vec WHERE model = ?1",
            params![model],
            |r| r.get(0),
        )?)
    }

    /// Exact nearest services to `query` (cosine over int8 normalised
    /// vectors), optionally restricted to hosts matching `restrict`.
    pub fn similar_services(
        &self,
        model: &str,
        query: &[i8],
        restrict: Option<&Query>,
        limit: usize,
    ) -> Result<Vec<SimilarHit>> {
        let allowed: Option<std::collections::HashSet<String>> = match restrict {
            Some(q) => Some(self.matching_ips(q)?.into_iter().collect()),
            None => None,
        };
        let mut stmt = self
            .conn
            .prepare("SELECT ip, port, transport, vec FROM service_vec WHERE model = ?1")?;
        let rows = stmt.query_map(params![model], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, u16>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Vec<u8>>(3)?,
            ))
        })?;
        let mut hits: Vec<SimilarHit> = Vec::new();
        for row in rows {
            let (ip, port, transport, blob) = row?;
            if allowed.as_ref().is_some_and(|a| !a.contains(&ip)) {
                continue;
            }
            if blob.len() != query.len() {
                continue;
            }
            let dot: i32 = blob
                .iter()
                .zip(query)
                .map(|(&b, &q)| i32::from(b as i8) * i32::from(q))
                .sum();
            hits.push(SimilarHit {
                ip,
                port,
                transport,
                // Quantisation rounding can push a self-match past 1.
                score: (dot as f32 / (127.0 * 127.0)).clamp(-1.0, 1.0),
            });
        }
        hits.sort_by(|a, b| b.score.total_cmp(&a.score));
        hits.truncate(limit);
        Ok(hits)
    }

    /// TCP port sets of every indexed host, for co-occurrence statistics.
    pub fn tcp_port_sets(&self) -> Result<Vec<Vec<u16>>> {
        let mut stmt = self.conn.prepare(
            "SELECT ip, group_concat(port) FROM services WHERE transport = 'tcp' GROUP BY ip",
        )?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(1))?;
        let mut out = Vec::new();
        for row in rows {
            let ports = row?
                .split(',')
                .filter_map(|p| p.parse::<u16>().ok())
                .collect();
            out.push(ports);
        }
        Ok(out)
    }

    /// Insert or update a host and all of its services atomically.
    ///
    /// Current-state rows in `hosts`/`services`/`tags` are replaced; every
    /// service is also appended to `service_history`; the FTS index for this
    /// IP is rebuilt from the host's banners, titles and cert names.
    pub fn upsert_host(&mut self, host: &Host) -> Result<()> {
        let tx = self.conn.transaction()?;
        write_host(&tx, host)?;
        bump_generation(&tx)?;
        tx.commit()?;
        Ok(())
    }

    /// Upsert many hosts in a single transaction.
    ///
    /// Bulk ingest is dominated by per-transaction commit cost, so sweeps and
    /// backfills should batch rather than calling [`Store::upsert_host`] in a
    /// loop. Either every host in the batch is written or none is.
    pub fn upsert_hosts(&mut self, hosts: &[Host]) -> Result<()> {
        if hosts.is_empty() {
            return Ok(());
        }
        let tx = self.conn.transaction()?;
        for host in hosts {
            write_host(&tx, host)?;
        }
        bump_generation(&tx)?;
        tx.commit()?;
        Ok(())
    }

    /// Fetch one host by IP string, reconstructed from its stored JSON.
    pub fn get_host(&self, ip: &str) -> Result<Option<Host>> {
        let doc: Option<String> = self
            .conn
            .query_row("SELECT doc FROM hosts WHERE ip = ?1", params![ip], |r| {
                r.get(0)
            })
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
        let Compiled { sql, params } = compile_count(query);
        let sql = format!("SELECT COUNT(*) FROM ({sql})");
        let n: i64 = self
            .conn
            .query_row(&sql, rusqlite::params_from_iter(params.iter()), |r| {
                r.get(0)
            })?;
        Ok(n)
    }

    /// Count matches, stopping once `cap` is reached.
    ///
    /// An exact count scans every matching row, which at millions of hosts
    /// costs far more than the page of results the caller is about to show.
    /// Returns `(count, exact)`: when `exact` is false the real total is at
    /// least `count`, and callers should render it as "N+".
    pub fn count_capped(&self, query: &Query, cap: i64) -> Result<(i64, bool)> {
        let Compiled { sql, params } = compile_count(query);
        let sql = format!("SELECT COUNT(*) FROM (SELECT 1 FROM ({sql}) LIMIT {cap})");
        let n: i64 = self
            .conn
            .query_row(&sql, rusqlite::params_from_iter(params.iter()), |r| {
                r.get(0)
            })?;
        Ok((n, n < cap))
    }

    /// The current write generation (0 before any write).
    pub fn write_generation(&self) -> i64 {
        self.conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'write_generation'",
                [],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .ok()
            .flatten()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    }

    /// Facets for `query` (empty = whole dataset), served from the cache when
    /// the data behind it has not changed since it was computed.
    ///
    /// Faceting the whole index is a full scan — seconds at a few hundred
    /// thousand hosts — and the stats page would otherwise pay it on every
    /// view. Writes bump a generation counter, so a stale entry is never
    /// served: it is recomputed and replaced.
    pub fn facets_cached(&self, query: &Query, top_n: usize) -> Result<Facets> {
        let rendered = query.to_string();
        let key = format!("{top_n}:{rendered}");
        let generation = self.write_generation();

        let hit: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM facet_cache WHERE key = ?1 AND generation = ?2",
                params![key, generation],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(json) = hit {
            if let Ok(facets) = serde_json::from_str(&json) {
                return Ok(facets);
            }
        }

        let facets = if rendered.is_empty() {
            self.facets(top_n)?
        } else {
            self.facets_for_query(query, top_n)?
        };
        // Best-effort write-back: a read-only or locked database should still
        // serve the page.
        let _ = self.conn.execute(
            "INSERT OR REPLACE INTO facet_cache (key, generation, computed_at, value)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                key,
                generation,
                time::OffsetDateTime::now_utc().unix_timestamp(),
                serde_json::to_string(&facets)?
            ],
        );
        Ok(facets)
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
            Ok(Facet {
                value: r.get::<_, String>(0)?,
                count: r.get(1)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    fn facet_int(&self, sql: &str, top_n: usize) -> Result<Vec<Facet>> {
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map(params![top_n as i64], |r| {
            Ok(Facet {
                value: r.get::<_, i64>(0)?.to_string(),
                count: r.get(1)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Total number of hosts in the store.
    pub fn host_count(&self) -> Result<i64> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM hosts", [], |r| r.get(0))?)
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

    fn facet_sub_text(
        &self,
        sql: &str,
        params: &[rusqlite::types::Value],
        top_n: usize,
    ) -> Result<Vec<Facet>> {
        let mut stmt = self.conn.prepare(sql)?;
        let mut binds: Vec<rusqlite::types::Value> = params.to_vec();
        binds.push(rusqlite::types::Value::Integer(top_n as i64));
        let rows = stmt.query_map(rusqlite::params_from_iter(binds.iter()), |r| {
            Ok(Facet {
                value: r.get::<_, String>(0)?,
                count: r.get(1)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    fn facet_sub_int(
        &self,
        sql: &str,
        params: &[rusqlite::types::Value],
        top_n: usize,
    ) -> Result<Vec<Facet>> {
        let mut stmt = self.conn.prepare(sql)?;
        let mut binds: Vec<rusqlite::types::Value> = params.to_vec();
        binds.push(rusqlite::types::Value::Integer(top_n as i64));
        let rows = stmt.query_map(rusqlite::params_from_iter(binds.iter()), |r| {
            Ok(Facet {
                value: r.get::<_, i64>(0)?.to_string(),
                count: r.get(1)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Host IPs not scanned since `cutoff` (unix seconds), oldest first — the
    /// rescan queue for `crusade monitor`.
    pub fn stale_host_ips(&self, cutoff: i64, limit: usize) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT ip FROM hosts WHERE last_seen < ?1 ORDER BY last_seen ASC LIMIT ?2")?;
        let rows = stmt.query_map(params![cutoff, limit as i64], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Every host IP in the store (for a full rescan sweep).
    pub fn all_host_ips(&self) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT ip FROM hosts ORDER BY last_seen ASC")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Append-only scan history for a host: (observed_at unix seconds, Service)
    /// snapshots, newest first. Powers the per-host timeline / trends views.
    pub fn service_history(&self, ip: &str) -> Result<Vec<(i64, crusade_core::Service)>> {
        let mut stmt = self.conn.prepare(
            "SELECT observed_at, doc FROM service_history WHERE ip = ?1 ORDER BY observed_at DESC",
        )?;
        let rows = stmt.query_map(params![ip], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (ts, doc) = row?;
            if let Ok(svc) = serde_json::from_str::<crusade_core::Service>(&doc) {
                out.push((ts, svc));
            }
        }
        Ok(out)
    }

    /// Enqueue a scan job; returns its id.
    pub fn enqueue_job(
        &self,
        target: &str,
        ports: Option<&str>,
        udp: bool,
        ics: bool,
    ) -> Result<i64> {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        self.conn.execute(
            "INSERT INTO jobs (target, ports, udp, ics, status, created_at)
             VALUES (?1,?2,?3,?4,'pending',?5)",
            params![target, ports, udp as i64, ics as i64, now],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Atomically claim the next pending job for `worker` (oldest first), or
    /// None if the queue is empty. Safe across concurrent workers via an
    /// IMMEDIATE transaction on the WAL database.
    pub fn claim_next_job(&mut self, worker: &str) -> Result<Option<Job>> {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let id: Option<i64> = tx
            .query_row(
                "SELECT id FROM jobs WHERE status = 'pending' ORDER BY id LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let job = match id {
            None => None,
            Some(id) => {
                tx.execute(
                    "UPDATE jobs SET status='running', worker=?1, claimed_at=?2 WHERE id=?3",
                    params![worker, now, id],
                )?;
                Some(tx.query_row(
                    "SELECT id, target, ports, udp, ics, status, worker, note FROM jobs WHERE id=?1",
                    params![id],
                    Self::row_to_job,
                )?)
            }
        };
        tx.commit()?;
        Ok(job)
    }

    /// Mark a claimed job done/failed with a short note.
    pub fn finish_job(&self, id: i64, ok: bool, note: &str) -> Result<()> {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let status = if ok { "done" } else { "failed" };
        self.conn.execute(
            "UPDATE jobs SET status=?1, note=?2, finished_at=?3 WHERE id=?4",
            params![status, note, now, id],
        )?;
        Ok(())
    }

    /// (pending, running, done, failed) counts.
    pub fn job_counts(&self) -> Result<(i64, i64, i64, i64)> {
        let one = |st: &str| -> Result<i64> {
            Ok(self.conn.query_row(
                "SELECT COUNT(*) FROM jobs WHERE status=?1",
                params![st],
                |r| r.get(0),
            )?)
        };
        Ok((
            one("pending")?,
            one("running")?,
            one("done")?,
            one("failed")?,
        ))
    }

    /// Most recent jobs, newest first.
    pub fn recent_jobs(&self, limit: usize) -> Result<Vec<Job>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, target, ports, udp, ics, status, worker, note FROM jobs ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], Self::row_to_job)?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    fn row_to_job(r: &rusqlite::Row) -> rusqlite::Result<Job> {
        Ok(Job {
            id: r.get(0)?,
            target: r.get(1)?,
            ports: r.get(2)?,
            udp: r.get::<_, i64>(3)? != 0,
            ics: r.get::<_, i64>(4)? != 0,
            status: r.get(5)?,
            worker: r.get(6)?,
            note: r.get(7)?,
        })
    }

    /// Record an alert (returns its id). `delivered` starts false.
    pub fn record_alert(&self, ip: &str, kind: &str, detail: &str) -> Result<i64> {
        let ts = time::OffsetDateTime::now_utc().unix_timestamp();
        self.conn.execute(
            "INSERT INTO alerts (ts, ip, kind, detail, delivered) VALUES (?1,?2,?3,?4,0)",
            params![ts, ip, kind, detail],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Alerts not yet marked delivered, oldest first.
    pub fn undelivered_alerts(&self) -> Result<Vec<Alert>> {
        self.query_alerts("SELECT id, ts, ip, kind, detail, delivered FROM alerts WHERE delivered = 0 ORDER BY ts ASC", &[])
    }

    /// The most recent alerts, newest first.
    pub fn recent_alerts(&self, limit: usize) -> Result<Vec<Alert>> {
        self.query_alerts(
            "SELECT id, ts, ip, kind, detail, delivered FROM alerts ORDER BY ts DESC LIMIT ?1",
            &[&(limit as i64)],
        )
    }

    pub fn mark_alert_delivered(&self, id: i64) -> Result<()> {
        self.conn
            .execute("UPDATE alerts SET delivered = 1 WHERE id = ?1", params![id])?;
        Ok(())
    }

    fn query_alerts(&self, sql: &str, binds: &[&dyn rusqlite::ToSql]) -> Result<Vec<Alert>> {
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map(binds, |r| {
            Ok(Alert {
                id: r.get(0)?,
                ts: r.get(1)?,
                ip: r.get(2)?,
                kind: r.get(3)?,
                detail: r.get(4)?,
                delivered: r.get::<_, i64>(5)? != 0,
            })
        })?;
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
