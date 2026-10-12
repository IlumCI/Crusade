//! Retention: measuring what the index costs, and reclaiming it.
//!
//! Three things grow without any natural bound: the scan-history timeline, the
//! alert log, and the host table itself as sweeps reach new address space. Left
//! alone they fill the disk, and the parts most likely to be useless are also
//! the largest — history for hosts nobody has looked at in months.
//!
//! "Useless" is measured, not assumed. Every host carries `last_seen` (when it
//! last answered) and `last_accessed` (when it was last surfaced to someone,
//! via a search page, a host view, or the API). A host that has neither
//! answered nor been looked at is the correct thing to drop first, and a host
//! someone keeps opening is kept however old it is.
//!
//! This module only *selects and deletes*. Writing the data out to an archive
//! file before it goes is the caller's job (see `src/archive.rs`), so nothing
//! here can lose data that was not already written somewhere else.
//!
//! Note that SQLite does not return space to the filesystem on delete: freed
//! pages are reused for later writes. [`Store::vacuum`] rewrites the database
//! to actually shrink the file, and needs temporary room for a second copy.

use anyhow::Result;
use rusqlite::params;

use crate::Store;

/// Where the bytes are.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StorageReport {
    /// Size of the database file on disk, when it is a file.
    pub file_bytes: u64,
    /// Bytes SQLite has allocated (page size x page count).
    pub allocated_bytes: u64,
    /// Bytes on the free list: already reclaimable by `VACUUM`.
    pub free_bytes: u64,
    /// Per-table (and per-index) usage, largest first.
    pub tables: Vec<TableUsage>,
    pub hosts: i64,
    pub services: i64,
    pub history_rows: i64,
    pub alerts: i64,
    /// Hosts that have never been surfaced to anyone.
    pub never_accessed: i64,
}

/// One table or index and what it costs.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TableUsage {
    pub name: String,
    pub bytes: u64,
    pub rows: i64,
}

/// What may be deleted, and when.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retention {
    /// Drop timeline entries older than this. The newest entry per service is
    /// always kept, so a host page never loses its current state.
    pub history_days: i64,
    /// Drop delivered alerts older than this. Undelivered alerts are kept
    /// regardless: they have not been acted on yet.
    pub alerts_days: i64,
    /// Drop finished (done/failed) jobs older than this.
    pub jobs_days: i64,
    /// A host is a candidate once it has not answered for this long.
    pub host_stale_days: i64,
    /// ...and has not been looked at for this long (never counts as forever).
    pub host_unaccessed_days: i64,
}

impl Default for Retention {
    fn default() -> Self {
        Retention {
            history_days: 180,
            alerts_days: 90,
            jobs_days: 30,
            host_stale_days: 180,
            host_unaccessed_days: 90,
        }
    }
}

/// What a sweep removed.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct Pruned {
    pub history_rows: i64,
    pub alerts: i64,
    pub jobs: i64,
    pub facet_cache: i64,
}

impl Pruned {
    pub fn total(&self) -> i64 {
        self.history_rows + self.alerts + self.jobs + self.facet_cache
    }
}

fn days_ago(now: i64, days: i64) -> i64 {
    now - days.max(0) * 86_400
}

impl Store {
    /// Measure current storage. `file_bytes` is 0 for an in-memory database.
    pub fn storage_report(&self) -> Result<StorageReport> {
        let page_size: u64 =
            self.conn
                .query_row("PRAGMA page_size", [], |r| r.get::<_, i64>(0))? as u64;
        let page_count: u64 =
            self.conn
                .query_row("PRAGMA page_count", [], |r| r.get::<_, i64>(0))? as u64;
        let free_pages: u64 =
            self.conn
                .query_row("PRAGMA freelist_count", [], |r| r.get::<_, i64>(0))? as u64;

        let file_bytes = self
            .conn
            .path()
            .filter(|p| !p.is_empty())
            .and_then(|p| std::fs::metadata(p).ok())
            .map(|m| m.len())
            .unwrap_or(0);

        // dbstat reports pages per b-tree, which is how the space is really
        // apportioned between tables, indexes and the FTS shadow tables.
        let mut tables: Vec<TableUsage> = Vec::new();
        if let Ok(mut stmt) = self.conn.prepare(
            "SELECT name, SUM(pgsize) AS bytes FROM dbstat GROUP BY name ORDER BY bytes DESC",
        ) {
            if let Ok(rows) = stmt.query_map([], |r| {
                Ok(TableUsage {
                    name: r.get(0)?,
                    bytes: r.get::<_, i64>(1).unwrap_or(0).max(0) as u64,
                    rows: 0,
                })
            }) {
                tables = rows.flatten().collect();
            }
        }
        for t in &mut tables {
            // Only real tables can be counted; indexes and shadow tables are
            // left at zero rather than guessed at.
            t.rows = self
                .conn
                .query_row(&format!("SELECT count(*) FROM \"{}\"", t.name), [], |r| {
                    r.get(0)
                })
                .unwrap_or(0);
        }

        let count = |sql: &str| -> i64 { self.conn.query_row(sql, [], |r| r.get(0)).unwrap_or(0) };
        Ok(StorageReport {
            file_bytes,
            allocated_bytes: page_size * page_count,
            free_bytes: page_size * free_pages,
            tables,
            hosts: count("SELECT count(*) FROM hosts"),
            services: count("SELECT count(*) FROM services"),
            history_rows: count("SELECT count(*) FROM service_history"),
            alerts: count("SELECT count(*) FROM alerts"),
            never_accessed: count("SELECT count(*) FROM hosts WHERE last_accessed IS NULL"),
        })
    }

    /// Record that these hosts were surfaced to someone.
    ///
    /// Called from the search and host-detail paths. Best-effort and batched:
    /// a read path must not fail or stall because a usage timestamp could not
    /// be written (the database may legitimately be read-only or locked).
    pub fn touch_hosts(&self, ips: &[String]) {
        self.touch_hosts_at(ips, time::OffsetDateTime::now_utc().unix_timestamp())
    }

    /// [`Store::touch_hosts`] with an explicit timestamp, so retention can be
    /// tested without depending on the wall clock.
    pub fn touch_hosts_at(&self, ips: &[String], now: i64) {
        if ips.is_empty() {
            return;
        }
        let placeholders = vec!["?"; ips.len()].join(",");
        let sql = format!("UPDATE hosts SET last_accessed = ?1 WHERE ip IN ({placeholders})");
        let mut values: Vec<rusqlite::types::Value> = Vec::with_capacity(ips.len() + 1);
        values.push(now.into());
        values.extend(ips.iter().map(|ip| ip.clone().into()));
        if let Err(e) = self
            .conn
            .execute(&sql, rusqlite::params_from_iter(values.iter()))
        {
            tracing::debug!("recording host access failed: {e}");
        }
    }

    /// Screenshot filenames that some service still points at.
    ///
    /// Screenshots live on disk, outside the database, so deleting a host
    /// leaves its PNG orphaned unless it is swept up against this set.
    pub fn referenced_screenshots(&self) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT DISTINCT screenshot FROM services WHERE screenshot IS NOT NULL")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Hosts worth archiving: stale, unvisited, and not awaiting an alert.
    ///
    /// Ordered least-useful first — never-accessed before long-ago-accessed,
    /// then oldest-seen — so a capped run removes the least valuable rows.
    pub fn archivable_hosts(
        &self,
        now: i64,
        policy: &Retention,
        limit: usize,
    ) -> Result<Vec<String>> {
        let stale_before = days_ago(now, policy.host_stale_days);
        let access_before = days_ago(now, policy.host_unaccessed_days);
        let mut stmt = self.conn.prepare(
            "SELECT ip FROM hosts
             WHERE last_seen < ?1
               AND (last_accessed IS NULL OR last_accessed < ?2)
               AND ip NOT IN (SELECT ip FROM alerts WHERE delivered = 0)
             ORDER BY (last_accessed IS NOT NULL), last_accessed ASC, last_seen ASC
             LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![stale_before, access_before, limit as i64], |r| {
            r.get::<_, String>(0)
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Delete hosts and everything attached to them. Returns how many went.
    ///
    /// The caller is expected to have archived them first.
    pub fn delete_hosts(&mut self, ips: &[String]) -> Result<usize> {
        let mut n = 0;
        for ip in ips {
            self.delete_host(ip)?;
            n += 1;
        }
        Ok(n)
    }

    /// Apply the time-based retention rules. Derived and superseded rows only:
    /// nothing here removes a host or its current services.
    pub fn prune(&mut self, now: i64, policy: &Retention) -> Result<Pruned> {
        let tx = self.conn.transaction()?;

        // History, keeping each service's most recent entry so the timeline
        // always has a current point even after a deep prune.
        let history_rows = tx.execute(
            "DELETE FROM service_history
             WHERE observed_at < ?1
               AND id NOT IN (
                   SELECT MAX(id) FROM service_history GROUP BY ip, port, transport
               )",
            params![days_ago(now, policy.history_days)],
        )? as i64;

        // Delivered alerts only: an undelivered one has not been acted on.
        let alerts = tx.execute(
            "DELETE FROM alerts WHERE delivered = 1 AND ts < ?1",
            params![days_ago(now, policy.alerts_days)],
        )? as i64;

        let jobs = tx.execute(
            "DELETE FROM jobs
             WHERE status IN ('done', 'failed')
               AND COALESCE(finished_at, created_at) < ?1",
            params![days_ago(now, policy.jobs_days)],
        )? as i64;

        // Cached aggregates are pure derived data and cheap to recompute.
        let facet_cache = tx.execute("DELETE FROM facet_cache", [])? as i64;

        let pruned = Pruned {
            history_rows,
            alerts,
            jobs,
            facet_cache,
        };

        if pruned.total() > 0 {
            crate::bump_generation(&tx)?;
        }
        tx.commit()?;
        Ok(pruned)
    }

    /// Rewrite the database to return freed pages to the filesystem.
    ///
    /// Deletes alone do not shrink the file; SQLite keeps the pages for reuse.
    /// This needs temporary space for a second copy of the database, so it can
    /// fail on a nearly full disk — the caller should treat that as
    /// non-fatal, since the space is still reusable in place.
    pub fn vacuum(&self) -> Result<()> {
        self.conn.execute_batch("VACUUM")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crusade_core::model::{Host, Service, Transport};
    use std::net::IpAddr;
    use time::OffsetDateTime;

    const NOW: i64 = 1_800_000_000;
    const DAY: i64 = 86_400;

    fn host_at(ip: &str, last_seen: i64) -> Host {
        let mut h = Host::new(ip.parse::<IpAddr>().unwrap());
        h.last_seen = OffsetDateTime::from_unix_timestamp(last_seen).unwrap();
        let mut s = Service::new(80, Transport::Tcp);
        s.observed_at = h.last_seen;
        s.banner = Some("nginx default page".into());
        h.services.push(s);
        h
    }

    fn store_with(hosts: &[(&str, i64)]) -> Store {
        let mut store = Store::open_in_memory().unwrap();
        for (ip, seen) in hosts {
            store.upsert_host(&host_at(ip, *seen)).unwrap();
        }
        store
    }

    #[test]
    fn selects_stale_and_unvisited_hosts_least_useful_first() {
        let mut store = store_with(&[
            ("192.0.2.1", NOW - 400 * DAY), // stale, never accessed
            ("192.0.2.2", NOW - 300 * DAY), // stale, never accessed (newer)
            ("192.0.2.3", NOW - 400 * DAY), // stale but visited recently
            ("192.0.2.4", NOW - DAY),       // fresh
        ]);
        let policy = Retention::default();

        // Mark .3 as recently looked at.
        store.touch_hosts_at(&["192.0.2.3".to_string()], NOW - DAY);

        let picked = store.archivable_hosts(NOW, &policy, 10).unwrap();
        assert_eq!(
            picked,
            vec!["192.0.2.1", "192.0.2.2"],
            "a visited host and a fresh host are both kept"
        );

        // Oldest-seen first among the never-accessed.
        let one = store.archivable_hosts(NOW, &policy, 1).unwrap();
        assert_eq!(one, vec!["192.0.2.1"]);

        // Deleting really removes them and their services.
        assert_eq!(store.delete_hosts(&picked).unwrap(), 2);
        assert_eq!(store.host_count().unwrap(), 2);
        let left: i64 = store
            .conn
            .query_row("SELECT count(*) FROM services", [], |r| r.get(0))
            .unwrap();
        assert_eq!(left, 2);
    }

    #[test]
    fn an_old_but_visited_host_is_never_selected() {
        let store = store_with(&[("192.0.2.9", NOW - 3650 * DAY)]);
        store.touch_hosts_at(&["192.0.2.9".to_string()], NOW - DAY);
        assert!(store
            .archivable_hosts(NOW, &Retention::default(), 10)
            .unwrap()
            .is_empty());

        // Once the visit itself is old enough, it becomes a candidate.
        store
            .conn
            .execute(
                "UPDATE hosts SET last_accessed = ?1",
                params![NOW - 200 * DAY],
            )
            .unwrap();
        assert_eq!(
            store
                .archivable_hosts(NOW, &Retention::default(), 10)
                .unwrap(),
            vec!["192.0.2.9"]
        );
    }

    #[test]
    fn a_host_with_an_undelivered_alert_is_held_back() {
        let store = store_with(&[("192.0.2.5", NOW - 400 * DAY)]);
        store
            .record_alert("192.0.2.5", "new-port", "port 22")
            .unwrap();
        assert!(
            store
                .archivable_hosts(NOW, &Retention::default(), 10)
                .unwrap()
                .is_empty(),
            "an alert nobody has seen yet must not be archived away"
        );
        store.mark_alert_delivered(1).unwrap();
        assert_eq!(
            store
                .archivable_hosts(NOW, &Retention::default(), 10)
                .unwrap(),
            vec!["192.0.2.5"]
        );
    }

    #[test]
    fn prune_keeps_the_newest_history_entry_per_service() {
        let mut store = store_with(&[("192.0.2.6", NOW - 400 * DAY)]);
        // Three distinct observations, all old.
        for (i, age) in [400i64, 300, 200].iter().enumerate() {
            let mut h = host_at("192.0.2.6", NOW - age * DAY);
            h.services[0].version = Some(format!("1.{i}"));
            store.upsert_host(&h).unwrap();
        }
        let history = |s: &Store| -> i64 {
            s.conn
                .query_row("SELECT count(*) FROM service_history", [], |r| r.get(0))
                .unwrap()
        };
        assert!(history(&store) >= 3);

        let pruned = store.prune(NOW, &Retention::default()).unwrap();
        assert!(pruned.history_rows > 0);
        assert_eq!(
            history(&store),
            1,
            "exactly the most recent entry per service survives"
        );
        // And the host itself is untouched by pruning.
        assert_eq!(store.host_count().unwrap(), 1);
        assert!(store.get_host("192.0.2.6").unwrap().is_some());
    }

    #[test]
    fn prune_respects_alert_delivery_and_job_state() {
        let mut store = store_with(&[("192.0.2.7", NOW)]);
        let old = NOW - 200 * DAY;

        store
            .record_alert("192.0.2.7", "new-port", "delivered+old")
            .unwrap();
        store
            .record_alert("192.0.2.7", "new-vuln", "undelivered+old")
            .unwrap();
        store.mark_alert_delivered(1).unwrap();
        store
            .conn
            .execute("UPDATE alerts SET ts = ?1", params![old])
            .unwrap();

        let pending = store
            .enqueue_job("192.0.2.0/24", None, false, false)
            .unwrap();
        let done = store
            .enqueue_job("198.51.100.0/24", None, false, false)
            .unwrap();
        store.finish_job(done, true, "ok").unwrap();
        store
            .conn
            .execute(
                "UPDATE jobs SET created_at = ?1, finished_at = ?1",
                params![old],
            )
            .unwrap();

        let pruned = store.prune(NOW, &Retention::default()).unwrap();
        assert_eq!(pruned.alerts, 1, "only the delivered alert goes");
        assert_eq!(pruned.jobs, 1, "only the finished job goes");

        let alerts_left: i64 = store
            .conn
            .query_row("SELECT count(*) FROM alerts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(alerts_left, 1);
        let jobs_left: i64 = store
            .conn
            .query_row("SELECT id FROM jobs", [], |r| r.get(0))
            .unwrap();
        assert_eq!(jobs_left, pending, "the queued job is still queued");
    }

    #[test]
    fn pruning_nothing_is_a_no_op_and_leaves_the_generation_alone() {
        let mut store = store_with(&[("192.0.2.8", NOW)]);
        // Prime the facet cache so there is something derived to clear.
        let _ = store
            .facets_cached(&crusade_core::query::Query::default(), 5)
            .unwrap();
        let first = store.prune(NOW, &Retention::default()).unwrap();
        assert_eq!(first.facet_cache, 1);
        let generation = store.write_generation();

        let second = store.prune(NOW, &Retention::default()).unwrap();
        assert_eq!(second, Pruned::default(), "nothing left to prune");
        assert_eq!(
            store.write_generation(),
            generation,
            "a no-op prune must not invalidate caches"
        );
    }

    #[test]
    fn storage_report_accounts_for_the_data() {
        let mut store = store_with(&[("192.0.2.20", NOW), ("192.0.2.21", NOW)]);
        store.touch_hosts_at(&["192.0.2.20".to_string()], NOW);

        let r = store.storage_report().unwrap();
        assert_eq!(r.hosts, 2);
        assert_eq!(r.services, 2);
        assert_eq!(r.never_accessed, 1, "one host has been visited");
        assert!(r.allocated_bytes > 0);
        assert_eq!(r.file_bytes, 0, "in-memory database has no file");
        assert!(
            r.tables.iter().any(|t| t.name == "hosts" && t.bytes > 0),
            "dbstat should attribute space to the hosts table: {:?}",
            r.tables.iter().map(|t| &t.name).collect::<Vec<_>>()
        );
        // Deleting frees pages for reuse without shrinking the allocation.
        store
            .delete_hosts(&["192.0.2.20".into(), "192.0.2.21".into()])
            .unwrap();
        let after = store.storage_report().unwrap();
        assert_eq!(after.hosts, 0);
        store.vacuum().unwrap();
        assert!(store.storage_report().unwrap().free_bytes <= after.free_bytes);
    }

    #[test]
    fn touch_is_batched_and_ignores_unknown_hosts() {
        let store = store_with(&[("192.0.2.30", NOW)]);
        // Unknown IPs are simply not matched; no error, no panic.
        store.touch_hosts_at(&["192.0.2.30".into(), "203.0.113.99".into()], NOW);
        store.touch_hosts(&[]);
        let touched: i64 = store
            .conn
            .query_row(
                "SELECT count(*) FROM hosts WHERE last_accessed IS NOT NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(touched, 1);
    }
}
