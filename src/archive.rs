//! Archiving: write old data out, then reclaim the space.
//!
//! [`crate::store`] decides *what* is expendable; this module is what makes it
//! safe to act on. Hosts selected for removal are written to a gzipped JSON
//! Lines file under `<data dir>/archive/` first, and deleted only once that
//! file is on disk — so "archived and deleted" never means "lost". The archive
//! is the same shape `crusade export` produces, so it can be read back with
//! the same tools.
//!
//! Two ways in:
//!
//! * [`run`] — an explicit `crusade archive`, applying the configured
//!   retention rules once.
//! * [`auto_archive`] — called after a scan or monitor pass. It does nothing
//!   until the database exceeds `[archive] max_db_mb`, then escalates through
//!   tiers, cheapest and least destructive first, stopping as soon as the
//!   database is back under the limit:
//!
//!   1. derived data and expired rows (facet cache, old delivered alerts,
//!      finished jobs, history past its retention) — nothing irreplaceable;
//!   2. orphaned screenshots on disk, which no service references any more;
//!   3. stale, never-visited hosts, least useful first, archived then deleted
//!      in bounded batches.
//!
//! Only after something was actually removed is the database vacuumed, since
//! deletes alone do not shrink the file.

use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use crusade_store::{Pruned, Retention, Store};
use flate2::write::GzEncoder;
use flate2::Compression;

use crate::config::Config;

/// Hosts archived per batch, so one pass holds no unbounded amount in memory.
const BATCH: usize = 2_000;
/// Give up after this many tier-3 batches in a single automatic run, so a
/// badly configured limit cannot delete the whole index in one go.
const MAX_AUTO_BATCHES: usize = 25;

/// What an archive run did.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ArchiveOutcome {
    pub pruned: Pruned,
    pub hosts_archived: u64,
    pub screenshots_removed: u64,
    /// Archive files written, in order.
    pub files: Vec<PathBuf>,
    pub bytes_before: u64,
    pub bytes_after: u64,
    pub vacuumed: bool,
    /// Set when the run stopped at its batch limit while still over the size
    /// limit, so the caller can say so rather than implying success.
    pub hit_batch_limit: bool,
}

impl ArchiveOutcome {
    pub fn removed_anything(&self) -> bool {
        self.pruned.total() > 0 || self.hosts_archived > 0 || self.screenshots_removed > 0
    }

    /// Space returned to the filesystem, if any.
    pub fn reclaimed(&self) -> u64 {
        self.bytes_before.saturating_sub(self.bytes_after)
    }
}

/// Retention rules from config.
pub fn retention(cfg: &Config) -> Retention {
    Retention {
        history_days: cfg.archive.history_days,
        alerts_days: cfg.archive.alerts_days,
        jobs_days: cfg.archive.jobs_days,
        host_stale_days: cfg.archive.host_stale_days,
        host_unaccessed_days: cfg.archive.host_unaccessed_days,
    }
}

/// Current size of the database file (0 when it cannot be read).
fn db_bytes(cfg: &Config) -> u64 {
    std::fs::metadata(&cfg.database.path)
        .map(|m| m.len())
        .unwrap_or(0)
}

/// Write hosts to a new gzipped JSON Lines archive and return its path.
///
/// The file is written to a temporary name and renamed into place, so an
/// interrupted run never leaves a short archive that looks complete — the
/// hosts are only deleted after this returns.
fn write_archive(dir: &Path, hosts: &[crusade_core::Host]) -> Result<PathBuf> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let stamp = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unknown".into())
        .replace(':', "-");
    let name = format!("hosts-{stamp}-{}.jsonl.gz", hosts.len());
    let final_path = dir.join(&name);
    let tmp = dir.join(format!("{name}.partial"));

    let file =
        std::fs::File::create(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
    let mut gz = GzEncoder::new(std::io::BufWriter::new(file), Compression::default());
    for host in hosts {
        serde_json::to_writer(&mut gz, host)?;
        gz.write_all(b"\n")?;
    }
    // Finish the gzip stream and flush to the OS before the rename.
    gz.finish()?.flush()?;
    std::fs::rename(&tmp, &final_path)
        .with_context(|| format!("installing {}", final_path.display()))?;
    Ok(final_path)
}

/// Archive and delete one batch of hosts. Returns how many went.
fn archive_batch(cfg: &Config, store: &mut Store, ips: &[String]) -> Result<(u64, PathBuf)> {
    let mut hosts = Vec::with_capacity(ips.len());
    for ip in ips {
        if let Some(h) = store.get_host(ip)? {
            hosts.push(h);
        }
    }
    let path = write_archive(&cfg.data.dir.join("archive"), &hosts)?;
    // Only now that the archive exists on disk.
    let removed = store.delete_hosts(ips)? as u64;
    Ok((removed, path))
}

/// Delete screenshots no service references any more.
///
/// These are the one piece of state that lives outside the database, so
/// deleting a host leaves its PNG behind unless it is swept up here.
fn remove_orphan_screenshots(cfg: &Config, store: &Store) -> Result<u64> {
    let dir = cfg.data.dir.join("screens");
    if !dir.exists() {
        return Ok(0);
    }
    let referenced: HashSet<String> = store.referenced_screenshots()?.into_iter().collect();
    let mut removed = 0;
    for entry in std::fs::read_dir(&dir)?.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".png") || referenced.contains(&name) {
            continue;
        }
        if std::fs::remove_file(entry.path()).is_ok() {
            removed += 1;
        }
    }
    Ok(removed)
}

/// Apply the retention rules once: prune expired rows, sweep orphaned
/// screenshots, and archive every host that qualifies.
///
/// `dry_run` reports what would go without writing or deleting anything.
pub fn run(cfg: &Config, store: &mut Store, dry_run: bool) -> Result<ArchiveOutcome> {
    let policy = retention(cfg);
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let mut out = ArchiveOutcome {
        bytes_before: db_bytes(cfg),
        ..Default::default()
    };

    if dry_run {
        let candidates = store.archivable_hosts(now, &policy, usize::MAX)?;
        out.hosts_archived = candidates.len() as u64;
        out.bytes_after = out.bytes_before;
        return Ok(out);
    }

    out.pruned = store.prune(now, &policy)?;

    loop {
        let batch = store.archivable_hosts(now, &policy, BATCH)?;
        if batch.is_empty() {
            break;
        }
        let (removed, path) = archive_batch(cfg, store, &batch)?;
        out.hosts_archived += removed;
        out.files.push(path);
    }

    out.screenshots_removed = remove_orphan_screenshots(cfg, store).unwrap_or(0);

    if out.removed_anything() {
        // Non-fatal: the space is reusable in place even if the rewrite fails
        // (it needs room for a second copy of the database).
        match store.vacuum() {
            Ok(()) => out.vacuumed = true,
            Err(e) => tracing::warn!("vacuum failed ({e:#}); freed pages stay reusable in place"),
        }
    }
    out.bytes_after = db_bytes(cfg);
    Ok(out)
}

/// Archive automatically, but only once the database is over its limit.
///
/// Returns `None` when no limit is configured or the database is under it, so
/// callers can stay quiet in the common case.
pub fn auto_archive(cfg: &Config, store: &mut Store) -> Result<Option<ArchiveOutcome>> {
    let Some(limit) = cfg.archive.max_db_bytes() else {
        return Ok(None);
    };
    let before = db_bytes(cfg);
    if before <= limit {
        return Ok(None);
    }

    let policy = retention(cfg);
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let mut out = ArchiveOutcome {
        bytes_before: before,
        ..Default::default()
    };
    tracing::info!(
        bytes = before,
        limit,
        "database over its size limit; archiving"
    );

    // Deletes free pages for reuse but do not shrink the file, so judge
    // progress by live bytes (allocated minus free list) rather than file
    // size. Vacuuming after every batch just to re-measure would cost more
    // than the archiving itself — it rewrites the whole database.
    let live_bytes = |store: &Store| -> u64 {
        store
            .storage_report()
            .map(|r| r.allocated_bytes.saturating_sub(r.free_bytes))
            .unwrap_or(before)
    };

    // Tier 1: expired and derived rows. Nothing irreplaceable.
    out.pruned = store.prune(now, &policy)?;

    // Tier 2: screenshots nothing points at.
    out.screenshots_removed = remove_orphan_screenshots(cfg, store).unwrap_or(0);

    // Tier 3: stale, unvisited hosts, least useful first.
    for batch_no in 0..MAX_AUTO_BATCHES {
        if live_bytes(store) <= limit {
            break;
        }
        let batch = store.archivable_hosts(now, &policy, BATCH)?;
        if batch.is_empty() {
            tracing::warn!(
                "over the size limit with nothing eligible to archive: lower \
                 [archive] host_stale_days / host_unaccessed_days, or raise max_db_mb"
            );
            break;
        }
        let (removed, path) = archive_batch(cfg, store, &batch)?;
        out.hosts_archived += removed;
        out.files.push(path);
        if batch_no + 1 == MAX_AUTO_BATCHES {
            out.hit_batch_limit = true;
        }
    }

    // One rewrite at the end, and only if there is something to reclaim.
    if out.removed_anything() {
        match store.vacuum() {
            Ok(()) => out.vacuumed = true,
            Err(e) => tracing::warn!("vacuum failed ({e:#}); freed pages stay reusable in place"),
        }
    }
    out.bytes_after = db_bytes(cfg);
    Ok(Some(out))
}

/// Human-readable byte size.
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[0])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_sizes_read_sensibly() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert_eq!(human_bytes(1_048_576), "1.0 MiB");
        assert_eq!(human_bytes(3_221_225_472), "3.0 GiB");
    }

    #[test]
    fn archive_file_is_readable_jsonl_and_atomic() {
        use crusade_core::Host;
        use std::net::IpAddr;

        let dir = std::env::temp_dir().join(format!("crusade-arch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let hosts: Vec<Host> = (0..3)
            .map(|i| Host::new(format!("192.0.2.{i}").parse::<IpAddr>().unwrap()))
            .collect();
        let path = write_archive(&dir, &hosts).unwrap();
        assert!(path.exists());
        assert!(
            path.to_string_lossy().ends_with("-3.jsonl.gz"),
            "the name records how many hosts it holds: {}",
            path.display()
        );
        // No leftover partial file.
        let partials = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains("partial"))
            .count();
        assert_eq!(partials, 0);

        // Round-trips as JSON Lines through gzip.
        let file = std::fs::File::open(&path).unwrap();
        let mut text = String::new();
        std::io::Read::read_to_string(
            &mut flate2::read::GzDecoder::new(std::io::BufReader::new(file)),
            &mut text,
        )
        .unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        for (i, line) in lines.iter().enumerate() {
            let back: Host = serde_json::from_str(line).unwrap();
            assert_eq!(back.ip.to_string(), format!("192.0.2.{i}"));
        }

        // An empty archive is still a valid, readable file.
        let empty = write_archive(&dir, &[]).unwrap();
        assert!(empty.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
