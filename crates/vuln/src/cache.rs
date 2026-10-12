//! An on-disk, indexed CVE cache.
//!
//! The NVD feeds are ~470 MB of JSON holding ~324k matchable CVEs. Parsing all
//! of them into memory costs about six seconds and several hundred megabytes on
//! every invocation — to then match, typically, a handful of products. Measured
//! on a scan that found no open ports at all, 86% of the run was spent loading
//! vulnerability data that was never consulted.
//!
//! So the feeds are parsed **once** into a SQLite cache indexed by product, and
//! afterwards only opened (not read). Matching a service is then an indexed
//! query returning just the rules for that product, and an in-process memo
//! keeps repeat lookups free — a scan of many hosts sees the same few products
//! over and over.
//!
//! The cache is derived data: delete it and it rebuilds. Its `meta` table
//! fingerprints the source feeds, so a changed or newly downloaded feed is
//! noticed and the cache is rebuilt rather than silently serving stale CVEs.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use crusade_core::{Host, Tag};
use rusqlite::{params, Connection, OptionalExtension};

use crate::cve::{CpeMatch, CveEntry, KevCatalog};
use crate::exploit::ExploitRefs;

/// Schema of the cache database. Bumped when the layout changes, which forces
/// a rebuild rather than a misread.
const CACHE_SCHEMA: i64 = 1;

/// File name of the cache inside the data directory.
pub const CACHE_FILE: &str = "cve-cache.db";

const SCHEMA_SQL: &str = "
PRAGMA journal_mode = WAL;
CREATE TABLE IF NOT EXISTS cve (
    id          TEXT PRIMARY KEY,
    description TEXT NOT NULL
);
-- One row per vulnerable CPE rule. `product` is lower-cased so the index
-- serves a case-insensitive lookup directly.
CREATE TABLE IF NOT EXISTS cve_match (
    product TEXT NOT NULL,
    vendor  TEXT NOT NULL,
    version TEXT,
    vsi     TEXT,   -- versionStartIncluding
    vse     TEXT,   -- versionStartExcluding
    vei     TEXT,   -- versionEndIncluding
    vee     TEXT,   -- versionEndExcluding
    cve_id  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cve_match_product ON cve_match(product);
CREATE TABLE IF NOT EXISTS kev (cve_id TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS exploit (
    cve_id  TEXT PRIMARY KEY,
    summary TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
";

/// Identity of the source feeds, so a stale cache can be detected.
///
/// Uses each file's name, length and modification time rather than its
/// contents: hashing half a gigabyte to decide whether to parse half a
/// gigabyte would defeat the purpose.
pub fn source_fingerprint(dir: &Path) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| {
                    let name = p.file_name().unwrap_or_default().to_string_lossy();
                    (name.starts_with("nvdcve-") && name.ends_with(".json"))
                        || name == "known_exploited_vulnerabilities.json"
                        || name == "files_exploits.csv"
                        || name == "modules_metadata_base.json"
                })
                .collect()
        })
        .unwrap_or_default();
    entries.sort();
    for path in entries {
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let (len, modified) = std::fs::metadata(&path)
            .map(|m| {
                let secs = m
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                (m.len(), secs)
            })
            .unwrap_or((0, 0));
        parts.push(format!("{name}:{len}:{modified}"));
    }
    parts.join("|")
}

/// A handle to the on-disk CVE cache.
/// Shared across the scan pipeline via `Arc`, so both the connection and the
/// memo are behind mutexes. Contention is irrelevant here: the work inside is
/// a single indexed SQLite lookup, and a memo hit avoids even that.
pub struct CveCache {
    conn: Mutex<Connection>,
    /// Memo of lower-cased product -> candidate rules, filled as products are
    /// seen. A scan meets the same handful of products repeatedly.
    memo: Mutex<HashMap<String, Vec<CachedMatch>>>,
}

/// One candidate rule, as read back from the cache.
#[derive(Debug, Clone)]
struct CachedMatch {
    cve: String,
    description: String,
    rule: CpeMatch,
}

impl CveCache {
    /// Open an existing cache, verifying its schema and that it was built from
    /// the feeds currently in `dir`.
    ///
    /// Returns `Ok(None)` when there is no usable cache, so the caller can
    /// build one or fall back to parsing the feeds directly.
    pub fn open(dir: &Path) -> Result<Option<Self>> {
        let path = dir.join(CACHE_FILE);
        if !path.exists() {
            return Ok(None);
        }
        let conn =
            Connection::open(&path).with_context(|| format!("opening {}", path.display()))?;
        let meta = |key: &str| -> Option<String> {
            conn.query_row("SELECT value FROM meta WHERE key = ?1", params![key], |r| {
                r.get::<_, String>(0)
            })
            .optional()
            .ok()
            .flatten()
        };
        let schema_ok = meta("schema").and_then(|v| v.parse::<i64>().ok()) == Some(CACHE_SCHEMA);
        let fresh = meta("sources").as_deref() == Some(source_fingerprint(dir).as_str());
        if !schema_ok || !fresh {
            tracing::info!(
                schema_ok,
                fresh,
                "CVE cache is stale; it will be rebuilt by `crusade update-data`"
            );
            return Ok(None);
        }
        Ok(Some(CveCache {
            conn: Mutex::new(conn),
            memo: Mutex::new(HashMap::new()),
        }))
    }

    /// Build (or replace) the cache in `dir` from already-parsed feed data.
    ///
    /// Inserts run in one transaction with reused statements: this is ~324k
    /// CVEs and several million rules, where per-statement overhead dominates.
    pub fn build(
        dir: &Path,
        entries: &[CveEntry],
        kev: &KevCatalog,
        exploits: &HashMap<String, ExploitRefs>,
    ) -> Result<usize> {
        let path = dir.join(CACHE_FILE);
        // Build beside the live file and swap, so an interrupted build never
        // leaves a half-populated cache that looks valid.
        let tmp = dir.join(format!("{CACHE_FILE}.building"));
        let _ = std::fs::remove_file(&tmp);
        let mut conn = Connection::open(&tmp)?;
        conn.execute_batch(SCHEMA_SQL)?;

        let mut rules = 0usize;
        {
            let tx = conn.transaction()?;
            {
                let mut ins_cve =
                    tx.prepare("INSERT OR REPLACE INTO cve (id, description) VALUES (?1, ?2)")?;
                let mut ins_match = tx.prepare(
                    "INSERT INTO cve_match (product, vendor, version, vsi, vse, vei, vee, cve_id)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                )?;
                for e in entries {
                    if e.matches.is_empty() {
                        continue;
                    }
                    ins_cve.execute(params![e.id, e.description])?;
                    for m in &e.matches {
                        ins_match.execute(params![
                            m.product.to_lowercase(),
                            m.vendor,
                            m.version,
                            m.version_start_including,
                            m.version_start_excluding,
                            m.version_end_including,
                            m.version_end_excluding,
                            e.id
                        ])?;
                        rules += 1;
                    }
                }
                let mut ins_kev = tx.prepare("INSERT OR REPLACE INTO kev (cve_id) VALUES (?1)")?;
                for id in kev.entries.keys() {
                    ins_kev.execute(params![id])?;
                }
                let mut ins_exp =
                    tx.prepare("INSERT OR REPLACE INTO exploit (cve_id, summary) VALUES (?1, ?2)")?;
                for (cve, refs) in exploits {
                    if !refs.is_empty() {
                        ins_exp.execute(params![cve, refs.summary()])?;
                    }
                }
                let mut ins_meta =
                    tx.prepare("INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)")?;
                ins_meta.execute(params!["schema", CACHE_SCHEMA.to_string()])?;
                ins_meta.execute(params!["sources", source_fingerprint(dir)])?;
                ins_meta.execute(params!["cves", entries.len().to_string()])?;
            }
            tx.commit()?;
        }
        conn.execute_batch("ANALYZE")?;
        drop(conn);
        std::fs::rename(&tmp, &path).with_context(|| format!("installing {}", path.display()))?;
        Ok(rules)
    }

    /// Number of CVEs recorded.
    pub fn len(&self) -> usize {
        let Ok(conn) = self.conn.lock() else {
            return 0;
        };
        conn.query_row("SELECT count(*) FROM cve", [], |r| r.get::<_, i64>(0))
            .unwrap_or(0) as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Candidate rules for one product, read through the memo.
    fn candidates(&self, product: &str) -> Vec<CachedMatch> {
        let key = product.to_lowercase();
        if let Ok(memo) = self.memo.lock() {
            if let Some(hit) = memo.get(&key) {
                return hit.clone();
            }
        }
        let loaded = self.load_candidates(&key).unwrap_or_default();
        if let Ok(mut memo) = self.memo.lock() {
            memo.insert(key, loaded.clone());
        }
        loaded
    }

    fn load_candidates(&self, product: &str) -> Result<Vec<CachedMatch>> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| anyhow::anyhow!("CVE cache lock poisoned"))?;
        let mut stmt = conn.prepare_cached(
            "SELECT m.cve_id, c.description, m.vendor, m.version, m.vsi, m.vse, m.vei, m.vee
             FROM cve_match m JOIN cve c ON c.id = m.cve_id
             WHERE m.product = ?1",
        )?;
        let rows = stmt.query_map(params![product], |r| {
            Ok(CachedMatch {
                cve: r.get(0)?,
                description: r.get(1)?,
                rule: CpeMatch {
                    vendor: r.get(2)?,
                    product: product.to_string(),
                    version: r.get(3)?,
                    version_start_including: r.get(4)?,
                    version_start_excluding: r.get(5)?,
                    version_end_including: r.get(6)?,
                    version_end_excluding: r.get(7)?,
                },
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    fn is_kev(&self, cve: &str) -> bool {
        let Ok(conn) = self.conn.lock() else {
            return false;
        };
        conn.prepare_cached("SELECT 1 FROM kev WHERE cve_id = ?1")
            .and_then(|mut s| s.exists(params![cve]))
            .unwrap_or(false)
    }

    fn exploit_summary(&self, cve: &str) -> Option<String> {
        let conn = self.conn.lock().ok()?;
        let mut stmt = conn
            .prepare_cached("SELECT summary FROM exploit WHERE cve_id = ?1")
            .ok()?;
        stmt.query_row(params![cve.to_uppercase()], |r| r.get(0))
            .optional()
            .ok()
            .flatten()
    }

    /// Tags for one service, with the same semantics as
    /// [`crate::VulnDb::match_service`].
    pub fn match_service(
        &self,
        product: Option<&str>,
        version: Option<&str>,
        cpe: Option<&str>,
    ) -> Vec<Tag> {
        let parsed = cpe.and_then(crate::cve::parse_cpe);
        let product = product.or_else(|| parsed.as_ref().and_then(|p| p.product.as_deref()));
        let version = version.or_else(|| parsed.as_ref().and_then(|p| p.version.as_deref()));
        let Some(product) = product else {
            return Vec::new();
        };

        let mut tags = Vec::new();
        let mut seen: Vec<String> = Vec::new();
        for cand in self.candidates(product) {
            if !cand.rule.applies(product, version) || seen.contains(&cand.cve) {
                continue;
            }
            seen.push(cand.cve.clone());
            tags.push(Tag {
                name: "cve".to_string(),
                cve: Some(cand.cve.clone()),
                detail: Some(crate::cve::short_detail(&cand.description)),
            });
            if self.is_kev(&cand.cve) {
                tags.push(Tag {
                    name: "known-exploited".to_string(),
                    cve: Some(cand.cve.clone()),
                    detail: Some(
                        "listed in the CISA Known Exploited Vulnerabilities catalog".to_string(),
                    ),
                });
            }
        }
        tags
    }

    /// Append heuristic, CVE and exploit tags to `host`, as
    /// [`crate::VulnDb::tag_host`] does.
    pub fn tag_host(&self, host: &mut Host) {
        let mut new_tags = crate::heuristics::heuristic_tags(host);
        for svc in &host.services {
            new_tags.extend(self.match_service(
                svc.product.as_deref(),
                svc.version.as_deref(),
                svc.cpe.as_deref(),
            ));
        }
        let mut exploit_tags: Vec<Tag> = Vec::new();
        for tag in &new_tags {
            let Some(cve) = &tag.cve else { continue };
            if let Some(summary) = self.exploit_summary(cve) {
                exploit_tags.push(Tag {
                    name: "exploit-available".to_string(),
                    cve: Some(cve.clone()),
                    detail: Some(summary),
                });
            }
        }
        new_tags.extend(exploit_tags);

        for tag in new_tags {
            let dup = host
                .tags
                .iter()
                .any(|t| t.name == tag.name && t.cve == tag.cve);
            if !dup {
                host.tags.push(tag);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crusade_core::{Service, Transport};
    use std::net::IpAddr;

    fn entry(id: &str, product: &str, end_excl: Option<&str>) -> CveEntry {
        CveEntry {
            id: id.to_string(),
            description: format!("a flaw in {product}"),
            matches: vec![CpeMatch {
                vendor: "vendor".into(),
                product: product.into(),
                version: if end_excl.is_some() {
                    None
                } else {
                    Some("1.0".into())
                },
                version_start_including: None,
                version_start_excluding: None,
                version_end_including: None,
                version_end_excluding: end_excl.map(str::to_string),
            }],
        }
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("crusade-cache-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn builds_queries_and_reports_staleness() {
        let dir = tmpdir("basic");
        let entries = vec![
            entry("CVE-2026-0001", "nginx", Some("1.20.0")),
            entry("CVE-2026-0002", "OpenSSH", None),
            // A CVE with no usable rule is not worth a row.
            CveEntry {
                id: "CVE-2026-0003".into(),
                description: "no cpe".into(),
                matches: vec![],
            },
        ];
        let mut kev = KevCatalog::default();
        kev.entries.insert(
            "CVE-2026-0001".into(),
            crate::cve::KevEntry {
                cve_id: "CVE-2026-0001".into(),
                vendor: None,
                product: None,
            },
        );
        let mut exploits = HashMap::new();
        exploits.insert(
            "CVE-2026-0001".to_string(),
            ExploitRefs {
                edb_ids: vec!["42".into()],
                msf_modules: vec![],
            },
        );

        let rules = CveCache::build(&dir, &entries, &kev, &exploits).unwrap();
        assert_eq!(rules, 2, "only CVEs with rules are stored");

        let cache = CveCache::open(&dir).unwrap().expect("cache is usable");
        assert_eq!(cache.len(), 2);

        // Range rule: matches below the bound, not at or above it.
        let hit = cache.match_service(Some("nginx"), Some("1.18.0"), None);
        let names: Vec<&str> = hit.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, vec!["cve", "known-exploited"]);
        assert_eq!(hit[0].cve.as_deref(), Some("CVE-2026-0001"));
        assert!(cache
            .match_service(Some("nginx"), Some("1.20.0"), None)
            .is_empty());

        // Product match is case-insensitive in both directions.
        assert_eq!(
            cache
                .match_service(Some("openssh"), Some("1.0"), None)
                .len(),
            1
        );
        assert!(cache
            .match_service(Some("apache"), Some("1.0"), None)
            .is_empty());

        // CPE supplies product/version when they are not given directly, in
        // either CPE generation.
        assert_eq!(
            cache
                .match_service(None, None, Some("cpe:/a:vendor:nginx:1.18.0"))
                .len(),
            2,
            "2.2 URI form, as nmap emits"
        );
        assert_eq!(
            cache
                .match_service(
                    None,
                    None,
                    Some("cpe:2.3:a:vendor:nginx:1.18.0:*:*:*:*:*:*:*")
                )
                .len(),
            2,
            "2.3 formatted string, as NVD publishes"
        );

        // The memo answers a repeat lookup without touching the database.
        let before = cache.memo.lock().unwrap().len();
        let _ = cache.match_service(Some("nginx"), Some("1.18.0"), None);
        assert_eq!(cache.memo.lock().unwrap().len(), before);

        // A new feed file changes the fingerprint, so the cache reads as stale.
        std::fs::write(dir.join("nvdcve-2.0-2027.json"), "{}").unwrap();
        assert!(
            CveCache::open(&dir).unwrap().is_none(),
            "a changed feed set must invalidate the cache"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tag_host_matches_the_in_memory_path() {
        let dir = tmpdir("parity");
        let entries = vec![entry("CVE-2026-0001", "nginx", Some("1.20.0"))];
        let kev = KevCatalog::default();
        let exploits = HashMap::new();
        CveCache::build(&dir, &entries, &kev, &exploits).unwrap();
        let cache = CveCache::open(&dir).unwrap().unwrap();

        let mut host = Host::new("192.0.2.5".parse::<IpAddr>().unwrap());
        let mut svc = Service::new(80, Transport::Tcp);
        svc.product = Some("nginx".into());
        svc.version = Some("1.18.0".into());
        host.services.push(svc);

        let mut via_memory = host.clone();
        crate::VulnDb::from_entries(entries, KevCatalog::default()).tag_host(&mut via_memory);
        cache.tag_host(&mut host);

        let tags = |h: &Host| -> Vec<(String, Option<String>)> {
            let mut v: Vec<_> = h
                .tags
                .iter()
                .map(|t| (t.name.clone(), t.cve.clone()))
                .collect();
            v.sort();
            v
        };
        assert_eq!(tags(&host), tags(&via_memory));
        assert!(host
            .tags
            .iter()
            .any(|t| t.cve.as_deref() == Some("CVE-2026-0001")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_cache_is_not_an_error() {
        let dir = tmpdir("absent");
        assert!(CveCache::open(&dir).unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
