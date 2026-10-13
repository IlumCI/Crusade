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
use std::sync::{Mutex, OnceLock};

use anyhow::{Context, Result};
use crusade_core::{Host, Tag};
use rusqlite::{params, Connection, OptionalExtension};

use crate::cve::{CpeMatch, CveEntry, KevCatalog};
use crate::exploit::ExploitRefs;
use crate::resolve::{Candidate, ProductVocab, Resolution, Tier as Resolution2Tier};

/// Schema of the cache database. Bumped when the layout changes, which forces
/// a rebuild rather than a misread.
const CACHE_SCHEMA: i64 = 2;

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
-- The distinct (vendor, product) pairs the rules name: the only identifiers
-- `resolve` is allowed to return, so a resolved CPE always has CVEs behind it.
CREATE TABLE IF NOT EXISTS cpe_vocab (
    vendor  TEXT NOT NULL,
    product TEXT NOT NULL,
    rules   INTEGER NOT NULL,
    PRIMARY KEY (vendor, product)
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
/// Derive `cpe_vocab` from the rules already in a schema-1 cache.
fn migrate_v1_to_v2(conn: &Connection) -> Result<usize> {
    conn.execute_batch(SCHEMA_SQL)?;
    let have: i64 = conn.query_row("SELECT count(*) FROM cpe_vocab", [], |r| r.get(0))?;
    if have == 0 {
        conn.execute_batch(
            "INSERT INTO cpe_vocab (vendor, product, rules)
             SELECT vendor, product, COUNT(*) FROM cve_match GROUP BY vendor, product",
        )?;
    }
    let pairs: i64 = conn.query_row("SELECT count(*) FROM cpe_vocab", [], |r| r.get(0))?;
    conn.execute(
        "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema', ?1)",
        params![CACHE_SCHEMA.to_string()],
    )?;
    Ok(pairs as usize)
}

pub struct CveCache {
    conn: Mutex<Connection>,
    /// Memo of lower-cased product -> candidate rules, filled as products are
    /// seen. A scan meets the same handful of products repeatedly.
    memo: Mutex<HashMap<String, Vec<CachedMatch>>>,
    /// Whether to fall back to CPE resolution when a product name matches no
    /// rule literally. Off unless the caller turns it on, since it attaches
    /// weaker evidence than an exact match.
    resolution: bool,
    /// The vocabulary, loaded on first resolution and not before.
    vocab: OnceLock<ProductVocab>,
    /// Memo of product name -> resolution, including the misses: a scan is
    /// mostly the same few unresolvable banners repeated.
    resolved: Mutex<HashMap<String, Option<Resolution>>>,
    /// Weakest tier accepted.
    floor: Resolution2Tier,
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
        let schema = meta("schema").and_then(|v| v.parse::<i64>().ok());
        let fresh = meta("sources").as_deref() == Some(source_fingerprint(dir).as_str());
        // Schema 2 only added `cpe_vocab`, which is derived from rules the
        // cache already holds. Deriving it in place takes a second; declaring
        // the cache stale would cost a re-download and re-parse of half a
        // gigabyte of feeds for data that is already there.
        if schema == Some(1) && fresh {
            match migrate_v1_to_v2(&conn) {
                Ok(pairs) => tracing::info!(pairs, "derived the CPE vocabulary in place"),
                Err(e) => tracing::warn!("could not migrate the CVE cache: {e}"),
            }
        }
        let schema_ok = meta("schema").and_then(|v| v.parse::<i64>().ok()) == Some(CACHE_SCHEMA);
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
            resolution: false,
            vocab: OnceLock::new(),
            resolved: Mutex::new(HashMap::new()),
            floor: Resolution2Tier::Lexical,
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
                // The vocabulary is derived from the rules just inserted
                // rather than counted in Rust: SQLite groups several million
                // rows faster than a HashMap keyed on two owned Strings, and
                // the counts have to agree with the table regardless.
                tx.execute_batch(
                    "INSERT INTO cpe_vocab (vendor, product, rules)
                     SELECT vendor, product, COUNT(*) FROM cve_match
                     GROUP BY vendor, product",
                )?;
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

    /// The `(vendor, product)` vocabulary.
    ///
    /// Loaded on demand: it is ~120k rows, and most commands never resolve a
    /// product at all.
    pub fn vocab(&self) -> Result<ProductVocab> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| anyhow::anyhow!("CVE cache lock poisoned"))?;
        let mut stmt =
            conn.prepare("SELECT vendor, product, rules FROM cpe_vocab ORDER BY rowid")?;
        let rows = stmt.query_map([], |r| {
            Ok(Candidate {
                vendor: r.get(0)?,
                product: r.get(1)?,
                rules: r.get::<_, i64>(2)? as u32,
            })
        })?;
        Ok(ProductVocab::new(
            rows.collect::<std::result::Result<Vec<_>, _>>()?,
        ))
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

    /// Refuse resolutions weaker than this tier.
    ///
    /// The tiers differ in measured precision, so which ones to trust is a
    /// judgement about how a particular index is used rather than a constant.
    pub fn set_resolution_floor(&mut self, tier: Resolution2Tier) {
        self.floor = tier;
    }

    /// Turn CPE resolution on or off for this cache.
    ///
    /// With it on, a product name that matches no rule literally is resolved
    /// against the vocabulary of pairs the rules do name (see
    /// [`crate::resolve`]), and any CVE found that way carries the tier and
    /// score in its detail. With it off the behaviour is exact-match only.
    pub fn set_resolution(&mut self, on: bool) {
        self.resolution = on;
    }

    /// Resolve a product name to a CPE pair in the vocabulary, memoised.
    pub fn resolve_product(&self, name: &str) -> Option<Resolution> {
        let key = name.to_ascii_lowercase();
        if let Ok(memo) = self.resolved.lock() {
            if let Some(hit) = memo.get(&key) {
                return hit.clone();
            }
        }
        let out = self
            .vocab_lazy()
            .resolve(name)
            .filter(|r| r.tier.strength() >= self.floor.strength());
        if let Ok(mut memo) = self.resolved.lock() {
            memo.insert(key, out.clone());
        }
        out
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

        // Exact first. Only when the name names nothing does resolution run:
        // a product NVD already knows by that name must not be re-interpreted.
        let mut candidates = self.candidates(product);
        let mut via: Option<Resolution> = None;
        if candidates.is_empty() && self.resolution {
            if let Some(res) = self.resolve_product(product) {
                let resolved = self.candidates(&res.product);
                if !resolved.is_empty() {
                    candidates = resolved;
                    via = Some(res);
                }
            }
        }
        let match_name = via.as_ref().map(|r| r.product.clone());
        let match_name = match_name.as_deref().unwrap_or(product);

        let mut tags = Vec::new();
        let mut seen: Vec<String> = Vec::new();
        for cand in candidates {
            if !cand.rule.applies(match_name, version) || seen.contains(&cand.cve) {
                continue;
            }
            seen.push(cand.cve.clone());
            let detail = match &via {
                // A resolved match is weaker evidence than an exact one, so
                // the substitution travels with the tag rather than being
                // folded away where nobody can audit it.
                Some(r) => format!(
                    "{} [{}]",
                    crate::cve::short_detail(&cand.description),
                    r.explain()
                ),
                None => crate::cve::short_detail(&cand.description),
            };
            tags.push(Tag {
                name: "cve".to_string(),
                cve: Some(cand.cve.clone()),
                detail: Some(detail),
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

    /// Name the software behind each banner that fingerprinting could not
    /// place, using the CVE vocabulary (see [`crate::identify`]).
    ///
    /// Only services with no product are touched: a fingerprint match is
    /// evidence from a hand-written rule about this exact banner, and nothing
    /// here outranks it. Each name that is filled in records how it was
    /// arrived at, since the product decides which CVEs the host carries.
    pub fn identify_products(&self, host: &mut Host) -> usize {
        if !self.resolution {
            return 0;
        }
        let mut named = 0;
        let mut evidence: Vec<String> = Vec::new();
        for svc in &mut host.services {
            if svc.product.is_some() {
                continue;
            }
            let Some(banner) = svc.banner.as_deref() else {
                continue;
            };
            let vocab = self.vocab_lazy();
            let Some(r) = crate::identify::identify(banner, vocab) else {
                continue;
            };
            evidence.push(format!(
                "port {}: {} ({}, {:.2})",
                svc.port,
                r.product,
                r.tier.as_str(),
                r.score
            ));
            svc.product = Some(r.product.clone());
            named += 1;
        }
        if named > 0 {
            host.tags.push(Tag {
                name: "product-from-banner".to_string(),
                cve: None,
                detail: Some(format!(
                    "named from the banner, not a fingerprint: {}",
                    evidence.join("; ")
                )),
            });
        }
        named
    }

    /// The vocabulary, loading it on first use.
    fn vocab_lazy(&self) -> &ProductVocab {
        self.vocab.get_or_init(|| {
            let t = std::time::Instant::now();
            let v = self.vocab().unwrap_or_else(|e| {
                tracing::warn!("no CPE vocabulary: {e}");
                ProductVocab::new(Vec::new())
            });
            tracing::info!(
                ms = t.elapsed().as_millis() as u64,
                pairs = v.len(),
                "loaded CPE vocabulary"
            );
            v
        })
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

    /// A product name NVD spells differently finds nothing exactly, and is
    /// found through the vocabulary once resolution is on — with the
    /// substitution recorded in the tag, not hidden.
    #[test]
    fn resolution_finds_cves_under_nvds_own_name() {
        let dir = tmpdir("resolve");
        let rule = |vendor: &str, product: &str| CpeMatch {
            vendor: vendor.into(),
            product: product.into(),
            version: None,
            version_start_including: None,
            version_start_excluding: None,
            version_end_including: None,
            version_end_excluding: Some("2.4.60".into()),
        };
        // Enough pairs for rarity to mean something: with one pair in the
        // vocabulary every token is both unique and universal, and the
        // weighting that does the work has nothing to weigh.
        let entries = vec![
            CveEntry {
                id: "CVE-2026-0101".into(),
                description: "a flaw in the apache http server".into(),
                matches: vec![rule("apache", "http_server")],
            },
            CveEntry {
                id: "CVE-2026-0102".into(),
                description: "unrelated".into(),
                matches: vec![
                    rule("apache", "tomcat"),
                    rule("f5", "nginx"),
                    rule("openbsd", "openssh"),
                    rule("exim", "exim"),
                    rule("postfix", "postfix"),
                    rule("isc", "bind"),
                    rule("dovecot", "dovecot"),
                    rule("lighttpd", "lighttpd"),
                    rule("redhat", "vsftpd"),
                ],
            },
        ];
        CveCache::build(&dir, &entries, &KevCatalog::default(), &HashMap::new()).unwrap();

        let mut cache = CveCache::open(&dir).unwrap().unwrap();
        // Exact matching alone: the name NVD never used finds nothing, and
        // the name it did use still works.
        assert!(cache
            .match_service(Some("Apache httpd"), Some("2.4.50"), None)
            .is_empty());
        assert!(!cache
            .match_service(Some("http_server"), Some("2.4.50"), None)
            .is_empty());

        cache.set_resolution(true);
        let tags = cache.match_service(Some("Apache httpd"), Some("2.4.50"), None);
        let cve = tags.iter().find(|t| t.name == "cve").expect("resolved CVE");
        assert_eq!(cve.cve.as_deref(), Some("CVE-2026-0101"));
        let detail = cve.detail.clone().unwrap_or_default();
        assert!(
            detail.contains("apache:http_server"),
            "the resolution has to travel with the tag: {detail}"
        );

        // A version outside the rule is still outside it after resolution:
        // resolving the name must not loosen the version comparison.
        assert!(cache
            .match_service(Some("Apache httpd"), Some("2.4.70"), None)
            .is_empty());
        std::fs::remove_dir_all(&dir).ok();
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
