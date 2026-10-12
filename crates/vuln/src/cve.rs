//! CVE/CPE matching from free, no-key vulnerability feeds.
//!
//! This module parses a small, deliberately tolerant subset of two public
//! feeds that an operator can download by hand (no network access happens
//! here):
//!
//! * **NVD JSON feeds**, either the current CVE API 2.0 / JSON 2.0 feed schema
//!   (`vulnerabilities[].cve`, `cpeMatch[].criteria`) or the retired 1.1
//!   data-feed schema (`CVE_Items`, `cpe23Uri`). Per CVE we keep the id, the
//!   English description, and the list of *vulnerable* CPE match rules plus any
//!   simple `versionStart*/versionEnd*` bounds.
//! * **The CISA KEV catalog** (`known_exploited_vulnerabilities.json`): the set
//!   of CVE ids that are known to be exploited in the wild, with vendor/product.
//!
//! Matching is intentionally simple but correct for dotted numeric versions:
//! products are compared case-insensitively and a service version is tested
//! against either an exact CPE version or the inclusive/exclusive range bounds.
//!
//! Every result is an *informational* [`Tag`] only. Nothing in this module
//! connects to, probes, verifies, or exploits anything.

use std::cmp::Ordering;
use std::collections::HashMap;

use anyhow::Context;
use crusade_core::{Host, Tag};
use serde::Deserialize;

use crate::exploit::ExploitRefs;

/// Maximum length of the description copied into a tag's `detail`.
const DETAIL_MAX: usize = 180;

// ---------------------------------------------------------------------------
// Parsed, in-memory representation
// ---------------------------------------------------------------------------

/// A single vulnerable CPE rule extracted from an NVD configuration node.
#[derive(Debug, Clone)]
pub struct CpeMatch {
    pub vendor: String,
    pub product: String,
    /// Exact version from the CPE, or `None` when the CPE used `*`/`-` (ANY).
    pub version: Option<String>,
    pub version_start_including: Option<String>,
    pub version_start_excluding: Option<String>,
    pub version_end_including: Option<String>,
    pub version_end_excluding: Option<String>,
}

impl CpeMatch {
    fn has_range(&self) -> bool {
        self.version_start_including.is_some()
            || self.version_start_excluding.is_some()
            || self.version_end_including.is_some()
            || self.version_end_excluding.is_some()
    }

    /// Does this rule apply to `product` at `version`?
    ///
    /// Product match is case-insensitive. When the service version is unknown
    /// we only match a rule that is unconstrained (affects every version), to
    /// avoid flooding unknown services with speculative CVEs.
    pub(crate) fn applies(&self, product: &str, version: Option<&str>) -> bool {
        if !self.product.eq_ignore_ascii_case(product) {
            return false;
        }
        match version {
            None => self.version.is_none() && !self.has_range(),
            Some(v) => {
                if let Some(exact) = &self.version {
                    return version_cmp(exact, v) == Ordering::Equal;
                }
                self.in_range(v)
            }
        }
    }

    fn in_range(&self, v: &str) -> bool {
        if let Some(s) = &self.version_start_including {
            if version_cmp(v, s) == Ordering::Less {
                return false;
            }
        }
        if let Some(s) = &self.version_start_excluding {
            if version_cmp(v, s) != Ordering::Greater {
                return false;
            }
        }
        if let Some(e) = &self.version_end_including {
            if version_cmp(v, e) == Ordering::Greater {
                return false;
            }
        }
        if let Some(e) = &self.version_end_excluding {
            if version_cmp(v, e) != Ordering::Less {
                return false;
            }
        }
        // No bounds at all => an unversioned CPE that affects every version.
        true
    }
}

/// One CVE with just enough data to match services and label them.
#[derive(Debug, Clone)]
pub struct CveEntry {
    pub id: String,
    pub description: String,
    pub matches: Vec<CpeMatch>,
}

/// One entry from the CISA KEV catalog.
#[derive(Debug, Clone)]
pub struct KevEntry {
    pub cve_id: String,
    pub vendor: Option<String>,
    pub product: Option<String>,
}

/// The parsed KEV catalog, indexed by CVE id.
#[derive(Debug, Clone, Default)]
pub struct KevCatalog {
    pub entries: HashMap<String, KevEntry>,
}

impl KevCatalog {
    pub fn contains(&self, cve_id: &str) -> bool {
        self.entries.contains_key(cve_id)
    }
}

/// A combined, queryable vulnerability database built from one or more NVD
/// feeds and (optionally) the CISA KEV catalog.
#[derive(Debug, Clone, Default)]
pub struct VulnDb {
    cves: Vec<CveEntry>,
    /// Lower-cased CPE product -> indices into `cves` that carry a rule for it.
    by_product: HashMap<String, Vec<usize>>,
    kev: KevCatalog,
    /// CVE (upper-cased) → known public exploits, populated additively by
    /// [`VulnDb::load_exploits`]. Empty until exploit feeds are loaded.
    exploits: HashMap<String, ExploitRefs>,
}

impl VulnDb {
    /// An empty database (matches nothing).
    pub fn new() -> Self {
        VulnDb::default()
    }

    /// Build a database from several NVD feed JSON documents plus an optional
    /// KEV catalog JSON document.
    ///
    /// A CVE id seen in a later feed replaces the earlier entry, so passing the
    /// yearly feeds followed by the `modified` feed yields the newest data.
    pub fn from_feeds(nvd_jsons: &[String], kev_json: Option<&str>) -> anyhow::Result<Self> {
        let mut parsed = Vec::new();
        for (i, json) in nvd_jsons.iter().enumerate() {
            parsed.push(load_nvd(json).with_context(|| format!("parsing NVD feed #{i}"))?);
        }
        let kev = match kev_json {
            Some(j) => load_kev(j).context("parsing CISA KEV catalog")?,
            None => KevCatalog::default(),
        };
        Ok(VulnDb::from_entries(parsed.into_iter().flatten(), kev))
    }

    /// Build a database from already-parsed entries (later ids win).
    pub fn from_entries(entries: impl IntoIterator<Item = CveEntry>, kev: KevCatalog) -> Self {
        let mut pos: HashMap<String, usize> = HashMap::new();
        let mut cves: Vec<CveEntry> = Vec::new();
        for e in entries {
            match pos.get(&e.id) {
                Some(&i) => cves[i] = e,
                None => {
                    pos.insert(e.id.clone(), cves.len());
                    cves.push(e);
                }
            }
        }
        let mut by_product: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, cve) in cves.iter().enumerate() {
            let mut seen: Vec<String> = Vec::new();
            for m in &cve.matches {
                let key = m.product.to_ascii_lowercase();
                if !seen.contains(&key) {
                    by_product.entry(key.clone()).or_default().push(i);
                    seen.push(key);
                }
            }
        }
        VulnDb {
            cves,
            by_product,
            kev,
            exploits: HashMap::new(),
        }
    }

    /// Mutable access to the exploit index, for [`VulnDb::load_exploits`].
    pub(crate) fn exploits_mut(&mut self) -> &mut HashMap<String, ExploitRefs> {
        &mut self.exploits
    }

    /// The known public exploits for `cve`, if any (CVE id is matched
    /// case-insensitively).
    pub fn exploits_for(&self, cve: &str) -> Option<&ExploitRefs> {
        self.exploits.get(&cve.to_uppercase())
    }

    /// The parsed CVE entries, for building the on-disk cache.
    pub fn entries(&self) -> &[CveEntry] {
        &self.cves
    }

    /// The exploit index, for building the on-disk cache.
    pub fn exploits(&self) -> &HashMap<String, ExploitRefs> {
        &self.exploits
    }

    /// Number of CVEs loaded.
    pub fn len(&self) -> usize {
        self.cves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cves.is_empty()
    }

    /// Match a single service description against the database.
    ///
    /// `product`/`version` take precedence; when either is missing they are
    /// recovered from `cpe` if a parseable CPE string was supplied. Returns a
    /// `"cve"` tag per matching CVE, and an additional `"known-exploited"` tag
    /// for any match that also appears in the KEV catalog.
    pub fn match_service(
        &self,
        product: Option<&str>,
        version: Option<&str>,
        cpe: Option<&str>,
    ) -> Vec<Tag> {
        let parsed = cpe.and_then(parse_cpe);
        let product = product.or_else(|| parsed.as_ref().and_then(|p| p.product.as_deref()));
        let version = version.or_else(|| parsed.as_ref().and_then(|p| p.version.as_deref()));

        let Some(product) = product else {
            return Vec::new();
        };

        let Some(candidates) = self.by_product.get(&product.to_ascii_lowercase()) else {
            return Vec::new();
        };
        let mut tags = Vec::new();
        for cve in candidates.iter().map(|&i| &self.cves[i]) {
            if cve.matches.iter().any(|m| m.applies(product, version)) {
                tags.push(Tag {
                    name: "cve".to_string(),
                    cve: Some(cve.id.clone()),
                    detail: Some(short_detail(&cve.description)),
                });
                if self.kev.contains(&cve.id) {
                    tags.push(Tag {
                        name: "known-exploited".to_string(),
                        cve: Some(cve.id.clone()),
                        detail: Some(
                            "listed in the CISA Known Exploited Vulnerabilities catalog"
                                .to_string(),
                        ),
                    });
                }
            }
        }
        tags
    }

    /// Append both heuristic tags and CVE-match tags to `host`, de-duplicated
    /// by `(name, cve)`.
    ///
    /// The tags produced here are INFORMATIONAL only: this never verifies,
    /// exploits, or connects to anything.
    pub fn tag_host(&self, host: &mut Host) {
        let mut new_tags = crate::heuristics::heuristic_tags(host);
        for svc in &host.services {
            new_tags.extend(self.match_service(
                svc.product.as_deref(),
                svc.version.as_deref(),
                svc.cpe.as_deref(),
            ));
        }

        // Exploit cross-reference: for each CVE already tagged (from NVD/KEV
        // matching), record that a PUBLIC exploit EXISTS when the exploit index
        // knows one. This never verifies or runs anything — it only reports the
        // existence of a public exploit for a matched CVE.
        if !self.exploits.is_empty() {
            let mut exploit_tags: Vec<Tag> = Vec::new();
            for tag in &new_tags {
                let Some(cve) = &tag.cve else { continue };
                if let Some(refs) = self.exploits.get(&cve.to_uppercase()) {
                    exploit_tags.push(Tag {
                        name: "exploit-available".to_string(),
                        cve: Some(cve.clone()),
                        detail: Some(refs.summary()),
                    });
                }
            }
            new_tags.extend(exploit_tags);
        }

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

// ---------------------------------------------------------------------------
// Feed parsing
// ---------------------------------------------------------------------------

/// Parse the vulnerable-CPE subset of an NVD JSON feed.
///
/// Accepts both the JSON 2.0 schema (CVE API 2.0 responses and the
/// `nvdcve-2.0-*.json` bulk feeds) and the retired 1.1 data-feed schema.
pub fn load_nvd(json: &str) -> anyhow::Result<Vec<CveEntry>> {
    let feed: NvdFeed = serde_json::from_str(json).context("invalid NVD JSON")?;
    let mut out = Vec::with_capacity(feed.cve_items.len() + feed.vulnerabilities.len());

    for v in feed.vulnerabilities {
        let cve = v.cve;
        if cve.id.is_empty() {
            continue;
        }
        let description = cve
            .descriptions
            .into_iter()
            .find(|d| d.lang == "en")
            .map(|d| d.value)
            .unwrap_or_default();
        let mut matches = Vec::new();
        for cfg in &cve.configurations {
            for node in &cfg.nodes {
                for cm in &node.cpe_match {
                    push_match(cm, &mut matches);
                }
            }
        }
        out.push(CveEntry {
            id: cve.id,
            description,
            matches,
        });
    }

    for item in feed.cve_items {
        let id = item.cve.meta.id;
        if id.is_empty() {
            continue;
        }
        let description = item
            .cve
            .description
            .description_data
            .into_iter()
            .find(|d| d.lang == "en")
            .map(|d| d.value)
            .unwrap_or_default();

        let mut matches = Vec::new();
        if let Some(cfg) = item.configurations {
            for node in &cfg.nodes {
                collect_matches(node, &mut matches);
            }
        }
        out.push(CveEntry {
            id,
            description,
            matches,
        });
    }
    Ok(out)
}

/// Serialize entries as a compact NVD JSON 2.0 document that [`load_nvd`]
/// reads back. Used by `update-data` to store only the matchable subset of the
/// (very large) upstream feeds.
pub fn to_nvd2_json(entries: &[CveEntry]) -> String {
    let vulns: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| {
            let cpe_match: Vec<serde_json::Value> = e
                .matches
                .iter()
                .map(|m| {
                    let mut o = serde_json::json!({
                        "vulnerable": true,
                        "criteria": format!(
                            "cpe:2.3:a:{}:{}:{}:*:*:*:*:*:*:*",
                            m.vendor,
                            m.product,
                            m.version.as_deref().unwrap_or("*")
                        ),
                    });
                    let bounds = [
                        ("versionStartIncluding", &m.version_start_including),
                        ("versionStartExcluding", &m.version_start_excluding),
                        ("versionEndIncluding", &m.version_end_including),
                        ("versionEndExcluding", &m.version_end_excluding),
                    ];
                    for (k, v) in bounds {
                        if let Some(v) = v {
                            o[k] = serde_json::Value::String(v.clone());
                        }
                    }
                    o
                })
                .collect();
            serde_json::json!({
                "cve": {
                    "id": e.id,
                    "descriptions": [{ "lang": "en", "value": e.description }],
                    "configurations": [{ "nodes": [{ "cpeMatch": cpe_match }] }],
                }
            })
        })
        .collect();
    serde_json::json!({ "format": "NVD_CVE", "version": "2.0", "vulnerabilities": vulns })
        .to_string()
}

/// Recursively collect vulnerable `cpe_match` rules from a node and its
/// children.
fn collect_matches(node: &NvdNode, out: &mut Vec<CpeMatch>) {
    for cm in &node.cpe_match {
        push_match(cm, out);
    }
    for child in &node.children {
        collect_matches(child, out);
    }
}

/// Convert one vulnerable match rule (either schema) into a [`CpeMatch`].
fn push_match(cm: &NvdCpeMatch, out: &mut Vec<CpeMatch>) {
    if !cm.vulnerable {
        return;
    }
    let Some(parsed) = parse_cpe(&cm.cpe23_uri) else {
        return;
    };
    // A CPE match must name a vendor+product to be usable.
    let (Some(vendor), Some(product)) = (parsed.vendor, parsed.product) else {
        return;
    };
    out.push(CpeMatch {
        vendor,
        product,
        version: parsed.version,
        version_start_including: cm.version_start_including.clone(),
        version_start_excluding: cm.version_start_excluding.clone(),
        version_end_including: cm.version_end_including.clone(),
        version_end_excluding: cm.version_end_excluding.clone(),
    });
}

/// Parse the CISA KEV catalog JSON.
pub fn load_kev(json: &str) -> anyhow::Result<KevCatalog> {
    let feed: KevFeed = serde_json::from_str(json).context("invalid KEV JSON")?;
    let mut entries = HashMap::with_capacity(feed.vulnerabilities.len());
    for v in feed.vulnerabilities {
        if v.cve_id.is_empty() {
            continue;
        }
        entries.insert(
            v.cve_id.clone(),
            KevEntry {
                cve_id: v.cve_id,
                vendor: v.vendor_project,
                product: v.product,
            },
        );
    }
    Ok(KevCatalog { entries })
}

// ---------------------------------------------------------------------------
// CPE parsing & version comparison
// ---------------------------------------------------------------------------

/// The fields we care about from a parsed `cpe:2.3:` string.
#[derive(Debug, Clone, Default)]
pub struct ParsedCpe {
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
}

/// Parse a CPE name, in either of the two forms that occur in practice:
///
/// * CPE 2.3 formatted string, as NVD publishes:
///   `cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*`
/// * CPE 2.2 URI, as `nmap-service-probes` emits and Crusade therefore stores:
///   `cpe:/a:igor_sysoev:nginx:1.18.0`
///
/// Returns `None` for anything else. Fields set to `*` (ANY) or `-` (NA)
/// become `None`, as does a missing trailing field.
pub fn parse_cpe(cpe: &str) -> Option<ParsedCpe> {
    let parts: Vec<&str> = cpe.split(':').collect();
    if parts.first() != Some(&"cpe") {
        return None;
    }
    // 2.3: cpe:2.3:part:vendor:product:version:...
    // 2.2: cpe:/part:vendor:product:version
    let offset = match parts.get(1) {
        Some(&"2.3") => 2,
        Some(p) if p.starts_with('/') => 1,
        _ => return None,
    };
    let field = |i: usize| -> Option<String> {
        match parts.get(i) {
            None | Some(&"*") | Some(&"-") | Some(&"") => None,
            Some(s) => Some(s.to_string()),
        }
    };
    // part / vendor / product / version follow the prefix in both forms.
    let (vendor, product, version) = (offset + 1, offset + 2, offset + 3);
    if parts.len() <= product {
        return None;
    }
    Some(ParsedCpe {
        vendor: field(vendor),
        product: field(product),
        version: field(version),
    })
}

/// Compare two dotted version strings numerically (a small semver-ish compare).
///
/// Components are split on `.`; each component's leading digits are parsed as a
/// number (so `1.10` > `1.9`), and a missing component counts as `0`
/// (so `2.0` == `2.0.0`). Non-numeric trailing text within a component is
/// ignored for ordering.
pub fn version_cmp(a: &str, b: &str) -> Ordering {
    fn segments(s: &str) -> Vec<u64> {
        s.split('.')
            .map(|part| {
                let digits: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
                digits.parse::<u64>().unwrap_or(0)
            })
            .collect()
    }
    let va = segments(a);
    let vb = segments(b);
    let n = va.len().max(vb.len());
    for i in 0..n {
        let x = va.get(i).copied().unwrap_or(0);
        let y = vb.get(i).copied().unwrap_or(0);
        match x.cmp(&y) {
            Ordering::Equal => continue,
            other => return other,
        }
    }
    Ordering::Equal
}

/// Trim a CVE description down to a short, single-line tag detail.
pub(crate) fn short_detail(desc: &str) -> String {
    let one_line = desc.split_whitespace().collect::<Vec<_>>().join(" ");
    if one_line.chars().count() <= DETAIL_MAX {
        one_line
    } else {
        let truncated: String = one_line.chars().take(DETAIL_MAX).collect();
        format!("{}…", truncated.trim_end())
    }
}

// ---------------------------------------------------------------------------
// Serde shapes for the NVD 2.0 and 1.1 feeds (tolerant subset)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct NvdFeed {
    /// 1.1 data-feed schema.
    #[serde(rename = "CVE_Items", default)]
    cve_items: Vec<NvdItem>,
    /// 2.0 schema (API responses and bulk feeds).
    #[serde(default)]
    vulnerabilities: Vec<Nvd2Vuln>,
}

#[derive(Deserialize)]
struct Nvd2Vuln {
    cve: Nvd2Cve,
}

#[derive(Deserialize)]
struct Nvd2Cve {
    #[serde(default)]
    id: String,
    #[serde(default)]
    descriptions: Vec<NvdDescData>,
    #[serde(default)]
    configurations: Vec<Nvd2Config>,
}

#[derive(Deserialize)]
struct Nvd2Config {
    #[serde(default)]
    nodes: Vec<Nvd2Node>,
}

#[derive(Deserialize)]
struct Nvd2Node {
    #[serde(rename = "cpeMatch", default)]
    cpe_match: Vec<NvdCpeMatch>,
}

#[derive(Deserialize)]
struct NvdItem {
    cve: NvdCve,
    #[serde(default)]
    configurations: Option<NvdConfigurations>,
}

#[derive(Deserialize)]
struct NvdCve {
    #[serde(rename = "CVE_data_meta")]
    meta: NvdMeta,
    #[serde(default)]
    description: NvdDescription,
}

#[derive(Deserialize)]
struct NvdMeta {
    #[serde(rename = "ID", default)]
    id: String,
}

#[derive(Deserialize, Default)]
struct NvdDescription {
    #[serde(rename = "description_data", default)]
    description_data: Vec<NvdDescData>,
}

#[derive(Deserialize)]
struct NvdDescData {
    #[serde(default)]
    lang: String,
    #[serde(default)]
    value: String,
}

#[derive(Deserialize, Default)]
struct NvdConfigurations {
    #[serde(default)]
    nodes: Vec<NvdNode>,
}

#[derive(Deserialize, Default)]
struct NvdNode {
    #[serde(default)]
    cpe_match: Vec<NvdCpeMatch>,
    #[serde(default)]
    children: Vec<NvdNode>,
}

#[derive(Deserialize)]
struct NvdCpeMatch {
    #[serde(default)]
    vulnerable: bool,
    /// `cpe23Uri` in 1.1, `criteria` in 2.0.
    #[serde(rename = "cpe23Uri", alias = "criteria", default)]
    cpe23_uri: String,
    #[serde(rename = "versionStartIncluding", default)]
    version_start_including: Option<String>,
    #[serde(rename = "versionStartExcluding", default)]
    version_start_excluding: Option<String>,
    #[serde(rename = "versionEndIncluding", default)]
    version_end_including: Option<String>,
    #[serde(rename = "versionEndExcluding", default)]
    version_end_excluding: Option<String>,
}

// ---------------------------------------------------------------------------
// Serde shapes for the CISA KEV catalog
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct KevFeed {
    #[serde(default)]
    vulnerabilities: Vec<KevVuln>,
}

#[derive(Deserialize)]
struct KevVuln {
    #[serde(rename = "cveID", default)]
    cve_id: String,
    #[serde(rename = "vendorProject", default)]
    vendor_project: Option<String>,
    #[serde(default)]
    product: Option<String>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const NVD: &str = r#"{
      "CVE_Items": [
        {
          "cve": {
            "CVE_data_meta": { "ID": "CVE-2021-23017" },
            "description": {
              "description_data": [
                { "lang": "en", "value": "A security issue in nginx resolver was identified." }
              ]
            }
          },
          "configurations": {
            "nodes": [
              {
                "operator": "OR",
                "cpe_match": [
                  {
                    "vulnerable": true,
                    "cpe23Uri": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
                    "versionStartIncluding": "1.18.0",
                    "versionEndExcluding": "1.20.0"
                  }
                ]
              }
            ]
          }
        }
      ]
    }"#;

    const KEV: &str = r#"{
      "title": "CISA KEV",
      "vulnerabilities": [
        { "cveID": "CVE-2021-23017", "vendorProject": "nginx", "product": "nginx" }
      ]
    }"#;

    #[test]
    fn matches_in_range_and_reports_kev() {
        let db = VulnDb::from_feeds(&[NVD.to_string()], Some(KEV)).unwrap();
        assert_eq!(db.len(), 1);

        let tags = db.match_service(Some("nginx"), Some("1.18.0"), None);
        assert!(
            tags.iter()
                .any(|t| t.name == "cve" && t.cve.as_deref() == Some("CVE-2021-23017")),
            "expected a cve tag, got {tags:?}"
        );
        assert!(
            tags.iter()
                .any(|t| t.name == "known-exploited" && t.cve.as_deref() == Some("CVE-2021-23017")),
            "expected a known-exploited tag, got {tags:?}"
        );
    }

    #[test]
    fn version_out_of_range_does_not_match() {
        let db = VulnDb::from_feeds(&[NVD.to_string()], Some(KEV)).unwrap();
        let tags = db.match_service(Some("nginx"), Some("1.25.0"), None);
        assert!(tags.is_empty(), "1.25.0 is out of range, got {tags:?}");
    }

    #[test]
    fn exact_cpe_version_matches() {
        let nvd = r#"{
          "CVE_Items": [
            {
              "cve": {
                "CVE_data_meta": { "ID": "CVE-2020-0001" },
                "description": { "description_data": [{ "lang": "en", "value": "demo" }] }
              },
              "configurations": {
                "nodes": [
                  { "cpe_match": [
                    { "vulnerable": true, "cpe23Uri": "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*" }
                  ] }
                ]
              }
            }
          ]
        }"#;
        let db = VulnDb::from_feeds(&[nvd.to_string()], None).unwrap();
        assert!(!db
            .match_service(Some("nginx"), Some("1.18.0"), None)
            .is_empty());
        assert!(db
            .match_service(Some("nginx"), Some("1.19.0"), None)
            .is_empty());
        // No KEV feed => no known-exploited tag.
        assert!(db
            .match_service(Some("nginx"), Some("1.18.0"), None)
            .iter()
            .all(|t| t.name != "known-exploited"));
    }

    #[test]
    fn product_match_is_case_insensitive_and_can_use_cpe() {
        let db = VulnDb::from_feeds(&[NVD.to_string()], None).unwrap();
        // Product/version recovered from the CPE string alone.
        let tags = db.match_service(
            None,
            None,
            Some("cpe:2.3:a:nginx:NGINX:1.19.0:*:*:*:*:*:*:*"),
        );
        assert!(tags.iter().any(|t| t.name == "cve"), "got {tags:?}");
    }

    #[test]
    fn version_cmp_edge_cases() {
        assert_eq!(version_cmp("1.18.0", "1.20.0"), Ordering::Less);
        // numeric, not lexical: 9 < 10
        assert_eq!(version_cmp("1.9.0", "1.10.0"), Ordering::Less);
        // missing trailing components count as zero
        assert_eq!(version_cmp("2.0", "2.0.0"), Ordering::Equal);
        assert_eq!(version_cmp("1.18.0", "1.18.0"), Ordering::Equal);
        assert_eq!(version_cmp("1.21.6", "1.21.0"), Ordering::Greater);
        // trailing non-numeric text is ignored for ordering
        assert_eq!(version_cmp("1.0.0a", "1.0.0"), Ordering::Equal);
    }

    #[test]
    fn parse_cpe_handles_any_fields() {
        let p = parse_cpe("cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*").unwrap();
        assert_eq!(p.vendor.as_deref(), Some("nginx"));
        assert_eq!(p.product.as_deref(), Some("nginx"));
        assert_eq!(p.version, None);
        assert!(parse_cpe("not-a-cpe").is_none());
    }

    #[test]
    fn tag_host_marks_cve_with_known_public_exploit() {
        use crusade_core::{Host, Service, Transport};
        use std::net::{IpAddr, Ipv4Addr};

        // NVD matches nginx 1.18.0 -> CVE-2021-23017.
        let mut db = VulnDb::from_feeds(&[NVD.to_string()], None).unwrap();
        // Exploit index knows a public exploit for exactly that CVE.
        let edb = "id,file,description,codes\n\
7777,exploits/x.py,\"nginx resolver bug\",CVE-2021-23017\n";
        db.load_exploits(Some(edb), None).unwrap();

        let mut host = Host::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));
        let mut svc = Service::new(80, Transport::Tcp);
        svc.product = Some("nginx".to_string());
        svc.version = Some("1.18.0".to_string());
        host.services.push(svc);

        db.tag_host(&mut host);

        let exploit = host.tags.iter().find(|t| t.name == "exploit-available");
        let exploit = exploit.expect("expected an exploit-available tag");
        assert_eq!(exploit.cve.as_deref(), Some("CVE-2021-23017"));
        assert!(
            exploit
                .detail
                .as_deref()
                .unwrap_or_default()
                .contains("EDB-7777"),
            "detail was {:?}",
            exploit.detail
        );
    }

    #[test]
    fn tag_host_does_not_mark_cve_without_known_exploit() {
        use crusade_core::{Host, Service, Transport};
        use std::net::{IpAddr, Ipv4Addr};

        let mut db = VulnDb::from_feeds(&[NVD.to_string()], None).unwrap();
        // Exploit index only knows an UNRELATED CVE.
        let edb = "id,file,description,codes\n\
8888,exploits/y.py,\"unrelated\",CVE-1999-0001\n";
        db.load_exploits(Some(edb), None).unwrap();

        let mut host = Host::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)));
        let mut svc = Service::new(80, Transport::Tcp);
        svc.product = Some("nginx".to_string());
        svc.version = Some("1.18.0".to_string());
        host.services.push(svc);

        db.tag_host(&mut host);

        // The host is still tagged with the CVE itself ...
        assert!(host.tags.iter().any(|t| t.name == "cve"));
        // ... but nothing claims a public exploit exists for it.
        assert!(
            !host.tags.iter().any(|t| t.name == "exploit-available"),
            "unexpected exploit-available tag: {:?}",
            host.tags
        );
    }

    const NVD2: &str = r#"{
      "format": "NVD_CVE", "version": "2.0",
      "vulnerabilities": [
        { "cve": {
            "id": "CVE-2023-38408",
            "descriptions": [
              { "lang": "es", "value": "otro" },
              { "lang": "en", "value": "OpenSSH ssh-agent PKCS#11 issue." }
            ],
            "configurations": [
              { "nodes": [
                  { "operator": "OR", "negate": false, "cpeMatch": [
                      { "vulnerable": true,
                        "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                        "versionEndExcluding": "9.3",
                        "matchCriteriaId": "X" },
                      { "vulnerable": false,
                        "criteria": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*" }
                  ] }
              ] }
            ]
        } },
        { "cve": { "id": "CVE-2000-0001", "descriptions": [] } }
      ]
    }"#;

    #[test]
    fn nvd2_parses_criteria_and_bounds() {
        let entries = load_nvd(NVD2).unwrap();
        assert_eq!(entries.len(), 2);
        let e = &entries[0];
        assert_eq!(e.id, "CVE-2023-38408");
        assert_eq!(e.description, "OpenSSH ssh-agent PKCS#11 issue.");
        assert_eq!(e.matches.len(), 1, "non-vulnerable rules are skipped");
        assert_eq!(e.matches[0].product, "openssh");
        assert_eq!(e.matches[0].version_end_excluding.as_deref(), Some("9.3"));
        assert!(entries[1].matches.is_empty());
    }

    #[test]
    fn nvd2_matches_service_case_insensitively() {
        let db = VulnDb::from_feeds(&[NVD2.to_string()], None).unwrap();
        let hit = db.match_service(Some("OpenSSH"), Some("8.9p1"), None);
        assert_eq!(hit.len(), 1);
        assert_eq!(hit[0].cve.as_deref(), Some("CVE-2023-38408"));
        assert!(db
            .match_service(Some("OpenSSH"), Some("9.3"), None)
            .is_empty());
        assert!(db
            .match_service(Some("nginx"), Some("1.0"), None)
            .is_empty());
    }

    #[test]
    fn later_feed_replaces_same_cve_id() {
        let newer = NVD2.replace("\"9.3\"", "\"8.0\"");
        let db = VulnDb::from_feeds(&[NVD2.to_string(), newer], None).unwrap();
        assert_eq!(db.len(), 2);
        assert!(db
            .match_service(Some("openssh"), Some("8.9"), None)
            .is_empty());
        assert_eq!(
            db.match_service(Some("openssh"), Some("7.4"), None).len(),
            1
        );
    }

    #[test]
    fn compact_nvd2_roundtrips() {
        let v1 = load_nvd(NVD).unwrap();
        let back = load_nvd(&to_nvd2_json(&v1)).unwrap();
        assert_eq!(back.len(), v1.len());
        assert_eq!(back[0].id, v1[0].id);
        assert_eq!(back[0].description, v1[0].description);
        assert_eq!(back[0].matches.len(), v1[0].matches.len());
        let (a, b) = (&v1[0].matches[0], &back[0].matches[0]);
        assert_eq!(a.product, b.product);
        assert_eq!(a.version, b.version);
        assert_eq!(a.version_start_including, b.version_start_including);
        assert_eq!(a.version_end_excluding, b.version_end_excluding);
    }

    #[test]
    fn parses_both_cpe_generations() {
        // 2.3, as NVD publishes.
        let c = parse_cpe("cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*").unwrap();
        assert_eq!(c.vendor.as_deref(), Some("nginx"));
        assert_eq!(c.product.as_deref(), Some("nginx"));
        assert_eq!(c.version.as_deref(), Some("1.18.0"));

        // 2.2 URI, as nmap emits and Crusade stores.
        let c = parse_cpe("cpe:/a:igor_sysoev:nginx:1.18.0").unwrap();
        assert_eq!(c.vendor.as_deref(), Some("igor_sysoev"));
        assert_eq!(c.product.as_deref(), Some("nginx"));
        assert_eq!(c.version.as_deref(), Some("1.18.0"));

        // 2.2 without a version is still usable for the product.
        let c = parse_cpe("cpe:/a:apache:http_server").unwrap();
        assert_eq!(c.product.as_deref(), Some("http_server"));
        assert_eq!(c.version, None);

        // ANY/NA fields read as unknown.
        let c = parse_cpe("cpe:2.3:a:vendor:prod:*:*:*:*:*:*:*:*").unwrap();
        assert_eq!(c.version, None);
        let c = parse_cpe("cpe:/o:vendor:prod:-").unwrap();
        assert_eq!(c.version, None);

        // Not CPEs.
        assert!(parse_cpe("").is_none());
        assert!(parse_cpe("nginx/1.18.0").is_none());
        assert!(parse_cpe("cpe:2.4:a:v:p:1").is_none());
        assert!(parse_cpe("cpe:/a:vendor").is_none(), "no product");
    }
}
