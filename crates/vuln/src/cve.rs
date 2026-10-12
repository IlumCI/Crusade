//! CVE/CPE matching from free, no-key vulnerability feeds.
//!
//! This module parses a small, deliberately tolerant subset of two public
//! feeds that an operator can download by hand (no network access happens
//! here):
//!
//! * **NVD JSON feeds** (the classic 1.1 data-feed schema): per CVE we keep the
//!   id, the English description, and the list of *vulnerable* CPE match rules
//!   (`cpe23Uri` plus any simple `versionStart*/versionEnd*` bounds).
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
    fn applies(&self, product: &str, version: Option<&str>) -> bool {
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
    kev: KevCatalog,
}

impl VulnDb {
    /// An empty database (matches nothing).
    pub fn new() -> Self {
        VulnDb::default()
    }

    /// Build a database from several NVD feed JSON documents plus an optional
    /// KEV catalog JSON document.
    pub fn from_feeds(nvd_jsons: &[String], kev_json: Option<&str>) -> anyhow::Result<Self> {
        let mut cves = Vec::new();
        for (i, json) in nvd_jsons.iter().enumerate() {
            let parsed = load_nvd(json)
                .with_context(|| format!("parsing NVD feed #{i}"))?;
            cves.extend(parsed);
        }
        let kev = match kev_json {
            Some(j) => load_kev(j).context("parsing CISA KEV catalog")?,
            None => KevCatalog::default(),
        };
        Ok(VulnDb { cves, kev })
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

        let mut tags = Vec::new();
        for cve in &self.cves {
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
                        detail: Some("listed in the CISA Known Exploited Vulnerabilities catalog".to_string()),
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

/// Parse the vulnerable-CPE subset of an NVD 1.1 JSON data feed.
pub fn load_nvd(json: &str) -> anyhow::Result<Vec<CveEntry>> {
    let feed: NvdFeed = serde_json::from_str(json).context("invalid NVD JSON")?;
    let mut out = Vec::with_capacity(feed.cve_items.len());
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

/// Recursively collect vulnerable `cpe_match` rules from a node and its
/// children.
fn collect_matches(node: &NvdNode, out: &mut Vec<CpeMatch>) {
    for cm in &node.cpe_match {
        if !cm.vulnerable {
            continue;
        }
        if let Some(parsed) = parse_cpe(&cm.cpe23_uri) {
            // A CPE match must name a vendor+product to be usable.
            let (Some(vendor), Some(product)) = (parsed.vendor, parsed.product) else {
                continue;
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
    }
    for child in &node.children {
        collect_matches(child, out);
    }
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

/// Parse a CPE 2.3 formatted-string URI, e.g.
/// `cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*`.
///
/// Returns `None` for anything that is not a `cpe:2.3:` string. Fields set to
/// `*` (ANY) or `-` (NA) become `None`.
pub fn parse_cpe(cpe: &str) -> Option<ParsedCpe> {
    let parts: Vec<&str> = cpe.split(':').collect();
    // cpe : 2.3 : part : vendor : product : version : ...
    if parts.len() < 6 || parts[0] != "cpe" || parts[1] != "2.3" {
        return None;
    }
    let field = |s: &str| -> Option<String> {
        if s == "*" || s == "-" || s.is_empty() {
            None
        } else {
            Some(s.to_string())
        }
    };
    Some(ParsedCpe {
        vendor: field(parts[3]),
        product: field(parts[4]),
        version: field(parts[5]),
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
fn short_detail(desc: &str) -> String {
    let one_line = desc.split_whitespace().collect::<Vec<_>>().join(" ");
    if one_line.chars().count() <= DETAIL_MAX {
        one_line
    } else {
        let truncated: String = one_line.chars().take(DETAIL_MAX).collect();
        format!("{}…", truncated.trim_end())
    }
}

// ---------------------------------------------------------------------------
// Serde shapes for the NVD 1.1 feed (tolerant subset)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct NvdFeed {
    #[serde(rename = "CVE_Items", default)]
    cve_items: Vec<NvdItem>,
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
    #[serde(rename = "cpe23Uri", default)]
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
            tags.iter().any(|t| t.name == "cve" && t.cve.as_deref() == Some("CVE-2021-23017")),
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
        assert!(!db.match_service(Some("nginx"), Some("1.18.0"), None).is_empty());
        assert!(db.match_service(Some("nginx"), Some("1.19.0"), None).is_empty());
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
        let tags = db.match_service(None, None, Some("cpe:2.3:a:nginx:NGINX:1.19.0:*:*:*:*:*:*:*"));
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
}
