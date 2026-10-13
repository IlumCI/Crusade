//! Score CPE resolution against nmap's own CPE assignments.
//!
//! ```text
//! cargo run --release --example resolve_precision -- \
//!     <data dir> /usr/share/nmap/nmap-service-probes
//! ```
//!
//! `nmap-service-probes` carries, for thousands of its match rules, both a
//! human product name (`p/Apache httpd/`) and the CPE its author assigned
//! (`cpe:/a:apache:http_server`). That is independent ground truth for exactly
//! the mapping `crusade_vuln::resolve` performs, curated by people who were
//! not thinking about this resolver — which is worth more than any test set
//! written alongside the code it tests.
//!
//! Reported per tier, because the tiers are meant to differ in reliability and
//! the point of recording a tier on every resolution is that a caller can
//! treat them differently.

use std::collections::BTreeMap;
use std::path::Path;

use crusade_vuln::{CveCache, Tier};

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let data_dir = args.next().unwrap_or_else(|| "data".to_string());
    let probes = args
        .next()
        .unwrap_or_else(|| "/usr/share/nmap/nmap-service-probes".to_string());

    let cases = parse_probes(Path::new(&probes))?;
    println!("{} (product, cpe) pair(s) from {probes}", cases.len());

    let cache = CveCache::open(Path::new(&data_dir))?
        .ok_or_else(|| anyhow::anyhow!("no usable CVE cache in {data_dir}"))?;
    let vocab = cache.vocab()?;
    println!("{} CPE pair(s) in the vocabulary\n", vocab.len());

    // Only pairs whose true CPE is in the vocabulary can be got right: the
    // resolver answers from the indexed CVE rules, so software with no CVEs
    // is not a miss, it is out of scope.
    let mut answerable = 0usize;
    let mut tally: BTreeMap<&str, [usize; 3]> = BTreeMap::new();
    let mut misses: Vec<(String, String, String)> = Vec::new();
    for (name, want_vendor, want_product) in &cases {
        if !vocab.contains(want_vendor, want_product) {
            continue;
        }
        answerable += 1;
        match vocab.resolve(name) {
            None => tally.entry("none").or_default()[2] += 1,
            Some(r) => {
                let slot = if &r.vendor == want_vendor && &r.product == want_product {
                    0
                } else if &r.product == want_product {
                    1
                } else {
                    2
                };
                tally.entry(tier_name(r.tier)).or_default()[slot] += 1;
                if slot == 2 && misses.len() < 15 {
                    misses.push((
                        name.clone(),
                        format!("{}:{}", r.vendor, r.product),
                        format!("{want_vendor}:{want_product}"),
                    ));
                }
            }
        }
    }

    println!("{answerable} pair(s) whose true CPE the vocabulary contains\n");
    println!(
        "{:<10} {:>8} {:>14} {:>8}",
        "tier", "exact", "product only", "wrong"
    );
    let mut totals = [0usize; 3];
    for (tier, counts) in &tally {
        println!(
            "{:<10} {:>8} {:>14} {:>8}",
            tier, counts[0], counts[1], counts[2]
        );
        for (t, c) in totals.iter_mut().zip(counts) {
            *t += c;
        }
    }
    let graded = totals.iter().sum::<usize>().max(1);
    println!(
        "\nvendor and product: {:.1}%   product alone: {:.1}%   wrong or none: {:.1}%",
        100.0 * totals[0] as f64 / graded as f64,
        100.0 * (totals[0] + totals[1]) as f64 / graded as f64,
        100.0 * totals[2] as f64 / graded as f64
    );

    if !misses.is_empty() {
        println!("\nwrong answers (a sample):");
        for (name, got, want) in misses {
            println!("  {name:<34} -> {got:<34} want {want}");
        }
    }
    Ok(())
}

fn tier_name(t: Tier) -> &'static str {
    t.as_str()
}

/// Pull `(product name, cpe vendor, cpe product)` out of nmap's match lines.
///
/// Only application CPEs (`cpe:/a:`) with both parts present are usable, and
/// a line whose product name is empty says nothing about the mapping.
fn parse_probes(path: &Path) -> anyhow::Result<Vec<(String, String, String)>> {
    let text = std::fs::read_to_string(path)?;
    let mut out: Vec<(String, String, String)> = Vec::new();
    for line in text.lines() {
        if !line.starts_with("match ") && !line.starts_with("softmatch ") {
            continue;
        }
        let Some(product) = field(line, " p/") else {
            continue;
        };
        let Some(cpe) = line.split(" cpe:/a:").nth(1) else {
            continue;
        };
        let cpe = cpe.split_whitespace().next().unwrap_or("");
        let mut parts = cpe.split(':');
        let (Some(vendor), Some(cpe_product)) = (parts.next(), parts.next()) else {
            continue;
        };
        if product.is_empty() || vendor.is_empty() || cpe_product.is_empty() {
            continue;
        }
        // A product name with a version template in it (`$1`) is not a name.
        if product.contains('$') {
            continue;
        }
        let entry = (
            product.to_string(),
            vendor.to_ascii_lowercase(),
            cpe_product.to_ascii_lowercase(),
        );
        if !out.contains(&entry) {
            out.push(entry);
        }
    }
    Ok(out)
}

/// The value of a `p/…/`-style field, honouring nmap's choice of delimiter.
fn field(line: &str, key: &str) -> Option<String> {
    let at = line.find(key)? + key.len();
    let rest = &line[at..];
    let delim = key.chars().last()?;
    let end = rest.find(delim)?;
    Some(rest[..end].to_string())
}
