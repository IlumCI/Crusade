//! `crusade update-data` — fetch the free, no-key datasets into the data dir.
//!
//! Sources:
//!   * iptoasn.com ip2asn tables (IPv4 + IPv6), gzipped TSV.
//!   * CISA Known Exploited Vulnerabilities catalog (JSON).
//!   * NVD CVE JSON 2.0 bulk feeds (one per year, plus `modified`), keyless.
//!     Each is reduced to its matchable subset (CVEs with vulnerable CPE rules)
//!     and stored as a compact `nvdcve-2.0-<name>.json`.

use crate::config::Config;
use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use std::io::Read;
use std::path::Path;

const IP2ASN_V4: &str = "https://iptoasn.com/data/ip2asn-v4.tsv.gz";
const IP2ASN_V6: &str = "https://iptoasn.com/data/ip2asn-v6.tsv.gz";
const CISA_KEV: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
// Exploit cross-reference feeds (keyless, public):
const EXPLOITDB_CSV: &str =
    "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv";
/// NVD JSON 2.0 bulk feeds; `{}` is a year or `modified`.
const NVD_FEED: &str = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{}.json.gz";
/// First year NVD publishes a feed for.
const NVD_FIRST_YEAR: i32 = 2002;
const METASPLOIT_META: &str =
    "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json";

pub async fn update_data(cfg: &Config) -> Result<()> {
    let dir = &cfg.data.dir;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;

    download_gz(IP2ASN_V4, &dir.join("ip2asn-v4.tsv")).await?;
    download_gz(IP2ASN_V6, &dir.join("ip2asn-v6.tsv")).await?;
    download_plain(CISA_KEV, &dir.join("known_exploited_vulnerabilities.json")).await?;
    // Exploit cross-reference. Best-effort: a failure here shouldn't abort the
    // whole update (these hosts/paths change occasionally).
    if let Err(e) = download_plain(EXPLOITDB_CSV, &dir.join("files_exploits.csv")).await {
        eprintln!("  (exploit-db feed skipped: {e})");
    }
    if let Err(e) = download_plain(METASPLOIT_META, &dir.join("modules_metadata_base.json")).await {
        eprintln!("  (metasploit feed skipped: {e})");
    }

    let (kept, failed) = update_nvd(dir).await;
    if failed > 0 {
        eprintln!("  ({failed} NVD feed(s) failed; rerun update-data to retry)");
    }

    println!(
        "Datasets updated in {} ({kept} matchable CVEs from NVD).",
        dir.display()
    );
    Ok(())
}

/// Fetch every yearly NVD 2.0 feed plus `modified`, keep only CVEs that carry
/// a vulnerable CPE rule, and write each as a compact JSON 2.0 file. Returns
/// (CVEs kept, feeds failed). Per-feed failures are reported, not fatal.
async fn update_nvd(dir: &Path) -> (usize, usize) {
    let this_year = time::OffsetDateTime::now_utc().year();
    let names = (NVD_FIRST_YEAR..=this_year)
        .map(|y| y.to_string())
        .chain(std::iter::once("modified".to_string()));
    let (mut kept, mut failed) = (0, 0);
    for name in names {
        let url = NVD_FEED.replace("{}", &name);
        let out = dir.join(format!("nvdcve-2.0-{name}.json"));
        match fetch_nvd_compact(&url, &out).await {
            Ok(n) => kept += n,
            Err(e) => {
                eprintln!("  (NVD feed {name} skipped: {e:#})");
                failed += 1;
            }
        }
    }
    (kept, failed)
}

async fn fetch_nvd_compact(url: &str, out: &Path) -> Result<usize> {
    let gz = fetch(url).await?;
    let mut text = String::new();
    GzDecoder::new(&gz[..])
        .read_to_string(&mut text)
        .with_context(|| format!("gunzip {url}"))?;
    let mut entries = crusade_vuln::load_nvd(&text)?;
    drop(text);
    entries.retain(|e| !e.matches.is_empty());
    std::fs::write(out, crusade_vuln::to_nvd2_json(&entries))
        .with_context(|| format!("writing {}", out.display()))?;
    eprintln!("  → {} ({} CVEs)", out.display(), entries.len());
    Ok(entries.len())
}

async fn fetch(url: &str) -> Result<Vec<u8>> {
    eprintln!("↓ {url}");
    let bytes = reqwest::get(url)
        .await
        .with_context(|| format!("GET {url}"))?
        .error_for_status()?
        .bytes()
        .await?;
    Ok(bytes.to_vec())
}

async fn download_gz(url: &str, out: &Path) -> Result<()> {
    let gz = fetch(url).await?;
    let mut decoder = GzDecoder::new(&gz[..]);
    let mut text = String::new();
    decoder
        .read_to_string(&mut text)
        .with_context(|| format!("gunzip {url}"))?;
    std::fs::write(out, text).with_context(|| format!("writing {}", out.display()))?;
    eprintln!("  → {}", out.display());
    Ok(())
}

async fn download_plain(url: &str, out: &Path) -> Result<()> {
    let bytes = fetch(url).await?;
    std::fs::write(out, bytes).with_context(|| format!("writing {}", out.display()))?;
    eprintln!("  → {}", out.display());
    Ok(())
}
