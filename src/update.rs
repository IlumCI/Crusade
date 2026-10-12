//! `crusade update-data` — fetch the free, no-key datasets into the data dir.
//!
//! Sources:
//!   * iptoasn.com ip2asn tables (IPv4 + IPv6), gzipped TSV.
//!   * CISA Known Exploited Vulnerabilities catalog (JSON).
//!
//! NVD CVE feeds are large and now key-gated; drop any `nvdcve-*.json` files
//! into the data dir yourself and the vuln tagger will consume them.

use crate::config::Config;
use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use std::io::Read;
use std::path::Path;

const IP2ASN_V4: &str = "https://iptoasn.com/data/ip2asn-v4.tsv.gz";
const IP2ASN_V6: &str = "https://iptoasn.com/data/ip2asn-v6.tsv.gz";
const CISA_KEV: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

pub async fn update_data(cfg: &Config) -> Result<()> {
    let dir = &cfg.data.dir;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;

    download_gz(IP2ASN_V4, &dir.join("ip2asn-v4.tsv")).await?;
    download_gz(IP2ASN_V6, &dir.join("ip2asn-v6.tsv")).await?;
    download_plain(CISA_KEV, &dir.join("known_exploited_vulnerabilities.json")).await?;

    println!(
        "Datasets updated in {}. (For CVE matching, add NVD `nvdcve-*.json` feeds there too.)",
        dir.display()
    );
    Ok(())
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
