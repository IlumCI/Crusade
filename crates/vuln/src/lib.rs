//! crusade-vuln: offline vulnerability tagging for observed hosts.
//!
//! This crate turns the metadata Crusade already collected about a [`Host`]
//! into informational [`crusade_core::Tag`]s. It works in two ways:
//!
//! * [`cve`] matches each service's product/version/CPE against a [`VulnDb`]
//!   built from free, no-key feeds the operator downloads separately (NVD JSON
//!   data feeds and the CISA KEV catalog). No network access happens here — the
//!   feeds are consumed from strings/disk by the caller.
//! * [`heuristics`] derives feed-free tags from TLS certificates, HTTP titles,
//!   open ports, and observed authentication posture (self-signed/expired
//!   certs, default pages, plaintext HTTP, exposed/unauthenticated databases
//!   and ICS devices, etc.).
//! * [`exploit`] cross-references matched CVEs against free, no-key public
//!   exploit feeds (Exploit-DB's `files_exploits.csv` and Metasploit's
//!   `modules_metadata_base.json`) to record that a public exploit *exists*.
//!
//! # Safety / scope
//!
//! Every tag produced by this crate is **INFORMATIONAL ONLY**. This crate does
//! **not** connect to, probe, verify, or exploit any host or service, and it
//! performs no network I/O whatsoever. A tag means "based on what we already
//! observed, this looks relevant" — never "we confirmed this is exploitable".
//! In particular, the exploit cross-reference only records that a public
//! exploit EXISTS for a matched CVE — it never downloads, runs, or verifies any
//! exploit. Acting on a tag is left entirely to the operator.

pub mod cache;
pub mod cve;
pub mod exploit;
pub mod heuristics;
pub mod honeypot;
pub mod identify;
pub mod resolve;

pub use cache::{source_fingerprint, CveCache, CACHE_FILE};
pub use cve::{
    load_kev, load_nvd, parse_cpe, to_nvd2_json, version_cmp, CpeMatch, CveEntry, KevCatalog,
    KevEntry, ParsedCpe, VulnDb,
};
pub use exploit::{parse_exploitdb_csv, parse_metasploit_json, ExploitRefs};
pub use heuristics::heuristic_tags;
pub use honeypot::{HoneypotRules, HoneypotScorer, HONEYPOT_TAG_THRESHOLD};
pub use identify::{candidate_names, identify};
pub use resolve::{Candidate, ProductVocab, Resolution, Tier};
