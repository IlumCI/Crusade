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
//!   and open ports (self-signed/expired certs, default pages, plaintext HTTP,
//!   exposed databases, etc.).
//!
//! # Safety / scope
//!
//! Every tag produced by this crate is **INFORMATIONAL ONLY**. This crate does
//! **not** connect to, probe, verify, or exploit any host or service, and it
//! performs no network I/O whatsoever. A tag means "based on what we already
//! observed, this looks relevant" — never "we confirmed this is exploitable".
//! Acting on a tag is left entirely to the operator.

pub mod cve;
pub mod heuristics;

pub use cve::{
    load_kev, load_nvd, parse_cpe, version_cmp, CpeMatch, CveEntry, KevCatalog, KevEntry,
    ParsedCpe, VulnDb,
};
pub use heuristics::heuristic_tags;
