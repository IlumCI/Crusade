//! Reverse DNS resolution.
//!
//! Uses [`hickory_resolver`] configured from the host's system resolver config
//! (`/etc/resolv.conf` and friends). Reverse DNS is best-effort enrichment:
//! this module never surfaces errors — any failure (no config, timeout, NXDOMAIN)
//! yields an empty list.

use std::net::IpAddr;

use hickory_resolver::TokioAsyncResolver;

/// Resolve the PTR (reverse DNS) names for an IP address.
///
/// Returns the resolved hostnames with trailing dots stripped, or an empty
/// vector on any failure.
pub async fn reverse_dns(ip: IpAddr) -> Vec<String> {
    let resolver = match TokioAsyncResolver::tokio_from_system_conf() {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    match resolver.reverse_lookup(ip).await {
        Ok(lookup) => lookup
            .iter()
            .map(|name| name.to_utf8().trim_end_matches('.').to_string())
            .filter(|n| !n.is_empty())
            .collect(),
        Err(_) => Vec::new(),
    }
}
