//! Certificate Transparency lookups via [crt.sh](https://crt.sh/).
//!
//! Queries crt.sh's JSON endpoint for every logged certificate whose name
//! matches `%.<domain>` (a SQL-style wildcard), then extracts the `name_value`
//! fields into a deduplicated, sorted list of hostnames. This surfaces
//! subdomains that appear in CT logs even if they were never scanned directly.

use std::collections::BTreeSet;

use serde::Deserialize;

/// Build the crt.sh JSON query URL for a domain.
///
/// Kept as a pure function so it can be unit-tested without a network round-trip.
/// `%25` is the URL-encoded `%` SQL wildcard, so this matches all subdomains.
pub fn crtsh_url(domain: &str) -> String {
    format!("https://crt.sh/?q=%25.{domain}&output=json")
}

/// One entry in the crt.sh JSON array (we only care about `name_value`).
#[derive(Debug, Deserialize)]
struct CrtEntry {
    name_value: String,
}

/// Parse a crt.sh JSON response body into a sorted, deduplicated list of
/// hostnames.
///
/// `name_value` fields may hold several newline-separated names and leading
/// wildcards (`*.example.com`); these are normalised (wildcard stripped,
/// lowercased).
pub fn parse_crtsh_names(json: &str) -> anyhow::Result<Vec<String>> {
    let entries: Vec<CrtEntry> = serde_json::from_str(json)?;
    let mut set: BTreeSet<String> = BTreeSet::new();
    for entry in entries {
        for raw in entry.name_value.split('\n') {
            let name = raw
                .trim()
                .trim_start_matches("*.")
                .trim()
                .to_ascii_lowercase();
            if !name.is_empty() {
                set.insert(name);
            }
        }
    }
    Ok(set.into_iter().collect())
}

/// Query crt.sh for all subdomains of `domain`.
pub async fn crtsh_subdomains(domain: &str) -> anyhow::Result<Vec<String>> {
    let url = crtsh_url(domain);
    let client = reqwest::Client::builder()
        .user_agent(concat!("crusade-enrich/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let body = client
        .get(&url)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    parse_crtsh_names(&body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_is_built_as_expected() {
        assert_eq!(
            crtsh_url("example.com"),
            "https://crt.sh/?q=%25.example.com&output=json"
        );
    }

    #[test]
    fn parse_dedups_sorts_and_strips_wildcards() {
        let json = r#"[
            {"name_value": "www.example.com\n*.example.com"},
            {"name_value": "api.example.com"},
            {"name_value": "WWW.EXAMPLE.COM"},
            {"name_value": "example.com"}
        ]"#;
        let names = parse_crtsh_names(json).unwrap();
        assert_eq!(
            names,
            vec![
                "api.example.com".to_string(),
                "example.com".to_string(),
                "www.example.com".to_string(),
            ]
        );
    }
}
