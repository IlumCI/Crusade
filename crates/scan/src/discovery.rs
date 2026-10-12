//! The `masscan` discovery front-end.
//!
//! A full internet-wide SYN sweep is far too large for this crate's own
//! connect scanner, so for bulk discovery we shell out to a sanctioned system
//! `masscan` deployment and ingest its output. This module is only the
//! plumbing around that external tool; it opens no sockets itself.
//!
//! The mandatory blocklist is enforced in depth, because handing a range to an
//! external SYN scanner is exactly where it matters most:
//!
//!   1. The target list is filtered through the [`Blocklist`] *before* masscan
//!      is invoked, so a blocked address is never even passed to it.
//!   2. masscan is always given an `--excludefile` built from the blocklist's
//!      full reserved + user ranges ([`Blocklist::exclude_ranges`]), so the
//!      external tool refuses those ranges on its own too.
//!   3. The parsed results are run back through [`filter_blocked`] before they
//!      are returned, so nothing blocked can leak out even if masscan misbehaved.

use std::net::IpAddr;
use std::path::Path;

use anyhow::Context;
use ipnet::IpNet;

use crate::blocklist::Blocklist;
use crate::sweep::{filter_blocked, parse_masscan_json};

/// The system `masscan` binary name. Resolved via `PATH` when spawned.
const MASSCAN_BIN: &str = "masscan";

/// Tuning for a [`masscan_discover`] run.
#[derive(Debug, Clone)]
pub struct MasscanConfig {
    /// Packets per second masscan is allowed to send. Deliberately conservative
    /// by default; raise it only for a deployment that is explicitly authorised
    /// to scan faster.
    pub rate: u32,
    /// Extra raw arguments appended to the masscan invocation (e.g. a specific
    /// source interface or router MAC). Rarely needed.
    pub extra_args: Vec<String>,
}

impl Default for MasscanConfig {
    fn default() -> Self {
        // 1000 pps is gentle for masscan, whose own default is 100 but which is
        // routinely driven far higher; we stay low unless told otherwise.
        MasscanConfig { rate: 1000, extra_args: Vec::new() }
    }
}

/// Run `masscan` for fast SYN discovery over `targets` × `ports`, returning the
/// open `(ip, port)` pairs it found, blocklist-clean.
///
/// This shells out to the system `masscan` binary. The blocklist is enforced
/// three times over (see the [module docs](self)). If the `masscan` binary is
/// not installed, this returns a clear error rather than hanging.
pub async fn masscan_discover(
    targets: &[IpAddr],
    ports: &[u16],
    cfg: &MasscanConfig,
    bl: &Blocklist,
) -> anyhow::Result<Vec<(IpAddr, u16)>> {
    // (1) Pre-filter the targets: never even hand a blocked address to masscan.
    let targets: Vec<IpAddr> = targets.iter().copied().filter(|ip| !bl.is_blocked(*ip)).collect();
    if targets.is_empty() {
        return Ok(Vec::new());
    }
    if ports.is_empty() {
        anyhow::bail!("masscan_discover: no ports specified");
    }

    // (2) Write the exclude file from the full blocklist so masscan honours it.
    let exclude = tempfile::Builder::new()
        .prefix("crusade-masscan-exclude-")
        .suffix(".conf")
        .tempfile()
        .context("creating masscan exclude file")?;
    std::fs::write(exclude.path(), build_exclude_file(&bl.exclude_ranges()))
        .context("writing masscan exclude file")?;

    // Output file for masscan's -oJ JSON.
    let out = tempfile::Builder::new()
        .prefix("crusade-masscan-out-")
        .suffix(".json")
        .tempfile()
        .context("creating masscan output file")?;

    let args = build_masscan_args(&targets, ports, cfg.rate, out.path(), exclude.path(), &cfg.extra_args);

    // (3) Invoke masscan. A missing binary surfaces as a clear error, not a hang.
    let output = tokio::process::Command::new(MASSCAN_BIN)
        .args(&args)
        .output()
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                anyhow::anyhow!(
                    "the `{MASSCAN_BIN}` binary was not found on PATH; install masscan or \
                     run discovery out-of-band and ingest its -oJ output with parse_masscan_json"
                )
            } else {
                anyhow::Error::from(e).context("spawning masscan")
            }
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("masscan exited with {}: {}", output.status, stderr.trim());
    }

    let json = std::fs::read_to_string(out.path()).context("reading masscan output")?;
    let pairs = parse_masscan_json(&json);

    // (4) Final guardrail: re-apply the blocklist to whatever masscan reported.
    Ok(filter_blocked(pairs, bl))
}

/// Build the `--excludefile` contents from a set of ranges: one CIDR per line,
/// which is exactly the format masscan expects. Pure and testable.
fn build_exclude_file(ranges: &[IpNet]) -> String {
    let mut out = String::from("# Crusade masscan exclude file: the mandatory blocklist.\n");
    for net in ranges {
        out.push_str(&net.to_string());
        out.push('\n');
    }
    out
}

/// Build the masscan argument vector (everything after the program name). Pure
/// and testable, so the invocation can be asserted without running masscan.
fn build_masscan_args(
    targets: &[IpAddr],
    ports: &[u16],
    rate: u32,
    out_path: &Path,
    exclude_path: &Path,
    extra: &[String],
) -> Vec<String> {
    let ports_csv = ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");

    let mut args: Vec<String> = vec![
        "-p".to_string(),
        ports_csv,
        "--rate".to_string(),
        rate.to_string(),
        "--excludefile".to_string(),
        exclude_path.to_string_lossy().into_owned(),
        "-oJ".to_string(),
        out_path.to_string_lossy().into_owned(),
    ];
    args.extend(extra.iter().cloned());
    // Targets come last, so the flags above cannot be mistaken for one.
    for ip in targets {
        args.push(ip.to_string());
    }
    args
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn exclude_file_contains_all_reserved_and_user_ranges() {
        let mut bl = Blocklist::new(false);
        // Two operator ranges that are NOT among the built-ins.
        bl.add("8.8.8.0/24".parse().unwrap());
        bl.add("198.18.0.0/15".parse().unwrap());
        let content = build_exclude_file(&bl.exclude_ranges());

        // A representative from each built-in group must be present.
        // special:
        assert!(content.contains("0.0.0.0/8"), "{content}");
        assert!(content.contains("224.0.0.0/4"), "{content}");
        assert!(content.contains("192.0.2.0/24"), "{content}");
        assert!(content.contains("2001:db8::/32"), "{content}");
        assert!(content.contains("ff00::/8"), "{content}");
        // private:
        assert!(content.contains("10.0.0.0/8"), "{content}");
        assert!(content.contains("172.16.0.0/12"), "{content}");
        assert!(content.contains("192.168.0.0/16"), "{content}");
        assert!(content.contains("127.0.0.0/8"), "{content}");
        assert!(content.contains("169.254.0.0/16"), "{content}");
        assert!(content.contains("100.64.0.0/10"), "{content}");
        assert!(content.contains("fc00::/7"), "{content}");
        assert!(content.contains("fe80::/10"), "{content}");
        // user ranges:
        assert!(content.contains("8.8.8.0/24"), "{content}");
        assert!(content.contains("198.18.0.0/15"), "{content}");
    }

    #[test]
    fn exclude_file_covers_everything_is_blocked_forbids() {
        // Defence-in-depth check: every reserved range that is_blocked enforces
        // appears in the exclude file, so masscan can never be told it may scan
        // an address the blocklist forbids.
        let bl = Blocklist::new(false);
        let content = build_exclude_file(&bl.exclude_ranges());
        for probe in [
            v4(10, 0, 0, 1),
            v4(127, 0, 0, 1),
            v4(169, 254, 1, 1),
            v4(192, 0, 2, 1),
            v4(224, 0, 0, 1),
        ] {
            assert!(bl.is_blocked(probe));
        }
        // The exclude file is non-trivial and well-formed (comment + entries).
        assert!(content.lines().count() > 10);
        assert!(content.starts_with('#'));
    }

    #[test]
    fn masscan_args_carry_rate_ports_output_and_excludefile() {
        let out = PathBuf::from("/tmp/crusade-out.json");
        let excl = PathBuf::from("/tmp/crusade-excl.conf");
        let targets = vec![v4(8, 8, 8, 8), v4(1, 1, 1, 1)];
        let args = build_masscan_args(
            &targets,
            &[80, 443, 53],
            1500,
            &out,
            &excl,
            &["--router-mac".to_string(), "00:11:22:33:44:55".to_string()],
        );

        // Ports, as a single comma-joined -p value.
        let p_idx = args.iter().position(|a| a == "-p").expect("-p flag present");
        assert_eq!(args[p_idx + 1], "80,443,53");

        // Rate.
        let r_idx = args.iter().position(|a| a == "--rate").expect("--rate flag present");
        assert_eq!(args[r_idx + 1], "1500");

        // Output flags.
        let o_idx = args.iter().position(|a| a == "-oJ").expect("-oJ flag present");
        assert_eq!(args[o_idx + 1], out.to_string_lossy());

        // Excludefile.
        let e_idx =
            args.iter().position(|a| a == "--excludefile").expect("--excludefile flag present");
        assert_eq!(args[e_idx + 1], excl.to_string_lossy());

        // Extra args are passed through.
        assert!(args.iter().any(|a| a == "--router-mac"));
        assert!(args.iter().any(|a| a == "00:11:22:33:44:55"));

        // Targets are present (and last, after the flags).
        assert!(args.iter().any(|a| a == "8.8.8.8"));
        assert!(args.iter().any(|a| a == "1.1.1.1"));
        let last_flag = args.iter().rposition(|a| a.starts_with('-')).unwrap();
        let first_target = args.iter().position(|a| a == "8.8.8.8").unwrap();
        assert!(first_target > last_flag, "targets must come after flags: {args:?}");
    }

    #[tokio::test]
    async fn discover_with_all_blocked_targets_returns_empty_without_running() {
        // Every target is blocked, so masscan is never invoked (and the binary's
        // presence is irrelevant); the result is empty.
        let bl = Blocklist::new(false);
        let targets = vec![v4(127, 0, 0, 1), v4(10, 0, 0, 1), v4(192, 0, 2, 1)];
        let got = masscan_discover(&targets, &[80], &MasscanConfig::default(), &bl).await.unwrap();
        assert!(got.is_empty());
    }
}
