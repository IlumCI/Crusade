//! Host enrichment for Crusade.
//!
//! Turns a bare [`Host`] (just an IP and whatever a scan/probe learned) into a
//! richer record by layering on free, no-key intelligence:
//!
//! * [`geoasn`] — GeoIP / ASN / org / country / city from the iptoasn.com
//!   `ip2asn` tables and the optional DB-IP City Lite dataset. Also decomposes
//!   an ASN's announced ranges into CIDR prefixes for `asn:` scan targets.
//! * [`dns`] — best-effort reverse DNS (PTR) lookups.
//! * [`ct`] — Certificate Transparency subdomain discovery via crt.sh.
//!
//! The [`enrich_host`] entry point applies GeoIP/ASN and reverse DNS to a
//! mutable [`Host`] according to an [`EnrichConfig`].
//!
//! * [`screenshot`] — best-effort web-service screenshots via a headless
//!   Chrome/Chromium binary ([`ChromeScreenshotter`]). A [`Screenshotter`]
//!   trait keeps the seam stable, and [`NoopScreenshotter`] is the default when
//!   screenshots are disabled or no browser is available.

pub mod ct;
pub mod dns;
pub mod geoasn;
pub mod screenshot;

use crusade_core::Host;

pub use ct::{crtsh_subdomains, crtsh_url, parse_crtsh_names};
pub use dns::reverse_dns;
pub use geoasn::{parse_ip2asn_tsv, AsnInfo, CityInfo, GeoAsnDb, RawRange};
pub use screenshot::{chrome_screenshot_args, detect_chrome, ChromeScreenshotter};

/// Which enrichment steps to run.
#[derive(Debug, Clone)]
pub struct EnrichConfig {
    /// Fill ASN/org/country/city/lat/lon from the [`GeoAsnDb`].
    pub geo: bool,
    /// Fill `hostnames` from reverse DNS.
    pub reverse_dns: bool,
}

impl Default for EnrichConfig {
    fn default() -> Self {
        EnrichConfig {
            geo: true,
            reverse_dns: true,
        }
    }
}

/// Enrich a host in place: GeoIP/ASN from `db` and hostnames from reverse DNS.
///
/// All steps are best-effort and gated by `cfg`; nothing here fails the host.
pub async fn enrich_host(host: &mut Host, db: &GeoAsnDb, cfg: &EnrichConfig) {
    if cfg.geo {
        if let Some(info) = db.lookup(host.ip) {
            host.asn = Some(info.asn);
            if !info.org.is_empty() {
                host.org = Some(info.org);
            }
            if !info.country.is_empty() {
                host.country = Some(info.country);
            }
        }
        if let Some(city) = db.lookup_city(host.ip) {
            if city.city.is_some() {
                host.city = city.city;
            }
            if city.latitude.is_some() {
                host.latitude = city.latitude;
            }
            if city.longitude.is_some() {
                host.longitude = city.longitude;
            }
        }
    }

    if cfg.reverse_dns {
        for name in reverse_dns(host.ip).await {
            if !host.hostnames.contains(&name) {
                host.hostnames.push(name);
            }
        }
    }
}

/// Captures a screenshot of a rendered web service.
///
/// Deferred to v2 — the real implementation will drive a headless browser. This
/// trait is the stable seam so callers can depend on it today.
#[allow(async_fn_in_trait)]
pub trait Screenshotter {
    /// Capture `url`, returning the image bytes, or `None` if capture is
    /// unavailable / disabled.
    async fn capture(&self, url: &str) -> anyhow::Result<Option<Vec<u8>>>;
}

/// A no-op [`Screenshotter`] that always succeeds with `None`.
///
/// Used until the v2 headless-browser capturer lands, so the rest of the
/// pipeline can wire up the trait without a Chrome dependency.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopScreenshotter;

impl Screenshotter for NoopScreenshotter {
    async fn capture(&self, _url: &str) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn enrich_fills_geo_without_network() {
        // Pure/offline: geo on, reverse DNS off.
        let tsv = "192.0.2.0\t192.0.2.255\t64500\tDE\tEXAMPLE-DOC-NET\n";
        let db = GeoAsnDb::from_tsv(tsv, None);
        let mut host = Host::new("192.0.2.10".parse::<IpAddr>().unwrap());
        let cfg = EnrichConfig {
            geo: true,
            reverse_dns: false,
        };

        // Drive the future to completion on a tiny runtime (no I/O happens).
        futures_block_on(enrich_host(&mut host, &db, &cfg));

        assert_eq!(host.asn, Some(64500));
        assert_eq!(host.org.as_deref(), Some("EXAMPLE-DOC-NET"));
        assert_eq!(host.country.as_deref(), Some("DE"));
        assert!(host.hostnames.is_empty());
    }

    #[test]
    fn noop_screenshotter_returns_none() {
        let shot = futures_block_on(NoopScreenshotter.capture("http://example.com/"));
        assert!(matches!(shot, Ok(None)));
    }

    /// Minimal executor for driving a non-I/O future to completion in tests
    /// without requiring a full tokio runtime.
    fn futures_block_on<F: std::future::Future>(mut fut: F) -> F::Output {
        use std::pin::Pin;
        use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

        fn noop_raw_waker() -> RawWaker {
            fn no_op(_: *const ()) {}
            fn clone(_: *const ()) -> RawWaker {
                noop_raw_waker()
            }
            let vtable = &RawWakerVTable::new(clone, no_op, no_op, no_op);
            RawWaker::new(std::ptr::null(), vtable)
        }

        let waker = unsafe { Waker::from_raw(noop_raw_waker()) };
        let mut cx = Context::from_waker(&waker);
        // SAFETY: `fut` is not moved after being pinned here.
        let mut fut = unsafe { Pin::new_unchecked(&mut fut) };
        loop {
            match fut.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => std::hint::spin_loop(),
            }
        }
    }
}
