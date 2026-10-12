//! Web-service screenshots via a headless Chrome/Chromium binary.
//!
//! A screenshot here is nothing more than what any browser does when it visits
//! the target: Crusade fetches the service's own web UI over HTTP(S) and renders
//! it to a PNG. It is still a connect-and-read operation — the page is loaded
//! exactly as a visitor would load it, with **no interaction, form submission,
//! authentication, or exploitation** of any kind. The capture is entirely
//! best-effort: if Chrome is absent, times out, or fails for any reason, the
//! capturer returns `Ok(None)` and a scan continues unaffected.
//!
//! Rather than depend on a CDP crate, this drives the browser binary's built-in
//! command-line `--screenshot` mode and shells out to it under a timeout. That
//! keeps the dependency surface tiny (just [`tempfile`] for the output path)
//! and robust across Chrome/Chromium builds.

use std::path::Path;
use std::time::Duration;

use crate::Screenshotter;

/// Chrome/Chromium binaries to probe for, in priority order.
const CHROME_CANDIDATES: &[&str] = &[
    "chromium",
    "chromium-browser",
    "google-chrome",
    "google-chrome-stable",
    "chrome",
];

/// Default headless capture window, in CSS pixels (width, height).
const DEFAULT_WINDOW: (u32, u32) = (1280, 800);

/// Default wall-clock budget for a single capture before it is abandoned.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

/// A [`Screenshotter`] backed by a headless Chrome/Chromium binary.
///
/// Set `chrome_path` to pin a specific binary; when `None` the binary is
/// discovered with [`detect_chrome`] at capture time. Capture is best-effort:
/// a missing binary, a non-HTTP(S) URL, a timeout, a non-zero exit, or a
/// missing output file all yield `Ok(None)`.
#[derive(Debug, Clone)]
pub struct ChromeScreenshotter {
    /// Explicit path to a Chrome/Chromium binary, or `None` to auto-detect.
    pub chrome_path: Option<String>,
    /// Wall-clock budget for a single capture.
    pub timeout: Duration,
    /// Render window size as `(width, height)` in CSS pixels.
    pub window: (u32, u32),
}

impl Default for ChromeScreenshotter {
    fn default() -> Self {
        ChromeScreenshotter {
            chrome_path: None,
            timeout: DEFAULT_TIMEOUT,
            window: DEFAULT_WINDOW,
        }
    }
}

impl ChromeScreenshotter {
    /// Create a capturer with the default timeout (15s) and window (1280x800),
    /// auto-detecting the Chrome binary at capture time.
    pub fn new() -> Self {
        Self::default()
    }

    /// Pin the Chrome/Chromium binary this capturer will use.
    pub fn with_chrome_path(mut self, path: impl Into<String>) -> Self {
        self.chrome_path = Some(path.into());
        self
    }

    /// Set the per-capture timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the render window size as `(width, height)`.
    pub fn with_window(mut self, window: (u32, u32)) -> Self {
        self.window = window;
        self
    }

    /// Resolve the binary this capturer should run: the explicit `chrome_path`
    /// if set, otherwise the first binary found on `PATH`.
    fn resolve_binary(&self) -> Option<String> {
        self.chrome_path.clone().or_else(detect_chrome)
    }
}

/// Probe `PATH` for a usable Chrome/Chromium binary.
///
/// Walks the directories in the `PATH` environment variable (`which`-style) and
/// returns the full path of the first candidate that exists, trying
/// `chromium`, `chromium-browser`, `google-chrome`, `google-chrome-stable`,
/// then `chrome`. Returns `None` if none are found.
pub fn detect_chrome() -> Option<String> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        for candidate in CHROME_CANDIDATES {
            let full = dir.join(candidate);
            if is_executable_file(&full) {
                return Some(full.to_string_lossy().into_owned());
            }
        }
    }
    None
}

/// True if `path` points at an existing regular file (best-effort; on Unix it
/// also checks an executable bit).
fn is_executable_file(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Build the argument vector for a headless Chrome screenshot run.
///
/// Pure and side-effect free so it can be unit-tested without executing
/// anything. The `url` is always placed last, matching Chrome's CLI contract.
pub fn chrome_screenshot_args(out_path: &str, url: &str, window: (u32, u32)) -> Vec<String> {
    vec![
        "--headless=new".to_string(),
        "--disable-gpu".to_string(),
        "--no-sandbox".to_string(),
        "--hide-scrollbars".to_string(),
        format!("--screenshot={out_path}"),
        format!("--window-size={},{}", window.0, window.1),
        "--virtual-time-budget=5000".to_string(),
        url.to_string(),
    ]
}

/// Accept only `http://` and `https://` URLs; everything else is rejected.
fn is_http_url(url: &str) -> bool {
    let lower = url.trim_start().to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

impl Screenshotter for ChromeScreenshotter {
    async fn capture(&self, url: &str) -> anyhow::Result<Option<Vec<u8>>> {
        // Only render real web URLs; anything else is a graceful no-op.
        if !is_http_url(url) {
            return Ok(None);
        }

        // Resolve the binary; if there is none, capture is unavailable.
        let Some(bin) = self.resolve_binary() else {
            return Ok(None);
        };

        // A fresh temp file for the PNG output; dropped (deleted) on return.
        let out = match tempfile::Builder::new()
            .prefix("crusade-shot-")
            .suffix(".png")
            .tempfile()
        {
            Ok(f) => f,
            Err(_) => return Ok(None),
        };
        let out_path = out.path().to_string_lossy().into_owned();

        let args = chrome_screenshot_args(&out_path, url, self.window);

        let mut cmd = tokio::process::Command::new(&bin);
        cmd.args(&args)
            .kill_on_drop(true)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());

        // Run under a timeout. A spawn failure (missing/broken binary), a
        // timeout, or a non-zero exit all degrade to Ok(None).
        let status = match tokio::time::timeout(self.timeout, async {
            match cmd.spawn() {
                Ok(mut child) => child.wait().await.ok(),
                Err(_) => None,
            }
        })
        .await
        {
            Ok(Some(status)) => status,
            // Timed out, spawn failed, or wait failed.
            Ok(None) | Err(_) => return Ok(None),
        };

        if !status.success() {
            return Ok(None);
        }

        // Chrome writes the PNG to the output path; read it back, if present.
        match tokio::fs::read(&out_path).await {
            Ok(bytes) if !bytes.is_empty() => Ok(Some(bytes)),
            // Missing output file or empty render: best-effort miss.
            _ => Ok(None),
        }
        // `out` is dropped here, removing the temp file.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_include_expected_flags_and_url_last() {
        let args = chrome_screenshot_args("/tmp/out.png", "http://example.com/", (1280, 800));

        // --headless (in whatever form) is present.
        assert!(
            args.iter().any(|a| a.starts_with("--headless")),
            "missing --headless: {args:?}"
        );
        // The screenshot flag carries the exact output path.
        assert!(
            args.contains(&"--screenshot=/tmp/out.png".to_string()),
            "missing --screenshot=<path>: {args:?}"
        );
        // The default window size is wired through.
        assert!(
            args.contains(&"--window-size=1280,800".to_string()),
            "missing --window-size=1280,800: {args:?}"
        );
        // The URL is always the final argument.
        assert_eq!(args.last().map(String::as_str), Some("http://example.com/"));
    }

    #[test]
    fn custom_window_is_reflected() {
        let args = chrome_screenshot_args("/tmp/o.png", "https://host/", (640, 480));
        assert!(
            args.contains(&"--window-size=640,480".to_string()),
            "{args:?}"
        );
    }

    #[tokio::test]
    async fn missing_binary_degrades_to_none() {
        let shot = ChromeScreenshotter::new().with_chrome_path("/nonexistent/chrome");
        let out = shot.capture("http://example.com/").await;
        assert!(
            matches!(out, Ok(None)),
            "expected Ok(None) for missing binary"
        );
    }

    #[tokio::test]
    async fn non_http_url_degrades_to_none() {
        // Even if a real Chrome exists, a non-HTTP(S) URL must be refused.
        let shot = ChromeScreenshotter::new();
        for url in [
            "file:///etc/passwd",
            "ftp://host/x",
            "javascript:alert(1)",
            "data:text/html,x",
        ] {
            let out = shot.capture(url).await;
            assert!(matches!(out, Ok(None)), "expected Ok(None) for {url}");
        }
    }

    #[test]
    fn detect_chrome_never_panics() {
        // Returns None or a plausible path; must not panic either way.
        match detect_chrome() {
            None => {}
            Some(p) => assert!(!p.is_empty(), "detected path should be non-empty"),
        }
    }

    #[test]
    fn is_http_url_matches_schemes() {
        assert!(is_http_url("http://x/"));
        assert!(is_http_url("https://x/"));
        assert!(is_http_url("HTTPS://X/"));
        assert!(!is_http_url("ftp://x/"));
        assert!(!is_http_url("file:///x"));
        assert!(!is_http_url("x"));
    }
}
