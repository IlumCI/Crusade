//! Alert transports for `crusade monitor`.
//!
//! Every change the monitor detects is first persisted to the `alerts` table
//! (so nothing is lost and the web UI / `crusade alerts` can show history), then
//! dispatched best-effort to any configured transports: generic JSON webhooks
//! (Slack/Discord/Teams-compatible) and SMTP email. A transport failure is
//! logged but never aborts the scan — the alert stays recorded and undelivered.

use crate::config::Config;
use anyhow::Result;
use crusade_store::{Alert, Store};
use tracing::{info, warn};

/// Dispatch all undelivered alerts in the store through configured transports,
/// marking each delivered on success. Called by the monitor after each pass.
pub async fn flush_undelivered(cfg: &Config, store: &Store) -> Result<()> {
    let pending = store.undelivered_alerts()?;
    if pending.is_empty() {
        return Ok(());
    }
    let have_transport = !cfg.alert.webhooks.is_empty() || cfg.alert.smtp_host.is_some();
    if !have_transport {
        // No transports configured: alerts are logged + stored only.
        for a in &pending {
            store.mark_alert_delivered(a.id)?;
        }
        return Ok(());
    }
    for a in pending {
        match deliver(cfg, &a).await {
            Ok(()) => {
                store.mark_alert_delivered(a.id)?;
                info!(ip = %a.ip, kind = %a.kind, "alert delivered");
            }
            Err(e) => warn!(ip = %a.ip, kind = %a.kind, "alert delivery failed: {e}"),
        }
    }
    Ok(())
}

/// Send one alert through every configured transport. Succeeds only if all
/// configured transports accept it (so a failure leaves it to retry next pass).
async fn deliver(cfg: &Config, a: &Alert) -> Result<()> {
    let text = format!("[crusade] {} — {} ({})", a.kind, a.detail, a.ip);
    for url in &cfg.alert.webhooks {
        post_webhook(url, a, &text).await?;
    }
    if cfg.alert.smtp_host.is_some() {
        send_email(cfg, a, &text).await?;
    }
    Ok(())
}

async fn post_webhook(url: &str, a: &Alert, text: &str) -> Result<()> {
    // `text` is the Slack/Discord/Mattermost common field; the structured
    // fields let other receivers parse it.
    let body = serde_json::json!({
        "text": text,
        "content": text,            // Discord uses `content`
        "ip": a.ip,
        "kind": a.kind,
        "detail": a.detail,
        "ts": a.ts,
    });
    let resp = reqwest::Client::new()
        .post(url)
        .json(&body)
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!("webhook {} returned {}", url, resp.status());
    }
    Ok(())
}

async fn send_email(cfg: &Config, a: &Alert, text: &str) -> Result<()> {
    use lettre::message::header::ContentType;
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

    let host = cfg.alert.smtp_host.as_ref().unwrap();
    let from = cfg
        .alert
        .email_from
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("alert.email_from not set"))?;
    if cfg.alert.email_to.is_empty() {
        anyhow::bail!("alert.email_to is empty");
    }

    let mut builder = Message::builder()
        .from(from.parse()?)
        .subject(format!("[crusade] {} on {}", a.kind, a.ip))
        .header(ContentType::TEXT_PLAIN);
    for to in &cfg.alert.email_to {
        builder = builder.to(to.parse()?);
    }
    let email = builder.body(text.to_string())?;

    let mut tb = AsyncSmtpTransport::<Tokio1Executor>::relay(host)?;
    if let Some(port) = cfg.alert.smtp_port {
        tb = tb.port(port);
    }
    if let (Some(u), Some(p)) = (&cfg.alert.smtp_user, &cfg.alert.smtp_pass) {
        tb = tb.credentials(Credentials::new(u.clone(), p.clone()));
    }
    let transport = tb.build();
    transport.send(email).await?;
    Ok(())
}
