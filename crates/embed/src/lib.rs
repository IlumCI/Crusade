//! Embedded, CPU-only text embeddings for semantic search over services.
//!
//! Crusade embeds one short text per service (product, title, server, banner,
//! certificate names, ...) with a static Model2Vec model, by default
//! `minishlab/potion-base-8M` (~8M parameters, 256 dimensions, ~30 MB). Static
//! models need no transformer forward pass: a token-embedding lookup plus mean
//! pooling, so ingest-time embedding of every banner is cheap on CPU (see
//! SwiftEmbed, arXiv:2510.24793, for latency at this model size).
//!
//! Vectors are L2-normalised and stored int8-quantised (256 bytes each), and
//! similarity is the exact dot product over the stored vectors. Everything is
//! optional: when no model is installed, embedding is skipped and the rest of
//! Crusade behaves exactly as before.

use std::path::Path;

use anyhow::{Context, Result};
use crusade_core::Service;
use model2vec_rs::model::StaticModel;

/// Default model, fetched by `crusade update-data` into
/// `<data dir>/models/<DEFAULT_MODEL_DIR>`.
pub const DEFAULT_MODEL_REPO: &str = "minishlab/potion-base-8M";
pub const DEFAULT_MODEL_DIR: &str = "potion-base-8M";
/// Files a Model2Vec model directory must contain.
pub const MODEL_FILES: &[&str] = &["config.json", "tokenizer.json", "model.safetensors"];

/// Maximum characters of raw banner included in a service's text.
const BANNER_CHARS: usize = 600;
/// Token cap per text (keeps very long banners from dominating the mean).
const MAX_TOKENS: usize = 256;

/// A loaded embedding model.
pub struct Embedder {
    model: StaticModel,
    name: String,
}

impl Embedder {
    /// Load a Model2Vec model from a local directory.
    pub fn load(dir: &Path) -> Result<Self> {
        let model = StaticModel::from_pretrained(dir, None, Some(true), None)
            .with_context(|| format!("loading embedding model from {}", dir.display()))?;
        let name = dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "model".into());
        Ok(Embedder { model, name })
    }

    /// Identifier stored next to each vector, so vectors from different
    /// models are never compared.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Embed texts into quantised, normalised vectors.
    pub fn embed(&self, texts: &[String]) -> Vec<Vec<i8>> {
        self.model
            .encode_with_args(texts, Some(MAX_TOKENS), 256)
            .iter()
            .map(|v| quantize(v))
            .collect()
    }

    /// Embed one query string.
    pub fn embed_one(&self, text: &str) -> Vec<i8> {
        self.embed(&[text.to_string()]).pop().unwrap_or_default()
    }
}

/// The text that represents a service for embedding, or `None` when the
/// service revealed nothing beyond being open.
pub fn service_text(svc: &Service) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    let mut push = |s: Option<&str>| {
        if let Some(s) = s.map(str::trim).filter(|s| !s.is_empty()) {
            parts.push(s.to_string());
        }
    };
    push(svc.service.as_deref());
    push(svc.product.as_deref());
    push(svc.version.as_deref());
    if let Some(h) = &svc.http {
        push(h.server.as_deref());
        push(h.title.as_deref());
        push(Some(h.technologies.join(" ").as_str()));
    }
    if let Some(t) = &svc.tls {
        push(t.subject_cn.as_deref());
        push(t.issuer_cn.as_deref());
    }
    if let Some(s) = &svc.ssh {
        push(s.banner.as_deref());
    }
    if let Some(i) = &svc.ics {
        push(Some(i.protocol.as_str()));
        push(i.vendor.as_deref());
        push(i.product.as_deref());
    }
    if let Some(b) = &svc.banner {
        let printable: String = b
            .chars()
            .filter(|c| !c.is_control() || c.is_whitespace())
            .take(BANNER_CHARS)
            .collect();
        push(Some(printable.as_str()));
    }
    (!parts.is_empty()).then(|| parts.join(" | "))
}

/// Scale an L2-normalised vector into int8.
pub fn quantize(v: &[f32]) -> Vec<i8> {
    v.iter()
        .map(|x| (x * 127.0).round().clamp(-127.0, 127.0) as i8)
        .collect()
}

/// Cosine similarity of two int8-quantised normalised vectors, in `[-1, 1]`.
pub fn similarity(a: &[i8], b: &[i8]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let dot: i32 = a.iter().zip(b).map(|(&x, &y)| x as i32 * y as i32).sum();
    dot as f32 / (127.0 * 127.0)
}

/// Raw bytes for storage.
pub fn to_bytes(v: &[i8]) -> Vec<u8> {
    v.iter().map(|&x| x as u8).collect()
}

/// Inverse of [`to_bytes`].
pub fn from_bytes(b: &[u8]) -> Vec<i8> {
    b.iter().map(|&x| x as i8).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crusade_core::{HttpInfo, Transport};

    #[test]
    fn quantize_roundtrip_similarity() {
        let a = [0.6f32, 0.8, 0.0];
        let qa = quantize(&a);
        assert!((similarity(&qa, &qa) - 1.0).abs() < 0.02);
        let b = quantize(&[0.0, 0.0, 1.0]);
        assert!(similarity(&qa, &b).abs() < 0.01);
        assert_eq!(from_bytes(&to_bytes(&qa)), qa);
        assert_eq!(similarity(&qa, &b[..2]), 0.0);
    }

    #[test]
    fn service_text_collects_fields() {
        let mut s = Service::new(8080, Transport::Tcp);
        assert_eq!(service_text(&s), None);
        s.product = Some("nginx".into());
        s.http = Some(HttpInfo {
            status: Some(200),
            server: Some("nginx/1.24.0".into()),
            title: Some("Welcome to nginx!".into()),
            headers: vec![],
            favicon_hash: None,
            technologies: vec!["PHP".into()],
            security_headers: vec![],
        });
        s.banner = Some("HTTP/1.1 200 OK\r\n\u{0}\u{1}Server: nginx".into());
        let t = service_text(&s).unwrap();
        assert!(t.starts_with("nginx | nginx/1.24.0 | Welcome to nginx! | PHP | HTTP/1.1"));
        assert!(!t.contains('\u{1}'));
    }

    /// Runs only with `CRUSADE_EMBED_MODEL=<model dir>` set.
    #[test]
    fn real_model_ranks_related_services_together() {
        let Ok(dir) = std::env::var("CRUSADE_EMBED_MODEL") else {
            return;
        };
        let e = Embedder::load(Path::new(&dir)).unwrap();
        let texts: Vec<String> = [
            "http | nginx | 1.18.0 | nginx/1.18.0 | Welcome to nginx!",
            "http | Apache httpd | 2.4.41 | Apache/2.4.41 (Ubuntu) | Apache2 Ubuntu Default Page",
            "ssh | OpenSSH | 8.9p1 | SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
            "mysql | MySQL | 8.0.36 | 5.5.5-10.6.12-MariaDB",
            "s7 | Siemens | SIMATIC S7-1200 | 6ES7 214-1AG40-0XB0",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let v = e.embed(&texts);
        assert_eq!(v[0].len(), 256);
        let rank = |q: &str| -> usize {
            let qv = e.embed_one(q);
            (0..v.len())
                .max_by(|&a, &b| similarity(&qv, &v[a]).total_cmp(&similarity(&qv, &v[b])))
                .unwrap()
        };
        assert_eq!(rank("web server default welcome page nginx"), 0);
        assert_eq!(rank("ssh server"), 2);
        assert_eq!(rank("ubuntu apache"), 1);
        assert_eq!(rank("siemens plc industrial controller"), 4);
        assert_eq!(rank("mariadb database"), 3);
    }
}
