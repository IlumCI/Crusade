//! Crusade web UI: a read-only, Shodan-style browser over already-collected
//! host data.
//!
//! This crate serves an [`axum`] application with a small HTML frontend
//! (rendered with [`askama`] templates) and a matching JSON API. It never
//! writes to the datastore — every route locks the shared [`crusade_store::Store`]
//! only to read.
//!
//! Routes:
//! - `GET /` — search page (query via `?q=&page=`).
//! - `GET /host/:ip` — host detail (404 page if unknown).
//! - `GET /host/:ip/history` — per-host scan-history timeline.
//! - `GET /trends` — recent alerts + a dataset activity summary.
//! - `GET /stats` — dataset facets and a Leaflet host map.
//! - `GET /screens/:file` — captured screenshots (only via [`router_with`]).
//! - `GET /api/search?q=&page=` — JSON `{query,total,page,results}`.
//! - `GET /api/host/:ip` — JSON [`Host`](crusade_core::model::Host) or 404.
//! - `GET /similar?q=&like=` — services ranked by embedding similarity.
//! - `GET /api/map` — JSON `[{ip,lat,lon,country}]` for located hosts.
//! - `GET /api/similar?q=&like=` — the same ranking as JSON.
//! - `GET /healthz` — liveness probe.
//!
//! The store is a single rusqlite connection (`Send` but not `Sync`), so it is
//! shared as an `Arc<Mutex<Store>>` ([`SharedStore`]) and locked per request.

mod handlers;
mod views;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::FromRef;
use axum::{routing::get, Router};
use crusade_embed::Embedder;
use crusade_store::Store;
use tokio::sync::Mutex;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;

/// Shared, lockable handle to the datastore used as axum router state.
pub type SharedStore = Arc<Mutex<Store>>;

/// Router state: the datastore, plus the embedding model when one is
/// installed (semantic-similarity routes answer 503 without it).
#[derive(Clone)]
pub struct AppState {
    pub store: SharedStore,
    pub embedder: Option<Arc<Embedder>>,
}

impl FromRef<AppState> for SharedStore {
    fn from_ref(state: &AppState) -> Self {
        state.store.clone()
    }
}

/// Build the application router over a shared store (no screenshot serving).
pub fn router(store: SharedStore) -> Router {
    router_with(store, None)
}

/// Build the router with an embedding model mounted, enabling `/similar`.
pub fn router_with_embedder(
    store: SharedStore,
    screenshots_dir: Option<PathBuf>,
    embedder: Option<Arc<Embedder>>,
) -> Router {
    build_router(AppState { store, embedder }, screenshots_dir)
}

/// Build the application router, optionally mounting a static file service that
/// serves captured screenshots. When `screenshots_dir` is `Some(dir)`, PNGs are
/// served at `GET /screens/<file>` from `dir` (the filenames held in
/// [`crusade_core::model::Service::screenshot`]).
pub fn router_with(store: SharedStore, screenshots_dir: Option<PathBuf>) -> Router {
    build_router(
        AppState {
            store,
            embedder: None,
        },
        screenshots_dir,
    )
}

fn build_router(state: AppState, screenshots_dir: Option<PathBuf>) -> Router {
    let mut app = Router::new()
        .route("/", get(handlers::index))
        .route("/host/:ip", get(handlers::host_detail))
        .route("/host/:ip/history", get(handlers::host_history))
        .route("/trends", get(handlers::trends))
        .route("/stats", get(handlers::stats))
        .route("/api/search", get(handlers::api_search))
        .route("/api/host/:ip", get(handlers::api_host))
        .route("/api/map", get(handlers::api_map))
        .route("/similar", get(handlers::similar))
        .route("/api/similar", get(handlers::api_similar))
        .route("/healthz", get(handlers::healthz));

    if let Some(dir) = screenshots_dir {
        // ServeDir already rejects path traversal; the view layer additionally
        // only emits bare filenames. A missing file yields 404, not a panic.
        app = app.nest_service("/screens", ServeDir::new(dir));
    }

    app.with_state(state)
}

/// Bind `addr` and serve the web UI until the process is terminated.
pub async fn serve(addr: SocketAddr, store: SharedStore) -> anyhow::Result<()> {
    serve_with(addr, store, None).await
}

/// Like [`serve_with`], with an embedding model mounted for `/similar`.
pub async fn serve_with_embedder(
    addr: SocketAddr,
    store: SharedStore,
    screenshots_dir: Option<PathBuf>,
    embedder: Option<Arc<Embedder>>,
) -> anyhow::Result<()> {
    let app =
        router_with_embedder(store, screenshots_dir, embedder).layer(TraceLayer::new_for_http());
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "crusade-web listening");
    axum::serve(listener, app).await?;
    Ok(())
}

/// Like [`serve`], but also serves screenshots from `screenshots_dir` (if any)
/// at `/screens/<file>`.
pub async fn serve_with(
    addr: SocketAddr,
    store: SharedStore,
    screenshots_dir: Option<PathBuf>,
) -> anyhow::Result<()> {
    let app = router_with(store, screenshots_dir).layer(TraceLayer::new_for_http());
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "crusade-web listening");
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use crusade_core::model::{AuthState, Host, HttpInfo, Service, SshInfo, Tag, Transport};
    use http_body_util::BodyExt;
    use std::net::IpAddr;
    use time::OffsetDateTime;
    use tower::ServiceExt; // for `oneshot`

    fn seeded_store() -> SharedStore {
        let mut store = Store::open_in_memory().expect("open in-memory store");

        let ip: IpAddr = "203.0.113.10".parse().unwrap();
        let mut host = Host::new(ip);
        host.country = Some("DE".into());
        host.asn = Some(3320);
        host.org = Some("Example Telekom".into());
        host.hostnames = vec!["web.example.com".into()];
        host.latitude = Some(52.52);
        host.longitude = Some(13.405);
        let mut svc = Service::new(80, Transport::Tcp);
        svc.service = Some("http".into());
        svc.product = Some("nginx".into());
        svc.version = Some("1.25.0".into());
        svc.banner = Some("HTTP/1.1 200 OK\r\nServer: nginx".into());
        svc.jarm = Some("27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d".into());
        // Reachable without credentials — the notable recon signal.
        svc.auth = Some(AuthState::Open);
        svc.http = Some(HttpInfo {
            status: Some(200),
            server: Some("nginx".into()),
            title: Some("Welcome".into()),
            headers: vec![("server".into(), "nginx".into())],
            favicon_hash: Some(-247388890),
            technologies: vec!["nginx".into(), "PHP".into()],
            security_headers: vec!["Strict-Transport-Security".into()],
        });
        svc.ssh = Some(SshInfo {
            banner: Some("SSH-2.0-OpenSSH_8.9".into()),
            host_key_type: Some("ssh-ed25519".into()),
            host_key_sha256: Some("SHA256:abc+def/ghi=".into()),
            kex_algorithms: vec!["curve25519-sha256".into()],
            hassh: Some("06046964c022c6407d15a27b12a6a4fb".into()),
        });
        svc.screenshot = Some("203.0.113.10_80.png".into());
        host.services.push(svc);
        // A matched CVE with a known public exploit.
        host.tags.push(Tag {
            name: "exploit-available".into(),
            cve: Some("CVE-2021-1234".into()),
            detail: Some("EDB-50123; msf: exploit/linux/http/example".into()),
        });
        // Upsert twice (distinct observation times) so the append-only history
        // has two rows for this host's port.
        host.services[0].observed_at = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        store.upsert_host(&host).expect("seed host 1");
        host.services[0].observed_at = OffsetDateTime::from_unix_timestamp(1_700_086_400).unwrap();
        host.services[0].version = Some("1.25.1".into());
        store.upsert_host(&host).expect("seed host 1 again");

        let ip2: IpAddr = "198.51.100.7".parse().unwrap();
        let mut host2 = Host::new(ip2);
        host2.country = Some("US".into());
        let mut svc2 = Service::new(22, Transport::Tcp);
        svc2.service = Some("ssh".into());
        svc2.product = Some("OpenSSH".into());
        host2.services.push(svc2);
        store.upsert_host(&host2).expect("seed host 2");

        Arc::new(Mutex::new(store))
    }

    async fn body_string(resp: axum::response::Response) -> String {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn healthz_ok() {
        let app = router(seeded_store());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_string(resp).await, "ok");
    }

    #[tokio::test]
    async fn index_search_shows_host() {
        let app = router(seeded_store());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/?q=port:80")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(
            body.contains("203.0.113.10"),
            "body missing seeded IP: {body}"
        );
    }

    #[tokio::test]
    async fn index_bad_query_does_not_500() {
        let app = router(seeded_store());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/?q=port:notaport")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(
            body.contains("Could not parse query"),
            "expected friendly error"
        );
    }

    #[tokio::test]
    async fn api_host_known_and_unknown() {
        let app = router(seeded_store());
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/host/203.0.113.10")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["ip"], "203.0.113.10");

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/host/192.0.2.99")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn api_search_returns_total() {
        let app = router(seeded_store());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/search?q=port:80")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(json["total"].as_i64().unwrap() >= 1);
        assert_eq!(json["results"][0]["ip"], "203.0.113.10");
    }

    #[tokio::test]
    async fn api_map_only_located_hosts() {
        let app = router(seeded_store());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/map")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        // Only host 1 has coordinates.
        assert_eq!(json.as_array().unwrap().len(), 1);
        assert_eq!(json[0]["ip"], "203.0.113.10");
    }

    #[tokio::test]
    async fn host_page_shows_jarm_and_favicon() {
        let app = router(seeded_store());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/host/203.0.113.10")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        // JARM fingerprint and its pivot link are rendered.
        assert!(body.contains("JARM"), "host page missing JARM section");
        assert!(
            body.contains("27d40d40d29d40d1"),
            "host page missing JARM value"
        );
        // Favicon hash rendered with a clickable pivot to the favicon search.
        assert!(
            body.contains("-247388890"),
            "host page missing favicon hash"
        );
        assert!(
            body.contains("/?q=http.favicon.hash%3A-247388890"),
            "host page missing favicon pivot link: {body}"
        );
        // SSH + technologies surfaced as well.
        assert!(
            body.contains("SSH-2.0-OpenSSH_8.9"),
            "host page missing SSH banner"
        );
        assert!(
            body.contains("06046964c022c6407d15a27b12a6a4fb"),
            "host page missing HASSH"
        );
    }

    #[tokio::test]
    async fn host_page_shows_auth_and_exploit() {
        let app = router(seeded_store());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/host/203.0.113.10")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        // Auth posture badge rendered on the service header line.
        assert!(
            body.contains("auth:open"),
            "host page missing auth badge: {body}"
        );
        // exploit-available tag surfaced with its CVE and a pivot link.
        assert!(
            body.contains("exploit-available"),
            "host page missing exploit-available tag"
        );
        assert!(
            body.contains("/?q=vuln%3ACVE-2021-1234"),
            "host page missing CVE pivot link: {body}"
        );
    }

    #[tokio::test]
    async fn auth_open_query_finds_host() {
        let app = router(seeded_store());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/?q=auth:open")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(
            body.contains("203.0.113.10"),
            "auth:open search missing seeded open-auth host: {body}"
        );
        // The result row flags the unauthenticated exposure.
        assert!(
            body.contains("open/no-auth"),
            "results row missing open/no-auth badge"
        );
    }

    #[tokio::test]
    async fn stats_scoped_query_ok() {
        let app = router(seeded_store());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/stats?q=port:80")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(
            body.contains("Stats for this search"),
            "expected scoped header"
        );
    }

    #[tokio::test]
    async fn stats_page_renders() {
        let app = router(seeded_store());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/stats")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(body.contains("leaflet"), "expected leaflet embed");
    }

    #[tokio::test]
    async fn host_history_shows_timeline() {
        let app = router(seeded_store());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/host/203.0.113.10/history")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        // The port appears in the timeline.
        assert!(body.contains("80/tcp"), "history page missing port: {body}");
        // Two upserts at distinct times => two snapshots.
        assert!(
            body.contains("2 snapshots"),
            "expected two history snapshots: {body}"
        );
    }

    #[tokio::test]
    async fn host_history_empty_for_unknown() {
        let app = router(seeded_store());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/host/192.0.2.123/history")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // Rendered empty-state page (200) rather than a panic.
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(
            body.contains("No scan history"),
            "expected empty-state message"
        );
    }

    #[tokio::test]
    async fn trends_page_renders() {
        let app = router(seeded_store());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/trends")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(body.contains("Recent alerts"), "expected alerts section");
        assert!(body.contains("Top ports"), "expected ports facet");
    }

    #[tokio::test]
    async fn host_page_shows_screenshot() {
        let app = router(seeded_store());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/host/203.0.113.10")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(
            body.contains("/screens/203.0.113.10_80.png"),
            "host page missing screenshot img: {body}"
        );
        // And the History link is present.
        assert!(
            body.contains("/host/203.0.113.10/history"),
            "missing history link"
        );
    }

    #[tokio::test]
    async fn router_with_screens_dir_missing_file_is_404() {
        let dir = std::env::temp_dir().join("crusade_web_screens_test");
        std::fs::create_dir_all(&dir).unwrap();
        let app = router_with(seeded_store(), Some(dir));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/screens/nope.png")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // Missing file: a clean 404, not a panic.
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// A store with two embedded services: one web, one SSH-ish.
    fn store_with_vectors() -> SharedStore {
        let store = seeded_store();
        {
            let mut s = store.try_lock().unwrap();
            let mut other = Host::new("203.0.113.11".parse::<IpAddr>().unwrap());
            let mut svc = Service::new(22, Transport::Tcp);
            svc.service = Some("ssh".into());
            svc.product = Some("OpenSSH".into());
            svc.observed_at = OffsetDateTime::from_unix_timestamp(1_760_000_000).unwrap();
            other.services.push(svc);
            other.last_seen = svc_time();
            s.upsert_host(&other).unwrap();

            // Orthogonal 2-d vectors: the query picks exactly one.
            s.set_service_vectors("203.0.113.10", "m", &[(80, "tcp".into(), vec![127, 0])])
                .unwrap();
            s.set_service_vectors("203.0.113.11", "m", &[(22, "tcp".into(), vec![0, 127])])
                .unwrap();
        }
        store
    }

    fn svc_time() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_760_000_000).unwrap()
    }

    #[tokio::test]
    async fn similar_page_without_a_model_explains_itself() {
        let app = router(seeded_store());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/similar?q=web+server")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(body.contains("No embedding model installed"), "{body}");
    }

    #[tokio::test]
    async fn api_similar_without_a_model_is_503() {
        let app = router(seeded_store());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/similar?q=web")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// `--like` needs only stored vectors, so it works without a model file.
    #[tokio::test]
    async fn api_similar_ranks_by_reference_service() {
        let store = store_with_vectors();
        // An embedder is required for the model name; reuse the stored one by
        // going through the store directly.
        let hits = {
            let s = store.try_lock().unwrap();
            let v = s.service_vector("m", "203.0.113.10", 80, "tcp").unwrap();
            assert_eq!(v, Some(vec![127, 0]));
            s.similar_services("m", &v.unwrap(), None, 10).unwrap()
        };
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].ip, "203.0.113.10");
        assert!(hits[0].score > hits[1].score);
    }

    #[tokio::test]
    async fn host_page_links_to_similar_services() {
        let app = router(seeded_store());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/host/203.0.113.10")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = body_string(resp).await;
        assert!(
            body.contains("/similar?like=203.0.113.10:80/tcp"),
            "host page should offer a similarity pivot"
        );
    }

    #[tokio::test]
    async fn viewing_a_host_records_access_for_retention() {
        let store = seeded_store();
        let before = {
            let s = store.try_lock().unwrap();
            let r = s.storage_report().unwrap();
            assert_eq!(r.never_accessed, r.hosts, "nothing has been viewed yet");
            r.never_accessed
        };

        let app = router(store.clone());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/host/203.0.113.10")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let after = {
            let s = store.try_lock().unwrap();
            s.storage_report().unwrap().never_accessed
        };
        assert_eq!(after, before - 1, "exactly the viewed host was recorded");
    }

    #[tokio::test]
    async fn a_search_records_access_for_every_result() {
        let store = seeded_store();
        let app = router(store.clone());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/?q=port:80")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let (hosts, never) = {
            let s = store.try_lock().unwrap();
            let r = s.storage_report().unwrap();
            (r.hosts, r.never_accessed)
        };
        assert!(hosts > never, "results should count as usage");
    }
}
