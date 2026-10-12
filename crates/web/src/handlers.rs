//! Axum request handlers for every route.
//!
//! All handlers lock the shared [`Store`] (a single rusqlite connection) for
//! the duration of the request. Reads only; the web layer never mutates data.

use askama::Template;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    Json,
};
use crusade_core::query::parse;
use serde::{Deserialize, Serialize};

use crate::views::{
    facet_max, AlertView, HistoryTemplate, HostRow, HostTemplate, IndexTemplate, NotFoundTemplate,
    SimilarRow, SimilarTemplate, StatsTemplate, TrendsTemplate,
};
use crate::{AppState, SharedStore};

/// Results per search page.
const PAGE_SIZE: usize = 25;
/// Cap on points returned by the map endpoint.
const MAP_CAP: usize = 5000;

/// Query string for both the HTML search page and the JSON search API.
#[derive(Debug, Default, Deserialize)]
pub struct SearchParams {
    #[serde(default)]
    pub q: Option<String>,
    #[serde(default)]
    pub page: Option<usize>,
}

/// Render any askama template into an HTML response, mapping render failures
/// to a 500 rather than panicking.
fn render<T: Template>(tpl: T) -> Response {
    match tpl.render() {
        Ok(body) => Html(body).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "template render failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal template error").into_response()
        }
    }
}

/// Percent-encode a query-string component (enough for our pager links).
fn encode_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// `GET /healthz`
pub async fn healthz() -> &'static str {
    "ok"
}

/// `GET /` — the search page.
pub async fn index(
    State(store): State<SharedStore>,
    Query(params): Query<SearchParams>,
) -> Response {
    let q = params.q.unwrap_or_default();
    let page = params.page.unwrap_or(0);
    let searched = !q.trim().is_empty() || params.page.is_some();

    let mut tpl = IndexTemplate {
        q: q.clone(),
        error: None,
        searched,
        total: 0,
        page,
        results: Vec::new(),
        has_prev: false,
        has_next: false,
        prev_url: String::new(),
        next_url: String::new(),
    };

    if searched {
        match parse(&q) {
            Ok(query) => {
                let store = store.lock().await;
                let offset = page * PAGE_SIZE;
                let total = store.count(&query).unwrap_or(0);
                let hosts = store.search(&query, PAGE_SIZE, offset).unwrap_or_default();
                tpl.results = hosts.iter().map(HostRow::from).collect();
                tpl.total = total;
                tpl.has_prev = page > 0;
                tpl.has_next = offset + tpl.results.len() < total as usize;
                let enc = encode_component(&q);
                tpl.prev_url = format!("/?q={enc}&page={}", page.saturating_sub(1));
                tpl.next_url = format!("/?q={enc}&page={}", page + 1);
            }
            Err(e) => {
                tpl.error = Some(e.to_string());
            }
        }
    }

    render(tpl)
}

/// `GET /host/:ip` — host detail page.
pub async fn host_detail(State(store): State<SharedStore>, Path(ip): Path<String>) -> Response {
    let host = {
        let store = store.lock().await;
        store.get_host(&ip).unwrap_or(None)
    };
    match host {
        Some(h) => render(HostTemplate::from(&h)),
        None => {
            let tpl = NotFoundTemplate {
                message: format!("No host {ip} in the index."),
            };
            match tpl.render() {
                Ok(body) => (StatusCode::NOT_FOUND, Html(body)).into_response(),
                Err(_) => (StatusCode::NOT_FOUND, "not found").into_response(),
            }
        }
    }
}

/// `GET /host/:ip/history` — reverse-chronological scan-history timeline.
pub async fn host_history(State(store): State<SharedStore>, Path(ip): Path<String>) -> Response {
    let rows = {
        let store = store.lock().await;
        store.service_history(&ip).unwrap_or_default()
    };
    render(HistoryTemplate::from_history(ip, rows))
}

/// `GET /trends` — recent alerts plus a cheap activity summary (total hosts and
/// the global facet tables).
pub async fn trends(State(store): State<SharedStore>) -> Response {
    let (host_count, alerts, facets) = {
        let store = store.lock().await;
        let host_count = store.host_count().unwrap_or(0);
        let alerts = store.recent_alerts(50).unwrap_or_default();
        let facets = store.facets(20).unwrap_or_default();
        (host_count, alerts, facets)
    };

    let tpl = TrendsTemplate {
        host_count,
        alerts: alerts.iter().map(AlertView::from).collect(),
        ports_max: facet_max(&facets.ports),
        products_max: facet_max(&facets.products),
        countries_max: facet_max(&facets.countries),
        tags_max: facet_max(&facets.tags),
        ports: facets.ports,
        products: facets.products,
        countries: facets.countries,
        tags: facets.tags,
    };
    render(tpl)
}

/// `GET /stats` — facets + map page. With `?q=`, the facets are scoped to the
/// hosts matching that search ("stats for this search").
pub async fn stats(
    State(store): State<SharedStore>,
    Query(params): Query<SearchParams>,
) -> Response {
    let q = params.q.unwrap_or_default();
    let scope = q.trim();

    let (host_count, facets, scoped) = {
        let store = store.lock().await;
        // Scope to a search only when `q` is non-empty and parses cleanly.
        match (!scope.is_empty()).then(|| parse(scope)) {
            Some(Ok(query)) => {
                let count = store.count(&query).unwrap_or(0);
                let facets = store.facets_for_query(&query, 20).unwrap_or_default();
                (count, facets, true)
            }
            _ => {
                let count = store.host_count().unwrap_or(0);
                let facets = store.facets(20).unwrap_or_default();
                (count, facets, false)
            }
        }
    };

    let tpl = StatsTemplate {
        host_count,
        q: if scoped { q } else { String::new() },
        scoped,
        ports_max: facet_max(&facets.ports),
        products_max: facet_max(&facets.products),
        countries_max: facet_max(&facets.countries),
        asns_max: facet_max(&facets.asns),
        tags_max: facet_max(&facets.tags),
        ports: facets.ports,
        products: facets.products,
        countries: facets.countries,
        asns: facets.asns,
        tags: facets.tags,
    };
    render(tpl)
}

/// JSON envelope for `GET /api/search`.
#[derive(Serialize)]
struct SearchResponse {
    query: String,
    total: i64,
    page: usize,
    results: Vec<crusade_core::model::Host>,
}

/// `GET /api/search?q=&page=`
pub async fn api_search(
    State(store): State<SharedStore>,
    Query(params): Query<SearchParams>,
) -> Response {
    let q = params.q.unwrap_or_default();
    let page = params.page.unwrap_or(0);
    match parse(&q) {
        Ok(query) => {
            let store = store.lock().await;
            let offset = page * PAGE_SIZE;
            let total = store.count(&query).unwrap_or(0);
            let results = store.search(&query, PAGE_SIZE, offset).unwrap_or_default();
            Json(SearchResponse {
                query: q,
                total,
                page,
                results,
            })
            .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e.to_string(), "query": q })),
        )
            .into_response(),
    }
}

/// `GET /api/host/:ip`
pub async fn api_host(State(store): State<SharedStore>, Path(ip): Path<String>) -> Response {
    let host = {
        let store = store.lock().await;
        store.get_host(&ip).unwrap_or(None)
    };
    match host {
        Some(h) => Json(h).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "not found", "ip": ip })),
        )
            .into_response(),
    }
}

/// One plotted point for the map.
#[derive(Serialize)]
struct MapPoint {
    ip: String,
    lat: f64,
    lon: f64,
    country: Option<String>,
}

/// `GET /api/map` — hosts that have coordinates (capped).
pub async fn api_map(State(store): State<SharedStore>) -> Response {
    let hosts = {
        let store = store.lock().await;
        // An empty query selects all hosts, newest first.
        match parse("") {
            Ok(all) => store.search(&all, MAP_CAP, 0).unwrap_or_default(),
            Err(_) => Vec::new(),
        }
    };
    let points: Vec<MapPoint> = hosts
        .into_iter()
        .filter_map(|h| match (h.latitude, h.longitude) {
            (Some(lat), Some(lon)) => Some(MapPoint {
                ip: h.ip.to_string(),
                lat,
                lon,
                country: h.country,
            }),
            _ => None,
        })
        .collect();
    Json(points).into_response()
}

// ---------------------------------------------------------------------------
// Semantic similarity
// ---------------------------------------------------------------------------

/// Results per similarity page.
const SIMILAR_LIMIT: usize = 50;
/// Longest description shown per row.
const SIMILAR_TEXT_CHARS: usize = 110;

/// Query string for `/similar` and `/api/similar`.
#[derive(Debug, Default, Deserialize)]
pub struct SimilarParams {
    /// Free text to search by meaning.
    #[serde(default)]
    pub q: Option<String>,
    /// An indexed service to use as the query: `IP:PORT` or `IP:PORT/udp`.
    #[serde(default)]
    pub like: Option<String>,
    /// Restrict results to hosts matching this Crusade query.
    #[serde(default)]
    pub filter: Option<String>,
}

/// Split `IP:PORT` / `IP:PORT/udp` into its parts.
fn parse_service_ref(s: &str) -> Option<(String, u16, String)> {
    let (addr, transport) = match s.rsplit_once('/') {
        Some((a, t)) if t == "tcp" || t == "udp" => (a, t),
        _ => (s, "tcp"),
    };
    let sock: std::net::SocketAddr = addr.parse().ok()?;
    Some((sock.ip().to_string(), sock.port(), transport.to_string()))
}

/// Shorten and flatten a service description for one table row.
fn one_line(text: &str, max: usize) -> String {
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= max {
        return flat;
    }
    flat.chars().take(max.saturating_sub(1)).collect::<String>() + "…"
}

/// Rank services by embedding similarity. Returns the hits plus how many
/// vectors are indexed, or `None` when no model is installed.
async fn rank_similar(
    state: &AppState,
    params: &SimilarParams,
) -> Option<(Vec<crusade_store::SimilarHit>, i64)> {
    let embedder = state.embedder.as_ref()?;
    let model = embedder.name();

    let filter = params
        .filter
        .as_deref()
        .filter(|f| !f.trim().is_empty())
        .and_then(|f| parse(f).ok());

    let store = state.store.lock().await;
    let indexed = store.vector_count(model).unwrap_or(0);

    // Either an indexed service or free text supplies the query vector.
    let query_vec = match params.like.as_deref().filter(|l| !l.trim().is_empty()) {
        Some(reference) => {
            let (ip, port, transport) = parse_service_ref(reference)?;
            store.service_vector(model, &ip, port, &transport).ok()??
        }
        None => {
            let text = params.q.as_deref().unwrap_or_default();
            if text.trim().is_empty() {
                return Some((Vec::new(), indexed));
            }
            embedder.embed_one(text)
        }
    };

    let hits = store
        .similar_services(model, &query_vec, filter.as_ref(), SIMILAR_LIMIT)
        .unwrap_or_default();
    Some((hits, indexed))
}

/// `GET /similar?q=&like=&filter=`
pub async fn similar(
    State(state): State<AppState>,
    Query(params): Query<SimilarParams>,
) -> Response {
    let q = params.q.clone().unwrap_or_default();
    let like = params.like.clone().unwrap_or_default();
    let filter = params.filter.clone().unwrap_or_default();

    let Some((hits, indexed)) = rank_similar(&state, &params).await else {
        return render(SimilarTemplate {
            q,
            like,
            filter,
            // Distinguish "no model" from "model present, reference not found":
            // only the former leaves the state without an embedder.
            unavailable: state.embedder.is_none(),
            indexed: 0,
            hits: Vec::new(),
        });
    };

    // Describe each hit from its stored service record.
    let mut rows = Vec::with_capacity(hits.len());
    {
        let store = state.store.lock().await;
        for h in hits {
            let text = store
                .get_host(&h.ip)
                .ok()
                .flatten()
                .and_then(|host| {
                    host.services
                        .iter()
                        .find(|s| s.port == h.port)
                        .and_then(crusade_embed::service_text)
                })
                .unwrap_or_default();
            rows.push(SimilarRow {
                ip: h.ip,
                port: h.port,
                transport: h.transport,
                pct: (h.score.max(0.0) * 100.0).round() as u32,
                score: format!("{:.3}", h.score),
                text: one_line(&text, SIMILAR_TEXT_CHARS),
            });
        }
    }

    render(SimilarTemplate {
        q,
        like,
        filter,
        unavailable: false,
        indexed,
        hits: rows,
    })
}

/// `GET /api/similar?q=&like=&filter=`
pub async fn api_similar(
    State(state): State<AppState>,
    Query(params): Query<SimilarParams>,
) -> Response {
    match rank_similar(&state, &params).await {
        Some((hits, indexed)) => Json(serde_json::json!({
            "query": params.q.unwrap_or_default(),
            "like": params.like.unwrap_or_default(),
            "indexed": indexed,
            "results": hits,
        }))
        .into_response(),
        None if state.embedder.is_none() => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "no embedding model installed; run `crusade update-data`"
            })),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "no vector for that service" })),
        )
            .into_response(),
    }
}
