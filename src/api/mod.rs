//! REST API for threat intelligence.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, header};
use axum::middleware::{Next, from_fn};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde_json::{Value, json};
use tower_http::cors::{AllowOrigin, CorsLayer};
use uuid::Uuid;

use crate::auth::AuthState;
use crate::enrichment::EnrichmentEngine;
use crate::models::ioc_utils::{validate_indicator_request, validate_label};
use crate::models::{
    BulkImportRequest, BulkImportResponse, CreateIndicatorRequest, DashboardStats, IndicatorFilter,
    IndicatorResponse, InputError, PaginatedResponse,
};
use crate::rate_limit::KeyedLimiter;
use crate::storage::ThreatIntelRepo;

const MAX_BULK_INDICATORS: usize = 500;
const MAX_SIGHTING_CONTEXT: usize = 8 * 1024;

/// Application state shared across handlers.
pub struct AppState {
    pub repo: ThreatIntelRepo,
    pub enrichment: Arc<EnrichmentEngine>,
    pub auth: AuthState,
    pub limiter: Arc<KeyedLimiter>,
}

/// Create the API router. HTTP limits and CORS are applied by [`with_http_layers`].
pub fn create_router(state: Arc<AppState>) -> Router {
    let reads = Router::new()
        .route("/api/v1/indicators", get(list_indicators))
        .route("/api/v1/indicators/:id", get(get_indicator))
        .route("/api/v1/lookup", get(lookup_indicator))
        .route("/api/v1/lookup/:value", get(lookup_indicator_by_path))
        .route("/api/v1/stats", get(get_stats))
        .route("/api/v1/sources", get(list_sources))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_read_auth,
        ));

    let writes = Router::new()
        .route("/api/v1/indicators", post(create_indicator))
        .route("/api/v1/indicators/bulk", post(bulk_import))
        .route("/api/v1/indicators/:id", delete(delete_indicator))
        .route("/api/v1/indicators/:id/enrich", post(enrich_indicator))
        .route("/api/v1/indicators/:id/sightings", post(add_sighting))
        .route("/api/v1/feeds/refresh", post(refresh_feeds))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_write_auth,
        ));

    Router::new()
        .route("/health", get(health_check))
        .merge(reads)
        .merge(writes)
        .layer(from_fn(security_headers))
        .with_state(state)
}

/// Settings for edge middleware that does not belong in [`AppState`].
pub struct HttpSettings {
    pub cors_origins: String,
    pub body_limit: usize,
}

pub fn with_http_layers(router: Router, settings: &HttpSettings) -> Router {
    router
        .layer(DefaultBodyLimit::max(settings.body_limit))
        .layer(cors_layer(&settings.cors_origins))
}

pub fn cors_layer(origins: &str) -> CorsLayer {
    let values: Vec<HeaderValue> = origins
        .split(',')
        .map(str::trim)
        .filter(|origin| !origin.is_empty())
        .filter_map(|origin| match origin.parse::<HeaderValue>() {
            Ok(value) => Some(value),
            Err(_) => {
                tracing::warn!("ignoring invalid CORS origin");
                None
            }
        })
        .collect();

    CorsLayer::new()
        .allow_origin(AllowOrigin::list(values))
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            HeaderName::from_static("x-api-key"),
        ])
        .max_age(Duration::from_secs(600))
}

async fn security_headers(request: Request<axum::body::Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

async fn require_read_auth(
    State(state): State<Arc<AppState>>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    if state.auth.require_read_auth && !authorize(&state, &request) {
        return unauthorized();
    }
    next.run(request).await
}

async fn require_write_auth(
    State(state): State<Arc<AppState>>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    if !authorize(&state, &request) {
        return unauthorized();
    }
    next.run(request).await
}

pub async fn limit_requests(
    State(state): State<Arc<AppState>>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));

    if state.limiter.check_key(&ip).is_err() {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", "1")],
            Json(json!({ "error": "rate limit exceeded" })),
        )
            .into_response();
    }

    next.run(request).await
}

fn authorize(state: &AppState, request: &Request<axum::body::Body>) -> bool {
    state
        .auth
        .authorize(presented_key(request.headers()).as_deref())
}

fn presented_key(headers: &HeaderMap) -> Option<String> {
    if let Some(value) = headers.get("x-api-key") {
        return header_text(value);
    }
    let value = headers.get(header::AUTHORIZATION)?;
    let text = value.to_str().ok()?;
    let token = text.strip_prefix("Bearer ")?.trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

fn header_text(value: &HeaderValue) -> Option<String> {
    let text = value.to_str().ok()?.trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer")],
        Json(json!({ "error": "unauthorized" })),
    )
        .into_response()
}

fn map_err(err: anyhow::Error) -> (StatusCode, Json<Value>) {
    if let Some(input) = err.downcast_ref::<InputError>() {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": input.0 })));
    }
    tracing::error!(error = %err, "request failed");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": "internal error" })),
    )
}

async fn health_check() -> Json<Value> {
    Json(json!({
        "status": "healthy",
        "service": "sentinelforge",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn list_indicators(
    State(state): State<Arc<AppState>>,
    Query(filter): Query<IndicatorFilter>,
) -> Result<Json<PaginatedResponse<crate::models::Indicator>>, (StatusCode, Json<Value>)> {
    state
        .repo
        .search_indicators(&filter)
        .await
        .map(Json)
        .map_err(map_err)
}

async fn create_indicator(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateIndicatorRequest>,
) -> Result<(StatusCode, Json<crate::models::Indicator>), (StatusCode, Json<Value>)> {
    if let Err(msg) = validate_indicator_request(&req) {
        return Err((StatusCode::BAD_REQUEST, Json(json!({ "error": msg }))));
    }

    let indicator = state
        .repo
        .upsert_indicator(&req, None)
        .await
        .map_err(map_err)?;

    let enrichment = state.enrichment.clone();
    let repo = state.repo.clone();
    let indicator_clone = indicator.clone();

    tokio::spawn(async move {
        let results = enrichment.enrich_all(&indicator_clone).await;
        for (enrichment_type, provider, data, ttl) in results {
            if let Err(err) = repo
                .add_enrichment(
                    indicator_clone.id,
                    &enrichment_type,
                    &provider,
                    data,
                    Some(ttl),
                )
                .await
            {
                tracing::warn!(error = %err, "failed to save enrichment");
            }
        }
    });

    Ok((StatusCode::CREATED, Json(indicator)))
}

async fn bulk_import(
    State(state): State<Arc<AppState>>,
    Json(req): Json<BulkImportRequest>,
) -> Result<Json<BulkImportResponse>, (StatusCode, Json<Value>)> {
    if req.indicators.len() > MAX_BULK_INDICATORS {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "error": format!("bulk import is limited to {MAX_BULK_INDICATORS} indicators") }),
            ),
        ));
    }
    if let Err(msg) = validate_label(&req.source, "source") {
        return Err((StatusCode::BAD_REQUEST, Json(json!({ "error": msg }))));
    }
    if let Some(tags) = &req.tags
        && let Err(msg) = crate::models::ioc_utils::validate_tags(tags)
    {
        return Err((StatusCode::BAD_REQUEST, Json(json!({ "error": msg }))));
    }

    let total = req.indicators.len();
    let mut created = 0;
    let mut failed = 0;
    let mut errors = vec![];

    for mut indicator_req in req.indicators {
        if indicator_req.source.is_none() {
            indicator_req.source = Some(req.source.clone());
        }
        if indicator_req.tlp.is_none() {
            indicator_req.tlp = req.tlp.clone();
        }
        if let Some(ref bulk_tags) = req.tags {
            let mut tags = indicator_req.tags.unwrap_or_default();
            tags.extend(bulk_tags.clone());
            indicator_req.tags = Some(tags);
        }

        match state.repo.upsert_indicator(&indicator_req, None).await {
            Ok(_) => created += 1,
            Err(err) => {
                failed += 1;
                let reason = err
                    .downcast_ref::<InputError>()
                    .map(|input| input.0.clone())
                    .unwrap_or_else(|| "rejected".to_string());
                let value = truncate_chars(&indicator_req.value, 80);
                errors.push(format!("{value}: {reason}"));
            }
        }
    }

    Ok(Json(BulkImportResponse {
        total,
        created,
        updated: 0,
        failed,
        errors,
    }))
}

async fn get_indicator(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<IndicatorResponse>, (StatusCode, Json<Value>)> {
    let indicator = state
        .repo
        .get_indicator(id)
        .await
        .map_err(map_err)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "indicator not found" })),
            )
        })?;

    let enrichments = state.repo.get_enrichments(id).await.unwrap_or_default();
    let sightings_count = state.repo.count_sightings(id).await.unwrap_or(0);

    Ok(Json(IndicatorResponse {
        indicator,
        enrichments,
        sightings_count,
        related_indicators: vec![],
    }))
}

async fn delete_indicator(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, Json<Value>)> {
    let deleted = state.repo.delete_indicator(id).await.map_err(map_err)?;
    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "indicator not found" })),
        ))
    }
}

async fn enrich_indicator(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let indicator = state
        .repo
        .get_indicator(id)
        .await
        .map_err(map_err)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "indicator not found" })),
            )
        })?;

    let results = state.enrichment.enrich_all(&indicator).await;
    let mut enrichments_added = 0;

    for (enrichment_type, provider, data, ttl) in results {
        if state
            .repo
            .add_enrichment(id, &enrichment_type, &provider, data, Some(ttl))
            .await
            .is_ok()
        {
            enrichments_added += 1;
        }
    }

    Ok(Json(json!({
        "message": "enrichment complete",
        "enrichments_added": enrichments_added,
    })))
}

async fn add_sighting(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let source = body
        .get("source")
        .and_then(|v| v.as_str())
        .unwrap_or("manual");
    if let Err(msg) = validate_label(source, "source") {
        return Err((StatusCode::BAD_REQUEST, Json(json!({ "error": msg }))));
    }
    let context = body.get("context").cloned();
    if context
        .as_ref()
        .is_some_and(|value| value.to_string().len() > MAX_SIGHTING_CONTEXT)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "context is too large" })),
        ));
    }

    let sighting = state
        .repo
        .add_sighting(id, source, context)
        .await
        .map_err(map_err)?;

    Ok(Json(json!({
        "id": sighting.id,
        "observed_at": sighting.observed_at,
    })))
}

async fn lookup_indicator(
    State(state): State<Arc<AppState>>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let value = params.get("value").ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "missing 'value' parameter" })),
        )
    })?;
    lookup_by_value(&state, value).await
}

async fn lookup_indicator_by_path(
    State(state): State<Arc<AppState>>,
    Path(value): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    lookup_by_value(&state, &value).await
}

async fn lookup_by_value(
    state: &Arc<AppState>,
    value: &str,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if value.chars().count() > 2048 || value.chars().any(|c| c.is_control()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid lookup value" })),
        ));
    }

    let indicator = state
        .repo
        .get_indicator_by_value(value)
        .await
        .map_err(map_err)?;

    match indicator {
        Some(ind) => {
            let enrichments = state.repo.get_enrichments(ind.id).await.unwrap_or_default();
            Ok(Json(json!({
                "found": true,
                "indicator": ind,
                "enrichments": enrichments,
            })))
        }
        None => Ok(Json(json!({
            "found": false,
        }))),
    }
}

async fn get_stats(
    State(state): State<Arc<AppState>>,
) -> Result<Json<DashboardStats>, (StatusCode, Json<Value>)> {
    state.repo.get_stats().await.map(Json).map_err(map_err)
}

async fn list_sources(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let sources = state.repo.get_enabled_sources().await.map_err(map_err)?;
    Ok(Json(json!({ "sources": sources })))
}

async fn refresh_feeds(State(_state): State<Arc<AppState>>) -> Json<Value> {
    Json(json!({
        "message": "feed refresh is not wired to collectors yet",
    }))
}

fn truncate_chars(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_string();
    }
    let truncated: String = value.chars().take(max).collect();
    format!("{truncated}...")
}
