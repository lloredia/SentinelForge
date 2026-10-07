//! Postgres-backed tests for indicator search and API-key auth.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use sentinelforge::api::{AppState, create_router};
use sentinelforge::auth::AuthState;
use sentinelforge::enrichment::EnrichmentEngine;
use sentinelforge::models::{CreateIndicatorRequest, IndicatorFilter, IocType, Severity};
use sentinelforge::rate_limit::build_limiter;
use sentinelforge::storage::ThreatIntelRepo;
use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use tower::ServiceExt;

const API_KEY: &str = "test-suite-api-key";

async fn lock_db() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    LOCK.lock().await
}

async fn repo() -> ThreatIntelRepo {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .expect("connect");
    let repo = ThreatIntelRepo::from_pool(pool);
    repo.migrate().await.expect("migrate");
    sqlx::query("TRUNCATE indicators CASCADE")
        .execute(repo.pool())
        .await
        .expect("truncate");
    repo
}

fn indicator(value: &str, severity: Severity, confidence: i32) -> CreateIndicatorRequest {
    CreateIndicatorRequest {
        value: value.to_string(),
        ioc_type: None,
        severity: Some(severity),
        confidence: Some(confidence),
        tlp: None,
        tags: Some(vec!["suite".to_string()]),
        source: Some("test".to_string()),
        expiration_days: None,
    }
}

fn state(repo: ThreatIntelRepo, require_read_auth: bool) -> Arc<AppState> {
    Arc::new(AppState {
        repo,
        enrichment: Arc::new(EnrichmentEngine::new()),
        auth: AuthState::new(API_KEY, require_read_auth),
        limiter: build_limiter(50, 100).expect("limiter"),
    })
}

#[tokio::test]
async fn search_binds_each_filter_and_keeps_count_in_sync() {
    if std::env::var("DATABASE_URL").is_err() {
        eprintln!("DATABASE_URL not set; skipping integration test");
        return;
    }
    let _guard = lock_db().await;
    let repo = repo().await;

    repo.upsert_indicator(&indicator("8.8.8.8", Severity::Low, 20), None)
        .await
        .unwrap();
    repo.upsert_indicator(&indicator("1.2.3.4", Severity::High, 90), None)
        .await
        .unwrap();
    repo.upsert_indicator(&indicator("evil.example", Severity::Medium, 60), None)
        .await
        .unwrap();

    let all = repo
        .search_indicators(&IndicatorFilter::default())
        .await
        .unwrap();
    assert_eq!(all.total, 3);
    assert_eq!(all.data.len(), 3);
    assert_eq!(all.page, 1);
    assert_eq!(all.per_page, 50);

    let ips = repo
        .search_indicators(&IndicatorFilter {
            ioc_type: Some(IocType::Ip),
            ..IndicatorFilter::default()
        })
        .await
        .unwrap();
    assert_eq!(ips.total, 2);
    assert!(ips.data.iter().all(|row| row.ioc_type == IocType::Ip));

    let high = repo
        .search_indicators(&IndicatorFilter {
            severity: Some(Severity::High),
            ..IndicatorFilter::default()
        })
        .await
        .unwrap();
    assert_eq!(high.total, 1);
    assert_eq!(high.data[0].value, "1.2.3.4");

    let confident = repo
        .search_indicators(&IndicatorFilter {
            min_confidence: Some(50),
            ..IndicatorFilter::default()
        })
        .await
        .unwrap();
    assert_eq!(confident.total, 2);

    let searched = repo
        .search_indicators(&IndicatorFilter {
            search: Some("EVIL".into()),
            ..IndicatorFilter::default()
        })
        .await
        .unwrap();
    assert_eq!(searched.total, 1);
    assert_eq!(searched.data[0].value, "evil.example");

    let wildcard = repo
        .search_indicators(&IndicatorFilter {
            search: Some("%".into()),
            ..IndicatorFilter::default()
        })
        .await
        .unwrap();
    assert_eq!(wildcard.total, 0);

    let page = repo
        .search_indicators(&IndicatorFilter {
            page: Some(2),
            per_page: Some(1),
            ..IndicatorFilter::default()
        })
        .await
        .unwrap();
    assert_eq!(page.total, 3);
    assert_eq!(page.data.len(), 1);
    assert_eq!(page.total_pages, 3);
    assert_eq!(page.page, 2);

    let bad_page = repo
        .search_indicators(&IndicatorFilter {
            page: Some(0),
            ..IndicatorFilter::default()
        })
        .await;
    assert!(bad_page.is_err());

    let bad_size = repo
        .search_indicators(&IndicatorFilter {
            per_page: Some(1000),
            ..IndicatorFilter::default()
        })
        .await;
    assert!(bad_size.is_err());
}

#[tokio::test]
async fn writes_require_api_key_and_reads_are_configurable() {
    if std::env::var("DATABASE_URL").is_err() {
        eprintln!("DATABASE_URL not set; skipping integration test");
        return;
    }
    let _guard = lock_db().await;
    let store = repo().await;
    let app = create_router(state(store, false));

    let missing = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/indicators",
            None,
            r#"{"value":"9.9.9.9"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

    let wrong = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/indicators",
            Some("not-the-right-key"),
            r#"{"value":"9.9.9.9"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);

    let invalid = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/indicators",
            Some(API_KEY),
            r#"{"value":"not an indicator"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);

    let created = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/indicators",
            Some(API_KEY),
            r#"{"value":"9.9.9.9","severity":"low"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);

    let health = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::OK);

    let reads = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/indicators")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(reads.status(), StatusCode::OK);
    let body = axum::body::to_bytes(reads.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let parsed: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["total"], 1);

    let locked = create_router(state(repo().await, true));
    let denied = locked
        .oneshot(
            Request::builder()
                .uri("/api/v1/stats")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
}

fn json_request(method: &str, uri: &str, key: Option<&str>, body: &'static str) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(key) = key {
        builder = builder.header("x-api-key", key);
    }
    builder.body(Body::from(body)).unwrap()
}
