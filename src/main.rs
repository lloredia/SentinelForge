//! SentinelForge
//!
//! A service for collecting, enriching, and serving threat intelligence data.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::middleware;
use clap::Parser;
use tokio::net::TcpListener;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use sentinelforge::api::{AppState, HttpSettings, create_router, limit_requests, with_http_layers};
use sentinelforge::auth::AuthState;
use sentinelforge::enrichment::EnrichmentEngine;
use sentinelforge::enrichment::abuseipdb::AbuseIpDbProvider;
use sentinelforge::enrichment::dns::DnsProvider;
use sentinelforge::enrichment::geoip::GeoIpProvider;
use sentinelforge::enrichment::virustotal::VirusTotalProvider;
use sentinelforge::rate_limit::build_limiter;
use sentinelforge::storage::ThreatIntelRepo;

/// SentinelForge
#[derive(Parser)]
#[command(name = "sentinelforge")]
#[command(about = "Collect, enrich, and serve threat intelligence")]
struct Args {
    /// Server host. Defaults to loopback; set HOST=0.0.0.0 inside a container.
    #[arg(long, env = "HOST", default_value = "127.0.0.1")]
    host: String,

    /// Server port
    #[arg(long, env = "PORT", default_value_t = 8080)]
    port: u16,

    /// Database URL
    #[arg(long, env = "DATABASE_URL")]
    database_url: Option<String>,

    /// GeoIP city database path
    #[arg(long, env = "GEOIP_CITY_DB")]
    geoip_city_db: Option<String>,

    /// GeoIP ASN database path
    #[arg(long, env = "GEOIP_ASN_DB")]
    geoip_asn_db: Option<String>,

    /// AbuseIPDB API key
    #[arg(long, env = "ABUSEIPDB_API_KEY")]
    abuseipdb_api_key: Option<String>,

    /// VirusTotal API key
    #[arg(long, env = "VIRUSTOTAL_API_KEY")]
    virustotal_api_key: Option<String>,

    /// Comma-separated API keys accepted on write requests (and reads, when enabled).
    #[arg(long, env = "API_KEYS", default_value = "")]
    api_keys: String,

    /// Require an API key for read endpoints.
    #[arg(long, env = "REQUIRE_READ_AUTH", default_value_t = false)]
    require_read_auth: bool,

    /// Comma-separated browser origins allowed to call the API.
    #[arg(
        long,
        env = "CORS_ALLOWED_ORIGINS",
        default_value = "http://127.0.0.1:3000,http://localhost:3000"
    )]
    cors_allowed_origins: String,

    /// Maximum request body size in bytes.
    #[arg(long, env = "BODY_LIMIT_BYTES", default_value_t = 2 * 1024 * 1024)]
    body_limit_bytes: usize,

    /// Sustained requests per second per client IP.
    #[arg(long, env = "RATE_LIMIT_PER_SECOND", default_value_t = 10)]
    rate_limit_per_second: u32,

    /// Burst size per client IP. Values below the per-second rate are raised to match it.
    #[arg(long, env = "RATE_LIMIT_BURST", default_value_t = 30)]
    rate_limit_burst: u32,

    /// Run database migrations before serving.
    #[arg(long, default_value_t = false)]
    migrate: bool,

    /// Probe /health and exit. Used by container healthchecks.
    #[arg(long, default_value_t = false)]
    healthcheck: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sentinelforge=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();

    if args.healthcheck {
        return run_healthcheck(args.port).await;
    }

    tracing::info!("starting SentinelForge");

    let database_url = args
        .database_url
        .as_deref()
        .filter(|url| !url.is_empty())
        .context("DATABASE_URL is required")?;

    let repo = ThreatIntelRepo::new(database_url)
        .await
        .context("failed to connect to database")?;

    if args.migrate {
        tracing::info!("running database migrations");
        repo.migrate().await?;
        tracing::info!("migrations complete");
    }

    let mut enrichment = EnrichmentEngine::new();

    let geoip = GeoIpProvider::new(
        args.geoip_city_db.as_deref().map(Path::new),
        args.geoip_asn_db.as_deref().map(Path::new),
    );
    if geoip.is_available() {
        tracing::info!("GeoIP enrichment enabled");
    } else {
        tracing::info!("GeoIP database absent; geo enrichment will no-op");
    }
    enrichment.add_provider(Box::new(geoip));

    match DnsProvider::new().await {
        Ok(dns) => {
            tracing::info!("DNS enrichment enabled");
            enrichment.add_provider(Box::new(dns));
        }
        Err(err) => tracing::warn!(error = %err, "DNS enrichment disabled"),
    }

    if let Some(api_key) = nonempty(args.abuseipdb_api_key) {
        match AbuseIpDbProvider::new(api_key) {
            Ok(provider) => {
                tracing::info!("AbuseIPDB enrichment enabled");
                enrichment.add_provider(Box::new(provider));
            }
            Err(err) => tracing::warn!(error = %err, "AbuseIPDB enrichment disabled"),
        }
    }

    if let Some(api_key) = nonempty(args.virustotal_api_key) {
        match VirusTotalProvider::new(api_key) {
            Ok(provider) => {
                tracing::info!("VirusTotal enrichment enabled");
                enrichment.add_provider(Box::new(provider));
            }
            Err(err) => tracing::warn!(error = %err, "VirusTotal enrichment disabled"),
        }
    }

    let auth = AuthState::new(&args.api_keys, args.require_read_auth);
    if auth.key_count() == 0 {
        tracing::warn!("no API keys configured; write requests will be rejected");
    } else {
        tracing::info!(count = auth.key_count(), "API keys loaded");
    }

    let limiter = build_limiter(args.rate_limit_per_second, args.rate_limit_burst)?;
    let limiter_gc = limiter.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            limiter_gc.retain_recent();
            limiter_gc.shrink_to_fit();
        }
    });

    let state = Arc::new(AppState {
        repo,
        enrichment: Arc::new(enrichment),
        auth,
        limiter,
    });

    let settings = HttpSettings {
        cors_origins: args.cors_allowed_origins,
        body_limit: args.body_limit_bytes,
    };

    let app = with_http_layers(create_router(state.clone()), &settings)
        .layer(middleware::from_fn_with_state(state, limit_requests))
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::new(Duration::from_secs(30)));

    let addr: SocketAddr = format!("{}:{}", args.host, args.port)
        .parse()
        .context("invalid host or port")?;
    tracing::info!(%addr, "listening");

    let listener = TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

async fn run_healthcheck(port: u16) -> Result<()> {
    let client = sentinelforge::http_util::external_client(Duration::from_secs(3))?;
    let url = format!("http://127.0.0.1:{port}/health");
    let response = client
        .get(url)
        .send()
        .await
        .context("healthcheck request failed")?;
    if !response.status().is_success() {
        anyhow::bail!("healthcheck status {}", response.status());
    }
    Ok(())
}

fn nonempty(value: Option<String>) -> Option<String> {
    value.filter(|item| !item.trim().is_empty())
}
