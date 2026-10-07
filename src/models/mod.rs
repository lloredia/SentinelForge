//! Core data models for Threat Intelligence

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Types of Indicators of Compromise
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "ioc_type", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum IocType {
    Ip,
    Domain,
    Url,
    Hash,
    Email,
    Cve,
}

impl std::fmt::Display for IocType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IocType::Ip => write!(f, "ip"),
            IocType::Domain => write!(f, "domain"),
            IocType::Url => write!(f, "url"),
            IocType::Hash => write!(f, "hash"),
            IocType::Email => write!(f, "email"),
            IocType::Cve => write!(f, "cve"),
        }
    }
}

/// Threat severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "severity", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

impl From<i32> for Severity {
    fn from(score: i32) -> Self {
        match score {
            0..=20 => Severity::Low,
            21..=50 => Severity::Medium,
            51..=80 => Severity::High,
            81..=100 => Severity::Critical,
            _ => Severity::Unknown,
        }
    }
}

/// Traffic light protocol for sharing
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "tlp", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum Tlp {
    White, // Public
    Green, // Community
    Amber, // Limited
    Red,   // Restricted
}

/// Source of the IOC
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct IocSource {
    pub id: Uuid,
    pub name: String,
    pub source_type: String, // internal, feed, manual
    pub url: Option<String>,
    pub api_key_required: bool,
    pub reliability_score: i32, // 0-100
    pub enabled: bool,
    pub last_fetch: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Main IOC record
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Indicator {
    pub id: Uuid,
    pub ioc_type: IocType,
    pub value: String,
    pub severity: Severity,
    pub confidence: i32,   // 0-100
    pub threat_score: i32, // 0-100 composite score
    pub tlp: Tlp,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub expiration: Option<DateTime<Utc>>,
    pub tags: Vec<String>,
    pub source_ids: Vec<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Enrichment data for an IOC
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Enrichment {
    pub id: Uuid,
    pub indicator_id: Uuid,
    pub enrichment_type: String, // geoip, whois, dns, virustotal, etc.
    pub data: serde_json::Value,
    pub provider: String,
    pub fetched_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// GeoIP enrichment data
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GeoIpData {
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub city: Option<String>,
    pub region: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub asn: Option<u32>,
    pub as_org: Option<String>,
    pub isp: Option<String>,
}

/// WHOIS enrichment data
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WhoisData {
    pub registrar: Option<String>,
    pub registrant: Option<String>,
    pub registrant_org: Option<String>,
    pub registrant_country: Option<String>,
    pub creation_date: Option<DateTime<Utc>>,
    pub expiration_date: Option<DateTime<Utc>>,
    pub updated_date: Option<DateTime<Utc>>,
    pub name_servers: Vec<String>,
    pub status: Vec<String>,
    pub raw: Option<String>,
}

/// DNS enrichment data
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsData {
    pub a_records: Vec<String>,
    pub aaaa_records: Vec<String>,
    pub mx_records: Vec<String>,
    pub txt_records: Vec<String>,
    pub ns_records: Vec<String>,
    pub cname_records: Vec<String>,
}

/// Sighting - when an IOC was observed
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Sighting {
    pub id: Uuid,
    pub indicator_id: Uuid,
    pub source: String,
    pub context: Option<serde_json::Value>,
    pub observed_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// API request to create/update an IOC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateIndicatorRequest {
    pub value: String,
    pub ioc_type: Option<IocType>, // Auto-detect if not provided
    pub severity: Option<Severity>,
    pub confidence: Option<i32>,
    pub tlp: Option<Tlp>,
    pub tags: Option<Vec<String>>,
    pub source: Option<String>,
    pub expiration_days: Option<i32>,
}

/// API response for IOC queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndicatorResponse {
    pub indicator: Indicator,
    pub enrichments: Vec<Enrichment>,
    pub sightings_count: i64,
    pub related_indicators: Vec<Indicator>,
}

/// Bulk import request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkImportRequest {
    pub indicators: Vec<CreateIndicatorRequest>,
    pub source: String,
    pub tlp: Option<Tlp>,
    pub tags: Option<Vec<String>>,
}

/// Bulk import response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkImportResponse {
    pub total: usize,
    pub created: usize,
    pub updated: usize,
    pub failed: usize,
    pub errors: Vec<String>,
}

/// Search/filter parameters
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IndicatorFilter {
    pub ioc_type: Option<IocType>,
    pub severity: Option<Severity>,
    pub min_confidence: Option<i32>,
    pub min_threat_score: Option<i32>,
    pub tags: Option<Vec<String>>,
    pub source_id: Option<Uuid>,
    pub first_seen_after: Option<DateTime<Utc>>,
    pub first_seen_before: Option<DateTime<Utc>>,
    pub search: Option<String>,
    pub page: Option<i64>,
    pub per_page: Option<i64>,
}

/// Paginated response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    pub data: Vec<T>,
    pub total: i64,
    pub page: i64,
    pub per_page: i64,
    pub total_pages: i64,
}

/// Feed status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedStatus {
    pub source: IocSource,
    pub last_run: Option<DateTime<Utc>>,
    pub next_run: Option<DateTime<Utc>>,
    pub indicators_count: i64,
    pub status: String,
    pub last_error: Option<String>,
}

/// Dashboard statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardStats {
    pub total_indicators: i64,
    pub indicators_by_type: std::collections::HashMap<String, i64>,
    pub indicators_by_severity: std::collections::HashMap<String, i64>,
    pub new_today: i64,
    pub new_this_week: i64,
    pub active_sources: i64,
    pub top_tags: Vec<(String, i64)>,
    pub recent_sightings: i64,
}
pub mod ioc_utils;

pub use ioc_utils::InputError;
