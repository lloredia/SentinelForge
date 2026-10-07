//! Database storage layer for threat intelligence

use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Postgres, QueryBuilder};
use uuid::Uuid;

use crate::models::ioc_utils::{
    InputError, detect_ioc_type, normalize_filter, normalize_ioc, validate_indicator_request,
};
use crate::models::{
    CreateIndicatorRequest, DashboardStats, Enrichment, Indicator, IndicatorFilter, IocSource,
    PaginatedResponse, Severity, Sighting, Tlp,
};

/// Database repository for threat intelligence
#[derive(Clone)]
pub struct ThreatIntelRepo {
    pool: PgPool,
}

impl ThreatIntelRepo {
    /// Create new repository with database connection
    pub async fn new(database_url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(20)
            .connect(database_url)
            .await
            .context("Failed to connect to database")?;

        Ok(Self { pool })
    }

    /// Wrap an existing pool. Used by tests and embedders that manage the pool.
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get the connection pool
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Run database migrations
    pub async fn migrate(&self) -> Result<()> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .context("Failed to run migrations")?;
        Ok(())
    }

    // ==================== Indicators ====================

    /// Create or update an indicator
    pub async fn upsert_indicator(
        &self,
        req: &CreateIndicatorRequest,
        source_id: Option<Uuid>,
    ) -> Result<Indicator> {
        validate_indicator_request(req).map_err(|msg| anyhow::Error::new(InputError(msg)))?;
        let ioc_type = req
            .ioc_type
            .clone()
            .or_else(|| detect_ioc_type(&req.value))
            .ok_or_else(|| {
                anyhow::Error::new(InputError("could not detect IOC type".to_string()))
            })?;

        let normalized_value = normalize_ioc(&req.value, &ioc_type);
        let now = Utc::now();
        let expiration = req
            .expiration_days
            .map(|days| now + Duration::days(days as i64));

        let indicator = sqlx::query_as::<_, Indicator>(
            r#"
            INSERT INTO indicators (
                id, ioc_type, value, severity, confidence, threat_score, tlp,
                first_seen, last_seen, expiration, tags, source_ids, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8, $9, $10, $11, $8, $8)
            ON CONFLICT (ioc_type, value) DO UPDATE SET
                severity = CASE WHEN EXCLUDED.severity > indicators.severity THEN EXCLUDED.severity ELSE indicators.severity END,
                confidence = GREATEST(indicators.confidence, EXCLUDED.confidence),
                last_seen = EXCLUDED.last_seen,
                tags = array_cat(indicators.tags, EXCLUDED.tags),
                source_ids = array_cat(indicators.source_ids, EXCLUDED.source_ids),
                updated_at = EXCLUDED.updated_at
            RETURNING *
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(&ioc_type)
        .bind(&normalized_value)
        .bind(req.severity.clone().unwrap_or(Severity::Unknown))
        .bind(req.confidence.unwrap_or(50))
        .bind(req.confidence.unwrap_or(50)) // Initial threat_score = confidence
        .bind(req.tlp.clone().unwrap_or(Tlp::Amber))
        .bind(now)
        .bind(expiration)
        .bind(req.tags.clone().unwrap_or_default())
        .bind(source_id.map(|id| vec![id]).unwrap_or_default())
        .fetch_one(&self.pool)
        .await
        .context("Failed to upsert indicator")?;

        Ok(indicator)
    }

    /// Get indicator by ID
    pub async fn get_indicator(&self, id: Uuid) -> Result<Option<Indicator>> {
        let indicator = sqlx::query_as::<_, Indicator>("SELECT * FROM indicators WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .context("Failed to fetch indicator")?;

        Ok(indicator)
    }

    /// Get indicator by value
    pub async fn get_indicator_by_value(&self, value: &str) -> Result<Option<Indicator>> {
        // Try to detect type and normalize
        if let Some(ioc_type) = detect_ioc_type(value) {
            let normalized = normalize_ioc(value, &ioc_type);
            let indicator = sqlx::query_as::<_, Indicator>(
                "SELECT * FROM indicators WHERE ioc_type = $1 AND value = $2",
            )
            .bind(&ioc_type)
            .bind(&normalized)
            .fetch_optional(&self.pool)
            .await
            .context("Failed to fetch indicator by value")?;

            return Ok(indicator);
        }

        // Fallback to direct search
        let indicator = sqlx::query_as::<_, Indicator>("SELECT * FROM indicators WHERE value = $1")
            .bind(value)
            .fetch_optional(&self.pool)
            .await
            .context("Failed to fetch indicator by value")?;

        Ok(indicator)
    }

    /// Search indicators with filters.
    ///
    /// Both the page query and the count query bind every predicate through
    /// `QueryBuilder`, so omitted filters do not leave unused placeholders.
    pub async fn search_indicators(
        &self,
        filter: &IndicatorFilter,
    ) -> Result<PaginatedResponse<Indicator>> {
        let normalized =
            normalize_filter(filter).map_err(|msg| anyhow::Error::new(InputError(msg)))?;

        let mut data: QueryBuilder<Postgres> =
            QueryBuilder::new("SELECT * FROM indicators WHERE 1=1");
        push_indicator_filters(&mut data, filter, normalized.search_pattern.as_deref());
        data.push(" ORDER BY last_seen DESC, id DESC LIMIT ");
        data.push_bind(normalized.per_page);
        data.push(" OFFSET ");
        data.push_bind(normalized.offset);

        let indicators = data
            .build_query_as::<Indicator>()
            .fetch_all(&self.pool)
            .await
            .context("Failed to search indicators")?;

        let mut count: QueryBuilder<Postgres> =
            QueryBuilder::new("SELECT COUNT(*) FROM indicators WHERE 1=1");
        push_indicator_filters(&mut count, filter, normalized.search_pattern.as_deref());
        let total: (i64,) = count
            .build_query_as()
            .fetch_one(&self.pool)
            .await
            .context("Failed to count indicators")?;

        let total_pages = if total.0 == 0 {
            0
        } else {
            (total.0 + normalized.per_page - 1) / normalized.per_page
        };

        Ok(PaginatedResponse {
            data: indicators,
            total: total.0,
            page: normalized.page,
            per_page: normalized.per_page,
            total_pages,
        })
    }

    /// Delete an indicator and its dependent rows. Returns false when missing.
    pub async fn delete_indicator(&self, id: Uuid) -> Result<bool> {
        let result = sqlx::query("DELETE FROM indicators WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to delete indicator")?;
        Ok(result.rows_affected() > 0)
    }

    /// Update threat score for an indicator
    pub async fn update_threat_score(&self, id: Uuid, score: i32) -> Result<()> {
        sqlx::query(
            "UPDATE indicators SET threat_score = $1, severity = $2, updated_at = NOW() WHERE id = $3"
        )
        .bind(score)
        .bind(Severity::from(score))
        .bind(id)
        .execute(&self.pool)
        .await
        .context("Failed to update threat score")?;

        Ok(())
    }

    /// Delete expired indicators
    pub async fn delete_expired(&self) -> Result<i64> {
        let result = sqlx::query(
            "DELETE FROM indicators WHERE expiration IS NOT NULL AND expiration < NOW()",
        )
        .execute(&self.pool)
        .await
        .context("Failed to delete expired indicators")?;

        Ok(result.rows_affected() as i64)
    }

    // ==================== Enrichments ====================

    /// Add enrichment data for an indicator
    pub async fn add_enrichment(
        &self,
        indicator_id: Uuid,
        enrichment_type: &str,
        provider: &str,
        data: serde_json::Value,
        ttl_hours: Option<i64>,
    ) -> Result<Enrichment> {
        let expires_at = ttl_hours.map(|h| Utc::now() + Duration::hours(h));

        let enrichment = sqlx::query_as::<_, Enrichment>(
            r#"
            INSERT INTO enrichments (id, indicator_id, enrichment_type, provider, data, fetched_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, NOW(), $6)
            ON CONFLICT (indicator_id, enrichment_type, provider) DO UPDATE SET
                data = EXCLUDED.data,
                fetched_at = EXCLUDED.fetched_at,
                expires_at = EXCLUDED.expires_at
            RETURNING *
            "#
        )
        .bind(Uuid::new_v4())
        .bind(indicator_id)
        .bind(enrichment_type)
        .bind(provider)
        .bind(data)
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await
        .context("Failed to add enrichment")?;

        Ok(enrichment)
    }

    /// Get enrichments for an indicator
    pub async fn get_enrichments(&self, indicator_id: Uuid) -> Result<Vec<Enrichment>> {
        let enrichments = sqlx::query_as::<_, Enrichment>(
            "SELECT * FROM enrichments WHERE indicator_id = $1 ORDER BY fetched_at DESC",
        )
        .bind(indicator_id)
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch enrichments")?;

        Ok(enrichments)
    }

    // ==================== Sightings ====================

    /// Record a sighting of an indicator
    pub async fn add_sighting(
        &self,
        indicator_id: Uuid,
        source: &str,
        context: Option<serde_json::Value>,
    ) -> Result<Sighting> {
        let sighting = sqlx::query_as::<_, Sighting>(
            r#"
            INSERT INTO sightings (id, indicator_id, source, context, observed_at, created_at)
            VALUES ($1, $2, $3, $4, NOW(), NOW())
            RETURNING *
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(indicator_id)
        .bind(source)
        .bind(context)
        .fetch_one(&self.pool)
        .await
        .context("Failed to add sighting")?;

        // Update last_seen on indicator
        sqlx::query("UPDATE indicators SET last_seen = NOW() WHERE id = $1")
            .bind(indicator_id)
            .execute(&self.pool)
            .await?;

        Ok(sighting)
    }

    /// Count sightings for an indicator
    pub async fn count_sightings(&self, indicator_id: Uuid) -> Result<i64> {
        let count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM sightings WHERE indicator_id = $1")
                .bind(indicator_id)
                .fetch_one(&self.pool)
                .await
                .context("Failed to count sightings")?;

        Ok(count.0)
    }

    // ==================== Sources ====================

    /// Create or update a source
    pub async fn upsert_source(&self, source: &IocSource) -> Result<IocSource> {
        let result = sqlx::query_as::<_, IocSource>(
            r#"
            INSERT INTO ioc_sources (id, name, source_type, url, api_key_required, reliability_score, enabled, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
            ON CONFLICT (name) DO UPDATE SET
                url = EXCLUDED.url,
                reliability_score = EXCLUDED.reliability_score,
                enabled = EXCLUDED.enabled,
                updated_at = NOW()
            RETURNING *
            "#
        )
        .bind(source.id)
        .bind(&source.name)
        .bind(&source.source_type)
        .bind(&source.url)
        .bind(source.api_key_required)
        .bind(source.reliability_score)
        .bind(source.enabled)
        .fetch_one(&self.pool)
        .await
        .context("Failed to upsert source")?;

        Ok(result)
    }

    /// Get all enabled sources
    pub async fn get_enabled_sources(&self) -> Result<Vec<IocSource>> {
        let sources = sqlx::query_as::<_, IocSource>(
            "SELECT * FROM ioc_sources WHERE enabled = true ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch sources")?;

        Ok(sources)
    }

    /// Update source last fetch time
    pub async fn update_source_fetch_time(&self, source_id: Uuid) -> Result<()> {
        sqlx::query("UPDATE ioc_sources SET last_fetch = NOW(), updated_at = NOW() WHERE id = $1")
            .bind(source_id)
            .execute(&self.pool)
            .await
            .context("Failed to update source fetch time")?;

        Ok(())
    }

    // ==================== Statistics ====================

    /// Get dashboard statistics
    pub async fn get_stats(&self) -> Result<DashboardStats> {
        let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM indicators")
            .fetch_one(&self.pool)
            .await?;

        let new_today: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM indicators WHERE created_at >= CURRENT_DATE")
                .fetch_one(&self.pool)
                .await?;

        let new_this_week: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM indicators WHERE created_at >= CURRENT_DATE - INTERVAL '7 days'",
        )
        .fetch_one(&self.pool)
        .await?;

        let active_sources: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM ioc_sources WHERE enabled = true")
                .fetch_one(&self.pool)
                .await?;

        let recent_sightings: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM sightings WHERE observed_at >= CURRENT_DATE - INTERVAL '24 hours'"
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(DashboardStats {
            total_indicators: total.0,
            indicators_by_type: std::collections::HashMap::new(), // TODO: implement
            indicators_by_severity: std::collections::HashMap::new(), // TODO: implement
            new_today: new_today.0,
            new_this_week: new_this_week.0,
            active_sources: active_sources.0,
            top_tags: vec![], // TODO: implement
            recent_sightings: recent_sightings.0,
        })
    }
}

fn push_indicator_filters<'a>(
    builder: &mut QueryBuilder<'a, Postgres>,
    filter: &'a IndicatorFilter,
    search_pattern: Option<&'a str>,
) {
    if let Some(ioc_type) = &filter.ioc_type {
        builder.push(" AND ioc_type = ");
        builder.push_bind(ioc_type);
    }
    if let Some(severity) = &filter.severity {
        builder.push(" AND severity = ");
        builder.push_bind(severity);
    }
    if let Some(min_confidence) = filter.min_confidence {
        builder.push(" AND confidence >= ");
        builder.push_bind(min_confidence);
    }
    if let Some(min_threat_score) = filter.min_threat_score {
        builder.push(" AND threat_score >= ");
        builder.push_bind(min_threat_score);
    }
    if let Some(pattern) = search_pattern {
        builder.push(" AND value ILIKE ");
        builder.push_bind(pattern);
        builder.push(" ESCAPE '\\'");
    }
    if let Some(tags) = &filter.tags
        && !tags.is_empty()
    {
        builder.push(" AND tags @> ");
        builder.push_bind(tags);
    }
    if let Some(source_id) = filter.source_id {
        builder.push(" AND ");
        builder.push_bind(source_id);
        builder.push(" = ANY(source_ids)");
    }
}
