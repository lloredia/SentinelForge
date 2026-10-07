//! Enrichment services for threat intelligence

pub mod abuseipdb;
pub mod dns;
pub mod geoip;
pub mod virustotal;
pub mod whois;

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use crate::models::{Indicator, IocType};

/// Trait for enrichment providers
#[allow(clippy::double_must_use)]
#[async_trait]
pub trait EnrichmentProvider: Send + Sync {
    /// Provider name
    fn name(&self) -> &'static str;

    /// Enrichment type (geoip, whois, dns, reputation, etc.)
    fn enrichment_type(&self) -> &'static str;

    /// Check if this provider can enrich the given IOC type
    fn supports(&self, ioc_type: &IocType) -> bool;

    /// Perform enrichment
    async fn enrich(&self, indicator: &Indicator) -> Result<Option<Value>>;

    /// TTL for cached results in hours
    fn ttl_hours(&self) -> i64 {
        24
    }
}

/// Enrichment engine that coordinates multiple providers
pub struct EnrichmentEngine {
    providers: Vec<Box<dyn EnrichmentProvider>>,
}

impl EnrichmentEngine {
    pub fn new() -> Self {
        Self { providers: vec![] }
    }

    pub fn add_provider(&mut self, provider: Box<dyn EnrichmentProvider>) {
        self.providers.push(provider);
    }

    /// Enrich an indicator with all applicable providers
    pub async fn enrich_all(&self, indicator: &Indicator) -> Vec<(String, String, Value, i64)> {
        let mut results = vec![];

        for provider in &self.providers {
            if !provider.supports(&indicator.ioc_type) {
                continue;
            }

            match provider.enrich(indicator).await {
                Ok(Some(data)) => {
                    results.push((
                        provider.enrichment_type().to_string(),
                        provider.name().to_string(),
                        data,
                        provider.ttl_hours(),
                    ));
                }
                Ok(None) => {
                    tracing::debug!(
                        provider = provider.name(),
                        indicator = %indicator.value,
                        "No enrichment data returned"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        provider = provider.name(),
                        indicator = %indicator.value,
                        error = %e,
                        "Enrichment failed"
                    );
                }
            }
        }

        results
    }
}

impl Default for EnrichmentEngine {
    fn default() -> Self {
        Self::new()
    }
}
