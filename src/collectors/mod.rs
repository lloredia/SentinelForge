//! Threat intelligence feed collectors

pub mod alienvault;
pub mod emerging_threats;
pub mod honeytrap;

use anyhow::Result;
use async_trait::async_trait;

use crate::models::CreateIndicatorRequest;

/// Trait for feed collectors
#[allow(clippy::double_must_use)]
#[async_trait]
pub trait FeedCollector: Send + Sync {
    /// Feed name
    fn name(&self) -> &'static str;

    /// Fetch indicators from the feed
    async fn fetch(&self) -> Result<Vec<CreateIndicatorRequest>>;

    /// Check if API key is configured (for feeds that require it)
    fn is_configured(&self) -> bool {
        true
    }
}

/// Feed collection result
pub struct FeedResult {
    pub source: String,
    pub indicators: Vec<CreateIndicatorRequest>,
    pub errors: Vec<String>,
}
