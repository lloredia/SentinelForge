//! VirusTotal enrichment provider

use std::net::IpAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::http_util::{external_client, redact};

use crate::enrichment::EnrichmentProvider;
use crate::models::{Indicator, IocType};

const VT_API_URL: &str = "https://www.virustotal.com/api/v3";

/// VirusTotal analysis stats
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct VtAnalysisStats {
    malicious: i32,
    suspicious: i32,
    harmless: i32,
    undetected: i32,
    timeout: Option<i32>,
}

/// VirusTotal attributes
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct VtAttributes {
    last_analysis_stats: Option<VtAnalysisStats>,
    last_analysis_date: Option<i64>,
    reputation: Option<i32>,
    total_votes: Option<VtVotes>,
    tags: Option<Vec<String>>,
    // IP specific
    country: Option<String>,
    continent: Option<String>,
    asn: Option<i32>,
    as_owner: Option<String>,
    // Domain specific
    registrar: Option<String>,
    creation_date: Option<i64>,
    // Hash specific
    meaningful_name: Option<String>,
    type_description: Option<String>,
    size: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct VtVotes {
    harmless: i32,
    malicious: i32,
}

#[derive(Debug, Deserialize)]
struct VtData {
    attributes: VtAttributes,
}

#[derive(Debug, Deserialize)]
struct VtResponse {
    data: VtData,
}

/// VirusTotal enrichment provider
pub struct VirusTotalProvider {
    client: Client,
    api_key: String,
}

impl VirusTotalProvider {
    /// Create a new VirusTotal provider
    pub fn new(api_key: String) -> Result<Self> {
        let client = external_client(Duration::from_secs(10))?;
        Ok(Self { client, api_key })
    }

    /// Check an IP address
    pub async fn check_ip(&self, ip: &str) -> Result<Value> {
        let ip: IpAddr = ip.parse().context("invalid ip for VirusTotal lookup")?;
        self.fetch(&format!("{VT_API_URL}/ip_addresses/{ip}")).await
    }

    /// Check a domain
    pub async fn check_domain(&self, domain: &str) -> Result<Value> {
        if !is_safe_path_token(domain) {
            anyhow::bail!("invalid domain for VirusTotal lookup");
        }
        self.fetch(&format!("{VT_API_URL}/domains/{domain}")).await
    }

    /// Check a file hash
    pub async fn check_hash(&self, hash: &str) -> Result<Value> {
        if !is_safe_path_token(hash) {
            anyhow::bail!("invalid hash for VirusTotal lookup");
        }
        self.fetch(&format!("{VT_API_URL}/files/{hash}")).await
    }

    /// Check a URL (URL must be base64 encoded without padding)
    pub async fn check_url(&self, url: &str) -> Result<Value> {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let url_id = URL_SAFE_NO_PAD.encode(url);
        self.fetch(&format!("{}/urls/{}", VT_API_URL, url_id)).await
    }

    async fn fetch(&self, url: &str) -> Result<Value> {
        let response = self
            .client
            .get(url)
            .header("x-apikey", &self.api_key)
            .send()
            .await
            .context("Failed to send request to VirusTotal")?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(json!({ "found": false }));
        }

        if !response.status().is_success() {
            anyhow::bail!("VirusTotal API error: status {}", response.status());
        }

        let data: VtResponse = response
            .json()
            .await
            .context("Failed to parse VirusTotal response")?;

        let attrs = &data.data.attributes;

        let mut result = json!({
            "found": true,
            "reputation": attrs.reputation,
            "tags": attrs.tags,
        });

        if let Some(stats) = &attrs.last_analysis_stats {
            result["analysis"] = json!({
                "malicious": stats.malicious,
                "suspicious": stats.suspicious,
                "harmless": stats.harmless,
                "undetected": stats.undetected,
                "detection_ratio": format!("{}/{}",
                    stats.malicious + stats.suspicious,
                    stats.malicious + stats.suspicious + stats.harmless + stats.undetected
                ),
            });
        }

        if let Some(votes) = &attrs.total_votes {
            result["votes"] = json!({
                "harmless": votes.harmless,
                "malicious": votes.malicious,
            });
        }

        // IP specific
        if let Some(country) = &attrs.country {
            result["country"] = json!(country);
        }
        if let Some(asn) = attrs.asn {
            result["asn"] = json!(asn);
        }
        if let Some(as_owner) = &attrs.as_owner {
            result["as_owner"] = json!(as_owner);
        }

        // Domain specific
        if let Some(registrar) = &attrs.registrar {
            result["registrar"] = json!(registrar);
        }

        // Hash specific
        if let Some(name) = &attrs.meaningful_name {
            result["meaningful_name"] = json!(name);
        }
        if let Some(type_desc) = &attrs.type_description {
            result["type_description"] = json!(type_desc);
        }
        if let Some(size) = attrs.size {
            result["size"] = json!(size);
        }

        Ok(result)
    }
}

#[async_trait]
impl EnrichmentProvider for VirusTotalProvider {
    fn name(&self) -> &'static str {
        "virustotal"
    }

    fn enrichment_type(&self) -> &'static str {
        "reputation"
    }

    fn supports(&self, ioc_type: &IocType) -> bool {
        matches!(
            ioc_type,
            IocType::Ip | IocType::Domain | IocType::Hash | IocType::Url
        )
    }

    async fn enrich(&self, indicator: &Indicator) -> Result<Option<Value>> {
        let fetched = match indicator.ioc_type {
            IocType::Ip => self.check_ip(&indicator.value).await,
            IocType::Domain => self.check_domain(&indicator.value).await,
            IocType::Hash => self.check_hash(&indicator.value).await,
            IocType::Url => self.check_url(&indicator.value).await,
            IocType::Email | IocType::Cve => return Ok(None),
        };
        let result =
            fetched.map_err(|err| anyhow::anyhow!(redact(&err.to_string(), &[&self.api_key])))?;

        // Check if we got meaningful data
        if result.get("found") == Some(&json!(false)) {
            return Ok(None);
        }

        Ok(Some(result))
    }

    fn ttl_hours(&self) -> i64 {
        12 // Check reputation frequently
    }
}

fn is_safe_path_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}
