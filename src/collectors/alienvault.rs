//! AlienVault OTX feed collector

use std::time::Duration;

use crate::collectors::FeedCollector;
use crate::http_util::{external_client, redact};
use crate::models::{CreateIndicatorRequest, IocType, Severity, Tlp};
use anyhow::{Context, Result};
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;

const OTX_API_URL: &str = "https://otx.alienvault.com/api/v1";

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct OtxPulseResponse {
    results: Vec<OtxPulse>,
    next: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct OtxPulse {
    id: String,
    name: String,
    description: Option<String>,
    tags: Vec<String>,
    indicators: Vec<OtxIndicator>,
    tlp: Option<String>,
    adversary: Option<String>,
    malware_families: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct OtxIndicator {
    indicator: String,
    #[serde(rename = "type")]
    indicator_type: String,
    description: Option<String>,
}

/// AlienVault OTX feed collector
pub struct AlienVaultCollector {
    client: Client,
    api_key: String,
}

impl AlienVaultCollector {
    /// Create a new AlienVault OTX collector
    pub fn new(api_key: String) -> Result<Self> {
        let client = external_client(Duration::from_secs(15))?;
        Ok(Self { client, api_key })
    }

    /// Fetch subscribed pulses
    async fn fetch_subscribed_pulses(&self) -> Result<Vec<OtxPulse>> {
        let response = self
            .client
            .get(format!("{}/pulses/subscribed", OTX_API_URL))
            .header("X-OTX-API-KEY", &self.api_key)
            .query(&[("limit", "50"), ("modified_since", "7d")])
            .send()
            .await
            .context("Failed to fetch OTX pulses")?;

        if !response.status().is_success() {
            anyhow::bail!("OTX API error: status {}", response.status());
        }

        let data: OtxPulseResponse = response
            .json()
            .await
            .context("Failed to parse OTX response")?;

        Ok(data.results)
    }

    /// Convert OTX indicator type to our IocType
    fn convert_type(otx_type: &str) -> Option<IocType> {
        match otx_type {
            "IPv4" | "IPv6" => Some(IocType::Ip),
            "domain" | "hostname" => Some(IocType::Domain),
            "URL" | "URI" => Some(IocType::Url),
            "FileHash-MD5" | "FileHash-SHA1" | "FileHash-SHA256" => Some(IocType::Hash),
            "email" => Some(IocType::Email),
            "CVE" => Some(IocType::Cve),
            _ => None,
        }
    }

    /// Convert OTX TLP to our TLP
    fn convert_tlp(otx_tlp: Option<&str>) -> Tlp {
        match otx_tlp {
            Some("white") => Tlp::White,
            Some("green") => Tlp::Green,
            Some("amber") => Tlp::Amber,
            Some("red") => Tlp::Red,
            _ => Tlp::Amber,
        }
    }
}

#[async_trait]
impl FeedCollector for AlienVaultCollector {
    fn name(&self) -> &'static str {
        "alienvault_otx"
    }

    async fn fetch(&self) -> Result<Vec<CreateIndicatorRequest>> {
        let pulses = self
            .fetch_subscribed_pulses()
            .await
            .map_err(|err| anyhow::anyhow!(redact(&err.to_string(), &[&self.api_key])))?;
        let mut indicators = vec![];

        for pulse in pulses {
            let tlp = Self::convert_tlp(pulse.tlp.as_deref());

            let mut base_tags: Vec<String> = pulse.tags.clone();
            base_tags.push(format!("pulse:{}", pulse.id));

            if let Some(ref adversary) = pulse.adversary {
                base_tags.push(format!("adversary:{}", adversary));
            }

            for malware in &pulse.malware_families {
                base_tags.push(format!("malware:{}", malware));
            }

            for indicator in pulse.indicators {
                if let Some(ioc_type) = Self::convert_type(&indicator.indicator_type) {
                    let mut tags = base_tags.clone();
                    tags.push(format!("otx_type:{}", indicator.indicator_type));

                    indicators.push(CreateIndicatorRequest {
                        value: indicator.indicator,
                        ioc_type: Some(ioc_type),
                        severity: Some(Severity::Medium),
                        confidence: Some(70),
                        tlp: Some(tlp.clone()),
                        tags: Some(tags),
                        source: Some("alienvault_otx".to_string()),
                        expiration_days: Some(90),
                    });
                }
            }
        }

        Ok(indicators)
    }

    fn is_configured(&self) -> bool {
        !self.api_key.is_empty()
    }
}
