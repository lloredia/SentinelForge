//! Emerging Threats feed collector (free rules feed)

use anyhow::{Context, Result};
use async_trait::async_trait;
use reqwest::Client;
use std::time::Duration;

use crate::collectors::FeedCollector;
use crate::http_util::{assert_allowlisted_feed, external_client};
use crate::models::{CreateIndicatorRequest, IocType, Severity, Tlp};

const ALLOWED_FEED_HOSTS: &[&str] = &[
    "rules.emergingthreats.net",
    "feodotracker.abuse.ch",
    "urlhaus.abuse.ch",
];

const ET_COMPROMISED_IPS: &str = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt";
const FEODO_TRACKER_IPS: &str = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt";
const URLHAUS_URLS: &str = "https://urlhaus.abuse.ch/downloads/text_online/";

pub struct EmergingThreatsCollector {
    client: Client,
}

impl EmergingThreatsCollector {
    pub fn new() -> Result<Self> {
        let client = external_client(Duration::from_secs(20))?;
        Ok(Self { client })
    }

    async fn fetch_ip_list(
        &self,
        url: &str,
        source: &str,
        tags: Vec<String>,
    ) -> Result<Vec<CreateIndicatorRequest>> {
        let url =
            assert_allowlisted_feed(url, ALLOWED_FEED_HOSTS).map_err(|err| anyhow::anyhow!(err))?;
        let response = self
            .client
            .get(url)
            .send()
            .await
            .context("Failed to fetch feed")?;
        if !response.status().is_success() {
            anyhow::bail!("failed to fetch feed: status {}", response.status());
        }

        let text = response.text().await?;
        let mut indicators = vec![];

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let ip = line.split_whitespace().next().unwrap_or(line);
            if ip.parse::<std::net::Ipv4Addr>().is_ok() {
                indicators.push(CreateIndicatorRequest {
                    value: ip.to_string(),
                    ioc_type: Some(IocType::Ip),
                    severity: Some(Severity::High),
                    confidence: Some(80),
                    tlp: Some(Tlp::White),
                    tags: Some(tags.clone()),
                    source: Some(source.to_string()),
                    expiration_days: Some(30),
                });
            }
        }
        Ok(indicators)
    }

    async fn fetch_url_list(
        &self,
        url: &str,
        source: &str,
        tags: Vec<String>,
    ) -> Result<Vec<CreateIndicatorRequest>> {
        let url =
            assert_allowlisted_feed(url, ALLOWED_FEED_HOSTS).map_err(|err| anyhow::anyhow!(err))?;
        let response = self
            .client
            .get(url)
            .send()
            .await
            .context("Failed to fetch feed")?;
        if !response.status().is_success() {
            anyhow::bail!("failed to fetch feed: status {}", response.status());
        }
        let text = response.text().await?;
        let mut indicators = vec![];
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if crate::models::ioc_utils::validate_ioc_value(line, Some(&IocType::Url)).is_err() {
                continue;
            }
            indicators.push(CreateIndicatorRequest {
                value: line.to_string(),
                ioc_type: Some(IocType::Url),
                severity: Some(Severity::High),
                confidence: Some(75),
                tlp: Some(Tlp::White),
                tags: Some(tags.clone()),
                source: Some(source.to_string()),
                expiration_days: Some(14),
            });
        }
        Ok(indicators)
    }
}

impl Default for EmergingThreatsCollector {
    fn default() -> Self {
        Self::new().expect("HTTP client")
    }
}

#[async_trait]
impl FeedCollector for EmergingThreatsCollector {
    fn name(&self) -> &'static str {
        "emerging_threats"
    }

    async fn fetch(&self) -> Result<Vec<CreateIndicatorRequest>> {
        let mut all_indicators = vec![];

        // Fetch compromised IPs
        if let Ok(indicators) = self
            .fetch_ip_list(
                ET_COMPROMISED_IPS,
                "emerging_threats",
                vec!["compromised".to_string(), "et_rules".to_string()],
            )
            .await
        {
            all_indicators.extend(indicators);
        }

        // Fetch Feodo Tracker (banking trojans)
        if let Ok(indicators) = self
            .fetch_ip_list(
                FEODO_TRACKER_IPS,
                "feodo_tracker",
                vec!["botnet".to_string(), "banking_trojan".to_string()],
            )
            .await
        {
            all_indicators.extend(indicators);
        }

        if let Ok(indicators) = self
            .fetch_url_list(
                URLHAUS_URLS,
                "urlhaus",
                vec!["malware".to_string(), "urlhaus".to_string()],
            )
            .await
        {
            all_indicators.extend(indicators);
        }

        Ok(all_indicators)
    }
}
