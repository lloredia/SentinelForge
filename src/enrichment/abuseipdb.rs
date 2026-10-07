//! AbuseIPDB enrichment provider

use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::http_util::{external_client, redact};

use crate::enrichment::EnrichmentProvider;
use crate::models::{Indicator, IocType};

const ABUSEIPDB_API_URL: &str = "https://api.abuseipdb.com/api/v2";

/// AbuseIPDB API response
#[derive(Debug, Deserialize)]
struct AbuseIpDbResponse {
    data: AbuseIpDbData,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AbuseIpDbData {
    ip_address: String,
    is_public: bool,
    ip_version: i32,
    is_whitelisted: Option<bool>,
    abuse_confidence_score: i32,
    country_code: Option<String>,
    usage_type: Option<String>,
    isp: Option<String>,
    domain: Option<String>,
    hostnames: Vec<String>,
    total_reports: i32,
    num_distinct_users: i32,
    last_reported_at: Option<String>,
}

/// AbuseIPDB enrichment provider
pub struct AbuseIpDbProvider {
    client: Client,
    api_key: String,
}

impl AbuseIpDbProvider {
    /// Create a new AbuseIPDB provider
    pub fn new(api_key: String) -> Result<Self> {
        let client = external_client(Duration::from_secs(10))?;
        Ok(Self { client, api_key })
    }

    /// Check an IP address against AbuseIPDB
    pub(crate) async fn check_ip(&self, ip: &str) -> Result<AbuseIpDbData> {
        let response = self
            .client
            .get(format!("{}/check", ABUSEIPDB_API_URL))
            .header("Key", &self.api_key)
            .header("Accept", "application/json")
            .query(&[
                ("ipAddress", ip),
                ("maxAgeInDays", "90"),
                ("verbose", "true"),
            ])
            .send()
            .await
            .context("Failed to send request to AbuseIPDB")?;

        if !response.status().is_success() {
            anyhow::bail!("AbuseIPDB API error: status {}", response.status());
        }

        let data: AbuseIpDbResponse = response
            .json()
            .await
            .context("Failed to parse AbuseIPDB response")?;

        Ok(data.data)
    }

    /// Report an IP to AbuseIPDB
    pub async fn report_ip(
        &self,
        ip: &str,
        categories: &[i32],
        comment: Option<&str>,
    ) -> Result<()> {
        let categories_str = categories
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(",");

        let mut form = vec![("ip", ip.to_string()), ("categories", categories_str)];

        if let Some(c) = comment {
            form.push(("comment", c.to_string()));
        }

        let response = self
            .client
            .post(format!("{}/report", ABUSEIPDB_API_URL))
            .header("Key", &self.api_key)
            .header("Accept", "application/json")
            .form(&form)
            .send()
            .await
            .context("Failed to report IP to AbuseIPDB")?;

        if !response.status().is_success() {
            anyhow::bail!("AbuseIPDB report error: status {}", response.status());
        }

        Ok(())
    }
}

#[async_trait]
impl EnrichmentProvider for AbuseIpDbProvider {
    fn name(&self) -> &'static str {
        "abuseipdb"
    }

    fn enrichment_type(&self) -> &'static str {
        "reputation"
    }

    fn supports(&self, ioc_type: &IocType) -> bool {
        matches!(ioc_type, IocType::Ip)
    }

    async fn enrich(&self, indicator: &Indicator) -> Result<Option<Value>> {
        let data = self
            .check_ip(&indicator.value)
            .await
            .map_err(|err| anyhow::anyhow!(redact(&err.to_string(), &[&self.api_key])))?;

        Ok(Some(json!({
            "abuse_confidence_score": data.abuse_confidence_score,
            "country_code": data.country_code,
            "usage_type": data.usage_type,
            "isp": data.isp,
            "domain": data.domain,
            "hostnames": data.hostnames,
            "total_reports": data.total_reports,
            "num_distinct_users": data.num_distinct_users,
            "last_reported_at": data.last_reported_at,
            "is_whitelisted": data.is_whitelisted,
        })))
    }

    fn ttl_hours(&self) -> i64 {
        12 // Check reputation more frequently
    }
}

/// AbuseIPDB attack categories
pub mod categories {
    pub const DNS_COMPROMISE: i32 = 1;
    pub const DNS_POISONING: i32 = 2;
    pub const FRAUD_ORDERS: i32 = 3;
    pub const DDOS_ATTACK: i32 = 4;
    pub const FTP_BRUTE_FORCE: i32 = 5;
    pub const PING_OF_DEATH: i32 = 6;
    pub const PHISHING: i32 = 7;
    pub const FRAUD_VOIP: i32 = 8;
    pub const OPEN_PROXY: i32 = 9;
    pub const WEB_SPAM: i32 = 10;
    pub const EMAIL_SPAM: i32 = 11;
    pub const BLOG_SPAM: i32 = 12;
    pub const VPN_IP: i32 = 13;
    pub const PORT_SCAN: i32 = 14;
    pub const HACKING: i32 = 15;
    pub const SQL_INJECTION: i32 = 16;
    pub const SPOOFING: i32 = 17;
    pub const BRUTE_FORCE: i32 = 18;
    pub const BAD_WEB_BOT: i32 = 19;
    pub const EXPLOITED_HOST: i32 = 20;
    pub const WEB_APP_ATTACK: i32 = 21;
    pub const SSH: i32 = 22;
    pub const IOT_TARGETED: i32 = 23;
}
