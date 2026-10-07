//! WHOIS enrichment provider

use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::{Value, json};

use crate::enrichment::EnrichmentProvider;
use crate::models::ioc_utils::validate_ioc_value;
use crate::models::{Indicator, IocType, WhoisData};

/// WHOIS enrichment provider
pub struct WhoisProvider {
    // Could add configuration here for custom WHOIS servers
}

impl WhoisProvider {
    /// Create a new WHOIS provider
    pub fn new() -> Self {
        Self {}
    }

    /// Perform WHOIS lookup for a domain.
    ///
    /// The query is sent only to a fixed server for the TLD. Referral servers
    /// in the response are not contacted.
    pub async fn lookup(&self, domain: &str) -> Result<WhoisData> {
        validate_ioc_value(domain, Some(&IocType::Domain)).map_err(|msg| anyhow::anyhow!(msg))?;
        let host = whois_host(domain);
        let raw = query_whois(host, domain).await?;
        Ok(parse_whois_response(&raw))
    }
}

fn whois_host(domain: &str) -> &'static str {
    match domain.rsplit('.').next().unwrap_or("") {
        "com" | "net" => "whois.verisign-grs.com",
        "org" => "whois.pir.org",
        "io" => "whois.nic.io",
        "app" | "dev" => "whois.nic.google",
        "uk" => "whois.nic.uk",
        _ => "whois.iana.org",
    }
}

async fn query_whois(host: &str, domain: &str) -> Result<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::time::timeout(
        Duration::from_secs(8),
        tokio::net::TcpStream::connect((host, 43)),
    )
    .await
    .context("WHOIS connect timed out")?
    .with_context(|| format!("WHOIS connect to {host} failed"))?;

    tokio::time::timeout(
        Duration::from_secs(8),
        stream.write_all(format!("{domain}\r\n").as_bytes()),
    )
    .await
    .context("WHOIS write timed out")?
    .context("WHOIS write failed")?;

    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(8), stream.read_to_end(&mut buf))
        .await
        .context("WHOIS read timed out")?
        .context("WHOIS read failed")?;
    buf.truncate(256 * 1024);
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

impl Default for WhoisProvider {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse raw WHOIS response into structured data
fn parse_whois_response(raw: &str) -> WhoisData {
    let mut data = WhoisData {
        raw: Some(raw.to_string()),
        ..Default::default()
    };

    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('%') || line.starts_with('#') {
            continue;
        }

        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim().to_lowercase();
            let value = value.trim();

            if value.is_empty() {
                continue;
            }

            match key.as_str() {
                "registrar" | "registrar name" => {
                    if data.registrar.is_none() {
                        data.registrar = Some(value.to_string());
                    }
                }
                "registrant" | "registrant name" => {
                    data.registrant = Some(value.to_string());
                }
                "registrant organization" | "registrant org" => {
                    data.registrant_org = Some(value.to_string());
                }
                "registrant country" => {
                    data.registrant_country = Some(value.to_string());
                }
                "creation date" | "created" | "created date" | "registration date" => {
                    // Parse date - simplified, just store as string for now
                    // In production, use chrono to parse various date formats
                }
                "expiration date" | "expires" | "expiry date" | "registry expiry date" => {
                    // Parse date
                }
                "name server" | "nserver" => {
                    data.name_servers.push(value.to_lowercase());
                }
                "status" | "domain status" => {
                    data.status.push(value.to_string());
                }
                _ => {}
            }
        }
    }

    data
}

#[async_trait]
impl EnrichmentProvider for WhoisProvider {
    fn name(&self) -> &'static str {
        "whois"
    }

    fn enrichment_type(&self) -> &'static str {
        "whois"
    }

    fn supports(&self, ioc_type: &IocType) -> bool {
        matches!(ioc_type, IocType::Domain)
    }

    async fn enrich(&self, indicator: &Indicator) -> Result<Option<Value>> {
        let data = self.lookup(&indicator.value).await?;

        // Only return if we got some meaningful data
        if data.registrar.is_none() && data.name_servers.is_empty() {
            return Ok(None);
        }

        Ok(Some(json!({
            "registrar": data.registrar,
            "registrant": data.registrant,
            "registrant_org": data.registrant_org,
            "registrant_country": data.registrant_country,
            "name_servers": data.name_servers,
            "status": data.status,
        })))
    }

    fn ttl_hours(&self) -> i64 {
        168 // 1 week - WHOIS data changes infrequently
    }
}
