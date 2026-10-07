//! HoneyTrap honeypot feed collector
//! Reads IOCs captured by our honeypot network

use anyhow::{Context, Result};
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;

use crate::collectors::FeedCollector;
use crate::http_util::{external_client, validate_collector_url};
use crate::models::{CreateIndicatorRequest, IocType, Severity, Tlp};

/// HoneyTrap event from the honeypot
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct HoneytrapEvent {
    session_id: String,
    protocol: String,
    category: String,
    severity: String,
    source: HoneytrapSource,
    credentials: Option<HoneytrapCredentials>,
    command: Option<HoneytrapCommand>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct HoneytrapSource {
    ip: String,
    port: u16,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct HoneytrapCredentials {
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct HoneytrapCommand {
    command: String,
}

/// Collector for HoneyTrap events
pub struct HoneytrapCollector {
    client: Client,
    api_url: String,
    api_key: Option<String>,
    allow_private: bool,
}

impl HoneytrapCollector {
    /// Create a new HoneyTrap collector.
    ///
    /// `allow_private` permits loopback and RFC1918 hosts (typical for a local
    /// honeypot). Link-local and cloud metadata addresses are always rejected.
    pub fn new(api_url: String, api_key: Option<String>, allow_private: bool) -> Result<Self> {
        let client = external_client(Duration::from_secs(10))?;
        Ok(Self {
            client,
            api_url,
            api_key,
            allow_private,
        })
    }

    /// Parse events file directly (for local deployment)
    pub async fn parse_events_file(path: &str) -> Result<Vec<CreateIndicatorRequest>> {
        let content = tokio::fs::read_to_string(path)
            .await
            .context("Failed to read events file")?;

        let mut indicators = vec![];
        let mut seen_ips = std::collections::HashSet::new();

        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }

            if let Ok(event) = serde_json::from_str::<HoneytrapEvent>(line) {
                // Deduplicate IPs
                if seen_ips.contains(&event.source.ip) {
                    continue;
                }
                seen_ips.insert(event.source.ip.clone());

                // Create indicator from attacker IP
                let mut tags = vec![
                    format!("honeypot:{}", event.protocol),
                    format!("category:{}", event.category),
                ];

                // Add credential-based tags
                if let Some(ref creds) = event.credentials {
                    tags.push("has_credentials".to_string());
                    if creds.username == "root" || creds.username == "admin" {
                        tags.push("targets_admin".to_string());
                    }
                }

                // Add command-based tags
                if let Some(ref cmd) = event.command {
                    tags.push("executed_commands".to_string());

                    // Detect suspicious commands
                    let cmd_lower = cmd.command.to_lowercase();
                    if cmd_lower.contains("wget") || cmd_lower.contains("curl") {
                        tags.push("download_attempt".to_string());
                    }
                    if cmd_lower.contains("chmod") && cmd_lower.contains("+x") {
                        tags.push("made_executable".to_string());
                    }
                    if cmd_lower.contains("/etc/passwd") || cmd_lower.contains("/etc/shadow") {
                        tags.push("credential_access".to_string());
                    }
                }

                let severity = match event.severity.as_str() {
                    "critical" => Severity::Critical,
                    "high" => Severity::High,
                    "medium" => Severity::Medium,
                    "low" => Severity::Low,
                    _ => Severity::Medium,
                };

                indicators.push(CreateIndicatorRequest {
                    value: event.source.ip,
                    ioc_type: Some(IocType::Ip),
                    severity: Some(severity),
                    confidence: Some(90), // High confidence - we observed it directly
                    tlp: Some(Tlp::Green),
                    tags: Some(tags),
                    source: Some("honeytrap".to_string()),
                    expiration_days: Some(30), // Keep for 30 days
                });
            }
        }

        Ok(indicators)
    }
}

#[async_trait]
impl FeedCollector for HoneytrapCollector {
    fn name(&self) -> &'static str {
        "honeytrap"
    }

    async fn fetch(&self) -> Result<Vec<CreateIndicatorRequest>> {
        if !self.api_url.is_empty() {
            let base = validate_collector_url(&self.api_url, self.allow_private)
                .await
                .map_err(|err| anyhow::anyhow!("refusing HoneyTrap URL: {err}"))?;
            let mut endpoint = base;
            endpoint.set_path("/api/events");
            endpoint.set_query(None);
            endpoint.set_fragment(None);

            let mut request = self.client.get(endpoint);
            if let Some(ref key) = self.api_key {
                request = request.header("Authorization", format!("Bearer {key}"));
            }

            let response = request
                .send()
                .await
                .context("Failed to fetch from HoneyTrap API")?;

            if !response.status().is_success() {
                anyhow::bail!("HoneyTrap API error: status {}", response.status());
            }

            let events: Vec<HoneytrapEvent> = response
                .json()
                .await
                .context("Failed to parse HoneyTrap response")?;

            let mut indicators = vec![];
            for event in events {
                indicators.push(CreateIndicatorRequest {
                    value: event.source.ip,
                    ioc_type: Some(IocType::Ip),
                    severity: Some(Severity::High),
                    confidence: Some(90),
                    tlp: Some(Tlp::Green),
                    tags: Some(vec![
                        format!("honeypot:{}", event.protocol),
                        format!("category:{}", event.category),
                    ]),
                    source: Some("honeytrap".to_string()),
                    expiration_days: Some(30),
                });
            }

            return Ok(indicators);
        }

        // Fallback to local file
        Self::parse_events_file("./events.jsonl").await
    }

    fn is_configured(&self) -> bool {
        true // HoneyTrap is always available locally
    }
}
