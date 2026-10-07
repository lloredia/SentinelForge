//! Shared HTTP helpers: outbound URL policy, client timeouts, and secret redaction.

use anyhow::{Context, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use url::Url;

/// Build an HTTP client that times out and does not follow redirects.
pub fn external_client(timeout: Duration) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("sentinelforge/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("failed to build HTTP client")
}

/// Remove known secrets from a message before it is logged.
pub fn redact(message: &str, secrets: &[&str]) -> String {
    let mut out = message.to_string();
    for secret in secrets {
        if secret.len() >= 8 {
            out = out.replace(secret, "[redacted]");
        }
    }
    out
}

/// Validate a collector base URL before SentinelForge connects to it.
///
/// Link-local and metadata addresses are always rejected. Loopback, RFC1918,
/// and carrier-grade NAT addresses are rejected unless `allow_private` is set.
pub async fn validate_collector_url(raw: &str, allow_private: bool) -> Result<Url, String> {
    let parsed = Url::parse(raw.trim()).map_err(|_| "invalid URL".to_string())?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err("URL scheme must be http or https".into());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("URL must not include credentials".into());
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "URL must include a host".to_string())?;
    if is_metadata_name(host) {
        return Err("metadata endpoints are blocked".into());
    }
    if is_localhost_name(host) && !allow_private {
        return Err("private hosts are blocked".into());
    }

    match parsed.host() {
        Some(url::Host::Ipv4(ip)) => check_ip(IpAddr::V4(ip), allow_private)?,
        Some(url::Host::Ipv6(ip)) => check_ip(IpAddr::V6(ip), allow_private)?,
        Some(url::Host::Domain(domain)) => {
            let port = parsed.port_or_known_default().unwrap_or(80);
            let addrs = tokio::net::lookup_host((domain, port))
                .await
                .map_err(|_| format!("failed to resolve {domain}"))?;
            let mut saw = false;
            for addr in addrs {
                saw = true;
                check_ip(addr.ip(), allow_private)?;
            }
            if !saw {
                return Err(format!("host {domain} did not resolve"));
            }
        }
        None => return Err("URL must include a host".into()),
    }

    Ok(parsed)
}

/// HTTPS feed URLs SentinelForge is willing to download.
pub fn assert_allowlisted_feed(raw: &str, allowed_hosts: &[&str]) -> Result<Url, String> {
    let parsed = Url::parse(raw).map_err(|_| "invalid feed URL".to_string())?;
    if parsed.scheme() != "https" {
        return Err("feed URL must use https".into());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("feed URL must not include credentials".into());
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "feed URL must include a host".to_string())?;
    if !allowed_hosts
        .iter()
        .any(|allowed| host.eq_ignore_ascii_case(allowed))
    {
        return Err(format!("feed host {host} is not allowlisted"));
    }
    Ok(parsed)
}

fn is_metadata_name(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host == "metadata.google.internal" || host == "metadata.internal"
}

fn is_localhost_name(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host == "localhost" || host.ends_with(".localhost")
}

fn check_ip(ip: IpAddr, allow_private: bool) -> Result<(), String> {
    if is_blocked(ip) {
        return Err(format!("address {ip} is blocked"));
    }
    if !allow_private && is_private(ip) {
        return Err(format!("private address {ip} is blocked"));
    }
    Ok(())
}

fn is_blocked(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_unspecified()
                || ip.is_broadcast()
                || ip.is_multicast()
                || ip.is_link_local()
                || ip == Ipv4Addr::new(255, 255, 255, 255)
        }
        IpAddr::V6(ip) => {
            if let Some(v4) = ip.to_ipv4_mapped() {
                return is_blocked(IpAddr::V4(v4));
            }
            ip.is_unspecified() || ip.is_multicast() || is_ipv6_link_local(&ip)
        }
    }
}

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_loopback() || ip.is_private() || is_cgnat(ip),
        IpAddr::V6(ip) => {
            if let Some(v4) = ip.to_ipv4_mapped() {
                return is_private(IpAddr::V4(v4));
            }
            ip.is_loopback() || is_unique_local(&ip)
        }
    }
}

fn is_cgnat(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

fn is_ipv6_link_local(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

fn is_unique_local(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn blocks_metadata_and_non_http_urls() {
        let metadata =
            validate_collector_url("http://169.254.169.254/latest/meta-data", true).await;
        assert!(metadata.is_err());
        let file = validate_collector_url("file:///etc/passwd", true).await;
        assert!(file.is_err());
        let creds = validate_collector_url("http://user:pass@127.0.0.1:9100", true).await;
        assert!(creds.is_err());
        let name = validate_collector_url("http://metadata.google.internal/", true).await;
        assert!(name.is_err());
    }

    #[tokio::test]
    async fn private_hosts_follow_the_allow_flag() {
        let denied = validate_collector_url("http://127.0.0.1:9100/api", false).await;
        assert!(denied.is_err());
        let allowed = validate_collector_url("http://127.0.0.1:9100/api", true).await;
        assert!(allowed.is_ok());
        let rfc1918 = validate_collector_url("http://10.1.2.3:9100", false).await;
        assert!(rfc1918.is_err());
    }

    #[test]
    fn feed_allowlist_rejects_other_hosts() {
        let ok = assert_allowlisted_feed(
            "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
            &["rules.emergingthreats.net"],
        );
        assert!(ok.is_ok());
        let bad = assert_allowlisted_feed(
            "https://evil.example/blockrules/compromised-ips.txt",
            &["rules.emergingthreats.net"],
        );
        assert!(bad.is_err());
        let http = assert_allowlisted_feed(
            "http://rules.emergingthreats.net/blockrules/compromised-ips.txt",
            &["rules.emergingthreats.net"],
        );
        assert!(http.is_err());
    }

    #[test]
    fn redacts_secrets_and_ignores_short_tokens() {
        let message = "status 401 key=super-secret-value";
        let redacted = redact(message, &["super-secret-value", "short"]);
        assert_eq!(redacted, "status 401 key=[redacted]");
        assert!(!redacted.contains("super-secret-value"));
    }
}
