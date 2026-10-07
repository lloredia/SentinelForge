// src/models/ioc_utils.rs

use crate::models::{CreateIndicatorRequest, IndicatorFilter, IocType};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Caller-supplied input that failed validation.
#[derive(Debug)]
pub struct InputError(pub String);

impl std::fmt::Display for InputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for InputError {}

/// Page bounds plus an escaped `ILIKE` pattern for indicator search.
#[derive(Debug)]
pub struct NormalizedFilter {
    pub page: i64,
    pub per_page: i64,
    pub offset: i64,
    pub search_pattern: Option<String>,
}

pub fn normalize_filter(filter: &IndicatorFilter) -> Result<NormalizedFilter, String> {
    let (page, per_page, offset) = validate_pagination(filter.page, filter.per_page)?;
    if let Some(confidence) = filter.min_confidence
        && !(0..=100).contains(&confidence)
    {
        return Err("min_confidence must be between 0 and 100".into());
    }
    if let Some(score) = filter.min_threat_score
        && !(0..=100).contains(&score)
    {
        return Err("min_threat_score must be between 0 and 100".into());
    }
    if let Some(tags) = &filter.tags {
        validate_tags(tags)?;
    }

    let search_pattern = match filter.search.as_deref() {
        Some(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                None
            } else if trimmed.chars().count() > 200 || trimmed.chars().any(|c| c.is_control()) {
                return Err(
                    "search must be at most 200 characters and contain no control characters"
                        .into(),
                );
            } else {
                Some(format!("%{}%", escape_like(trimmed)))
            }
        }
        None => None,
    };

    Ok(NormalizedFilter {
        page,
        per_page,
        offset,
        search_pattern,
    })
}

pub fn validate_pagination(
    page: Option<i64>,
    per_page: Option<i64>,
) -> Result<(i64, i64, i64), String> {
    let page = page.unwrap_or(1);
    let per_page = per_page.unwrap_or(50);
    if page < 1 {
        return Err("page must be >= 1".into());
    }
    if !(1..=100).contains(&per_page) {
        return Err("per_page must be between 1 and 100".into());
    }
    let offset = (page - 1)
        .checked_mul(per_page)
        .ok_or_else(|| "page is too large".to_string())?;
    Ok((page, per_page, offset))
}

pub fn validate_indicator_request(req: &CreateIndicatorRequest) -> Result<(), String> {
    validate_ioc_value(&req.value, req.ioc_type.as_ref())?;
    if let Some(confidence) = req.confidence
        && !(0..=100).contains(&confidence)
    {
        return Err("confidence must be between 0 and 100".into());
    }
    if let Some(days) = req.expiration_days
        && !(1..=3650).contains(&days)
    {
        return Err("expiration_days must be between 1 and 3650".into());
    }
    if let Some(tags) = &req.tags {
        validate_tags(tags)?;
    }
    if let Some(source) = &req.source {
        validate_label(source, "source")?;
    }
    Ok(())
}

pub fn validate_ioc_value(value: &str, declared: Option<&IocType>) -> Result<IocType, String> {
    if value.trim().is_empty() || value.chars().count() > 2048 {
        return Err("IOC value must be 1-2048 characters".into());
    }
    if value.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("IOC value must not contain whitespace or control characters".into());
    }
    let detected = detect_ioc_type(value.trim());
    let ioc_type = match (declared, detected) {
        (Some(declared), Some(detected)) if declared != &detected => {
            return Err("declared IOC type does not match the value".into());
        }
        (Some(declared), _) => declared.clone(),
        (None, Some(detected)) => detected,
        (None, None) => return Err("could not detect IOC type".into()),
    };
    if !value_matches_type(value.trim(), &ioc_type) {
        return Err(format!("value is not a valid {ioc_type}"));
    }
    Ok(ioc_type)
}

pub fn validate_tags(tags: &[String]) -> Result<(), String> {
    if tags.len() > 32 {
        return Err("at most 32 tags are allowed".into());
    }
    for tag in tags {
        validate_label(tag, "tag")?;
    }
    Ok(())
}

pub fn validate_label(value: &str, field: &str) -> Result<(), String> {
    if value.is_empty() || value.chars().count() > 64 {
        return Err(format!("{field} must be 1-64 characters"));
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | '/'))
    {
        return Err(format!(
            "{field} may contain only letters, numbers, and . _ : / -"
        ));
    }
    Ok(())
}

pub fn escape_like(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn value_matches_type(value: &str, ioc_type: &IocType) -> bool {
    match ioc_type {
        IocType::Ip => valid_ip_or_cidr(value),
        IocType::Domain => valid_domain(value),
        IocType::Url => valid_http_url(value),
        IocType::Hash => valid_hash(value),
        IocType::Email => valid_email(value),
        IocType::Cve => valid_cve(value),
    }
}

fn valid_ip_or_cidr(value: &str) -> bool {
    if let Some((addr, prefix)) = value.split_once('/') {
        let Some(prefix) = prefix.parse::<u8>().ok() else {
            return false;
        };
        return match addr.parse::<IpAddr>() {
            Ok(IpAddr::V4(_)) => prefix <= 32,
            Ok(IpAddr::V6(_)) => prefix <= 128,
            Err(_) => false,
        };
    }
    value.parse::<IpAddr>().is_ok()
}

fn valid_domain(value: &str) -> bool {
    if value.len() > 253 || value.starts_with('.') || value.ends_with('.') || value.contains("..") {
        return false;
    }
    let labels: Vec<&str> = value.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    let labels_ok = labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    });
    labels_ok
        && labels
            .last()
            .is_some_and(|label| label.chars().any(|c| c.is_ascii_alphabetic()))
}

fn valid_http_url(value: &str) -> bool {
    let Ok(parsed) = url::Url::parse(value) else {
        return false;
    };
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return false;
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return false;
    }
    parsed.host_str().is_some()
}

fn valid_hash(value: &str) -> bool {
    matches!(value.len(), 32 | 40 | 64) && value.chars().all(|c| c.is_ascii_hexdigit())
}

fn valid_email(value: &str) -> bool {
    let Some((local, domain)) = value.rsplit_once('@') else {
        return false;
    };
    if local.is_empty() || local.len() > 64 || domain.len() > 253 {
        return false;
    }
    local
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
        && valid_domain(domain)
}

fn valid_cve(value: &str) -> bool {
    let upper = value.to_ascii_uppercase();
    let Some(rest) = upper.strip_prefix("CVE-") else {
        return false;
    };
    let Some((year, id)) = rest.split_once('-') else {
        return false;
    };
    year.len() == 4
        && year.chars().all(|c| c.is_ascii_digit())
        && (4..=7).contains(&id.len())
        && id.chars().all(|c| c.is_ascii_digit())
}

/// Detect the IOC type from a raw value string
pub fn detect_ioc_type(value: &str) -> Option<IocType> {
    let trimmed = value.trim();

    if trimmed.is_empty() {
        return None;
    }

    // CVE pattern (e.g., CVE-2021-44228)
    if trimmed.to_uppercase().starts_with("CVE-") {
        return Some(IocType::Cve);
    }

    // Hash patterns (MD5=32, SHA1=40, SHA256=64 hex chars)
    if (trimmed.len() == 32 || trimmed.len() == 40 || trimmed.len() == 64)
        && trimmed.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Some(IocType::Hash);
    }

    // URL pattern
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return Some(IocType::Url);
    }

    // Email pattern
    if trimmed.contains('@') && trimmed.contains('.') {
        return Some(IocType::Email);
    }

    // IPv4 pattern
    if trimmed.parse::<Ipv4Addr>().is_ok() {
        return Some(IocType::Ip);
    }

    // IPv6 pattern
    if trimmed.parse::<Ipv6Addr>().is_ok() {
        return Some(IocType::Ip);
    }

    // CIDR patterns (treat as IP)
    if trimmed.contains('/') {
        let parts: Vec<&str> = trimmed.split('/').collect();
        if parts.len() == 2
            && (parts[0].parse::<Ipv4Addr>().is_ok() || parts[0].parse::<Ipv6Addr>().is_ok())
        {
            return Some(IocType::Ip);
        }
    }

    // Domain pattern
    if trimmed.contains('.')
        && !trimmed.contains(' ')
        && !trimmed.contains('/')
        && !trimmed.contains('@')
        && trimmed
            .chars()
            .all(|c| c.is_alphanumeric() || c == '.' || c == '-')
    {
        return Some(IocType::Domain);
    }

    None
}

/// Normalize an IOC value based on its type
pub fn normalize_ioc(value: &str, ioc_type: &IocType) -> String {
    let trimmed = value.trim();

    match ioc_type {
        IocType::Domain => trimmed.to_lowercase(),
        IocType::Url => {
            if let Some(idx) = trimmed.find("://") {
                let (scheme, rest) = trimmed.split_at(idx + 3);
                if let Some(path_idx) = rest.find('/') {
                    let (host, path) = rest.split_at(path_idx);
                    format!("{}{}{}", scheme.to_lowercase(), host.to_lowercase(), path)
                } else {
                    trimmed.to_lowercase()
                }
            } else {
                trimmed.to_lowercase()
            }
        }
        IocType::Email => trimmed.to_lowercase(),
        IocType::Ip => trimmed.to_lowercase(),
        IocType::Hash => trimmed.to_lowercase(),
        IocType::Cve => trimmed.to_uppercase(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pagination_rejects_out_of_range_values() {
        assert!(validate_pagination(Some(0), Some(10)).is_err());
        assert!(validate_pagination(Some(1), Some(0)).is_err());
        assert!(validate_pagination(Some(1), Some(101)).is_err());
        assert!(validate_pagination(Some(i64::MAX), Some(100)).is_err());
        assert_eq!(validate_pagination(None, None).unwrap(), (1, 50, 0));
        assert_eq!(validate_pagination(Some(3), Some(20)).unwrap(), (3, 20, 40));
    }

    #[test]
    fn search_pattern_escapes_like_wildcards() {
        let filter = IndicatorFilter {
            search: Some("100%_evil\\".into()),
            ..IndicatorFilter::default()
        };
        let normalized = normalize_filter(&filter).unwrap();
        assert_eq!(
            normalized.search_pattern.as_deref(),
            Some("%100\\%\\_evil\\\\%")
        );
    }

    #[test]
    fn indicator_values_are_typed_strictly() {
        assert!(validate_ioc_value("8.8.8.8", None).is_ok());
        assert!(validate_ioc_value("2001:4860:4860::8888", None).is_ok());
        assert!(validate_ioc_value("10.0.0.0/8", None).is_ok());
        assert!(validate_ioc_value("evil.example", None).is_ok());
        assert!(validate_ioc_value("https://evil.example/a", None).is_ok());
        assert!(validate_ioc_value("https://user:pass@evil.example/a", None).is_err());
        assert!(validate_ioc_value(&"ab".repeat(16), None).is_ok());
        assert!(validate_ioc_value("attacker@evil.example", None).is_ok());
        assert!(validate_ioc_value("CVE-2021-44228", None).is_ok());
        assert!(validate_ioc_value("CVE-not-real", None).is_err());
        assert!(validate_ioc_value("not an ioc", None).is_err());
        assert!(validate_ioc_value("8.8.8.8", Some(&IocType::Domain)).is_err());
    }

    #[test]
    fn request_bounds_confidence_and_tags() {
        let mut req = CreateIndicatorRequest {
            value: "8.8.8.8".into(),
            ioc_type: None,
            severity: None,
            confidence: Some(101),
            tlp: None,
            tags: None,
            source: None,
            expiration_days: None,
        };
        assert!(validate_indicator_request(&req).is_err());
        req.confidence = Some(50);
        req.tags = Some(vec!["ok".into(), "has space".into()]);
        assert!(validate_indicator_request(&req).is_err());
        req.tags = Some(vec!["phishing".into()]);
        assert!(validate_indicator_request(&req).is_ok());
    }
}
