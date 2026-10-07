//! GeoIP enrichment using MaxMind database

use anyhow::{Context, Result};
use async_trait::async_trait;
use maxminddb::{Reader, geoip2};
use serde_json::{Value, json};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use crate::enrichment::EnrichmentProvider;
use crate::models::{GeoIpData, Indicator, IocType};

/// GeoIP enrichment provider using MaxMind databases
pub struct GeoIpProvider {
    city_reader: Option<Arc<Reader<Vec<u8>>>>,
    asn_reader: Option<Arc<Reader<Vec<u8>>>>,
}

impl GeoIpProvider {
    /// Open whichever databases exist. Missing or unreadable files disable that
    /// lookup and leave the provider in place so enrichment can continue.
    pub fn new(city_db_path: Option<&Path>, asn_db_path: Option<&Path>) -> Self {
        Self {
            city_reader: city_db_path.and_then(open_reader),
            asn_reader: asn_db_path.and_then(open_reader),
        }
    }

    pub fn is_available(&self) -> bool {
        self.city_reader.is_some() || self.asn_reader.is_some()
    }

    /// Lookup GeoIP data for an IP address
    pub fn lookup(&self, ip: &str) -> Result<GeoIpData> {
        let ip_addr: IpAddr = ip.parse().context("Invalid IP address")?;
        let mut data = GeoIpData::default();

        if let Some(reader) = &self.city_reader
            && let Ok(result) = reader.lookup(ip_addr)
            && let Ok(Some(city)) = result.decode::<geoip2::City>()
        {
            data.country_code = city.country.iso_code.map(str::to_string);
            data.country_name = city.country.names.english.map(str::to_string);
            data.city = city.city.names.english.map(str::to_string);
            if let Some(region) = city.subdivisions.first() {
                data.region = region.names.english.map(str::to_string);
            }
            data.latitude = city.location.latitude;
            data.longitude = city.location.longitude;
        }

        if let Some(reader) = &self.asn_reader
            && let Ok(result) = reader.lookup(ip_addr)
            && let Ok(Some(asn)) = result.decode::<geoip2::Asn>()
        {
            data.asn = asn.autonomous_system_number;
            data.as_org = asn.autonomous_system_organization.map(str::to_string);
        }

        Ok(data)
    }
}

fn open_reader(path: &Path) -> Option<Arc<Reader<Vec<u8>>>> {
    if !path.exists() {
        tracing::warn!(path = %path.display(), "GeoIP database not found; skipping");
        return None;
    }
    match Reader::open_readfile(path) {
        Ok(reader) => Some(Arc::new(reader)),
        Err(err) => {
            tracing::warn!(path = %path.display(), error = %err, "GeoIP database unreadable; skipping");
            None
        }
    }
}

#[async_trait]
impl EnrichmentProvider for GeoIpProvider {
    fn name(&self) -> &'static str {
        "maxmind"
    }

    fn enrichment_type(&self) -> &'static str {
        "geoip"
    }

    fn supports(&self, ioc_type: &IocType) -> bool {
        matches!(ioc_type, IocType::Ip)
    }

    async fn enrich(&self, indicator: &Indicator) -> Result<Option<Value>> {
        if self.city_reader.is_none() && self.asn_reader.is_none() {
            return Ok(None);
        }

        let data = self.lookup(&indicator.value)?;

        // Only return if we got some data
        if data.country_code.is_none() && data.asn.is_none() {
            return Ok(None);
        }

        Ok(Some(json!({
            "country_code": data.country_code,
            "country_name": data.country_name,
            "city": data.city,
            "region": data.region,
            "latitude": data.latitude,
            "longitude": data.longitude,
            "asn": data.asn,
            "as_org": data.as_org,
        })))
    }

    fn ttl_hours(&self) -> i64 {
        168 // 1 week - GeoIP data doesn't change often
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{IocType, Severity, Tlp};
    use chrono::Utc;
    use uuid::Uuid;

    #[tokio::test]
    async fn missing_databases_do_not_fail_enrichment() {
        let provider = GeoIpProvider::new(
            Some(Path::new("data/does-not-exist-city.mmdb")),
            Some(Path::new("data/does-not-exist-asn.mmdb")),
        );
        assert!(!provider.is_available());
        let now = Utc::now();
        let indicator = Indicator {
            id: Uuid::nil(),
            ioc_type: IocType::Ip,
            value: "8.8.8.8".into(),
            severity: Severity::Low,
            confidence: 10,
            threat_score: 10,
            tlp: Tlp::White,
            first_seen: now,
            last_seen: now,
            expiration: None,
            tags: vec![],
            source_ids: vec![],
            created_at: now,
            updated_at: now,
        };
        let result = provider.enrich(&indicator).await.unwrap();
        assert!(result.is_none());
    }
}
