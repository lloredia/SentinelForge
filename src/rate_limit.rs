//! Per-client request rate limiting using the `governor` crate.

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;

use governor::clock::DefaultClock;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};

pub type KeyedLimiter = RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>;

pub fn build_limiter(per_second: u32, burst: u32) -> anyhow::Result<Arc<KeyedLimiter>> {
    let per_second = NonZeroU32::new(per_second.max(1))
        .ok_or_else(|| anyhow::anyhow!("rate limit per_second must be >= 1"))?;
    let burst = NonZeroU32::new(burst.max(per_second.get()))
        .ok_or_else(|| anyhow::anyhow!("rate limit burst must be >= 1"))?;
    let quota = Quota::per_second(per_second).allow_burst(burst);
    Ok(Arc::new(RateLimiter::keyed(quota)))
}
