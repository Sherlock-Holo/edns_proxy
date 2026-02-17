use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use cidr::IpInet;
use hickory_proto::op::Query;
use hickory_proto::xfer::DnsResponse;
use moka::Expiry;
use moka::future::Cache as MokaCache;

#[derive(Debug)]
pub struct Cache {
    inner: MokaCache<RequestKey, CacheResponse>,
    ipv4_prefix: u8,
    ipv6_prefix: u8,
}

impl Cache {
    pub fn new(capacity: NonZeroUsize, ipv4_prefix: u8, ipv6_prefix: u8) -> Self {
        let cache = MokaCache::builder()
            .max_capacity(capacity.get() as _)
            .expire_after(TtlExpiry)
            .build();

        Self {
            inner: cache,
            ipv4_prefix,
            ipv6_prefix,
        }
    }

    pub async fn get_cache_response(&self, query: Query, src_ip: IpAddr) -> Option<DnsResponse> {
        let prefix = match src_ip {
            IpAddr::V4(_) => self.ipv4_prefix,
            IpAddr::V6(_) => self.ipv6_prefix,
        };

        let ip_inet = IpInet::new(src_ip, prefix).unwrap().first();
        self.get_response(query, ip_inet).await
    }

    pub async fn put_cache_response(&self, query: Query, src_ip: IpAddr, response: DnsResponse) {
        let prefix = match src_ip {
            IpAddr::V4(_) => self.ipv4_prefix,
            IpAddr::V6(_) => self.ipv6_prefix,
        };

        let ip_inet = IpInet::new(src_ip, prefix).unwrap().first();
        self.add_response(query, ip_inet, response).await;
    }
}

#[derive(Debug)]
struct TtlExpiry;

impl Expiry<RequestKey, CacheResponse> for TtlExpiry {
    fn expire_after_create(
        &self,
        _key: &RequestKey,
        value: &CacheResponse,
        _created_at: Instant,
    ) -> Option<Duration> {
        let ttl = Duration::from_secs(value.ttl as _);

        Some(ttl)
    }
}

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
struct RequestKey {
    query: Query,
    src_ip: IpInet,
}

#[derive(Debug, Clone)]
struct CacheResponse {
    response: DnsResponse,
    ttl: u32,
    cache_time: Instant,
}

impl Cache {
    async fn get_response(&self, query: Query, src_ip: IpInet) -> Option<DnsResponse> {
        let key = RequestKey { query, src_ip };
        let resp = self.inner.get(&key).await?;
        let elapsed = resp.cache_time.elapsed().as_secs() as u32;
        let ttl = resp.ttl;

        if elapsed >= ttl {
            self.inner.invalidate(&key).await;

            None
        } else {
            let mut resp = resp.response.clone();
            for answer in resp.answers_mut() {
                answer.set_ttl(ttl - elapsed);
            }

            Some(resp)
        }
    }

    async fn add_response(&self, query: Query, src_ip: IpInet, response: DnsResponse) {
        let ttl = match response.answers().iter().map(|record| record.ttl()).min() {
            None => return,
            Some(ttl) => {
                if ttl == 0 {
                    return;
                }

                ttl
            }
        };

        let key = RequestKey { query, src_ip };
        self.inner
            .insert(
                key,
                CacheResponse {
                    response,
                    ttl,
                    cache_time: Instant::now(),
                },
            )
            .await;
    }
}
