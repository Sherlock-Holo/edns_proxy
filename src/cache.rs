use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::time::Instant;

use cidr::IpInet;
use futures_util::lock::Mutex;
use hickory_proto::op::Query;
use hickory_proto::xfer::DnsResponse;
use lru::LruCache;

#[derive(Debug)]
pub struct Cache {
    inner: Mutex<CacheInner>,
    ipv4_prefix: u8,
    ipv6_prefix: u8,
}

impl Cache {
    pub fn new(capacity: NonZeroUsize, ipv4_prefix: u8, ipv6_prefix: u8) -> Self {
        Self {
            inner: Mutex::new(CacheInner {
                lru_cache: LruCache::new(capacity),
            }),
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
        self.inner.lock().await.get_response(query, ip_inet)
    }

    pub async fn put_cache_response(&self, query: Query, src_ip: IpAddr, response: DnsResponse) {
        let prefix = match src_ip {
            IpAddr::V4(_) => self.ipv4_prefix,
            IpAddr::V6(_) => self.ipv6_prefix,
        };

        let ip_inet = IpInet::new(src_ip, prefix).unwrap().first();
        self.inner
            .lock()
            .await
            .add_response(query, ip_inet, response);
    }
}

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
struct RequestKey {
    query: Query,
    src_ip: IpInet,
}

#[derive(Debug)]
struct CacheResponse {
    response: DnsResponse,
    ttl: u32,
    cache_time: Instant,
}

#[derive(Debug)]
struct CacheInner {
    lru_cache: LruCache<RequestKey, CacheResponse>,
}

impl CacheInner {
    fn get_response(&mut self, query: Query, src_ip: IpInet) -> Option<DnsResponse> {
        let key = RequestKey { query, src_ip };
        let resp = self.lru_cache.get(&key)?;
        let elapsed = resp.cache_time.elapsed().as_secs() as u32;
        let ttl = resp.ttl;

        if elapsed >= ttl {
            self.lru_cache.pop(&key);

            None
        } else {
            let mut resp = resp.response.clone();
            for answer in resp.answers_mut() {
                answer.set_ttl(ttl - elapsed);
            }

            Some(resp)
        }
    }

    fn add_response(&mut self, query: Query, src_ip: IpInet, response: DnsResponse) {
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
        self.lru_cache.push(key, CacheResponse {
            response,
            ttl,
            cache_time: Instant::now(),
        });
    }
}
