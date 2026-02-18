use std::collections::{BTreeMap, HashMap};
use std::future::ready;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use futures_util::Stream;
use hickory_proto::ProtoError;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::xfer::{DnsRequest, DnsRequestSender, DnsResponse, DnsResponseStream};
use tracing::{info, instrument};

use crate::backend::adaptor_backend::{DnsRequestSenderBuild, DynDnsRequestSender};
use crate::config::StaticFileBackendConfig;

const DEFAULT_TTL: u32 = 3600; // 1 hour

#[derive(Debug, Clone, Ord, PartialOrd)]
struct DomainKey(Name);

impl DomainKey {
    fn from_name(mut name: Name) -> Self {
        name.set_fqdn(true);

        Self(name)
    }
}

impl PartialEq for DomainKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_root(&other.0)
    }
}

impl Eq for DomainKey {}

/// Inner data shared between builder and request sender
#[derive(Debug, Default)]
struct StaticFileInner {
    /// Exact domain match: domain -> IPs
    exact_matches: BTreeMap<DomainKey, Vec<RData>>,
    /// Wildcard domain match: suffix -> IPs
    /// For example, "*.test.com" is stored as "test.com." -> IPs
    wildcard_matches: HashMap<String, Vec<RData>>,
}

#[derive(Debug, Clone)]
pub struct StaticFileBuilder {
    inner: Arc<StaticFileInner>,
}

impl StaticFileBuilder {
    pub fn new(config: StaticFileBackendConfig) -> anyhow::Result<Self> {
        info!(?config, "create static file backend builder");

        let mut exact_matches = BTreeMap::new();
        let mut wildcard_matches = HashMap::new();

        for record in config.records {
            let ips = record
                .ips
                .iter()
                .map(|ip| {
                    if let Ok(ipv4) = ip.parse::<Ipv4Addr>() {
                        Ok(RData::A(ipv4.into()))
                    } else if let Ok(ipv6) = ip.parse::<Ipv6Addr>() {
                        Ok(RData::AAAA(ipv6.into()))
                    } else {
                        Err(anyhow::anyhow!("Invalid IP address: {}", ip))
                    }
                })
                .collect::<anyhow::Result<Vec<_>>>()?;

            match record.domain.strip_prefix("*.") {
                None => {
                    // Exact domain
                    let name = Name::from_utf8(&record.domain)?;
                    exact_matches.insert(DomainKey::from_name(name), ips);
                }

                Some(suffix) => {
                    // Wildcard domain: *.test.com -> stored as test.com.
                    let name = Name::from_utf8(suffix)?;
                    wildcard_matches
                        .insert(normalize_domain_str(&mut name.to_string()).to_string(), ips);
                }
            }
        }

        let inner = StaticFileInner {
            exact_matches,
            wildcard_matches,
        };

        info!(?inner, "created static file backend builder inner done");

        Ok(Self {
            inner: Arc::new(inner),
        })
    }
}

#[async_trait]
impl DnsRequestSenderBuild for StaticFileBuilder {
    async fn build(&self) -> anyhow::Result<DynDnsRequestSender> {
        Ok(DynDnsRequestSender::new_with_clone(
            StaticFileDnsRequestSender {
                inner: self.inner.clone(),
                shutdown: false,
            },
        ))
    }
}

#[derive(Debug, Clone)]
struct StaticFileDnsRequestSender {
    inner: Arc<StaticFileInner>,
    shutdown: bool,
}

impl Stream for StaticFileDnsRequestSender {
    type Item = Result<(), ProtoError>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.shutdown {
            Poll::Ready(None)
        } else {
            Poll::Ready(Some(Ok(())))
        }
    }
}

impl DnsRequestSender for StaticFileDnsRequestSender {
    #[instrument(skip(self), fields(request = ?&*request))]
    fn send_message(&mut self, request: DnsRequest) -> DnsResponseStream {
        let (message, _options) = request.into_parts();

        let query = match message.queries().first() {
            Some(q) => q,
            None => {
                return DnsResponseStream::from(ProtoError::from("No query in message"));
            }
        };

        let query_name = query.name();
        let query_type = query.query_type();

        info!("Static backend lookup: {} {}", query_name, query_type);

        let mut response = Message::new();
        response.set_id(message.id());
        response.set_recursion_desired(message.recursion_desired());
        response.set_recursion_available(true);
        response.add_query(query.clone());

        // Look up matching records
        let ips = self.lookup_ips(query_name.clone(), query_type);

        if let Some(ips) = ips {
            // Found matching records
            for ip in ips {
                let record = Record::from_rdata(query_name.clone(), DEFAULT_TTL, ip);
                response.add_answer(record);
            }
            response.set_response_code(ResponseCode::NoError);
        } else {
            // No matching records found
            response.set_response_code(ResponseCode::NXDomain);
        }

        match DnsResponse::from_message(response) {
            Ok(dns_response) => Box::pin(ready(Ok(dns_response))).into(),
            Err(err) => DnsResponseStream::from(err),
        }
    }

    fn shutdown(&mut self) {
        self.shutdown = true;
    }

    fn is_shutdown(&self) -> bool {
        self.shutdown
    }
}

impl StaticFileDnsRequestSender {
    /// Look up matching IPs for a query
    #[instrument(skip(self), ret)]
    fn lookup_ips(&self, query_name: Name, query_type: RecordType) -> Option<Vec<RData>> {
        let query_key = DomainKey::from_name(query_name);

        // First try exact match
        if let Some(found) = self.inner.exact_matches.get(&query_key) {
            let filtered = Self::filter_by_type(found, query_type);
            if !filtered.is_empty() {
                return Some(filtered);
            }
        }

        // Try wildcard match
        let mut query_key = query_key.0.to_string();
        let query_trimmed = normalize_domain_str(&mut query_key);
        for (suffix, rdata_list) in self.inner.wildcard_matches.iter() {
            let wildcard_hit =
                query_trimmed == *suffix || query_trimmed.ends_with(&format!(".{suffix}"));
            if wildcard_hit {
                let filtered = Self::filter_by_type(rdata_list, query_type);
                if !filtered.is_empty() {
                    return Some(filtered);
                }
            }
        }

        None
    }

    /// Filter IPs by query type
    #[instrument(ret)]
    fn filter_by_type(ips: &[RData], query_type: RecordType) -> Vec<RData> {
        match query_type {
            RecordType::A => ips
                .iter()
                .filter(|ip| matches!(ip, RData::A(_)))
                .cloned()
                .collect(),

            RecordType::AAAA => ips
                .iter()
                .filter(|ip| matches!(ip, RData::AAAA(_)))
                .cloned()
                .collect(),

            _ => ips.to_vec(),
        }
    }
}

fn normalize_domain_str(input: &mut str) -> &str {
    input.make_ascii_lowercase();

    input.trim_end_matches('.')
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use hickory_proto::op::{Message, Query};

    use super::*;
    use crate::backend::Backend;
    use crate::backend::adaptor_backend::AdaptorBackend;
    use crate::config::StaticRecord;

    fn create_query_message(domain: &str, record_type: RecordType) -> Message {
        let mut message = Message::new();
        message.add_query(Query::query(Name::from_utf8(domain).unwrap(), record_type));
        message.set_recursion_desired(true);
        message
    }

    fn dummy_socket_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234)
    }

    #[tokio::test]
    async fn test_exact_match() {
        let config = StaticFileBackendConfig {
            records: vec![StaticRecord {
                domain: "example.com".to_string(),
                ips: vec!["1.2.3.4".to_string()],
            }],
        };

        let builder = StaticFileBuilder::new(config).unwrap();
        let backend = AdaptorBackend::new(builder, 3).await.unwrap();

        let message = create_query_message("example.com", RecordType::A);
        let response = backend
            .send_request(message, dummy_socket_addr())
            .await
            .unwrap();

        assert_eq!(response.answers().len(), 1);
        let record = &response.answers()[0];
        assert_eq!(record.record_type(), RecordType::A);
        if let RData::A(ip) = record.data() {
            assert_eq!(ip.0, Ipv4Addr::new(1, 2, 3, 4));
        } else {
            panic!("Expected A record");
        }
    }

    #[tokio::test]
    async fn test_wildcard_match() {
        let config = StaticFileBackendConfig {
            records: vec![StaticRecord {
                domain: "*.test.com".to_string(),
                ips: vec!["5.6.7.8".to_string()],
            }],
        };

        let builder = StaticFileBuilder::new(config).unwrap();
        let backend = AdaptorBackend::new(builder, 3).await.unwrap();

        // Test test.com
        let message = create_query_message("test.com", RecordType::A);
        let response = backend
            .send_request(message, dummy_socket_addr())
            .await
            .unwrap();
        assert_eq!(response.answers().len(), 1);

        // Test a.test.com
        let message = create_query_message("a.test.com", RecordType::A);
        let response = backend
            .send_request(message, dummy_socket_addr())
            .await
            .unwrap();
        assert_eq!(response.answers().len(), 1);

        // Test a.b.test.com
        let message = create_query_message("a.b.test.com", RecordType::A);
        let response = backend
            .send_request(message, dummy_socket_addr())
            .await
            .unwrap();
        assert_eq!(response.answers().len(), 1);
    }

    #[tokio::test]
    async fn test_no_match() {
        let config = StaticFileBackendConfig {
            records: vec![StaticRecord {
                domain: "example.com".to_string(),
                ips: vec!["1.2.3.4".to_string()],
            }],
        };

        let builder = StaticFileBuilder::new(config).unwrap();
        let backend = AdaptorBackend::new(builder, 3).await.unwrap();

        let message = create_query_message("other.com", RecordType::A);
        let response = backend
            .send_request(message, dummy_socket_addr())
            .await
            .unwrap();

        assert_eq!(response.response_code(), ResponseCode::NXDomain);
        assert_eq!(response.answers().len(), 0);
    }

    #[tokio::test]
    async fn test_multiple_ips() {
        let config = StaticFileBackendConfig {
            records: vec![StaticRecord {
                domain: "example.com".to_string(),
                ips: vec!["1.2.3.4".to_string(), "5.6.7.8".to_string()],
            }],
        };

        let builder = StaticFileBuilder::new(config).unwrap();
        let backend = AdaptorBackend::new(builder, 3).await.unwrap();

        let message = create_query_message("example.com", RecordType::A);
        let response = backend
            .send_request(message, dummy_socket_addr())
            .await
            .unwrap();

        assert_eq!(response.answers().len(), 2);
    }

    #[tokio::test]
    async fn test_ipv6() {
        let config = StaticFileBackendConfig {
            records: vec![StaticRecord {
                domain: "example.com".to_string(),
                ips: vec!["2001:db8::1".to_string()],
            }],
        };

        let builder = StaticFileBuilder::new(config).unwrap();
        let backend = AdaptorBackend::new(builder, 3).await.unwrap();

        let message = create_query_message("example.com", RecordType::AAAA);
        let response = backend
            .send_request(message, dummy_socket_addr())
            .await
            .unwrap();

        assert_eq!(response.answers().len(), 1);
        let record = &response.answers()[0];
        assert_eq!(record.record_type(), RecordType::AAAA);
    }
}
