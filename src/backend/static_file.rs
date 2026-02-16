use std::collections::HashMap;
use std::future::ready;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use futures_util::Stream;
use hickory_proto::ProtoError;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::xfer::{DnsRequest, DnsRequestSender, DnsResponse, DnsResponseStream};
use tracing::debug;

use crate::backend::adaptor_backend::{BoxDnsRequestSender, DnsRequestSenderBuild};
use crate::config::StaticFileBackendConfig;

const DEFAULT_TTL: u32 = 3600; // 1 hour

/// Inner data shared between builder and request sender
#[derive(Debug, Default)]
struct StaticFileInner {
    /// Exact domain match: domain -> IPs
    exact_matches: HashMap<Name, Vec<RData>>,
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
        let mut inner = StaticFileInner::default();

        for record in config.records {
            let ips = record
                .ips
                .iter()
                .map(|ip| {
                    if let Ok(ipv4) = ip.parse::<std::net::Ipv4Addr>() {
                        Ok(RData::A(ipv4.into()))
                    } else if let Ok(ipv6) = ip.parse::<std::net::Ipv6Addr>() {
                        Ok(RData::AAAA(ipv6.into()))
                    } else {
                        Err(anyhow::anyhow!("Invalid IP address: {}", ip))
                    }
                })
                .collect::<anyhow::Result<Vec<_>>>()?;

            match record.domain.strip_prefix("*.") {
                None => {
                    // Exact domain
                    let name = Name::from_utf8(&record.domain)?.to_lowercase();
                    inner.exact_matches.insert(name, ips);
                }

                Some(suffix) => {
                    // Wildcard domain: *.test.com -> stored as test.com.
                    let name = Name::from_utf8(suffix)?.to_lowercase();
                    inner.wildcard_matches.insert(name.to_string(), ips);
                }
            }
        }

        Ok(Self {
            inner: Arc::new(inner),
        })
    }
}

#[async_trait]
impl DnsRequestSenderBuild for StaticFileBuilder {
    async fn build(&self) -> anyhow::Result<BoxDnsRequestSender> {
        Ok(BoxDnsRequestSender::new(StaticFileDnsRequestSender {
            inner: self.inner.clone(),
            shutdown: false,
        }))
    }
}

#[derive(Debug)]
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

        debug!("Static backend lookup: {} {}", query_name, query_type);

        let mut response = Message::new();
        response.set_id(message.id());
        response.set_recursion_desired(message.recursion_desired());
        response.set_recursion_available(true);
        response.add_query(query.clone());

        // Look up matching records
        let ips = self.lookup_ips(query_name, query_type);

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
    fn lookup_ips(&self, query_name: &Name, query_type: RecordType) -> Option<Vec<RData>> {
        // First try exact match
        if let Some(found) = self.inner.exact_matches.get(query_name) {
            let filtered = Self::filter_by_type(found, query_type);
            if !filtered.is_empty() {
                return Some(filtered);
            }
        }

        // Try wildcard match
        let query_name_str = query_name.to_lowercase().to_string();
        for (suffix, found) in self.inner.wildcard_matches.iter() {
            if query_name_str == *suffix || query_name_str.ends_with(&format!(".{}", suffix)) {
                let filtered = Self::filter_by_type(found, query_type);
                if !filtered.is_empty() {
                    return Some(filtered);
                }
            }
        }

        None
    }

    /// Filter IPs by query type
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

#[cfg(test)]
mod tests {
    use hickory_proto::xfer::FirstAnswer;

    use super::*;
    use crate::config::StaticRecord;

    #[tokio::test]
    async fn test_exact_match() {
        let config = StaticFileBackendConfig {
            records: vec![StaticRecord {
                domain: "example.com".to_string(),
                ips: vec!["1.2.3.4".to_string()],
            }],
        };

        let builder = StaticFileBuilder::new(config).unwrap();
        let mut sender = builder.build().await.unwrap();

        let mut message = Message::new();
        message.add_query(hickory_proto::op::Query::query(
            Name::from_utf8("example.com").unwrap(),
            RecordType::A,
        ));

        let request = DnsRequest::new(message, hickory_proto::xfer::DnsRequestOptions::default());
        let response = sender.send_message(request).first_answer().await.unwrap();

        assert_eq!(response.answers().len(), 1);
        let record = &response.answers()[0];
        assert_eq!(record.record_type(), RecordType::A);
        if let RData::A(ip) = record.data() {
            assert_eq!(ip.0, std::net::Ipv4Addr::new(1, 2, 3, 4));
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
        let mut sender = builder.build().await.unwrap();

        // Test test.com
        let mut message = Message::new();
        message.add_query(hickory_proto::op::Query::query(
            Name::from_utf8("test.com").unwrap(),
            RecordType::A,
        ));
        let request = DnsRequest::new(message, hickory_proto::xfer::DnsRequestOptions::default());
        let response = sender.send_message(request).first_answer().await.unwrap();
        assert_eq!(response.answers().len(), 1);

        // Test a.test.com
        let mut message = Message::new();
        message.add_query(hickory_proto::op::Query::query(
            Name::from_utf8("a.test.com").unwrap(),
            RecordType::A,
        ));
        let request = DnsRequest::new(message, hickory_proto::xfer::DnsRequestOptions::default());
        let response = sender.send_message(request).first_answer().await.unwrap();
        assert_eq!(response.answers().len(), 1);

        // Test a.b.test.com
        let mut message = Message::new();
        message.add_query(hickory_proto::op::Query::query(
            Name::from_utf8("a.b.test.com").unwrap(),
            RecordType::A,
        ));
        let request = DnsRequest::new(message, hickory_proto::xfer::DnsRequestOptions::default());
        let response = sender.send_message(request).first_answer().await.unwrap();
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
        let mut sender = builder.build().await.unwrap();

        let mut message = Message::new();
        message.add_query(hickory_proto::op::Query::query(
            Name::from_utf8("other.com").unwrap(),
            RecordType::A,
        ));

        let request = DnsRequest::new(message, hickory_proto::xfer::DnsRequestOptions::default());
        let response = sender.send_message(request).first_answer().await.unwrap();

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
        let mut sender = builder.build().await.unwrap();

        let mut message = Message::new();
        message.add_query(hickory_proto::op::Query::query(
            Name::from_utf8("example.com").unwrap(),
            RecordType::A,
        ));

        let request = DnsRequest::new(message, hickory_proto::xfer::DnsRequestOptions::default());
        let response = sender.send_message(request).first_answer().await.unwrap();

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
        let mut sender = builder.build().await.unwrap();

        let mut message = Message::new();
        message.add_query(hickory_proto::op::Query::query(
            Name::from_utf8("example.com").unwrap(),
            RecordType::AAAA,
        ));

        let request = DnsRequest::new(message, hickory_proto::xfer::DnsRequestOptions::default());
        let response = sender.send_message(request).first_answer().await.unwrap();

        assert_eq!(response.answers().len(), 1);
        let record = &response.answers()[0];
        assert_eq!(record.record_type(), RecordType::AAAA);
    }
}
