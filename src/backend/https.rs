use std::collections::HashSet;
use std::fmt::{Debug, Formatter};
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use futures_util::TryStreamExt;
use hickory_proto::h2::HttpsClientStreamBuilder;
use hickory_proto::runtime::TokioRuntimeProvider;
use rand::prelude::*;
use rand::rng;
use rustls::{ClientConfig, RootCertStore};

use crate::backend::adaptor_backend::{BoxDnsRequestSender, DnsRequestSenderBuild};

#[derive(Debug, Clone)]
pub struct HttpsBuilder {
    inner: Arc<HttpsBuilderInner>,
}

impl HttpsBuilder {
    pub fn new(
        addrs: HashSet<SocketAddr>,
        host: String,
        query_path: String,
    ) -> anyhow::Result<Self> {
        let mut root_cert_store = RootCertStore::empty();
        let certs = rustls_native_certs::load_native_certs();
        if !certs.errors.is_empty() {
            return Err(anyhow::anyhow!(
                "load native cert errors: {:?}",
                certs.errors
            ));
        }
        for cert in certs.certs {
            root_cert_store.add(cert)?;
        }

        let client_config = ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth();

        Ok(Self {
            inner: Arc::new(HttpsBuilderInner {
                addrs,
                host,
                query_path,
                builder: HttpsClientStreamBuilder::with_client_config(
                    Arc::new(client_config),
                    TokioRuntimeProvider::new(),
                ),
            }),
        })
    }
}

#[async_trait]
impl DnsRequestSenderBuild for HttpsBuilder {
    async fn build(&self) -> anyhow::Result<BoxDnsRequestSender> {
        let addr = self
            .inner
            .addrs
            .iter()
            .copied()
            .choose(&mut rng())
            .expect("addrs must not empty");

        let mut https_client_stream = self
            .inner
            .builder
            .clone()
            .build(addr, self.inner.host.clone(), self.inner.query_path.clone())
            .await?;

        https_client_stream
            .try_next()
            .await?
            .ok_or_else(|| anyhow::anyhow!("https stream connected but closed immediately"))?;

        Ok(BoxDnsRequestSender::new(https_client_stream))
    }
}

struct HttpsBuilderInner {
    addrs: HashSet<SocketAddr>,
    host: String,
    query_path: String,
    builder: HttpsClientStreamBuilder<TokioRuntimeProvider>,
}

impl Debug for HttpsBuilderInner {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpsBuilderInner")
            .field("addrs", &self.addrs)
            .field("host", &self.host)
            .field("query_path", &self.query_path)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::{Name, RData, RecordType};
    use hickory_proto::xfer::DnsResponse;

    use super::*;
    use crate::backend::Backend;
    use crate::backend::adaptor_backend::AdaptorBackend;

    fn create_query_message() -> Message {
        let mut message = Message::new();
        message.add_query(Query::query(
            Name::from_utf8("www.example.com").unwrap(),
            RecordType::A,
        ));

        message
    }

    fn check_dns_response(dns_response: &DnsResponse) {
        assert!(dns_response.answers().iter().any(|record| {
            let data = record.data();
            match data {
                RData::A(ip) => ip.0 == Ipv4Addr::new(104, 18, 26, 120),
                _ => false,
            }
        }));
    }

    #[tokio::test]
    async fn test() {
        let https_builder = HttpsBuilder::new(
            ["1.12.12.21:443".parse().unwrap()].into(),
            "doh.pub".to_string(),
            "/dns-query".to_string(),
        )
        .unwrap();

        let generic_backend = AdaptorBackend::new(https_builder, 3).await.unwrap();

        let dns_response = generic_backend
            .send_request(
                create_query_message(),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234),
            )
            .await
            .unwrap();

        check_dns_response(&dns_response);
    }
}
