use std::collections::HashSet;
use std::fmt::{Debug, Formatter};
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use hickory_proto::quic::QuicClientStreamBuilder;
use rand::prelude::*;
use rand::rng;
use rustls::{ClientConfig, RootCertStore};

use crate::backend::adaptor_backend::{DnsRequestSenderBuild, DynDnsRequestSender};

#[derive(Debug, Clone)]
pub struct QuicBuilder {
    inner: Arc<QuicBuilderInner>,
}

impl QuicBuilder {
    pub fn new(addrs: HashSet<SocketAddr>, host: String) -> anyhow::Result<Self> {
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

        let mut builder = QuicClientStreamBuilder::default();
        builder.crypto_config(client_config);

        Ok(Self {
            inner: Arc::new(QuicBuilderInner {
                addrs,
                host,
                builder,
            }),
        })
    }
}

#[async_trait]
impl DnsRequestSenderBuild for QuicBuilder {
    async fn build(&self) -> anyhow::Result<DynDnsRequestSender> {
        let addr = self
            .inner
            .addrs
            .iter()
            .copied()
            .choose(&mut rng())
            .expect("addrs must not empty");

        let quic_client_stream = self
            .inner
            .builder
            .clone()
            .build(addr, self.inner.host.clone())
            .await?;

        Ok(DynDnsRequestSender::new_with_clone(quic_client_stream))
    }
}

struct QuicBuilderInner {
    addrs: HashSet<SocketAddr>,
    host: String,
    builder: QuicClientStreamBuilder,
}

impl Debug for QuicBuilderInner {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicManagerBuilderInner")
            .field("addrs", &self.addrs)
            .field("host", &self.host)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::super::tests::*;
    use super::*;
    use crate::backend::{AdaptorBackend, Backend};

    #[tokio::test]
    async fn test() {
        init_tls_provider();

        let https_builder = QuicBuilder::new(
            ["45.90.28.1:853".parse().unwrap()].into(),
            "dns.nextdns.io".to_string(),
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
