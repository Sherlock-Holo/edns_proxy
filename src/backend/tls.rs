use std::collections::HashSet;
use std::fmt::Debug;
use std::future::ready;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use hickory_proto::DnsMultiplexer;
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::rustls::tls_connect;
use hickory_proto::tcp::TcpClientStream;
use rand::{prelude::*, rng};
use rustls::{ClientConfig, RootCertStore};

use crate::backend::adaptor_backend::{BoxDnsRequestSender, DnsRequestSenderBuild};

#[derive(Debug, Clone)]
pub struct TlsBuilder {
    inner: Arc<TlsBuilderInner>,
}

impl TlsBuilder {
    pub fn new(addrs: HashSet<SocketAddr>, name: String) -> anyhow::Result<Self> {
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
            inner: Arc::new(TlsBuilderInner {
                addrs,
                name,
                tls_client_config: client_config.into(),
            }),
        })
    }
}

#[async_trait]
impl DnsRequestSenderBuild for TlsBuilder {
    async fn build(&self) -> anyhow::Result<BoxDnsRequestSender> {
        let chosen_addr = self
            .inner
            .addrs
            .iter()
            .copied()
            .choose(&mut rng())
            .expect("addrs must not empty");

        let (fut, sender) = tls_connect(
            chosen_addr,
            self.inner.name.clone(),
            self.inner.tls_client_config.clone(),
            TokioRuntimeProvider::new(),
        );

        let tls_stream = fut.await?;
        let tls_stream = TcpClientStream::from_stream(tls_stream);
        let dns_multiplexer = DnsMultiplexer::new(ready(Ok(tls_stream)), sender, None).await?;

        Ok(BoxDnsRequestSender::new(dns_multiplexer))
    }
}

#[derive(Debug)]
struct TlsBuilderInner {
    addrs: HashSet<SocketAddr>,
    name: String,
    tls_client_config: Arc<ClientConfig>,
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::super::tests::*;
    use super::*;
    use crate::backend::Backend;
    use crate::backend::adaptor_backend::AdaptorBackend;

    #[tokio::test]
    async fn test() {
        let https_builder = TlsBuilder::new(
            ["1.12.12.21:853".parse().unwrap()].into(),
            "dot.pub".to_string(),
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
