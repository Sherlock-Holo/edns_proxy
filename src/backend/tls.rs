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
        let (fut, sender) = tls_connect(
            self.inner
                .addrs
                .iter()
                .copied()
                .choose(&mut rng())
                .expect("addrs must not empty"),
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
