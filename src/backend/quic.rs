use std::collections::HashSet;
use std::fmt::{Debug, Formatter};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use futures_util::TryStreamExt;
use hickory_proto::op::Message;
use hickory_proto::quic::{QuicClientStream, QuicClientStreamBuilder};
use hickory_proto::xfer::{
    DnsRequest, DnsRequestOptions, DnsRequestSender, DnsResponse, FirstAnswer,
};
use rand::prelude::*;
use rand::rng;
use rustls::{ClientConfig, RootCertStore};
use tracing::instrument;

use crate::backend::Backend;

#[derive(Debug)]
pub struct QuicBackend {
    inner: Arc<QuicBackendInner>,
}

impl QuicBackend {
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
            inner: Arc::new(QuicBackendInner {
                addrs,
                host,
                builder,
                stream_cache: RwLock::new(None),
            }),
        })
    }

    async fn build_stream(&self) -> anyhow::Result<QuicClientStream> {
        let addr = self
            .inner
            .addrs
            .iter()
            .copied()
            .choose(&mut rng())
            .expect("addrs must not empty");

        self.inner
            .builder
            .clone()
            .build(addr, self.inner.host.clone())
            .await
            .map_err(Into::into)
    }

    async fn do_send_with_stream(
        stream: &mut QuicClientStream,
        message: Message,
    ) -> anyhow::Result<DnsResponse> {
        stream
            .try_next()
            .await?
            .ok_or_else(|| anyhow::anyhow!("quic stream connected but closed immediately"))?;

        let mut options = DnsRequestOptions::default();
        options.use_edns = true;
        let request = DnsRequest::new(message, options);
        let dns_response = stream.send_message(request).first_answer().await?;

        Ok(dns_response)
    }

    #[instrument(skip(self), ret, err)]
    async fn do_send(&self, message: Message) -> anyhow::Result<DnsResponse> {
        let stream = self.inner.stream_cache.read().unwrap().clone();

        if let Some(mut s) = stream {
            match Self::do_send_with_stream(&mut s, message.clone()).await {
                Ok(r) => return Ok(r),
                Err(_) => {
                    *self.inner.stream_cache.write().unwrap() = None;
                }
            }
        }

        let mut new_stream = self.build_stream().await?;
        *self.inner.stream_cache.write().unwrap() = Some(new_stream.clone());

        Self::do_send_with_stream(&mut new_stream, message).await
    }
}

struct QuicBackendInner {
    addrs: HashSet<SocketAddr>,
    host: String,
    builder: QuicClientStreamBuilder,
    stream_cache: RwLock<Option<QuicClientStream>>,
}

impl Debug for QuicBackendInner {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicBackendInner")
            .field("addrs", &self.addrs)
            .field("host", &self.host)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl Backend for QuicBackend {
    #[instrument(skip(self), ret, err)]
    async fn send_request(
        &self,
        message: Message,
        _src: SocketAddr,
    ) -> anyhow::Result<DnsResponse> {
        let res = self.do_send(message.clone()).await;
        if res.is_ok() {
            return res;
        }

        self.do_send(message).await
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::super::tests::*;
    use super::*;

    #[tokio::test]
    async fn test() {
        init_tls_provider();

        let backend = QuicBackend::new(
            ["45.90.28.1:853".parse().unwrap()].into(),
            "dns.nextdns.io".to_string(),
        )
        .unwrap();

        let dns_response = backend
            .send_request(
                create_query_message(),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234),
            )
            .await
            .unwrap();

        check_dns_response(&dns_response);
    }
}
