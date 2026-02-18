use std::collections::HashSet;
use std::fmt::Debug;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use deadpool::Runtime;
use deadpool::managed::{Manager, Metrics, Object, Pool, RecycleResult};
use futures_util::{Stream, TryStreamExt};
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::runtime::iocompat::AsyncIoTokioAsStd;
use hickory_proto::rustls::tls_stream::TokioTlsClientStream;
use hickory_proto::rustls::{TlsStream, tls_connect};
use hickory_proto::xfer::{
    DnsRequest, DnsRequestSender, DnsResponse, DnsResponseStream, SerialMessage,
};
use hickory_proto::{BufDnsStreamHandle, DnsStreamHandle, ProtoError};
use rand::{prelude::*, rng};
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;

use crate::backend::adaptor_backend::{DnsRequestSenderBuild, DynDnsRequestSender};

#[derive(Debug, Clone)]
pub struct TlsBuilder {
    pool: Pool<TlsStreamManager>,
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
            pool: Pool::builder(TlsStreamManager {
                addrs,
                name,
                tls_client_config: client_config.into(),
            })
            .runtime(Runtime::Tokio1)
            .build()?,
        })
    }
}

#[derive(Debug)]
struct TlsStreamManager {
    addrs: HashSet<SocketAddr>,
    name: String,
    tls_client_config: Arc<ClientConfig>,
}

impl Manager for TlsStreamManager {
    type Type = TlsStreamWrapper;
    type Error = ProtoError;

    async fn create(&self) -> Result<Self::Type, Self::Error> {
        let chosen_addr = self
            .addrs
            .iter()
            .copied()
            .choose(&mut rng())
            .expect("addrs must not empty");

        let (fut, sender) = tls_connect(
            chosen_addr,
            self.name.clone(),
            self.tls_client_config.clone(),
            TokioRuntimeProvider::new(),
        );

        let tls_stream = fut.await?;

        Ok(TlsStreamWrapper { tls_stream, sender })
    }

    async fn recycle(&self, _: &mut Self::Type, _: &Metrics) -> RecycleResult<Self::Error> {
        Ok(())
    }
}

struct TlsStreamWrapper {
    tls_stream: TlsStream<AsyncIoTokioAsStd<TokioTlsClientStream<AsyncIoTokioAsStd<TcpStream>>>>,
    sender: BufDnsStreamHandle,
}

impl Debug for TlsStreamWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsStreamWrapper").finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct TlsStreamDnsRequestSender {
    pool: Pool<TlsStreamManager>,
}

impl Stream for TlsStreamDnsRequestSender {
    type Item = Result<(), ProtoError>;

    fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(Some(Ok(())))
    }
}

impl DnsRequestSender for TlsStreamDnsRequestSender {
    fn send_message(&mut self, request: DnsRequest) -> DnsResponseStream {
        let pool = self.pool.clone();

        Box::pin(async move {
            let mut tls_stream = pool.get().await.map_err(io::Error::other)?;
            let peer_addr = tls_stream.tls_stream.peer_addr();
            let (message, _) = request.into_parts();
            let serial_message = SerialMessage::new(message.to_vec()?, peer_addr);

            async {
                tls_stream.sender.send(serial_message)?;
                let resp = tls_stream
                    .tls_stream
                    .try_next()
                    .await?
                    .ok_or_else(|| ProtoError::from("TLS stream EOF unexpected"))?;

                let buffer = resp.into_parts().0;

                DnsResponse::from_buffer(buffer)
            }
            .await
            .inspect_err(|_| {
                let _ = Object::<_>::take(tls_stream);
            })
        })
        .into()
    }

    fn shutdown(&mut self) {}

    fn is_shutdown(&self) -> bool {
        false
    }
}

#[async_trait]
impl DnsRequestSenderBuild for TlsBuilder {
    async fn build(&self) -> anyhow::Result<DynDnsRequestSender> {
        Ok(DynDnsRequestSender::new_with_clone(
            TlsStreamDnsRequestSender {
                pool: self.pool.clone(),
            },
        ))
    }
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
        init_tls_provider();

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
