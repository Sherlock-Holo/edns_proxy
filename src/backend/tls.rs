use std::collections::HashSet;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use deadpool::Runtime;
use deadpool::managed::{Manager, Metrics, Object, Pool, RecycleResult};
use futures_util::TryStreamExt;
use hickory_proto::op::Message;
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::runtime::iocompat::AsyncIoTokioAsStd;
use hickory_proto::rustls::tls_stream::TokioTlsClientStream;
use hickory_proto::rustls::{TlsStream, tls_connect};
use hickory_proto::xfer::{DnsResponse, SerialMessage};
use hickory_proto::{BufDnsStreamHandle, DnsStreamHandle, ProtoError};
use rand::{prelude::*, rng};
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tracing::instrument;

use crate::backend::Backend;

#[derive(Debug)]
pub struct TlsBackend {
    pool: Pool<TlsStreamManager>,
}

impl TlsBackend {
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

    #[instrument(skip(self), ret, err)]
    async fn do_send(&self, message: Message, src: SocketAddr) -> anyhow::Result<DnsResponse> {
        let mut tls_stream = self.pool.get().await?;
        let serial_message = SerialMessage::new(message.to_vec()?, src);

        let result = async {
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
        });

        result.map_err(Into::into)
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

#[async_trait]
impl Backend for TlsBackend {
    #[instrument(skip(self), ret, err)]
    async fn send_request(&self, message: Message, src: SocketAddr) -> anyhow::Result<DnsResponse> {
        let res = self.do_send(message.clone(), src).await;
        if res.is_ok() {
            return res;
        }

        self.do_send(message, src).await
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

        let backend = TlsBackend::new(
            ["1.12.12.21:853".parse().unwrap()].into(),
            "dot.pub".to_string(),
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
