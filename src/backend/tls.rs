use std::collections::HashSet;
use std::fmt::{Debug, Formatter};
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::ops::ControlFlow;
use std::sync::Arc;

use async_trait::async_trait;
use deadpool::managed::{Manager, Metrics, Object, Pool, RecycleResult};
use futures_util::TryStreamExt;
use hickory_proto::op::Message;
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::runtime::iocompat::AsyncIoTokioAsStd;
use hickory_proto::rustls::tls_stream::TokioTlsClientStream;
use hickory_proto::rustls::{TlsStream, tls_connect};
use hickory_proto::xfer::{DnsResponse, SerialMessage};
use hickory_proto::{BufDnsStreamHandle, DnsStreamHandle};
use rand::prelude::*;
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tracing::{debug, error, instrument};

use crate::backend::Backend;
use crate::retry::retry;

#[derive(Debug, Clone)]
pub struct TlsBackend {
    pool: Pool<TlsManager>,
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

        let pool = Pool::builder(TlsManager {
            addrs,
            name,
            tls_client_config: Arc::new(client_config),
        })
        .build()?;

        Ok(Self { pool })
    }
}

#[async_trait]
impl Backend for TlsBackend {
    #[instrument(level = "debug", ret, err)]
    async fn send_request(&self, message: Message, src: SocketAddr) -> anyhow::Result<DnsResponse> {
        // FIXME: temporary clone to avoid god damn not Send for &HttpsBackend problem
        let inner = self.clone();

        retry(
            None,
            async move |cx| {
                let mut obj = inner.pool.get().await.map_err(|err| {
                    error!(%err, "get tls session failed");

                    anyhow::anyhow!("get tls session failed: {err}")
                })?;

                if let Ok(Some(resp)) = obj.send_to_tls(&message, src).await {
                    Ok(resp)
                } else {
                    cx.replace(obj);

                    Err(anyhow::anyhow!("try get dns response failed"))
                }
            },
            async |err, cx| {
                if let Some(obj) = cx.take() {
                    let _ = Object::take(obj);
                }

                ControlFlow::Continue(err)
            },
            NonZeroUsize::new(3).unwrap(),
            None,
        )
        .await
    }
}

struct Tls {
    tls_stream: TlsStream<AsyncIoTokioAsStd<TokioTlsClientStream<AsyncIoTokioAsStd<TcpStream>>>>,
    sender: BufDnsStreamHandle,
}

impl Debug for Tls {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tls").finish_non_exhaustive()
    }
}

impl Tls {
    #[instrument(level = "debug", ret, err)]
    async fn send_to_tls(
        &mut self,
        message: &Message,
        src: SocketAddr,
    ) -> anyhow::Result<Option<DnsResponse>> {
        let message_data = message.to_vec()?;

        self.sender.send(SerialMessage::new(message_data, src))?;

        let resp = match self.tls_stream.try_next().await? {
            None => {
                debug!("no more tls dns response for this session");

                return Ok(None);
            }

            Some(resp) => resp,
        };

        let resp_message = resp.to_message()?;

        Ok(Some(DnsResponse::from_message(resp_message)?))
    }
}

#[derive(Debug)]
struct TlsManager {
    addrs: HashSet<SocketAddr>,
    name: String,
    tls_client_config: Arc<ClientConfig>,
}

impl Manager for TlsManager {
    type Type = Tls;
    type Error = io::Error;

    #[instrument(level = "debug", err)]
    async fn create(&self) -> Result<Self::Type, Self::Error> {
        let (fut, sender) = tls_connect(
            self.addrs
                .iter()
                .copied()
                .choose(&mut thread_rng())
                .expect("addrs must not empty"),
            self.name.clone(),
            self.tls_client_config.clone(),
            TokioRuntimeProvider::new(),
        );
        let tls_stream = fut.await?;

        Ok(Tls { tls_stream, sender })
    }

    async fn recycle(
        &self,
        _obj: &mut Self::Type,
        _metrics: &Metrics,
    ) -> RecycleResult<Self::Error> {
        Ok(())
    }
}
