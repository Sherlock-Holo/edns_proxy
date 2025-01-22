use std::collections::HashSet;
use std::fmt::{Debug, Formatter};
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::ops::ControlFlow;

use async_trait::async_trait;
use deadpool::managed::{Manager, Metrics, Object, Pool, RecycleResult};
use futures_util::TryStreamExt;
use hickory_proto::op::Message;
use hickory_proto::quic::{QuicClientStream, QuicClientStreamBuilder};
use hickory_proto::xfer::{DnsRequest, DnsRequestOptions, DnsRequestSender, DnsResponse};
use rand::prelude::IteratorRandom;
use rand::thread_rng;
use rustls::{ClientConfig, RootCertStore};
use tracing::{error, instrument};

use crate::backend::Backend;
use crate::retry::retry;

#[derive(Debug, Clone)]
pub struct QuicBackend {
    pool: Pool<QuicManager>,
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

        let pool = Pool::builder(QuicManager {
            addrs,
            host,
            builder,
        })
        .build()?;

        Ok(Self { pool })
    }
}

#[async_trait]
impl Backend for QuicBackend {
    #[instrument(level = "debug", ret, err)]
    async fn send_request(&self, message: Message, _: SocketAddr) -> anyhow::Result<DnsResponse> {
        // FIXME: temporary clone to avoid god damn not Send for &HttpsBackend problem
        let inner = self.clone();

        retry(
            None,
            async move |cx| {
                let mut obj = inner.pool.get().await.map_err(|err| {
                    error!(%err, "get quic session failed");

                    anyhow::anyhow!("get quic session failed: {err}")
                })?;

                if let Ok(Some(resp)) = obj.send_to_quic(message.clone()).await {
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

struct Quic {
    quic_client_stream: QuicClientStream,
}

impl Debug for Quic {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Quic")
            .field("quic_client_stream", &self.quic_client_stream.to_string())
            .finish()
    }
}

impl Quic {
    #[instrument(level = "debug", ret, err)]
    async fn send_to_quic(&mut self, message: Message) -> anyhow::Result<Option<DnsResponse>> {
        let mut dns_request_options = DnsRequestOptions::default();
        dns_request_options.use_edns = true;
        let mut dns_response_stream = self
            .quic_client_stream
            .send_message(DnsRequest::new(message, dns_request_options));

        Ok(dns_response_stream.try_next().await.inspect_err(|_| {
            // drop the incorrect state quic session
            self.quic_client_stream.shutdown();
        })?)
    }
}

struct QuicManager {
    addrs: HashSet<SocketAddr>,
    host: String,
    builder: QuicClientStreamBuilder,
}

impl Debug for QuicManager {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicManager")
            .field("addrs", &self.addrs)
            .field("host", &self.host)
            .finish_non_exhaustive()
    }
}

impl Manager for QuicManager {
    type Type = Quic;
    type Error = anyhow::Error;

    #[instrument(level = "debug", err)]
    async fn create(&self) -> Result<Self::Type, Self::Error> {
        let addr = self
            .addrs
            .iter()
            .copied()
            .choose(&mut thread_rng())
            .expect("addrs must not empty");

        let quic_client_stream = self.builder.clone().build(addr, self.host.clone()).await?;

        Ok(Quic { quic_client_stream })
    }

    async fn recycle(
        &self,
        _obj: &mut Self::Type,
        _metrics: &Metrics,
    ) -> RecycleResult<Self::Error> {
        Ok(())
    }
}
