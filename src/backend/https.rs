use std::collections::HashSet;
use std::fmt::{Debug, Formatter};
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use deadpool::managed::{Manager, Metrics, Object, Pool, RecycleResult};
use futures_util::TryStreamExt;
use hickory_proto::h2::{HttpsClientStream, HttpsClientStreamBuilder};
use hickory_proto::iocompat::AsyncIoTokioAsStd;
use hickory_proto::op::Message;
use hickory_proto::xfer::{DnsRequest, DnsRequestOptions, DnsRequestSender, DnsResponse};
use rand::prelude::IteratorRandom;
use rand::thread_rng;
use rustls::{Certificate, ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tracing::{error, instrument};

use crate::backend::Backend;

#[derive(Debug, Clone)]
pub struct HttpsBackend {
    pool: Pool<HttpsManager>,
}

impl HttpsBackend {
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
            root_cert_store.add(&Certificate(cert.to_vec()))?;
        }

        let client_config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth();

        let pool = Pool::builder(HttpsManager {
            addrs,
            host,
            builder: HttpsClientStreamBuilder::with_client_config(Arc::new(client_config)),
        })
        .build()?;

        Ok(Self { pool })
    }
}

impl Backend for HttpsBackend {
    #[instrument(level = "debug", err)]
    async fn send_request(&self, message: Message, _: SocketAddr) -> anyhow::Result<DnsResponse> {
        for _ in 0..3 {
            let mut obj = match self.pool.get().await {
                Err(err) => {
                    error!(%err, "get https session failed");

                    continue;
                }

                Ok(obj) => obj,
            };

            if let Ok(Some(resp)) = obj.send_to_https(message.clone()).await {
                return Ok(resp);
            } else {
                // drop the incorrect state https session
                obj.https_client_stream.shutdown();
                let _ = Object::take(obj);
            }
        }

        Err(anyhow::anyhow!("get dns response failed"))
    }
}

struct Https {
    https_client_stream: HttpsClientStream,
}

impl Debug for Https {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Https").finish_non_exhaustive()
    }
}

impl Https {
    #[instrument(level = "debug", ret, err)]
    async fn send_to_https(&mut self, message: Message) -> anyhow::Result<Option<DnsResponse>> {
        let mut dns_request_options = DnsRequestOptions::default();
        dns_request_options.use_edns = true;
        let mut dns_response_stream = self
            .https_client_stream
            .send_message(DnsRequest::new(message, dns_request_options));

        Ok(dns_response_stream.try_next().await?)
    }
}

struct HttpsManager {
    addrs: HashSet<SocketAddr>,
    host: String,
    builder: HttpsClientStreamBuilder,
}

impl Debug for HttpsManager {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpsManager")
            .field("addrs", &self.addrs)
            .field("host", &self.host)
            .finish_non_exhaustive()
    }
}

impl Manager for HttpsManager {
    type Type = Https;
    type Error = anyhow::Error;

    #[instrument(level = "debug", err)]
    async fn create(&self) -> Result<Self::Type, Self::Error> {
        let addr = self
            .addrs
            .iter()
            .copied()
            .choose(&mut thread_rng())
            .expect("addrs must not empty");

        let https_client_stream = self
            .builder
            .clone()
            .build::<AsyncIoTokioAsStd<TcpStream>>(addr, self.host.clone())
            .await
            .with_context(|| "build https client stream failed")?;

        Ok(Https {
            https_client_stream,
        })
    }

    async fn recycle(
        &self,
        _obj: &mut Self::Type,
        _metrics: &Metrics,
    ) -> RecycleResult<Self::Error> {
        Ok(())
    }
}
