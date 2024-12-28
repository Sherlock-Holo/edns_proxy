use std::collections::HashSet;
use std::fmt::{Debug, Formatter};
use std::net::SocketAddr;

use deadpool::managed::{Manager, Metrics, Object, Pool, RecycleResult};
use futures_util::TryStreamExt;
use hickory_proto::h3::{H3ClientStream, H3ClientStreamBuilder};
use hickory_proto::op::Message;
use hickory_proto::xfer::{DnsRequest, DnsRequestOptions, DnsRequestSender, DnsResponse};
use rand::prelude::IteratorRandom;
use rand::thread_rng;
use rustls::{ClientConfig, RootCertStore};
use tracing::{error, instrument};

use crate::backend::Backend;

#[derive(Debug, Clone)]
pub struct H3Backend {
    pool: Pool<H3Manager>,
}

impl H3Backend {
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

        let mut builder = H3ClientStreamBuilder::default();
        builder.crypto_config(client_config);

        let pool = Pool::builder(H3Manager {
            addrs,
            host,
            query_path,
            builder,
        })
        .build()?;

        Ok(Self { pool })
    }
}

impl Backend for H3Backend {
    #[instrument(level = "debug", ret, err)]
    async fn send_request(&self, message: Message, _: SocketAddr) -> anyhow::Result<DnsResponse> {
        for _ in 0..3 {
            let mut obj = match self.pool.get().await {
                Err(err) => {
                    error!(%err, "get h3 session failed");

                    continue;
                }

                Ok(obj) => obj,
            };

            if let Ok(Some(resp)) = obj.send_to_h3(message.clone()).await {
                return Ok(resp);
            } else {
                let _ = Object::take(obj);
            }
        }

        Err(anyhow::anyhow!("get dns response failed"))
    }
}

struct H3 {
    h3_client_stream: H3ClientStream,
}

impl Debug for H3 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H3")
            .field("h3_client_stream", &self.h3_client_stream.to_string())
            .finish()
    }
}

impl H3 {
    #[instrument(level = "debug", ret, err)]
    async fn send_to_h3(&mut self, message: Message) -> anyhow::Result<Option<DnsResponse>> {
        let mut dns_request_options = DnsRequestOptions::default();
        dns_request_options.use_edns = true;
        let mut dns_response_stream = self
            .h3_client_stream
            .send_message(DnsRequest::new(message, dns_request_options));

        Ok(dns_response_stream.try_next().await.inspect_err(|_| {
            // drop the incorrect state h3 session
            self.h3_client_stream.shutdown();
        })?)
    }
}

struct H3Manager {
    addrs: HashSet<SocketAddr>,
    host: String,
    query_path: String,
    builder: H3ClientStreamBuilder,
}

impl Debug for H3Manager {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H3Manager")
            .field("addrs", &self.addrs)
            .field("host", &self.host)
            .finish_non_exhaustive()
    }
}

impl Manager for H3Manager {
    type Type = H3;
    type Error = anyhow::Error;

    #[instrument(level = "debug", err)]
    async fn create(&self) -> Result<Self::Type, Self::Error> {
        let addr = self
            .addrs
            .iter()
            .copied()
            .choose(&mut thread_rng())
            .expect("addrs must not empty");

        let h3_client_stream = self
            .builder
            .clone()
            .build(addr, self.host.clone(), self.query_path.clone())
            .await?;

        Ok(H3 { h3_client_stream })
    }

    async fn recycle(
        &self,
        _obj: &mut Self::Type,
        _metrics: &Metrics,
    ) -> RecycleResult<Self::Error> {
        Ok(())
    }
}
