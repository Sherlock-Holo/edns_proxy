use std::collections::HashSet;
use std::fmt::{Debug, Formatter};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::TryStreamExt;
use futures_util::lock::Mutex;
use hickory_proto::h2::{HttpsClientStream, HttpsClientStreamBuilder};
use hickory_proto::op::Message;
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::xfer::{DnsRequest, DnsRequestOptions, DnsRequestSender, DnsResponse};
use rand::prelude::IteratorRandom;
use rand::thread_rng;
use rustls::{ClientConfig, RootCertStore};
use tokio::time::timeout;
use tracing::{error, instrument};

use crate::backend::Backend;

#[derive(Debug, Clone)]
pub struct HttpsBackend {
    inner: Arc<Inner>,
}

impl HttpsBackend {
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

        Ok(Self {
            inner: Arc::new(Inner {
                addrs,
                host,
                query_path,
                builder: HttpsClientStreamBuilder::with_client_config(
                    Arc::new(client_config),
                    TokioRuntimeProvider::new(),
                ),
                using_https_client_stream: Default::default(),
            }),
        })
    }
}

#[async_trait]
impl Backend for HttpsBackend {
    #[instrument(level = "debug", ret, err)]
    async fn send_request(&self, message: Message, _: SocketAddr) -> anyhow::Result<DnsResponse> {
        for _ in 0..3 {
            let mut https_client_stream = match self.inner.create().await {
                Err(err) => {
                    error!(%err, "get https session failed");

                    continue;
                }

                Ok(https_client_stream) => https_client_stream,
            };

            let mut dns_request_options = DnsRequestOptions::default();
            dns_request_options.use_edns = true;
            let mut dns_response_stream = https_client_stream
                .send_message(DnsRequest::new(message.clone(), dns_request_options));

            if let Ok(Some(resp)) = dns_response_stream.try_next().await {
                return Ok(resp);
            } else {
                https_client_stream.shutdown();
            }
        }

        Err(anyhow::anyhow!("get dns response failed"))
    }
}

struct Inner {
    addrs: HashSet<SocketAddr>,
    host: String,
    query_path: String,
    builder: HttpsClientStreamBuilder<TokioRuntimeProvider>,
    using_https_client_stream: Mutex<Option<HttpsClientStream>>,
}

impl Debug for Inner {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inner")
            .field("addrs", &self.addrs)
            .field("host", &self.host)
            .field("using_https_client_stream", &self.using_https_client_stream)
            .finish_non_exhaustive()
    }
}

impl Inner {
    #[instrument(level = "debug", err)]
    async fn create(&self) -> anyhow::Result<HttpsClientStream> {
        const LOCK_TIMEOUT: Duration = Duration::from_millis(300);

        let https_client_stream = match timeout(LOCK_TIMEOUT, async {
            let mut using_https_client_stream = self.using_https_client_stream.lock().await;
            let using_https_client_stream_mut = match &mut *using_https_client_stream {
                None => {
                    let https_client_stream = self.create_new_https_client_stream().await?;
                    *using_https_client_stream = Some(https_client_stream.clone());

                    return Ok(https_client_stream);
                }

                Some(using_https_client_stream) => using_https_client_stream,
            };

            match using_https_client_stream_mut.try_next().await {
                Err(_) => {
                    *using_https_client_stream = None;
                    let https_client_stream = self.create_new_https_client_stream().await?;
                    *using_https_client_stream = Some(https_client_stream.clone());

                    Ok(https_client_stream)
                }

                Ok(None) => return self.create_new_https_client_stream().await,
                Ok(Some(_)) => Ok(using_https_client_stream_mut.clone()),
            }
        })
        .await
        {
            Err(_) => self.create_new_https_client_stream().await?,
            Ok(Err(err)) => return Err(err),
            Ok(Ok(https_client_stream)) => https_client_stream,
        };

        Ok(https_client_stream)
    }

    #[instrument(level = "debug", err)]
    async fn create_new_https_client_stream(&self) -> anyhow::Result<HttpsClientStream> {
        let addr = self
            .addrs
            .iter()
            .copied()
            .choose(&mut thread_rng())
            .expect("addrs must not empty");

        let mut https_client_stream = self
            .builder
            .clone()
            .build(addr, self.host.clone(), self.query_path.clone())
            .await?;

        https_client_stream
            .try_next()
            .await?
            .ok_or_else(|| anyhow::anyhow!("https stream connected but closed immediately"))?;

        Ok(https_client_stream)
    }
}
