use std::collections::HashSet;
use std::fmt::{Debug, Formatter};
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::ops::ControlFlow;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::TryStreamExt;
use futures_util::lock::Mutex;
use hickory_proto::h3::{H3ClientStream, H3ClientStreamBuilder};
use hickory_proto::op::Message;
use hickory_proto::xfer::{DnsRequest, DnsRequestOptions, DnsRequestSender, DnsResponse};
use rand::prelude::IteratorRandom;
use rand::thread_rng;
use rustls::{ClientConfig, RootCertStore};
use tokio::time::timeout;
use tracing::{error, instrument};

use crate::backend::Backend;
use crate::retry::retry;

#[derive(Debug, Clone)]
pub struct H3Backend {
    inner: Arc<Inner>,
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

        Ok(Self {
            inner: Arc::new(Inner {
                addrs,
                host,
                query_path,
                builder,
                using_h3_client_stream: Default::default(),
            }),
        })
    }
}

#[async_trait]
impl Backend for H3Backend {
    #[instrument(level = "debug", ret, err)]
    async fn send_request(&self, message: Message, _: SocketAddr) -> anyhow::Result<DnsResponse> {
        // FIXME: temporary clone to avoid god damn not Send for &HttpsBackend problem
        let inner = self.inner.clone();

        retry(
            None,
            async move |cx| {
                let mut h3_client_stream = inner.create().await.inspect_err(|err| {
                    error!(%err, "get h3 session failed");
                })?;

                let mut dns_request_options = DnsRequestOptions::default();
                dns_request_options.use_edns = true;
                let mut dns_response_stream = h3_client_stream
                    .send_message(DnsRequest::new(message.clone(), dns_request_options));

                if let Ok(Some(resp)) = dns_response_stream.try_next().await {
                    Ok(resp)
                } else {
                    cx.replace(h3_client_stream);

                    Err(anyhow::anyhow!("try get dns response failed"))
                }
            },
            async |err, cx| {
                if let Some(mut h3_client_stream) = cx.take() {
                    h3_client_stream.shutdown();
                }

                ControlFlow::Continue(err)
            },
            NonZeroUsize::new(3).unwrap(),
            None,
        )
        .await
    }
}

struct Inner {
    addrs: HashSet<SocketAddr>,
    host: String,
    query_path: String,
    builder: H3ClientStreamBuilder,
    using_h3_client_stream: Mutex<Option<H3ClientStream>>,
}

impl Debug for Inner {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inner")
            .field("addrs", &self.addrs)
            .field("host", &self.host)
            .field("using_h3_client_stream", &self.using_h3_client_stream)
            .finish_non_exhaustive()
    }
}

impl Inner {
    #[instrument(level = "debug", err)]
    async fn create(&self) -> anyhow::Result<H3ClientStream> {
        const LOCK_TIMEOUT: Duration = Duration::from_millis(300);

        let h3_client_stream = match timeout(LOCK_TIMEOUT, async {
            let mut using_h3_client_stream = self.using_h3_client_stream.lock().await;
            let using_h3_client_stream_mut = match &mut *using_h3_client_stream {
                None => {
                    let h3_client_stream = self.create_new_h3_client_stream().await?;
                    *using_h3_client_stream = Some(h3_client_stream.clone());

                    return Ok(h3_client_stream);
                }

                Some(using_h3_client_stream) => using_h3_client_stream,
            };

            match using_h3_client_stream_mut.try_next().await {
                Err(_) => {
                    *using_h3_client_stream = None;
                    let h3_client_stream = self.create_new_h3_client_stream().await?;
                    *using_h3_client_stream = Some(h3_client_stream.clone());

                    Ok(h3_client_stream)
                }

                Ok(None) => return self.create_new_h3_client_stream().await,
                Ok(Some(_)) => Ok(using_h3_client_stream_mut.clone()),
            }
        })
        .await
        {
            Err(_) => self.create_new_h3_client_stream().await?,
            Ok(Err(err)) => return Err(err),
            Ok(Ok(h3_client_stream)) => h3_client_stream,
        };

        Ok(h3_client_stream)
    }

    #[instrument(level = "debug", err)]
    async fn create_new_h3_client_stream(&self) -> anyhow::Result<H3ClientStream> {
        let addr = self
            .addrs
            .iter()
            .copied()
            .choose(&mut thread_rng())
            .expect("addrs must not empty");

        let mut h3_client_stream = self
            .builder
            .clone()
            .build(addr, self.host.clone(), self.query_path.clone())
            .await?;

        h3_client_stream
            .try_next()
            .await?
            .ok_or_else(|| anyhow::anyhow!("h3 stream connected but closed immediately"))?;

        Ok(h3_client_stream)
    }
}
