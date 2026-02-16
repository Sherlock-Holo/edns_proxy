use std::collections::HashSet;
use std::fmt::{Debug, Formatter};
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use futures_util::TryStreamExt;
use hickory_proto::h3::H3ClientStreamBuilder;
use rand::prelude::*;
use rand::rng;
use rustls::{ClientConfig, RootCertStore};

use crate::backend::adaptor_backend::{BoxDnsRequestSender, DnsRequestSenderBuild};

#[derive(Debug, Clone)]
pub struct H3Builder {
    inner: Arc<H3BuilderInner>,
}

impl H3Builder {
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
            inner: Arc::new(H3BuilderInner {
                addrs,
                host,
                query_path,
                builder,
            }),
        })
    }
}

#[async_trait]
impl DnsRequestSenderBuild for H3Builder {
    async fn build(&self) -> anyhow::Result<BoxDnsRequestSender> {
        let addr = self
            .inner
            .addrs
            .iter()
            .copied()
            .choose(&mut rng())
            .expect("addrs must not empty");

        let mut h3_client_stream = self
            .inner
            .builder
            .clone()
            .build(addr, self.inner.host.clone(), self.inner.query_path.clone())
            .await?;

        h3_client_stream
            .try_next()
            .await?
            .ok_or_else(|| anyhow::anyhow!("h3 stream connected but closed immediately"))?;

        Ok(BoxDnsRequestSender::new(h3_client_stream))
    }
}

struct H3BuilderInner {
    addrs: HashSet<SocketAddr>,
    host: String,
    query_path: String,
    builder: H3ClientStreamBuilder,
}

impl Debug for H3BuilderInner {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H3BuilderInner")
            .field("addrs", &self.addrs)
            .field("host", &self.host)
            .field("query_path", &self.query_path)
            .finish_non_exhaustive()
    }
}
