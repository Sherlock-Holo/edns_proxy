use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::udp::UdpClientStream;
use rand::prelude::*;
use rand::rng;

use crate::backend::adaptor_backend::{BoxDnsRequestSender, DnsRequestSenderBuild};

#[derive(Debug, Clone)]
pub struct UdpBuilder {
    addrs: Arc<HashSet<SocketAddr>>,
    timeout: Option<Duration>,
}

impl UdpBuilder {
    pub fn new(addrs: HashSet<SocketAddr>, timeout: Option<Duration>) -> Self {
        Self {
            addrs: Arc::new(addrs),
            timeout,
        }
    }
}

#[async_trait]
impl DnsRequestSenderBuild for UdpBuilder {
    async fn build(&self) -> anyhow::Result<BoxDnsRequestSender> {
        let addr = self
            .addrs
            .iter()
            .choose(&mut rng())
            .expect("addrs must not empty");

        let udp_client_stream = UdpClientStream::builder(*addr, TokioRuntimeProvider::new())
            .with_timeout(self.timeout)
            .build()
            .await?;

        Ok(BoxDnsRequestSender::new(udp_client_stream))
    }
}
