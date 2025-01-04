use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::TryStreamExt;
use hickory_proto::op::Message;
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::udp::UdpClientStream;
use hickory_proto::xfer::{DnsRequest, DnsRequestOptions, DnsRequestSender, DnsResponse};
use rand::prelude::*;
use rand::thread_rng;
use tracing::instrument;

use crate::backend::Backend;

#[derive(Debug, Clone)]
pub struct UdpBackend {
    addrs: HashSet<SocketAddr>,
    timeout: Option<Duration>,
}

impl UdpBackend {
    pub fn new(addrs: HashSet<SocketAddr>, timeout: Option<Duration>) -> Self {
        Self { addrs, timeout }
    }
}

#[async_trait]
impl Backend for UdpBackend {
    #[instrument(level = "debug", ret, err)]
    async fn send_request(&self, message: Message, _: SocketAddr) -> anyhow::Result<DnsResponse> {
        let addr = self
            .addrs
            .iter()
            .choose(&mut thread_rng())
            .expect("addrs must not empty");

        let mut udp_client_stream = UdpClientStream::builder(*addr, TokioRuntimeProvider::new())
            .with_timeout(self.timeout)
            .build()
            .await?;

        let mut dns_request_options = DnsRequestOptions::default();
        dns_request_options.use_edns = true;
        let mut resp_stream =
            udp_client_stream.send_message(DnsRequest::new(message, dns_request_options));

        match resp_stream.try_next().await? {
            None => Err(anyhow::anyhow!("get udp dns response failed")),

            Some(resp) => Ok(resp),
        }
    }
}
