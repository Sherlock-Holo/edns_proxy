use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::TryStreamExt;
use hickory_proto::op::Message;
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::udp::UdpClientStream;
use hickory_proto::xfer::{
    DnsRequest, DnsRequestOptions, DnsRequestSender, DnsResponse, FirstAnswer,
};
use rand::prelude::*;
use rand::rng;
use tracing::instrument;

use crate::backend::Backend;

#[derive(Debug)]
pub struct UdpBackend {
    addrs: Arc<HashSet<SocketAddr>>,
    timeout: Option<Duration>,
}

impl UdpBackend {
    pub fn new(addrs: HashSet<SocketAddr>, timeout: Option<Duration>) -> Self {
        Self {
            addrs: Arc::new(addrs),
            timeout,
        }
    }

    #[instrument(skip(self), ret, err)]
    async fn do_send(&self, message: Message) -> anyhow::Result<DnsResponse> {
        let addr = self
            .addrs
            .iter()
            .choose(&mut rng())
            .expect("addrs must not empty");

        let mut udp_client_stream = UdpClientStream::builder(*addr, TokioRuntimeProvider::new())
            .with_timeout(self.timeout)
            .build()
            .await?;

        udp_client_stream
            .try_next()
            .await?
            .ok_or_else(|| anyhow::anyhow!("udp stream connected but closed immediately"))?;

        let mut options = DnsRequestOptions::default();
        options.use_edns = true;
        let request = DnsRequest::new(message, options);
        let dns_response = udp_client_stream
            .send_message(request)
            .first_answer()
            .await?;

        Ok(dns_response)
    }
}

#[async_trait]
impl Backend for UdpBackend {
    #[instrument(skip(self), ret, err)]
    async fn send_request(
        &self,
        message: Message,
        _src: SocketAddr,
    ) -> anyhow::Result<DnsResponse> {
        let r = self.do_send(message.clone()).await;
        if r.is_ok() {
            return r;
        }
        self.do_send(message).await
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::backend::tests::{check_dns_response, create_query_message};

    #[tokio::test]
    async fn test() {
        let backend = UdpBackend::new(
            ["119.28.28.28:53".parse().unwrap()].into(),
            Duration::from_secs(5).into(),
        );

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
