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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::backend::tests::{check_dns_response, create_query_message};
    use crate::backend::{AdaptorBackend, Backend};

    #[tokio::test]
    async fn test() {
        let https_builder = UdpBuilder::new(
            ["119.28.28.28:53".parse().unwrap()].into(),
            Duration::from_secs(5).into(),
        );

        let generic_backend = AdaptorBackend::new(https_builder, 3).await.unwrap();

        let dns_response = generic_backend
            .send_request(
                create_query_message(),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234),
            )
            .await
            .unwrap();

        check_dns_response(&dns_response);
    }
}
