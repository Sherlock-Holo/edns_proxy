use std::collections::HashSet;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use futures_util::{Stream, StreamExt};
use hickory_proto::ProtoError;
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::udp::UdpClientStream;
use hickory_proto::xfer::{DnsRequest, DnsRequestSender, DnsResponseStream};
use rand::prelude::*;
use rand::rng;

use crate::backend::adaptor_backend::{
    DnsRequestSenderBuild, DynDnsRequestSender, ToDynDnsRequestSender,
};

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
    async fn build(&self) -> anyhow::Result<DynDnsRequestSender> {
        let addr = self
            .addrs
            .iter()
            .choose(&mut rng())
            .expect("addrs must not empty");

        let udp_client_stream = UdpClientStream::builder(*addr, TokioRuntimeProvider::new())
            .with_timeout(self.timeout)
            .build()
            .await?;

        Ok(DynDnsRequestSender::new(WrapUdpClientStream {
            builder: self.clone(),
            udp_client_stream,
        }))
    }
}

struct WrapUdpClientStream {
    builder: UdpBuilder,
    udp_client_stream: UdpClientStream<TokioRuntimeProvider>,
}

impl Stream for WrapUdpClientStream {
    type Item = Result<(), ProtoError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.udp_client_stream.poll_next_unpin(cx)
    }
}

impl DnsRequestSender for WrapUdpClientStream {
    fn send_message(&mut self, request: DnsRequest) -> DnsResponseStream {
        self.udp_client_stream.send_message(request)
    }

    fn shutdown(&mut self) {
        self.udp_client_stream.shutdown()
    }

    fn is_shutdown(&self) -> bool {
        self.udp_client_stream.is_shutdown()
    }
}

#[async_trait]
impl ToDynDnsRequestSender for WrapUdpClientStream {
    async fn to_dyn_dns_request_sender(&self) -> anyhow::Result<Box<dyn DnsRequestSender>> {
        let addr = self
            .builder
            .addrs
            .iter()
            .choose(&mut rng())
            .expect("addrs must not empty");

        let udp_client_stream = UdpClientStream::builder(*addr, TokioRuntimeProvider::new())
            .with_timeout(self.builder.timeout)
            .build()
            .await?;

        Ok(Box::new(WrapUdpClientStream {
            builder: self.builder.clone(),
            udp_client_stream,
        }))
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
