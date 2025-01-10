use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use futures_util::lock::Mutex;
use hickory_proto::op::Message;
use hickory_proto::xfer::DnsResponse;

use crate::backend::Backend;
use crate::wrr::SmoothWeight;

#[derive(Debug)]
pub struct Group {
    backends: Mutex<SmoothWeight<Arc<dyn Backend + Send + Sync>>>,
}

impl Group {
    pub fn new(backends: Vec<(usize, Arc<dyn Backend + Send + Sync>)>) -> Self {
        let backends =
            backends
                .into_iter()
                .fold(SmoothWeight::new(), |mut backends, (weight, backend)| {
                    backends.add(backend, weight as _);

                    backends
                });

        Self {
            backends: Mutex::new(backends),
        }
    }
}

#[async_trait]
impl Backend for Group {
    async fn send_request(&self, message: Message, src: SocketAddr) -> anyhow::Result<DnsResponse> {
        let backend = self
            .backends
            .lock()
            .await
            .next()
            .expect("backends must not empty");

        backend.send_request(message, src).await
    }
}
