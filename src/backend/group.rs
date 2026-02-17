use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use hickory_proto::op::Message;
use hickory_proto::xfer::DnsResponse;

use crate::backend::{Backend, DynBackend};
use crate::wrr::SmoothWeight;

#[derive(Clone)]
pub struct Group {
    backends: Arc<Mutex<SmoothWeight<DynBackend>>>,
}

impl Debug for Group {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Group").finish_non_exhaustive()
    }
}

impl Group {
    pub fn new(backends: Vec<(usize, DynBackend)>) -> Self {
        let backends =
            backends
                .into_iter()
                .fold(SmoothWeight::new(), |mut backends, (weight, backend)| {
                    backends.add(backend, weight as _);

                    backends
                });

        Self {
            backends: Arc::new(Mutex::new(backends)),
        }
    }
}

#[async_trait]
impl Backend for Group {
    async fn send_request(&self, message: Message, src: SocketAddr) -> anyhow::Result<DnsResponse> {
        let backend = self
            .backends
            .lock()
            .unwrap()
            .next()
            .expect("backends must not empty");

        backend.send_request(message, src).await
    }

    fn to_dyn_clone(&self) -> DynBackend {
        Box::new(self.clone())
    }
}
