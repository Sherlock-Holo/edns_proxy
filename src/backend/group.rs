use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use futures_util::lock::Mutex;
use hickory_proto::op::Message;
use hickory_proto::xfer::DnsResponse;
use rand::distributions::WeightedIndex;
use rand::prelude::*;

use crate::backend::Backend;

#[derive(Debug)]
pub struct Group {
    backends: Vec<Arc<dyn Backend + Send + Sync>>,
    weighted_index: Mutex<WeightedIndex<usize>>,
}

impl Group {
    pub fn new(backends: Vec<(usize, Arc<dyn Backend + Send + Sync>)>) -> Self {
        let weight_iter = backends.iter().map(|(weight, _)| *weight);
        let weighted_index = WeightedIndex::new(weight_iter).unwrap();

        Self {
            backends: backends.into_iter().map(|(_, backend)| backend).collect(),
            weighted_index: Mutex::new(weighted_index),
        }
    }
}

#[async_trait]
impl Backend for Group {
    async fn send_request(&self, message: Message, src: SocketAddr) -> anyhow::Result<DnsResponse> {
        let index = self.weighted_index.lock().await.sample(&mut thread_rng());

        self.backends[index].send_request(message, src).await
    }
}
