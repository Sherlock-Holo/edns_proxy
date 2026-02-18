use std::fmt::{Debug, Formatter};
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_notify::Notify;
use async_trait::async_trait;
use futures_util::TryStreamExt;
use hickory_proto::op::Message;
use hickory_proto::xfer::{
    DnsRequest, DnsRequestOptions, DnsRequestSender, DnsResponse, FirstAnswer,
};
use tokio::sync::RwLock;
use tracing::{error, instrument};

use crate::backend::{Backend, DynBackend};
use crate::utils::TimeoutExt;

const BUILD_TIMEOUT: Duration = Duration::from_secs(10);

pub struct DynDnsRequestSender {
    inner: Box<dyn ToDynDnsRequestSender>,
}

impl DynDnsRequestSender {
    #[inline]
    pub fn new_with_clone<S: DnsRequestSender + Clone + Sync>(sender: S) -> Self {
        Self {
            inner: Box::new(sender),
        }
    }

    #[inline]
    pub fn new<S: ToDynDnsRequestSender>(sender: S) -> Self {
        Self {
            inner: Box::new(sender),
        }
    }
}

#[async_trait]
pub trait DnsRequestSenderBuild {
    async fn build(&self) -> anyhow::Result<DynDnsRequestSender>;
}

#[derive(Debug, Clone)]
pub struct AdaptorBackend {
    inner: Arc<Inner>,
    attempts: usize,
}

impl AdaptorBackend {
    pub async fn new(
        builder: impl DnsRequestSenderBuild + Sync + Send + 'static,
        attempts: usize,
    ) -> anyhow::Result<Self> {
        let dns_request_sender = builder.build().await?;

        Ok(Self {
            inner: Arc::new(Inner {
                builder: Box::new(builder),
                dyn_sender: RwLock::new(dns_request_sender),
                rebuild: Mutex::new(RebuildCoordinator {
                    in_progress: false,
                    result: Ok(()), // make it ok when init
                }),
                rebuild_done: Notify::new(),
            }),
            attempts,
        })
    }
}

#[async_trait]
impl Backend for AdaptorBackend {
    #[instrument(skip(self), ret, err)]
    async fn send_request(
        &self,
        message: Message,
        _src: SocketAddr,
    ) -> anyhow::Result<DnsResponse> {
        for _ in 0..self.attempts {
            match self.inner.do_query(message.clone()).await {
                Ok(resp) => return Ok(resp),
                Err(_) => {
                    self.inner.ensure_rebuilt().await?;
                }
            }
        }

        Err(anyhow::anyhow!(
            "send request failed {} times",
            self.attempts
        ))
    }

    fn to_dyn_clone(&self) -> DynBackend {
        Box::new(self.clone())
    }
}

/// Coordinates concurrent rebuild: only one task rebuilds at a time, others wait;
/// if rebuild fails, one of the waiters continues.
struct RebuildCoordinator {
    /// Whether someone is currently rebuilding
    in_progress: bool,
    /// Result after rebuild completes, for waiters to read
    result: anyhow::Result<()>,
}

struct Inner {
    builder: Box<dyn DnsRequestSenderBuild + Sync + Send + 'static>,
    dyn_sender: RwLock<DynDnsRequestSender>,
    rebuild: Mutex<RebuildCoordinator>,
    rebuild_done: Notify,
}

impl Debug for Inner {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GenericBackend").finish_non_exhaustive()
    }
}

impl Inner {
    #[instrument(skip(self), ret, err)]
    async fn update_exchange(&self) -> anyhow::Result<()> {
        let sender = self.builder.build().timeout(BUILD_TIMEOUT).await??;

        *self.dyn_sender.write().await = sender;

        Ok(())
    }

    /// Ensure connection is rebuilt. If someone is rebuilding, wait; otherwise perform the rebuild.
    /// When rebuild fails, one of the waiters will compete and rebuild again until success or
    /// return an error.
    #[instrument(skip(self), ret, err)]
    async fn ensure_rebuilt(&self) -> anyhow::Result<()> {
        loop {
            let build_by_me = {
                let mut guard = self.rebuild.lock().unwrap();
                if !guard.in_progress {
                    guard.in_progress = true;
                    true
                } else {
                    false
                }
            };

            if build_by_me {
                let result = self.update_exchange().await;
                let result_for_waiters = result
                    .as_ref()
                    .map(|_| ())
                    .map_err(|e| anyhow::anyhow!("{}", e));
                {
                    let mut guard = self.rebuild.lock().unwrap();
                    guard.in_progress = false;
                    guard.result = result_for_waiters;
                }
                self.rebuild_done
                    .notify_waiters(NonZeroUsize::new(usize::MAX).unwrap());

                return result;
            }

            self.rebuild_done.notified().await;

            match &self.rebuild.lock().unwrap().result {
                Ok(()) => return Ok(()),

                Err(err) => {
                    error!(%err, "other people rebuild failed");
                }
            }
        }
    }

    #[instrument(skip(self), ret, err)]
    async fn do_query(&self, message: Message) -> anyhow::Result<DnsResponse> {
        let mut sender = self
            .dyn_sender
            .read()
            .await
            .inner
            .to_dyn_dns_request_sender()
            .await?;

        sender
            .try_next()
            .await?
            .ok_or_else(|| anyhow::anyhow!("sender dropped"))?;

        let mut options = DnsRequestOptions::default();
        options.use_edns = true;
        let request = DnsRequest::new(message, options);
        let dns_response = sender.send_message(request).first_answer().await?;

        Ok(dns_response)
    }
}

#[async_trait]
pub trait ToDynDnsRequestSender: DnsRequestSender + Sync {
    async fn to_dyn_dns_request_sender(&self) -> anyhow::Result<Box<dyn DnsRequestSender>>;
}

#[async_trait]
impl<T: DnsRequestSender + Clone + Sync> ToDynDnsRequestSender for T {
    async fn to_dyn_dns_request_sender(&self) -> anyhow::Result<Box<dyn DnsRequestSender>> {
        Ok(Box::new(self.clone()))
    }
}
