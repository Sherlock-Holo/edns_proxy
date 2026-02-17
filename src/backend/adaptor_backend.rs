use std::fmt::{Debug, Formatter};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use futures_util::{Stream, StreamExt};
use hickory_proto::DnsHandle;
use hickory_proto::op::Message;
use hickory_proto::runtime::TokioTime;
use hickory_proto::xfer::{
    DnsExchange, DnsRequest, DnsRequestOptions, DnsRequestSender, DnsResponse, DnsResponseStream,
    FirstAnswer,
};
use hickory_proto::{ProtoError, RetryDnsHandle};
use tokio::sync::{Mutex, Notify, RwLock};
use tracing::{error, instrument};

use crate::backend::{Backend, DynBackend};
use crate::utils::TimeoutExt;

const BUILD_TIMEOUT: Duration = Duration::from_secs(10);

pub struct BoxDnsRequestSender(Pin<Box<dyn DnsRequestSender + 'static + Send + Unpin>>);

impl Stream for BoxDnsRequestSender {
    type Item = Result<(), ProtoError>;

    #[inline]
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.0.poll_next_unpin(cx)
    }
}

impl DnsRequestSender for BoxDnsRequestSender {
    #[inline]
    fn send_message(&mut self, request: DnsRequest) -> DnsResponseStream {
        self.0.as_mut().send_message(request)
    }

    #[inline]
    fn shutdown(&mut self) {
        self.0.as_mut().shutdown()
    }

    #[inline]
    fn is_shutdown(&self) -> bool {
        self.0.as_ref().is_shutdown()
    }
}

impl BoxDnsRequestSender {
    pub fn new(sender: impl DnsRequestSender + 'static) -> Self {
        BoxDnsRequestSender(Box::pin(sender))
    }
}

#[async_trait]
pub trait DnsRequestSenderBuild {
    async fn build(&self) -> anyhow::Result<BoxDnsRequestSender>;
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

        let (exchange, background_task) =
            DnsExchange::from_stream::<_, TokioTime>(dns_request_sender);
        tokio::spawn(background_task);

        Ok(Self {
            inner: Arc::new(Inner {
                builder: Box::new(builder),
                exchange: RwLock::new(RetryDnsHandle::new(exchange, attempts)),
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
        loop {
            match self.inner.do_query(message.clone()).await {
                Ok(resp) => return Ok(resp),
                Err(_) => {
                    self.inner.ensure_rebuilt(self.attempts).await?;
                }
            }
        }
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
    exchange: RwLock<RetryDnsHandle<DnsExchange>>,
    rebuild: Mutex<RebuildCoordinator>,
    rebuild_done: Notify,
}

impl Debug for Inner {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GenericBackend").finish_non_exhaustive()
    }
}

impl Inner {
    async fn update_exchange(&self, attempts: usize) -> anyhow::Result<()> {
        let sender = self.builder.build().timeout(BUILD_TIMEOUT).await??;

        let (exchange, background_task) = DnsExchange::from_stream::<_, TokioTime>(sender);
        tokio::spawn(background_task);

        *self.exchange.write().await = RetryDnsHandle::new(exchange, attempts);

        Ok(())
    }

    /// Ensure connection is rebuilt. If someone is rebuilding, wait; otherwise perform the rebuild.
    /// When rebuild fails, one of the waiters will compete and rebuild again until success or return an error.
    async fn ensure_rebuilt(&self, attempts: usize) -> anyhow::Result<()> {
        loop {
            let build_by_me = {
                let mut guard = self.rebuild.lock().await;
                if !guard.in_progress {
                    guard.in_progress = true;
                    true
                } else {
                    false
                }
            };

            if build_by_me {
                let result = self.update_exchange(attempts).await;
                let result_for_waiters = result
                    .as_ref()
                    .map(|_| ())
                    .map_err(|e| anyhow::anyhow!("{}", e));
                {
                    let mut guard = self.rebuild.lock().await;
                    guard.in_progress = false;
                    guard.result = result_for_waiters;
                }
                self.rebuild_done.notify_waiters();
                return result;
            }

            self.rebuild_done.notified().await;

            match &self.rebuild.lock().await.result {
                Ok(()) => return Ok(()),

                Err(err) => {
                    error!(%err, "other people rebuild failed");
                }
            }
        }
    }

    #[instrument(skip(self), ret, err)]
    async fn do_query(&self, message: Message) -> anyhow::Result<DnsResponse> {
        let mut options = DnsRequestOptions::default();
        options.use_edns = true;
        let request = DnsRequest::new(message, options);
        let exchange = self.exchange.read().await;
        let response = exchange.clone().send(request).first_answer().await?;

        Ok(response)
    }
}
