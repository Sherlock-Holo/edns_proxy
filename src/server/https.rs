use std::convert::Infallible;
use std::fmt::Debug;
use std::future::{Ready, ready};
use std::io;
use std::net::SocketAddr;
use std::pin::pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::Context;
use axum::Router;
use axum::body::Body;
use axum::extract::{Extension, Request, State};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use compio::net::{TcpListener, TcpStream};
use compio::tls::{TlsAcceptor, TlsStream};
use cyper_axum::Listener;
use futures_util::future::LocalBoxFuture;
use futures_util::stream::FuturesUnordered;
use futures_util::{FutureExt, StreamExt, select};
use hickory_proto26::op::Message;
use http::{Request as HttpRequest, StatusCode};
use http_body_util::{BodyExt, Limited};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use send_wrapper::SendWrapper;
use tower::Service;
use tower_http::trace::TraceLayer;
use tracing::{error, instrument};

use crate::backend::backend2::DynBackend;

struct HttpError(anyhow::Error);

impl From<anyhow::Error> for HttpError {
    fn from(e: anyhow::Error) -> Self {
        HttpError(e)
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::new(self.0.to_string()))
            .unwrap()
    }
}

#[derive(Clone, Debug)]
struct PeerAddrMakeService<S> {
    inner: S,
}

impl<S> PeerAddrMakeService<S> {
    fn new(inner: S) -> Self {
        Self { inner }
    }
}

#[derive(Clone, Debug)]
struct PeerAddrService<S> {
    inner: S,
    remote_addr: SocketAddr,
}

impl<ReqBody, S> Service<HttpRequest<ReqBody>> for PeerAddrService<S>
where
    S: Service<HttpRequest<ReqBody>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: HttpRequest<ReqBody>) -> Self::Future {
        req.extensions_mut().insert(self.remote_addr);
        self.inner.call(req)
    }
}

pub struct HttpsServer {
    tls_acceptor: TlsAcceptor,
    tcp_listener: TcpListener,
    path: String,
    backend: Rc<dyn DynBackend>,
    timeout: Option<Duration>,
}

impl Debug for HttpsServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpsServer")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl HttpsServer {
    pub async fn new(
        addr: SocketAddr,
        certificate: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
        path: String,
        backend: Rc<dyn DynBackend>,
        timeout: Option<Duration>,
    ) -> anyhow::Result<HttpsServer> {
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certificate, private_key)?;

        let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));
        let tcp_listener = TcpListener::bind(addr).await?;

        Ok(Self {
            tls_acceptor,
            tcp_listener,
            path,
            backend,
            timeout,
        })
    }

    #[inline]
    async fn handle(
        Extension(src): Extension<SocketAddr>,
        backend: State<SendWrapper<Rc<dyn DynBackend>>>,
        req: Request,
    ) -> Result<Response, HttpError> {
        HttpsServer::do_handle(req, src, backend)
            .await
            .map_err(Into::into)
    }

    #[instrument(skip(backend), ret, err)]
    async fn do_handle(
        req: Request,
        src: SocketAddr,
        backend: State<SendWrapper<Rc<dyn DynBackend>>>,
    ) -> anyhow::Result<Response> {
        let body = Limited::new(req.into_body(), 4096)
            .collect()
            .await
            .map_err(|err| anyhow::Error::msg(err.to_string()))?
            .to_bytes();

        let message = Message::from_vec(&body).with_context(|| "parse dns message failed")?;

        let dns_response = SendWrapper::new(backend.dyn_send_request(message, src)).await?;

        Ok(Response::new(Body::from(dns_response.into_buffer())))
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let router = Router::new()
            .route(&self.path, post(Self::handle))
            .layer(TraceLayer::new_for_http())
            .with_state(SendWrapper::new(self.backend));

        let tls_listener = TlsListener {
            tls_acceptor: self.tls_acceptor,
            tcp_listener: self.tcp_listener,
            tls_accept_futs: Default::default(),
        };

        cyper_axum::serve(tls_listener, PeerAddrMakeService::new(router)).await?;

        Err(anyhow::anyhow!("https server stopped unexpectedly"))
    }
}

impl<S> Service<cyper_axum::IncomingStream<'_, TlsListener>> for PeerAddrMakeService<S>
where
    S: Clone,
{
    type Response = PeerAddrService<S>;
    type Error = Infallible;
    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, stream: cyper_axum::IncomingStream<'_, TlsListener>) -> Self::Future {
        ready(Ok(PeerAddrService {
            inner: self.inner.clone(),
            remote_addr: *stream.remote_addr(),
        }))
    }
}

type TlsAcceptFuture =
    LocalBoxFuture<'static, Result<(TlsStream<TcpStream>, SocketAddr), io::Error>>;

struct TlsListener {
    tls_acceptor: TlsAcceptor,
    tcp_listener: TcpListener,
    tls_accept_futs: FuturesUnordered<TlsAcceptFuture>,
}

impl TlsListener {
    #[instrument(skip(self))]
    fn push_accept_tls_fut(&self, tcp_stream: TcpStream, peer_addr: SocketAddr) {
        let tls_acceptor = self.tls_acceptor.clone();
        self.tls_accept_futs.push(
            async move {
                let tls_stream = tls_acceptor
                    .accept(tcp_stream)
                    .await
                    .inspect_err(|err| error!(%err, "tls accept failed"))?;

                Ok::<_, io::Error>((tls_stream, peer_addr))
            }
            .boxed_local(),
        );
    }
}

impl Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        let tcp_listener = &self.tcp_listener;
        let mut accept_fut = pin!(tcp_listener.accept().fuse());
        loop {
            if self.tls_accept_futs.is_empty() {
                let (tcp_stream, peer_addr) = match accept_fut.as_mut().await {
                    Err(err) => {
                        error!(%err, "accept new tcp stream failed");

                        accept_fut.set(tcp_listener.accept().fuse());
                        continue;
                    }

                    Ok((tcp_stream, peer_addr)) => (tcp_stream, peer_addr),
                };

                accept_fut.set(tcp_listener.accept().fuse());
                self.push_accept_tls_fut(tcp_stream, peer_addr);
            }

            select! {
                res = self.tls_accept_futs.next() => {
                    if let Some(Ok(res)) = res {
                        return res
                    }
                }

                res = accept_fut.as_mut() => {
                    accept_fut.set(tcp_listener.accept().fuse());

                    match res {
                        Err(err) => {
                            error!(%err, "accept new tcp stream failed");
                        }

                        Ok((tcp_stream, peer_addr)) => {
                            self.push_accept_tls_fut(tcp_stream, peer_addr);
                        }
                    }
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.tcp_listener.local_addr()
    }
}
