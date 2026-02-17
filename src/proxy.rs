use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_notify::Notify;
use async_trait::async_trait;
use futures_util::FutureExt;
use hickory_proto::op::{Header, Message, ResponseCode};
use hickory_proto::rr::Record;
use hickory_proto::xfer::DnsResponse;
use hickory_server::ServerFuture;
use hickory_server::authority::{MessageResponse, MessageResponseBuilder};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use rustls::ServerConfig;
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use socket2::{Domain, SockAddr, Socket, Type};
use tokio::net::{TcpListener, TcpSocket, UdpSocket};
use tracing::{error, info, instrument};

use crate::addr::BindAddr;
use crate::backend::Backend;
use crate::cache::Cache;
use crate::route::Route;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Socket or listener created with SO_REUSEPORT for per-core binding.
#[derive(Debug)]
pub enum BindSocket {
    Udp(UdpSocket),
    Tcp(TcpListener),
}

/// Creates a UDP socket bound to `addr` with SO_REUSEPORT.
pub fn create_udp_socket_reuse_port(addr: SocketAddr) -> anyhow::Result<UdpSocket> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, None)?;
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&SockAddr::from(addr))?;
    let std_socket = std::net::UdpSocket::from(socket);

    Ok(UdpSocket::from_std(std_socket)?)
}

/// Creates a TCP listener bound to `addr` with SO_REUSEPORT.
pub fn create_tcp_listener_reuse_port(addr: SocketAddr) -> anyhow::Result<TcpListener> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    socket.set_reuseport(true)?;
    socket.bind(addr)?;

    Ok(socket.listen(1024)?)
}

pub struct ProxyTask {
    server: ServerFuture<DnsHandler>,
}

impl ProxyTask {
    /// Run the server until it completes or shutdown is requested via the Notify.
    pub async fn run_until_shutdown(mut self, shutdown: Arc<Notify>) -> anyhow::Result<()> {
        let token = self.server.shutdown_token().clone();
        let server_future = self.server.block_until_done();

        futures_util::select! {
            res = server_future.fuse() => res.map_err(Into::into),

            _ = shutdown.notified().fuse() => {
                token.cancel();

                Ok(())
            }
        }
    }
}

/// Starts proxy with a pre-created socket (SO_REUSEPORT). Used for per-core workers.
#[instrument(err)]
pub async fn start_proxy_with_socket<B: Backend + Send + Sync + 'static>(
    bind_addr: Arc<BindAddr>,
    socket: BindSocket,
    route: Arc<Route>,
    default_backend: B,
    cache: Option<Cache>,
) -> anyhow::Result<ProxyTask> {
    let mut server = ServerFuture::new(DnsHandler {
        cache,
        default_backend: Box::new(default_backend),
        route,
    });

    match (&*bind_addr, socket) {
        (BindAddr::Udp(_), BindSocket::Udp(udp_socket)) => {
            server.register_socket(udp_socket);
        }

        (BindAddr::Tcp { timeout, .. }, BindSocket::Tcp(tcp_listener)) => {
            server.register_listener(
                tcp_listener,
                timeout.as_ref().copied().unwrap_or(DEFAULT_TIMEOUT),
            );
        }

        (
            BindAddr::Https {
                certificate,
                private_key,
                domain,
                path,
                timeout,
                ..
            },
            BindSocket::Tcp(tcp_listener),
        ) => {
            server.register_https_listener(
                tcp_listener,
                timeout.as_ref().copied().unwrap_or(DEFAULT_TIMEOUT),
                Arc::new(SingleCertAndKey::from(CertifiedKey::from_der(
                    certificate.clone(),
                    private_key.clone_key(),
                    &rustls::crypto::aws_lc_rs::default_provider(),
                )?)),
                domain.clone(),
                path.clone(),
            )?;
        }

        (
            BindAddr::Tls {
                certificate,
                private_key,
                timeout,
                ..
            },
            BindSocket::Tcp(tcp_listener),
        ) => {
            let server_config = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certificate.clone(), private_key.clone_key())?;
            server.register_tls_listener_with_tls_config(
                tcp_listener,
                timeout.as_ref().copied().unwrap_or(DEFAULT_TIMEOUT),
                Arc::new(server_config),
            )?;
        }

        (
            BindAddr::Quic {
                certificate,
                private_key,
                timeout,
                ..
            },
            BindSocket::Udp(udp_socket),
        ) => {
            server.register_quic_listener(
                udp_socket,
                timeout.as_ref().copied().unwrap_or(DEFAULT_TIMEOUT),
                Arc::new(SingleCertAndKey::from(CertifiedKey::from_der(
                    certificate.clone(),
                    private_key.clone_key(),
                    &rustls::crypto::aws_lc_rs::default_provider(),
                )?)),
                None,
            )?;
        }

        (
            BindAddr::H3 {
                certificate,
                private_key,
                timeout,
                ..
            },
            BindSocket::Udp(udp_socket),
        ) => {
            server.register_h3_listener(
                udp_socket,
                timeout.as_ref().copied().unwrap_or(DEFAULT_TIMEOUT),
                Arc::new(SingleCertAndKey::from(CertifiedKey::from_der(
                    certificate.clone(),
                    private_key.clone_key(),
                    &rustls::crypto::aws_lc_rs::default_provider(),
                )?)),
                None,
            )?;
        }

        _ => {
            return Err(anyhow::anyhow!(
                "bind_addr and socket type mismatch: Udp/Quic/H3 need UdpSocket, Tcp/Https/Tls need TcpListener"
            ));
        }
    }

    info!("proxy starting...");

    Ok(ProxyTask { server })
}

/// Returns the socket type needed for the given BindAddr.
pub fn socket_type_for_bind(bind_addr: &BindAddr) -> SocketType {
    match bind_addr {
        BindAddr::Udp(_) => SocketType::Udp,
        BindAddr::Tcp { .. } | BindAddr::Https { .. } | BindAddr::Tls { .. } => SocketType::Tcp,
        BindAddr::Quic { .. } | BindAddr::H3 { .. } => SocketType::Udp,
    }
}

/// Socket type required for a BindAddr variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketType {
    Udp,
    Tcp,
}

impl BindAddr {
    /// Returns the address to bind for this BindAddr.
    pub fn addr(&self) -> SocketAddr {
        match self {
            BindAddr::Udp(addr)
            | BindAddr::Tcp { addr, .. }
            | BindAddr::Https { addr, .. }
            | BindAddr::Tls { addr, .. }
            | BindAddr::Quic { addr, .. }
            | BindAddr::H3 { addr, .. } => *addr,
        }
    }
}

#[derive(Debug)]
struct DnsHandler {
    cache: Option<Cache>,
    default_backend: Box<dyn Backend + Send + Sync>,
    route: Arc<Route>,
}

#[async_trait]
impl RequestHandler for DnsHandler {
    #[instrument(skip(response_handle), ret)]
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        let resp_result = if let Some(resp) = self.try_get_cache_response(request).await {
            Ok(resp)
        } else {
            self.send_request(request).await
        };

        match resp_result {
            Err(err) => {
                error!(%err, "send dns request to backend failed");

                let err_resp = MessageResponseBuilder::from_message_request(request)
                    .error_msg(request.header(), ResponseCode::ServFail);

                Self::send_resp(request, response_handle, err_resp).await
            }

            Ok(resp) => {
                let builder = MessageResponseBuilder::from_message_request(request);
                let resp_message = resp.into_message();

                info!(%resp_message, "get dns response done");

                let mut resp_parts = resp_message.into_parts();
                resp_parts.header.set_id(request.id());

                let resp = builder.build(
                    resp_parts.header,
                    &resp_parts.answers,
                    &resp_parts.name_servers,
                    [],
                    &resp_parts.additionals,
                );

                Self::send_resp(request, response_handle, resp).await
            }
        }
    }
}

impl DnsHandler {
    #[instrument]
    async fn send_request(&self, request: &Request) -> anyhow::Result<DnsResponse> {
        let query = request
            .queries()
            .first()
            .ok_or_else(|| anyhow::anyhow!("no query found"))?;

        let backend = self
            .route
            .get_backend(query.original().name())
            .unwrap_or(self.default_backend.as_ref());

        let src_addr = request.src();
        let message = self.extract_message(request);

        let response = backend.send_request(message, src_addr).await?;

        if let Some(cache) = &self.cache
            && let Some(query) = request.queries().first()
        {
            cache
                .put_cache_response(query.original().clone(), src_addr.ip(), response.clone())
                .await;
        }

        Ok(response)
    }

    async fn send_resp<'a, R: ResponseHandler>(
        request: &Request,
        mut response_handle: R,
        resp: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> ResponseInfo {
        response_handle
            .send_response(resp)
            .await
            .unwrap_or_else(|_| {
                let mut header = Header::new();
                header.set_id(request.id());
                header.set_response_code(ResponseCode::ServFail);

                ResponseInfo::from(header)
            })
    }

    fn extract_message(&self, request: &Request) -> Message {
        let mut message = Message::new();
        message.set_header(*request.header());
        message.set_id(request.id());
        message.set_message_type(request.message_type());
        message.set_op_code(request.op_code());
        message.add_queries(
            request
                .queries()
                .iter()
                .map(|query| query.original().clone()),
        );
        message.answers_mut().extend_from_slice(request.answers());
        message
            .name_servers_mut()
            .extend_from_slice(request.name_servers());
        message
            .additionals_mut()
            .extend_from_slice(request.additionals());

        // disable dnssec until hickory dns fix compile error
        /*for record in request.sig0() {
            message.add_sig0(record.clone());
        }*/

        message
    }

    async fn try_get_cache_response(&self, request: &Request) -> Option<DnsResponse> {
        let cache = self.cache.as_ref()?;

        cache
            .get_cache_response(
                request.queries().first()?.original().clone(),
                request.src().ip(),
            )
            .await
    }
}
