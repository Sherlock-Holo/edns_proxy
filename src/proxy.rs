use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hickory_proto::op::{Edns, Header, Message, ResponseCode};
use hickory_proto::rr::Record;
use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};
use hickory_proto::xfer::DnsResponse;
use hickory_server::ServerFuture;
use hickory_server::authority::{MessageResponse, MessageResponseBuilder};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use rustls::ServerConfig;
use tokio::net::{TcpListener, UdpSocket};
use tracing::{error, info, instrument};

use crate::addr::BindAddr;
use crate::backend::{Backend, ExtensionBackend};
use crate::cache::Cache;
use crate::route::Route;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

pub struct ProxyTask {
    server: ServerFuture<DnsHandler>,
}

impl ProxyTask {
    pub async fn stop(&mut self) -> anyhow::Result<()> {
        Ok(self.server.shutdown_gracefully().await?)
    }
}

#[instrument(err)]
pub async fn start_proxy(
    bind_addr: BindAddr,
    ipv4_source_prefix: u8,
    ipv6_source_prefix: u8,
    route: Route,
    default_backend: ExtensionBackend,
    cache: Option<NonZeroUsize>,
) -> anyhow::Result<ProxyTask> {
    let mut server = ServerFuture::new(DnsHandler {
        cache: cache.map(Cache::new),
        default_backend,
        route,
        ipv4_source_prefix,
        ipv6_source_prefix,
    });

    match bind_addr {
        BindAddr::Udp(addr) => {
            let udp_socket = UdpSocket::bind(addr).await?;
            server.register_socket(udp_socket);
        }

        BindAddr::Tcp { addr, timeout } => {
            let tcp_listener = TcpListener::bind(addr).await?;
            server.register_listener(tcp_listener, timeout.unwrap_or(DEFAULT_TIMEOUT));
        }

        BindAddr::Https {
            addr,
            certificate,
            private_key,
            domain,
            path,
            timeout,
        } => {
            let tcp_listener = TcpListener::bind(addr).await?;
            server.register_https_listener(
                tcp_listener,
                timeout.unwrap_or(DEFAULT_TIMEOUT),
                (certificate, private_key),
                domain,
                path,
            )?;
        }

        BindAddr::Tls {
            addr,
            certificate,
            private_key,
            timeout,
        } => {
            let tcp_listener = TcpListener::bind(addr).await?;

            let server_config = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certificate, private_key)?;

            server.register_tls_listener_with_tls_config(
                tcp_listener,
                timeout.unwrap_or(DEFAULT_TIMEOUT),
                Arc::new(server_config),
            )?;
        }

        BindAddr::Quic {
            addr,
            certificate,
            private_key,
            timeout,
        } => {
            let udp_socket = UdpSocket::bind(addr).await?;
            server.register_quic_listener(
                udp_socket,
                timeout.unwrap_or(DEFAULT_TIMEOUT),
                (certificate, private_key),
                None,
            )?;
        }

        BindAddr::H3 {
            addr,
            certificate,
            private_key,
            timeout,
        } => {
            let udp_socket = UdpSocket::bind(addr).await?;
            server.register_h3_listener(
                udp_socket,
                timeout.unwrap_or(DEFAULT_TIMEOUT),
                (certificate, private_key),
                None,
            )?;
        }
    }

    info!("proxy starting...");

    Ok(ProxyTask { server })
}

#[derive(Debug)]
struct DnsHandler {
    cache: Option<Cache>,
    default_backend: ExtensionBackend,
    route: Route,
    ipv4_source_prefix: u8,
    ipv6_source_prefix: u8,
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
                let mut resp_parts = resp.into_message().into_parts();
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
        let src_addr = request.src();
        let message = self.extract_message(request, src_addr);

        let backend = self
            .route
            .get_backend(&request.query().original().name().to_string())
            .unwrap_or(&self.default_backend);

        let response = backend.send_request(message, src_addr).await?;

        if let Some(cache) = &self.cache {
            let src_ip = src_addr.ip();
            let prefix = match src_ip {
                IpAddr::V4(_) => self.ipv4_source_prefix,
                IpAddr::V6(_) => self.ipv6_source_prefix,
            };

            cache
                .put_cache_response(
                    request.query().original().clone(),
                    src_ip,
                    prefix,
                    response.clone(),
                )
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

    fn extract_message(&self, request: &Request, src_addr: SocketAddr) -> Message {
        let mut message = Message::new();
        message.set_header(*request.header());
        message.set_id(request.id());
        message.set_message_type(request.message_type());
        message.set_op_code(request.op_code());
        message.add_queries([request.query().original().clone()]);
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

        let extensions = message.extensions_mut();
        if let Some(edns) = request.edns() {
            *extensions = Some(edns.clone());
        }

        let opt = extensions.get_or_insert_with(Edns::new).options_mut();
        if opt.get(EdnsCode::Subnet).is_none() {
            let src_ip = src_addr.ip();
            let prefix = match src_ip {
                IpAddr::V4(_) => self.ipv4_source_prefix,
                IpAddr::V6(_) => self.ipv6_source_prefix,
            };

            opt.insert(EdnsOption::Subnet(ClientSubnet::new(src_ip, prefix, 0)));
        }

        message
    }

    async fn try_get_cache_response(&self, request: &Request) -> Option<DnsResponse> {
        let cache = self.cache.as_ref()?;

        let query = request.query().original();
        let src_ip = request.src().ip();
        let prefix = match src_ip {
            IpAddr::V4(_) => self.ipv4_source_prefix,
            IpAddr::V6(_) => self.ipv6_source_prefix,
        };

        cache
            .get_cache_response(query.clone(), src_ip, prefix)
            .await
    }
}
