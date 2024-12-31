use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use async_trait::async_trait;
use hickory_proto::op::{Edns, Header, Message, ResponseCode};
use hickory_proto::rr::Record;
use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};
use hickory_server::ServerFuture;
use hickory_server::authority::{MessageResponse, MessageResponseBuilder};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use tokio::net::{TcpListener, UdpSocket};
use tracing::{error, info};

use crate::addr::BindAddr;
use crate::backend::{Backend, Backends};
use crate::route::Route;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_ENDPOINT: &str = "/dns-query";

pub struct ProxyTask {
    server: ServerFuture<DnsHandler>,
}

impl ProxyTask {
    pub async fn stop(&mut self) -> anyhow::Result<()> {
        Ok(self.server.shutdown_gracefully().await?)
    }
}

pub async fn start_proxy(
    bind_addr: BindAddr,
    ipv4_source_prefix: u8,
    ipv6_source_prefix: u8,
    route: Route,
    default_backend: Backends,
) -> anyhow::Result<ProxyTask> {
    let mut server = ServerFuture::new(DnsHandler {
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
                path.unwrap_or_else(|| DEFAULT_ENDPOINT.to_string()),
            )?;
        }

        BindAddr::Tls {
            addr,
            certificate,
            private_key,
            timeout,
        } => {
            let tcp_listener = TcpListener::bind(addr).await?;
            server.register_tls_listener(
                tcp_listener,
                timeout.unwrap_or(DEFAULT_TIMEOUT),
                (certificate, private_key),
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

    Ok(ProxyTask { server })
}

#[derive(Debug)]
struct DnsHandler {
    default_backend: Backends,
    route: Route,
    ipv4_source_prefix: u8,
    ipv6_source_prefix: u8,
}

#[async_trait]
impl RequestHandler for DnsHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        let src_addr = request.src();
        let message = self.extract_message(request, src_addr);

        let backend = match message.query() {
            None => {
                info!(?message, "message has no query, use default backend");

                &self.default_backend
            }

            Some(query) => {
                let name = query.name().to_string();
                self.route
                    .get_backend(&name)
                    .unwrap_or_else(|| &self.default_backend)
            }
        };

        match backend.send_request(message, src_addr).await {
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
}
