use std::net::IpAddr;

use async_trait::async_trait;
use hickory_proto::op::{Edns, Header, Message, ResponseCode};
use hickory_proto::rr::Record;
use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsOption};
use hickory_server::authority::{MessageResponse, MessageResponseBuilder};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use tracing::error;

use crate::backend::{Backend, Backends};

#[derive(Debug)]
struct DnsHandler {
    backend: Backends,
}

#[async_trait]
impl RequestHandler for DnsHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        let src_addr = request.src();

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
        if let Some(edns) = request.edns() {
            *message.extensions_mut() = Some(edns.clone());
        }
        for record in request.sig0() {
            message.add_sig0(record.clone());
        }

        let src_ip = src_addr.ip();
        let prefix = match src_ip {
            IpAddr::V4(_) => 16,
            IpAddr::V6(_) => 64,
        };

        message
            .extensions_mut()
            .get_or_insert(Edns::new())
            .options_mut()
            .insert(EdnsOption::Subnet(ClientSubnet::new(src_ip, prefix, 0)));

        match self.backend.send_request(message, src_addr).await {
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
}
