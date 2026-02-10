use actix_web::{HttpRequest, HttpResponse, web, Error};
use reqwest::Client;
use crate::config::WafConfig;
use log::{info, error};
use futures_util::StreamExt;
use actix_web::web::BytesMut;

pub async fn forward_request(
    req: HttpRequest,
    mut payload: web::Payload,
    client: web::Data<Client>,
    config: web::Data<WafConfig>,
) -> Result<HttpResponse, Error> {
    let upstream_url = format!("{}{}", config.upstream.url, req.uri());
    
    info!("Proxying request to: {}", upstream_url);

    let method = req.method().clone();
    
    // Filter hop-by-hop headers
    let mut request_builder = client.request(method, &upstream_url);
    
    for (key, value) in req.headers() {
        if !is_hop_by_hop(key.as_str()) {
            request_builder = request_builder.header(key, value);
        }
    }

    // Add X-Forwarded-For
    if let Some(peer_addr) = req.peer_addr() {
        request_builder = request_builder.header("X-Forwarded-For", peer_addr.ip().to_string());
    }

    // Forward the body
    // In a real production scenario, we might want to buffer this for inspection
    // or stream it. For now, we stream it directly to upstream after WAF inspection (which happens in middleware).
    // The middleware will have already inspected the body if configured to do so.
    // Note: Actix payload is a stream.
    // However, Actix payload is !Send, but reqwest requires Send. So we must buffer it.
    let mut body_bytes = web::BytesMut::new();
    while let Some(chunk) = payload.next().await {
        let chunk = chunk?;
        body_bytes.extend_from_slice(&chunk);
    }
    let body = body_bytes.freeze();

    request_builder = request_builder.body(reqwest::Body::from(body));

    let response = request_builder.send().await.map_err(|e| {
        error!("Upstream request failed: {}", e);
        actix_web::error::ErrorBadGateway("Upstream Unreachable")
    })?;

    let status = response.status();
    let mut client_resp = HttpResponse::build(status);

    for (key, value) in response.headers() {
        if !is_hop_by_hop(key.as_str()) {
            client_resp.insert_header((key, value));
        }
    }

    Ok(client_resp.streaming(response.bytes_stream()))
}

fn is_hop_by_hop(header_name: &str) -> bool {
    use std::collections::HashSet;
    // Standard hop-by-hop headers
    let hop_headers: HashSet<&str> = [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
    ].iter().cloned().collect();

    hop_headers.contains(header_name.to_lowercase().as_str())
}
