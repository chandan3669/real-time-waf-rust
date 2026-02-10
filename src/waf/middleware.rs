use std::pin::Pin;
use std::task::{Context, Poll};
use actix_web::{
    dev::{Service, Transform, ServiceRequest, ServiceResponse},
    Error, HttpMessage, web,
};
use futures_util::future::{ok, Ready, Future};
use log::{info, warn};
use super::inspector::{Inspector, Decision};
use super::logger::{self, SecurityEvent};
use urlencoding::decode;
use serde::Serialize;
use serde_json::json;
use chrono::Utc;
use uuid::Uuid;

// WafLog struct removed in favor of wa::logger::SecurityEvent

// There are two steps in middleware processing.
// 1. Middleware initialization, middleware factory gets called with
//    next service in chain as parameter.
// 2. Middleware's call method gets called with normal request.
pub struct WafMiddleware;

use actix_web::body::EitherBody;

// Middleware factory is `Transform` trait
impl<S, B> Transform<S, ServiceRequest> for WafMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = WafMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(WafMiddlewareService { service })
    }
}

pub struct WafMiddlewareService<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for WafMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, ctx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let svc = &self.service;
        
        // ... (engine setup code omitted for brevity, assuming it's unchanged above) ...
        // We need to verify if we need to copy the engine code here or if replace_file_content context is enough.
        // The replace_file_content context is limited.
        // Let's rewrite the whole call method to be safe and clean.
        
        let engine_opt = req.app_data::<web::Data<Inspector>>().cloned();
        
        if let Some(engine) = engine_opt {
            let method = req.method().to_string();
            let path = req.uri().path().to_string();
            let query = req.query_string().to_string();
            
            let mut headers_vec = Vec::new();
            for (name, value) in req.headers() {
                // Exclude Host header to prevent SSRF false positives
                if name == actix_web::http::header::HOST { continue; }
                if let Ok(v) = value.to_str() {
                    headers_vec.push((name.to_string(), v.to_string()));
                }
            }
            
            let body = ""; 
            let source_ip = req.peer_addr().map(|a| a.ip().to_string());

            let decision = engine.inspect(&method, &path, &query, &headers_vec, body);
            
            if let Decision::Block { reason, matched_pattern } = decision {
                 let request_id = Uuid::new_v4().to_string();
                 
                 // 1. Create Security Event
                 let event = SecurityEvent {
                    timestamp: Utc::now().to_rfc3339(),
                    source_ip: source_ip.unwrap_or_else(|| "unknown".to_string()),
                    method: method.clone(),
                    uri: req.uri().to_string(),
                    attack_type: "Exploit Attempt".to_string(), // Could refine this based on rule category
                    rule_id: matched_pattern.clone(),
                    user_agent: req.headers().get("User-Agent").and_then(|h| h.to_str().ok()).unwrap_or("Unknown").to_string(),
                    request_id: request_id.clone(),
                };
                
                // 2. Log to File (Security Log)
                logger::log_attack(&event);
                
                // 3. Log to Console (Operational Log)
                warn!("🚨 WAF Block: {} - Rule: {}", reason, matched_pattern);
                
                // BLOCKING ACTION
                let response = actix_web::HttpResponse::Forbidden()
                    .json(serde_json::json!({
                        "error": "Request Blocked",
                        "reason": reason,
                        "request_id": request_id
                    }));
                
                return Box::pin(async { 
                    let res = req.into_response(response);
                    Ok(res.map_into_right_body())
                });
            }
        }

        // ALLOW ACTION
        let fut = svc.call(req);
        Box::pin(async move {
            let res = fut.await?;
            Ok(res.map_into_left_body())
        })
    }
}
