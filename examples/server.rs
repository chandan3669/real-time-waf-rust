use actix_web::{HttpRequest, HttpResponse, web};
use futures_util::StreamExt;
use log::info;

/// Main request handler - captures ALL HTTP requests
/// 
/// Flow:
/// 1. Capture metadata (Method, Path, Query)
/// 2. Capture all Headers
/// 3. Capture Query String
/// 4. Capture Request Body (buffered)
/// 5. Pass to Inspection Engine (Placeholder)
/// 6. Return Clean/Blocked response
pub async fn handle_request(
    req: HttpRequest,
    mut payload: web::Payload,
) -> HttpResponse {
    // ============================================================================
    // STEP 1: Capture Request Metadata
    // ============================================================================
    
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let query = req.query_string().to_string();
    
    info!("📥 Incoming Request: {} {}", method, path);
    
    // ============================================================================
    // STEP 2: Capture Headers
    // ============================================================================
    
    let mut headers = Vec::new();
    for (name, value) in req.headers() {
        if let Ok(val_str) = value.to_str() {
            headers.push((name.to_string(), val_str.to_string()));
            info!("  📋 Header: {} = {}", name, val_str);
        }
    }
    
    // ============================================================================
    // STEP 3: Capture Query Parameters (Already in query string)
    // ============================================================================
    
    if !query.is_empty() {
        info!("  🔍 Query String: {}", query);
    }
    
    // ============================================================================
    // STEP 4: Capture Request Body (Buffered)
    // ============================================================================
    
    // Create a buffer for the body
    let mut body_bytes = web::BytesMut::new();
    
    // Stream chunks from the payload
    while let Some(chunk) = payload.next().await {
        match chunk {
            Ok(data) => body_bytes.extend_from_slice(&data),
            Err(e) => {
                info!("  ❌ Error reading body: {}", e);
                return HttpResponse::BadRequest().body("Failed to read request body");
            }
        }
    }
    
    // Convert body to string (lossy conversion handles non-UTF8 safely)
    let body = String::from_utf8_lossy(&body_bytes).to_string();
    if !body.is_empty() {
        info!("  📦 Body ({}bytes): {}", body.len(), 
              if body.len() > 100 { &body[..100] } else { &body });
    }
    
    // ============================================================================
    // STEP 5: Pass to Inspection Engine (PLACEHOLDER)
    // ============================================================================
    
    let inspection_result = inspect_request(&method, &path, &query, &headers, &body);
    
    // ============================================================================
    // STEP 6: Return Response
    // ============================================================================
    
    match inspection_result {
        InspectionResult::Clean => {
            info!("  ✅ Request CLEAN - Passed inspection\n");
            HttpResponse::Ok().json(serde_json::json!({
                "status": "success",
                "message": "Request passed inspection",
                "inspected": {
                    "method": method,
                    "path": path,
                    "headers": headers.len(),
                    "body_size": body.len()
                }
            }))
        }
        InspectionResult::Blocked(reason) => {
            info!("  🚫 Request BLOCKED: {}\n", reason);
            HttpResponse::Forbidden().json(serde_json::json!({
                "status": "blocked",
                "reason": reason
            }))
        }
    }
}

// ============================================================================
// Inspection Engine Logic (Placeholder)
// ============================================================================

enum InspectionResult {
    Clean,
    Blocked(String),
}

/// Simplified Inspection Logic
/// This function simulates the WAF engine decision process.
fn inspect_request(
    _method: &str,
    _path: &str,
    _query: &str,
    _headers: &[(String, String)],
    _body: &str,
) -> InspectionResult {
    // TODO: Add actual detection logic here
    // Verify against SQLi, XSS, etc.
    
    // Always return Clean for this simplified example
    InspectionResult::Clean
}
