use actix_web::{web, web::Payload};
use futures_util::StreamExt;

// Helper to read payload to string (for simple inspection)
// In production, we would want stream inspection to avoid buffering large bodies.
pub async fn read_body(mut payload: Payload) -> Result<String, actix_web::Error> {
    let mut body = web::BytesMut::new();
    while let Some(chunk) = payload.next().await {
        let chunk = chunk?;
        body.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8_lossy(&body).to_string())
}
