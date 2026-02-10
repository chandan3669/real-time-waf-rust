/// Security Logging System
/// 
/// Handles structured logging of security incidents to a local file.
/// Designed for ingestion by SIEM tools (Splunk, ELK, Wazuh).

use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;
use actix_web::http::header::HeaderMap;
use chrono::Utc;
use once_cell::sync::Lazy; // or use std::sync::OnceLock in newer Rust

// Global mutex to prevent race conditions when writing to the log file from multiple threads
static LOG_FILE_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

/// Path to the security log file
const LOG_FILE_PATH: &str = "waf_security.log";

/// Structured Security Event for SIEM ingestion
#[derive(Serialize)]
pub struct SecurityEvent {
    /// ISO 8601 Timestamp
    pub timestamp: String,
    /// Source IP address (client)
    pub source_ip: String,
    /// HTTP Method (GET, POST, etc.)
    pub method: String,
    /// Target URI/Path
    pub uri: String,
    /// Detected Attack Category (e.g., SQL Injection)
    pub attack_type: String,
    /// Specific rule that triggered the block
    pub rule_id: String,
    /// User-Agent header (for fingerprinting)
    pub user_agent: String,
    /// Unique Request ID for correlation
    pub request_id: String,
}

impl SecurityEvent {
    /// Create a new security event from request data
    pub fn new(
        source_ip: &str,
        method: &str,
        uri: &str,
        attack_type: &str, // e.g. "SQL Injection"
        rule_id: &str,     // e.g. "SQL-001"
        headers: &HeaderMap,
        request_id: &str,
    ) -> Self {
        let user_agent = headers
            .get("User-Agent")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("Unknown")
            .to_string();

        SecurityEvent {
            timestamp: Utc::now().to_rfc3339(),
            source_ip: source_ip.to_string(),
            method: method.to_string(),
            uri: uri.to_string(),
            attack_type: attack_type.to_string(),
            rule_id: rule_id.to_string(),
            user_agent,
            request_id: request_id.to_string(),
        }
    }
}

/// Append a security event to the log file
pub fn log_attack(event: &SecurityEvent) {
    // Serialize event to JSON
    let json_output = match serde_json::to_string(event) {
        Ok(json) => json,
        Err(e) => {
            eprintln!("Failed to serialize security event: {}", e);
            return;
        }
    };

    // Lock global mutex to ensure atomic writes
    let _guard = LOG_FILE_LOCK.lock().unwrap();

    // Open file in Append mode
    let mut file = match OpenOptions::new()
        .create(true)
        .append(true)
        .open(LOG_FILE_PATH)
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to open log file '{}': {}", LOG_FILE_PATH, e);
            return;
        }
    };

    // Write JSON line followed by newline
    if let Err(e) = writeln!(file, "{}", json_output) {
        eprintln!("Failed to write to security log: {}", e);
    }
}
