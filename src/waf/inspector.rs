/// Core Request Inspection Engine
/// 
/// This module handles the detection logic for the WAF.
/// It combines all request data and checks for malicious patterns.

use log::{info, warn};
use super::rules::{Rule, load_default_rules};

// ============================================================================
// Decision Enum
// ============================================================================

/// Represents the inspection decision for a request
#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    /// Request is clean and should be allowed
    Allow,
    /// Request contains malicious pattern and should be blocked
    Block { 
        /// Reason for blocking (e.g., "SQL Injection detected")
        reason: String,
        /// The specific pattern that triggered the block
        matched_pattern: String,
    },
}

// ============================================================================
// Inspector Struct
// ============================================================================

/// Main inspection engine
pub struct Inspector {
    /// List of attack patterns to check
    rules: Vec<Rule>,
}

impl Inspector {
    /// Create a new Inspector with default rules
    pub fn new() -> Self {
        let rules = load_default_rules();
        Inspector { rules }
    }

    /// Inspect a request and return a decision
    /// 
    /// # Arguments
    /// * `method` - HTTP method
    /// * `path` - Request path
    /// * `query` - Query string
    /// * `headers` - Request headers
    /// * `body` - Request body
    /// 
    /// # Returns
    /// Decision::Allow or Decision::Block
    pub fn inspect(
        &self,
        method: &str,
        path: &str,
        query: &str,
        headers: &[(String, String)],
        body: &str,
    ) -> Decision {
        // ========================================================================
        // STEP 1: Combine all request data into a single string
        // ========================================================================
        
        let mut combined = String::new();
        combined.push_str(path);
        combined.push(' ');
        combined.push_str(query);
        combined.push(' ');
        
        for (name, value) in headers {
            combined.push_str(name);
            combined.push(':');
            combined.push_str(value);
            combined.push(' ');
        }
        
        combined.push_str(body);
        
        // info!("🔍 Inspecting combined payload ({} bytes)", combined.len());
        
        // ========================================================================
        // STEP 2: Convert to lowercase for case-insensitive matching if needed
        // but our Regex uses (?i) so we can skip this step OR do it for other checks
        // We will trust our Regex patterns which are case insensitive
        // ========================================================================
        
        // ========================================================================
        // STEP 3: Check against all rules
        // ========================================================================
        
        for rule in &self.rules {
            if rule.matches(&combined) {
                // Return immediate block
                warn!("🚨 ATTACK DETECTED: {} (ID: {})", rule.name, rule.id);
                return Decision::Block {
                    reason: rule.name.clone(),
                    matched_pattern: rule.id.clone(),
                };
            }
        }
        
        Decision::Allow
    }
}
