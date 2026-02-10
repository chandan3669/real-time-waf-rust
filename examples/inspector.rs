/// Core Request Inspection Engine
/// 
/// This module handles the detection logic for the WAF.
/// It combines all request data and checks for malicious patterns.

use log::{info, warn};

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
    attack_patterns: Vec<AttackPattern>,
}

/// Represents a single attack pattern
#[derive(Debug, Clone)]
struct AttackPattern {
    name: String,
    pattern: String,
    category: AttackCategory,
}

/// Categories of attacks
#[derive(Debug, Clone)]
enum AttackCategory {
    SQLInjection,
    XSS,
    PathTraversal,
    CommandInjection,
}

// ============================================================================
// Implementation
// ============================================================================

impl Inspector {
    /// Create a new Inspector with default attack patterns
    pub fn new() -> Self {
        let attack_patterns = vec![
            // SQL Injection patterns
            AttackPattern {
                name: "SQL Union Attack".to_string(),
                pattern: "union select".to_string(),
                category: AttackCategory::SQLInjection,
            },
            AttackPattern {
                name: "SQL OR Attack".to_string(),
                pattern: "or 1=1".to_string(),
                category: AttackCategory::SQLInjection,
            },
            AttackPattern {
                name: "SQL Comment".to_string(),
                pattern: "' --".to_string(),
                category: AttackCategory::SQLInjection,
            },
            
            // XSS patterns
            AttackPattern {
                name: "Script Tag".to_string(),
                pattern: "<script".to_string(),
                category: AttackCategory::XSS,
            },
            AttackPattern {
                name: "JavaScript URI".to_string(),
                pattern: "javascript:".to_string(),
                category: AttackCategory::XSS,
            },
            AttackPattern {
                name: "Event Handler".to_string(),
                pattern: "onerror=".to_string(),
                category: AttackCategory::XSS,
            },
            
            // Path Traversal patterns
            AttackPattern {
                name: "Directory Traversal".to_string(),
                pattern: "../".to_string(),
                category: AttackCategory::PathTraversal,
            },
            
            // Command Injection patterns
            AttackPattern {
                name: "Unix Command Chain".to_string(),
                pattern: "; cat /etc/passwd".to_string(),
                category: AttackCategory::CommandInjection,
            },
        ];

        Inspector { attack_patterns }
    }

    /// Inspect a request and return a decision
    /// 
    /// # Arguments
    /// * `method` - HTTP method (GET, POST, etc.)
    /// * `path` - Request path (/api/users)
    /// * `query` - Query string (id=123&name=test)
    /// * `headers` - Request headers as key-value pairs
    /// * `body` - Request body
    /// 
    /// # Returns
    /// Decision::Allow or Decision::Block with reason
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
        
        // Optimizing allocation: pre-allocate likely size
        let mut combined = String::with_capacity(path.len() + query.len() + body.len() + 200);
        
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
        
        info!("🔍 Inspecting combined payload ({} bytes)", combined.len());
        
        // ========================================================================
        // STEP 2: Convert to lowercase for case-insensitive matching
        // ========================================================================
        
        let normalized = combined.to_lowercase();
        
        // ========================================================================
        // STEP 3: Check against all attack patterns
        // ========================================================================
        
        for pattern in &self.attack_patterns {
            if normalized.contains(&pattern.pattern) {
                // Attack detected!
                warn!("🚨 ATTACK DETECTED: {} ({:?})", pattern.name, pattern.category);
                
                return Decision::Block {
                    reason: format!("{} detected", pattern.name),
                    matched_pattern: pattern.pattern.clone(),
                };
            }
        }
        
        // ========================================================================
        // STEP 4: No threats found - allow the request
        // ========================================================================
        
        info!("✅ No threats detected - request is CLEAN");
        Decision::Allow
    }

    /// Get the number of attack patterns loaded
    pub fn pattern_count(&self) -> usize {
        self.attack_patterns.len()
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_request() {
        let inspector = Inspector::new();
        let decision = inspector.inspect(
            "GET",
            "/api/users",
            "id=123",
            &[("Host".to_string(), "example.com".to_string())],
            "",
        );
        
        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn test_sql_injection_in_query() {
        let inspector = Inspector::new();
        let decision = inspector.inspect(
            "GET",
            "/search",
            "q=test' OR 1=1 --",
            &[],
            "",
        );
        
        match decision {
            Decision::Block { reason, .. } => {
                assert!(reason.contains("SQL"));
            }
            Decision::Allow => panic!("Should have blocked SQL injection"),
        }
    }

    #[test]
    fn test_xss_in_body() {
        let inspector = Inspector::new();
        let decision = inspector.inspect(
            "POST",
            "/comment",
            "",
            &[],
            r#"{"content":"<script>alert('XSS')</script>"}"#,
        );
        
        match decision {
            Decision::Block { reason, .. } => {
                assert!(reason.contains("Script Tag"));
            }
            Decision::Allow => panic!("Should have blocked XSS"),
        }
    }

    #[test]
    fn test_path_traversal() {
        let inspector = Inspector::new();
        let decision = inspector.inspect(
            "GET",
            "/../../../etc/passwd",
            "",
            &[],
            "",
        );
        
        match decision {
            Decision::Block { .. } => {
                // Success
            }
            Decision::Allow => panic!("Should have blocked path traversal"),
        }
    }

    #[test]
    fn test_case_insensitive_matching() {
        let inspector = Inspector::new();
        
        // Test uppercase SQL injection
        let decision = inspector.inspect(
            "GET",
            "/search",
            "q=UNION SELECT password FROM users",
            &[],
            "",
        );
        
        match decision {
            Decision::Block { .. } => {
                // Success - detected despite uppercase
            }
            Decision::Allow => panic!("Should have blocked uppercase SQL injection"),
        }
    }
}
