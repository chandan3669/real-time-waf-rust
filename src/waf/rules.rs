/// OWASP Top 10 Attack Detection Rules
/// 
/// This module defines regex-based rules for detecting common web attacks.
/// Rules are organized by OWASP Top 10 categories.

use regex::Regex;

// ============================================================================
// Severity Levels
// ============================================================================

/// Severity rating for detected attacks
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Severity {
    /// Low risk - informational, rarely acted upon
    Low,
    /// Medium risk - suspicious but may have legitimate use cases
    Medium,
    /// High risk - strong indicator of attack, immediate action recommended
    High,
    /// Critical - definite attack pattern, no legitimate use cases
    Critical,
}

// ============================================================================
// Attack Types (OWASP Top 10)
// ============================================================================

/// OWASP Top 10 attack categories
#[derive(Debug, Clone, PartialEq)]
pub enum AttackType {
    /// A1:2021 – Broken Access Control
    BrokenAccessControl,
    /// A2:2021 – Cryptographic Failures
    CryptographicFailure,
    /// A3:2021 – Injection (SQL, NoSQL, LDAP, etc.)
    Injection,
    /// A4:2021 – Insecure Design
    InsecureDesign,
    /// A5:2021 – Security Misconfiguration
    SecurityMisconfiguration,
    /// A6:2021 – Vulnerable Components
    VulnerableComponents,
    /// A7:2021 – Identification and Authentication Failures
    AuthenticationFailure,
    /// A8:2021 – Software and Data Integrity Failures
    IntegrityFailure,
    /// A9:2021 – Security Logging Failures
    LoggingFailure,
    /// A10:2021 – Server-Side Request Forgery (SSRF)
    SSRF,
}

// ============================================================================
// Detection Rule
// ============================================================================

/// A single detection rule
pub struct Rule {
    /// Unique rule ID (e.g., "SQL-001")
    pub id: String,
    /// Human-readable rule name
    pub name: String,
    /// OWASP attack category
    pub attack_type: AttackType,
    /// Severity level
    pub severity: Severity,
    /// Compiled regex pattern
    pub pattern: Regex,
    /// Description of what this rule detects
    pub description: String,
    /// False positive risk assessment
    pub false_positive_risk: FalsePositiveRisk,
}

/// Risk of false positives for a rule
#[derive(Debug, Clone, Copy)]
pub enum FalsePositiveRisk {
    /// Very unlikely to trigger on legitimate traffic
    Low,
    /// May occasionally trigger on edge cases
    Medium,
    /// Frequently triggers on legitimate traffic (use with caution)
    High,
}

// ============================================================================
// Rule Builder
// ============================================================================

impl Rule {
    /// Create a new rule
    pub fn new(
        id: &str,
        name: &str,
        attack_type: AttackType,
        severity: Severity,
        pattern: &str,
        description: &str,
        false_positive_risk: FalsePositiveRisk,
    ) -> Self {
        Rule {
            id: id.to_string(),
            name: name.to_string(),
            attack_type,
            severity,
            pattern: Regex::new(pattern).expect("Invalid regex pattern"),
            description: description.to_string(),
            false_positive_risk,
        }
    }

    /// Check if this rule matches the given input
    pub fn matches(&self, input: &str) -> bool {
        self.pattern.is_match(input)
    }
}

// ============================================================================
// Default Rule Set (OWASP Top 10)
// ============================================================================

/// Load the default OWASP-based rule set
pub fn load_default_rules() -> Vec<Rule> {
    vec![
        // ====================================================================
        // SQL INJECTION RULES (A3:2021 - Injection)
        // ====================================================================
        
        Rule::new(
            "SQL-001",
            "SQL Union Attack",
            AttackType::Injection,
            Severity::Critical,
            r"(?i)\bunion\b.{0,100}\bselect\b",
            "Detects UNION-based SQL injection attempts",
            FalsePositiveRisk::Low,
        ),
        
        Rule::new(
            "SQL-002",
            "SQL Tautology (OR 1=1)",
            AttackType::Injection,
            Severity::High,
            r"(?i)(\bor\b|\|\|).{0,10}(1\s*=\s*1|'1'\s*=\s*'1')",
            "Detects tautology-based SQL injection (always true conditions)",
            FalsePositiveRisk::Medium, // Math expressions might trigger
        ),
        
        Rule::new(
            "SQL-003",
            "SQL Comment Injection",
            AttackType::Injection,
            Severity::High,
            r"(?i)('|%27|%2527)\s*(--|#|;|/\*)",
            "Detects SQL comment sequences used to terminate queries",
            FalsePositiveRisk::Low,
        ),
        
        Rule::new(
            "SQL-004",
            "SQL Stacked Queries",
            AttackType::Injection,
            Severity::Critical,
            r"(?i);\s*(drop|delete|update|insert|alter|create)\s+",
            "Detects multiple SQL statements (stacked queries)",
            FalsePositiveRisk::Low,
        ),
        
        Rule::new(
            "SQL-005",
            "SQL Sleep/Benchmark",
            AttackType::Injection,
            Severity::High,
            r"(?i)\b(sleep|benchmark|waitfor delay)\s*\(",
            "Detects time-based blind SQL injection",
            FalsePositiveRisk::Low,
        ),
        
        // ====================================================================
        // CROSS-SITE SCRIPTING (XSS) RULES (A3:2021 - Injection)
        // ====================================================================
        
        Rule::new(
            "XSS-001",
            "Script Tag Injection",
            AttackType::Injection,
            Severity::Critical,
            r"(?i)<script[^>]*>.*?</script>",
            "Detects <script> tags in user input",
            FalsePositiveRisk::Low,
        ),
        
        Rule::new(
            "XSS-002",
            "JavaScript Event Handlers",
            AttackType::Injection,
            Severity::High,
            r"(?i)\bon(load|error|click|mouseover|focus|blur)\s*=",
            "Detects inline JavaScript event handlers",
            FalsePositiveRisk::Medium, // HTML emails might trigger
        ),
        
        Rule::new(
            "XSS-003",
            "JavaScript URI Scheme",
            AttackType::Injection,
            Severity::High,
            r"(?i)javascript\s*:",
            "Detects javascript: URI scheme",
            FalsePositiveRisk::Low,
        ),
        
        Rule::new(
            "XSS-004",
            "Data URI with Script",
            AttackType::Injection,
            Severity::High,
            r"(?i)data:text/html.*<script",
            "Detects data URIs containing scripts",
            FalsePositiveRisk::Low,
        ),
        
        Rule::new(
            "XSS-005",
            "Encoded Script Tags",
            AttackType::Injection,
            Severity::High,
            r"(%3C|&lt;)script(%3E|&gt;)",
            "Detects URL/HTML encoded script tags",
            FalsePositiveRisk::Low,
        ),
        
        // ====================================================================
        // PATH TRAVERSAL RULES (A1:2021 - Broken Access Control)
        // ====================================================================
        
        Rule::new(
            "PATH-001",
            "Directory Traversal (Simple)",
            AttackType::BrokenAccessControl,
            Severity::High,
            r"\.\./|\.\.\%2[fF]|\.\.\%5[cC]",
            "Detects basic directory traversal patterns (../)",
            FalsePositiveRisk::Low,
        ),
        
        Rule::new(
            "PATH-002",
            "Absolute Path Access",
            AttackType::BrokenAccessControl,
            Severity::Medium,
            r"(?i)(^|[^a-z])/etc/(passwd|shadow|hosts)|c:\\windows\\system32",
            "Detects attempts to access sensitive system files",
            FalsePositiveRisk::Medium, // Documentation might reference these
        ),
        
        Rule::new(
            "PATH-003",
            "Null Byte Injection",
            AttackType::BrokenAccessControl,
            Severity::High,
            r"%00|\\0",
            "Detects null byte injection for bypassing file extension checks",
            FalsePositiveRisk::Low,
        ),
        
        // ====================================================================
        // COMMAND INJECTION RULES (A3:2021 - Injection)
        // ====================================================================
        
        Rule::new(
            "CMD-001",
            "Unix Command Chaining",
            AttackType::Injection,
            Severity::Critical,
            r"(?i)[;|&`$]\s*(cat|ls|wget|curl|nc|netcat|bash|sh|chmod)",
            "Detects Unix command injection with chaining operators",
            FalsePositiveRisk::Low,
        ),
        
        Rule::new(
            "CMD-002",
            "Windows Command Execution",
            AttackType::Injection,
            Severity::Critical,
            r"(?i)(cmd\.exe|powershell\.exe|wscript\.exe)\s",
            "Detects Windows command execution attempts",
            FalsePositiveRisk::Low,
        ),
        
        Rule::new(
            "CMD-003",
            "Command Substitution",
            AttackType::Injection,
            Severity::Critical,
            r"\$\(.*\)|\`.*\`",
            "Detects command substitution patterns $(cmd) or `cmd`",
            FalsePositiveRisk::Low,
        ),
        
        // ====================================================================
        // LDAP INJECTION RULES (A3:2021 - Injection)
        // ====================================================================
        
        Rule::new(
            "LDAP-001",
            "LDAP Filter Injection",
            AttackType::Injection,
            Severity::High,
            r"(?i)(\(|\)|\||&)\s*(objectClass|cn|uid)=",
            "Detects LDAP query injection patterns",
            FalsePositiveRisk::Medium,
        ),
        
        // ====================================================================
        // XML/XXE INJECTION RULES (A3:2021 - Injection)
        // ====================================================================
        
        Rule::new(
            "XXE-001",
            "XML External Entity",
            AttackType::Injection,
            Severity::Critical,
            r"(?i)<!DOCTYPE.*ENTITY",
            "Detects XXE (XML External Entity) attacks",
            FalsePositiveRisk::Low,
        ),
        
        // ====================================================================
        // SSRF RULES (A10:2021 - SSRF)
        // ====================================================================
        
        Rule::new(
            "SSRF-001",
            "Internal IP Access",
            AttackType::SSRF,
            Severity::High,
            r"(http://|https://)?(127\.0\.0\.1|localhost|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)",
            "Detects attempts to access internal/private IP addresses",
            FalsePositiveRisk::Medium, // Apps may legitimately reference localhost
        ),
    ]
}
