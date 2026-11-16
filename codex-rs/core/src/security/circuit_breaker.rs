//! Per-endpoint circuit breaker for the security assessment agent.
//!
//! Monitors tool results for error patterns (403, 429, WAF blocks, rate
//! limits) and tracks consecutive failures per endpoint. When the failure
//! count reaches the threshold, the circuit opens and the endpoint is
//! blocked for a cooldown period.
//!
//! Integrated in `drain_in_flight()`: each tool result is inspected
//! before being recorded into conversation history.

use std::collections::HashMap;
use std::time::{Duration, Instant};

const DEFAULT_FAILURE_THRESHOLD: u32 = 3;
const DEFAULT_COOLDOWN: Duration = Duration::from_secs(300);

/// Error patterns that indicate the endpoint should be backed off.
const BLOCK_PATTERNS: &[&str] = &[
    "403 forbidden",
    "429 too many",
    "rate limit",
    "rate-limit",
    "waf block",
    "access denied",
    "ip banned",
    "temporarily blocked",
    "captcha",
    "cloudflare",
    "security challenge",
];

/// Patterns that indicate a non-actionable error (don't count as real failures).
const IGNORE_PATTERNS: &[&str] = &[
    "connection refused",
    "connection reset",
    "dns resolution",
    "timeout",
    "name or service not known",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open { remaining_secs: u64 },
    HalfOpen,
}

#[derive(Debug)]
struct EndpointState {
    consecutive_failures: u32,
    last_failure: Option<Instant>,
    circuit_open: bool,
    cooldown_until: Option<Instant>,
}

impl Default for EndpointState {
    fn default() -> Self {
        Self {
            consecutive_failures: 0,
            last_failure: None,
            circuit_open: false,
            cooldown_until: None,
        }
    }
}

/// Per-endpoint circuit breaker.
pub struct CircuitBreaker {
    endpoints: HashMap<String, EndpointState>,
    failure_threshold: u32,
    cooldown: Duration,
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self {
            endpoints: HashMap::new(),
            failure_threshold: DEFAULT_FAILURE_THRESHOLD,
            cooldown: DEFAULT_COOLDOWN,
        }
    }
}

impl CircuitBreaker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_threshold(mut self, threshold: u32) -> Self {
        self.failure_threshold = threshold;
        self
    }

    pub fn with_cooldown(mut self, cooldown: Duration) -> Self {
        self.cooldown = cooldown;
        self
    }

    /// Check whether an endpoint's circuit is open.
    pub fn check(&mut self, endpoint: &str) -> CircuitState {
        let state = match self.endpoints.get_mut(endpoint) {
            Some(s) => s,
            None => return CircuitState::Closed,
        };

        if !state.circuit_open {
            return CircuitState::Closed;
        }

        if let Some(cooldown_until) = state.cooldown_until {
            if Instant::now() >= cooldown_until {
                state.circuit_open = false;
                state.consecutive_failures = self.failure_threshold - 1;
                state.cooldown_until = None;
                return CircuitState::HalfOpen;
            }
            let remaining = (cooldown_until - Instant::now()).as_secs();
            return CircuitState::Open {
                remaining_secs: remaining,
            };
        }

        CircuitState::Closed
    }

    /// Record a failure for an endpoint. Returns the new circuit state.
    pub fn record_failure(&mut self, endpoint: &str) -> CircuitState {
        let state = self.endpoints.entry(endpoint.to_string()).or_default();
        state.consecutive_failures += 1;
        state.last_failure = Some(Instant::now());

        if state.consecutive_failures >= self.failure_threshold {
            state.circuit_open = true;
            state.cooldown_until = Some(Instant::now() + self.cooldown);
            CircuitState::Open {
                remaining_secs: self.cooldown.as_secs(),
            }
        } else {
            CircuitState::Closed
        }
    }

    /// Record a success — resets the failure counter.
    pub fn record_success(&mut self, endpoint: &str) {
        if let Some(state) = self.endpoints.get_mut(endpoint) {
            state.consecutive_failures = 0;
            state.circuit_open = false;
            state.cooldown_until = None;
        }
    }

    /// Classify a tool output string. Returns the endpoint (if detectable)
    /// and whether it represents a blockable failure.
    pub fn classify_tool_output(output: &str) -> ToolOutputClass {
        let lower = output.to_lowercase();

        for pattern in IGNORE_PATTERNS {
            if lower.contains(pattern) {
                return ToolOutputClass::Ignorable;
            }
        }

        for pattern in BLOCK_PATTERNS {
            if lower.contains(pattern) {
                return ToolOutputClass::BlockableFailure;
            }
        }

        if lower.contains("http/1.1 403")
            || lower.contains("http/1.1 429")
            || lower.contains("http/2 403")
            || lower.contains("http/2 429")
            || lower.contains("\"status\": 403")
            || lower.contains("\"status\": 429")
            || lower.contains("\"status\":403")
            || lower.contains("\"status\":429")
        {
            return ToolOutputClass::BlockableFailure;
        }

        ToolOutputClass::Normal
    }

    /// Extract the target endpoint from a tool call command string.
    /// Looks for URLs in curl/httpx/ffuf/nuclei commands.
    pub fn extract_endpoint(command: &str) -> Option<String> {
        for token in command.split_whitespace() {
            if token.starts_with("http://") || token.starts_with("https://") {
                let url = token.trim_matches(|c: char| c == '\'' || c == '"');
                if let Some(path_end) = url.find('?') {
                    return Some(url[..path_end].to_string());
                }
                return Some(url.to_string());
            }
        }
        None
    }

    /// List all endpoints with open circuits.
    pub fn open_circuits(&self) -> Vec<(&str, u64)> {
        self.endpoints
            .iter()
            .filter(|(_, s)| s.circuit_open)
            .filter_map(|(ep, s)| {
                let remaining = s
                    .cooldown_until
                    .map(|cu| cu.saturating_duration_since(Instant::now()).as_secs())
                    .unwrap_or(0);
                Some((ep.as_str(), remaining))
            })
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolOutputClass {
    Normal,
    BlockableFailure,
    Ignorable,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn circuit_stays_closed_under_threshold() {
        let mut cb = CircuitBreaker::new().with_threshold(3);
        cb.record_failure("http://target/api/v1/users");
        cb.record_failure("http://target/api/v1/users");
        assert_eq!(cb.check("http://target/api/v1/users"), CircuitState::Closed);
    }

    #[test]
    fn circuit_opens_at_threshold() {
        let mut cb = CircuitBreaker::new().with_threshold(3);
        for _ in 0..3 {
            cb.record_failure("http://target/api/login");
        }
        match cb.check("http://target/api/login") {
            CircuitState::Open { .. } => {}
            other => panic!("Expected Open, got {:?}", other),
        }
    }

    #[test]
    fn success_resets_circuit() {
        let mut cb = CircuitBreaker::new().with_threshold(2);
        cb.record_failure("http://target/api/x");
        cb.record_success("http://target/api/x");
        cb.record_failure("http://target/api/x");
        assert_eq!(cb.check("http://target/api/x"), CircuitState::Closed);
    }

    #[test]
    fn classify_403() {
        assert_eq!(
            CircuitBreaker::classify_tool_output("HTTP/1.1 403 Forbidden\r\nContent-Type: text/html"),
            ToolOutputClass::BlockableFailure,
        );
    }

    #[test]
    fn classify_normal_200() {
        assert_eq!(
            CircuitBreaker::classify_tool_output("HTTP/1.1 200 OK\r\n{\"data\": \"ok\"}"),
            ToolOutputClass::Normal,
        );
    }

    #[test]
    fn extract_endpoint_from_curl() {
        let cmd = "curl -s -X POST http://target:8888/api/v1/users -H 'Content-Type: application/json'";
        assert_eq!(
            CircuitBreaker::extract_endpoint(cmd),
            Some("http://target:8888/api/v1/users".to_string()),
        );
    }
}
