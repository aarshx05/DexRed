//! HTTP replay engine for finding validation.
//!
//! Replays a finding's raw HTTP request and captures the response
//! with precise timing. The replay result is fed to the LLM judge
//! for vuln-class-aware validation.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Parsed HTTP request from a finding's `http_request` field.
#[derive(Debug, Clone)]
pub struct ParsedRequest {
    pub method: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
}

/// Result of replaying an HTTP request.
#[derive(Debug, Clone)]
pub struct ReplayResult {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub body_length: usize,
    pub elapsed: Duration,
    pub error: Option<String>,
}

impl ParsedRequest {
    /// Parse a raw HTTP request string into structured fields.
    pub fn parse(raw: &str) -> Option<Self> {
        let raw = raw.trim();
        if raw.is_empty() {
            return None;
        }

        let mut lines = raw.lines();
        let request_line = lines.next()?;
        let parts: Vec<&str> = request_line.splitn(3, ' ').collect();
        if parts.len() < 2 {
            return None;
        }

        let method = parts[0].to_uppercase();
        let mut url = parts[1].to_string();

        let mut headers = HashMap::new();
        let mut in_body = false;
        let mut body_lines = Vec::new();

        for line in lines {
            if in_body {
                body_lines.push(line);
            } else if line.trim().is_empty() {
                in_body = true;
            } else if let Some((key, value)) = line.split_once(':') {
                headers.insert(key.trim().to_string(), value.trim().to_string());
            }
        }

        if !url.starts_with("http") {
            let host = headers
                .get("Host")
                .or_else(|| headers.get("host"))
                .cloned()
                .unwrap_or_else(|| "localhost".to_string());
            let scheme = if host.contains(":443") { "https" } else { "http" };
            url = format!("{scheme}://{host}{url}");
        }

        let body = if body_lines.is_empty() {
            None
        } else {
            Some(body_lines.join("\n"))
        };

        Some(Self {
            method,
            url,
            headers,
            body,
        })
    }

    /// Build a timed replay result without actually making the HTTP call.
    /// The actual HTTP call is delegated to the Python layer (or a Rust HTTP
    /// client if `reqwest` is added as a dependency). This module provides
    /// the parsing and timing infrastructure.
    pub fn to_judge_context(&self, replay: &ReplayResult) -> JudgeContext {
        JudgeContext {
            request_method: self.method.clone(),
            request_url: self.url.clone(),
            request_headers: self.headers.clone(),
            request_body: self.body.clone(),
            response_status: replay.status_code,
            response_body_preview: if replay.body.len() > 3000 {
                replay.body[..3000].to_string()
            } else {
                replay.body.clone()
            },
            response_elapsed_ms: replay.elapsed.as_millis() as u64,
            response_headers: replay.headers.clone(),
        }
    }
}

/// Everything the LLM judge needs to make its determination.
#[derive(Debug, Clone)]
pub struct JudgeContext {
    pub request_method: String,
    pub request_url: String,
    pub request_headers: HashMap<String, String>,
    pub request_body: Option<String>,
    pub response_status: u16,
    pub response_body_preview: String,
    pub response_elapsed_ms: u64,
    pub response_headers: HashMap<String, String>,
}

impl JudgeContext {
    /// Serialize to a string suitable for the LLM judge prompt.
    pub fn to_prompt_section(&self) -> String {
        let mut s = String::with_capacity(4096);
        s.push_str(&format!(
            "## Replay Result\n\
             Status: HTTP {}\n\
             Response time: {}ms\n\
             Response size: {} bytes\n\n",
            self.response_status,
            self.response_elapsed_ms,
            self.response_body_preview.len(),
        ));

        s.push_str("### Response Headers\n");
        for (k, v) in &self.response_headers {
            s.push_str(&format!("{}: {}\n", k, v));
        }

        s.push_str("\n### Response Body (preview)\n```\n");
        s.push_str(&self.response_body_preview);
        s.push_str("\n```\n");

        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_get() {
        let raw = "GET /api/v1/users HTTP/1.1\nHost: localhost:8888\nAuthorization: Bearer tok123\n";
        let parsed = ParsedRequest::parse(raw).unwrap();
        assert_eq!(parsed.method, "GET");
        assert_eq!(parsed.url, "http://localhost:8888/api/v1/users");
        assert_eq!(parsed.headers.get("Authorization").unwrap(), "Bearer tok123");
        assert!(parsed.body.is_none());
    }

    #[test]
    fn parse_post_with_body() {
        let raw = "POST /api/login HTTP/1.1\nHost: target.com\nContent-Type: application/json\n\n{\"user\":\"admin\",\"pass\":\"test\"}";
        let parsed = ParsedRequest::parse(raw).unwrap();
        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.body.as_deref(), Some("{\"user\":\"admin\",\"pass\":\"test\"}"));
    }

    #[test]
    fn parse_full_url() {
        let raw = "GET https://api.target.com/v2/data HTTP/1.1\n";
        let parsed = ParsedRequest::parse(raw).unwrap();
        assert_eq!(parsed.url, "https://api.target.com/v2/data");
    }

    #[test]
    fn empty_input_returns_none() {
        assert!(ParsedRequest::parse("").is_none());
        assert!(ParsedRequest::parse("   ").is_none());
    }
}
