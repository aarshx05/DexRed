//! Cross-agent finding deduplication.
//!
//! Deduplicates findings from multiple parallel agents by hashing
//! (endpoint, CWE, normalized_payload). When duplicates exist, merges
//! reproduction steps from the agent with the clearest PoC.

use crate::agent::Finding;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;

/// Deduplicate a list of findings from multiple agents.
/// Returns unique findings with the best reproduction from each group.
pub fn deduplicate(findings: Vec<Finding>) -> Vec<Finding> {
    let mut groups: HashMap<String, Vec<Finding>> = HashMap::new();

    for finding in findings {
        let key = dedup_key(&finding);
        groups.entry(key).or_default().push(finding);
    }

    let mut result: Vec<Finding> = groups
        .into_values()
        .map(|group| pick_best(group))
        .collect();

    result.sort_by(|a, b| {
        severity_rank(&a.severity)
            .cmp(&severity_rank(&b.severity))
            .then(a.endpoint.cmp(&b.endpoint))
    });

    result
}

/// Build a dedup key from (endpoint_normalized, CWE, payload_hash).
fn dedup_key(f: &Finding) -> String {
    let endpoint = normalize_endpoint(&f.endpoint);
    let cwe = f.cwe.to_lowercase().replace("cwe-", "");
    let payload_hash = hash_payload(&f.http_request);
    format!("{}:{}:{}", endpoint, cwe, payload_hash)
}

/// Normalize endpoint for comparison — strip query params, trailing slashes,
/// and collapse numeric IDs to a placeholder.
fn normalize_endpoint(endpoint: &str) -> String {
    let mut normalized = endpoint.split('?').next().unwrap_or(endpoint).to_string();
    normalized = normalized.trim_end_matches('/').to_string();

    let re_numeric = regex_lite::Regex::new(r"/\d+(/|$)").unwrap_or_else(|_| {
        regex_lite::Regex::new(r"NEVER_MATCH").unwrap()
    });
    normalized = re_numeric.replace_all(&normalized, "/{ID}$1").to_string();

    let re_uuid = regex_lite::Regex::new(
        r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(/|$)",
    )
    .unwrap_or_else(|_| regex_lite::Regex::new(r"NEVER_MATCH").unwrap());
    normalized = re_uuid.replace_all(&normalized, "/{UUID}$1").to_string();

    normalized.to_lowercase()
}

/// Hash the payload portion of an HTTP request for dedup.
/// Strips headers and normalizes whitespace.
fn hash_payload(http_request: &str) -> String {
    if http_request.is_empty() {
        return "empty".to_string();
    }

    let body = http_request
        .split("\n\n")
        .nth(1)
        .or_else(|| http_request.split("\r\n\r\n").nth(1))
        .unwrap_or(http_request);

    let normalized: String = body
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    let mut hasher = Sha256::new();
    hasher.update(normalized.as_bytes());
    format!("{:.8x}", u64::from_be_bytes(hasher.finalize()[..8].try_into().unwrap_or([0; 8])))
}

/// Pick the best finding from a group of duplicates.
/// Prefers: validated > unvalidated, longer PoC, higher severity.
fn pick_best(mut group: Vec<Finding>) -> Finding {
    group.sort_by(|a, b| {
        let v_cmp = b.validated.cmp(&a.validated);
        if v_cmp != std::cmp::Ordering::Equal {
            return v_cmp;
        }
        let poc_cmp = b.proof_of_concept.len().cmp(&a.proof_of_concept.len());
        if poc_cmp != std::cmp::Ordering::Equal {
            return poc_cmp;
        }
        b.http_request.len().cmp(&a.http_request.len())
    });

    let mut best = group.remove(0);

    let agent_names: Vec<String> = std::iter::once(best.agent_name.clone())
        .chain(group.iter().map(|f| f.agent_name.clone()))
        .filter(|n| !n.is_empty())
        .collect();

    if agent_names.len() > 1 {
        best.agent_name = format!("{} (+{} agents)", agent_names[0], agent_names.len() - 1);
    }

    best
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "Critical" => 0,
        "High" => 1,
        "Medium" => 2,
        "Low" => 3,
        "Informational" => 4,
        _ => 5,
    }
}

/// Write merged findings to a JSON file.
pub fn write_merged_findings(findings: &[Finding], path: &Path) -> crate::anyhow::Result<()> {
    let output = serde_json::json!({
        "findings": findings,
        "metadata": {
            "total": findings.len(),
            "validated": findings.iter().filter(|f| f.validated).count(),
            "deduplication": "endpoint+cwe+payload_hash",
            "merged_at": chrono::Utc::now().to_rfc3339(),
        }
    });

    std::fs::write(path, serde_json::to_string_pretty(&output)?)?;
    tracing::info!("Wrote {} findings to {:?}", findings.len(), path);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_finding(title: &str, endpoint: &str, cwe: &str, agent: &str) -> Finding {
        Finding {
            id: None,
            title: title.into(),
            severity: "High".into(),
            cwe: cwe.into(),
            endpoint: endpoint.into(),
            app_type: "web".into(),
            description: "test".into(),
            proof_of_concept: "test poc".into(),
            http_request: "GET /api/test".into(),
            http_response: "200 OK".into(),
            impact: "test".into(),
            remediation: "test".into(),
            validated: false,
            validation_result: None,
            agent_name: agent.into(),
            reported_at: String::new(),
        }
    }

    #[test]
    fn deduplicates_same_endpoint_and_cwe() {
        let findings = vec![
            make_finding("IDOR on users", "/api/v1/users/123", "CWE-639", "agent-a"),
            make_finding("IDOR users endpoint", "/api/v1/users/456", "CWE-639", "agent-b"),
        ];
        let result = deduplicate(findings);
        assert_eq!(result.len(), 1);
        assert!(result[0].agent_name.contains("+1 agents"));
    }

    #[test]
    fn keeps_different_cwes() {
        let findings = vec![
            make_finding("SQLi on login", "/api/login", "CWE-89", "agent-a"),
            make_finding("XSS on login", "/api/login", "CWE-79", "agent-b"),
        ];
        let result = deduplicate(findings);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn prefers_validated_finding() {
        let mut f1 = make_finding("IDOR", "/api/users/1", "CWE-639", "a");
        let mut f2 = make_finding("IDOR", "/api/users/2", "CWE-639", "b");
        f2.validated = true;
        f2.proof_of_concept = "detailed steps".into();

        let result = deduplicate(vec![f1, f2]);
        assert_eq!(result.len(), 1);
        assert!(result[0].validated);
    }

    #[test]
    fn normalizes_numeric_ids() {
        assert_eq!(normalize_endpoint("/api/users/123"), "/api/users/{id}");
        assert_eq!(normalize_endpoint("/api/users/456"), "/api/users/{id}");
    }
}
