//! Agent process management — spawn, monitor, and collect findings.
//!
//! Each agent is a separate `codex exec` process with its own prompt,
//! iteration budget, and findings output file. Agents run in parallel
//! (up to N per specialist).

use crate::config::{SpecialistProfile, TargetConfig};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Stdio;
use tokio::process::Command;
use tracing::{info, warn, error};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: Option<String>,
    pub title: String,
    pub severity: String,
    #[serde(default)]
    pub cwe: String,
    pub endpoint: String,
    #[serde(default)]
    pub app_type: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub proof_of_concept: String,
    #[serde(default)]
    pub http_request: String,
    #[serde(default)]
    pub http_response: String,
    #[serde(default)]
    pub impact: String,
    #[serde(default)]
    pub remediation: String,
    #[serde(default)]
    pub validated: bool,
    #[serde(default)]
    pub validation_result: Option<String>,
    #[serde(default)]
    pub agent_name: String,
    #[serde(default)]
    pub reported_at: String,
}

#[derive(Debug)]
struct AgentInstance {
    name: String,
    specialist: String,
    run_id: u32,
    findings_path: PathBuf,
}

pub async fn spawn_all(
    target: &TargetConfig,
    specialists: &[SpecialistProfile],
    model: &str,
    n: u32,
    max_turns: u32,
) -> crate::anyhow::Result<Vec<Finding>> {
    let mut handles = Vec::new();
    let base_url = target.base_url();

    for specialist in specialists {
        if specialist.app_type != target.target.app_type && specialist.app_type != "any" {
            info!("Skipping {} (app_type {} != {})", specialist.name, specialist.app_type, target.target.app_type);
            continue;
        }

        for run in 0..n {
            let instance = AgentInstance {
                name: format!("{}-run{}", specialist.name, run),
                specialist: specialist.name.clone(),
                run_id: run,
                findings_path: PathBuf::from(format!("findings-{}-{}.json", specialist.name, run)),
            };

            let prompt = build_agent_prompt(specialist, &base_url, max_turns, &instance.findings_path.to_string_lossy());
            let model = model.to_string();
            let findings_path = instance.findings_path.clone();
            let agent_name = instance.name.clone();

            info!("Spawning agent: {} (specialist: {}, run: {})", instance.name, specialist.name, run);

            let handle = tokio::spawn(async move {
                run_agent(&agent_name, &prompt, &model, max_turns, &findings_path).await
            });
            handles.push((instance, handle));
        }
    }

    info!("Launched {} agent instances, waiting for completion...", handles.len());

    let mut all_findings = Vec::new();
    for (instance, handle) in handles {
        match handle.await {
            Ok(Ok(findings)) => {
                info!("{}: {} findings", instance.name, findings.len());
                all_findings.extend(findings);
            }
            Ok(Err(e)) => {
                warn!("{}: failed — {}", instance.name, e);
            }
            Err(e) => {
                error!("{}: panicked — {}", instance.name, e);
            }
        }
    }

    info!("All agents complete. Total raw findings: {}", all_findings.len());
    Ok(all_findings)
}

fn build_agent_prompt(specialist: &SpecialistProfile, base_url: &str, max_turns: u32, findings_file: &str) -> String {
    format!(
        "You are a security assessment agent specializing in {}. \
         Your target is {}. You have {} iterations. \
         Read AGENTS.md for methodology, then focus ONLY on your specialty. \
         IMPORTANT: Write your findings to {} (NOT findings-crapi.json). \
         Use the MCP tools: report_finding with http_request for validation, \
         log_attempt to track progress, check_progress every 5-10 iterations. \
         Report findings with full HTTP request/response proof.\n\n\
         --- SPECIALIST INSTRUCTIONS ---\n\n{}",
        specialist.vuln_class,
        base_url,
        max_turns,
        findings_file,
        specialist.prompt,
    )
}

async fn run_agent(
    name: &str,
    prompt: &str,
    model: &str,
    _max_turns: u32,
    findings_path: &PathBuf,
) -> crate::anyhow::Result<Vec<Finding>> {
    let output = Command::new("codex")
        .args([
            "exec",
            "--trust",
            "-m", model,
            "--dangerously-bypass-approvals-and-sandbox",
            prompt,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?
        .wait_with_output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("Agent {} exited with {}: {}", name, output.status, &stderr[..stderr.len().min(200)]);
    }

    collect_findings(findings_path, name)
}

fn collect_findings(path: &PathBuf, agent_name: &str) -> crate::anyhow::Result<Vec<Finding>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let content = std::fs::read_to_string(path)?;
    let data: serde_json::Value = serde_json::from_str(&content)?;

    let findings_arr = data
        .get("findings")
        .and_then(|v| v.as_array())
        .or_else(|| data.as_array());

    match findings_arr {
        Some(arr) => {
            let mut findings: Vec<Finding> = Vec::new();
            for item in arr {
                if let Ok(mut f) = serde_json::from_value::<Finding>(item.clone()) {
                    f.agent_name = agent_name.to_string();
                    findings.push(f);
                }
            }
            Ok(findings)
        }
        None => Ok(Vec::new()),
    }
}
