//! Recon → Hunt pipeline (3.3)
//!
//! Phase 1: Broad recon agent maps the attack surface — endpoints, params,
//! tech stack, auth flows. Output is structured.
//!
//! Phase 2: Recon output feeds specialized hunters. Each specialist gets
//! the endpoints relevant to their vuln class.

use crate::agent::{self, Finding};
use crate::config::{SpecialistProfile, TargetConfig};
use serde::{Deserialize, Serialize};
use std::process::Stdio;
use tokio::process::Command;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconResults {
    pub endpoints: Vec<ReconEndpoint>,
    pub tech_stack: Vec<String>,
    pub auth_methods: Vec<String>,
    pub api_docs_found: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconEndpoint {
    pub url: String,
    pub method: String,
    pub auth_required: bool,
    pub params: Vec<String>,
    pub content_type: String,
    pub tags: Vec<String>,
}

impl ReconEndpoint {
    pub fn matches_specialist(&self, specialist: &SpecialistProfile) -> bool {
        let class = specialist.vuln_class.to_lowercase();

        if !specialist.focus_endpoints.is_empty() {
            return specialist
                .focus_endpoints
                .iter()
                .any(|pat| self.url.to_lowercase().contains(&pat.to_lowercase()));
        }

        match class.as_str() {
            "authentication" | "auth" => {
                self.tags.iter().any(|t| t.contains("auth"))
                    || self.url.contains("login")
                    || self.url.contains("token")
                    || self.url.contains("oauth")
                    || self.url.contains("password")
                    || self.url.contains("otp")
            }
            "injection" | "sqli" | "xss" => {
                !self.params.is_empty() || self.method != "GET"
            }
            "access_control" | "idor" | "bola" => {
                self.url.contains("{") || self.url.chars().any(|c| c.is_numeric())
            }
            "ssrf" => {
                self.params.iter().any(|p| {
                    p.contains("url") || p.contains("uri") || p.contains("link") || p.contains("api")
                })
            }
            _ => true,
        }
    }
}

const RECON_PROMPT: &str = r#"You are a RECON-ONLY agent. Your job is to MAP the attack surface, not exploit it.

1. Discover ALL endpoints (use curl, httpx, katana, or manual crawling)
2. For each endpoint, identify: HTTP method, parameters, auth requirements, content type
3. Identify the tech stack (frameworks, databases, server software)
4. Identify auth mechanisms (JWT, sessions, OAuth, API keys)
5. Find API documentation (swagger, openapi, graphql introspection)

When done, write your results to recon-results.json in this format:
{
  "endpoints": [
    {"url": "/api/v1/users", "method": "GET", "auth_required": true, "params": ["id"], "content_type": "application/json", "tags": ["user_data", "idor_candidate"]}
  ],
  "tech_stack": ["python", "django", "postgresql"],
  "auth_methods": ["jwt", "bearer_token"],
  "api_docs_found": true
}

DO NOT test for vulnerabilities. ONLY map the surface. Be thorough."#;

const MAX_RECON_RETRIES: u32 = 3;

pub async fn run_recon_phase(
    target: &TargetConfig,
    model: &str,
    max_turns: u32,
) -> crate::anyhow::Result<ReconResults> {
    let base_url = target.base_url();
    let prompt = format!(
        "{}\n\nTarget: {}\nMax iterations: {}",
        RECON_PROMPT,
        base_url,
        max_turns / 3,
    );

    for attempt in 1..=MAX_RECON_RETRIES {
        info!("Recon phase attempt {}/{} on {}", attempt, MAX_RECON_RETRIES, base_url);

        // Clean previous recon output
        let _ = std::fs::remove_file("recon-results.json");

        let result = run_recon_agent(&prompt, model).await;

        match result {
            Ok(recon) if !recon.endpoints.is_empty() => {
                info!("Recon succeeded: {} endpoints, {} tech stack items",
                    recon.endpoints.len(), recon.tech_stack.len());
                return Ok(recon);
            }
            Ok(_recon) if attempt < MAX_RECON_RETRIES => {
                tracing::warn!("Recon returned 0 endpoints on attempt {}, retrying...", attempt);
                continue;
            }
            Ok(recon) => return Ok(recon),
            Err(e) if attempt < MAX_RECON_RETRIES => {
                tracing::warn!("Recon failed on attempt {}: {}, retrying...", attempt, e);
                continue;
            }
            Err(e) => return Err(e),
        }
    }

    unreachable!()
}

async fn run_recon_agent(prompt: &str, model: &str) -> crate::anyhow::Result<ReconResults> {
    let output = Command::new("codex")
        .args([
            "exec", "--trust",
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
        tracing::warn!("Recon agent exited with {}", output.status);
    }

    let recon_path = std::path::Path::new("recon-results.json");
    if recon_path.exists() {
        let content = std::fs::read_to_string(recon_path)?;
        let results: ReconResults = serde_json::from_str(&content)?;
        Ok(results)
    } else {
        tracing::warn!("Recon agent didn't produce recon-results.json, using defaults");
        Ok(ReconResults {
            endpoints: Vec::new(),
            tech_stack: Vec::new(),
            auth_methods: Vec::new(),
            api_docs_found: false,
        })
    }
}

pub async fn run_hunt_phase(
    target: &TargetConfig,
    recon: &ReconResults,
    specialists: &[SpecialistProfile],
    model: &str,
    n: u32,
    max_turns: u32,
) -> crate::anyhow::Result<Vec<Finding>> {
    let mut enriched_specialists: Vec<SpecialistProfile> = Vec::new();

    for specialist in specialists {
        if specialist.app_type != target.target.app_type && specialist.app_type != "any" {
            continue;
        }

        let relevant: Vec<&ReconEndpoint> = recon
            .endpoints
            .iter()
            .filter(|ep| ep.matches_specialist(specialist))
            .collect();

        if relevant.is_empty() && !specialist.focus_endpoints.is_empty() {
            info!("Skipping {} — no matching endpoints from recon", specialist.name);
            continue;
        }

        let endpoints_context: String = relevant
            .iter()
            .map(|ep| format!("  {} {} (params: {}, auth: {})",
                ep.method, ep.url,
                ep.params.join(", "),
                ep.auth_required,
            ))
            .collect::<Vec<_>>()
            .join("\n");

        let mut enriched = specialist.clone();
        enriched.prompt = format!(
            "{}\n\n--- RECON RESULTS ---\n\
             Tech stack: {}\n\
             Auth methods: {}\n\
             Relevant endpoints ({}):\n{}\n\
             --- END RECON ---",
            specialist.prompt,
            recon.tech_stack.join(", "),
            recon.auth_methods.join(", "),
            relevant.len(),
            endpoints_context,
        );

        info!("{}: {} relevant endpoints from recon", specialist.name, relevant.len());
        enriched_specialists.push(enriched);
    }

    agent::spawn_all(target, &enriched_specialists, model, n, max_turns).await
}
