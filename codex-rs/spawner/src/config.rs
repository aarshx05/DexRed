//! Configuration loading — target.toml and specialist profiles.

use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct TargetConfig {
    pub target: TargetSection,
}

#[derive(Debug, Deserialize)]
pub struct TargetSection {
    pub domains: Vec<String>,
    #[serde(default = "default_app_type")]
    pub app_type: String,
    #[serde(default = "default_methodology")]
    pub methodology: String,
    #[serde(default = "default_max_turns")]
    pub max_turns: u32,
    #[serde(default)]
    pub findings_output: Option<String>,
    #[serde(default)]
    pub scope: Option<ScopeSection>,
    #[serde(default)]
    pub context: Option<ContextSection>,
}

#[derive(Debug, Default, Deserialize)]
pub struct ScopeSection {
    pub include_paths: Option<Vec<String>>,
    pub exclude_paths: Option<Vec<String>>,
    pub rate_limit: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
pub struct ContextSection {
    pub tech_stack: Option<Vec<String>>,
    pub api_docs_url: Option<String>,
    pub focus_areas: Option<Vec<String>>,
    pub notes: Option<String>,
}

fn default_app_type() -> String { "web".into() }
fn default_methodology() -> String { "blackbox".into() }
fn default_max_turns() -> u32 { 100 }

impl TargetConfig {
    pub fn load(path: &Path) -> crate::anyhow::Result<Self> {
        let content = fs::read_to_string(path)?;
        Ok(toml::from_str(&content)?)
    }

    pub fn base_url(&self) -> String {
        self.target
            .domains
            .first()
            .map(|d| {
                if d.starts_with("http") {
                    d.clone()
                } else {
                    format!("http://{}", d)
                }
            })
            .unwrap_or_else(|| "http://localhost".into())
    }
}

/// A specialist agent profile loaded from a markdown file.
#[derive(Debug, Clone)]
pub struct SpecialistProfile {
    pub name: String,
    pub vuln_class: String,
    pub app_type: String,
    pub prompt: String,
    pub focus_endpoints: Vec<String>,
}

pub fn load_specialist_profiles(dir: &Path) -> crate::anyhow::Result<Vec<SpecialistProfile>> {
    let mut profiles = Vec::new();

    if !dir.exists() {
        tracing::warn!("Specialist directory {:?} not found, using default profiles", dir);
        return Ok(default_specialist_profiles());
    }

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().map_or(false, |e| e == "md") {
            let content = fs::read_to_string(&path)?;
            let name = path
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();

            let (vuln_class, app_type) = parse_profile_metadata(&content);

            profiles.push(SpecialistProfile {
                name: name.clone(),
                vuln_class,
                app_type,
                prompt: content,
                focus_endpoints: Vec::new(),
            });

            tracing::info!("Loaded specialist profile: {}", name);
        }
    }

    if profiles.is_empty() {
        tracing::warn!("No specialist profiles found, using defaults");
        return Ok(default_specialist_profiles());
    }

    Ok(profiles)
}

fn parse_profile_metadata(content: &str) -> (String, String) {
    let mut vuln_class = "general".to_string();
    let mut app_type = "web".to_string();

    for line in content.lines().take(20) {
        let lower = line.to_lowercase();
        if lower.starts_with("vuln_class:") || lower.starts_with("# vuln_class:") {
            vuln_class = line.split(':').nth(1).unwrap_or("general").trim().to_string();
        }
        if lower.starts_with("app_type:") || lower.starts_with("# app_type:") {
            app_type = line.split(':').nth(1).unwrap_or("web").trim().to_string();
        }
    }

    (vuln_class, app_type)
}

fn default_specialist_profiles() -> Vec<SpecialistProfile> {
    vec![
        SpecialistProfile {
            name: "auth-specialist".into(),
            vuln_class: "authentication".into(),
            app_type: "web".into(),
            prompt: include_str!("../../agents/default_auth.md").to_string(),
            focus_endpoints: vec!["/auth".into(), "/login".into(), "/token".into(), "/oauth".into()],
        },
        SpecialistProfile {
            name: "injection-specialist".into(),
            vuln_class: "injection".into(),
            app_type: "web".into(),
            prompt: include_str!("../../agents/default_injection.md").to_string(),
            focus_endpoints: vec![],
        },
        SpecialistProfile {
            name: "access-control-specialist".into(),
            vuln_class: "access_control".into(),
            app_type: "web".into(),
            prompt: include_str!("../../agents/default_access_control.md").to_string(),
            focus_endpoints: vec![],
        },
    ]
}
