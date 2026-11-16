//! Model alloy — assigns the right model and turn budget per task.
//!
//! Reads alloy-config.yaml and returns (model, max_turns) for
//! each specialist, recon, validation, and SAST task.

use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

const DEFAULT_MODEL: &str = "claude-opus-4-6";
const DEFAULT_TURNS: u32 = 80;

#[derive(Debug, Deserialize)]
struct AlloyConfig {
    recon: Option<TaskConfig>,
    specialists: Option<HashMap<String, TaskConfig>>,
    validation: Option<TaskConfig>,
    sast: Option<TaskConfig>,
    default: Option<TaskConfig>,
}

#[derive(Debug, Clone, Deserialize)]
struct TaskConfig {
    model: Option<String>,
    max_turns: Option<u32>,
    #[allow(dead_code)]
    rationale: Option<String>,
}

pub struct ModelAssignment {
    pub model: String,
    pub max_turns: u32,
}

pub struct Alloy {
    config: Option<AlloyConfig>,
}

impl Alloy {
    pub fn load(config_path: &Path) -> Self {
        let config = if config_path.exists() {
            match std::fs::read_to_string(config_path) {
                Ok(content) => match serde_yaml::from_str(&content) {
                    Ok(c) => Some(c),
                    Err(e) => {
                        tracing::warn!("Failed to parse alloy config: {}", e);
                        None
                    }
                },
                Err(e) => {
                    tracing::warn!("Failed to read alloy config: {}", e);
                    None
                }
            }
        } else {
            None
        };
        Self { config }
    }

    pub fn empty() -> Self {
        Self { config: None }
    }

    pub fn get_recon(&self) -> ModelAssignment {
        self.resolve_task(self.config.as_ref().and_then(|c| c.recon.as_ref()), 30)
    }

    pub fn get_specialist(&self, specialist_key: &str) -> ModelAssignment {
        let section = self.config.as_ref()
            .and_then(|c| c.specialists.as_ref())
            .and_then(|s| s.get(specialist_key));
        self.resolve_task(section, DEFAULT_TURNS)
    }

    pub fn get_validation(&self) -> ModelAssignment {
        self.resolve_task(self.config.as_ref().and_then(|c| c.validation.as_ref()), 10)
    }

    pub fn get_sast(&self) -> ModelAssignment {
        self.resolve_task(self.config.as_ref().and_then(|c| c.sast.as_ref()), 20)
    }

    fn resolve_task(&self, section: Option<&TaskConfig>, default_turns: u32) -> ModelAssignment {
        let default_config = self.config.as_ref().and_then(|c| c.default.as_ref());

        let model = section
            .and_then(|s| s.model.as_ref())
            .or_else(|| default_config.and_then(|d| d.model.as_ref()))
            .cloned()
            .unwrap_or_else(|| DEFAULT_MODEL.to_string());

        let max_turns = section
            .and_then(|s| s.max_turns)
            .or_else(|| default_config.and_then(|d| d.max_turns))
            .unwrap_or(default_turns);

        ModelAssignment { model, max_turns }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn defaults_when_no_config() {
        let alloy = Alloy::empty();
        let recon = alloy.get_recon();
        assert_eq!(recon.model, "claude-opus-4-6");
        assert_eq!(recon.max_turns, 30);
    }

    #[test]
    fn reads_yaml_config() {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, r#"
recon:
  model: claude-haiku-5-5
  max_turns: 25
specialists:
  auth:
    model: claude-opus-4-6
    max_turns: 80
  ssrf:
    model: claude-sonnet-5-5
    max_turns: 60
default:
  model: claude-opus-4-6
  max_turns: 80
"#).unwrap();

        let alloy = Alloy::load(f.path());
        let recon = alloy.get_recon();
        assert_eq!(recon.model, "claude-haiku-5-5");
        assert_eq!(recon.max_turns, 25);

        let auth = alloy.get_specialist("auth");
        assert_eq!(auth.model, "claude-opus-4-6");

        let ssrf = alloy.get_specialist("ssrf");
        assert_eq!(ssrf.model, "claude-sonnet-5-5");
        assert_eq!(ssrf.max_turns, 60);

        let unknown = alloy.get_specialist("unknown");
        assert_eq!(unknown.model, "claude-opus-4-6");
    }
}
