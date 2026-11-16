//! Dynamic specialist selection based on app_type + recon results.
//!
//! No hardcoded specialist list. Reads target config and recon output,
//! matches signals to specialist types, applies priority ordering and
//! hard cap from config.

use crate::config::TargetConfig;
use crate::pipeline::ReconResults;
use std::collections::HashSet;
use std::path::Path;

const PRIORITY_ORDER: &[&str] = &[
    "auth", "injection", "access-control", "api-security", "ssrf",
    "business-logic", "info-disclosure", "file-upload", "mobile",
    "agentic", "websocket", "cache-poisoning", "http-smuggling",
];

/// Signals in recon data that trigger specific specialists.
fn signal_map() -> Vec<(&'static str, &'static str)> {
    vec![
        ("jwt", "auth"), ("bearer", "auth"), ("oauth", "auth"),
        ("session", "auth"), ("login", "auth"), ("token", "auth"),
        ("otp", "auth"), ("password", "auth"),

        ("sql", "injection"), ("query", "injection"), ("search", "injection"),
        ("filter", "injection"), ("mongodb", "injection"), ("nosql", "injection"),
        ("template", "injection"),

        ("id", "access-control"), ("user", "access-control"),
        ("admin", "access-control"), ("role", "access-control"),

        ("url", "ssrf"), ("uri", "ssrf"), ("link", "ssrf"),
        ("webhook", "ssrf"), ("callback", "ssrf"), ("fetch", "ssrf"),

        ("order", "business-logic"), ("payment", "business-logic"),
        ("cart", "business-logic"), ("coupon", "business-logic"),
        ("transfer", "business-logic"), ("balance", "business-logic"),

        ("upload", "file-upload"), ("file", "file-upload"),
        ("image", "file-upload"), ("avatar", "file-upload"),

        ("ws", "websocket"), ("socket", "websocket"), ("chat", "websocket"),

        ("cache", "cache-poisoning"), ("cdn", "cache-poisoning"),
        ("proxy", "http-smuggling"),
    ]
}

fn base_specialists(app_type: &str) -> Vec<&'static str> {
    match app_type {
        "web" => vec!["auth", "injection", "access-control", "api-security", "info-disclosure"],
        "mobile" => vec!["mobile", "auth", "access-control", "api-security"],
        "agentic" => vec!["agentic", "auth", "injection", "api-security"],
        _ => vec!["auth", "injection", "access-control", "api-security", "info-disclosure"],
    }
}

/// Profile filename for a specialist type.
pub fn profile_filename(specialist: &str) -> String {
    format!("{}-specialist.md", specialist)
}

/// Alloy config key for model selection.
pub fn alloy_key(specialist: &str) -> &'static str {
    match specialist {
        "auth" => "auth",
        "injection" => "injection",
        "access-control" => "access_control",
        "ssrf" => "ssrf",
        "business-logic" => "business_logic",
        "api-security" | "file-upload" | "websocket" | "cache-poisoning"
        | "http-smuggling" | "info-disclosure" => "api_security",
        "mobile" => "access_control",
        "agentic" => "injection",
        _ => "default",
    }
}

#[derive(Debug, Clone)]
pub struct SelectedSpecialist {
    pub name: String,
    pub profile_file: String,
    pub alloy_key: String,
}

/// Select specialists based on target config and recon results.
pub fn select(
    target: &TargetConfig,
    recon: &ReconResults,
    agents_dir: &Path,
    max_specialists: usize,
    force_list: &[String],
) -> Vec<SelectedSpecialist> {
    let mut selected: HashSet<String> = HashSet::new();

    if !force_list.is_empty() {
        for s in force_list {
            selected.insert(s.clone());
        }
    } else {
        for s in base_specialists(&target.target.app_type) {
            selected.insert(s.to_string());
        }

        let signal_text = build_signal_text(recon);
        let lower = signal_text.to_lowercase();
        for (signal, specialist) in signal_map() {
            if lower.contains(signal) {
                selected.insert(specialist.to_string());
            }
        }
    }

    let mut ordered: Vec<String> = selected.into_iter().collect();
    ordered.sort_by_key(|s| {
        PRIORITY_ORDER.iter().position(|p| p == s).unwrap_or(99)
    });

    let mut available = Vec::new();
    for spec in &ordered {
        let filename = profile_filename(spec);
        let path = agents_dir.join(&filename);
        if path.exists() {
            available.push(SelectedSpecialist {
                name: spec.clone(),
                profile_file: filename,
                alloy_key: alloy_key(spec).to_string(),
            });
        } else {
            tracing::warn!("{} selected but {} not found, skipping", spec, path.display());
        }
    }

    if max_specialists > 0 && available.len() > max_specialists {
        let dropped: Vec<_> = available[max_specialists..].iter().map(|s| s.name.clone()).collect();
        available.truncate(max_specialists);
        tracing::info!("Hard cap: {} specialists. Dropped: {:?}", max_specialists, dropped);
    }

    available
}

fn build_signal_text(recon: &ReconResults) -> String {
    let mut text = String::with_capacity(4096);
    for ep in &recon.endpoints {
        text.push_str(&ep.url);
        text.push(' ');
        text.push_str(&ep.method);
        text.push(' ');
        for p in &ep.params {
            text.push_str(p);
            text.push(' ');
        }
        for t in &ep.tags {
            text.push_str(t);
            text.push(' ');
        }
    }
    for t in &recon.tech_stack {
        text.push_str(t);
        text.push(' ');
    }
    for a in &recon.auth_methods {
        text.push_str(a);
        text.push(' ');
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::{ReconEndpoint, ReconResults};
    use tempfile::tempdir;
    use std::fs;

    fn make_recon(endpoints: Vec<(&str, &str, Vec<&str>)>, tech: Vec<&str>) -> ReconResults {
        ReconResults {
            endpoints: endpoints.into_iter().map(|(url, method, tags)| ReconEndpoint {
                url: url.to_string(),
                method: method.to_string(),
                auth_required: false,
                params: vec![],
                content_type: String::new(),
                tags: tags.into_iter().map(String::from).collect(),
            }).collect(),
            tech_stack: tech.into_iter().map(String::from).collect(),
            auth_methods: vec!["jwt".to_string()],
            api_docs_found: false,
        }
    }

    #[test]
    fn web_app_gets_base_specialists() {
        let dir = tempdir().unwrap();
        for name in ["auth", "injection", "access-control", "api-security", "info-disclosure"] {
            fs::write(dir.path().join(format!("{name}-specialist.md")), "test").unwrap();
        }

        let target = TargetConfig {
            target: crate::config::TargetSection {
                domains: vec!["localhost".into()],
                app_type: "web".into(),
                methodology: "blackbox".into(),
                max_turns: 80,
                findings_output: None,
                scope: None,
                context: None,
            },
        };
        let recon = make_recon(vec![], vec![]);
        let result = select(&target, &recon, dir.path(), 0, &[]);
        let names: Vec<_> = result.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"auth"));
        assert!(names.contains(&"injection"));
    }

    #[test]
    fn recon_triggers_ssrf_specialist() {
        let dir = tempdir().unwrap();
        for name in ["auth", "injection", "access-control", "api-security", "info-disclosure", "ssrf"] {
            fs::write(dir.path().join(format!("{name}-specialist.md")), "test").unwrap();
        }

        let target = TargetConfig {
            target: crate::config::TargetSection {
                domains: vec!["localhost".into()],
                app_type: "web".into(),
                methodology: "blackbox".into(),
                max_turns: 80,
                findings_output: None,
                scope: None,
                context: None,
            },
        };
        let recon = make_recon(
            vec![("/api/contact", "POST", vec!["url_param"])],
            vec!["python"],
        );
        let result = select(&target, &recon, dir.path(), 0, &[]);
        let names: Vec<_> = result.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"ssrf"));
    }

    #[test]
    fn hard_cap_limits_specialists() {
        let dir = tempdir().unwrap();
        for name in ["auth", "injection", "access-control", "api-security", "info-disclosure", "ssrf", "business-logic"] {
            fs::write(dir.path().join(format!("{name}-specialist.md")), "test").unwrap();
        }

        let target = TargetConfig {
            target: crate::config::TargetSection {
                domains: vec!["localhost".into()],
                app_type: "web".into(),
                methodology: "blackbox".into(),
                max_turns: 80,
                findings_output: None,
                scope: None,
                context: None,
            },
        };
        let recon = make_recon(
            vec![("/api/orders", "POST", vec!["payment"]), ("/api/webhook", "POST", vec!["url"])],
            vec!["python", "jwt"],
        );
        let result = select(&target, &recon, dir.path(), 4, &[]);
        assert_eq!(result.len(), 4);
        assert_eq!(result[0].name, "auth");
    }

    #[test]
    fn force_list_overrides_selection() {
        let dir = tempdir().unwrap();
        for name in ["auth", "ssrf"] {
            fs::write(dir.path().join(format!("{name}-specialist.md")), "test").unwrap();
        }

        let target = TargetConfig {
            target: crate::config::TargetSection {
                domains: vec!["localhost".into()],
                app_type: "web".into(),
                methodology: "blackbox".into(),
                max_turns: 80,
                findings_output: None,
                scope: None,
                context: None,
            },
        };
        let recon = make_recon(vec![], vec![]);
        let result = select(&target, &recon, dir.path(), 0, &["auth".into(), "ssrf".into()]);
        assert_eq!(result.len(), 2);
    }
}
