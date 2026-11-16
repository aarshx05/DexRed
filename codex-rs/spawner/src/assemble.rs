//! Dynamic specialist prompt assembly.
//!
//! Builds each specialist's prompt at runtime based on:
//! - The specialist's base profile (from agents/specialists/)
//! - Recon results (tech stack, endpoints, auth methods)
//! - Shared attack surface DB (other agents' discoveries)
//!
//! This means the injection specialist gets Django-specific payloads if
//! Django is detected, the auth specialist gets the exact auth endpoints
//! found, and nobody tests endpoints another agent already covered.

use crate::config::SpecialistProfile;
use crate::pipeline::ReconResults;

/// Tech-stack-specific payload hints injected into specialist prompts.
const TECH_HINTS: &[(&str, &str, &str)] = &[
    ("django", "injection", concat!(
        "Django uses parameterized queries by default but raw SQL via .extra() and .raw() is vulnerable. ",
        "Test: ORM bypass via __regex, __contains lookups. Check for DEBUG=True (stack traces). ",
        "Django REST Framework: test serializer validation bypass, permission_classes misconfiguration.")),
    ("flask", "injection", concat!(
        "Flask uses Jinja2 templates - test SSTI with {{7*7}}. Check for debug mode (Werkzeug debugger). ",
        "Flask-SQLAlchemy: text() queries may be injectable. Check for secret_key in config.")),
    ("express", "injection", concat!(
        "Express/Node.js: test prototype pollution via __proto__ in JSON bodies. ",
        "MongoDB backend likely - test NoSQL injection with $gt, $ne operators. ",
        "Check for eval(), Function() usage in server code. Test path traversal with ../ in routes.")),
    ("spring", "injection", concat!(
        "Spring Boot: test actuator endpoints (/actuator/env, /actuator/heapdump). ",
        "SpEL injection in expression-based annotations. Check for H2 console (/h2-console). ",
        "Mass assignment via Jackson: @JsonProperty fields may be bindable.")),
    ("laravel", "injection", concat!(
        "Laravel uses Eloquent ORM but raw queries via DB::raw() are vulnerable. ",
        "Blade templates: test for unescaped output. ",
        "Check for APP_DEBUG=true (stack traces with paths). Test artisan routes.")),
    ("mongodb", "injection", concat!(
        "Primary target for NoSQL injection. Test EVERY input field with: ",
        "$gt, $ne, $regex, $where operators. ",
        "Check for aggregation pipeline injection. Test operator injection in URL params.")),
    ("postgresql", "injection", concat!(
        "PostgreSQL supports stacked queries (;) - test for multi-statement injection. ",
        "pg_sleep(N) for time-based blind. COPY TO for file write. ",
        "Check for PL/pgSQL functions with EXECUTE.")),
    ("mysql", "injection", concat!(
        "MySQL: SLEEP(N) for time-based blind. LOAD_FILE() for file read. INTO OUTFILE for write. ",
        "GROUP BY with FLOOR(RAND()) for error-based extraction.")),
    ("jwt", "authentication", concat!(
        "JWT detected - run the full JWT attack chain: ",
        "1) alg:none 2) HS256 with RS256 public key 3) kid injection 4) jku/x5u 5) weak secret. ",
        "Check /jwks.json and /.well-known/jwks.json for public keys.")),
    ("graphql", "api_security", concat!(
        "GraphQL detected - run introspection first. ",
        "Test batching (array of queries), alias-based rate limit bypass, nested query DoS. ",
        "Check for mutations that bypass permission checks.")),
    ("docker", "ssrf", concat!(
        "Docker environment detected - internal services likely on Docker network. ",
        "Test SSRF to: 172.17.0.0/16 (default Docker bridge), common service ports. ",
        "Docker API: http://172.17.0.1:2375/containers/json")),
    ("aws", "ssrf", concat!(
        "AWS environment - SSRF to metadata service is critical: ",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/ for temp credentials.")),
    ("redis", "injection", concat!(
        "Redis backend: test for SSRF to redis://localhost:6379. ",
        "If command injection exists, Redis commands: CONFIG SET dir, SET payload, BGSAVE.")),
];

/// Assemble a specialist's prompt dynamically based on recon results.
pub fn assemble_prompt(
    specialist: &SpecialistProfile,
    recon: &ReconResults,
    shared_findings: &[String],
) -> String {
    let mut sections = Vec::new();

    sections.push(specialist.prompt.clone());

    let tech_hints = get_tech_hints(&specialist.vuln_class, &recon.tech_stack);
    if !tech_hints.is_empty() {
        sections.push(format!(
            "\n--- TECH-SPECIFIC GUIDANCE ---\n\
             Detected tech stack: {}\n\n{}",
            recon.tech_stack.join(", "),
            tech_hints.join("\n\n"),
        ));
    }

    let relevant_endpoints = get_relevant_endpoints(specialist, recon);
    if !relevant_endpoints.is_empty() {
        let ep_list: String = relevant_endpoints
            .iter()
            .map(|ep| format!("  {} {} (params: {}, auth: {})",
                ep.method, ep.url,
                ep.params.join(", "),
                ep.auth_required,
            ))
            .collect::<Vec<_>>()
            .join("\n");

        sections.push(format!(
            "\n--- RECON RESULTS ({} relevant endpoints) ---\n\
             Auth methods: {}\n\
             Endpoints:\n{}\n--- END RECON ---",
            relevant_endpoints.len(),
            recon.auth_methods.join(", "),
            ep_list,
        ));
    }

    if !shared_findings.is_empty() {
        sections.push(format!(
            "\n--- ALREADY FOUND (by other agents — skip these) ---\n{}\n--- END ---",
            shared_findings.join("\n"),
        ));
    }

    sections.join("\n")
}

fn get_tech_hints(vuln_class: &str, tech_stack: &[String]) -> Vec<String> {
    let mut hints = Vec::new();
    let tech_lower: Vec<String> = tech_stack.iter().map(|t| t.to_lowercase()).collect();

    for (pattern, target_class, hint) in TECH_HINTS {
        if vuln_class.to_lowercase() == *target_class || *target_class == "any" {
            if tech_lower.iter().any(|t| t.contains(pattern)) {
                hints.push(hint.to_string());
            }
        }
    }
    hints
}

fn get_relevant_endpoints<'a>(
    specialist: &SpecialistProfile,
    recon: &'a ReconResults,
) -> Vec<&'a crate::pipeline::ReconEndpoint> {
    recon
        .endpoints
        .iter()
        .filter(|ep| ep.matches_specialist(specialist))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SpecialistProfile;
    use crate::pipeline::ReconResults;

    #[test]
    fn adds_django_hints_for_injection_specialist() {
        let specialist = SpecialistProfile {
            name: "injection".into(),
            vuln_class: "injection".into(),
            app_type: "web".into(),
            prompt: "Base injection prompt.".into(),
            focus_endpoints: vec![],
        };
        let recon = ReconResults {
            endpoints: vec![],
            tech_stack: vec!["Python".into(), "Django".into(), "PostgreSQL".into()],
            auth_methods: vec!["jwt".into()],
            api_docs_found: false,
        };

        let assembled = assemble_prompt(&specialist, &recon, &[]);
        assert!(assembled.contains("Django uses parameterized"));
        assert!(assembled.contains("PostgreSQL supports stacked"));
    }

    #[test]
    fn no_hints_for_unrelated_tech() {
        let specialist = SpecialistProfile {
            name: "auth".into(),
            vuln_class: "authentication".into(),
            app_type: "web".into(),
            prompt: "Base auth prompt.".into(),
            focus_endpoints: vec![],
        };
        let recon = ReconResults {
            endpoints: vec![],
            tech_stack: vec!["Rust".into(), "Actix".into()],
            auth_methods: vec![],
            api_docs_found: false,
        };

        let assembled = assemble_prompt(&specialist, &recon, &[]);
        assert!(!assembled.contains("TECH-SPECIFIC"));
    }

    #[test]
    fn includes_shared_findings_to_skip() {
        let specialist = SpecialistProfile {
            name: "injection".into(),
            vuln_class: "injection".into(),
            app_type: "web".into(),
            prompt: "Base.".into(),
            focus_endpoints: vec![],
        };
        let recon = ReconResults {
            endpoints: vec![],
            tech_stack: vec![],
            auth_methods: vec![],
            api_docs_found: false,
        };

        let existing = vec!["[High] SQLi on /api/login — found by injection-run0".into()];
        let assembled = assemble_prompt(&specialist, &recon, &existing);
        assert!(assembled.contains("ALREADY FOUND"));
        assert!(assembled.contains("SQLi on /api/login"));
    }
}
