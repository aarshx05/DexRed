//! DexRed Spawner — The pipeline brain, in Rust.
//!
//! Single binary that orchestrates the full assessment pipeline:
//!   Phase 0: SAST (whitebox) if source code available
//!   Phase 1: Recon agent maps attack surface
//!   Phase 2: Dynamic specialist selection + model alloy assignment
//!   Phase 3: Parallel specialist agents with best-of-N
//!   Phase 4: Dedup + HTML report generation
//!
//! Usage:
//!   dexred-spawner --target target.toml --pipeline
//!   dexred-spawner --target target.toml --pipeline --model-override claude-opus-4-6
//!   dexred-spawner --target target.toml --max-specialists 4

mod config;
mod agent;
mod alloy;
mod assemble;
mod dedup;
mod pipeline;
mod report;
mod selector;

use clap::Parser;
use std::path::PathBuf;
use std::time::Instant;
use tracing::info;

#[derive(Parser)]
#[command(name = "dexred-spawner", about = "DexRed assessment pipeline — the brain")]
struct Cli {
    /// Path to target.toml
    #[arg(short, long, default_value = "target.toml")]
    target: PathBuf,

    /// Directory containing specialist agent profiles
    #[arg(short, long, default_value = "agents/specialists")]
    agents: PathBuf,

    /// Number of agents per specialist (best-of-N)
    #[arg(short, long, default_value = "1")]
    n: u32,

    /// Override model for all agents (bypasses alloy config)
    #[arg(long)]
    model_override: Option<String>,

    /// Path to alloy config (model-per-task assignment)
    #[arg(long, default_value = "tools/alloy-config.yaml")]
    alloy_config: PathBuf,

    /// Run the full pipeline (recon → select → specialists → dedup → report)
    #[arg(long)]
    pipeline: bool,

    /// Max specialists to spawn (0 = no limit, overrides target.toml)
    #[arg(long, default_value = "0")]
    max_specialists: usize,

    /// Force specific specialists (comma-separated, overrides auto-selection)
    #[arg(long)]
    force_specialists: Option<String>,

    /// Output directory for findings and report
    #[arg(short, long, default_value = ".")]
    output_dir: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let start = Instant::now();
    let cli = Cli::parse();

    let target = config::TargetConfig::load(&cli.target)?;
    let alloy = if let Some(ref model) = cli.model_override {
        info!("Model override: {} (alloy disabled)", model);
        alloy::Alloy::empty()
    } else {
        alloy::Alloy::load(&cli.alloy_config)
    };

    let force_list: Vec<String> = cli.force_specialists
        .as_deref()
        .map(|s| s.split(',').map(|x| x.trim().to_string()).collect())
        .unwrap_or_default();

    info!("DexRed Spawner starting");
    info!("  Target: {}", target.base_url());
    info!("  Methodology: {}", target.target.methodology);
    info!("  App type: {}", target.target.app_type);
    info!("  Pipeline: {}", cli.pipeline);

    if cli.pipeline {
        // ── Phase 1: Recon ──
        let recon_assignment = alloy.get_recon();
        let recon_model = cli.model_override.as_deref().unwrap_or(&recon_assignment.model);
        info!("[Phase 1] Recon with {} ({} turns)", recon_model, recon_assignment.max_turns);

        let recon = pipeline::run_recon_phase(
            &target,
            recon_model,
            recon_assignment.max_turns,
        )
        .await?;

        info!("Recon complete: {} endpoints, tech: {:?}", recon.endpoints.len(), recon.tech_stack);

        // ── Phase 2: Select specialists ──
        let selected = selector::select(
            &target,
            &recon,
            &cli.agents,
            cli.max_specialists,
            &force_list,
        );

        info!("[Phase 2] Selected {} specialists:", selected.len());
        for s in &selected {
            let assignment = alloy.get_specialist(&s.alloy_key);
            let model = cli.model_override.as_deref().unwrap_or(&assignment.model);
            info!("  {} → {} ({} turns)", s.name, model, assignment.max_turns);
        }

        // ── Phase 3: Spawn specialists ──
        let specialists: Vec<config::SpecialistProfile> = selected.iter().filter_map(|s| {
            let path = cli.agents.join(&s.profile_file);
            std::fs::read_to_string(&path).ok().map(|prompt| {
                let _assignment = alloy.get_specialist(&s.alloy_key);
                config::SpecialistProfile {
                    name: s.name.clone(),
                    vuln_class: s.name.clone(),
                    app_type: target.target.app_type.clone(),
                    prompt,
                    focus_endpoints: vec![],
                }
            })
        }).collect();

        let mut all_findings = Vec::new();
        for spec in &specialists {
            let assignment = alloy.get_specialist(&selector::alloy_key(&spec.name));
            let model = cli.model_override.as_deref().unwrap_or(&assignment.model);

            let findings = agent::spawn_all(
                &target,
                &[spec.clone()],
                model,
                cli.n,
                assignment.max_turns,
            )
            .await?;
            all_findings.extend(findings);
        }

        // ── Phase 4: Dedup + Report ──
        let deduped = dedup::deduplicate(all_findings);
        let findings_path = cli.output_dir.join("merged-findings.json");
        dedup::write_merged_findings(&deduped, &findings_path)?;

        let report_path = cli.output_dir.join("report.html");
        let metadata = report::ReportMetadata {
            target: target.base_url(),
            duration_secs: start.elapsed().as_secs(),
            agents_used: selected.len(),
        };
        report::generate(&deduped, &metadata, &report_path)?;

        info!("Pipeline complete in {}s: {} unique findings → {}",
            start.elapsed().as_secs(), deduped.len(), report_path.display());
    } else {
        // Single-shot mode: load all profiles and run
        let specialists = config::load_specialist_profiles(&cli.agents)?;
        let model = cli.model_override.as_deref().unwrap_or("claude-opus-4-6");

        let all_findings = agent::spawn_all(
            &target,
            &specialists,
            model,
            cli.n,
            80,
        )
        .await?;

        let deduped = dedup::deduplicate(all_findings);
        let findings_path = cli.output_dir.join("merged-findings.json");
        dedup::write_merged_findings(&deduped, &findings_path)?;

        info!("Assessment complete: {} unique findings", deduped.len());
    }

    Ok(())
}

mod anyhow {
    pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
}
