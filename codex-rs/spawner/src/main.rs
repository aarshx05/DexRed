//! DexRed Best-of-N Agent Spawner
//!
//! Orchestrates parallel security assessment agents, each focused on a
//! specific vulnerability class or endpoint group. Implements the XBOW
//! pattern: many short-lived narrow agents (~80 iterations each) beat
//! a single long-running orchestrator.
//!
//! Usage:
//!   dexred-spawner --target target.toml --agents agents/specialists/ --n 3
//!
//! Each agent gets:
//! - A specialist prompt (from agents/specialists/)
//! - A focused scope (subset of endpoints or vuln class)
//! - An iteration budget (~80 turns)
//! - Its own findings output file
//!
//! The spawner collects all findings, deduplicates by (endpoint, CWE, payload),
//! and merges reproduction steps from the clearest agent.

mod config;
mod agent;
mod assemble;
mod dedup;
mod pipeline;

use clap::Parser;
use std::path::PathBuf;
use tracing::info;

#[derive(Parser)]
#[command(name = "dexred-spawner", about = "Best-of-N security assessment agent spawner")]
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

    /// Max iterations per agent
    #[arg(long, default_value = "80")]
    max_turns: u32,

    /// Model to use
    #[arg(short, long, default_value = "claude-opus-4-6")]
    model: String,

    /// Run recon phase first, then feed results to specialists
    #[arg(long)]
    pipeline: bool,

    /// Output file for merged findings
    #[arg(short, long, default_value = "findings-merged.json")]
    output: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();

    let target = config::TargetConfig::load(&cli.target)?;
    let specialists = config::load_specialist_profiles(&cli.agents)?;

    info!(
        "DexRed Spawner: {} specialists, best-of-{}, {} max turns each",
        specialists.len(),
        cli.n,
        cli.max_turns,
    );

    if cli.pipeline {
        info!("Pipeline mode: recon → hunt");
        let recon_findings = pipeline::run_recon_phase(
            &target,
            &cli.model,
            cli.max_turns,
        )
        .await?;

        info!("Recon complete: {} endpoints discovered", recon_findings.endpoints.len());

        let all_findings = pipeline::run_hunt_phase(
            &target,
            &recon_findings,
            &specialists,
            &cli.model,
            cli.n,
            cli.max_turns,
        )
        .await?;

        let deduped = dedup::deduplicate(all_findings);
        dedup::write_merged_findings(&deduped, &cli.output)?;

        info!("Pipeline complete: {} unique findings", deduped.len());
    } else {
        let all_findings = agent::spawn_all(
            &target,
            &specialists,
            &cli.model,
            cli.n,
            cli.max_turns,
        )
        .await?;

        let deduped = dedup::deduplicate(all_findings);
        dedup::write_merged_findings(&deduped, &cli.output)?;

        info!("Assessment complete: {} unique findings", deduped.len());
    }

    Ok(())
}

mod anyhow {
    pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
}
