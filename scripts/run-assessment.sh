#!/usr/bin/env bash
# DexRed — Run a security assessment
# Usage: ./scripts/run-assessment.sh [model] [mode]
#
# Modes:
#   pipeline  — Multi-agent: recon → specialists in parallel → dedup (DEFAULT)
#   single    — Single agent (legacy, for comparison benchmarks)
#
# Prerequisites: ANTHROPIC_API_KEY must be set in your environment
set -euo pipefail

cd "$(dirname "$0")/.."

MODEL="${1:-claude-opus-4-6}"
MODE="${2:-pipeline}"

if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
    echo "ERROR: ANTHROPIC_API_KEY not set. Run: export ANTHROPIC_API_KEY=sk-ant-..."
    exit 1
fi

# Start LiteLLM proxy
export LITELLM_MASTER_KEY="${LITELLM_MASTER_KEY:-$ANTHROPIC_API_KEY}"
export PATH="$HOME/.local/bin:$PATH"
pkill -f litellm 2>/dev/null || true
sleep 1

litellm --config tools/litellm-config.yaml --port 8087 --num_workers 1 &
PROXY_PID=$!
sleep 8

if curl -s -H "Authorization: Bearer $LITELLM_MASTER_KEY" http://localhost:8087/health | grep -q healthy; then
    echo "LiteLLM proxy running (PID $PROXY_PID)"
else
    echo "WARNING: LiteLLM health check didn't confirm healthy, proceeding..."
fi

if [ "$MODE" = "pipeline" ]; then
    echo "Running multi-agent pipeline..."
    bash scripts/run-pipeline.sh "$MODEL" 1
elif [ "$MODE" = "single" ]; then
    echo "Running single agent (legacy mode)..."
    rm -f state.db findings-*.json 2>/dev/null || true
    codex exec --trust \
        -m "$MODEL" \
        --dangerously-bypass-approvals-and-sandbox \
        "You are a security assessment agent. Read AGENTS.md and target.toml, then begin a full security assessment of the target. Follow the methodology phases: recon, enumeration, exploitation. Use the MCP tools for tracking. Report findings with full HTTP request/response proof."
    echo ""
    echo "Assessment complete. Findings:"
    cat findings-*.json 2>/dev/null || echo "No findings file found."
else
    echo "ERROR: Unknown mode '$MODE'. Use 'pipeline' or 'single'."
    exit 1
fi

# Cleanup
kill $PROXY_PID 2>/dev/null || true
