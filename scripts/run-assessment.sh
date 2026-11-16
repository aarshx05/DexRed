#!/usr/bin/env bash
# CodexSec — Run a security assessment
# Usage: ./scripts/run-assessment.sh [model]
# Prerequisites: ANTHROPIC_API_KEY must be set in your environment
set -euo pipefail

cd "$(dirname "$0")/.."

MODEL="${1:-claude-opus-4-6}"

if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
    echo "ERROR: ANTHROPIC_API_KEY not set. Run: export ANTHROPIC_API_KEY=sk-ant-..."
    exit 1
fi

# Clean previous state
rm -f state.db findings-*.json 2>/dev/null || true

# Kill any existing proxy
pkill -f "litellm" 2>/dev/null || true
pkill -f "bridge.py" 2>/dev/null || true
sleep 1

# Set up network-level scope enforcement (Phase 2)
if [ -f tools/firewall/enforce.sh ] && [ "$(id -u)" = "0" ]; then
    echo "Setting up network firewall..."
    bash tools/firewall/enforce.sh target.toml
elif [ -f tools/firewall/enforce.sh ]; then
    echo "NOTE: Run as root for network-level scope enforcement (sudo)."
    echo "      Proceeding with prompt-level scope checks only."
fi

# Start LiteLLM proxy (replaces custom bridge)
echo "Starting LiteLLM proxy..."
litellm --config tools/litellm-config.yaml --port 8087 --num_workers 1 &
PROXY_PID=$!
sleep 5

# Verify proxy is running
if ! kill -0 $PROXY_PID 2>/dev/null; then
    echo "ERROR: LiteLLM proxy failed to start."
    exit 1
fi

# Health check
if curl -s http://localhost:8087/health > /dev/null 2>&1; then
    echo "LiteLLM proxy running (PID $PROXY_PID)"
else
    echo "WARNING: LiteLLM health check failed, proceeding anyway..."
fi

echo ""
echo "Starting assessment with model: $MODEL"
echo ""

# Run Codex with security assessment prompt
codex exec --trust \
    -m "$MODEL" \
    --dangerously-bypass-approvals-and-sandbox \
    "You are a security assessment agent. Read AGENTS.md and target.toml, then begin a full security assessment of the target. Follow the methodology phases: recon, enumeration, exploitation. Use the MCP tools: add_endpoint to register discovered endpoints, log_attempt before/after each exploit test, report_finding with full http_request for auto-validation. Call check_progress every 5-10 iterations. Use the tool wrappers (python3 tools/wrappers/run_tool.py) for structured output. When you find a vulnerability, document it with full HTTP request/response proof."

echo ""
echo "Assessment complete. Findings:"
cat findings-*.json 2>/dev/null || echo "No findings file found."

# Cleanup
kill $PROXY_PID 2>/dev/null || true
