#!/usr/bin/env bash
# CodexSec — Run a security assessment
# Usage: ./scripts/run-assessment.sh
# Prerequisites: ANTHROPIC_API_KEY must be set in your environment
set -euo pipefail

cd "$(dirname "$0")/.."

if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
    echo "ERROR: ANTHROPIC_API_KEY not set. Run: export ANTHROPIC_API_KEY=sk-ant-..."
    exit 1
fi

# Clean previous state
rm -f state.db findings-*.json 2>/dev/null || true

# Kill any existing bridge
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

# Start bridge (inherits ANTHROPIC_API_KEY from this shell)
python3 tools/anthropic-bridge/bridge.py &
BRIDGE_PID=$!
sleep 2

# Verify bridge is running
if ! kill -0 $BRIDGE_PID 2>/dev/null; then
    echo "ERROR: Bridge failed to start. Check logs above."
    exit 1
fi

echo ""
echo "Bridge running (PID $BRIDGE_PID). Starting assessment..."
echo ""

# Run Codex with security assessment prompt
codex exec --trust \
    -m claude-opus-4-6 \
    --dangerously-bypass-approvals-and-sandbox \
    "You are a security assessment agent. Read AGENTS.md and target.toml, then begin a full security assessment of the target. Follow the methodology phases: recon, enumeration, exploitation. Use the MCP tools: add_endpoint to register discovered endpoints, log_attempt before/after each exploit test, report_finding with full http_request for auto-validation. Call check_progress every 5-10 iterations. Use the tool wrappers (python3 tools/wrappers/run_tool.py) for structured output. When you find a vulnerability, document it with full HTTP request/response proof."

echo ""
echo "Assessment complete. Findings:"
cat findings-*.json 2>/dev/null || echo "No findings file found."

# Cleanup
kill $BRIDGE_PID 2>/dev/null || true
