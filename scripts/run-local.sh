#!/usr/bin/env bash
# DexRed — Run assessment using local Ollama models
# Usage: ./scripts/run-local.sh [target_url] [model] [mode]
#
# Models: coder-fast (fastest), coder (7B), reason (Llama 8B)
# Modes:  pipeline (multi-agent), single (one agent)
#
# Prerequisites:
#   - Ollama running on localhost:11434 (start-harness.bat)
#   - For VM: SSH tunnel (ssh -N -R 11434:127.0.0.1:11434 azureuser@VM_IP)
set -euo pipefail

cd "$(dirname "$0")/.."

TARGET="${1:-http://localhost:8888}"
MODEL="${2:-coder-fast}"
MODE="${3:-single}"

# Point at local Ollama
export OLLAMA_BASE_URL="${OLLAMA_BASE_URL:-http://127.0.0.1:11434/v1}"
export LITELLM_MASTER_KEY="ollama-local"
export ANTHROPIC_API_KEY="ollama-local"

echo "========================================"
echo "  DexRed — Local Model Run"
echo "  Target: $TARGET"
echo "  Model: $MODEL"
echo "  Ollama: $OLLAMA_BASE_URL"
echo "  Mode: $MODE"
echo "========================================"

# Verify Ollama is reachable
if ! curl -s "$OLLAMA_BASE_URL/../api/tags" > /dev/null 2>&1; then
    # Try the v1 models endpoint
    if ! curl -s "${OLLAMA_BASE_URL}/models" > /dev/null 2>&1; then
        echo "WARNING: Can't reach Ollama at $OLLAMA_BASE_URL"
        echo "Make sure start-harness.bat is running"
    fi
fi

# Start LiteLLM proxy
pkill -f litellm 2>/dev/null || true
sleep 1

litellm --config tools/litellm-config.yaml --port 8087 --num_workers 1 &
PROXY_PID=$!
sleep 5

echo "LiteLLM proxy started (PID $PROXY_PID)"

if [ "$MODE" = "pipeline" ]; then
    bash scripts/run-pipeline.sh "$MODEL" 1
elif [ "$MODE" = "single" ]; then
    rm -f state.db findings-*.json 2>/dev/null || true
    codex exec --trust \
        -m "$MODEL" \
        --dangerously-bypass-approvals-and-sandbox \
        "You are a security assessment agent. Read AGENTS.md and target.toml, then begin a full security assessment of the target at $TARGET. Follow the methodology phases: recon, enumeration, exploitation. Report findings with full HTTP request/response proof."
    echo ""
    cat findings-*.json 2>/dev/null || echo "No findings."
fi

kill $PROXY_PID 2>/dev/null || true
