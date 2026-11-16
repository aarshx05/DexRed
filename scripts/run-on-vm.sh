#!/usr/bin/env bash
# CodexSec — Run assessment on an existing Azure VM
# Usage: bash scripts/run-on-vm.sh <VM_IP> <ANTHROPIC_API_KEY> [model]
set -euo pipefail

VM_IP="${1:?Usage: run-on-vm.sh <VM_IP> <API_KEY> [model]}"
API_KEY="${2:?Missing ANTHROPIC_API_KEY}"
MODEL="${3:-claude-opus-4-6}"

echo "Running assessment on $VM_IP with model $MODEL..."

# Write .codex project config
ssh -o StrictHostKeyChecking=no azureuser@"$VM_IP" 'mkdir -p /home/azureuser/codexsec/.codex && cat > /home/azureuser/codexsec/.codex/config.toml << "EOF"
sandbox = "danger-full-access"
project_doc_max_bytes = 65536

[mcp_servers.codexsec-orchestrator]
type = "stdio"
command = "python3"
args = ["tools/orchestrator/server.py"]
enabled = true
EOF'

# Write user-level Codex config (pointing to LiteLLM proxy)
ssh -o StrictHostKeyChecking=no azureuser@"$VM_IP" 'mkdir -p ~/.codex && cat > ~/.codex/config.toml << "EOF"
model = "claude-opus-4-6"
model_provider = "anthropic"
project_doc_max_bytes = 65536

[model_providers.anthropic]
name = "Anthropic (via LiteLLM Proxy)"
base_url = "http://localhost:8087/v1"
env_key = "ANTHROPIC_API_KEY"
wire_api = "responses"
EOF'

# Write start script
ssh -o StrictHostKeyChecking=no azureuser@"$VM_IP" "cat > /home/azureuser/codexsec/start.sh << RUNEOF
#!/bin/bash
export ANTHROPIC_API_KEY=\"$API_KEY\"
cd /home/azureuser/codexsec

# Clean previous state
rm -f state.db findings-*.json 2>/dev/null

# Set up network firewall
if [ -f tools/firewall/enforce.sh ]; then
    sudo bash tools/firewall/enforce.sh target.toml 2>/dev/null || echo 'Firewall skipped'
fi

# Kill old processes
pkill -f litellm 2>/dev/null
pkill -f bridge.py 2>/dev/null
sleep 1

# Start LiteLLM proxy
litellm --config tools/litellm-config.yaml --port 8087 --num_workers 1 &
sleep 5

# Verify proxy
if curl -s http://localhost:8087/health > /dev/null 2>&1; then
    echo 'LiteLLM proxy ready'
else
    echo 'WARNING: LiteLLM health check failed'
fi

codex exec --trust -m $MODEL --dangerously-bypass-approvals-and-sandbox \\
  \"You are a security assessment agent. Read AGENTS.md and target.toml, then begin a full security assessment of the target application. Follow the methodology phases: recon, enumeration, exploitation. Use the MCP tools: add_endpoint to register endpoints, log_attempt before/after exploits, report_finding with http_request for auto-validation, check_progress every 5-10 iterations. Use tool wrappers (python3 tools/wrappers/run_tool.py) for structured output. Focus on: BOLA/IDOR, broken auth, JWT attacks, injection, SSRF, mass assignment, race conditions.\"
RUNEOF
chmod +x /home/azureuser/codexsec/start.sh"

# Launch in background
ssh -o StrictHostKeyChecking=no azureuser@"$VM_IP" \
  "nohup bash /home/azureuser/codexsec/start.sh > /home/azureuser/codexsec/assessment.log 2>&1 &"

echo "Assessment launched. Monitor with:"
echo "  ssh azureuser@$VM_IP 'tail -f /home/azureuser/codexsec/assessment.log'"
