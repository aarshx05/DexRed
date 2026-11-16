#!/usr/bin/env bash
# CodexSec — Run assessment on an existing Azure VM
# Usage: bash scripts/run-on-vm.sh <VM_IP> <ANTHROPIC_API_KEY> [model]
#
# Called by the orchestrator after azure-deploy.sh has set up the VM.
set -euo pipefail

VM_IP="${1:?Usage: run-on-vm.sh <VM_IP> <API_KEY> [model]}"
API_KEY="${2:?Missing ANTHROPIC_API_KEY}"
MODEL="${3:-claude-opus-4-6}"

echo "Running assessment on $VM_IP with model $MODEL..."

# Write the .codex config with orchestrator MCP server
ssh -o StrictHostKeyChecking=no azureuser@"$VM_IP" "
mkdir -p /home/azureuser/codexsec/.codex
cat > /home/azureuser/codexsec/.codex/config.toml << 'CFGEOF'
sandbox = \"danger-full-access\"
approval_policy = \"full-auto\"
project_doc_max_bytes = 65536

[mcp_servers.codexsec-orchestrator]
type = \"stdio\"
command = \"python3\"
args = [\"tools/orchestrator/server.py\"]
enabled = true
CFGEOF
"

# Write the start script with the API key
ssh -o StrictHostKeyChecking=no azureuser@"$VM_IP" "
cat > /home/azureuser/codexsec/start.sh << 'RUNEOF'
#!/bin/bash
export ANTHROPIC_API_KEY=\"$API_KEY\"
cd /home/azureuser/codexsec

# Clean previous state
rm -f state.db findings-*.json 2>/dev/null

# Set up network firewall (Phase 2 scope enforcement)
if [ -f tools/firewall/enforce.sh ]; then
    sudo bash tools/firewall/enforce.sh target.toml 2>/dev/null || echo 'Firewall setup skipped (non-root)'
fi

pkill -f bridge.py 2>/dev/null
sleep 1
python3 tools/anthropic-bridge/bridge.py &
sleep 3
codex exec --trust -m $MODEL --dangerously-bypass-approvals-and-sandbox \
  \"You are a security assessment agent. Read AGENTS.md and target.toml, then begin a full security assessment of the target application. Follow the methodology phases: recon, enumeration, exploitation. Use the MCP tools: add_endpoint to register endpoints, log_attempt before/after exploits, report_finding with http_request for auto-validation, check_progress every 5-10 iterations. Use tool wrappers (python3 tools/wrappers/run_tool.py) for structured output. Focus on: BOLA/IDOR, broken auth, JWT attacks, injection, SSRF, mass assignment, race conditions.\"
RUNEOF
chmod +x /home/azureuser/codexsec/start.sh
"

# Launch in background
ssh -o StrictHostKeyChecking=no azureuser@"$VM_IP" \
  "nohup bash /home/azureuser/codexsec/start.sh > /home/azureuser/codexsec/assessment.log 2>&1 &"

echo "Assessment launched. Monitor with:"
echo "  ssh azureuser@$VM_IP 'tail -f /home/azureuser/codexsec/assessment.log'"
echo ""
echo "Check findings:"
echo "  ssh azureuser@$VM_IP 'cat /home/azureuser/codexsec/findings-crapi.json'"
