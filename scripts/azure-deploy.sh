#!/usr/bin/env bash
# CodexSec — Deploy target + harness to Azure VM
# Usage: bash scripts/azure-deploy.sh [target-name]
#
# This script:
# 1. Creates an auto-deleting Azure resource group (12h TTL)
# 2. Deploys a VM with all security tools pre-installed
# 3. Deploys the target application (e.g., crAPI)
# 4. Pushes CodexSec harness files to the VM
# 5. Waits for setup and prints connection details
#
# Prerequisites:
#   - Azure CLI logged in (az login)
#   - Visual Studio Enterprise subscription active
#   - SSH key pair (~/.ssh/id_rsa)
#
# The ANTHROPIC_API_KEY is NOT baked in — pass it at runtime.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

TARGET="${1:-crapi}"
RG_NAME="codexsec-${TARGET}-test"
VM_NAME="codexsec-vm"
VM_SIZE="Standard_D4s_v3"
LOCATION="centralindia"
TTL_HOURS=12

echo "================================================"
echo "  CodexSec Azure Deploy"
echo "  Target: $TARGET"
echo "  VM: $VM_SIZE in $LOCATION"
echo "  Auto-delete: ${TTL_HOURS}h"
echo "================================================"

# Create resource group
echo "[1/6] Creating resource group..."
az group create --name "$RG_NAME" --location "$LOCATION" \
  --tags "auto-delete=true" "purpose=codexsec-test" \
  --output none

# Create VM with cloud-init
echo "[2/6] Creating VM (this takes ~2 min)..."
VM_IP=$(az vm create \
  --resource-group "$RG_NAME" \
  --name "$VM_NAME" \
  --image Ubuntu2404 \
  --size "$VM_SIZE" \
  --admin-username azureuser \
  --generate-ssh-keys \
  --custom-data "$PROJECT_DIR/scripts/cloud-init-crapi.yaml" \
  --public-ip-sku Standard \
  --nsg-rule SSH \
  --tags "auto-delete=true" "purpose=codexsec-test" \
  --query "publicIpAddress" \
  --output tsv 2>/dev/null)
echo "  VM IP: $VM_IP"

# Open ports
echo "[3/6] Opening ports..."
az vm open-port --resource-group "$RG_NAME" --name "$VM_NAME" \
  --port 8888,8025,8443,80,443 --priority 1010 --output none 2>/dev/null

# Set auto-shutdown
echo "[4/6] Setting auto-shutdown..."
SHUTDOWN_TIME=$(date -u -d "+${TTL_HOURS} hours" '+%H%M' 2>/dev/null || python3 -c "from datetime import datetime,timedelta,timezone;print((datetime.now(timezone.utc)+timedelta(hours=$TTL_HOURS)).strftime('%H%M'))")
az vm auto-shutdown --resource-group "$RG_NAME" --name "$VM_NAME" \
  --time "$SHUTDOWN_TIME" --output none 2>/dev/null || true

# Wait for SSH
echo "[5/6] Waiting for SSH..."
for i in $(seq 1 30); do
  if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 azureuser@"$VM_IP" "echo ok" 2>/dev/null; then
    break
  fi
  sleep 5
done

# Push CodexSec files
echo "[6/6] Pushing harness files..."
ssh -o StrictHostKeyChecking=no azureuser@"$VM_IP" \
  "mkdir -p /home/azureuser/codexsec/{prompts/methodology,prompts/tools,tools/report-finding,tools/anthropic-bridge,tools/hooks,tools/orchestrator,tools/wrappers,tools/firewall,config-examples,scripts,.codex}"

scp -o StrictHostKeyChecking=no -q \
  "$PROJECT_DIR/AGENTS.md" \
  "$PROJECT_DIR/target-crapi.toml" \
  azureuser@"$VM_IP":/home/azureuser/codexsec/

scp -o StrictHostKeyChecking=no -q \
  "$PROJECT_DIR/tools/anthropic-bridge/bridge.py" \
  azureuser@"$VM_IP":/home/azureuser/codexsec/tools/anthropic-bridge/

scp -o StrictHostKeyChecking=no -q \
  "$PROJECT_DIR/tools/orchestrator/server.py" \
  azureuser@"$VM_IP":/home/azureuser/codexsec/tools/orchestrator/

scp -o StrictHostKeyChecking=no -q \
  "$PROJECT_DIR/tools/wrappers/run_tool.py" \
  azureuser@"$VM_IP":/home/azureuser/codexsec/tools/wrappers/

scp -o StrictHostKeyChecking=no -q \
  "$PROJECT_DIR/tools/firewall/enforce.sh" \
  azureuser@"$VM_IP":/home/azureuser/codexsec/tools/firewall/

scp -o StrictHostKeyChecking=no -q \
  "$PROJECT_DIR/tools/report-finding/server.py" \
  azureuser@"$VM_IP":/home/azureuser/codexsec/tools/report-finding/

scp -o StrictHostKeyChecking=no -q \
  "$PROJECT_DIR/prompts/methodology/"*.md \
  azureuser@"$VM_IP":/home/azureuser/codexsec/prompts/methodology/ 2>/dev/null || true

scp -o StrictHostKeyChecking=no -q \
  "$PROJECT_DIR/prompts/tools/"*.md \
  azureuser@"$VM_IP":/home/azureuser/codexsec/prompts/tools/ 2>/dev/null || true

scp -o StrictHostKeyChecking=no -q \
  "$PROJECT_DIR/config-examples/"*.toml \
  azureuser@"$VM_IP":/home/azureuser/codexsec/config-examples/ 2>/dev/null || true

scp -o StrictHostKeyChecking=no -q \
  "$PROJECT_DIR/scripts/"*.sh \
  azureuser@"$VM_IP":/home/azureuser/codexsec/scripts/ 2>/dev/null || true

# Set up target.toml
ssh -o StrictHostKeyChecking=no azureuser@"$VM_IP" \
  "cd /home/azureuser/codexsec && cp target-crapi.toml target.toml"

# Write Codex config
ssh -o StrictHostKeyChecking=no azureuser@"$VM_IP" "
mkdir -p ~/.codex
cat > ~/.codex/config.toml << 'EOF'
model = \"claude-opus-4-6\"
model_provider = \"anthropic\"
project_doc_max_bytes = 65536

[model_providers.anthropic]
name = \"Anthropic (via CodexSec Bridge)\"
base_url = \"http://localhost:8087/v1\"
env_key = \"ANTHROPIC_API_KEY\"
wire_api = \"responses\"
EOF
"

echo ""
echo "================================================"
echo "  DEPLOYED"
echo "  VM IP: $VM_IP"
echo "  Resource Group: $RG_NAME"
echo "  Auto-shutdown: ${TTL_HOURS}h from now"
echo ""
echo "  Cloud-init is still installing tools."
echo "  Wait ~5 min, then run the assessment:"
echo ""
echo "  ssh azureuser@$VM_IP"
echo "  export ANTHROPIC_API_KEY='sk-ant-...'"
echo "  cd /home/azureuser/codexsec && bash scripts/run-assessment.sh"
echo ""
echo "  Or to delete early:"
echo "  az group delete --name $RG_NAME --yes --no-wait"
echo "================================================"

# Save the IP for later use
echo "$VM_IP" > "$PROJECT_DIR/.last-vm-ip"
echo "$RG_NAME" > "$PROJECT_DIR/.last-rg"
