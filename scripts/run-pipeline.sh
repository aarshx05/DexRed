#!/usr/bin/env bash
# DexRed Multi-Agent Pipeline
# Usage: ./scripts/run-pipeline.sh [model] [n_per_specialist]
#
# This is DexRed's primary run mode. It:
# 1. Starts LiteLLM proxy
# 2. Runs a recon agent to map the attack surface
# 3. Launches specialist agents in parallel (auth, injection, access control, SSRF, business logic, API)
# 4. Each specialist gets recon results + its focused methodology
# 5. Collects and deduplicates findings across all agents
#
# Requires: ANTHROPIC_API_KEY set in environment
set -euo pipefail

cd "$(dirname "$0")/.."

MODEL="${1:-claude-opus-4-6}"
N="${2:-1}"  # agents per specialist
MAX_TURNS=80
RECON_TURNS=30

if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
    echo "ERROR: ANTHROPIC_API_KEY not set"
    exit 1
fi

echo "========================================"
echo "  DexRed Multi-Agent Pipeline"
echo "  Model: $MODEL"
echo "  Agents per specialist: $N"
echo "  Max turns per agent: $MAX_TURNS"
echo "========================================"

# Clean previous state
rm -f state.db findings-*.json recon-results.json merged-findings.json 2>/dev/null

# Read target
TARGET_URL=$(python3 -c "
import tomllib
with open('target.toml', 'rb') as f:
    c = tomllib.load(f)
d = c.get('target', {}).get('domains', ['localhost:8888'])[0]
print(f'http://{d}' if not d.startswith('http') else d)
")
echo "Target: $TARGET_URL"

# ── Phase 1: Recon ──────────────────────────────────────────────────────────

echo ""
echo "[Phase 1] Recon — mapping attack surface ($RECON_TURNS turns)"
echo ""

codex exec --trust -m "$MODEL" --dangerously-bypass-approvals-and-sandbox \
  "You are a RECON-ONLY agent. Your job is to MAP the attack surface of $TARGET_URL, NOT exploit it.

1. Discover ALL API endpoints using curl, directory bruting, and manual crawling
2. For each endpoint: identify HTTP method, parameters, auth requirements
3. Identify the tech stack, auth mechanisms (JWT/session/OAuth), and API docs
4. Find all user-facing features (registration, login, profile, orders, vehicles, community, mechanics)

When done, write results to recon-results.json:
{
  \"endpoints\": [{\"url\": \"/api/...\", \"method\": \"GET\", \"auth_required\": true, \"params\": [\"id\"], \"tags\": [\"user_data\"]}],
  \"tech_stack\": [\"python\", \"mongodb\", \"jwt\"],
  \"auth_methods\": [\"jwt_bearer\"],
  \"users\": [{\"email\": \"...\", \"token\": \"...\"}]
}

Create at least 2 test user accounts and capture their auth tokens. DO NOT test for vulnerabilities." \
  > recon.log 2>&1 || true

# Check if recon produced results
if [ ! -f recon-results.json ]; then
    echo "WARNING: Recon didn't produce recon-results.json, creating minimal version"
    echo '{"endpoints":[],"tech_stack":[],"auth_methods":[],"users":[]}' > recon-results.json
fi

ENDPOINTS=$(python3 -c "import json; print(len(json.load(open('recon-results.json')).get('endpoints',[])))" 2>/dev/null || echo 0)
echo "Recon found $ENDPOINTS endpoints"

# ── Phase 2: Specialist Agents ──────────────────────────────────────────────

echo ""
echo "[Phase 2] Launching specialist agents in parallel"
echo ""

RECON_CONTEXT=$(cat recon-results.json 2>/dev/null || echo '{}')

# Specialist definitions — name:profile_file
SPEC_LIST="auth:auth-specialist injection:injection-specialist access:access-control-specialist ssrf:ssrf-specialist logic:business-logic-specialist api:api-security-specialist"

PIDS=()
AGENT_NAMES=()

for SPEC_ENTRY in $SPEC_LIST; do
    SPEC="${SPEC_ENTRY%%:*}"
    PROFILE="${SPEC_ENTRY##*:}"

    for RUN in $(seq 0 $((N-1))); do
        AGENT_NAME="${SPEC}-agent-${RUN}"
        FINDINGS_FILE="findings-${AGENT_NAME}.json"
        LOG_FILE="agent-${AGENT_NAME}.log"

        echo "  Launching: $AGENT_NAME"

        # Build prompt from profile file — avoids bash variable expansion issues
        PROFILE_CONTENT=""
        if [ -f "agents/specialists/${PROFILE}.md" ]; then
            PROFILE_CONTENT=$(cat "agents/specialists/${PROFILE}.md")
        fi

        # Write prompt to temp file to avoid shell expansion of $ne/$gt etc.
        PROMPT_FILE="/tmp/prompt-${AGENT_NAME}.txt"
        cat > "$PROMPT_FILE" << PROMPTEOF
You are a security specialist agent. Read your methodology below and test ONLY your specialty area.

Target: $TARGET_URL
You have $MAX_TURNS iterations. Write findings to $FINDINGS_FILE by writing JSON directly.
Report ALL findings with full HTTP request/response proof.

--- SPECIALIST METHODOLOGY ---
$PROFILE_CONTENT
--- END METHODOLOGY ---

--- RECON RESULTS ---
$RECON_CONTEXT
--- END RECON ---
PROMPTEOF

        PROMPT=$(cat "$PROMPT_FILE")
        codex exec --trust -m "$MODEL" --dangerously-bypass-approvals-and-sandbox \
          "$PROMPT" > "$LOG_FILE" 2>&1 &

        PIDS+=($!)
        AGENT_NAMES+=("$AGENT_NAME")
    done
done

echo ""
echo "  ${#PIDS[@]} agents launched. Waiting for completion..."
echo ""

# Wait for all agents
COMPLETED=0
FAILED=0
for i in "${!PIDS[@]}"; do
    if wait "${PIDS[$i]}" 2>/dev/null; then
        echo "  ✓ ${AGENT_NAMES[$i]} completed"
        ((COMPLETED++))
    else
        echo "  ✗ ${AGENT_NAMES[$i]} failed"
        ((FAILED++))
    fi
done

echo ""
echo "  $COMPLETED completed, $FAILED failed"

# ── Phase 3: Collect and Deduplicate ────────────────────────────────────────

echo ""
echo "[Phase 3] Collecting and deduplicating findings"
echo ""

python3 tools/dedup.py

echo ""
echo "========================================"
echo "  DexRed Pipeline Complete"
echo "========================================"
cat merged-findings.json 2>/dev/null | python3 -c "
import sys, json
d = json.load(sys.stdin)
findings = d.get('findings', d if isinstance(d, list) else [])
print(f'  Total unique findings: {len(findings)}')
sev = {}
for f in findings:
    s = f.get('severity', '?')
    sev[s] = sev.get(s, 0) + 1
for s in ['Critical', 'High', 'Medium', 'Low', 'Informational']:
    if s in sev: print(f'    {s}: {sev[s]}')
" 2>/dev/null || echo "  No findings file"
