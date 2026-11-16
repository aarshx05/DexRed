#!/usr/bin/env bash
# DexRed Multi-Agent Pipeline
# Usage: ./scripts/run-pipeline.sh [model_override] [n_per_specialist]
#
# Fully integrated pipeline:
# 1. Reads target.toml for methodology (blackbox/whitebox/greybox)
# 2. If whitebox: runs SAST first, feeds static findings to specialists
# 3. Recon agent maps the attack surface
# 4. Specialist agents run in parallel with model alloy (right model per task)
# 5. Collects, deduplicates, and generates HTML report
#
# Requires: ANTHROPIC_API_KEY set in environment (or LITELLM_MASTER_KEY)
set -euo pipefail

cd "$(dirname "$0")/.."
PIPELINE_START=$(date +%s)

MODEL_OVERRIDE="${1:-}"
N="${2:-1}"

if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
    echo "ERROR: ANTHROPIC_API_KEY not set"
    exit 1
fi

# ── Read target config ──────────────────────────────────────────────────────

eval "$(python3 -c "
import tomllib
with open('target.toml', 'rb') as f:
    c = tomllib.load(f)
t = c.get('target', {})
d = t.get('domains', ['localhost:8888'])[0]
url = f'http://{d}' if not d.startswith('http') else d
print(f'TARGET_URL=\"{url}\"')
print(f'METHODOLOGY=\"{t.get(\"methodology\", \"blackbox\")}\"')
print(f'SOURCE_PATH=\"{c.get(\"target\", {}).get(\"context\", {}).get(\"source_code_path\", \"\")}\"')
")"

# ── Model alloy: get model per task ─────────────────────────────────────────

get_model() {
    local task="$1"
    local specialist="${2:-}"
    if [ -n "$MODEL_OVERRIDE" ]; then
        echo "$MODEL_OVERRIDE"
        return
    fi
    python3 -c "
import sys; sys.path.insert(0, 'tools')
from alloy import get_model
m, _ = get_model('$task', '$specialist')
print(m)
" 2>/dev/null || echo "claude-opus-4-6"
}

get_turns() {
    local task="$1"
    local specialist="${2:-}"
    python3 -c "
import sys; sys.path.insert(0, 'tools')
from alloy import get_model
_, t = get_model('$task', '$specialist')
print(t)
" 2>/dev/null || echo "80"
}

RECON_MODEL=$(get_model recon)
RECON_TURNS=$(get_turns recon)

echo "========================================"
echo "  DexRed Multi-Agent Pipeline"
echo "  Target: $TARGET_URL"
echo "  Methodology: $METHODOLOGY"
echo "  Recon model: $RECON_MODEL"
echo "  Agents per specialist: $N"
if [ -n "$MODEL_OVERRIDE" ]; then
    echo "  Model override: $MODEL_OVERRIDE (alloy disabled)"
fi
echo "========================================"

# Clean previous state
rm -f state.db findings-*.json recon-results.json merged-findings.json sast-findings.json report.html 2>/dev/null

# ── Phase 0: SAST (whitebox/greybox only) ──────────────────────────────────

SAST_CONTEXT=""
if [ "$METHODOLOGY" = "whitebox" ] || [ "$METHODOLOGY" = "greybox" ]; then
    if [ -n "$SOURCE_PATH" ] && [ -d "$SOURCE_PATH" ]; then
        echo ""
        echo "[Phase 0] SAST — static analysis on source code"
        echo "  Source: $SOURCE_PATH"
        echo ""

        SAST_MODEL=$(get_model sast)
        python3 -c "
import sys; sys.path.insert(0, 'tools/sast')
from analyzer import run_sast
import json
result = run_sast('$SOURCE_PATH')
print(json.dumps(result, indent=2))
" 2>/dev/null | tee /tmp/sast-summary.json || true

        if [ -f sast-findings.json ]; then
            SAST_COUNT=$(python3 -c "import json;print(len(json.load(open('sast-findings.json')).get('findings',[])))" 2>/dev/null || echo 0)
            echo "  SAST found $SAST_COUNT static findings"

            SAST_CONTEXT=$(python3 -c "
import json
data = json.load(open('sast-findings.json'))
findings = data.get('findings', [])[:20]
lines = []
for f in findings:
    lines.append(f\"{f.get('severity','?')}: {f.get('message','')[:80]} ({f.get('file','')}:{f.get('line',0)})\")
print('\n'.join(lines))
" 2>/dev/null || echo "")
        fi
    else
        echo ""
        echo "[Phase 0] SAST skipped — source_code_path not set or not found"
    fi
fi

# ── Phase 1: Recon ──────────────────────────────────────────────────────────

echo ""
echo "[Phase 1] Recon — mapping attack surface (model: $RECON_MODEL, $RECON_TURNS turns)"
echo ""

codex exec --trust -m "$RECON_MODEL" --dangerously-bypass-approvals-and-sandbox \
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

# Dynamic specialist selection based on app_type + recon results
echo "  Selecting specialists based on app_type=$METHODOLOGY and recon..."
SPECIALISTS_JSON=$(python3 tools/specialist_selector.py target.toml recon-results.json 2>/dev/null || echo '[]')
SPEC_COUNT=$(echo "$SPECIALISTS_JSON" | python3 -c "import sys,json;print(len(json.load(sys.stdin)))" 2>/dev/null || echo 0)
echo "  Selected $SPEC_COUNT specialists"
echo ""

PIDS=()
AGENT_NAMES=()

for SPEC_IDX in $(seq 0 $((SPEC_COUNT-1))); do
    SPEC=$(echo "$SPECIALISTS_JSON" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d[$SPEC_IDX]['name'])" 2>/dev/null)
    PROFILE=$(echo "$SPECIALISTS_JSON" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d[$SPEC_IDX]['profile'])" 2>/dev/null)
    ALLOY_KEY=$(echo "$SPECIALISTS_JSON" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d[$SPEC_IDX]['alloy_key'])" 2>/dev/null)

    SPEC_MODEL=$(get_model specialist "$ALLOY_KEY")
    SPEC_TURNS=$(get_turns specialist "$ALLOY_KEY")

    for RUN in $(seq 0 $((N-1))); do
        AGENT_NAME="${SPEC}-agent-${RUN}"
        FINDINGS_FILE="findings-${AGENT_NAME}.json"
        LOG_FILE="agent-${AGENT_NAME}.log"

        echo "  Launching: $AGENT_NAME (model: $SPEC_MODEL, ${SPEC_TURNS} turns)"

        PROFILE_CONTENT=""
        if [ -f "agents/specialists/${PROFILE}.md" ]; then
            PROFILE_CONTENT=$(cat "agents/specialists/${PROFILE}.md")
        fi

        PROMPT_FILE="/tmp/prompt-${AGENT_NAME}.txt"
        cat > "$PROMPT_FILE" << PROMPTEOF
You are a security specialist agent. Read your methodology below and test ONLY your specialty area.

Target: $TARGET_URL
You have $SPEC_TURNS iterations. Write findings to $FINDINGS_FILE by writing JSON directly.
Report ALL findings with full HTTP request/response proof.

--- SPECIALIST METHODOLOGY ---
$PROFILE_CONTENT
--- END METHODOLOGY ---

--- RECON RESULTS ---
$RECON_CONTEXT
--- END RECON ---
PROMPTEOF

        if [ -n "$SAST_CONTEXT" ]; then
            cat >> "$PROMPT_FILE" << SASTEOF

--- SAST STATIC FINDINGS (confirm these dynamically) ---
$SAST_CONTEXT
--- END SAST ---
SASTEOF
        fi

        PROMPT=$(cat "$PROMPT_FILE")
        codex exec --trust -m "$SPEC_MODEL" --dangerously-bypass-approvals-and-sandbox \
          "$PROMPT" > "$LOG_FILE" 2>&1 &

        PIDS+=($!)
        AGENT_NAMES+=("$AGENT_NAME")
    done
done

echo ""
echo "  ${#PIDS[@]} agents launched. Waiting for completion..."
echo ""

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

# ── Phase 3: Collect, Deduplicate, Report ───────────────────────────────────

echo ""
echo "[Phase 3] Collecting, deduplicating, and generating report"
echo ""

python3 tools/dedup.py

# Generate HTML report
python3 tools/report/generate.py merged-findings.json report.html 2>/dev/null || true

PIPELINE_END=$(date +%s)
DURATION=$((PIPELINE_END - PIPELINE_START))

echo ""
echo "========================================"
echo "  DexRed Pipeline Complete"
echo "  Duration: ${DURATION}s"
echo "  Report: report.html"
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
