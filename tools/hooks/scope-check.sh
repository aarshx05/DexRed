#!/usr/bin/env bash
# CodexSec PreToolUse Hook — Scope Enforcement
# Reads the tool call from stdin (JSON) and blocks requests to out-of-scope domains.
# Configure in .codex/config.toml hooks section.
#
# This is a SOFT check (prompt-level). Phase 2 adds network-level enforcement.

set -euo pipefail

# Read the hook input from stdin
INPUT=$(cat)

# Extract the tool input (command being executed)
TOOL_NAME=$(echo "$INPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('tool_name',''))" 2>/dev/null || echo "")

# Only check shell commands
if [ "$TOOL_NAME" != "shell" ] && [ "$TOOL_NAME" != "container.exec" ]; then
    # Allow non-shell tools (like report_finding)
    echo '{"decision": "approve"}'
    exit 0
fi

# Extract the command being run
COMMAND=$(echo "$INPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('input',{}).get('command',''))" 2>/dev/null || echo "")

# Load allowed domains from target.toml
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TARGET_FILE="$PROJECT_ROOT/target.toml"

if [ ! -f "$TARGET_FILE" ]; then
    echo '{"decision": "approve"}'
    exit 0
fi

# Extract target domains
DOMAINS=$(python3 -c "
import tomllib
with open('$TARGET_FILE', 'rb') as f:
    config = tomllib.load(f)
domains = config.get('target', {}).get('domains', [])
for d in domains:
    print(d)
" 2>/dev/null || echo "")

if [ -z "$DOMAINS" ]; then
    # No domains configured — allow everything (user hasn't set up targets yet)
    echo '{"decision": "approve"}'
    exit 0
fi

# Check if the command contains any URLs that are NOT in the allowed domains
# This is a basic check — sophisticated evasion is caught by network-level enforcement in Phase 2
SUSPICIOUS=$(python3 -c "
import re, sys
command = '''$COMMAND'''
domains = '''$DOMAINS'''.strip().split('\n')

# Find all URLs and hostnames in the command
urls = re.findall(r'https?://([^/\s:]+)', command)
# Also check curl/wget targets
curl_targets = re.findall(r'(?:curl|wget|httpx|ffuf|nuclei|nmap|sqlmap)\s+.*?(?:https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', command)

all_hosts = set(urls + curl_targets)
# Remove common safe hosts
safe_hosts = {'localhost', '127.0.0.1', '::1', 'github.com', 'raw.githubusercontent.com'}
check_hosts = all_hosts - safe_hosts

if not check_hosts:
    print('ok')
    sys.exit(0)

for host in check_hosts:
    in_scope = False
    for domain in domains:
        if host == domain or host.endswith('.' + domain):
            in_scope = True
            break
    if not in_scope:
        print(f'blocked:{host}')
        sys.exit(0)
print('ok')
" 2>/dev/null || echo "ok")

if [[ "$SUSPICIOUS" == blocked:* ]]; then
    BLOCKED_HOST="${SUSPICIOUS#blocked:}"
    echo "{\"decision\": \"deny\", \"reason\": \"Out of scope: $BLOCKED_HOST is not in the authorized target list. Check target.toml.\"}"
else
    echo '{"decision": "approve"}'
fi
