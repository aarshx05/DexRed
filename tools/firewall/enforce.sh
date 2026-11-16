#!/usr/bin/env bash
# CodexSec Phase 2 — Network-Level Scope Enforcement
#
# Reads target.toml, resolves target domains, and creates iptables rules
# that block all outbound traffic except:
#   - Target domain IPs
#   - Localhost / private ranges (for local services like crAPI)
#   - Anthropic API (for the bridge)
#   - DNS (for resolution)
#
# Usage: sudo bash tools/firewall/enforce.sh [target.toml]
# Must run as root.

set -euo pipefail

TARGET_FILE="${1:-./target.toml}"

if [ ! -f "$TARGET_FILE" ]; then
    echo "ERROR: $TARGET_FILE not found"
    exit 1
fi

DOMAINS=$(python3 -c "
import tomllib
with open('$TARGET_FILE', 'rb') as f:
    config = tomllib.load(f)
for d in config.get('target', {}).get('domains', []):
    print(d)
" 2>/dev/null)

if [ -z "$DOMAINS" ]; then
    echo "WARNING: No domains in target.toml — firewall not configured."
    exit 0
fi

echo "=== CodexSec Network Scope Enforcement ==="
echo "Allowed domains:"
echo "$DOMAINS" | sed 's/^/  - /'

# Resolve domains
ALLOWED_IPS=""
while IFS= read -r domain; do
    ips=$(dig +short "$domain" 2>/dev/null | grep -E '^[0-9]+\.' || true)
    if [ -n "$ips" ]; then
        ALLOWED_IPS="$ALLOWED_IPS $ips"
        echo "  $domain -> $ips"
    else
        echo "  WARNING: could not resolve $domain"
    fi
done <<< "$DOMAINS"

# Build iptables chain
iptables -N CODEXSEC_OUT 2>/dev/null || iptables -F CODEXSEC_OUT

# Loopback
iptables -A CODEXSEC_OUT -o lo -j ACCEPT
# Established
iptables -A CODEXSEC_OUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# DNS
iptables -A CODEXSEC_OUT -p udp --dport 53 -j ACCEPT
iptables -A CODEXSEC_OUT -p tcp --dport 53 -j ACCEPT

# Anthropic API
for ip in $(dig +short api.anthropic.com 2>/dev/null | grep -E '^[0-9]+\.' || true); do
    iptables -A CODEXSEC_OUT -d "$ip" -j ACCEPT
done

# Target domains
for ip in $ALLOWED_IPS; do
    iptables -A CODEXSEC_OUT -d "$ip" -j ACCEPT
done

# Private ranges (crAPI, Docker, etc.)
iptables -A CODEXSEC_OUT -d 10.0.0.0/8 -j ACCEPT
iptables -A CODEXSEC_OUT -d 172.16.0.0/12 -j ACCEPT
iptables -A CODEXSEC_OUT -d 192.168.0.0/16 -j ACCEPT
iptables -A CODEXSEC_OUT -d 169.254.0.0/16 -j ACCEPT

# Log + drop
iptables -A CODEXSEC_OUT -j LOG --log-prefix "CODEXSEC_BLOCKED: " --log-level 4
iptables -A CODEXSEC_OUT -j DROP

# Wire into OUTPUT
iptables -I OUTPUT 1 -j CODEXSEC_OUT

echo ""
echo "Firewall active. Blocked traffic logged to syslog."
echo "Disable: iptables -D OUTPUT -j CODEXSEC_OUT && iptables -F CODEXSEC_OUT"
