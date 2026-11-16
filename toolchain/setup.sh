#!/usr/bin/env bash
# CodexSec Security Harness — Non-Docker Setup Script
# For bare-metal installs (Azure VM, EC2, dedicated server)
#
# Usage: sudo bash setup.sh [--minimal] [--mobile] [--sast]
#   --minimal  Install only core tools (discovery + fuzzing + exploitation)
#   --mobile   Include mobile testing tools (apktool, jadx, frida, objection)
#   --sast     Include SAST tools (semgrep, trufflehog, gitleaks, bandit, gosec)
#
# Default (no flags): installs core + sast (no mobile)

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[-]${NC} $1"; exit 1; }

INSTALL_MOBILE=false
INSTALL_SAST=true
MINIMAL=false

for arg in "$@"; do
    case $arg in
        --minimal) MINIMAL=true; INSTALL_SAST=false ;;
        --mobile)  INSTALL_MOBILE=true ;;
        --sast)    INSTALL_SAST=true ;;
    esac
done

# ============================================================
# System packages
# ============================================================
log "Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
    ca-certificates curl wget git jq unzip \
    nmap masscan \
    python3 python3-pip python3-venv \
    build-essential libssl-dev pkg-config \
    dnsutils netcat-openbsd iputils-ping \
    chromium chromium-driver 2>/dev/null || \
apt-get install -y -qq --no-install-recommends \
    ca-certificates curl wget git jq unzip \
    nmap masscan \
    python3 python3-pip python3-venv \
    build-essential libssl-dev pkg-config \
    dnsutils netcat-openbsd iputils-ping

# ============================================================
# Go toolchain
# ============================================================
if ! command -v go &>/dev/null; then
    log "Installing Go..."
    GO_VERSION="1.23.4"
    curl -sL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" | tar -C /usr/local -xzf -
    export PATH="/usr/local/go/bin:$PATH"
    echo 'export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"' >> /etc/profile.d/go.sh
fi
export GOPATH="${GOPATH:-$HOME/go}"
export PATH="$GOPATH/bin:$PATH"

# ============================================================
# Rust toolchain
# ============================================================
if ! command -v rustc &>/dev/null; then
    log "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal
    source "$HOME/.cargo/env"
fi

# ============================================================
# Go tools — Discovery
# ============================================================
log "Installing Go-based discovery tools..."
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/tomnomnom/waybackurls@latest

# ============================================================
# Go tools — Fuzzing
# ============================================================
log "Installing Go-based fuzzing tools..."
go install github.com/ffuf/ffuf/v2@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# ============================================================
# Rust tools — Fuzzing
# ============================================================
log "Installing Rust-based tools..."
cargo install feroxbuster
cargo install dalfox

# ============================================================
# Go tools — Exploitation
# ============================================================
log "Installing Go-based exploitation tools..."
go install github.com/assetnote/kiterunner/cmd/kr@latest

# ============================================================
# Python tools — Exploitation + Utilities
# ============================================================
log "Creating Python virtual environment..."
python3 -m venv /opt/codexsec-tools
VENV="/opt/codexsec-tools/bin"

log "Installing Python-based tools..."
$VENV/pip install --no-cache-dir -q \
    sqlmap \
    ssrfmap \
    jwt-tool \
    requests \
    beautifulsoup4 \
    "pyjwt[crypto]" \
    "httpx[http2]" \
    pycryptodome \
    websockets \
    graphql-core

# Symlink key tools
for tool in sqlmap jwt_tool ssrfmap; do
    if [ -f "$VENV/$tool" ]; then
        ln -sf "$VENV/$tool" /usr/local/bin/"$tool"
    fi
done

# Add venv to PATH
echo "export PATH=\"$VENV:\$PATH\"" >> /etc/profile.d/codexsec.sh

# ============================================================
# SAST tools (optional)
# ============================================================
if [ "$INSTALL_SAST" = true ] && [ "$MINIMAL" = false ]; then
    log "Installing SAST tools..."
    $VENV/pip install --no-cache-dir -q semgrep bandit
    go install github.com/trufflesecurity/trufflehog/v3@latest
    go install github.com/gitleaks/gitleaks/v8@latest
    go install github.com/securego/gosec/v2/cmd/gosec@latest
fi

# ============================================================
# Mobile tools (optional)
# ============================================================
if [ "$INSTALL_MOBILE" = true ]; then
    log "Installing mobile testing tools..."

    # Java (for apktool, jadx)
    apt-get install -y -qq default-jre-headless

    # apktool
    APKTOOL_VERSION=$(curl -s https://api.github.com/repos/iBotPeaches/Apktool/releases/latest | jq -r .tag_name | sed 's/v//')
    curl -Lo /usr/local/bin/apktool.jar "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar"
    printf '#!/bin/sh\njava -jar /usr/local/bin/apktool.jar "$@"\n' > /usr/local/bin/apktool
    chmod +x /usr/local/bin/apktool

    # jadx
    JADX_VERSION=$(curl -s https://api.github.com/repos/skylot/jadx/releases/latest | jq -r .tag_name | sed 's/v//')
    curl -Lo /tmp/jadx.zip "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip"
    mkdir -p /opt/jadx
    unzip -qo /tmp/jadx.zip -d /opt/jadx
    ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx
    rm /tmp/jadx.zip

    # frida + objection
    $VENV/pip install --no-cache-dir -q frida-tools objection
fi

# ============================================================
# Wordlists
# ============================================================
log "Downloading wordlists..."
mkdir -p /wordlists
curl -sLo /wordlists/common.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt
curl -sLo /wordlists/raft-medium-dirs.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt
curl -sLo /wordlists/raft-medium-files.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-files.txt
curl -sLo /wordlists/api-endpoints.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt
curl -sLo /wordlists/params.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt
curl -sLo /wordlists/subdomains.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt

# ============================================================
# Nuclei templates
# ============================================================
log "Updating nuclei templates..."
nuclei -update-templates 2>/dev/null || true

# ============================================================
# Create directories
# ============================================================
mkdir -p /workspace /findings /state

# ============================================================
# Verification
# ============================================================
log "Verifying installations..."
PASS=0
FAIL=0

check_tool() {
    if command -v "$1" &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} $1"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}✗${NC} $1"
        FAIL=$((FAIL + 1))
    fi
}

echo ""
echo "Core tools:"
for tool in httpx subfinder katana waybackurls ffuf feroxbuster nuclei nmap masscan curl jq python3 go rustc sqlmap dalfox kiterunner; do
    # kiterunner installs as 'kr'
    if [ "$tool" = "kiterunner" ]; then
        check_tool "kr"
    else
        check_tool "$tool"
    fi
done

if [ "$INSTALL_SAST" = true ] && [ "$MINIMAL" = false ]; then
    echo ""
    echo "SAST tools:"
    for tool in semgrep trufflehog gitleaks bandit gosec; do
        check_tool "$tool"
    done
fi

if [ "$INSTALL_MOBILE" = true ]; then
    echo ""
    echo "Mobile tools:"
    for tool in apktool jadx frida objection; do
        check_tool "$tool"
    done
fi

echo ""
log "Setup complete: ${PASS} tools installed, ${FAIL} failed"
[ "$FAIL" -gt 0 ] && warn "Some tools failed to install. Check errors above."

echo ""
log "Add to your shell profile:"
echo '  source /etc/profile.d/codexsec.sh'
echo '  source /etc/profile.d/go.sh'
