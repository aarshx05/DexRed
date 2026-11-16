# CodexSec Security Harness — Multi-stage Docker Image
# Toolchain: 24 curated security tools + Rust build environment
#
# Build: docker build -t codexsec:latest .
# Run:   docker run --rm -it codexsec:latest

# ============================================================
# Stage 1: Go builder — compile all Go-based tools
# ============================================================
FROM golang:1.23-bookworm AS go-builder

ENV GOBIN=/go/bin
ENV CGO_ENABLED=0

RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/ffuf/ffuf/v2@latest && \
    go install github.com/assetnote/kiterunner/cmd/kr@latest && \
    go install github.com/trufflesecurity/trufflehog/v3@latest && \
    go install github.com/gitleaks/gitleaks/v8@latest && \
    go install github.com/securego/gosec/v2/cmd/gosec@latest && \
    go install github.com/OJ/gobuster/v3@latest && \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# ============================================================
# Stage 2: Rust builder — compile Rust-based tools + CodexSec
# ============================================================
FROM rust:1.82-bookworm AS rust-builder

RUN cargo install feroxbuster && \
    cargo install dalfox

# ============================================================
# Stage 3: Python builder — install Python tools in venv
# ============================================================
FROM python:3.12-slim-bookworm AS python-builder

RUN python -m venv /opt/sectools && \
    /opt/sectools/bin/pip install --no-cache-dir \
        sqlmap \
        ssrfmap \
        jwt-tool \
        semgrep \
        bandit \
        objection \
        frida-tools \
        requests \
        beautifulsoup4 \
        pyjwt[crypto] \
        httpx[http2] \
        pycryptodome \
        websockets \
        graphql-core

# ============================================================
# Stage 4: Final runtime image
# ============================================================
FROM debian:bookworm-slim

LABEL maintainer="CodexSec Security Harness"
LABEL description="Curated security toolchain for AI-powered pentesting"

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    wget \
    git \
    jq \
    nmap \
    masscan \
    chromium \
    chromium-driver \
    # Python runtime (needed for sqlmap, ssrfmap, jwt_tool, etc.)
    python3 \
    python3-venv \
    # Java runtime (needed for apktool, jadx)
    default-jre-headless \
    # Build essentials for any on-the-fly compilation
    build-essential \
    libssl-dev \
    pkg-config \
    # DNS utilities
    dnsutils \
    # Network utilities
    netcat-openbsd \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Copy Go tools
COPY --from=go-builder /go/bin/ /usr/local/bin/

# Copy Rust tools
COPY --from=rust-builder /usr/local/cargo/bin/feroxbuster /usr/local/bin/
COPY --from=rust-builder /usr/local/cargo/bin/dalfox /usr/local/bin/

# Copy Python venv
COPY --from=python-builder /opt/sectools /opt/sectools
ENV PATH="/opt/sectools/bin:${PATH}"

# Install Go runtime (for agent to build tools on-the-fly if needed)
COPY --from=go-builder /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/root/go"
ENV PATH="${GOPATH}/bin:${PATH}"

# Install Rust toolchain (for building CodexSec itself)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}"

# Install apktool
RUN APKTOOL_VERSION=$(curl -s https://api.github.com/repos/iBotPeaches/Apktool/releases/latest | jq -r .tag_name | sed 's/v//') && \
    curl -Lo /usr/local/bin/apktool.jar "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar" && \
    printf '#!/bin/sh\njava -jar /usr/local/bin/apktool.jar "$@"\n' > /usr/local/bin/apktool && \
    chmod +x /usr/local/bin/apktool

# Install jadx
RUN JADX_VERSION=$(curl -s https://api.github.com/repos/skylot/jadx/releases/latest | jq -r .tag_name | sed 's/v//') && \
    curl -Lo /tmp/jadx.zip "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" && \
    mkdir -p /opt/jadx && \
    unzip -q /tmp/jadx.zip -d /opt/jadx && \
    ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx && \
    ln -s /opt/jadx/bin/jadx-gui /usr/local/bin/jadx-gui && \
    rm /tmp/jadx.zip

# Update nuclei templates
RUN nuclei -update-templates 2>/dev/null || true

# Create workspace
RUN mkdir -p /workspace /findings /state
WORKDIR /workspace

# Default wordlists
RUN mkdir -p /wordlists && \
    curl -Lo /wordlists/common.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt && \
    curl -Lo /wordlists/raft-medium-dirs.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt && \
    curl -Lo /wordlists/raft-medium-files.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-files.txt && \
    curl -Lo /wordlists/api-endpoints.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt && \
    curl -Lo /wordlists/params.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt && \
    curl -Lo /wordlists/subdomains.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt

# Verify installations
RUN echo "=== Verifying toolchain ===" && \
    httpx -version && \
    subfinder -version && \
    nuclei -version && \
    ffuf -V && \
    nmap --version | head -1 && \
    sqlmap --version && \
    semgrep --version && \
    echo "=== All tools verified ==="

ENTRYPOINT ["/bin/bash"]
