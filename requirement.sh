#!/usr/bin/env bash

# ════════════════════════════════════════════════════════════════
# Elite Recon — Dependency Installer
# Auto installs all required recon tools
# Compatible: Ubuntu / Debian / Kali
# ════════════════════════════════════════════════════════════════

set -e

# ───────────────────────────────────────────────────────────────
# Colors
# ───────────────────────────────────────────────────────────────

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[+]${NC} $1"
}

info() {
    echo -e "${CYAN}[*]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

error() {
    echo -e "${RED}[-]${NC} $1"
}

# ───────────────────────────────────────────────────────────────
# Banner
# ───────────────────────────────────────────────────────────────

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║        Elite Recon Installer v1.0           ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# ───────────────────────────────────────────────────────────────
# Fix Broken MongoDB Repo Automatically
# ───────────────────────────────────────────────────────────────

info "Checking for broken MongoDB repositories..."

if ls /etc/apt/sources.list.d/mongodb*.list >/dev/null 2>&1; then
    warn "Broken MongoDB repo detected."

    mkdir -p /root/repo-backup 2>/dev/null || true

    mv /etc/apt/sources.list.d/mongodb*.list \
       /root/repo-backup/ 2>/dev/null || true

    log "MongoDB repo disabled temporarily."
fi

# ───────────────────────────────────────────────────────────────
# Update Packages
# ───────────────────────────────────────────────────────────────

info "Updating packages..."

apt update -y || true

# ───────────────────────────────────────────────────────────────
# Install Base Dependencies
# ───────────────────────────────────────────────────────────────

info "Installing base packages..."

apt install -y \
    git \
    curl \
    wget \
    unzip \
    jq \
    python3 \
    python3-pip \
    python3-venv \
    build-essential \
    libpcap-dev \
    snapd \
    software-properties-common

# ───────────────────────────────────────────────────────────────
# Install Golang
# ───────────────────────────────────────────────────────────────

if ! command -v go >/dev/null 2>&1; then

    info "Installing Golang..."

    GO_VERSION="1.22.5"

    cd /tmp

    wget -q https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz

    rm -rf /usr/local/go

    tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz

    rm go${GO_VERSION}.linux-amd64.tar.gz

    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

    # Add PATH only once
    grep -q "/usr/local/go/bin" ~/.bashrc || \
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc

    log "Golang installed."

else
    log "Golang already installed."
fi

# Current session PATH
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

# ───────────────────────────────────────────────────────────────
# Install Go Recon Tools
# ───────────────────────────────────────────────────────────────

info "Installing recon tools..."

TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/hakluke/hakrawler@latest"
    "github.com/jaeles-project/gospider@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/projectdiscovery/alterx/cmd/alterx@latest"
    "github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest"
    "github.com/incogbyte/shosubgo@latest"
)

for tool in "${TOOLS[@]}"; do
    info "Installing: $tool"

    go install -v "$tool" || warn "Failed installing $tool"
done

# ───────────────────────────────────────────────────────────────
# Install Amass
# ───────────────────────────────────────────────────────────────

if ! command -v amass >/dev/null 2>&1; then

    info "Installing Amass..."

    snap install amass || warn "Amass install failed"
fi

# ───────────────────────────────────────────────────────────────
# Install ParamSpider
# ───────────────────────────────────────────────────────────────

if [ ! -d "$HOME/tools/ParamSpider" ]; then

    info "Installing ParamSpider..."

    mkdir -p "$HOME/tools"

    git clone https://github.com/devanshbatham/ParamSpider.git \
        "$HOME/tools/ParamSpider" || true

    pip3 install -r "$HOME/tools/ParamSpider/requirements.txt" || true

    chmod +x "$HOME/tools/ParamSpider/paramspider.py"

    ln -sf "$HOME/tools/ParamSpider/paramspider.py" \
        /usr/local/bin/paramspider

    log "ParamSpider installed."
fi

# ───────────────────────────────────────────────────────────────
# Install GitHub Recon Tools
# ───────────────────────────────────────────────────────────────

info "Installing GitHub recon tools..."

go install github.com/gwen001/github-subdomains@latest || true
go install github.com/gwen001/github-endpoints@latest || true

# ───────────────────────────────────────────────────────────────
# Verify Installation
# ───────────────────────────────────────────────────────────────

echo ""
info "Verifying installed tools..."
echo ""

REQUIRED=(
    subfinder
    assetfinder
    amass
    httpx
    dnsx
    gau
    katana
    hakrawler
    gospider
    waybackurls
    alterx
    urlfinder
    shosubgo
    paramspider
)

for tool in "${REQUIRED[@]}"; do

    if command -v "$tool" >/dev/null 2>&1; then
        echo -e "${GREEN}[INSTALLED]${NC} $tool"
    else
        echo -e "${RED}[MISSING]${NC} $tool"
    fi
done

# ───────────────────────────────────────────────────────────────
# Final Message
# ───────────────────────────────────────────────────────────────

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║           Installation Complete             ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

echo "Run this command before using Elite Recon:"
echo ""

echo "source ~/.bashrc"
echo ""

echo "Usage:"
echo "./elite_recon.sh target.com"
echo ""

log "Elite Recon environment ready."
echo ""