#!/bin/bash

# ═══════════════════════════════════════════════════════════════════════════════
# RAVAN-ALEX — ORACLE VPS AUTO-SETUP SCRIPT
# Runs on Ubuntu 22.04 (Oracle Cloud Always-Free ARM A1 — 4 cores, 24GB RAM)
# "One command. Full deployment. ALEX online."
# ═══════════════════════════════════════════════════════════════════════════════

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${RED}"
cat << 'EOF'
██████╗  █████╗ ██╗   ██╗ █████╗ ███╗   ██╗ █████╗     ██╗     ███████╗██╗  ██╗
██╔══██╗██╔══██╗██║   ██║██╔══██╗████╗  ██║██╔══██╗    ██║     ██╔════╝╚██╗██╔╝
██████╔╝███████║██║   ██║███████║██╔██╗ ██║███████║    ██║     █████╗   ╚███╔╝
██╔══██╗██╔══██║╚██╗ ██╔╝██╔══██║██║╚██╗██║██╔══██║    ██║     ██╔══╝   ██╔██╗
██║  ██║██║  ██║ ╚████╔╝ ██║  ██║██║ ╚████║██║  ██║    ███████╗███████╗██╔╝ ██╗
╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝    ╚══════╝╚══════╝╚═╝  ╚═╝
EOF
echo -e "${NC}"
echo -e "${CYAN}  Created by: Charan Vankudoth (Ravan) — Elite Hacker of India${NC}"
echo -e "${YELLOW}  Oracle VPS Auto-Deploy — ALEX coming online...${NC}"
echo ""

# ─── 1. System Update ─────────────────────────────────────────────────────────
echo -e "${GREEN}[1/10] Updating system packages...${NC}"
sudo apt-get update -qq && sudo apt-get upgrade -y -qq

# ─── 2. Core Dependencies ─────────────────────────────────────────────────────
echo -e "${GREEN}[2/10] Installing core dependencies...${NC}"
sudo apt-get install -y -qq \
  git curl wget unzip zip \
  build-essential python3 python3-pip \
  nmap masscan \
  nikto \
  john hashcat \
  aircrack-ng \
  netcat-openbsd \
  tcpdump \
  dnsutils \
  whois \
  jq \
  ffmpeg \
  libssl-dev \
  openjdk-17-jdk \
  ruby ruby-dev \
  golang-go \
  cmake \
  libpcap-dev \
  net-tools \
  iproute2 \
  sqlite3

# ─── 3. Bun Runtime ───────────────────────────────────────────────────────────
echo -e "${GREEN}[3/10] Installing Bun runtime...${NC}"
if ! command -v bun &> /dev/null; then
  curl -fsSL https://bun.sh/install | bash
  export BUN_INSTALL="$HOME/.bun"
  export PATH="$BUN_INSTALL/bin:$PATH"
  echo 'export BUN_INSTALL="$HOME/.bun"' >> ~/.bashrc
  echo 'export PATH="$BUN_INSTALL/bin:$PATH"' >> ~/.bashrc
fi
echo "  Bun $(bun --version) installed ✓"

# ─── 4. Node.js ───────────────────────────────────────────────────────────────
echo -e "${GREEN}[4/10] Installing Node.js 20...${NC}"
if ! command -v node &> /dev/null; then
  curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - -qq
  sudo apt-get install -y -qq nodejs
fi
echo "  Node.js $(node --version) installed ✓"

# ─── 5. Security Tools ────────────────────────────────────────────────────────
echo -e "${GREEN}[5/10] Installing offensive security tools...${NC}"

# Metasploit Framework
if ! command -v msfconsole &> /dev/null; then
  curl -fsSL https://apt.metasploit.com/metasploit-framework.gpg.key | sudo apt-key add - 2>/dev/null
  echo "deb https://apt.metasploit.com/ buster main" | sudo tee /etc/apt/sources.list.d/metasploit-framework.list > /dev/null
  sudo apt-get update -qq
  sudo apt-get install -y -qq metasploit-framework || echo "  Metasploit install optional — skipping"
fi

# Hydra (brute force)
sudo apt-get install -y -qq hydra 2>/dev/null || true

# sqlmap
sudo apt-get install -y -qq sqlmap 2>/dev/null || true

# gobuster
sudo apt-get install -y -qq gobuster 2>/dev/null || true

# subfinder
if ! command -v subfinder &> /dev/null; then
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || true
fi

# httpx
if ! command -v httpx &> /dev/null; then
  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null || true
fi

# nuclei
if ! command -v nuclei &> /dev/null; then
  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || true
fi

# ffuf
if ! command -v ffuf &> /dev/null; then
  go install github.com/ffuf/ffuf/v2@latest 2>/dev/null || true
fi

echo "  Security tools installed ✓"

# ─── 6. Python Tools ──────────────────────────────────────────────────────────
echo -e "${GREEN}[6/10] Installing Python security libraries...${NC}"
pip3 install -q \
  impacket \
  pwntools \
  requests \
  beautifulsoup4 \
  scapy \
  cryptography \
  paramiko \
  dnspython \
  pyOpenSSL 2>/dev/null || true

echo "  Python tools installed ✓"

# ─── 7. Clone RAVAN-ALEX ──────────────────────────────────────────────────────
echo -e "${GREEN}[7/10] Cloning RAVAN-ALEX from GitHub...${NC}"
ALEX_DIR="/opt/ravanalex"
if [ -d "$ALEX_DIR" ]; then
  echo "  Existing installation found — pulling latest..."
  cd "$ALEX_DIR" && git pull origin main
else
  sudo git clone https://github.com/anxcrn/ravanalex.git "$ALEX_DIR"
  sudo chown -R "$USER:$USER" "$ALEX_DIR"
fi
cd "$ALEX_DIR"

# ─── 8. API Key Configuration ─────────────────────────────────────────────────
echo -e "${GREEN}[8/10] Configuring API keys...${NC}"
echo ""
echo -e "${YELLOW}  ALEX needs an LLM API key to operate.${NC}"
echo -e "${CYAN}  Choose your provider:${NC}"
echo "  1) Anthropic Claude (Recommended — most capable)"
echo "  2) OpenAI GPT-4o"
echo "  3) Google Gemini"
echo ""
read -p "  Enter choice (1/2/3): " provider_choice
echo ""

ENV_FILE="$ALEX_DIR/.env"

case $provider_choice in
  1)
    read -p "  Paste your Anthropic API key: " api_key
    echo "ANTHROPIC_API_KEY=$api_key" > "$ENV_FILE"
    echo "  Anthropic configured ✓"
    ;;
  2)
    read -p "  Paste your OpenAI API key: " api_key
    echo "OPENAI_API_KEY=$api_key" > "$ENV_FILE"
    echo "  OpenAI configured ✓"
    ;;
  3)
    read -p "  Paste your Gemini API key: " api_key
    echo "GEMINI_API_KEY=$api_key" > "$ENV_FILE"
    echo "  Gemini configured ✓"
    ;;
  *)
    echo "  Skipping — add API key manually to $ENV_FILE"
    ;;
esac

# ─── 9. Install ALEX Dependencies ─────────────────────────────────────────────
echo -e "${GREEN}[9/10] Installing ALEX dependencies...${NC}"
source ~/.bashrc 2>/dev/null || true
export BUN_INSTALL="$HOME/.bun"
export PATH="$BUN_INSTALL/bin:$PATH"
export GOPATH="$HOME/go"
export PATH="$GOPATH/bin:$PATH"

cd "$ALEX_DIR"
bun install --frozen-lockfile 2>/dev/null || bun install || true

# ─── 10. Systemd Service (24/7 Uptime) ────────────────────────────────────────
echo -e "${GREEN}[10/10] Setting up systemd service for 24/7 operation...${NC}"

sudo tee /etc/systemd/system/ravanalex.service > /dev/null << EOF
[Unit]
Description=RAVAN-ALEX Autonomous Red Team AI Engine
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=$USER
WorkingDirectory=$ALEX_DIR
EnvironmentFile=$ENV_FILE
Environment=PATH=/home/$USER/.bun/bin:/home/$USER/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=/home/$USER/.bun/bin/bun run dev
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable ravanalex
sudo systemctl start ravanalex 2>/dev/null || true

# ─── Firewall ─────────────────────────────────────────────────────────────────
echo -e "${GREEN}  Configuring firewall...${NC}"
sudo iptables -I INPUT -p tcp --dport 3000 -j ACCEPT 2>/dev/null || true
sudo iptables -I INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || true

# ─── Done ─────────────────────────────────────────────────────────────────────
PUBLIC_IP=$(curl -s ifconfig.me 2>/dev/null || echo "YOUR_VPS_IP")

echo ""
echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║${NC}                                                              ${RED}║${NC}"
echo -e "${RED}║${NC}    ${GREEN}✓ RAVAN-ALEX IS ONLINE AND HUNTING${NC}                      ${RED}║${NC}"
echo -e "${RED}║${NC}                                                              ${RED}║${NC}"
echo -e "${RED}║${NC}    ${CYAN}Web UI:${NC}  http://$PUBLIC_IP:3000                        ${RED}║${NC}"
echo -e "${RED}║${NC}    ${CYAN}Logs:${NC}    journalctl -u ravanalex -f                    ${RED}║${NC}"
echo -e "${RED}║${NC}    ${CYAN}Restart:${NC} sudo systemctl restart ravanalex              ${RED}║${NC}"
echo -e "${RED}║${NC}                                                              ${RED}║${NC}"
echo -e "${RED}║${NC}    ${YELLOW}Created by Ravan. Feared by systems.${NC}                   ${RED}║${NC}"
echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
