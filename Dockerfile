# ═══════════════════════════════════════════════════════════════════════════════
# RAVAN-ALEX — HUGGINGFACE SPACES DOCKERFILE
# "Zero credit card. 100% free. 16GB RAM."
# ═══════════════════════════════════════════════════════════════════════════════

FROM ubuntu:22.04

# Avoid prompts during apt installs
ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/root/.bun/bin:/root/go/bin:/usr/local/go/bin:${PATH}"

# Install core dependencies and hacking tools
RUN apt-get update -qq && apt-get install -y -qq \
    curl wget git unzip zip build-essential python3 python3-pip \
    nmap masscan nikto john hashcat aircrack-ng netcat-openbsd \
    tcpdump dnsutils whois jq ffmpeg libssl-dev openjdk-17-jdk \
    ruby ruby-dev golang-go cmake libpcap-dev net-tools iproute2 sqlite3 \
    hydra sqlmap gobuster \
    && rm -rf /var/lib/apt/lists/*

# Install ProjectDiscovery tools (Nuclei, Subfinder, Httpx)
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/ffuf/ffuf/v2@latest

# Install Python offensive libraries
RUN pip3 install -q impacket pwntools requests beautifulsoup4 scapy cryptography paramiko dnspython pyOpenSSL

# Install Bun
RUN curl -fsSL https://bun.sh/install | bash

# Create working directory
WORKDIR /app

# Copy package files and install dependencies
COPY package.json bun.lock ./
COPY packages/core/package.json ./packages/core/
COPY packages/alex/package.json ./packages/alex/
COPY packages/tui/package.json ./packages/tui/
COPY packages/server/package.json ./packages/server/
COPY packages/llm/package.json ./packages/llm/

RUN bun install --frozen-lockfile

# Copy the rest of the codebase
COPY . .

# HuggingFace requires binding to port 7860
ENV PORT=7860
EXPOSE 7860

# Ensure the .alex directory exists and has correct permissions
RUN mkdir -p /app/.alex && chmod -R 777 /app/.alex

# Start ALEX
CMD ["bun", "run", "dev"]
