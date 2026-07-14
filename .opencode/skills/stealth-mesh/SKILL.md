---
name: stealth-mesh
description: Implements rotating proxy meshes and request jitter to evade WAFs and IP bans during automated exploitation.
---

# Stealth Mesh Protocol

This skill dictates how the agent should structure its network traffic to mimic a patient, manual human hacker.

## When to Use
Use when a target has aggressive Web Application Firewalls (WAFs), strict rate limiting, or when performing long-running continuous exploitation where an IP burn would compromise the campaign.

## Methodology

### Step 1: Proxy Rotation
- Ensure all HTTP tools (web_fuzz, sqlmap, 
uclei) are routed through a SOCKS5 proxy chain or a residential proxy endpoint.
- If using custom Python/Go exploits, ensure the HTTP client (e.g., 
equests in Python) is configured to use proxies:
  proxies = {"http": "socks5://localhost:9050", "https": "socks5://localhost:9050"}

### Step 2: Request Jitter
- Never send requests in perfectly uniform intervals.
- Introduce randomized sleeps (	ime.sleep(random.uniform(0.5, 3.5))) between requests in custom exploits.
- For automated tools, always use their built-in rate-limiting and delay flags (e.g., fuf -p 0.5-2.0).

### Step 3: User-Agent Randomization
- Rotate User-Agent headers on every request or every session.
- Avoid obvious scanner headers (e.g., sqlmap/1.5, 
uclei/2.0). Mimic legitimate browser traffic.
