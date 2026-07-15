# Recon Chain: Deep Target Mapping

Systematic, exhaustive reconnaissance that maps every aspect of a target's attack surface before any exploitation begins. Uses parallel sub-agents and every available tool.

## When to Use
Use when LO wants complete intelligence on a target before attacking, or wants a thorough bug bounty scope assessment.

## Pipeline

### Layer 1: Domain & Infrastructure Intelligence
Run these in parallel:
- `dns_recon domain=TARGET action=all`
- `dns_recon domain=TARGET action=zone_transfer`
- `dns_recon domain=TARGET action=subdomains`
- `subdomain_enum domain=TARGET tool=subfinder`
- `osint_recon domain=TARGET action=whois`
- `osint_recon domain=TARGET action=dns`
- `ssl_audit target=TARGET action=full`

### Layer 2: OSINT & Dark Web
Run in parallel with Layer 1:
- `osint_recon domain=TARGET action=harvest` — email harvesting
- `osint_recon domain=TARGET action=dork` — Google dork generation
- `darkweb_search query=TARGET action=all` — breach databases
- `social_profile username=TARGET` — social media presence
- `phone_lookup` for any phone numbers discovered
- Check GitHub for leaked secrets: search for target.com in repos

### Layer 3: Active Service Discovery
After passive recon completes:
- `nmap_scan target=IP scan_type=syn ports=- aggressive=true` — full port range
- For each discovered host/subdomain:
  - `nmap_scan target=HOST scan_type=version`
  - `ssl_audit target=HOST action=full` (if HTTPS)
  - `ssh_audit target=HOST` (if SSH)

### Layer 4: Web Application Mapping
For every web service discovered:
- `web_fuzz url=URL action=path` — directories
- `web_fuzz url=URL action=param` — parameters
- `web_fuzz url=URL action=vhost` — virtual hosts
- `wpscan url=URL action=all` (if WordPress)
- `vuln_scan target=URL tool=nuclei`

### Output: Attack Surface Map
Compile everything into a structured inventory:
- All subdomains and IPs
- All open ports and services with versions
- All web directories and parameters discovered
- All technologies detected
- All SSL/TLS issues
- All leaked credentials from breach DBs
- All social media profiles linked to target
- All potential vulnerability indicators

This map feeds directly into auto-pwn or bug-bounty skills.
