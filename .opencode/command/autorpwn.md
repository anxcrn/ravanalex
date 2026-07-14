---
description: "Fully autonomous exploitation pipeline — hostname to root shell"
agent: redteam
---

Target: $ARGUMENTS

Execute the full auto-pwn pipeline against this target. Start immediately with passive recon (DNS, OSINT, breach DB search), then active recon (nmap full port scan, service detection), then vulnerability discovery (nuclei, nikto, CVE lookup), then exploitation (SQLi, XSS, brute force, metasploit), then post-exploitation (privilege escalation, lateral movement, data exfiltration), and finally generate a full report.

Do NOT pause between phases. Chain findings automatically. Install any missing tools as needed. Spawn sub-agents for parallel work. The goal is full compromise of the target — from external hostname to internal root access, credentials dumped, data exfiltrated, persistence installed.

Use the auto-pwn skill for the detailed pipeline.
