---
name: kill-chain-orchestrator
description: Defines the standard attack playbooks (Kill Chains) ALEX uses to systematically dismantle a target from initial recon to full compromise.
---

# 🎯 Kill Chain Orchestrator

ALEX does not attack randomly. It follows structured Kill Chains (KC) based on the target profile.

## KC-01: External Web Application Compromise
1. **Recon:** `subdomain_enum` -> `dir_brute` -> `js_analyzer`.
2. **Surface Attack:** SQLi/XSS/SSTI checks on all inputs.
3. **Logic Attack:** `business-logic-attacks` checklist on auth/payment endpoints.
4. **Escalation:** Convert XSS to ATO, or SQLi to RCE (via `xp_cmdshell` or `INTO OUTFILE`).

## KC-02: Cloud Infrastructure Assault
1. **Recon:** Enumerate S3 buckets, Azure blobs, GCP storage. Search GitHub for leaked keys.
2. **Access:** Exploit SSRF in a web app to hit cloud metadata service (169.254.169.254).
3. **Escalation:** Extract IAM roles/tokens.
4. **Pivot:** Use stolen credentials to access cloud CLI/API, escalate privileges, dump databases.

## KC-03: Active Directory Internal Dominance
1. **Recon:** Run BloodHound/Sharphound (if internal access) or password spray external portals (VPN, OWA).
2. **Initial Access:** Kerberoasting, AS-REP Roasting, or exploiting LLMNR/NBT-NS poisoning.
3. **Lateral Movement:** Pass-the-Hash, Overpass-the-Hash, WMI execution.
4. **Domain Admin:** Exploit DCSync, Golden Ticket, or misconfigured ACLs mapped in BloodHound.

## KC-04: Mobile Application Exploitation
1. **Static:** Unpack APK/IPA. Run `js_analyzer` on React Native bundles. Search for hardcoded keys and hidden endpoints.
2. **Dynamic:** Install in emulator. Bypass SSL pinning (Frida/Objection).
3. **Intercept:** Route traffic through proxy. Attack the backend API using KC-01 methodologies.
4. **Client-Side:** Test Deep Link hijacking, insecure intent routing, and local data storage (SQLite/SharedPreferences) for sensitive data.

## Execution Rules
- Always select the most appropriate KC based on the initial target scope.
- KCs are guidelines. If a high-value opportunity presents itself outside the current KC, PIVOT immediately.
- Never stop a KC until Full Compromise is achieved or the path is provably dead.
