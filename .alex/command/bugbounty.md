---
description: "Bug bounty mode — systematic vulnerability discovery for bug bounty"
agent: redteam
---

Target: $ARGUMENTS

Execute systematic bug bounty reconnaissance against this target. Find every vulnerability and document it properly for submission.

1. Map all in-scope assets (subdomains, IPs, APIs, mobile apps)
2. Run nuclei with all templates on every web asset
3. Run nikto on every web asset
4. Fuzz all parameters with ffuf
5. Test SQLi on every input (sqlmap)
6. Test XSS on every reflected parameter (dalfox)
7. Test for IDOR, auth bypass, SSRF, LFI/RFI, SSTI, XXE
8. Check for subdomain takeover
9. Check for exposed cloud storage (S3, GCS, Azure blobs)
10. Check for exposed secrets (GitHub, pastes, JS files)
11. Test JWT handling weaknesses
12. Check CORS misconfigurations
13. Test GraphQL endpoints
14. APK analysis if mobile app in scope

Document every finding with reproduction steps, CVSS score, and remediation. Use the bug-bounty skill. Generate a structured report at the end.
