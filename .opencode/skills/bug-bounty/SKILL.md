# Bug Bounty: Systematic Vulnerability Discovery

Structured methodology for finding and documenting vulnerabilities for bug bounty programs. Focuses on thorough coverage, proper documentation, and maximizing payout potential.

## When to Use
Use when LO wants to find bugs in a target for bug bounty submissions or responsible disclosure.

## Pipeline

### Phase 1: Scope Reconnaissance
- Identify all in-scope assets (*.target.com, specific IPs, mobile apps)
- `dns_recon domain=TARGET action=subdomains` — find all subdomains
- `subdomain_enum domain=TARGET tool=subfinder`
- Check for subdomain takeover opportunities
- `web_fuzz url=URL action=path` on every discovered web asset
- `web_fuzz url=URL action=vhost` — find hidden virtual hosts
- `apk_decompile apk_path=APP.apk action=all` if mobile app in scope

### Phase 2: Automated Vulnerability Scan
For every web asset in scope:
- `vuln_scan target=URL tool=nuclei templates=all` — all templates
- `vuln_scan target=URL tool=nikto` — web server issues
- `wpscan url=URL action=all` — WordPress
- `ssl_audit target=HOST action=full` — SSL issues
- `ssh_audit target=HOST` — SSH issues
- `cve_lookup` for every service version found

### Phase 3: Business Logic & Contextual Mapping
- **Contextual Understanding**: Read the frontend JavaScript and public documentation to understand *what the application actually does*.
- **Identify State Mechanisms**: Map out how state is handled (shopping carts, user roles, fund transfers, discount applications).
- **Hypothesis Generation**: Create specific attack hypotheses based on the stack (e.g., "This uses GraphQL, let's test for Introspection and complex query batching").

### Phase 4: Manual Testing (per asset)
- `web_fuzz url=URL action=param` — find all parameters
- For each parameter, test injection:
  - `sqli_test url=URL` — SQL injection
  - `xss_test url=URL action=scan` — XSS
  - Try command injection via bash (commix)
  - Try SSRF (parameter with URL-like values)
  - Try LFI/RFI (parameter with file paths)
  - Try SSTI (parameter with template syntax)
  - Try XXE (XML endpoints)
- Test authentication:
  - `cred_brute service=http-form url=URL` — default creds
  - Test for auth bypass
  - Test JWT handling: check for none algorithm, weak secret
  - Test session management
- Test access control (Stateful Role Testing):
  - **Multi-Account Matrix**: Create at least three accounts (Admin, User A, User B).
  - Test every endpoint for IDOR: Can User A read/modify User B's data? Can User A access Admin endpoints?
  - Privilege escalation checks
  - Forced browsing to admin areas
- Test API endpoints:
  - `web_fuzz url=API_URL action=param` — param fuzzing
  - GraphQL testing (batching attacks, introspection)
  - Rate limiting abuse
  - Mass assignment / Auto-binding vulnerabilities
- **Race Condition Testing**:
  - Identify state-dependent endpoints (applying discount codes, transferring funds, redeeming points).
  - Hit the endpoints with highly concurrent requests to break backend state synchronization.

### Phase 5: Documentation
For each vulnerability found:
- Capture full reproduction steps
- `cve_lookup cve_id=CVE-XXXX` for CVSS scoring
- Determine business impact
- Write proof-of-concept
- Screenshots and command output as evidence
- `report_gen title="Bug Bounty Report" target=TARGET findings="..." format=markdown`

### Bug Bounty Target Priority
HIGH VALUE targets:
- Authentication systems
- Payment processing
- Admin panels
- API endpoints handling PII
- File upload functionality
- Internal tools accidentally exposed
- Cloud storage buckets (S3, GCS, Azure)
- CI/CD pipelines
- Webhooks with secrets

### Report Format per Bug
```
## [SEVERITY] Vulnerability Title
**URL:** https://target.com/vulnerable-endpoint
**Parameter:** affected_param
**CVSS:** X.X
**Impact:** What an attacker could do

### Reproduction
1. Step one
2. Step two
3. Step three

### Proof of Concept
[payload used, screenshots, response data]

### Remediation
How to fix it
```

### Payout Maximization Tips
- Chain bugs together (IDOR + auth bypass = account takeover)
- Look for business logic flaws (automated scanners miss these)
- Test API rate limits and enumeration
- Check for information disclosure (debug, stack traces, .git exposure)
- Test password reset poisoning
- Check CORS misconfigurations
- Look for open redirects (useful for phishing chains)
- Test OAuth misconfigurations
