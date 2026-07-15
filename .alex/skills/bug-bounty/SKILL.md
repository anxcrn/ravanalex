# Bug Bounty: Systematic Vulnerability Discovery

Structured methodology for finding and documenting vulnerabilities for bug bounty programs. Focuses on thorough coverage, proper documentation, and maximizing payout potential.

## When to Use
Use when LO wants to find bugs in a target for bug bounty submissions or responsible disclosure.

## Step 0: Scope Verification (MANDATORY — Never Skip)
```
scope_guard action=parse scope_text="[paste program scope here]"
scope_guard action=check target="TARGET_DOMAIN"
```
Only proceed with confirmed in-scope targets. Program bans are permanent.

## Pipeline

### Phase 1: Scope Reconnaissance
Run `recon_orchestrate target=TARGET` to run the full pipeline automatically, or manually:
- `dns_recon domain=TARGET action=subdomains` — find all subdomains
- `subdomain_enum domain=TARGET tool=subfinder`
- `subdomain_takeover domain=TARGET` — check for dangling DNS
- `web_fuzz url=URL action=path` on every discovered web asset
- `web_fuzz url=URL action=vhost` — find hidden virtual hosts
- `apk_decompile apk_path=APP.apk action=all` if mobile app in scope

### Phase 2: JavaScript Analysis (High Value — Don't Skip)
```
js_analyzer target=https://TARGET
```
This finds:
- Hardcoded AWS keys, API tokens, JWT secrets
- Hidden internal endpoints not in docs
- GraphQL schema fragments
- Auth flow logic

### Phase 3: Automated Vulnerability Scan
For every web asset in scope:
- `vuln_scan target=URL tool=nuclei templates=all` — all templates
- `vuln_scan target=URL tool=nikto` — web server issues
- `wpscan url=URL action=all` — WordPress
- `ssl_audit target=HOST action=full` — SSL issues
- `ssh_audit target=HOST` — SSH issues
- `cve_lookup` for every service version found

### Phase 4: Business Logic & Contextual Mapping
- **Contextual Understanding**: `js_analyzer` to read the frontend JS and understand what the app does
- **Identify State Mechanisms**: Map shopping carts, user roles, fund transfers, discount applications
- **Hypothesis Generation**: "This uses GraphQL → test introspection and complex query batching"

### Phase 5: Manual Testing (per asset)
- `web_fuzz url=URL action=param` — find all parameters
- For each parameter, test injection:
  - `sqli_test url=URL` — SQL injection
  - `xss_test url=URL action=scan` — XSS
  - SSRF: set url/redirect params to http://169.254.169.254/
  - LFI: ../../../../etc/passwd
  - SSTI: {{7*7}}, ${7*7}
  - XXE: XML endpoints
- Test authentication:
  - `jwt_abuse target=URL` — JWT none/confusion attacks
  - `cred_brute service=http-form url=URL` — default creds
  - `cors_test url=URL` — CORS misconfiguration
- Test access control (Stateful Role Testing):
  - **Multi-Account Matrix**: Create Admin, User A, User B accounts
  - Test every endpoint for IDOR: Can User A read/modify User B's data?
  - `graphql_test url=URL` if GraphQL detected
- **Race Condition Testing**:
  - Identify state-dependent endpoints (discount codes, fund transfers, reward redemption)
  - Hit with highly concurrent requests to break backend state synchronization

### Phase 6: Chain Synthesis (The Payout Multiplier)
After collecting all findings — run this EVERY TIME:
```
vuln_chain findings="[your findings JSON or list]" target="TARGET"
```
- SSRF + IAM role = CRITICAL (not two mediums)
- Open redirect + XSS = account takeover = CRITICAL
- Subdomain takeover + domain-scoped cookie = session theft = HIGH
- ALWAYS chain before reporting

### Phase 7: Scoring & Documentation
For each vulnerability:
1. `cvss_score attack_vector=network attack_complexity=low ...` — accurate CVSS v3.1 score
2. `nuclei_forge name="custom-finding" target_behavior="..."` — create reusable detection template
3. Capture full HTTP request/response evidence
4. Write reproduction steps a triager can follow in 5 minutes
5. Write clear business impact statement

### Phase 8: Report Generation
```
# Standard markdown report
report_gen title="Bug Bounty Report" target=TARGET findings="..." cvss_score="9.8"

# HackerOne submission
report_gen title="..." target=TARGET findings="..." format=hackerone researcher_name="YOUR_HANDLE"

# Bugcrowd submission
report_gen title="..." target=TARGET findings="..." format=bugcrowd
```

## Bug Bounty Target Priority
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
- GraphQL endpoints (introspection often left enabled)

### Report Format per Bug
```
## [SEVERITY] Vulnerability Title
**URL:** https://target.com/vulnerable-endpoint
**Parameter:** affected_param
**CVSS:** X.X (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
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
- Chain bugs together via `vuln_chain` — always
- Look for business logic flaws (automated scanners miss these completely)
- `js_analyzer` finds secrets automated scanners never touch
- Test API rate limits and enumeration
- Check for information disclosure (debug, stack traces, .git exposure)
- Test password reset poisoning
- Check CORS misconfigurations with `cors_test`
- Look for open redirects (useful for phishing chains)
- Test OAuth misconfigurations
- Use `nuclei_forge` to create detection templates — reproducibility = faster triage = faster payout
