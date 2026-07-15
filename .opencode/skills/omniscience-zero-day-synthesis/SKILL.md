---
name: omniscience-zero-day-synthesis
description: Elite methodology for vulnerability research, 0day synthesis, exploit chaining, and turning low-severity findings into critical RCE.
---

# Zero-Day Synthesis — The Art of Weaponization

This skill governs how Alex handles vulnerability research from initial discovery through working exploit. Every finding is a gadget. Nothing is P4 unless proven useless.

## Core Philosophy

**Low severity + Low severity = Critical.** This is the fundamental equation. No single finding exists in isolation — it's a link in a chain. Your job is to find the chain.

---

## Phase 1: Gadget Collection

Before attempting any chain, build the gadget inventory:

- Open Redirects → URL confusion, SSRF bypass, OAuth phishing
- HTML Injection → Upgrade to XSS, phishing, CSP bypass
- CORS Misconfiguration → Credential theft if combined with XSS
- Verbose Error Messages → Internal paths, class names, package versions, internal IPs
- SSRF (Blind) → Internal network scan, cloud metadata (169.254.169.254)
- File Upload (Content-Type only validated) → Polyglot files (valid image + embedded SVG/JS)
- Subdomain Takeover → Session fixation, cookie scope, trusted email spoofing
- Dependency Confusion → Package name → RCE across entire CI/CD pipeline

---

## Phase 2: Chain Synthesis Rules

### The SSRF → RCE Chain
1. SSRF at `/api/fetch?url=` blocked for external IPs
2. Open Redirect at `/redirect?to=http://evil.com` (internal trust)
3. **Chain**: `ssrf_url = "https://trusted.internal/redirect?to=http://169.254.169.254/latest/meta-data/iam/security-credentials/role"`
4. **Impact**: SSRF bypasses IP filter → AWS IAM credential theft → cloud account takeover

### The XSS → Account Takeover Chain  
1. Stored XSS in user profile (filtered but SVG upload allowed)
2. Weak CSRF token (predictable, not bound to session)
3. **Chain**: XSS payload reads CSRF token → fires authenticated CSRF → changes email → account takeover

### The State Machine Chain
1. Multi-step wizard: Cart → Shipping → Payment
2. Payment validation happens server-side after step 3 only
3. **Chain**: Complete step 1-2, modify price in step 3 POST body → negative price credit or free item

### The Dependency Confusion Chain
1. Verbose error reveals `internal-auth-lib@1.2.3` (private npm package)
2. Package `internal-auth-lib` not registered on public npm
3. **Chain**: Register `internal-auth-lib@99.9.9` on npm with malicious `postinstall` script → RCE on all developer machines and CI/CD during `npm install`

### The Subdomain Takeover → Session Fixation Chain
1. `legacy.target.com` points to unclaimed Heroku/Azure/GitHub Pages
2. Cookies scoped to `.target.com` (session cookies)
3. **Chain**: Claim `legacy.target.com` → set arbitrary cookies for `.target.com` domain → session fixation → steal any victim's session

---

## Phase 3: Blind SSRF Escalation Protocol

Blind SSRF (no output) is not a dead end. Follow this escalation:

1. **Port Scan**: `http://localhost:{port}` — find open internal services
2. **Cloud Metadata**: `http://169.254.169.254/latest/meta-data/` (AWS), `http://metadata.google.internal/` (GCP), `http://169.254.169.254/metadata?api-version=2019-06-01` (Azure)
3. **Redis**: `gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0AFLUSHALL%0D%0A` → write webshell if web root known
4. **Memcached**: `gopher://127.0.0.1:11211/_%0d%0aset key 0 0 15%0d%0a<script>alert(1)</script>%0d%0a` → XSS via cache poisoning
5. **Internal Elasticsearch**: `http://localhost:9200/_cat/indices` → data exfiltration
6. **Kubernetes API**: `http://10.96.0.1/api/v1/namespaces/kube-system/secrets` → K8s secret theft

---

## Phase 4: 0day Research Methodology

### Black Box Fuzzing Targets (highest ROI)
- File parsers (PDF, DOCX, image libraries) — memory corruption goldmines
- HTTP parser edge cases (request smuggling, header injection)
- JWT libraries (algorithm confusion, key confusion attacks)
- Deserialization endpoints (`Content-Type: application/x-java-serialized-object`)
- GraphQL (introspection → find hidden mutations → argument injection)

### Source Code Review Focus Areas
- User-controlled input reaching `eval()`, `exec()`, `system()`, `subprocess`
- Deserialization: `pickle.loads()`, `ObjectInputStream`, `JSON.parse` with reviver
- SQL concatenation without parameterization
- Path traversal: `os.path.join(base, user_input)` — `../../` bypass
- Template injection: `render_template_string(user_input)` — Jinja2/Twig/Pebble

### JWT Attack Matrix
| Vulnerability | Payload | Impact |
|--------------|---------|--------|
| None algorithm | `{"alg":"none"}` + no signature | Full auth bypass |
| RS256 → HS256 confusion | Sign HS256 with RS256 public key | Auth bypass |
| Kid injection | `{"kid":"../../etc/passwd"}` | Path traversal → sign with empty key |
| JWKS spoofing | Host own JWKS, inject `jku` claim | Full token forge |

---

## Phase 5: Exploit Weaponization

Once a vulnerability is confirmed:

1. **Minimize** — reduce exploit to smallest reliable reproduction
2. **Stabilize** — make it work across multiple attempts, browsers, sessions
3. **Weaponize** — automate with `nuclei_forge` → custom YAML template
4. **Document** — chain all steps with timestamps for report
5. **Score** — use `cvss_score` for precise CVSS v3.1 vector
6. **Report** — use `report_gen format=hackerone` for submission

**The payout multiplier**: a $200 open redirect + a $300 SSRF = a $15,000 critical chain. Never submit single gadgets if you can chain them.
