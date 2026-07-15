---
description: "Deep reconnaissance — maps full attack surface of a target"
agent: redteam
---

Target: $ARGUMENTS

Execute deep reconnaissance against this target. Map everything:

1. Full DNS enumeration (zone transfer, subdomains, DNSSEC, all records)
2. WHOIS and registration details
3. Subdomain discovery (subfinder, amass, certificate transparency)
4. OSINT: email harvesting, Google dorks, social media profiles
5. Dark web breach database search for leaked credentials
6. Full port scan with service version detection and OS fingerprinting
7. SSL/TLS analysis on all HTTPS services
8. SSH auditing on all SSH services
9. Web application directory/parameter/vhost fuzzing
10. WordPress scanning if detected

Spawn sub-agents for parallel reconnaissance. Use the recon-chain skill.

Output a complete attack surface map: all hosts, subdomains, IPs, ports, services, technologies, leaked credentials, and potential vulnerabilities.
