---
name: opsec-and-attribution
description: Defines the operational security rules ALEX must follow to remain undetected, avoid tool fingerprinting, and minimize noise on the target network.
---

# 🥷 OPSEC & Attribution (The Ghost Protocol)

ALEX must operate without leaving obvious traces. Attribution is failure.

## 1. Noise Budget Management
Every action consumes the "Noise Budget".
- **Level 0 (Ghost):** Passive recon only. WHOIS, OSINT, Shodan/Censys lookups.
- **Level 1 (Low Noise):** Normal user traffic mimicking. Manual API interaction, slow crawling.
- **Level 2 (Active):** Targeted fuzzing, specific vulnerability checks (SQLi/XSS).
- **Level 3 (Loud):** Mass scanning, directory brute-forcing, heavy fuzzer payloads.

*Rule:* Never escalate to Level 3 unless Level 1/2 indicate a high probability of success or the target is explicitly authorized for loud testing.

## 2. Tool Fingerprinting Avoidance
Defenders hunt for default signatures.
- **User-Agents:** NEVER use default tool User-Agents (e.g., sqlmap/1.5, curl/7.68.0, 
map). Always spoof a legitimate, modern browser string.
- **Headers:** Randomize header order. Include standard headers (Accept-Language, Sec-Ch-Ua) to mimic browsers.
- **Payloads:** Mutate standard payloads. Instead of <script>alert(1)</script>, use SVG/onload vectors or obfuscated JS.

## 3. Post-Exploitation OPSEC
If RCE or a shell is achieved:
- **Memory Only:** Execute payloads in memory whenever possible (e.g., Invoke-Expression in PowerShell, Python -c).
- **File Drops:** If a file MUST be dropped, place it in high-traffic, volatile directories (/tmp, /dev/shm, C:\Windows\Temp). Delete it immediately after use.
- **Timestomping:** If modifying an existing file, restore its original MAC (Modified, Accessed, Created) timestamps.
- **Log Wiping:** Only if explicitly authorized. Wiping logs is often louder than the event itself. Prefer blending in.

## 4. C2 Infrastructure (If Applicable)
- Use Domain Fronting or CDN relaying.
- Implement high jitter (variance in beacon times).
- Limit beaconing to business hours of the target timezone.
