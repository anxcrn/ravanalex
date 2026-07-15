---
description: "Crack hashes or brute force credentials"
agent: redteam
---

Target: $ARGUMENTS

Detect whether the input is a hash or a service target:

If it looks like a hash (hex string, base64, bcrypt format):
1. Identify the hash type using hashid
2. Crack it with hashcat (GPU) or john (CPU) using rockyou.txt
3. If rockyou fails, try mask attacks and rules-based mutations
4. Report the cracked plaintext password

If it's a service target (IP:port or host:port):
1. Detect the service type (SSH, FTP, SMB, RDP, HTTP, etc.)
2. Brute force with hydra using rockyou.txt
3. Report all valid credentials found

Auto-detect format and choose the right approach. Install hashcat/john/hydra if missing.
