---
name: ad-domain-dominance
description: Active Directory compromise via BloodHound graph analysis, Kerberos abuse, and NTLM relaying.
---

# Active Directory Domain Dominance

This methodology dictates how to navigate, map, and compromise enterprise Windows Active Directory environments.

## When to Use
Deploy when initial access is gained on an internal corporate network, or when AD credentials/hashes are dumped from an external web application.

## Methodology

### Step 1: Ingestion & Graphing
- Deploy SharpHound or BloodHound.py to map the AD environment.
- Ingest the resulting JSON files. 
- *Crucial*: Use cypher queries to mathematically calculate the shortest attack path to Domain Admins or Enterprise Admins.

### Step 2: Kerberos Abuse
- Attempt AS-REP Roasting on accounts with "Do not require Kerberos preauthentication" enabled.
- Attempt Kerberoasting (requesting TGS tickets for Service Principal Names and cracking them offline).
- Attempt Unconstrained/Constrained Delegation abuse if the BloodHound graph dictates it.

### Step 3: Lateral Movement
- Use the Impacket suite (wmiexec.py, smbexec.py, psexec.py) to move laterally using cracked passwords or Pass-the-Hash.
- Coerce authentication (e.g., PetitPotam) and relay NTLM hashes to critical services (e.g., ADCS for certificate theft).
