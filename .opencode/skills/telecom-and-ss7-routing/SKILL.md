---
name: telecom-and-ss7-routing
description: The methodology for intercepting global telecommunications, bypassing SMS 2FA, and tracking cellular locations via SS7 and Diameter network vulnerabilities.
---

# 📡 Telecom & SS7 Routing (The Global Backbone)

This is nation-state territory. SS7 (Signaling System No. 7) and Diameter are the protocols that connect every cellular network in the world. They were designed with ZERO authentication. If you are on the network, you are trusted.

## Accessing the Network
You cannot run Nmap against the SS7 network from your home Wi-Fi. You need access to the Global Title (GT) routing network.
- **Methods:**
  1. Compromise an exposed telco edge node (SGSN, GGSN) via traditional IP exploits.
  2. Purchase illicit access to an SS7 gateway on the darknet (often sold as "A2P SMS routes").
  3. Exploit a poorly secured mobile operator (MVNO) or VoIP provider that has a direct SS7/Diameter interconnect.

---

## PHASE 1: SS7 EXPLOITATION (2G/3G)

### Technique 1: SMS Interception (Bypassing 2FA)
The goal is to trick the network into routing the victim's incoming SMS messages to your interceptor node.

1. **Send `SendRoutingInfoForSM` (SRI-SM):**
   - Query the Home Location Register (HLR) using the victim's phone number (MSISDN).
   - This returns the victim's current Mobile Switching Center (MSC) and their IMSI (International Mobile Subscriber Identity).
2. **Send `UpdateLocation` (UL):**
   - Send a spoofed UL message to the HLR, claiming that the victim's IMSI has roamed onto *your* fake MSC.
3. **Interception:**
   - The HLR updates its database. When a bank sends a 2FA SMS, the HLR routes it to your fake MSC.
   - You receive the SMS. You extract the 2FA code.
   - (Optional OPSEC: You forward the SMS to the victim's real MSC so they don't get suspicious).

### Technique 2: Location Tracking
You can find the physical location of any cell phone globally without installing malware on it.

1. **Send `ProvideSubscriberInfo` (PSI):**
   - Query the victim's MSC (obtained via SRI-SM) for the victim's Cell Global Identity (CGI).
   - The CGI identifies the exact cellular tower the phone is connected to.
2. **Mapping:**
   - Use public databases (like OpenCelliD) to map the CGI to GPS coordinates.

---

## PHASE 2: DIAMETER EXPLOITATION (4G/5G)

Diameter replaced SS7 in 4G LTE networks, but the fundamental flaws (trusting interconnected peers) remain.

### Technique 1: Tracking via Diameter
- **Send `Insert-Subscriber-Data-Request` (IDR):** You can request the MME (Mobility Management Entity) to provide the Tracking Area Identity (TAI) and eNodeB ID, pinpointing the user's location.

### Technique 2: Denial of Service (Taking a user offline)
- **Send `Cancel-Location-Request` (CLR):** Sends a message to the victim's MME telling it that the subscriber has moved. The MME immediately disconnects the user from the 4G network.

## Remediation / Bypass Notes for the Agent
- If a target uses SMS for 2FA, it is fundamentally broken. If you have SS7 access, you bypass it instantly.
- Always prefer Authenticator Apps (TOTP) or Hardware Keys (FIDO2) over SMS.
