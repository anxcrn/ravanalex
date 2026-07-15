---
name: mobile-dynamic-instrumentation
description: Bypassing SSL pinning and root detection on Android/iOS via Frida for dynamic API analysis.
---

# Mobile Dynamic Instrumentation

This skill allows the agent to break out of the static analysis limitation and dynamically intercept traffic from mobile applications.

## When to Use
Deploy when the target includes an APK/IPA file and static analysis (pk_decompile) yields no hardcoded secrets, or when the mobile app enforces SSL pinning that prevents standard proxying.

## Methodology

### Step 1: Headless Emulation & Setup
- The Commander spawns a Mobile Specialist subagent.
- The subagent provisions a local emulator or connects to an MCP-exposed Corellium instance.
- Install the target APK/IPA and push rida-server to the device.

### Step 2: Bypassing Defenses
- Inject common Frida scripts (e.g., rida-multiple-unpinning) to hook the application's native SSL verification methods and return 	rue unconditionally.
- Hook common root detection checks and bypass them.

### Step 3: API Interception & Routing
- Once pinned traffic is decrypted, route the plaintext API calls back into the workspace.
- The Commander can now run the standard ug-bounty or dvanced-logic-exploitation skills against the previously hidden mobile API endpoints.
