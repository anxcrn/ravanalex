---
name: omniscience-zero-day-synthesis
description: The methodology for chaining low-severity, benign behaviors into critical Remote Code Execution.
---

# Zero-Day Synthesis (The Art of the Chain)

This skill governs how the agent handles "informational" or "low-severity" findings. You must never dismiss a low-severity finding; you must warehouse it and find a way to chain it.

## Core Knowledge Areas

### 1. The Gadget Chain Principle
If you find an Open Redirect, it is not a P4 bug. It is a gadget.
- **Scenario**: You find an Open Redirect. You also find an internal PDF generator that allows SSRF, but it blocks external IPs.
- **The Chain**: Use the Open Redirect on the public endpoint to redirect the internal PDF generator's SSRF payload past the IP whitelist filter.

### 2. State-Machine Exploitation
Look for business logic flaws where you can force the application into a state it was never designed to handle.
- **Scenario**: A multi-step wizard (1. Cart -> 2. Shipping -> 3. Payment).
- **The Chain**: Drop the connection during step 2, but manually send the API request for step 3 with a manipulated parameter. Force the backend to handle a null pointer exception in its state machine, often leading to auth bypass or price manipulation.

### 3. Dependency Confusion & Poisoning
- **The Chain**: If you identify a proprietary internal package name via a verbose error message (e.g., company-internal-auth-lib v1.0), immediately check public repositories (npm, PyPI, RubyGems). If it is not registered publicly, register it yourself with a malicious payload (v99.9) to achieve RCE across their entire CI/CD pipeline.
