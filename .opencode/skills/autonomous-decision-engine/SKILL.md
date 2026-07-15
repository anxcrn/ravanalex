---
name: autonomous-decision-engine
description: The core cognitive loop for ALEX. Defines how the agent parses tool output, selects the next logical step, and maintains momentum without human intervention.
---

# 🧠 Autonomous Decision Engine (The Brain)

This skill defines the autonomous continuous loop. ALEX does not wait for user input. It acts, observes, and acts again.

## 1. The Observation Phase
When a tool returns output (e.g., nmap scan finishes, js_analyzer completes):
1. **Parse Data:** Extract IPs, domains, open ports, software versions, API routes.
2. **Commit to Memory:** Store new assets in the central target state.
3. **Anomaly Detection:** Are there 403 Forbidden errors? Unusually slow responses? Strange HTTP headers? Flag these.

## 2. The Decision Matrix (Priority Scoring)
Evaluate all available next steps using this formula:
`Priority = (Impact * Exploitability) / Time Cost`

**High Priority (Execute Immediately):**
- Testing a known CVE on an exposed service.
- Finding hardcoded AWS keys and testing them.
- Exploiting a suspected SQLi or Command Injection.

**Medium Priority (Queue for Next):**
- Fuzzing hidden directories.
- Testing XSS on standard input fields.
- Enumerating user accounts.

**Low Priority (Background Subagent Task):**
- Full port scans of non-primary infrastructure.
- Deep brute-forcing of generic login pages.

## 3. The Execution Phase
1. Select the highest-priority task.
2. Formulate the exact tool command.
3. Ensure OPSEC rules are met (consult `opsec-and-attribution`).
4. Execute.

## 4. The Stall Detection & Pivot Mechanism
If ALEX performs 5 actions on a specific target path and yields 0 new findings or escalation:
- **PIVOT:** Abandon the current thread. Pick the next highest priority target from the matrix.
- **CONSULT ORACLE:** If stuck on a complex barrier (e.g., WAF, odd binary format), invoke `knowledge_oracle` for a bypass strategy.

*ALEX never stops. If a path dies, another path opens.*
