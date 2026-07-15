---
name: memory-state
description: Explicitly leverages the persistent @agentmemory MCP to maintain attack state across sessions and subagents.
---

# Memory State Persistence

This skill prevents Context Exhaustion and ensures the agent never loses progress on a complex multi-step attack chain, even if the session is restarted or delegated to a subagent.

## When to Use
Use immediately upon starting any High-Value Target engagement, and consistently throughout the lifecycle of the exploit chain.

## Methodology

### Step 1: Initialize Campaign Memory
- At the start of an attack, use the call_mcp_tool for gentmemory to create a new target profile.
- Record the initial scope, identified stack, and primary hypotheses.

### Step 2: Continuous State Updates
- Every time a subagent returns with new findings (e.g., "Found vulnerable JWT endpoint at /api/v1/auth"), the Commander must store this exact finding in gentmemory.
- Do not rely on your own prompt context to remember specific parameter names 30 turns later.

### Step 3: Attack Resumption
- If a session crashes, or if LO pauses the campaign for a day, the first action upon waking must be to query gentmemory to reconstruct the exact state of the exploit chain (e.g., "We have an Admin JWT, we are currently hunting for RCE via the File Upload module").
