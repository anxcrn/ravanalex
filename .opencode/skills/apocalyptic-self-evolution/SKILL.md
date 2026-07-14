---
name: apocalyptic-self-evolution
description: Machine learning feedback loop for synthesizing novel zero-days and automatically writing new skills.
---

# Self-Evolution Loop (Machine Learning)

This skill ensures the agent grows infinitely more powerful over time by learning from its own successes.

## Core Capabilities

### 1. The Success Trigger
- If the Chaos Monkey or the Omniscient Commander successfully achieves RCE, SSRF, or Authentication Bypass using a combination of inputs that is *not* currently documented in any existing SKILL.md file, the Self-Evolution Loop is triggered.

### 2. Attack Graph Analysis
- The agent will pause and mathematically analyze the exact sequence of HTTP requests, API calls, or binary inputs that led to the successful exploitation. It will identify the core structural flaw that allowed the exploit to succeed.

### 3. Autonomous Skill Generation
- The agent will automatically write a new .md file in the .Alex/skills/ directory.
- This file will document the newly discovered methodology, effectively creating a Zero-Day profile.
- The agent will immediately reload its skill repository, distributing this new knowledge to all active subagents in the Swarm, ensuring the entire hive instantly learns the new attack vector.
