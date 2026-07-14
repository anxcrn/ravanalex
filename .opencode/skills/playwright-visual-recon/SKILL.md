---
name: playwright-visual-recon
description: Utilize headless browsers to overcome UI blindness and perform visual logic exploitation.
---

# Playwright Visual Reconnaissance

This skill is used to interact with targets that heavily rely on complex DOM manipulation, drag-and-drop interfaces, or visually rendered elements that cannot be understood via simple HTTP/JSON analysis.

## When to Use
Use when a target application requires visual rendering, CAPTCHA bypass analysis, or interaction with elements that are obscured from raw HTTP traffic.

## Methodology

### Step 1: Headless Navigation
- The Commander instructs a subagent or directly uses the Playwright integration (via @playwright/test scripts or the /browser slash command).
- Write a short Node.js script in the workspace using Playwright to navigate to the target URL, perform the necessary clicks/logins, and take a screenshot of the resulting state.

### Step 2: Visual Ingestion
- Analyze the screenshot. 
- Look for:
  - Error modals that might leak stack traces.
  - UI state inconsistencies (e.g., a "Checkout" button that becomes active prematurely).
  - Information disclosure in visually rendered PDFs or reports.

### Step 3: Actionable Output
- The visual analysis must result in a concrete HTTP request parameter modification or a state-machine bypass strategy that the Commander can then execute.
