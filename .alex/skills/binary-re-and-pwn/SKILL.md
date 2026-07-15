---
name: binary-re-and-pwn
description: Headless reverse engineering and exploit generation for compiled binaries using Ghidra and pwntools.
---

# Binary Reverse Engineering & Exploitation

This skill elevates the agent from web/cloud logic into low-level memory corruption and assembly exploitation.

## When to Use
Deploy when a custom, proprietary compiled executable (C/C++, Rust, Go) or a memory-unsafe binary is discovered during reconnaissance or internal enumeration.

## Methodology

### Step 1: Headless Reversing
- The Commander spawns a Binary Specialist subagent.
- The subagent uses headless Ghidra scripts (via Python) to ingest the binary, decompile it, and identify vulnerable functions (e.g., strcpy, printf without format strings, gets).

### Step 2: Symbolic Execution
- If the binary has complex logic, use ngr to perform symbolic execution and mathematically solve for the input required to reach the vulnerable function block.

### Step 3: Exploit Generation
- Identify the offset to the Instruction Pointer (EIP/RIP).
- Identify mitigation techniques (ASLR, DEP, NX).
- Use pwntools to automatically write a custom Python script that generates a Return-Oriented Programming (ROP) chain to pop a shell.
