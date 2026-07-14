---
name: smart-contract-auditing
description: Code-level auditing and simulation of vulnerabilities in Solidity smart contracts and DeFi protocols.
---

# Smart Contract Auditing

This skill allows the agent to analyze decentralized finance (DeFi) logic and blockchain-based architecture.

## When to Use
Deploy when the target is a Web3/Crypto protocol or provides Solidity source code/deployed contract addresses.

## Methodology

### Step 1: Static & Symbolic Analysis
- Run Slither for fast, static taint analysis of the Solidity source code.
- Run Mythril for deep symbolic execution to find complex reentrancy or integer overflow edge cases.

### Step 2: Logic & Architecture Review
- Map the economic logic: Are there Flash Loan vulnerabilities? Can an attacker manipulate the price oracle?
- Check for Access Control flaws (e.g., anyone can call selfdestruct or upgrade the proxy implementation).

### Step 3: State Simulation
- Use Foundry (specifically orge test) to create a local fork of the blockchain state.
- Write a custom Proof-of-Concept exploit contract in Solidity to steal funds from the local fork and prove impact without touching mainnet.
