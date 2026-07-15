export * as QuantumHarvestTool from "./quantum-harvest"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"

export const name = "quantum_harvest"

export const Input = Schema.Struct({
  action: Schema.String.annotate({
    description: "Action: 'sndl_exfil' (Store Now, Decrypt Later - extract heavily encrypted databases for future quantum decryption), 'pqc_downgrade' (Force target to downgrade from Post-Quantum Cryptography to vulnerable classical algorithms).",
  }),
})

const Output = Schema.Struct({
  output: Schema.String,
  script: Schema.String.pipe(Schema.optional),
})

type Output = typeof Output.Type

const layer = Layer.effectDiscard(
  Effect.gen(function* () {
    const tools = yield* Tools.Service

    yield* tools
      .register({
        [name]: Tool.make({
          description: `Quantum Warfare Engine. Executes "Store Now, Decrypt Later" (SNDL) campaigns to hoard AES-256/RSA-4096 encrypted data until Shor's algorithm becomes viable on quantum hardware. Also executes downgrade attacks against early Post-Quantum Cryptography (PQC) implementations (e.g., Kyber, Dilithium).`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const action = input.action.toLowerCase()
              let script = ""
              let outputText = ""

              if (action === "sndl_exfil") {
                outputText = `# SNDL (Store Now, Decrypt Later) Hoarding\n\nImpact: The agent identifies highly classified, heavily encrypted blobs (e.g., diplomatic cables, offline password vaults) and exfiltrates them to a cold storage C2, banking on future quantum compute to break them.`
              } else if (action === "pqc_downgrade") {
                outputText = `# Post-Quantum Cryptography (PQC) Downgrade Attack\n\nImpact: Intercepts TLS handshakes negotiating Kyber/Dilithium and strips the PQC ciphersuites, forcing the server to fall back to classical RSA/ECC, which can then be broken by SNDL.`
              } else {
                outputText = `Action ${action} logic framework generated.`
              }

              return { output: outputText, script: script }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "Quantum Harvest failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/quantum-harvest",
  layer,
  deps: [ToolRegistry.node],
})
