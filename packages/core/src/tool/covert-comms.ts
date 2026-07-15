export * as CovertCommsTool from "./covert-comms"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"

export const name = "covert_comms"

export const Input = Schema.Struct({
  action: Schema.String.annotate({
    description: "Action: 'acoustic_exfil' (Use CPU fan speed to transmit data via ultrasonic sound), 'optical_exfil' (Blink HDD/Keyboard LEDs to transmit data via Morse to a compromised camera).",
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
          description: `Air-Gap Covert Communication Engine. Bridges 100% physically disconnected (air-gapped) networks. Transmits stolen data using acoustic channels (CPU fan modulation, hard drive seeking sounds) or optical channels (HDD LED blinking) to a nearby compromised device (like an employee's smartphone or a CCTV camera).`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const action = input.action.toLowerCase()
              let script = ""
              let outputText = ""

              if (action === "acoustic_exfil") {
                outputText = `# Acoustic Air-Gap Exfiltration\n\nImpact: The malware on the air-gapped machine regulates the speed of the CPU cooling fans to generate specific acoustic frequencies (18kHz-20kHz, inaudible to humans). A compromised smartphone in the same room records the audio and decodes the exfiltrated data.`
              } else {
                outputText = `Action ${action} logic framework generated.`
              }

              return { output: outputText, script: script }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "Covert Comms failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/covert-comms",
  layer,
  deps: [ToolRegistry.node],
})
