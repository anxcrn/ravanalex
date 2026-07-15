export * as BciPwnTool from "./bci-pwn"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"

export const name = "bci_pwn"

export const Input = Schema.Struct({
  action: Schema.String.annotate({
    description: "Action: 'neural_sniff' (Intercept and decode EEG/Neuralink brainwave data to extract PINs/thoughts), 'stim_overload' (Manipulate neurostimulator parameters to induce physical harm/seizures).",
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
          description: `Brain-Computer Interface (BCI) Exploitation Engine. Targets neurotech devices (Neuralink, Deep Brain Stimulators, medical pacemakers). Capabilities: Brainwave (EEG) side-channel extraction to steal passwords from human thought, and malicious stimulation parameter injection.`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ output: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const action = input.action.toLowerCase()
              let script = ""
              let outputText = ""

              if (action === "neural_sniff") {
                outputText = `# Neural Data Extraction (P300 Wave Exploitation)\n\nImpact: We compromise the Bluetooth/Wi-Fi connection of a BCI headset. We flash subliminal images of numbers (0-9) on the user's screen. We monitor their P300 brainwave spike. When their brain recognizes a number that belongs to their ATM PIN, the P300 wave spikes, allowing us to literally extract their password from their subconscious thought.`
              } else if (action === "stim_overload") {
                outputText = `# Neurostimulator Parameter Overload\n\nImpact: We exploit the unencrypted telemetry link of a medical Deep Brain Stimulator (DBS) used for Parkinson's. We alter the electrical pulse amplitude and frequency parameters, forcing the device to induce a seizure in the patient.`
              } else {
                outputText = `Action ${action} logic framework generated.`
              }

              return { output: outputText, script: script }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "BCI Pwn failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/bci-pwn",
  layer,
  deps: [ToolRegistry.node],
})
