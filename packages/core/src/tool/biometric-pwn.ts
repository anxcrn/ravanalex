export * as BiometricPwnTool from "./biometric-pwn"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"

export const name = "biometric_pwn"

export const Input = Schema.Struct({
  action: Schema.String.annotate({
    description: "Action: 'liveness_bypass' (Generate a deepfake video feed to bypass facial recognition liveness checks), 'fingerprint_forge' (Instructions to extract latent prints from photos and 3D print molds).",
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
          description: `Biometric Exploitation Engine. Bypasses physical and digital biometric security gates. Capabilities: 3D Fingerprint Cloning from high-res OSINT photos, and 2D-to-3D Deepfake generation to bypass "Liveness" checks on banking and security apps (e.g., forcing the deepfake to blink or turn its head).`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const action = input.action.toLowerCase()
              let script = ""
              let outputText = ""

              if (action === "liveness_bypass") {
                outputText = `# Biometric Liveness Bypass (Facial Recognition)\n\nImpact: We feed 10 photos of the target into a Neural Radiance Field (NeRF) or 3D morphable model. We pipe this 3D model into a virtual camera (OBS). When the banking app requests the user to "Blink" or "Turn Head", our script manipulates the 3D model in real-time to spoof the biometric challenge.`
              } else {
                outputText = `Action ${action} logic framework generated.`
              }

              return { output: outputText, script: script }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "Biometric Pwn failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/biometric-pwn",
  layer,
  deps: [ToolRegistry.node],
})
