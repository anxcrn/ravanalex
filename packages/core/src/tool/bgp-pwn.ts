export * as BgpPwnTool from "./bgp-pwn"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"

export const name = "bgp_pwn"

export const Input = Schema.Struct({
  action: Schema.String.annotate({
    description: "Action: 'bgp_hijack' (Announce fake BGP routes to intercept traffic to an entire country/corporation).",
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
          description: `Global Routing Manipulation Engine. Executes BGP (Border Gateway Protocol) route hijacking. Used to steal IP space, reroute an entire corporation's traffic through attacker-controlled infrastructure (Man-in-the-Middle), or execute massive Denial of Service by blackholing autonomous systems.`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const action = input.action.toLowerCase()
              let script = ""
              let outputText = ""

              if (action === "bgp_hijack") {
                outputText = `# BGP Route Hijacking\n\nImpact: We compromise a vulnerable Edge Router (BGP speaker). We inject a more specific prefix (e.g., /24 instead of /16) into the global BGP routing table. The internet believes our router is the fastest path to the target, and all global traffic for that company routes to us first.`
              } else {
                outputText = `Action ${action} logic framework generated.`
              }

              return { output: outputText, script: script }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "BGP Pwn failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/bgp-pwn",
  layer,
  deps: [ToolRegistry.node],
})
