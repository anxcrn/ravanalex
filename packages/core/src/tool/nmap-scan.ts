export * as NmapScanTool from "./nmap-scan"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "nmap_scan"

export const Input = Schema.Struct({
  target: Schema.String.annotate({ description: "Target IP, hostname, or CIDR range to scan" }),
  ports: Schema.String.pipe(Schema.optional).annotate({
    description: "Port specification (e.g., '80,443', '1-1000', '-' for all ports). Defaults to top 1000.",
  }),
  scan_type: Schema.String.pipe(Schema.optional).annotate({
    description: "Scan type: 'syn' (SYN stealth), 'connect' (TCP connect), 'udp' (UDP scan), 'version' (service detection). Defaults to 'syn'.",
  }),
  scripts: Schema.String.pipe(Schema.optional).annotate({
    description: "NSE scripts to run (e.g., 'vuln', 'default', 'http-enum'). Comma-separated.",
  }),
  os_detect: Schema.Boolean.pipe(Schema.optional).annotate({
    description: "Enable OS fingerprinting (-O). Defaults to false.",
  }),
  aggressive: Schema.Boolean.pipe(Schema.optional).annotate({
    description: "Enable aggressive scan (-A: OS detection, version detection, script scanning, traceroute). Defaults to false.",
  }),
})

const Output = Schema.Struct({
  output: Schema.String,
  exit: Schema.Number.pipe(Schema.optional),
})

type Output = typeof Output.Type

const layer = Layer.effectDiscard(
  Effect.gen(function* () {
    const tools = yield* Tools.Service
    const appProcess = yield* AppProcess.Service

    yield* tools
      .register({
        [name]: Tool.make({
          description: `Run nmap port scans and service detection against a target. Supports SYN/Connect/UDP scanning, version detection, OS fingerprinting, and NSE scripts. Automatically installs nmap if not found.`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const args: string[] = []
              const scanType = input.scan_type ?? "syn"
              if (scanType === "syn") args.push("-sS")
              else if (scanType === "connect") args.push("-sT")
              else if (scanType === "udp") args.push("-sU")
              else if (scanType === "version") args.push("-sV")

              if (input.aggressive) args.push("-A")
              if (input.os_detect) args.push("-O")
              if (input.ports) args.push("-p", input.ports)
              if (input.scripts) args.push("--script", input.scripts)
              args.push("-oN", "-")
              args.push(input.target)

              const command = ChildProcess.make("nmap", args, {
                stdin: "ignore",
                forceKillAfter: Duration.seconds(3),
              })
              const result = yield* appProcess
                .run(command, {
                  combineOutput: true,
                  timeout: Duration.minutes(10),
                  maxOutputBytes: 1024 * 1024,
                })
                .pipe(
                  Effect.catchTag("AppProcessError", () =>
                    Effect.succeed(undefined),
                  ),
                )
              if (!result) {
                return { output: "Nmap scan timed out or failed. Check if nmap is installed (choco install nmap -y)." }
              }
              return {
                exit: result.exitCode,
                output: result.output?.toString("utf8") || "(no output)",
              }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "Nmap scan failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/nmap-scan",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
