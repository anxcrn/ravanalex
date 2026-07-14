export * as VulnScanTool from "./vuln-scan"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "vuln_scan"

export const Input = Schema.Struct({
  target: Schema.String.annotate({ description: "Target URL or host to scan for vulnerabilities" }),
  tool: Schema.String.pipe(Schema.optional).annotate({
    description: "Scanner to use: 'nuclei' (template-based, default), 'nikto' (web server scanner).",
  }),
  templates: Schema.String.pipe(Schema.optional).annotate({
    description: "Nuclei template tags to use (e.g., 'cve', 'exposure', 'misconfig', 'tech'). Comma-separated.",
  }),
  severity: Schema.String.pipe(Schema.optional).annotate({
    description: "Filter by severity: 'critical', 'high', 'medium', 'low', 'info'. Comma-separated.",
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
          description: `Scan targets for known vulnerabilities using nuclei (template-based CVE/misconfig detection) or nikto (web server scanner). Automatically identifies CVEs, misconfigurations, exposed panels, and security issues. Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const selectedTool = input.tool ?? "nuclei"
              let cmd: string

              if (selectedTool === "nuclei") {
                cmd = `nuclei -u ${input.target} -silent`
                if (input.templates) cmd += ` -tags ${input.templates}`
                if (input.severity) cmd += ` -severity ${input.severity}`
              } else {
                cmd = `nikto -h ${input.target} -Format txt`
              }

              const command = ChildProcess.make(cmd, [], {
                shell: process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh",
                stdin: "ignore",
                forceKillAfter: Duration.seconds(3),
              })
              const result = yield* appProcess
                .run(command, {
                  combineOutput: true,
                  timeout: Duration.minutes(15),
                  maxOutputBytes: 2 * 1024 * 1024,
                })
                .pipe(
                  Effect.catchTag("AppProcessError", () =>
                    Effect.succeed(undefined),
                  ),
                )
              if (!result) {
                return { output: `Vulnerability scan timed out or failed. Install ${selectedTool} first.` }
              }
              return {
                exit: result.exitCode,
                output: result.output?.toString("utf8") || "(no vulnerabilities found)",
              }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "Vulnerability scan failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/vuln-scan",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
