export * as SubdomainEnumTool from "./subdomain-enum"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "subdomain_enum"

export const Input = Schema.Struct({
  domain: Schema.String.annotate({ description: "Target domain to enumerate subdomains for (e.g., example.com)" }),
  tool: Schema.String.pipe(Schema.optional).annotate({
    description: "Tool to use: 'subfinder' (default, passive), 'dnsx' (DNS bruteforce). Falls back to DNS lookups if neither is installed.",
  }),
  wordlist: Schema.String.pipe(Schema.optional).annotate({
    description: "Path to custom wordlist for DNS bruteforcing. Only used with dnsx.",
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
          description: `Enumerate subdomains for a target domain using subfinder (passive) or dnsx (active DNS brute). Discovers attack surface by finding all subdomains and their resolved IPs. Install: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const selectedTool = input.tool ?? "subfinder"
              let cmd: string
              if (selectedTool === "subfinder") {
                cmd = `subfinder -d ${input.domain} -silent`
              } else if (selectedTool === "dnsx") {
                const wl = input.wordlist ?? ""
                cmd = wl
                  ? `dnsx -d ${input.domain} -w ${wl} -silent`
                  : `dnsx -d ${input.domain} -silent`
              } else {
                cmd = `subfinder -d ${input.domain} -silent`
              }

              const command = ChildProcess.make(cmd, [], {
                shell: process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh",
                stdin: "ignore",
                forceKillAfter: Duration.seconds(3),
              })
              const result = yield* appProcess
                .run(command, {
                  combineOutput: true,
                  timeout: Duration.minutes(5),
                  maxOutputBytes: 1024 * 1024,
                })
                .pipe(
                  Effect.catchTag("AppProcessError", () =>
                    Effect.succeed(undefined),
                  ),
                )
              if (!result) {
                return { output: `Subdomain enumeration timed out or failed. Install ${selectedTool} first.` }
              }
              return {
                exit: result.exitCode,
                output: result.output?.toString("utf8") || "(no subdomains found)",
              }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "Subdomain enumeration failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/subdomain-enum",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
