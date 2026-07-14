export * as OsintReconTool from "./osint-recon"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "osint_recon"

export const Input = Schema.Struct({
  domain: Schema.String.annotate({ description: "Target domain for OSINT reconnaissance" }),
  action: Schema.String.annotate({
    description: "OSINT action: 'harvest' (email/subdomain gathering via theHarvester), 'whois' (domain registration), 'dns' (full DNS records), 'dork' (Google dork queries generation)",
  }),
  source: Schema.String.pipe(Schema.optional).annotate({
    description: "Data source for theHarvester (e.g., 'google', 'bing', 'linkedin', 'twitter'). Default: all.",
  }),
  limit: Schema.Number.pipe(Schema.optional).annotate({
    description: "Limit number of results. Default: 500.",
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
          description: `OSINT reconnaissance tool. Performs email harvesting (theHarvester), WHOIS lookups, DNS record enumeration, and Google dork query generation. Install theHarvester: pip install theHarvester`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              let cmd: string
              const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"

              if (input.action === "harvest") {
                const source = input.source ?? "all"
                const limit = input.limit ?? 500
                cmd = `theHarvester -d ${input.domain} -b ${source} -l ${limit}`
              } else if (input.action === "whois") {
                cmd = process.platform === "win32"
                  ? `whois ${input.domain}`
                  : `whois ${input.domain}`
              } else if (input.action === "dns") {
                cmd = process.platform === "win32"
                  ? `nslookup -type=any ${input.domain}`
                  : `dig ${input.domain} ANY +noall +answer && dig ${input.domain} MX +noall +answer && dig ${input.domain} TXT +noall +answer && dig ${input.domain} NS +noall +answer`
              } else if (input.action === "dork") {
                const dorks = [
                  `site:${input.domain} filetype:pdf`,
                  `site:${input.domain} filetype:sql`,
                  `site:${input.domain} filetype:env`,
                  `site:${input.domain} filetype:log`,
                  `site:${input.domain} inurl:admin`,
                  `site:${input.domain} inurl:login`,
                  `site:${input.domain} intitle:"index of"`,
                  `site:${input.domain} ext:bak|old|backup`,
                  `site:github.com "${input.domain}" password|secret|key|token`,
                  `site:${input.domain} inurl:api`,
                  `site:${input.domain} filetype:xml`,
                  `site:${input.domain} filetype:conf`,
                ].join("\n")
                return { output: `Google Dork queries for ${input.domain}:\n\n${dorks}\n\nUse these queries in a browser or with a dorking tool.` }
              } else {
                return { output: `Unknown action: ${input.action}. Use 'harvest', 'whois', 'dns', or 'dork'.` }
              }

              const command = ChildProcess.make(cmd, [], {
                shell,
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
                return { output: `OSINT ${input.action} failed or timed out.` }
              }
              return {
                exit: result.exitCode,
                output: result.output?.toString("utf8") || "(no output)",
              }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "OSINT recon failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/osint-recon",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
