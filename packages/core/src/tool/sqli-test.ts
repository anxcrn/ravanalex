export * as SqliTestTool from "./sqli-test"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "sqli_test"

export const Input = Schema.Struct({
  url: Schema.String.annotate({ description: "Target URL with injectable parameter (e.g., http://target.com/page?id=1)" }),
  data: Schema.String.pipe(Schema.optional).annotate({
    description: "POST data for testing POST-based injection (e.g., 'username=admin&password=test')",
  }),
  level: Schema.Number.pipe(Schema.optional).annotate({
    description: "SQLMap test level (1-5). Higher = more payloads. Default: 1.",
  }),
  risk: Schema.Number.pipe(Schema.optional).annotate({
    description: "SQLMap risk level (1-3). Higher = more aggressive. Default: 1.",
  }),
  technique: Schema.String.pipe(Schema.optional).annotate({
    description: "SQLi techniques: B=Boolean, E=Error, U=Union, S=Stacked, T=Time, Q=Inline. Default: BEUSTQ.",
  }),
  dump: Schema.Boolean.pipe(Schema.optional).annotate({
    description: "Dump database tables if injection is found. Default: false.",
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
          description: `Test for SQL injection vulnerabilities using sqlmap. Supports GET/POST parameter testing, various injection techniques (Boolean, Error, Union, Stacked, Time-based), and database enumeration. Install: pip install sqlmap`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const args = ["-u", input.url, "--batch", "--random-agent"]
              if (input.data) args.push("--data", input.data)
              if (input.level) args.push("--level", String(input.level))
              if (input.risk) args.push("--risk", String(input.risk))
              if (input.technique) args.push("--technique", input.technique)
              if (input.dump) args.push("--dump")

              const command = ChildProcess.make("sqlmap", args, {
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
                return { output: "SQLMap timed out or failed. Install: pip install sqlmap" }
              }
              return {
                exit: result.exitCode,
                output: result.output?.toString("utf8") || "(no output)",
              }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "SQL injection test failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/sqli-test",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
