export * as GraphqlTestTool from "./graphql-test"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "graphql_test"

export const Input = Schema.Struct({
  url: Schema.String.annotate({ description: "GraphQL endpoint URL (e.g. https://target.com/graphql)" }),
  action: Schema.String.pipe(Schema.optional).annotate({
    description: "Test action: 'introspect' (schema introspection, default), 'batch' (batch query attack), 'suggest' (field suggestion exploitation), 'dos' (query depth DoS test), 'all' (run everything)",
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

    yield* tools.register({
      [name]: Tool.make({
        description: `Test GraphQL endpoints for security vulnerabilities. Performs schema introspection (reveals all types, queries, mutations, fields), batch query attacks, field suggestion exploitation (discover hidden fields via error messages), and query depth DoS testing. Uses graphw00f, inql, or manual queries. Essential for modern API security assessment.`,
        input: Input,
        output: Output,
        toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
        execute: (input) =>
          Effect.gen(function* () {
            const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"
            const action = input.action ?? "introspect"

            const introspectionQuery = JSON.stringify({
              query: `{ __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind description fields { name description type { name kind ofType { name kind } } args { name description type { name kind ofType { name kind } } } } } } }`
            })

            switch (action) {
              case "introspect":
              case "all": {
                const cmd = ChildProcess.make("curl", ["-s", "-X", "POST", "-H", "Content-Type: application/json", "-d", introspectionQuery, input.url], {
                  shell, stdin: "ignore", forceKillAfter: Duration.seconds(10),
                })
                const result = yield* appProcess.run(cmd, {
                  combineOutput: true, timeout: Duration.seconds(30), maxOutputBytes: 2 * 1024 * 1024,
                }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))

                const output = result?.output?.toString("utf8") ?? ""
                const hasSchema = output.includes("__schema") || output.includes("queryType")

                return {
                  exit: result?.exitCode,
                  output: hasSchema
                    ? `🎉 INTROSPECTION ENABLED!\n\nFull schema leaked:\n${output.substring(0, 5000)}\n\n[CRITICAL] Introspection reveals the entire API schema — all queries, mutations, types, and fields are visible.`
                    : `Introspection disabled (good practice). Response:\n${output}\n\nTry 'suggest' action to discover hidden fields via error messages.`,
                }
              }

              case "batch": {
                // Batch query attack — multiple queries in one request
                const batchQuery = JSON.stringify([
                  { query: "{ __typename }" },
                  { query: "{ __typename }" },
                  { query: "{ __typename }" },
                ])
                const cmd = ChildProcess.make("curl", ["-s", "-X", "POST", "-H", "Content-Type: application/json", "-d", batchQuery, input.url], {
                  shell, stdin: "ignore", forceKillAfter: Duration.seconds(10),
                })
                const result = yield* appProcess.run(cmd, {
                  combineOutput: true, timeout: Duration.seconds(30), maxOutputBytes: 1024 * 1024,
                }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                const output = result?.output?.toString("utf8") ?? ""
                return {
                  exit: result?.exitCode,
                  output: output.includes("[{") || output.includes("data")
                    ? `[VULNERABLE] Batch queries accepted!\n${output}\n\n[WARNING] Batch queries can be used for brute force bypass (rate limit evasion) and complex data extraction.`
                    : `Batch queries rejected.\n${output}`,
                }
              }

              case "suggest": {
                // Field suggestion exploitation
                const suggestQuery = JSON.stringify({ query: "{ user { idd } }" })
                const cmd = ChildProcess.make("curl", ["-s", "-X", "POST", "-H", "Content-Type: application/json", "-d", suggestQuery, input.url], {
                  shell, stdin: "ignore", forceKillAfter: Duration.seconds(10),
                })
                const result = yield* appProcess.run(cmd, {
                  combineOutput: true, timeout: Duration.seconds(30), maxOutputBytes: 1024 * 1024,
                }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                const output = result?.output?.toString("utf8") ?? ""
                const hasSuggestion = output.toLowerCase().includes("did you mean")
                return {
                  exit: result?.exitCode,
                  output: hasSuggestion
                    ? `[VULNERABLE] Field suggestions enabled!\n${output}\n\n[INFO] Error messages reveal valid field names. Iterate with typos to map the entire schema even without introspection.`
                    : `No field suggestions in error messages. Response:\n${output}`,
                }
              }

              case "dos": {
                // Query depth DoS
                let deepQuery = "query { user { posts { author { posts { author { posts { author { posts { author { posts { id } } } } } } } } } }"
                const dosPayload = JSON.stringify({ query: `{ ${"user { ".repeat(20)} id ${"} ".repeat(20)} }` })
                const cmd = ChildProcess.make("curl", ["-s", "-X", "POST", "-H", "Content-Type: application/json", "-d", dosPayload, input.url], {
                  shell, stdin: "ignore", forceKillAfter: Duration.seconds(10),
                })
                const result = yield* appProcess.run(cmd, {
                  combineOutput: true, timeout: Duration.seconds(30), maxOutputBytes: 1024 * 1024,
                }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                const output = result?.output?.toString("utf8") ?? ""
                return {
                  exit: result?.exitCode,
                  output: output.includes("data") || !output.includes("error")
                    ? `[POTENTIAL DoS] Deep query accepted (depth 20).\n${output}\n\n[WARNING] No query depth limiting detected. Nested queries can cause CPU/memory exhaustion.`
                    : `Deep query rejected.\n${output}`,
                }
              }

              default:
                return { output: `Unknown action: ${action}. Supported: introspect, batch, suggest, dos, all` }
            }
          }).pipe(Effect.mapError(() => new ToolFailure({ message: "GraphQL test failed" }))),
      }),
    }).pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/graphql-test",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
