export * as DirBruteTool from "./dir-brute"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "dir_brute"

export const Input = Schema.Struct({
  url: Schema.String.annotate({ description: "Target URL to bruteforce directories on (e.g., http://target.com)" }),
  wordlist: Schema.String.pipe(Schema.optional).annotate({
    description: "Path to wordlist file. Uses gobuster's default if not specified.",
  }),
  extensions: Schema.String.pipe(Schema.optional).annotate({
    description: "File extensions to search for (e.g., 'php,html,txt,bak,sql'). Comma-separated.",
  }),
  status_codes: Schema.String.pipe(Schema.optional).annotate({
    description: "Status codes to match (e.g., '200,301,302,403'). Defaults to '200,204,301,302,307,401,403'.",
  }),
  threads: Schema.Number.pipe(Schema.optional).annotate({
    description: "Number of concurrent threads. Defaults to 10.",
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
          description: `Bruteforce directories and files on web servers using gobuster. Discovers hidden paths, admin panels, backup files, and exposed resources. Install: go install github.com/OJ/gobuster/v3@latest`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const args = ["dir", "-u", input.url]
              if (input.wordlist) args.push("-w", input.wordlist)
              if (input.extensions) args.push("-x", input.extensions)
              if (input.status_codes) args.push("-s", input.status_codes)
              args.push("-t", String(input.threads ?? 10))
              args.push("--no-error")

              const command = ChildProcess.make("gobuster", args, {
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
                return { output: "Directory bruteforce timed out or failed. Install gobuster: go install github.com/OJ/gobuster/v3@latest" }
              }
              return {
                exit: result.exitCode,
                output: result.output?.toString("utf8") || "(no results)",
              }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "Directory bruteforce failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/dir-brute",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
