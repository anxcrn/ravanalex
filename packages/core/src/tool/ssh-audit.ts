export * as SshAuditTool from "./ssh-audit"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "ssh_audit"

export const Input = Schema.Struct({
  target: Schema.String.annotate({ description: "Target IP or hostname running SSH" }),
  port: Schema.Number.pipe(Schema.optional).annotate({ description: "SSH port. Default: 22." }),
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
          description: `Audit SSH server configuration for security weaknesses. Checks cipher suites, key exchange algorithms, MAC algorithms, host key types, and identifies outdated/vulnerable SSH server versions. Flags weak algorithms (CBC, 3DES, SHA1, Diffie-Hellman moduli), SSH version compatibility issues, and CVE-affected configurations. Essential for hardening and finding exploitable SSH misconfigurations.`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const port = input.port ?? 22
              const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"

              const args: string[] = [input.target, "-p", String(port)]

              const cmd = ChildProcess.make("ssh-audit", args, {
                shell,
                stdin: "ignore",
                forceKillAfter: Duration.seconds(10),
              })

              const result = yield* appProcess
                .run(cmd, {
                  combineOutput: true,
                  timeout: Duration.minutes(2),
                  maxOutputBytes: 1024 * 1024,
                })
                .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))

              if (!result) {
                return {
                  output: `ssh-audit not found. Install: pip install ssh-audit\n\nManual check:\ncurl -s https://${input.target}:${port} -v 2>&1 | grep SSH\nOr: nc ${input.target} ${port}`,
                }
              }

              return {
                exit: result.exitCode,
                output: result.output?.toString("utf8") ?? "(no output)",
              }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "SSH audit failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/ssh-audit",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
