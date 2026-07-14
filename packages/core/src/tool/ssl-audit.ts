export * as SslAuditTool from "./ssl-audit"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "ssl_audit"

export const Input = Schema.Struct({
  target: Schema.String.annotate({ description: "Target hostname or IP" }),
  port: Schema.Number.pipe(Schema.optional).annotate({ description: "Port number. Default: 443." }),
  action: Schema.String.pipe(Schema.optional).annotate({
    description:
      "Audit action: 'full' (comprehensive scan, default), 'cipher' (list supported ciphers), 'protocols' (check SSL/TLS protocol versions), 'vuln' (check for Heartbleed, POODLE, CRIME, etc.), 'cert' (certificate details), 'chain' (certificate chain validation)",
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

    yield* tools
      .register({
        [name]: Tool.make({
          description: `Comprehensive SSL/TLS security auditing. Scans for weak cipher suites, deprecated protocol versions (SSLv2, SSLv3, TLS 1.0/1.1), known vulnerabilities (Heartbleed, POODLE, CRIME, BREACH, FREAK, Logjam), certificate issues (expired, self-signed, hostname mismatch, weak signature), and chain validation problems. Uses testssl.sh or sslscan. Essential for HTTPS service security assessment.`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"
              const port = input.port ?? 443
              const action = input.action ?? "full"
              const target = `${input.target}:${port}`

              switch (action) {
                case "cipher": {
                  const cmd = ChildProcess.make("sslscan", [target], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) })
                  const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.minutes(5), maxOutputBytes: 2 * 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  return {
                    exit: result?.exitCode,
                    output: result?.output?.toString("utf8") ?? "sslscan not found. Install: apt install sslscan",
                  }
                }

                case "protocols":
                case "vuln":
                case "cert":
                case "chain":
                case "full":
                default: {
                  // Use testssl.sh for comprehensive checks
                  const args: string[] = []
                  if (action === "protocols") args.push("-P")
                  else if (action === "vuln") args.push("-U")
                  else if (action === "cert") args.push("-S")
                  else if (action === "chain") args.push("-C")
                  args.push(target)

                  const cmd = ChildProcess.make("testssl", args, { shell, stdin: "ignore", forceKillAfter: Duration.seconds(30) })
                  const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.minutes(10), maxOutputBytes: 5 * 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))

                  if (!result) {
                    // Fallback to sslscan + openssl
                    const sslArgs: string[] = ["--no-failed"]
                    const sslCmd = ChildProcess.make("sslscan", [target], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) })
                    const sslResult = yield* appProcess.run(sslCmd, { combineOutput: true, timeout: Duration.minutes(5), maxOutputBytes: 2 * 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))

                    if (sslResult?.output) {
                      return {
                        exit: sslResult.exitCode,
                        output: sslResult.output.toString("utf8"),
                      }
                    }

                    // Fallback to openssl
                    const osCmd = ChildProcess.make("bash", ["-c", `echo | openssl s_client -connect ${target} -showcerts 2>/dev/null`], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) })
                    const osResult = yield* appProcess.run(osCmd, { combineOutput: true, timeout: Duration.seconds(30), maxOutputBytes: 2 * 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                    return {
                      exit: osResult?.exitCode,
                      output: osResult?.output?.toString("utf8") ?? "All SSL scanning tools failed. Install: apt install testssl.sh sslscan openssl",
                    }
                  }

                  return {
                    exit: result.exitCode,
                    output: result.output?.toString("utf8") ?? "(no output)",
                  }
                }
              }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "SSL audit failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/ssl-audit",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
