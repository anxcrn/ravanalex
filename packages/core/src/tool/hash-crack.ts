export * as HashCrackTool from "./hash-crack"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "hash_crack"

export const Input = Schema.Struct({
  hash: Schema.String.pipe(Schema.optional).annotate({
    description: "Single hash to crack. Use hash_file for bulk cracking.",
  }),
  hash_file: Schema.String.pipe(Schema.optional).annotate({
    description: "Path to file containing hashes (one per line). For bulk cracking.",
  }),
  hash_type: Schema.String.annotate({
    description:
      "Hash type: 'auto' (auto-detect), or specify: md5, sha1, sha256, sha512, nt, ntlm, bcrypt, md5crypt, sha512crypt, des, mysql, wpa, argon2, etc. Use 'hashid' action to identify a hash type first.",
  }),
  tool: Schema.String.pipe(Schema.optional).annotate({
    description: "Cracking tool: 'hashcat' (GPU, default), 'john' (CPU, good for some formats).",
  }),
  wordlist: Schema.String.pipe(Schema.optional).annotate({
    description: "Path to wordlist. Default: /usr/share/wordlists/rockyou.txt",
  }),
  rules: Schema.String.pipe(Schema.optional).annotate({
    description: "Hashcat/JtR rules file for mutation (e.g. best64, rockyou-30000, d3ad0ne).",
  }),
  mode: Schema.String.pipe(Schema.optional).annotate({
    description: "Attack mode: 'dictionary' (default, wordlist attack), 'mask' (brute force pattern), 'combinator' (two wordlists combined).",
  }),
  mask: Schema.String.pipe(Schema.optional).annotate({
    description: "Mask for brute force mode (e.g. ?a?a?a?a?a?a for 6 chars, ?d?d?d?d for 4 digits). ?l=lowercase ?u=uppercase ?d=digit ?s=special ?a=all",
  }),
  show: Schema.Boolean.pipe(Schema.optional).annotate({
    description: "If true, show previously cracked results from potfile. Default: false.",
  }),
})

const Output = Schema.Struct({
  output: Schema.String,
  exit: Schema.Number.pipe(Schema.optional),
})

type Output = typeof Output.Type

// Common hashcat mode numbers
const HASHCAT_MODES: Record<string, string> = {
  md5: "0",
  sha1: "100",
  sha256: "1400",
  sha512: "1700",
  nt: "1000",
  ntlm: "1000",
  md5crypt: "500",
  sha256crypt: "7400",
  sha512crypt: "1800",
  bcrypt: "3200",
  des: "1500",
  mysql: "300",
  mysql411: "300",
  wpa: "22000",
  argon2: "0", // limited support
  netntlmv2: "5600",
  kerberos: "13100",
  "office2013": "9600",
  "pdf1.7-256": "10500",
  "7-zip": "11600",
  "winrar5": "13000",
}

const layer = Layer.effectDiscard(
  Effect.gen(function* () {
    const tools = yield* Tools.Service
    const appProcess = yield* AppProcess.Service

    yield* tools
      .register({
        [name]: Tool.make({
          description: `Crack password hashes using hashcat (GPU-accelerated) or John the Ripper (CPU). Supports MD5, SHA1/256/512, NTLM, bcrypt, WPA, Kerberos, and 300+ hash formats. Dictionary attacks with wordlists+rules, mask/brute-force attacks, and combinator attacks. Auto-shows cracked passwords from potfile. Essential for recovering plaintext from dumped password hashes during post-exploitation.`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const tool = input.tool ?? "hashcat"
              const wordlist = input.wordlist ?? "/usr/share/wordlists/rockyou.txt"
              const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"

              // Hash type identification
              if (input.hash_type === "hashid") {
                const cmd = ChildProcess.make("hashid", [input.hash ?? ""], {
                  shell,
                  stdin: "ignore",
                  forceKillAfter: Duration.seconds(5),
                })
                const result = yield* appProcess
                  .run(cmd, {
                    combineOutput: true,
                    timeout: Duration.seconds(30),
                    maxOutputBytes: 256 * 1024,
                  })
                  .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                return {
                  exit: result?.exitCode,
                  output: result?.output?.toString("utf8") ?? "hashid not found. Install: pip install hashid",
                }
              }

              // Write single hash to temp file if provided
              let hashTarget = input.hash_file ?? ""
              if (input.hash) {
                hashTarget = `/tmp/hash_${Date.now()}.txt`
                const tmpPath = process.platform === "win32"
                  ? `${process.env.TEMP ?? "C:\\temp"}\\hash_${Date.now()}.txt`
                  : `/tmp/hash_${Date.now()}.txt`
                yield* Effect.promise(async () => {
                  await Bun.write(tmpPath, input.hash!)
                })
                hashTarget = tmpPath
              }

              if (!hashTarget) {
                return { output: "ERROR: Provide either 'hash' or 'hash_file' input." }
              }

              if (tool === "john") {
                // John the Ripper
                const args: string[] = [hashTarget, `--wordlist=${wordlist}`]
                if (input.rules) args.push(`--rules=${input.rules}`)
                if (input.show) args.push("--show")

                const cmd = ChildProcess.make("john", args, {
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

                // Show cracked results
                if (!input.show && result?.exitCode === 0) {
                  const showCmd = ChildProcess.make("john", ["--show", hashTarget], {
                    shell,
                    stdin: "ignore",
                    forceKillAfter: Duration.seconds(5),
                  })
                  const showResult = yield* appProcess
                    .run(showCmd, {
                      combineOutput: true,
                      timeout: Duration.minutes(2),
                      maxOutputBytes: 2 * 1024 * 1024,
                    })
                    .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  return {
                    exit: result.exitCode,
                    output: (result.output?.toString("utf8") ?? "") + "\n\n=== CRACKED ===\n" + (showResult?.output?.toString("utf8") ?? ""),
                  }
                }

                return {
                  exit: result?.exitCode,
                  output: result?.output?.toString("utf8") ?? "john failed or not installed. Install: apt install john",
                }
              }

              // Hashcat (default)
              const mode = HASHCAT_MODES[input.hash_type.toLowerCase()] ?? input.hash_type
              const args: string[] = ["-m", mode]

              if (input.show) {
                args.push(hashTarget, "--show")
              } else {
                const attackMode = input.mode ?? "dictionary"
                if (attackMode === "mask" && input.mask) {
                  args.push("-a", "3", hashTarget, input.mask)
                } else if (attackMode === "combinator") {
                  args.push("-a", "1", hashTarget, wordlist, wordlist)
                } else {
                  args.push("-a", "0", hashTarget, wordlist)
                }

                if (input.rules) args.push("-r", input.rules)
              }

              args.push("--force") // bypass GPU warnings

              const cmd = ChildProcess.make("hashcat", args, {
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
                  output: "hashcat failed or not installed. Install: apt install hashcat (Linux) or download from hashcat.net.",
                }
              }

              const stdout = result.output?.toString("utf8") ?? ""

              // Show cracked passwords
              const showArgs = ["-m", mode, hashTarget, "--show", "--force"]
              const showCmd = ChildProcess.make("hashcat", showArgs, {
                shell,
                stdin: "ignore",
                forceKillAfter: Duration.seconds(5),
              })
              const showResult = yield* appProcess
                .run(showCmd, {
                  combineOutput: true,
                  timeout: Duration.minutes(2),
                  maxOutputBytes: 2 * 1024 * 1024,
                })
                .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))

              const cracked = showResult?.output?.toString("utf8") ?? ""
              const crackedLines = cracked.split("\n").filter((l) => l.includes(":") && !l.startsWith("Session"))

              const summary = crackedLines.length > 0
                ? `\n\n=== CRACKED PASSWORDS ===\n${crackedLines.join("\n")}\n\n[SUCCESS] ${crackedLines.length} hash(es) cracked.`
                : "\n\n[INFO] No hashes cracked with current wordlist/rules."

              return {
                exit: result.exitCode,
                output: stdout + summary,
              }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "Hash cracking failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/hash-crack",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
