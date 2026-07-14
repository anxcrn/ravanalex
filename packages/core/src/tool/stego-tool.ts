export * as StegoTool from "./stego-tool"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "stego_tool"

export const Input = Schema.Struct({
  action: Schema.String.annotate({
    description: "Stego action: 'embed' (hide data in image), 'extract' (extract hidden data), 'detect_lsb' (LSB detection via zsteg), 'crack_pass' (stegbreak password crack), 'analyze' (full analysis — exiftool+binwalk+strings+zsteg)",
  }),
  image_path: Schema.String.annotate({ description: "Path to image file" }),
  data_path: Schema.String.pipe(Schema.optional).annotate({ description: "Data file to embed (for 'embed' action)." }),
  password: Schema.String.pipe(Schema.optional).annotate({ description: "Password for steghide embed/extract." }),
  output_path: Schema.String.pipe(Schema.optional).annotate({ description: "Output path for extracted data or modified image." }),
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
        description: `Steganography toolkit. Hide and extract data in images using steghide, detect LSB (Least Significant Bit) encoding in PNG/BMP via zsteg, crack steghide passwords via stegbreak, and perform comprehensive analysis combining exiftool + binwalk + strings + zsteg. Essential for CTF challenges and data hiding/extraction during forensics.`,
        input: Input,
        output: Output,
        toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
        execute: (input) =>
          Effect.gen(function* () {
            const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"

            switch (input.action) {
              case "embed": {
                if (!input.data_path) return { output: "ERROR: 'data_path' required for embed." }
                const outFile = input.output_path ?? input.image_path.replace(/(\.\w+)$/, "_stego$1")
                const args = ["embed", "-cf", input.image_path, "-ef", input.data_path, "-sf", outFile]
                if (input.password) { args.push("-p", input.password) } else { args.push("-p", "") }
                const cmd = ChildProcess.make("steghide", args, { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) })
                const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.minutes(2), maxOutputBytes: 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                return { exit: result?.exitCode, output: result?.output?.toString("utf8") ?? "steghide failed. Install: apt install steghide" }
              }

              case "extract": {
                const args = ["extract", "-sf", input.image_path]
                if (input.password) { args.push("-p", input.password) } else { args.push("-p", "") }
                if (input.output_path) { args.push("-xf", input.output_path) } else { args.push("-xf", "extracted.txt") }
                const cmd = ChildProcess.make("steghide", args, { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) })
                const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.minutes(2), maxOutputBytes: 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                return { exit: result?.exitCode, output: result?.output?.toString("utf8") ?? "steghide failed or no data found." }
              }

              case "detect_lsb": {
                const cmd = ChildProcess.make("zsteg", [input.image_path], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) })
                const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.minutes(5), maxOutputBytes: 2 * 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                const output = result?.output?.toString("utf8") ?? ""
                const found = output.includes("b1") && (output.includes("text") || output.includes("file"))
                return {
                  exit: result?.exitCode,
                  output: found ? `🎉 LSB DATA DETECTED!\n\n${output}` : `No LSB data found.\n${output || "zsteg not found. Install: gem install zsteg"}`,
                }
              }

              case "crack_pass": {
                const cmd = ChildProcess.make("stegbreak", ["-r", "best", "-f", "/usr/share/wordlists/rockyou.txt", input.image_path], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) })
                const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.minutes(10), maxOutputBytes: 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                return { exit: result?.exitCode, output: result?.output?.toString("utf8") ?? "stegbreak failed. Try: stegcracker " + input.image_path + " rockyou.txt" }
              }

              case "analyze": {
                const results: string[] = [`=== FULL STEGO ANALYSIS: ${input.image_path} ===\n`]
                // exiftool
                const exCmd = ChildProcess.make("exiftool", [input.image_path], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) })
                const exResult = yield* appProcess.run(exCmd, { combineOutput: true, timeout: Duration.seconds(15), maxOutputBytes: 512 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                results.push("--- EXIFTOOL ---")
                results.push(exResult?.output?.toString("utf8") ?? "(not found)")
                // binwalk
                const bwCmd = ChildProcess.make("binwalk", [input.image_path], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) })
                const bwResult = yield* appProcess.run(bwCmd, { combineOutput: true, timeout: Duration.seconds(30), maxOutputBytes: 512 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                results.push("\n--- BINWALK ---")
                results.push(bwResult?.output?.toString("utf8") ?? "(not found)")
                // zsteg (PNG/BMP only)
                const zsCmd = ChildProcess.make("zsteg", [input.image_path], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) })
                const zsResult = yield* appProcess.run(zsCmd, { combineOutput: true, timeout: Duration.minutes(5), maxOutputBytes: 512 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                results.push("\n--- ZSTEG (LSB) ---")
                results.push(zsResult?.output?.toString("utf8") ?? "(not a PNG/BMP or not found)")
                // strings
                const sCmd = ChildProcess.make("strings", ["-n", "10", input.image_path], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) })
                const sResult = yield* appProcess.run(sCmd, { combineOutput: true, timeout: Duration.seconds(30), maxOutputBytes: 256 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                const strings = sResult?.output?.toString("utf8") ?? ""
                const interesting = strings.split("\n").filter((s) => /password|secret|key|flag|token|admin/i.test(s))
                results.push("\n--- INTERESTING STRINGS ---")
                results.push(interesting.length > 0 ? interesting.join("\n") : "(none found)")
                return { exit: 0, output: results.join("\n") }
              }

              default:
                return { output: `Unknown action: ${input.action}. Supported: embed, extract, detect_lsb, crack_pass, analyze` }
            }
          }).pipe(Effect.mapError(() => new ToolFailure({ message: "Stego operation failed" }))),
      }),
    }).pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/stego-tool",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
