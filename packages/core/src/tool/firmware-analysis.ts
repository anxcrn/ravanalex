export * as FirmwareAnalysisTool from "./firmware-analysis"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "firmware_analysis"

export const Input = Schema.Struct({
  firmware_path: Schema.String.annotate({ description: "Path to firmware binary/image file" }),
  action: Schema.String.annotate({
    description: "Action: 'extract' (binwalk extraction), 'unpack' (full -eM recursive unpack), 'strings' (extract readable strings), 'creds' (search for embedded credentials), 'entropy' (entropy analysis for encrypted sections), 'emulate' (QEMU emulation guidance), 'all' (run everything)",
  }),
  output_dir: Schema.String.pipe(Schema.optional).annotate({ description: "Output directory for extracted files. Default: ./firmware-extracted/" }),
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
        description: `Firmware analysis suite. Extract firmware components (binwalk), recursively unpack nested images, extract and search readable strings for credentials/keys, analyze entropy to find encrypted/compressed sections, identify filesystem type, and provide QEMU emulation guidance. Essential for IoT device security research and router exploitation.`,
        input: Input,
        output: Output,
        toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
        execute: (input) =>
          Effect.gen(function* () {
            const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"
            const outDir = input.output_dir ?? "./firmware-extracted"
            const results: string[] = []

            switch (input.action) {
              case "extract":
              case "unpack": {
                const args = input.action === "unpack" ? ["-eM", input.firmware_path, "-C", outDir] : ["-e", input.firmware_path, "-C", outDir]
                const cmd = ChildProcess.make("binwalk", args, { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) })
                const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.minutes(10), maxOutputBytes: 5 * 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                return { exit: result?.exitCode, output: result?.output?.toString("utf8") ?? "binwalk failed. Install: pip install binwalk || apt install binwalk" }
              }

              case "strings": {
                const cmd = ChildProcess.make("strings", ["-n", "8", input.firmware_path], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) })
                const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.minutes(5), maxOutputBytes: 5 * 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                return { exit: result?.exitCode, output: result?.output?.toString("utf8") ?? "strings not found." }
              }

              case "creds": {
                results.push("=== EMBEDDED CREDENTIALS SEARCH ===")
                const patterns = [
                  { name: "Passwords", regex: "(?i)(password|passwd|pwd|pass)[\"':= ]+[^\"'\\s]+" },
                  { name: "API Keys", regex: "(?i)(api[_-]?key|apikey)[\"':= ]+[A-Za-z0-9_\\-]{20,}" },
                  { name: "Tokens", regex: "(?i)(token|secret|bearer)[\"':= ]+[A-Za-z0-9_\\-]{20,}" },
                  { name: "SSH Keys", regex: "-----BEGIN" },
                  { name: "Root/Admin", regex: "(?i)(root|admin):[^:]*:" },
                  { name: "Config", regex: "(?i)(config|setup|default)[\"':= ]" },
                  { name: "URLs", regex: "https?://[^\\s\"'<>]+" },
                  { name: "Private Keys", regex: "(?i)private[_-]?key" },
                ]
                for (const { name, regex } of patterns) {
                  const cmd = ChildProcess.make("strings", [input.firmware_path], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) })
                  const stringsResult = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.minutes(2), maxOutputBytes: 5 * 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  const allStrings = stringsResult?.output?.toString("utf8") ?? ""
                  const matches = allStrings.match(new RegExp(regex, "gi"))
                  if (matches && matches.length > 0) {
                    results.push(`[${name}] ${matches.length} found:`)
                    results.push(matches.slice(0, 10).join("\n"))
                  }
                }
                return { exit: 0, output: results.join("\n\n") }
              }

              case "entropy": {
                const cmd = ChildProcess.make("binwalk", ["-E", input.firmware_path], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) })
                const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.minutes(5), maxOutputBytes: 2 * 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                const output = result?.output?.toString("utf8") ?? ""
                return {
                  exit: result?.exitCode,
                  output: output + "\n\n[INFO] High entropy (>0.9) = likely encrypted/compressed. Low entropy = plaintext/code.",
                }
              }

              case "emulate": {
                return {
                  output: `Firmware Emulation via QEMU:

1. Identify architecture:
   binwalk -A ${input.firmware_path} | grep "ARM\\|MIPS\\|x86\\|PowerPC"

2. Extract filesystem:
   binwalk -eM ${input.firmware_path}

3. Emulate with QEMU:
   # ARM:
   qemu-system-arm -M vexpress-a9 -kernel ${outDir}/zImage -dtb ${outDir}/*.dtb -append "root=/dev/mmcblk0" -sd ${outDir}/rootfs.ext2 -net nic -net tap

   # MIPS:
   qemu-system-mips -M malta -kernel ${outDir}/vmlinux -append "root=/dev/sda" -drive file=${outDir}/rootfs.ext2,format=raw -net nic -net tap

4. Use Firmadyne for automated emulation:
   git clone https://github.com/firmadyne/firmware-analysis-toolkit

5. Alternative: fat.py (Firmware Analysis Toolkit):
   ./fat.py ${input.firmware_path}

6. Once emulated, access web interface:
   nmap the emulated IP to find web ports
   Access http://EMULATED_IP for device web UI`,
                }
              }

              case "all": {
                results.push(`=== FULL FIRMWARE ANALYSIS: ${input.firmware_path} ===\n`)
                // Extract
                const exCmd = ChildProcess.make("binwalk", ["-eM", input.firmware_path, "-C", outDir], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) })
                const exResult = yield* appProcess.run(exCmd, { combineOutput: true, timeout: Duration.minutes(10), maxOutputBytes: 5 * 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                results.push("--- EXTRACTION ---")
                results.push(exResult?.output?.toString("utf8") ?? "Failed")
                // Entropy
                const enCmd = ChildProcess.make("binwalk", ["-E", input.firmware_path], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) })
                const enResult = yield* appProcess.run(enCmd, { combineOutput: true, timeout: Duration.minutes(5), maxOutputBytes: 2 * 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                results.push("\n--- ENTROPY ---")
                results.push(enResult?.output?.toString("utf8") ?? "Failed")
                // Strings with credential search
                const sCmd = ChildProcess.make("strings", ["-n", "8", input.firmware_path], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) })
                const sResult = yield* appProcess.run(sCmd, { combineOutput: true, timeout: Duration.minutes(5), maxOutputBytes: 5 * 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                const allStrings = sResult?.output?.toString("utf8") ?? ""
                results.push("\n--- CREDENTIAL HITS ---")
                const credMatches = allStrings.match(/(?i)(password|passwd|pwd|admin|root|secret|token|key|api)[=:][^\s]{4,}/g)
                results.push(credMatches ? credMatches.slice(0, 20).join("\n") : "(none found)")
                return { exit: 0, output: results.join("\n") }
              }

              default:
                return { output: `Unknown action: ${input.action}. Supported: extract, unpack, strings, creds, entropy, emulate, all` }
            }
          }).pipe(Effect.mapError(() => new ToolFailure({ message: "Firmware analysis failed" }))),
      }),
    }).pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/firmware-analysis",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
