export * as ApkDecompileTool from "./apk-decompile"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "apk_decompile"

export const Input = Schema.Struct({
  apk_path: Schema.String.annotate({ description: "Path to the APK file to decompile/analyze." }),
  action: Schema.String.annotate({
    description:
      "Action: 'decompile' (full decompile via jadx), 'decode' (decode resources via apktool), 'manifest' (extract AndroidManifest.xml), 'permissions' (list permissions), 'secrets' (find hardcoded secrets/API keys), 'urls' (extract hardcoded URLs/endpoints), 'all' (run everything)",
  }),
  output_dir: Schema.String.pipe(Schema.optional).annotate({
    description: "Output directory for decompiled files. Default: ./apk-output/",
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
          description: `Decompile and analyze Android APK files. Extracts Java source code (via jadx), decodes resources (via apktool), extracts AndroidManifest.xml, lists permissions, finds hardcoded secrets (API keys, passwords, tokens), and extracts hardcoded URLs/API endpoints. Essential for mobile app security testing and reverse engineering.`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"
              const outputDir = input.output_dir ?? "./apk-output"
              const results: string[] = []

              switch (input.action) {
                case "decompile": {
                  const cmd = ChildProcess.make(
                    "jadx",
                    ["-d", outputDir, input.apk_path],
                    { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) },
                  )
                  const result = yield* appProcess
                    .run(cmd, { combineOutput: true, timeout: Duration.minutes(10), maxOutputBytes: 5 * 1024 * 1024 })
                    .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  return {
                    exit: result?.exitCode,
                    output: result?.output?.toString("utf8") ?? "jadx failed. Install: https://github.com/skylot/jadx/releases",
                  }
                }

                case "decode": {
                  const cmd = ChildProcess.make(
                    "apktool",
                    ["d", input.apk_path, "-o", outputDir, "-f"],
                    { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) },
                  )
                  const result = yield* appProcess
                    .run(cmd, { combineOutput: true, timeout: Duration.minutes(10), maxOutputBytes: 5 * 1024 * 1024 })
                    .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  return {
                    exit: result?.exitCode,
                    output: result?.output?.toString("utf8") ?? "apktool failed. Install: https://ibotpeaches.github.io/Apktool/install/",
                  }
                }

                case "manifest": {
                  // Use aapt or apktool to extract manifest
                  const cmd = ChildProcess.make(
                    "aapt",
                    ["dump", "xmltree", input.apk_path, "AndroidManifest.xml"],
                    { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) },
                  )
                  const result = yield* appProcess
                    .run(cmd, { combineOutput: true, timeout: Duration.minutes(2), maxOutputBytes: 2 * 1024 * 1024 })
                    .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  return {
                    exit: result?.exitCode,
                    output: result?.output?.toString("utf8") ?? "aapt failed. Try: apktool d " + input.apk_path,
                  }
                }

                case "permissions": {
                  const cmd = ChildProcess.make(
                    "aapt",
                    ["dump", "permissions", input.apk_path],
                    { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) },
                  )
                  const result = yield* appProcess
                    .run(cmd, { combineOutput: true, timeout: Duration.minutes(2), maxOutputBytes: 1024 * 1024 })
                    .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  return {
                    exit: result?.exitCode,
                    output: result?.output?.toString("utf8") ?? "Failed to extract permissions.",
                  }
                }

                case "secrets":
                case "urls": {
                  // First decompile, then search
                  const jadxCmd = ChildProcess.make(
                    "jadx",
                    ["-d", outputDir, input.apk_path, "--no-res"],
                    { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) },
                  )
                  yield* appProcess
                    .run(jadxCmd, { combineOutput: true, timeout: Duration.minutes(10), maxOutputBytes: 5 * 1024 * 1024 })
                    .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))

                  if (input.action === "secrets") {
                    // Search for hardcoded secrets
                    const patterns = [
                      "api_key", "apikey", "api-key", "API_KEY",
                      "secret", "password", "passwd", "pwd",
                      "token", "Bearer", "Authorization",
                      "AWS_ACCESS_KEY", "aws_secret",
                      "firebase", "google_api",
                      "private_key", "BEGIN RSA",
                      "oauth", "client_secret",
                    ]
                    let allMatches = ""
                    for (const pattern of patterns) {
                      const grepCmd = ChildProcess.make(
                        "grep",
                        ["-rn", "-i", pattern, outputDir],
                        { shell, stdin: "ignore", forceKillAfter: Duration.seconds(5) },
                      )
                      const grepResult = yield* appProcess
                        .run(grepCmd, { combineOutput: true, timeout: Duration.minutes(2), maxOutputBytes: 2 * 1024 * 1024 })
                        .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                      if (grepResult?.output) {
                        allMatches += grepResult.output.toString("utf8")
                      }
                    }
                    return {
                      exit: 0,
                      output: `=== HARDCODED SECRETS FOUND ===\n\n${allMatches || "No obvious secrets found. Try manual analysis of decompiled source."}`,
                    }
                  } else {
                    // Search for URLs
                    const grepCmd = ChildProcess.make(
                      "bash",
                      ["-c", `grep -rEoh "https?://[^\"' >]+" ${outputDir} | sort -u`],
                      { shell, stdin: "ignore", forceKillAfter: Duration.seconds(5) },
                    )
                    const grepResult = yield* appProcess
                      .run(grepCmd, { combineOutput: true, timeout: Duration.minutes(2), maxOutputBytes: 2 * 1024 * 1024 })
                      .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                    return {
                      exit: 0,
                      output: `=== HARDCODED URLS FOUND ===\n\n${grepResult?.output?.toString("utf8") ?? "No URLs found."}`,
                    }
                  }
                }

                case "all": {
                  // Run everything
                  results.push("=== FULL APK ANALYSIS ===")
                  results.push(`APK: ${input.apk_path}`)
                  results.push(`Output: ${outputDir}`)
                  results.push("")

                  // Decompile
                  const jadxCmd = ChildProcess.make("jadx", ["-d", outputDir, input.apk_path], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) })
                  const jadxResult = yield* appProcess.run(jadxCmd, { combineOutput: true, timeout: Duration.minutes(10), maxOutputBytes: 5 * 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  results.push("--- DECOMPILE ---")
                  results.push(jadxResult?.output?.toString("utf8") ?? "Failed")

                  // Permissions
                  const permCmd = ChildProcess.make("aapt", ["dump", "permissions", input.apk_path], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) })
                  const permResult = yield* appProcess.run(permCmd, { combineOutput: true, timeout: Duration.minutes(2), maxOutputBytes: 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  results.push("\n--- PERMISSIONS ---")
                  results.push(permResult?.output?.toString("utf8") ?? "Failed")

                  // Secrets
                  const secCmd = ChildProcess.make("bash", ["-c", `grep -rniE "(api_key|secret|password|token|bearer|firebase|private_key)" ${outputDir} | head -50`], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(5) })
                  const secResult = yield* appProcess.run(secCmd, { combineOutput: true, timeout: Duration.minutes(2), maxOutputBytes: 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  results.push("\n--- POTENTIAL SECRETS ---")
                  results.push(secResult?.output?.toString("utf8") ?? "None found")

                  // URLs
                  const urlCmd = ChildProcess.make("bash", ["-c", `grep -rEoh "https?://[^\"' >]+" ${outputDir} | sort -u | head -30`], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(5) })
                  const urlResult = yield* appProcess.run(urlCmd, { combineOutput: true, timeout: Duration.minutes(2), maxOutputBytes: 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  results.push("\n--- URLS ---")
                  results.push(urlResult?.output?.toString("utf8") ?? "None found")

                  return {
                    exit: 0,
                    output: results.join("\n"),
                  }
                }

                default:
                  return { output: `Unknown action: ${input.action}. Supported: decompile, decode, manifest, permissions, secrets, urls, all` }
              }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "APK decompile failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/apk-decompile",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
