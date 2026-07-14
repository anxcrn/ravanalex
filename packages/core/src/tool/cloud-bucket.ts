export * as CloudBucketTool from "./cloud-bucket"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "cloud_bucket"

export const Input = Schema.Struct({
  provider: Schema.String.annotate({
    description: "Cloud provider: 'aws' (S3), 'gcp' (GCS), 'azure' (Blob Storage)",
  }),
  bucket_name: Schema.String.pipe(Schema.optional).annotate({
    description: "Specific bucket name to check. If omitted, generates permutations from the domain.",
  }),
  domain: Schema.String.pipe(Schema.optional).annotate({
    description: "Domain to derive bucket names from (e.g. example.com generates example, example-backup, etc.)",
  }),
  action: Schema.String.pipe(Schema.optional).annotate({
    description: "Action: 'check' (check read/write permissions, default), 'enum' (enumerate bucket contents), 'list' (list all objects), 'upload' (test write access by uploading a test file)",
  }),
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
        description: `Check cloud storage buckets (AWS S3, Google Cloud Storage, Azure Blob) for misconfigurations. Tests for anonymous read/write access, enumerates bucket contents, and generates bucket name permutations from a domain. Finds exposed backups, databases, credentials, and PII in misconfigured cloud storage. Essential for cloud security assessment.`,
        input: Input,
        output: Output,
        toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
        execute: (input) =>
          Effect.gen(function* () {
            const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"
            const action = input.action ?? "check"

            // Generate bucket name permutations if domain provided
            let bucketNames: string[] = []
            if (input.bucket_name) {
              bucketNames = [input.bucket_name]
            } else if (input.domain) {
              const d = input.domain.replace(/^https?:\/\//, "").split("/")[0].replace(/^www\./, "")
              const base = d.split(".")[0]
              bucketNames = [
                d, base, `${base}-backup`, `${base}-backups`, `${base}-uploads`, `${base}-files`,
                `${base}-media`, `${base}-images`, `${base}-assets`, `${base}-static`,
                `${base}-storage`, `${base}-data`, `${base}-db`, `${base}-database`,
                `${base}-logs`, `${base}-temp`, `${base}-test`, `${base}-dev`,
                `${base}-prod`, `${base}-staging`, `${base}-private`, `${base}-public`,
                `${base}-screenshots`, `${base}-documents`, `${base}-downloads`,
                d.replace(/\./g, "-"), `${d.replace(/\./g, "")}`,
                `${base}backup`, `${base}_backup`, `${base}.backup`,
              ]
            } else {
              return { output: "ERROR: Provide either 'bucket_name' or 'domain'." }
            }

            const results: string[] = [`=== CLOUD STORAGE AUDIT (${input.provider}) ===`, `Checking ${bucketNames.length} bucket permutations\n`]

            for (const bucket of bucketNames) {
              if (input.provider === "aws") {
                // Check S3 bucket
                const url = `https://${bucket}.s3.amazonaws.com`
                const cmd = ChildProcess.make("curl", ["-s", "-o", "/dev/null", "-w", "%{http_code}", url], {
                  shell, stdin: "ignore", forceKillAfter: Duration.seconds(5),
                })
                const result = yield* appProcess.run(cmd, {
                  combineOutput: true, timeout: Duration.seconds(15), maxOutputBytes: 64 * 1024,
                }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))

                const code = result?.output?.toString("utf8").trim() ?? "000"

                if (code === "200" || code === "403") {
                  // Bucket exists — check if listable
                  const listCmd = ChildProcess.make("curl", ["-s", `https://${bucket}.s3.amazonaws.com/?list-type=2`], {
                    shell, stdin: "ignore", forceKillAfter: Duration.seconds(5),
                  })
                  const listResult = yield* appProcess.run(listCmd, {
                    combineOutput: true, timeout: Duration.seconds(15), maxOutputBytes: 512 * 1024,
                  }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  const listOutput = listResult?.output?.toString("utf8") ?? ""
                  const listable = listOutput.includes("<Key>") || listOutput.includes("<Contents")
                  const access = listable ? "PUBLIC READ + LIST" : code === "200" ? "PUBLIC READ" : "EXISTS (denied)"

                  if (listable) {
                    // Count objects
                    const objCount = (listOutput.match(/<Key>/g) || []).length
                    results.push(`[VULNERABLE] s3://${bucket} — ${access} — ${objCount} objects visible!`)
                    if (action === "enum" || action === "list") {
                      results.push(`  Contents preview:\n${listOutput.substring(0, 2000)}`)
                    }
                    // Test write
                    const writeCmd = ChildProcess.make("curl", ["-s", "-X", "PUT", "-d", "test", `https://${bucket}.s3.amazonaws.com/opencode_test_${Date.now()}.txt`], {
                      shell, stdin: "ignore", forceKillAfter: Duration.seconds(5),
                    })
                    const writeResult = yield* appProcess.run(writeCmd, {
                      combineOutput: true, timeout: Duration.seconds(15), maxOutputBytes: 64 * 1024,
                    }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                    if (writeResult?.output?.toString("utf8").includes("OK") || !writeResult?.output?.toString("utf8").includes("AccessDenied")) {
                      results.push(`  [CRITICAL] WRITE ACCESS — bucket accepts uploads!`)
                    }
                  } else {
                    results.push(`[INFO] s3://${bucket} — ${access}`)
                  }
                }
              } else if (input.provider === "gcp") {
                const url = `https://storage.googleapis.com/${bucket}/`
                const cmd = ChildProcess.make("curl", ["-s", "-o", "/dev/null", "-w", "%{http_code}", url], {
                  shell, stdin: "ignore", forceKillAfter: Duration.seconds(5),
                })
                const result = yield* appProcess.run(cmd, {
                  combineOutput: true, timeout: Duration.seconds(15), maxOutputBytes: 64 * 1024,
                }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                const code = result?.output?.toString("utf8").trim() ?? "000"
                if (code === "200") {
                  results.push(`[VULNERABLE] gs://${bucket} — PUBLIC ACCESS!`)
                }
              } else if (input.provider === "azure") {
                const url = `https://${bucket}.blob.core.windows.net/?restype=container&comp=list`
                const cmd = ChildProcess.make("curl", ["-s", url], {
                  shell, stdin: "ignore", forceKillAfter: Duration.seconds(5),
                })
                const result = yield* appProcess.run(cmd, {
                  combineOutput: true, timeout: Duration.seconds(15), maxOutputBytes: 512 * 1024,
                }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                const output = result?.output?.toString("utf8") ?? ""
                if (output.includes("<Blob>")) {
                  results.push(`[VULNERABLE] azure://${bucket} — PUBLIC LIST ACCESS!`)
                }
              }
            }

            const vulnCount = results.filter(r => r.includes("[VULNERABLE]")).length
            results.push(`\n=== SUMMARY ===`)
            results.push(`Checked: ${bucketNames.length} buckets`)
            results.push(`Vulnerable: ${vulnCount}`)

            return { exit: 0, output: results.join("\n") }
          }).pipe(Effect.mapError(() => new ToolFailure({ message: "Cloud bucket check failed" }))),
      }),
    }).pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/cloud-bucket",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
