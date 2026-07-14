export * as CorsTestTool from "./cors-test"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "cors_test"

export const Input = Schema.Struct({
  url: Schema.String.annotate({ description: "Target URL to test for CORS misconfiguration" }),
  origin: Schema.String.pipe(Schema.optional).annotate({
    description: "Origin to test. Default: https://evil.com. Try your own domain for reflection tests.",
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
        description: `Test for CORS (Cross-Origin Resource Sharing) misconfigurations. Checks if the target reflects arbitrary origins, allows null origin, allows wildcard with credentials, or reflects subdomains. A vulnerable CORS policy allows attackers to read authenticated responses cross-origin from a malicious site. Tests multiple attack vectors: arbitrary origin reflection, null origin, subdomain wildcard, and regex bypass.`,
        input: Input,
        output: Output,
        toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
        execute: (input) =>
          Effect.gen(function* () {
            const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"
            const origins = [
              input.origin ?? "https://evil.com",
              "null",
              "https://evil.com",
              `https://${new URL(input.url).hostname}.evil.com`,
              `https://evil.${new URL(input.url).hostname}`,
              "https://subdomain.evil.com",
              "http://localhost",
              "https://target.com.evil.com",
            ]

            const results: string[] = [`=== CORS MISCONFIGURATION TEST ===`, `Target: ${input.url}`, ""]

            for (const origin of origins) {
              const cmd = ChildProcess.make(
                "curl",
                ["-s", "-D", "-", "-o", "/dev/null", "-H", `Origin: ${origin}`, input.url],
                { shell, stdin: "ignore", forceKillAfter: Duration.seconds(5) },
              )
              const result = yield* appProcess.run(cmd, {
                combineOutput: true, timeout: Duration.seconds(15), maxOutputBytes: 64 * 1024,
              }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))

              const headers = result?.output?.toString("utf8") ?? ""
              const acao = headers.match(/access-control-allow-origin:\s*(.+)/i)?.[1]?.trim()
              const acac = headers.match(/access-control-allow-credentials:\s*(.+)/i)?.[1]?.trim()

              if (acao && (acao === origin || acao === "*" && acac === "true")) {
                results.push(`[VULNERABLE] Origin: ${origin}`)
                results.push(`  ACAO: ${acao}`)
                results.push(`  ACAC: ${acac ?? "not set"}`)
                if (acac === "true" || acao === origin) {
                  results.push(`  [CRITICAL] Reflected origin ${acac === "true" ? "WITH credentials" : ""} — full CORS exploit possible!`)
                  results.push(`  Exploit: A malicious page can make authenticated requests and read responses.`)
                }
              } else if (acao) {
                results.push(`[INFO] Origin: ${origin} → ACAO: ${acao} (not exploitable with this origin)`)
              }
            }

            const vulnCount = results.filter(r => r.includes("[VULNERABLE]")).length
            results.push("")
            results.push(`=== SUMMARY ===`)
            results.push(`Origins tested: ${origins.length}`)
            results.push(`Vulnerable: ${vulnCount}`)

            if (vulnCount > 0) {
              results.push("\n[CRITICAL] CORS misconfiguration found! An attacker can read authenticated cross-origin responses.")
            }

            return { exit: 0, output: results.join("\n") }
          }).pipe(Effect.mapError(() => new ToolFailure({ message: "CORS test failed" }))),
      }),
    }).pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/cors-test",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
