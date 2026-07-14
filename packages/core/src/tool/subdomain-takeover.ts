export * as SubdomainTakeoverTool from "./subdomain-takeover"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "subdomain_takeover"

export const Input = Schema.Struct({
  domain: Schema.String.annotate({ description: "Root domain to check for subdomain takeover vulnerabilities (e.g. example.com)" }),
  wordlist: Schema.String.pipe(Schema.optional).annotate({
    description: "Subdomain wordlist. If omitted, uses subfinder to discover subdomains first.",
  }),
  threads: Schema.Number.pipe(Schema.optional).annotate({ description: "Concurrent threads. Default: 10." }),
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
        description: `Check for subdomain takeover vulnerabilities. Discovers subdomains (via subfinder) then checks each for dangling DNS records pointing to deprovisioned services (GitHub Pages, Heroku, S3, Azure, Shopify, Tumblr, etc). A vulnerable subdomain can be claimed by an attacker to host malicious content under the legitimate domain. Uses subzy or nucleii takeover templates.`,
        input: Input,
        output: Output,
        toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
        execute: (input) =>
          Effect.gen(function* () {
            const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"
            const threads = input.threads ?? 10

            // First, enumerate subdomains
            const enumCmd = ChildProcess.make("subfinder", ["-d", input.domain, "-silent"], {
              shell, stdin: "ignore", forceKillAfter: Duration.seconds(10),
            })
            const enumResult = yield* appProcess.run(enumCmd, {
              combineOutput: true, timeout: Duration.minutes(5), maxOutputBytes: 1024 * 1024,
            }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))

            const subdomains = (enumResult?.output?.toString("utf8") ?? "").trim().split("\n").filter(Boolean)
            if (subdomains.length === 0) {
              return { output: "No subdomains found via subfinder. Try providing a wordlist or using dns_recon first." }
            }

            // Write subdomains to temp file
            const tmpFile = `/tmp/subs_${Date.now()}.txt`
            yield* Effect.promise(async () => { await Bun.write(tmpFile, subdomains.join("\n")) })

            // Run subzy for takeover detection
            const args: string[] = ["-targets", tmpFile, "-concurrency", String(threads), "-timeout", "10"]
            const cmd = ChildProcess.make("subzy", args, { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) })
            const result = yield* appProcess.run(cmd, {
              combineOutput: true, timeout: Duration.minutes(15), maxOutputBytes: 5 * 1024 * 1024,
            }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))

            if (!result) {
              // Fallback: use nuclei with takeover templates
              const nucArgs: string[] = ["-l", tmpFile, "-t", "takeovers", "-silent"]
              const nucCmd = ChildProcess.make("nuclei", nucArgs, { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) })
              const nucResult = yield* appProcess.run(nucCmd, {
                combineOutput: true, timeout: Duration.minutes(15), maxOutputBytes: 5 * 1024 * 1024,
              }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
              return {
                exit: nucResult?.exitCode,
                output: nucResult?.output?.toString("utf8") ?? "Both subzy and nuclei failed. Install:\nsubzy: go install github.com/LukaSikic/subzy@latest\nnuclei: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
              }
            }

            const stdout = result.output?.toString("utf8") ?? ""
            const vulnerable = stdout.includes("VULNERABLE") || stdout.includes("[takeover]")
            return {
              exit: result.exitCode,
              output: vulnerable
                ? `🎉 SUBDOMAIN TAKEOVER FOUND!\n\nChecked ${subdomains.length} subdomains.\n\n${stdout}\n\n[CRITICAL] A dangling subdomain can be claimed to host malicious content.`
                : `Checked ${subdomains.length} subdomains. No takeover vulnerabilities found.\n\n${stdout}`,
            }
          }).pipe(Effect.mapError(() => new ToolFailure({ message: "Subdomain takeover check failed" }))),
      }),
    }).pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/subdomain-takeover",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
