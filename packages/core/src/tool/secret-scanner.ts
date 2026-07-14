export * as SecretScannerTool from "./secret-scanner"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "secret_scanner"

export const Input = Schema.Struct({
  target: Schema.String.pipe(Schema.optional).annotate({
    description: "Target URL or domain. Scans the site's JS files, source code, and responses for leaked secrets.",
  }),
  path: Schema.String.pipe(Schema.optional).annotate({
    description: "Local directory or file to scan for hardcoded secrets (e.g. ./decompiled-apk/ or /tmp/source/).",
  }),
  action: Schema.String.pipe(Schema.optional).annotate({
    description: "Scan type: 'local' (scan local files/directory), 'web' (crawl URL and scan JS), 'github' (search GitHub repos for target secrets), 'all' (run everything available)",
  }),
  github_query: Schema.String.pipe(Schema.optional).annotate({
    description: "GitHub search query for 'github' action (e.g. 'target.com password OR secret OR token OR api_key').",
  }),
})

const Output = Schema.Struct({
  output: Schema.String,
  exit: Schema.Number.pipe(Schema.optional),
})

const SECRET_PATTERNS: Array<{ name: string; regex: string; severity: string }> = [
  { name: "AWS Access Key", regex: "AKIA[0-9A-Z]{16}", severity: "CRITICAL" },
  { name: "AWS Secret Key", regex: "(?i)aws_secret_access_key.{0,20}['\"][A-Za-z0-9/+=]{40}['\"]", severity: "CRITICAL" },
  { name: "Google API Key", regex: "AIza[0-9A-Za-z_\\-]{35}", severity: "CRITICAL" },
  { name: "Stripe Secret Key", regex: "sk_live_[0-9a-zA-Z]{24}", severity: "CRITICAL" },
  { name: "Stripe Publishable", regex: "pk_live_[0-9a-zA-Z]{24}", severity: "HIGH" },
  { name: "GitHub Token", regex: "gh[pousr]_[0-9A-Za-z]{36}", severity: "CRITICAL" },
  { name: "Slack Token", regex: "xox[baprs]-[0-9A-Za-z-]{10,}", severity: "CRITICAL" },
  { name: "Slack Webhook", regex: "https://hooks.slack.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+", severity: "HIGH" },
  { name: "Generic API Key", regex: "(?i)api[_-]?key.{0,20}['\"][A-Za-z0-9_\\-]{20,}['\"]", severity: "HIGH" },
  { name: "Generic Secret", regex: "(?i)secret.{0,20}['\"][A-Za-z0-9_\\-]{20,}['\"]", severity: "HIGH" },
  { name: "Generic Password", regex: "(?i)(pass(word)?|passwd|pwd).{0,20}['\"][^'\"\\s]{8,}['\"]", severity: "HIGH" },
  { name: "Generic Token", regex: "(?i)token.{0,20}['\"][A-Za-z0-9_\\-\\.]{20,}['\"]", severity: "HIGH" },
  { name: "Bearer Token", regex: "Bearer\\s+[A-Za-z0-9_\\-\\.]{20,}", severity: "MEDIUM" },
  { name: "JWT Token", regex: "eyJ[A-Za-z0-9_\\-]+\\.eyJ[A-Za-z0-9_\\-]+\\.[A-Za-z0-9_\\-]*", severity: "MEDIUM" },
  { name: "Private Key", regex: "-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----", severity: "CRITICAL" },
  { name: "Database URL", regex: "(postgres|mysql|mongodb|redis)://[^:\\s]+:[^@\\s]+@[A-Za-z0-9.\\-]+:\\d+", severity: "CRITICAL" },
  { name: "Firebase URL", regex: "https://[A-Za-z0-9\\-]+\\.firebaseio\\.com", severity: "HIGH" },
  { name: "Firebase Config", regex: "(?i)firebase.{0,100}(apiKey|databaseURL|projectId)", severity: "MEDIUM" },
  { name: "Twilio SID", regex: "AC[a-z0-9]{32}", severity: "HIGH" },
  { name: "Twilio Token", regex: "(?i)twilio.{0,30}['\"][A-Za-z0-9]{32}['\"]", severity: "HIGH" },
  { name: "Mailgun API", regex: "key-[0-9a-zA-Z]{32}", severity: "HIGH" },
  { name: "SendGrid API", regex: "SG\\.[A-Za-z0-9_\\-]{22}\\.[A-Za-z0-9_\\-]{43}", severity: "HIGH" },
  { name: "PayPal Client ID", regex: "(?i)client_id.{0,20}['\"]A[A-Za-z0-9]{80}['\"]", severity: "HIGH" },
  { name: "Mailchimp API", regex: "[0-9a-f]{32}-us[0-9]{1,2}", severity: "MEDIUM" },
  { name: "Discord Webhook", regex: "https://discord(?:app)?\\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\\-]+", severity: "HIGH" },
  { name: "Heroku API Key", regex: "(?i)heroku.{0,30}['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]", severity: "HIGH" },
]

const layer = Layer.effectDiscard(
  Effect.gen(function* () {
    const tools = yield* Tools.Service
    const appProcess = yield* AppProcess.Service

    yield* tools.register({
      [name]: Tool.make({
        description: `Scan for hardcoded secrets and credentials in source code, web applications, and GitHub repositories. Detects AWS keys, Google API keys, Stripe keys, GitHub tokens, Slack tokens, JWTs, private keys, database URLs, Firebase configs, Twilio/SendGrid/Mailgun keys, and 25+ other secret types. Scans local files, crawls web app JS bundles, and queries GitHub code search. Essential for finding leaked credentials during recon.`,
        input: Input,
        output: Output,
        toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
        execute: (input) =>
          Effect.gen(function* () {
            const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"
            const action = input.action ?? (input.path ? "local" : input.target ? "web" : "github")
            const results: string[] = [`=== SECRET SCAN ===`]
            let totalFound = 0

            function scanContent(content: string, source: string): number {
              let found = 0
              for (const pattern of SECRET_PATTERNS) {
                const regex = new RegExp(pattern.regex, "g")
                const matches = content.match(regex)
                if (matches) {
                  for (const match of matches) {
                    // Mask the secret partially
                    const masked = match.length > 20 ? match.substring(0, 10) + "...[REDACTED]..." + match.substring(match.length - 4) : "...[REDACTED]..."
                    results.push(`[${pattern.severity}] ${pattern.name}: ${masked}`)
                    results.push(`  Source: ${source}`)
                    results.push(`  Full match length: ${match.length} chars`)
                    results.push("")
                    found++
                  }
                }
              }
              return found
            }

            if (action === "local" || action === "all") {
              const scanPath = input.path ?? "."
              results.push(`--- LOCAL FILE SCAN: ${scanPath} ---`)
              // Use grep with all patterns
              for (const pattern of SECRET_PATTERNS) {
                const cmd = ChildProcess.make(
                  "grep",
                  ["-rnE", pattern.regex, scanPath, "--include=*.js", "--include=*.ts", "--include=*.py", "--include=*.java", "--include=*.go", "--include=*.rb", "--include=*.php", "--include=*.env", "--include=*.json", "--include=*.yml", "--include=*.yaml", "--include=*.xml", "--include=*.conf", "--include=*.cfg", "--include=*.properties", "--include=*.txt", "--include=*.html", "--include=*.smali"],
                  { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) },
                )
                const result = yield* appProcess.run(cmd, {
                  combineOutput: true, timeout: Duration.minutes(2), maxOutputBytes: 2 * 1024 * 1024,
                }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                if (result?.output) {
                  const lines = result.output.toString("utf8").trim().split("\n").filter(Boolean)
                  for (const line of lines) {
                    results.push(`[${pattern.severity}] ${pattern.name}: ${line.substring(0, 200)}`)
                    totalFound++
                  }
                }
              }
              results.push("")
            }

            if (action === "web" || action === "all") {
              const target = input.target ?? input.path ?? ""
              if (!target) {
                results.push("--- WEB SCAN: no target provided ---")
              } else {
                results.push(`--- WEB SCAN: ${target} ---`)
                // Fetch the page and look for JS files
                const cmd = ChildProcess.make("curl", ["-s", target], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) })
                const result = yield* appProcess.run(cmd, {
                  combineOutput: true, timeout: Duration.seconds(30), maxOutputBytes: 5 * 1024 * 1024,
                }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                const html = result?.output?.toString("utf8") ?? ""

                // Scan HTML directly
                totalFound += scanContent(html, target)

                // Find JS files
                const jsUrls = html.match(/src=["']([^"']*\.js[^"']*)["']/g) || []
                results.push(`Found ${jsUrls.length} JS files to scan`)

                for (const jsSrc of jsUrls.slice(0, 20)) {
                  const jsUrl = jsSrc.match(/src=["']([^"']*)["']/)?.[1] ?? ""
                  if (!jsUrl) continue
                  const fullUrl = jsUrl.startsWith("http") ? jsUrl : jsUrl.startsWith("//") ? "https:" + jsUrl : new URL(jsUrl, target).href
                  const jsCmd = ChildProcess.make("curl", ["-s", fullUrl], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(5) })
                  const jsResult = yield* appProcess.run(jsCmd, {
                    combineOutput: true, timeout: Duration.seconds(15), maxOutputBytes: 5 * 1024 * 1024,
                  }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  if (jsResult?.output) {
                    totalFound += scanContent(jsResult.output.toString("utf8"), fullUrl)
                  }
                }
                results.push("")
              }
            }

            if (action === "github" || action === "all") {
              results.push("--- GITHUB SECRET SEARCH ---")
              const query = input.github_query ?? (input.target ? `"${input.target.replace(/^https?:\/\//, "").split("/")[0]}" password OR secret OR token OR api_key OR apikey OR access_key OR private_key` : "")
              const cmd = ChildProcess.make(
                "curl",
                ["-s", `https://api.github.com/search/code?q=${encodeURIComponent(query)}&per_page=20`],
                { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) },
              )
              const result = yield* appProcess.run(cmd, {
                combineOutput: true, timeout: Duration.minutes(2), maxOutputBytes: 2 * 1024 * 1024,
              }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
              const output = result?.output?.toString("utf8") ?? ""
              try {
                const data = JSON.parse(output)
                if (data.items) {
                  results.push(`Found ${data.total_count} GitHub results:`)
                  for (const item of data.items.slice(0, 20)) {
                    results.push(`[GITHUB] ${item.repository.full_name}/${item.name}:${item.line_count ?? "?"} lines`)
                    results.push(`  URL: ${item.html_url}`)
                  }
                }
              } catch {
                results.push("GitHub API rate limited or error. Try with authenticated request.")
                results.push(output.substring(0, 500))
              }
              results.push("")
            }

            results.push("=== SUMMARY ===")
            results.push(`Total secrets found: ${totalFound}`)
            const criticalCount = results.filter(r => r.includes("[CRITICAL]")).length
            const highCount = results.filter(r => r.includes("[HIGH]")).length
            results.push(`Critical: ${criticalCount}, High: ${highCount}`)

            return { exit: 0, output: results.join("\n") }
          }).pipe(Effect.mapError(() => new ToolFailure({ message: "Secret scan failed" }))),
      }),
    }).pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/secret-scanner",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
