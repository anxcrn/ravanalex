export * as WpScanTool from "./wpscan"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "wpscan"

export const Input = Schema.Struct({
  url: Schema.String.annotate({ description: "WordPress site URL (e.g. https://target.com)" }),
  action: Schema.String.pipe(Schema.optional).annotate({
    description:
      "Scan type: 'all' (full scan, default), 'enumerate_users' (find usernames), 'enumerate_plugins' (find plugins), 'enumerate_themes' (find themes), 'enumerate_timthumbs', 'enumerate_media', 'password_spray' (brute force login), 'aggressive' (aggressive plugin detection)",
  }),
  api_token: Schema.String.pipe(Schema.optional).annotate({
    description: "WPScan API token from wpscan.com for vulnerability database access (free tier available).",
  }),
  usernames: Schema.String.pipe(Schema.optional).annotate({
    description: "Username or wordlist path for password_spray action.",
  }),
  passwords: Schema.String.pipe(Schema.optional).annotate({
    description: "Password wordlist for password_spray. Default: /usr/share/wordlists/rockyou.txt",
  }),
  threads: Schema.Number.pipe(Schema.optional).annotate({
    description: "Number of threads. Default: 5.",
  }),
  disable_tls_check: Schema.Boolean.pipe(Schema.optional).annotate({
    description: "Disable TLS certificate verification. Default: false.",
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
          description: `WordPress security scanner. Enumerates WordPress core version, plugins, themes, users, and media. Detects known vulnerabilities in detected components. Supports password spraying against wp-login.php and XML-RPC. Requires WPScan API token (free) for vulnerability database. Essential for WordPress-targeted assessments.`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const action = input.action ?? "all"
              const threads = input.threads ?? 5
              const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"

              const args: string[] = ["--url", input.url, "--threads", String(threads), "--format", "json"]

              if (input.disable_tls_check) args.push("--disable-tls-checks")
              if (input.api_token) args.push("--api-token", input.api_token)

              switch (action) {
                case "enumerate_users":
                  args.push("--enumerate", "u")
                  break
                case "enumerate_plugins":
                  args.push("--enumerate", "vp") // vulnerable plugins
                  break
                case "enumerate_themes":
                  args.push("--enumerate", "vt") // vulnerable themes
                  break
                case "enumerate_timthumbs":
                  args.push("--enumerate", "tt")
                  break
                case "enumerate_media":
                  args.push("--enumerate", "m")
                  break
                case "aggressive":
                  args.push("--enumerate", "ap", "--plugins-detection", "aggressive")
                  break
                case "password_spray": {
                  if (!input.usernames) return { output: "ERROR: 'usernames' required for password_spray." }
                  const passList = input.passwords ?? "/usr/share/wordlists/rockyou.txt"
                  args.push("--passwords", passList, "--usernames", input.usernames, "--max-threads", String(threads))
                  break
                }
                case "all":
                default:
                  args.push("--enumerate", "vp,vt,u,m,t,d") // all enumeration
                  break
              }

              const cmd = ChildProcess.make("wpscan", args, {
                shell,
                stdin: "ignore",
                forceKillAfter: Duration.seconds(15),
              })

              const result = yield* appProcess
                .run(cmd, {
                  combineOutput: true,
                  timeout: Duration.minutes(20),
                  maxOutputBytes: 5 * 1024 * 1024,
                })
                .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))

              if (!result) {
                return {
                  output: "WPScan failed or not installed. Install: gem install wpscan (needs Ruby). Or via Docker: docker run --rm wpscanteam/wpscan --url " + input.url,
                }
              }

              return {
                exit: result.exitCode,
                output: result.output?.toString("utf8") ?? "(no output)",
              }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "WPScan failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/wpscan",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
