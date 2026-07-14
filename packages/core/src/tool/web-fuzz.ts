export * as WebFuzzTool from "./web-fuzz"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "web_fuzz"

export const Input = Schema.Struct({
  url: Schema.String.annotate({ description: "Target URL (e.g. https://target.com/FUZZ or https://target.com/?param=FUZZ)" }),
  action: Schema.String.pipe(Schema.optional).annotate({
    description:
      "Fuzzing action: 'path' (directory/path fuzzing, default), 'param' (parameter discovery), 'vhost' (virtual host fuzzing), 'method' (HTTP method fuzzing), 'header' (header fuzzing), 'subdomain' (subdomain fuzzing)",
  }),
  wordlist: Schema.String.pipe(Schema.optional).annotate({
    description: "Path to wordlist. Default depends on action type. Common: /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
  }),
  extensions: Schema.String.pipe(Schema.optional).annotate({
    description: "File extensions to append (e.g. 'php,html,txt,bak,sql,zip,json'). Comma-separated.",
  }),
  filter_code: Schema.String.pipe(Schema.optional).annotate({
    description: "Filter by HTTP status code (e.g. '200,204,301,302'). Use to show only successful responses.",
  }),
  hide_code: Schema.String.pipe(Schema.optional).annotate({
    description: "Hide specific status codes (e.g. '404').",
  }),
  threads: Schema.Number.pipe(Schema.optional).annotate({
    description: "Number of concurrent threads. Default: 40.",
  }),
  follow_redirects: Schema.Boolean.pipe(Schema.optional).annotate({
    description: "Follow HTTP redirects. Default: false.",
  }),
  recursive: Schema.Boolean.pipe(Schema.optional).annotate({
    description: "Enable recursive fuzzing (dive into found directories). Default: false.",
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
          description: `Web application fuzzing via ffuf (Fuzz Faster U Fool). Discovers hidden paths, parameters, virtual hosts, HTTP methods, and custom headers. Supports recursive directory fuzzing, file extension appending, status code filtering, and high-speed multi-threading. Essential for thorough web application enumeration beyond basic directory brute forcing.`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"
              const action = input.action ?? "path"
              const threads = input.threads ?? 40

              const args: string[] = ["-u", input.url, "-t", String(threads), "-ac"]

              // Wordlist selection based on action
              let defaultWordlist: string
              switch (action) {
                case "param":
                  defaultWordlist = "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"
                  break
                case "vhost":
                  defaultWordlist = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
                  break
                case "subdomain":
                  defaultWordlist = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
                  break
                case "method":
                  defaultWordlist = "" // special handling below
                  break
                case "header":
                  defaultWordlist = "/usr/share/seclists/Discovery/Web-Content/headers.txt"
                  break
                default:
                  defaultWordlist = "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
              }

              const wordlist = input.wordlist ?? defaultWordlist

              switch (action) {
                case "vhost":
                case "subdomain": {
                  args.push("-w", wordlist)
                  args.push("-H", `Host: FUZZ.${input.url.replace(/https?:\/\//, "").split("/")[0]}`)
                  break
                }
                case "method": {
                  args.push("-X", "GET,POST,PUT,DELETE,PATCH,OPTIONS,HEAD,TRACE")
                  break
                }
                case "header": {
                  args.push("-w", wordlist)
                  args.push("-H", "FUZZ: test")
                  break
                }
                case "param": {
                  args.push("-w", wordlist)
                  // URL should contain FUZZ marker as the parameter value
                  if (!input.url.includes("FUZZ")) {
                    args[args.indexOf("-u") + 1] = input.url + "/?FUZZ=test"
                  }
                  break
                }
                default: {
                  if (wordlist) args.push("-w", wordlist)
                }
              }

              if (input.extensions) args.push("-e", input.extensions)
              if (input.filter_code) args.push("-mc", input.filter_code)
              if (input.hide_code) args.push("-fc", input.hide_code)
              if (input.follow_redirects) args.push("-r")
              if (input.recursive) args.push("-recursion")

              const cmd = ChildProcess.make("ffuf", args, { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) })
              const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.minutes(20), maxOutputBytes: 5 * 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))

              if (!result) {
                return {
                  output: "ffuf not found. Install: go install github.com/ffuf/ffuf/v2@latest\nOr download from: https://github.com/ffuf/ffuf/releases\n\nDefault wordlists from: https://github.com/danielmiessler/SecLists",
                }
              }

              return {
                exit: result.exitCode,
                output: result.output?.toString("utf8") ?? "(no output)",
              }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "Web fuzzing failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/web-fuzz",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
