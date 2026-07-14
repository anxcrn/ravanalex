export * as DarkwebSearchTool from "./darkweb-search"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "darkweb_search"

export const Input = Schema.Struct({
  query: Schema.String.annotate({
    description: "Search query — email, username, phone, password, domain, or keyword to search for across dark web and breach sources.",
  }),
  action: Schema.String.annotate({
    description:
      "Search action: 'intelx' (Intelligence X), 'ahmia' (Ahmia .onion search engine), 'leakcheck' (leaked credential databases), 'pastebin' (paste site search), 'darksearch' (darksearch.io), 'onion_scan' (scan a .onion site), 'all' (search all available sources)",
  }),
  api_key: Schema.String.pipe(Schema.optional).annotate({
    description: "API key for services that require authentication (IntelX, LeakCheck, etc).",
  }),
  limit: Schema.Number.pipe(Schema.optional).annotate({
    description: "Maximum results. Default: 25.",
  }),
  target_onion: Schema.String.pipe(Schema.optional).annotate({
    description: ".onion URL for 'onion_scan' action.",
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
          description: `Search the dark web and breach databases for leaked credentials, data, and intelligence. Queries Intelligence X, Ahmia (.onion search), LeakCheck, paste sites, and darksearch.io. Can scan .onion websites for content. Requires Tor for direct .onion access. Essential for finding leaked passwords, breached accounts, and monitoring data exposures.`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"
              const limit = input.limit ?? 25

              switch (input.action) {
                case "intelx": {
                  if (!input.api_key) {
                    return {
                      output: "Intelligence X requires an API key. Get one at https://intelx.io\nFree tier: 10 searches/month.\n\nUsage:\nintelx --key YOUR_KEY --search \"" + input.query + "\"\n\nOr use the bash tool:\ncurl -s 'https://2.intelx.io/phonebook/view' -H 'x-key: YOUR_KEY' -d '\"term\":\"" + input.query + "\"'",
                    }
                  }
                  const cmd = ChildProcess.make(
                    "curl",
                    ["-s", "https://2.intelx.io/intelligent/search", "-H", `x-key: ${input.api_key}`, "-H", "Content-Type: application/json", "-d", `{"term":"${input.query}","maxresults":${limit}}`],
                    { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) },
                  )
                  const result = yield* appProcess
                    .run(cmd, { combineOutput: true, timeout: Duration.minutes(2), maxOutputBytes: 2 * 1024 * 1024 })
                    .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  return {
                    exit: result?.exitCode,
                    output: result?.output?.toString("utf8") ?? "IntelX search failed.",
                  }
                }

                case "ahmia": {
                  // Ahmia search engine for .onion sites (clearnet endpoint)
                  const cmd = ChildProcess.make(
                    "curl",
                    ["-s", `https://ahmia.fi/search/?q=${encodeURIComponent(input.query)}`],
                    { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) },
                  )
                  const result = yield* appProcess
                    .run(cmd, { combineOutput: true, timeout: Duration.minutes(2), maxOutputBytes: 2 * 1024 * 1024 })
                    .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  return {
                    exit: result?.exitCode,
                    output: result?.output?.toString("utf8") ?? "Ahmia search failed. Try installing Tor for direct .onion access.",
                  }
                }

                case "pastebin": {
                  // Search paste sites
                  const sites = [
                    `https://psbdmp.ws/api/search/${encodeURIComponent(input.query)}`,
                    `https://pastebin.com/u/${encodeURIComponent(input.query)}`,
                  ]
                  const results: string[] = []
                  for (const url of sites) {
                    const cmd = ChildProcess.make("curl", ["-s", url], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(5) })
                    const result = yield* appProcess
                      .run(cmd, { combineOutput: true, timeout: Duration.seconds(30), maxOutputBytes: 1024 * 1024 })
                      .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                    if (result?.output) {
                      results.push(`--- ${url} ---\n${result.output.toString("utf8")}`)
                    }
                  }
                  return {
                    exit: 0,
                    output: `=== PASTE SITE SEARCH: ${input.query} ===\n\n${results.join("\n\n")}\n\nAlso check:\n- pastebin.com/search?q=${encodeURIComponent(input.query)}\n- ghostbin.com\n- paste.debian.org\n- hastebin.com`,
                  }
                }

                case "leakcheck": {
                  if (!input.api_key) {
                    return {
                      output: `LeakCheck requires an API key from https://leakcheck.io\n\nAlternative free searches:\n- https://haveibeenpwned.com\n- https://breachdirectory.org\n- https://leakpeek.com\n\nDehashed (paid): https://dehashed.com\nSnusbase (paid): https://snusbase.com`,
                    }
                  }
                  const cmd = ChildProcess.make(
                    "curl",
                    ["-s", `https://leakcheck.io/api/query?query=${encodeURIComponent(input.query)}`, "-H", `X-API-Key: ${input.api_key}`],
                    { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) },
                  )
                  const result = yield* appProcess
                    .run(cmd, { combineOutput: true, timeout: Duration.minutes(2), maxOutputBytes: 2 * 1024 * 1024 })
                    .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  return {
                    exit: result?.exitCode,
                    output: result?.output?.toString("utf8") ?? "LeakCheck search failed.",
                  }
                }

                case "onion_scan": {
                  const target = input.target_onion ?? input.query
                  if (!target.endsWith(".onion")) {
                    return { output: "ERROR: target_onion must be a .onion URL for onion_scan action." }
                  }
                  const cmd = ChildProcess.make(
                    "onionscan",
                    ["--verbose", "--tor-proxy-address", "127.0.0.1:9050", target],
                    { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) },
                  )
                  const result = yield* appProcess
                    .run(cmd, { combineOutput: true, timeout: Duration.minutes(5), maxOutputBytes: 2 * 1024 * 1024 })
                    .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  return {
                    exit: result?.exitCode,
                    output: result?.output?.toString("utf8") ?? "OnionScan failed. Install: go install github.com/s-rah/onionscan@latest. Requires Tor running on 127.0.0.1:9050.",
                  }
                }

                case "all": {
                  // Aggregate results from multiple sources
                  const allResults: string[] = []
                  allResults.push(`=== DARK WEB & BREACH SEARCH: ${input.query} ===`)
                  allResults.push(``)
                  allResults.push(`Search these sources manually or with API keys:`)
                  allResults.push(``)
                  allResults.push(`[BREACH DATABASES]`)
                  allResults.push(`- IntelX: https://intelx.io (API key needed)`)
                  allResults.push(`- HaveIBeenPwned: https://haveibeenpwned.com`)
                  allResults.push(`- Dehashed: https://dehashed.com (paid)`)
                  allResults.push(`- LeakCheck: https://leakcheck.io`)
                  allResults.push(`- Snusbase: https://snusbase.com (paid)`)
                  allResults.push(`- BreachDirectory: https://breachdirectory.org`)
                  allResults.push(`- LeakPeek: https://leakpeek.com`)
                  allResults.push(``)
                  allResults.push(`[DARK WEB SEARCH ENGINES]`)
                  allResults.push(`- Ahmia: https://ahmia.fi/search/?q=${encodeURIComponent(input.query)}`)
                  allResults.push(`- Torch: http://torchdeedp3i2jigzjwmnpvqy3rlchmvyvqvecivityn2g5xjlhqkjvd.onion`)
                  allResults.push(`- Haystak: https://haystak5srjr3ldsrkqzhhm4xlnna5tjhtdcrmo4d5tlbwvtlrqzmqd.onion`)
                  allResults.push(`- DarkSearch: https://darksearch.io`)
                  allResults.push(`- OnionLand: https://onionland.io`)
                  allResults.push(``)
                  allResults.push(`[PASTE SITES]`)
                  allResults.push(`- Pastebin: https://pastebin.com/search?q=${encodeURIComponent(input.query)}`)
                  allResults.push(`- Psbdmp: https://psbdmp.ws/search?q=${encodeURIComponent(input.query)}`)
                  allResults.push(``)
                  allResults.push(`[TOR ACCESS]`)
                  allResults.push(`Ensure Tor is running: service tor start (Linux) or Tor Browser`)
                  allResults.push(`Configure SOCKS5 proxy: 127.0.0.1:9050`)
                  allResults.push(``)

                  // Try a quick automated search via Ahmia
                  const ahmiaCmd = ChildProcess.make("curl", ["-s", `-L`, `https://ahmia.fi/search/?q=${encodeURIComponent(input.query)}`], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) })
                  const ahmiaResult = yield* appProcess
                    .run(ahmiaCmd, { combineOutput: true, timeout: Duration.seconds(30), maxOutputBytes: 1024 * 1024 })
                    .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  if (ahmiaResult?.output) {
                    allResults.push(`[AHMIA RESULTS PREVIEW]`)
                    allResults.push(ahmiaResult.output.toString("utf8").substring(0, 2000))
                  }

                  return {
                    exit: 0,
                    output: allResults.join("\n"),
                  }
                }

                default:
                  return { output: `Unknown action: ${input.action}. Supported: intelx, ahmia, leakcheck, pastebin, darksearch, onion_scan, all` }
              }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "Dark web search failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/darkweb-search",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
