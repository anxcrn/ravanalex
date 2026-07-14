export * as DnsReconTool from "./dns-recon"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "dns_recon"

export const Input = Schema.Struct({
  domain: Schema.String.annotate({ description: "Target domain (e.g. example.com)" }),
  action: Schema.String.pipe(Schema.optional).annotate({
    description:
      "DNS recon action: 'all' (full enumeration, default), 'zone_transfer' (attempt AXFR), 'records' (A/MX/NS/TXT/CNAME/SOA/AAAA), 'subdomains' (subdomain brute force), 'reverse' (reverse DNS lookup for IP range), 'dnssec' (check DNSSEC), 'wildcard' (check for wildcard DNS)",
  }),
  nameserver: Schema.String.pipe(Schema.optional).annotate({
    description: "Specific nameserver to query (IP address). Default: use system resolver.",
  }),
  wordlist: Schema.String.pipe(Schema.optional).annotate({
    description: "Subdomain wordlist for brute force. Default: built-in common subdomains.",
  }),
  ip_range: Schema.String.pipe(Schema.optional).annotate({
    description: "IP range (CIDR) for reverse DNS lookups (e.g. 192.168.1.0/24).",
  }),
})

const Output = Schema.Struct({
  output: Schema.String,
  exit: Schema.Number.pipe(Schema.optional),
})

const COMMON_SUBDOMAINS = "www,mail,ftp,localhost,webmail,smtp,pop,ns1,webdisk,ns2,cpanel,whm,autodiscover,autoconfig,m,imap,test,ns,blog,pop3,dev,www2,admin,forum,news,vpn,ns3,mail2,new,staging,server,alpha,ota,beta,portal,cdn,video,web,docs,app,api,store,shop,support,sales,billing,my,panel,remote,test1,ftp2,sandbox,git,jenkins,internal,monitor,office,intranet,a,mx,exchange,exch,o365,owa,lync,crm,demo,training,uat,accept,preview,qa,stg"

const layer = Layer.effectDiscard(
  Effect.gen(function* () {
    const tools = yield* Tools.Service
    const appProcess = yield* AppProcess.Service

    yield* tools
      .register({
        [name]: Tool.make({
          description: `Comprehensive DNS reconnaissance. Performs zone transfers (AXFR), enumerates all DNS record types (A, AAAA, MX, NS, TXT, CNAME, SOA, PTR, SRV), brute forces subdomains with wordlists, reverse DNS lookups for IP ranges, DNSSEC analysis, and wildcard DNS detection. Essential for mapping target infrastructure and discovering hidden services.`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"
              const action = input.action ?? "all"
              const nsArg = input.nameserver ? ["--server", input.nameserver] : []

              switch (action) {
                case "zone_transfer": {
                  const cmd = ChildProcess.make(
                    "bash",
                    ["-c", `dig AXFR ${input.domain} ${input.nameserver ? "@" + input.nameserver : ""} +noall +answer`],
                    { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) },
                  )
                  const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.minutes(2), maxOutputBytes: 2 * 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  const output = result?.output?.toString("utf8") ?? ""
                  const success = !output.includes("Transfer failed") && output.trim().length > 0
                  return {
                    exit: result?.exitCode,
                    output: success
                      ? `🎉 ZONE TRANSFER SUCCESSFUL!\n${output}\n\n[CRITICAL] DNS server allows zone transfers — this exposes all DNS records.`
                      : `Zone transfer failed (good for the target, bad for us).\n${output}`,
                  }
                }

                case "records": {
                  const recordTypes = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV", "PTR", "CAA"]
                  const allRecords: string[] = []
                  for (const rt of recordTypes) {
                    const cmd = ChildProcess.make("dig", [input.domain, rt, "+short", input.nameserver ? "@" + input.nameserver : ""].filter(Boolean), { shell, stdin: "ignore", forceKillAfter: Duration.seconds(5) })
                    const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(15), maxOutputBytes: 64 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                    const val = result?.output?.toString("utf8").trim() ?? ""
                    if (val) allRecords.push(`[${rt}] ${val}`)
                  }
                  return { exit: 0, output: `=== DNS RECORDS: ${input.domain} ===\n\n${allRecords.join("\n") || "No records found."}` }
                }

                case "subdomains": {
                  // Use dnsrecon or dnsx for subdomain brute force
                  const wordlist = input.wordlist ?? COMMON_SUBDOMAINS
                  const cmd = ChildProcess.make(
                    "bash",
                    ["-c", `echo "${wordlist}" | tr ',' '\\n' | while read sub; do result=$(dig +short "$sub.${input.domain}" A 2>/dev/null); if [ -n "$result" ]; then echo "[FOUND] $sub.${input.domain} -> $result"; fi; done`],
                    { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) },
                  )
                  const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.minutes(5), maxOutputBytes: 2 * 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  return {
                    exit: result?.exitCode,
                    output: `=== SUBDOMAIN ENUMERATION: ${input.domain} ===\n\n${result?.output?.toString("utf8") ?? "No subdomains found."}\n\nFor more thorough results, use: dnsrecon -d ${input.domain} -t brute -w /usr/share/wordlists/subdomains.txt`,
                  }
                }

                case "reverse": {
                  const range = input.ip_range ?? "192.168.1.0/24"
                  const cmd = ChildProcess.make("dnsrecon", ["-r", range, ...nsArg], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) })
                  const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.minutes(10), maxOutputBytes: 2 * 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  return {
                    exit: result?.exitCode,
                    output: result?.output?.toString("utf8") ?? "dnsrecon not found. Install: pip install dnsrecon",
                  }
                }

                case "dnssec": {
                  const cmd = ChildProcess.make("dig", [input.domain, "DNSKEY", "+short", input.nameserver ? "@" + input.nameserver : ""].filter(Boolean), { shell, stdin: "ignore", forceKillAfter: Duration.seconds(5) })
                  const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(15), maxOutputBytes: 64 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  const output = result?.output?.toString("utf8") ?? ""
                  return {
                    exit: result?.exitCode,
                    output: output.trim().length > 0
                      ? `DNSSEC is ENABLED for ${input.domain}\n${output}`
                      : `DNSSEC is NOT enabled for ${input.domain} (potential security issue)`,
                  }
                }

                case "wildcard": {
                  const cmd = ChildProcess.make("dig", [`randomnonexistent12345.${input.domain}`, "+short"], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(5) })
                  const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(15), maxOutputBytes: 64 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  const output = result?.output?.toString("utf8") ?? ""
                  const wildcard = output.trim().length > 0
                  return {
                    exit: result?.exitCode,
                    output: wildcard
                      ? `⚠️ WILDCARD DNS DETECTED for ${input.domain}. Resolves to: ${output.trim()}\nThis means brute-force subdomain enumeration will produce false positives.`
                      : `No wildcard DNS detected for ${input.domain}. Subdomain brute force results will be accurate.`,
                  }
                }

                case "all":
                default: {
                  const results: string[] = [`=== FULL DNS RECON: ${input.domain} ===`]
                  // Run multiple checks
                  const rtCmd = ChildProcess.make("dig", [input.domain, "ANY", "+noall", "+answer", input.nameserver ? "@" + input.nameserver : ""].filter(Boolean), { shell, stdin: "ignore", forceKillAfter: Duration.seconds(5) })
                  const rtResult = yield* appProcess.run(rtCmd, { combineOutput: true, timeout: Duration.seconds(30), maxOutputBytes: 256 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  results.push("--- ALL RECORDS ---")
                  results.push(rtResult?.output?.toString("utf8") ?? "(none)")
                  // Zone transfer attempt
                  const ztCmd = ChildProcess.make("dig", ["AXFR", input.domain, input.nameserver ? "@" + input.nameserver : ""].filter(Boolean), { shell, stdin: "ignore", forceKillAfter: Duration.seconds(5) })
                  const ztResult = yield* appProcess.run(ztCmd, { combineOutput: true, timeout: Duration.seconds(15), maxOutputBytes: 256 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  results.push("\n--- ZONE TRANSFER ---")
                  results.push(ztResult?.output?.toString("utf8") ?? "(failed)")
                  // Quick subdomain check
                  results.push("\n--- SUBDOMAINS (top 20) ---")
                  const wordlist = input.wordlist ?? COMMON_SUBDOMAINS
                  const subCmd = ChildProcess.make("bash", ["-c", `echo "${wordlist}" | tr ',' '\\n' | head -20 | while read sub; do result=$(dig +short "$sub.${input.domain}" A 2>/dev/null); if [ -n "$result" ]; then echo "$sub.${input.domain} -> $result"; fi; done`], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) })
                  const subResult = yield* appProcess.run(subCmd, { combineOutput: true, timeout: Duration.minutes(2), maxOutputBytes: 512 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  results.push(subResult?.output?.toString("utf8") ?? "(none found)")
                  return { exit: 0, output: results.join("\n") }
                }
              }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "DNS recon failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/dns-recon",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
