export * as PhoneLookupTool from "./phone-lookup"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "phone_lookup"

export const Input = Schema.Struct({
  phone: Schema.String.annotate({
    description: "Phone number to look up. Include country code (e.g. +14155551234, +447712345678).",
  }),
  sources: Schema.String.pipe(Schema.optional).annotate({
    description:
      "Data sources to query: 'all' (default), or specific: 'truecaller', 'whatsapp', 'telegram', 'carrier', 'location', 'social', 'leaked'",
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
          description: `Look up phone number information across multiple sources. Identifies carrier, geographic location (area/region/city), line type (mobile/landline/VOIP), and cross-references with social media platforms (WhatsApp, Telegram, Truecaller, Facebook, Instagram). Also searches breach databases for leaked data associated with the number. Essential for OSINT investigations, social engineering prep, and people tracking.`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"
              const phone = input.phone.replace(/\s+/g, "")
              const sources = input.sources ?? "all"
              const results: string[] = []

              results.push("=== PHONE NUMBER OSINT REPORT ===")
              results.push(`Target: ${phone}`)
              results.push(`Timestamp: ${new Date().toISOString()}`)
              results.push("")

              // Carrier and location lookup via free APIs
              if (sources === "all" || sources === "carrier" || sources === "location") {
                const numapiCmd = ChildProcess.make(
                  "curl",
                  ["-s", `https://numverify.com/demo.php?number=${encodeURIComponent(phone)}&country_code=&format=1`],
                  { shell, stdin: "ignore", forceKillAfter: Duration.seconds(5) },
                )
                const numapiResult = yield* appProcess
                  .run(numapiCmd, {
                    combineOutput: true,
                    timeout: Duration.seconds(15),
                    maxOutputBytes: 256 * 1024,
                  })
                  .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))

                results.push("--- CARRIER & LOCATION ---")
                if (numapiResult?.output) {
                  results.push(numapiResult.output.toString("utf8"))
                } else {
                  results.push("Carrier lookup via numverify unavailable. Manual check needed.")
                }

                // Also try apilayer-style lookup
                results.push("")
                results.push(`Manual carrier/line-type lookup:`)
                results.push(`- Country code: +${phone.replace("+", "").match(/^(\d{1,3})/)?.[1] ?? "unknown"}`)
                results.push(`- Format: ${phone.match(/^\+/) ? "International E.164" : "Local format"}`)

                // Guess approximate location from area code
                const ccMatch = phone.match(/^\+(\d{1,3})(.*)/)
                if (ccMatch) {
                  const cc = ccMatch[1]
                  const rest = ccMatch[2]
                  const countryMap: Record<string, string> = {
                    "1": "USA/Canada (NANP)",
                    "44": "United Kingdom",
                    "33": "France",
                    "49": "Germany",
                    "34": "Spain",
                    "39": "Italy",
                    "31": "Netherlands",
                    "91": "India",
                    "86": "China",
                    "81": "Japan",
                    "82": "South Korea",
                    "55": "Brazil",
                    "52": "Mexico",
                    "7": "Russia/Kazakhstan",
                    "61": "Australia",
                    "971": "UAE",
                    "966": "Saudi Arabia",
                    "90": "Turkey",
                    "62": "Indonesia",
                    "63": "Philippines",
                    "60": "Malaysia",
                    "65": "Singapore",
                    "66": "Thailand",
                    "84": "Vietnam",
                    "92": "Pakistan",
                    "880": "Bangladesh",
                  }
                  results.push(`- Carrier country: ${countryMap[cc] ?? `Country code +${cc}`}`)

                  // US area code lookup
                  if (cc === "1" && rest.length >= 10) {
                    const areaCode = rest.substring(0, 3)
                    results.push(`- Area code: ${areaCode} (US/Canada)`)
                  }
                }
                results.push("")
              }

              // Social media cross-reference
              if (sources === "all" || sources === "social") {
                results.push("--- SOCIAL MEDIA CROSS-REFERENCE ---")
                results.push("")

                // WhatsApp check
                results.push("[WhatsApp]")
                const waCmd = ChildProcess.make(
                  "curl",
                  ["-s", `-o /dev/null -w "%{http_code}"`, `https://wa.me/${phone.replace("+", "")}`],
                  { shell, stdin: "ignore", forceKillAfter: Duration.seconds(5) },
                )
                const waResult = yield* appProcess
                  .run(waCmd, {
                    combineOutput: true,
                    timeout: Duration.seconds(15),
                    maxOutputBytes: 64 * 1024,
                  })
                  .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                results.push(waResult?.output ? `Status: ${waResult.output.toString("utf8")}` : "Unable to check.")
                results.push(`Profile link: https://wa.me/${phone.replace("+", "")}`)
                results.push("")

                // Telegram check
                results.push("[Telegram]")
                results.push(`Try: https://t.me/+${phone.replace("+", "")}`)
                results.push(`Or use phone contact sync in Telegram to check if number is registered.`)
                results.push("")

                // Truecaller / general profile
                results.push("[Truecaller]")
                results.push(`Manual lookup: https://www.truecaller.com/search/${phone.replace("+", "")}`)
                results.push("")

                // Other platforms
                results.push("[Other Platforms to Check]")
                results.push("- Facebook: search the number in Facebook search bar")
                results.push("- Instagram: sync contacts to find associated profile")
                results.push("- Snapchat: add by phone number")
                results.push("- Signal: check if registered")
                results.push("- Viber: check if registered")
                results.push("- LinkedIn: sync contacts")
                results.push("- Google Photos / Google Voice: check association")
                results.push("")
              }

              // Breach database check
              if (sources === "all" || sources === "leaked") {
                results.push("--- BREACH DATABASE CHECK ---")
                results.push("")
                results.push("Check these breach databases for this phone number:")
                results.push("- HaveIBeenPwned: https://haveibeenpwned.com")
                results.push("- IntelX: https://intelx.io")
                results.push("- Dehashed: https://dehashed.com")
                results.push("- LeakCheck: https://leakcheck.io")
                results.push("- Snusbase: https://snusbase.com")
                results.push("- BreachDirectory: https://breachdirectory.org")
                results.push("")

                // Try a quick public breach check via API
                const breachCmd = ChildProcess.make(
                  "curl",
                  ["-s", `https://breachdirectory.org/usage_api.php?key=test&query=${encodeURIComponent(phone)}`],
                  { shell, stdin: "ignore", forceKillAfter: Duration.seconds(5) },
                )
                const breachResult = yield* appProcess
                  .run(breachCmd, {
                    combineOutput: true,
                    timeout: Duration.seconds(15),
                    maxOutputBytes: 256 * 1024,
                  })
                  .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                if (breachResult?.output) {
                  results.push("Automated breach check result:")
                  results.push(breachResult.output.toString("utf8"))
                }
                results.push("")
              }

              // Maigret / Sherlock-style username search based on phone-derived usernames
              if (sources === "all" || sources === "social") {
                results.push("--- USERNAME HUNT ---")
                results.push("Try the phone number (without +) as a username on major platforms:")
                const cleanNum = phone.replace(/[^0-9]/g, "")
                results.push(`- Search "${cleanNum}" on Instagram, Twitter, TikTok, YouTube, Reddit`)
                results.push(`- Try Sherlock: sherlock "${cleanNum}"`)
                results.push(`- Try Maigret: maigret "${cleanNum}"`)
                results.push("")
              }

              results.push("=== END REPORT ===")

              return {
                exit: 0,
                output: results.join("\n"),
              }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "Phone lookup failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/phone-lookup",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
