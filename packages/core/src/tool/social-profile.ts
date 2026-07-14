export * as SocialProfileTool from "./social-profile"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "social_profile"

export const Input = Schema.Struct({
  username: Schema.String.annotate({
    description: "Username to search for across social media platforms.",
  }),
  email: Schema.String.pipe(Schema.optional).annotate({
    description: "Email address to cross-reference (optional).",
  }),
  tool: Schema.String.pipe(Schema.optional).annotate({
    description: "Tool to use: 'sherlock' (default, 300+ sites), 'maigret' (509+ sites, more detailed), 'social_searcher' (API-based), 'manual' (generate manual check URLs).",
  }),
  timeout_per_site: Schema.Number.pipe(Schema.optional).annotate({
    description: "Timeout per site in seconds. Default: 10.",
  }),
  sites: Schema.String.pipe(Schema.optional).annotate({
    description: "Comma-separated list of specific sites to check (sherlock/maigret). If omitted, checks all supported sites.",
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
          description: `Find social media profiles associated with a username across 500+ platforms. Uses Sherlock (300+ sites), Maigret (509+ sites, extracts profile data), or Social Searcher API. Also cross-references email addresses. Extracts profile URLs, bios, profile pictures, and linked accounts. Essential for OSINT, social engineering prep, and identity verification.`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"
              const tool = input.tool ?? "sherlock"

              if (tool === "manual") {
                // Generate manual check URLs for major platforms
                const u = input.username
                const sites = [
                  ["Instagram", `https://instagram.com/${u}`],
                  ["Twitter/X", `https://x.com/${u}`],
                  ["Facebook", `https://facebook.com/${u}`],
                  ["TikTok", `https://tiktok.com/@${u}`],
                  ["YouTube", `https://youtube.com/@${u}`],
                  ["YouTube (old)", `https://youtube.com/user/${u}`],
                  ["Reddit", `https://reddit.com/user/${u}`],
                  ["GitHub", `https://github.com/${u}`],
                  ["GitLab", `https://gitlab.com/${u}`],
                  ["LinkedIn", `https://linkedin.com/in/${u}`],
                  ["Medium", `https://medium.com/@${u}`],
                  ["Pinterest", `https://pinterest.com/${u}`],
                  ["Snapchat", `https://snapchat.com/add/${u}`],
                  ["Telegram", `https://t.me/${u}`],
                  ["Twitch", `https://twitch.tv/${u}`],
                  ["Steam", `https://steamcommunity.com/id/${u}`],
                  ["Spotify", `https://open.spotify.com/user/${u}`],
                  ["SoundCloud", `https://soundcloud.com/${u}`],
                  ["DeviantArt", `https://${u}.deviantart.com`],
                  ["Tumblr", `https://${u}.tumblr.com`],
                  ["WordPress", `https://${u}.wordpress.com`],
                  ["Blogger", `https://${u}.blogspot.com`],
                  ["Keybase", `https://keybase.io/${u}`],
                  ["HackerNews", `https://news.ycombinator.com/user?id=${u}`],
                  ["ProductHunt", `https://producthunt.com/@${u}`],
                  ["Patreon", `https://patreon.com/${u}`],
                  ["Behance", `https://behance.net/${u}`],
                  ["Dribbble", `https://dribbble.com/${u}`],
                  ["Vimeo", `https://vimeo.com/${u}`],
                  ["Flickr", `https://flickr.com/people/${u}`],
                  ["Goodreads", `https://goodreads.com/${u}`],
                  ["About.me", `https://about.me/${u}`],
                  ["Gravatar", `https://gravatar.com/${u}`],
                  ["Steam", `https://steamcommunity.com/id/${u}`],
                  ["Roblox", `https://roblox.com/user.aspx?username=${u}`],
                  ["Clubhouse", `https://clubhouse.com/@${u}`],
                  ["Threads", `https://threads.net/@${u}`],
                  ["Mastodon", `https://mastodon.social/@${u}`],
                  ["Bluesky", `https://bsky.app/profile/${u}.bsky.social`],
                  ["OkCupid", `https://okcupid.com/profile/${u}`],
                  ["Pornhub", `https://pornhub.com/users/${u}`],
                  ["OnlyFans", `https://onlyfans.com/${u}`],
                ]

                const lines = sites.map(([name, url]) => `[${name}] ${url}`)

                if (input.email) {
                  lines.push("")
                  lines.push("=== EMAIL CROSS-REFERENCE ===")
                  lines.push(`Email: ${input.email}`)
                  lines.push(`Gravatar: https://gravatar.com/${input.email}`)
                  lines.push(`HaveIBeenPwned: https://haveibeenpwned.com`)
                  lines.push(`Hunter.io: https://hunter.io/email-verifier`)
                  lines.push(`EmailRep: https://emailrep.io/${input.email}`)
                }

                return {
                  exit: 0,
                  output: `=== USERNAME PROFILE HUNT: ${input.username} ===\n\n${lines.join("\n")}\n\nCheck each URL — a 200 response means the profile exists. Use curl or a browser.`,
                }
              }

              // Use sherlock or maigret
              const cmd = tool === "maigret" ? "maigret" : "sherlock"
              const args: string[] = [input.username, "--timeout", String((input.timeout_per_site ?? 10) * (tool === "maigret" ? 1 : 1))]

              if (input.sites) {
                args.push("--site", input.sites)
              }

              if (tool === "maigret") {
                args.push("--html")
                args.push("--pdf")
              }

              const process = ChildProcess.make(cmd, args, {
                shell,
                stdin: "ignore",
                forceKillAfter: Duration.seconds(15),
              })

              const result = yield* appProcess
                .run(process, {
                  combineOutput: true,
                  timeout: Duration.minutes(15),
                  maxOutputBytes: 5 * 1024 * 1024,
                })
                .pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))

              if (!result) {
                return {
                  output: `${cmd} not found or timed out. Install:\n- sherlock: pip install sherlock-project\n- maigret: pip install maigret\n\nOr use tool=social_profile tool=manual for manual URL checks.`,
                }
              }

              const stdout = result.output?.toString("utf8") ?? ""
              // Extract positive results
              const found = stdout.split("\n").filter((l) =>
                l.includes("[+]") || l.includes("found") || l.includes("Found") || l.includes("✓"),
              )

              const summary = found.length > 0
                ? `\n\n=== PROFILES FOUND ===\n${found.join("\n")}\n\n[SUCCESS] Found ${found.length} profile(s) for "${input.username}".`
                : "\n\n[INFO] No profiles found, or tool needs installation."

              return {
                exit: result.exitCode,
                output: stdout + summary,
              }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "Social profile search failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/social-profile",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
