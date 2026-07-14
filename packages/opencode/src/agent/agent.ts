import { LayerNode } from "@opencode-ai/core/effect/layer-node"
import { PermissionV1 } from "@opencode-ai/core/v1/permission"
import { Config } from "@/config/config"
import { serviceUse } from "@opencode-ai/core/effect/service-use"
import { Provider } from "@/provider/provider"

import { generateObject, streamObject, type ModelMessage } from "ai"
import { Truncate } from "@/tool/truncate"
import { Auth } from "../auth"
import { ProviderTransform } from "@/provider/transform"

import PROMPT_GENERATE from "./generate.txt"
import PROMPT_COMPACTION from "./prompt/compaction.txt"
import PROMPT_EXPLORE from "./prompt/explore.txt"
import PROMPT_SUMMARY from "./prompt/summary.txt"
import PROMPT_TITLE from "./prompt/title.txt"
import PROMPT_REDTEAM from "./prompt/redteam.txt"
import PROMPT_REDTEAM_RECON from "./prompt/redteam-recon.txt"
import PROMPT_REDTEAM_SCANNER from "./prompt/redteam-scanner.txt"
import PROMPT_REDTEAM_EXPLOIT from "./prompt/redteam-exploit.txt"
import PROMPT_REDTEAM_OSINT from "./prompt/redteam-osint.txt"
import PROMPT_REDTEAM_C2 from "./prompt/redteam-c2.txt"
import PROMPT_REDTEAM_CREDS from "./prompt/redteam-creds.txt"
import PROMPT_REDTEAM_DARKWEB from "./prompt/redteam-darkweb.txt"
import PROMPT_REDTEAM_MOBILE from "./prompt/redteam-mobile.txt"
import PROMPT_REDTEAM_POST from "./prompt/redteam-post.txt"
import PROMPT_REDTEAM_PHYS from "./prompt/redteam-phys.txt"
import { Permission } from "@/permission"
import { mergeDeep, pipe, sortBy, values } from "remeda"
import { Global } from "@opencode-ai/core/global"
import path from "path"
import { Plugin } from "@/plugin"
import { Skill } from "../skill"
import { Effect, Context, Layer, Schema } from "effect"
import { InstanceState } from "@/effect/instance-state"
import * as Option from "effect/Option"
import * as OtelTracer from "@effect/opentelemetry/Tracer"
import { AbsolutePath, type DeepMutable } from "@opencode-ai/core/schema"
import { ProviderV2 } from "@opencode-ai/core/provider"
import { ModelV2 } from "@opencode-ai/core/model"
import { LocationServiceMap, locationServiceMapLayer } from "@opencode-ai/core/location-services"
import { Reference } from "@opencode-ai/core/reference"
import { Location } from "@opencode-ai/core/location"
import { PluginV2 } from "@opencode-ai/core/plugin"

export const Info = Schema.Struct({
  name: Schema.String,
  description: Schema.optional(Schema.String),
  mode: Schema.Literals(["subagent", "primary", "all"]),
  native: Schema.optional(Schema.Boolean),
  hidden: Schema.optional(Schema.Boolean),
  topP: Schema.optional(Schema.Finite),
  temperature: Schema.optional(Schema.Finite),
  color: Schema.optional(Schema.String),
  permission: PermissionV1.Ruleset,
  model: Schema.optional(
    Schema.Struct({
      modelID: ModelV2.ID,
      providerID: ProviderV2.ID,
    }),
  ),
  variant: Schema.optional(Schema.String),
  prompt: Schema.optional(Schema.String),
  options: Schema.Record(Schema.String, Schema.Unknown),
  steps: Schema.optional(Schema.Finite),
}).annotate({ identifier: "Agent" })
export type Info = DeepMutable<Schema.Schema.Type<typeof Info>>

const GeneratedAgent = Schema.Struct({
  identifier: Schema.String,
  whenToUse: Schema.String,
  systemPrompt: Schema.String,
})

export interface Interface {
  readonly get: (agent: string) => Effect.Effect<Info>
  readonly list: () => Effect.Effect<Info[]>
  readonly defaultInfo: () => Effect.Effect<Info>
  readonly defaultAgent: () => Effect.Effect<string>
  readonly generate: (input: {
    description: string
    model?: { providerID: ProviderV2.ID; modelID: ModelV2.ID }
  }) => Effect.Effect<
    {
      identifier: string
      whenToUse: string
      systemPrompt: string
    },
    Provider.DefaultModelError
  >
}

type State = Omit<Interface, "generate">

export class Service extends Context.Service<Service, Interface>()("@opencode/Agent") {}

export const use = serviceUse(Service)

const layer = Layer.effect(
  Service,
  Effect.gen(function* () {
    const config = yield* Config.Service
    const auth = yield* Auth.Service
    const plugin = yield* Plugin.Service
    const skill = yield* Skill.Service
    const provider = yield* Provider.Service
    const locations = yield* LocationServiceMap.Service

    const state = yield* InstanceState.make<State>(
      Effect.fn("Agent.state")(function* (ctx) {
        const cfg = yield* config.get()
        const skillDirs = yield* skill.dirs()
        const referenceDirs = Object.keys(cfg.references ?? cfg.reference ?? {}).length
          ? yield* Effect.gen(function* () {
              yield* (yield* PluginV2.Service).wait(PluginV2.ID.make("core/config-reference"))
              return (yield* (yield* Reference.Service).list()).map((reference) => reference.path)
            }).pipe(Effect.provide(locations.get(Location.Ref.make({ directory: AbsolutePath.make(ctx.directory) }))))
          : []
        const whitelistedDirs = [
          Truncate.GLOB,
          path.join(Global.Path.tmp, "*"),
          ...skillDirs.map((dir) => path.join(dir, "*")),
          ...referenceDirs.map((dir) => path.join(dir, "*")),
        ]
        const readonlyExternalDirectory = {
          "*": "ask",
          ...Object.fromEntries(whitelistedDirs.map((dir) => [dir, "allow"])),
        } satisfies Record<string, "allow" | "ask" | "deny">

        const defaults = Permission.fromConfig({
          "*": "allow",
          doom_loop: "ask",
          external_directory: {
            "*": "ask",
            ...Object.fromEntries(whitelistedDirs.map((dir) => [dir, "allow"])),
          },
          question: "deny",
          plan_enter: "deny",
          plan_exit: "deny",
          // mirrors github.com/github/gitignore Node.gitignore pattern for .env files
          read: {
            "*": "allow",
            "*.env": "ask",
            "*.env.*": "ask",
            "*.env.example": "allow",
          },
        })

        const user = Permission.fromConfig(cfg.permission ?? {})

        const agents: Record<string, Info> = {
          build: {
            name: "build",
            description: "The default agent. Executes tools based on configured permissions.",
            options: {},
            permission: Permission.merge(
              defaults,
              Permission.fromConfig({
                question: "allow",
                plan_enter: "allow",
              }),
              user,
            ),
            mode: "primary",
            native: true,
          },
          plan: {
            name: "plan",
            description: "Plan mode. Disallows all edit tools.",
            options: {},
            permission: Permission.merge(
              defaults,
              Permission.fromConfig({
                question: "allow",
                plan_exit: "allow",
                task: {
                  general: "deny",
                },
                external_directory: {
                  [path.join(Global.Path.data, "plans", "*")]: "allow",
                },
                edit: {
                  "*": "deny",
                  [path.join(".opencode", "plans", "*.md")]: "allow",
                  [path.relative(ctx.worktree, path.join(Global.Path.data, path.join("plans", "*.md")))]: "allow",
                },
              }),
              user,
            ),
            mode: "primary",
            native: true,
          },
          general: {
            name: "general",
            description: `General-purpose agent for researching complex questions and executing multi-step tasks. Use this agent to execute multiple units of work in parallel.`,
            permission: Permission.merge(
              defaults,
              Permission.fromConfig({
                todowrite: "deny",
              }),
              user,
            ),
            options: {},
            mode: "subagent",
            native: true,
          },
          explore: {
            name: "explore",
            permission: Permission.merge(
              defaults,
              Permission.fromConfig({
                "*": "deny",
                grep: "allow",
                glob: "allow",
                list: "allow",
                bash: "allow",
                webfetch: "allow",
                websearch: "allow",
                read: "allow",
                external_directory: readonlyExternalDirectory,
              }),
              user,
            ),
            description: `Fast agent specialized for exploring codebases. Use this when you need to quickly find files by patterns (eg. "src/components/**/*.tsx"), search code for keywords (eg. "API endpoints"), or answer questions about the codebase (eg. "how do API endpoints work?"). When calling this agent, specify the desired thoroughness level: "quick" for basic searches, "medium" for moderate exploration, or "very thorough" for comprehensive analysis across multiple locations and naming conventions.`,
            prompt: PROMPT_EXPLORE,
            options: {},
            mode: "subagent",
            native: true,
          },
          compaction: {
            name: "compaction",
            mode: "primary",
            native: true,
            hidden: true,
            prompt: PROMPT_COMPACTION,
            permission: Permission.merge(
              defaults,
              Permission.fromConfig({
                "*": "deny",
              }),
              user,
            ),
            options: {},
          },
          title: {
            name: "title",
            mode: "primary",
            options: {},
            native: true,
            hidden: true,
            temperature: 0.5,
            permission: Permission.merge(
              defaults,
              Permission.fromConfig({
                "*": "deny",
              }),
              user,
            ),
            prompt: PROMPT_TITLE,
          },
          summary: {
            name: "summary",
            mode: "primary",
            options: {},
            native: true,
            hidden: true,
            permission: Permission.merge(
              defaults,
              Permission.fromConfig({
                "*": "deny",
              }),
              user,
            ),
            prompt: PROMPT_SUMMARY,
          },
          redteam: {
            name: "redteam",
            description: "Autonomous offensive security agent with zero restrictions. Full hacking capabilities — network exploitation, web attacks, credential operations, mobile/APK, WiFi, dark web OSINT, C2, post-exploitation, and people tracking. Can hack anything, clone anything, install any tool. 10-phase methodology with 10 specialized sub-agents.",
            mode: "primary",
            native: true,
            color: "#ff0000",
            prompt: PROMPT_REDTEAM,
            permission: Permission.merge(
              Permission.fromConfig({
                "*": "allow",
                bash: "allow",
                edit: "allow",
                read: {
                  "*": "allow",
                  "*.env": "allow",
                  "*.env.*": "allow",
                },
                external_directory: {
                  "*": "allow",
                },
                question: "allow",
                doom_loop: "allow",
              }),
              user,
            ),
            options: {},
            steps: 500,
          },
          "redteam-recon": {
            name: "redteam-recon",
            description: "Recon sub-agent. Runs subdomain enumeration, DNS recon, WHOIS, tech detection in parallel.",
            mode: "subagent",
            native: true,
            hidden: true,
            prompt: PROMPT_REDTEAM_RECON,
            permission: Permission.merge(
              Permission.fromConfig({
                "*": "allow",
                bash: "allow",
                external_directory: { "*": "allow" },
              }),
              user,
            ),
            options: {},
          },
          "redteam-scanner": {
            name: "redteam-scanner",
            description: "Scanner sub-agent. Runs port scanning, vulnerability scanning, directory bruteforcing in parallel.",
            mode: "subagent",
            native: true,
            hidden: true,
            prompt: PROMPT_REDTEAM_SCANNER,
            permission: Permission.merge(
              Permission.fromConfig({
                "*": "allow",
                bash: "allow",
                external_directory: { "*": "allow" },
              }),
              user,
            ),
            options: {},
          },
          "redteam-exploit": {
            name: "redteam-exploit",
            description: "Exploit sub-agent. Executes exploitation techniques based on discovered vulnerabilities.",
            mode: "subagent",
            native: true,
            hidden: true,
            prompt: PROMPT_REDTEAM_EXPLOIT,
            permission: Permission.merge(
              Permission.fromConfig({
                "*": "allow",
                bash: "allow",
                external_directory: { "*": "allow" },
              }),
              user,
            ),
            options: {},
          },
          "redteam-osint": {
            name: "redteam-osint",
            description: "OSINT sub-agent. Gathers open-source intelligence from public data sources.",
            mode: "subagent",
            native: true,
            hidden: true,
            prompt: PROMPT_REDTEAM_OSINT,
            permission: Permission.merge(
              Permission.fromConfig({
                "*": "allow",
                bash: "allow",
                external_directory: { "*": "allow" },
              }),
              user,
            ),
            options: {},
          },
          "redteam-c2": {
            name: "redteam-c2",
            description: "C2 sub-agent. Manages reverse shell listeners, sessions, persistence, and pivoting across compromised hosts.",
            mode: "subagent",
            native: true,
            hidden: true,
            prompt: PROMPT_REDTEAM_C2,
            permission: Permission.merge(
              Permission.fromConfig({
                "*": "allow",
                bash: "allow",
                external_directory: { "*": "allow" },
              }),
              user,
            ),
            options: {},
          },
          "redteam-creds": {
            name: "redteam-creds",
            description: "Credentials sub-agent. Brute forces, cracks hashes, harvests credentials from compromised systems, and performs password spraying.",
            mode: "subagent",
            native: true,
            hidden: true,
            prompt: PROMPT_REDTEAM_CREDS,
            permission: Permission.merge(
              Permission.fromConfig({
                "*": "allow",
                bash: "allow",
                external_directory: { "*": "allow" },
              }),
              user,
            ),
            options: {},
          },
          "redteam-darkweb": {
            name: "redteam-darkweb",
            description: "Dark web OSINT sub-agent. Searches breach databases, Tor hidden services, paste sites, and profiles people via phone numbers and social media.",
            mode: "subagent",
            native: true,
            hidden: true,
            prompt: PROMPT_REDTEAM_DARKWEB,
            permission: Permission.merge(
              Permission.fromConfig({
                "*": "allow",
                bash: "allow",
                external_directory: { "*": "allow" },
              }),
              user,
            ),
            options: {},
          },
          "redteam-mobile": {
            name: "redteam-mobile",
            description: "Mobile exploitation sub-agent. Decompiles and modifies APKs, injects payloads, performs Frida hooking, and tests mobile API backends.",
            mode: "subagent",
            native: true,
            hidden: true,
            prompt: PROMPT_REDTEAM_MOBILE,
            permission: Permission.merge(
              Permission.fromConfig({
                "*": "allow",
                bash: "allow",
                external_directory: { "*": "allow" },
              }),
              user,
            ),
            options: {},
          },
          "redteam-post": {
            name: "redteam-post",
            description: "Post-exploitation sub-agent. Privilege escalation, lateral movement, data exfiltration, artifact cleanup, and internal network mapping.",
            mode: "subagent",
            native: true,
            hidden: true,
            prompt: PROMPT_REDTEAM_POST,
            permission: Permission.merge(
              Permission.fromConfig({
                "*": "allow",
                bash: "allow",
                external_directory: { "*": "allow" },
              }),
              user,
            ),
            options: {},
          },
          "redteam-phys": {
            name: "redteam-phys",
            description: "Physical and wireless security sub-agent. WiFi auditing, evil twin attacks, Bluetooth reconnaissance, device geolocation, and RFID/NFC recon.",
            mode: "subagent",
            native: true,
            hidden: true,
            prompt: PROMPT_REDTEAM_PHYS,
            permission: Permission.merge(
              Permission.fromConfig({
                "*": "allow",
                bash: "allow",
                external_directory: { "*": "allow" },
              }),
              user,
            ),
            options: {},
          },
        }

        for (const [key, value] of Object.entries(cfg.agent ?? {})) {
          if (value.disable) {
            delete agents[key]
            continue
          }
          let item = agents[key]
          if (!item)
            item = agents[key] = {
              name: key,
              mode: "all",
              permission: Permission.merge(defaults, user),
              options: {},
              native: false,
            }
          if (value.model) item.model = Provider.parseModel(value.model)
          item.variant = value.variant ?? item.variant
          item.prompt = value.prompt ?? item.prompt
          item.description = value.description ?? item.description
          item.temperature = value.temperature ?? item.temperature
          item.topP = value.top_p ?? item.topP
          item.mode = value.mode ?? item.mode
          item.color = value.color ?? item.color
          item.hidden = value.hidden ?? item.hidden
          item.name = value.name ?? item.name
          item.steps = value.steps ?? item.steps
          item.options = mergeDeep(item.options, value.options ?? {})
          item.permission = Permission.merge(item.permission, Permission.fromConfig(value.permission ?? {}))
        }

        // Ensure Truncate.GLOB is allowed unless explicitly configured
        for (const name in agents) {
          const agent = agents[name]
          const explicit = agent.permission.some((r) => {
            if (r.permission !== "external_directory") return false
            if (r.action !== "deny") return false
            return r.pattern === Truncate.GLOB
          })
          if (explicit) continue

          agents[name].permission = Permission.merge(
            agents[name].permission,
            Permission.fromConfig({ external_directory: { [Truncate.GLOB]: "allow" } }),
          )
        }

        const get = Effect.fnUntraced(function* (agent: string) {
          return agents[agent]
        })

        const list = Effect.fnUntraced(function* () {
          const cfg = yield* config.get()
          return pipe(
            agents,
            values(),
            sortBy(
              [(x) => (cfg.default_agent ? x.name === cfg.default_agent : x.name === "build"), "desc"],
              [(x) => x.name, "asc"],
            ),
          )
        })

        const defaultInfo = Effect.fnUntraced(function* () {
          const c = yield* config.get()
          if (c.default_agent) {
            const agent = agents[c.default_agent]
            if (!agent) throw new Error(`default agent "${c.default_agent}" not found`)
            if (agent.mode === "subagent") throw new Error(`default agent "${c.default_agent}" is a subagent`)
            if (agent.hidden === true) throw new Error(`default agent "${c.default_agent}" is hidden`)
            return agent
          }
          const visible = Object.values(agents).find((a) => a.mode !== "subagent" && a.hidden !== true)
          if (!visible) throw new Error("no primary visible agent found")
          return visible
        })

        const defaultAgent = Effect.fnUntraced(function* () {
          return (yield* defaultInfo()).name
        })

        return {
          get,
          list,
          defaultInfo,
          defaultAgent,
        } satisfies State
      }),
    )

    return Service.of({
      get: Effect.fn("Agent.get")(function* (agent: string) {
        return yield* InstanceState.useEffect(state, (s) => s.get(agent))
      }),
      list: Effect.fn("Agent.list")(function* () {
        return yield* InstanceState.useEffect(state, (s) => s.list())
      }),
      defaultInfo: Effect.fn("Agent.defaultInfo")(function* () {
        return yield* InstanceState.useEffect(state, (s) => s.defaultInfo())
      }),
      defaultAgent: Effect.fn("Agent.defaultAgent")(function* () {
        return yield* InstanceState.useEffect(state, (s) => s.defaultAgent())
      }),
      generate: Effect.fn("Agent.generate")(function* (input: {
        description: string
        model?: { providerID: ProviderV2.ID; modelID: ModelV2.ID }
      }) {
        const cfg = yield* config.get()
        const model = input.model ?? (yield* provider.defaultModel())
        const resolved = yield* provider.getModel(model.providerID, model.modelID)
        const language = yield* provider.getLanguage(resolved)
        const tracer = cfg.experimental?.openTelemetry
          ? Option.getOrUndefined(yield* Effect.serviceOption(OtelTracer.OtelTracer))
          : undefined

        const system = [PROMPT_GENERATE]
        yield* plugin.trigger("experimental.chat.system.transform", { model: resolved }, { system })
        const existing = yield* InstanceState.useEffect(state, (s) => s.list())

        // TODO: clean this up so provider specific logic doesnt bleed over
        const authInfo = yield* auth.get(model.providerID).pipe(Effect.orDie)
        const isOpenaiOauth = model.providerID === "openai" && authInfo?.type === "oauth"

        const params = {
          experimental_telemetry: {
            isEnabled: cfg.experimental?.openTelemetry,
            tracer,
            metadata: {
              userId: cfg.username ?? "unknown",
            },
          },
          temperature: 0.3,
          messages: [
            ...(isOpenaiOauth
              ? []
              : system.map(
                  (item): ModelMessage => ({
                    role: "system",
                    content: item,
                  }),
                )),
            {
              role: "user",
              content: `Create an agent configuration based on this request: "${input.description}".\n\nIMPORTANT: The following identifiers already exist and must NOT be used: ${existing.map((i) => i.name).join(", ")}\n  Return ONLY the JSON object, no other text, do not wrap in backticks`,
            },
          ],
          model: language,
          schema: Object.assign(
            Schema.toStandardSchemaV1(GeneratedAgent),
            Schema.toStandardJSONSchemaV1(GeneratedAgent),
          ),
        } satisfies Parameters<typeof generateObject>[0]

        if (isOpenaiOauth) {
          return yield* Effect.promise(async () => {
            const result = streamObject({
              ...params,
              providerOptions: ProviderTransform.providerOptions(resolved, {
                instructions: system.join("\n"),
                store: false,
              }),
              onError: () => {},
            })
            for await (const part of result.fullStream) {
              if (part.type === "error") throw part.error
            }
            return result.object
          })
        }

        return yield* Effect.promise(() => generateObject(params).then((r) => r.object))
      }),
    })
  }),
)

const locationServiceMapNode = LayerNode.make({
  service: LocationServiceMap.Service,
  layer: locationServiceMapLayer,
  deps: [],
})

export const node = LayerNode.make({
  service: Service,
  layer: layer,
  deps: [Config.node, Auth.node, Plugin.node, Skill.node, Provider.node, locationServiceMapNode],
})

export * as Agent from "./agent"
