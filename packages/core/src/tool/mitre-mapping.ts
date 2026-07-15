export * as MitreMappingTool from "./mitre-mapping"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"

export const name = "mitre_mapping"

export const Input = Schema.Struct({
  action: Schema.String.annotate({
    description:
      "MITRE action: 'map_technique' (get full ATT&CK technique details, detection methods, mitigations), 'map_activity' (describe your attack activity → get matching ATT&CK TTPs), 'threat_actor' (profile APT group — TTPs, tooling, targets, recent campaigns), 'kill_chain' (map current engagement progress against Lockheed Martin Cyber Kill Chain), 'technique_matrix' (display tactics and their top techniques), 'detection_evade' (for given TTP — how to evade detection), 'cve_to_technique' (map CVE to ATT&CK technique)",
  }),
  technique_id: Schema.String.pipe(Schema.optional).annotate({
    description: "MITRE ATT&CK technique ID (e.g., 'T1055' for Process Injection, 'T1003.001' for LSASS Memory).",
  }),
  activity: Schema.String.pipe(Schema.optional).annotate({
    description: "Description of your current attack activity for TTP mapping (e.g., 'dumped LSASS memory', 'scheduled task created').",
  }),
  threat_actor: Schema.String.pipe(Schema.optional).annotate({
    description: "APT group name/alias (e.g., 'APT29', 'Lazarus', 'FIN7', 'Scattered Spider', 'BlackCat').",
  }),
  phase: Schema.String.pipe(Schema.optional).annotate({
    description: "Current kill chain phase for 'kill_chain' mapping: 'recon', 'weaponize', 'deliver', 'exploit', 'install', 'c2', 'act'.",
  }),
})

const Output = Schema.Struct({
  output: Schema.String,
})

type Output = typeof Output.Type

// Comprehensive MITRE ATT&CK technique database (key techniques)
const TECHNIQUE_DB: Record<string, {
  name: string, tactic: string[], description: string,
  tools: string[], detection: string[], mitigation: string[], subtechniques?: string[]
}> = {
  "T1059": {
    name: "Command and Scripting Interpreter",
    tactic: ["Execution"],
    description: "Adversaries abuse command and script interpreters to execute commands, scripts, or binaries.",
    tools: ["PowerShell", "cmd.exe", "wscript.exe", "cscript.exe", "bash", "python"],
    subtechniques: ["T1059.001 PowerShell", "T1059.003 Windows Command Shell", "T1059.006 Python", "T1059.007 JavaScript"],
    detection: ["Script Block Logging (PowerShell Event 4104)", "Command line logging (Event 4688)", "Sysmon Process Creation (Event 1)"],
    mitigation: ["Constrained Language Mode (PowerShell)", "Application whitelisting", "Disable unnecessary interpreters"],
  },
  "T1055": {
    name: "Process Injection",
    tactic: ["Defense Evasion", "Privilege Escalation"],
    description: "Inject code into live processes to evade process-based defenses and elevate privileges.",
    tools: ["Metasploit", "Cobalt Strike", "custom shellcode loaders", "Donut", "Shellter"],
    subtechniques: ["T1055.001 DLL Injection", "T1055.002 PE Injection", "T1055.003 Thread Execution Hijacking", "T1055.012 Process Hollowing", "T1055.013 Process Doppelgänging", "T1055.015 ListPlanting"],
    detection: ["VirtualAllocEx API monitoring", "WriteProcessMemory + CreateRemoteThread sequence", "Anomalous process memory regions (Moneta)", "Module stomping artifacts"],
    mitigation: ["Attack Surface Reduction rules (Microsoft Defender)", "Credential Guard", "EDR behavioral detection"],
  },
  "T1003": {
    name: "OS Credential Dumping",
    tactic: ["Credential Access"],
    description: "Extract credential material from OS and software to obtain legitimate account credentials.",
    tools: ["Mimikatz", "impacket-secretsdump", "LaZagne", "pypykatz", "CrackMapExec"],
    subtechniques: ["T1003.001 LSASS Memory", "T1003.002 Security Account Manager", "T1003.003 NTDS", "T1003.004 LSA Secrets", "T1003.005 Cached Domain Credentials", "T1003.006 DCSync"],
    detection: ["LSASS access by non-system processes (Sysmon Event 10)", "Event ID 4661 (LSASS access)", "SAM/NTDS copy operations", "Suspicious DRSUAPI replication requests"],
    mitigation: ["Credential Guard (isolates LSASS in VTL1)", "Protected Users security group", "Disable WDigest authentication", "Restrict privileged account usage"],
  },
  "T1078": {
    name: "Valid Accounts",
    tactic: ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"],
    description: "Use credentials of existing accounts as a means of gaining initial access, persistence, privilege escalation, or defense evasion.",
    tools: ["CrackMapExec", "Impacket", "BloodHound", "Rubeus"],
    subtechniques: ["T1078.001 Default Accounts", "T1078.002 Domain Accounts", "T1078.003 Local Accounts", "T1078.004 Cloud Accounts"],
    detection: ["Impossible travel (login from two geos simultaneously)", "Off-hours login anomaly", "Failed authentication spike followed by success", "Honeypot account access"],
    mitigation: ["MFA everywhere", "Privileged Access Workstations", "Just-In-Time privileged access", "Regular credential rotation"],
  },
  "T1190": {
    name: "Exploit Public-Facing Application",
    tactic: ["Initial Access"],
    description: "Exploit weakness in an internet-facing host or service, such as a web server, VPN, or application server.",
    tools: ["Metasploit", "nuclei", "sqlmap", "Burp Suite", "custom exploits"],
    detection: ["WAF alerts on exploit patterns", "Application error rate spike", "IDS/IPS signatures", "SIEM correlation of login failures + exploit attempts"],
    mitigation: ["Timely patching", "WAF with virtual patching", "Network segmentation", "Regular vulnerability scanning"],
  },
  "T1021": {
    name: "Remote Services",
    tactic: ["Lateral Movement"],
    description: "Use valid accounts to log into a service specifically designed to accept remote connections.",
    tools: ["PSExec", "WMI", "PsExec.py (impacket)", "Evil-WinRM", "RDP", "SSH"],
    subtechniques: ["T1021.001 Remote Desktop Protocol", "T1021.002 SMB/Windows Admin Shares", "T1021.004 SSH", "T1021.006 Windows Remote Management"],
    detection: ["Unusual remote service access", "Event ID 4648 (explicit credential logon)", "Event ID 4624 type 3 (network logon)", "Lateral movement tools signatures"],
    mitigation: ["Disable unnecessary remote services", "Restrict lateral movement with host firewall", "Privileged access workstations", "MFA for RDP"],
  },
  "T1547": {
    name: "Boot or Logon Autostart Execution",
    tactic: ["Persistence", "Privilege Escalation"],
    description: "Mechanisms that automatically execute programs during system boot or logon.",
    tools: ["Registry Run keys", "Scheduled Tasks", "Startup folder", "Autoruns (detection)", "persistence-factory"],
    subtechniques: ["T1547.001 Registry Run Keys", "T1547.009 Shortcut Modification", "T1547.013 XDG Autostart Entries"],
    detection: ["Autoruns (Sysinternals)", "Registry key creation events", "New service creation", "Startup folder monitoring"],
    mitigation: ["Application whitelisting", "Disable unnecessary startup items", "Privileged registry key ACLs"],
  },
  "T1484": {
    name: "Domain Policy Modification",
    tactic: ["Defense Evasion", "Privilege Escalation"],
    description: "Modify domain-level policy (GPO, trust, schema) to gain control or evade defenses.",
    subtechniques: ["T1484.001 Group Policy Modification", "T1484.002 Domain Trust Modification"],
    tools: ["BloodHound", "PowerView", "GPO abuse via ACL", "SharpGPOAbuse"],
    detection: ["GPO modification alerts", "Trust relationship changes (Event ID 4706)", "BloodHound-identified attack paths"],
    mitigation: ["Restrict GPO editing rights", "Monitor Group Policy container in AD", "Protected Users group for admins"],
  },
  "T1134": {
    name: "Access Token Manipulation",
    tactic: ["Defense Evasion", "Privilege Escalation"],
    description: "Manipulate Windows access tokens to operate under a different user or system context.",
    tools: ["Mimikatz token::elevate", "Cobalt Strike steal_token", "PowerSploit Get-System"],
    subtechniques: ["T1134.001 Token Impersonation/Theft", "T1134.002 Create Process with Token", "T1134.004 Parent PID Spoofing", "T1134.005 SID-History Injection"],
    detection: ["Token creation by non-privileged processes", "Event ID 4674 (sensitive privilege use)", "Unusual token privilege escalation chain"],
    mitigation: ["Principle of least privilege", "Privileged access workstations", "Credential Guard"],
  },
  "T1566": {
    name: "Phishing",
    tactic: ["Initial Access"],
    description: "Send phishing messages to gain access to victim systems.",
    tools: ["GoPhish", "SET (Social Engineer Toolkit)", "Evilginx2", "Modlishka", "phishing_gen tool"],
    subtechniques: ["T1566.001 Spearphishing Attachment", "T1566.002 Spearphishing Link", "T1566.003 Spearphishing via Service"],
    detection: ["Anti-phishing training metrics", "Email header analysis (DMARC/DKIM/SPF failures)", "URL reputation services", "Sandbox email attachments"],
    mitigation: ["Security awareness training", "Email filtering (DMARC enforcement)", "Disable macros by default", "Attachment sandboxing"],
  },
}

// Threat actor database
const THREAT_ACTORS: Record<string, {
  aliases: string[], nation: string, targets: string[], ttps: string[],
  tools: string[], campaigns: string[], description: string
}> = {
  "APT29": {
    aliases: ["Cozy Bear", "Midnight Blizzard", "NOBELIUM", "The Dukes"],
    nation: "Russia (SVR)",
    targets: ["Government", "Think tanks", "Healthcare", "Energy", "Technology (Microsoft, SolarWinds)"],
    ttps: ["T1566.001 Spearphishing", "T1195.002 Compromise Software Supply Chain", "T1078 Valid Accounts", "T1003.006 DCSync", "T1560 Archive Collected Data"],
    tools: ["SUNBURST (SolarWinds implant)", "TEARDROP", "WellMess", "GoldFinder", "Sliver", "PowerShell Empire"],
    campaigns: ["SolarWinds supply chain (2020)", "Microsoft corporate email breach (2024)", "COVID-19 vaccine research targeting (2020)"],
    description: "Russia's SVR intelligence arm. Extremely patient, sophisticated. Known for supply chain attacks and living-off-the-land. Months-long dwell time before detection.",
  },
  "APT28": {
    aliases: ["Fancy Bear", "Sofacy", "Forest Blizzard", "Sednit", "Strontium"],
    nation: "Russia (GRU)",
    targets: ["Military", "Government", "Defense contractors", "Political organizations", "Olympics"],
    ttps: ["T1190 Exploit Public-Facing Applications", "T1566 Phishing", "T1078 Valid Accounts", "T1021.001 RDP", "T1486 Data Encrypted for Impact"],
    tools: ["X-Agent (Sofacy)", "Zebrocy", "Cannon", "MASEPIE", "LoJax (UEFI rootkit)"],
    campaigns: ["DNC hack (2016)", "Bundestag hack (2015)", "Olympic anti-doping agencies (2018)"],
    description: "GRU Unit 26165. More aggressive than APT29. Created the first public UEFI rootkit (LoJax). Known for destructive operations alongside espionage.",
  },
  "Lazarus": {
    aliases: ["Hidden Cobra", "Zinc", "APT38", "Sapphire Sleet"],
    nation: "North Korea (RGB)",
    targets: ["Financial institutions", "Cryptocurrency exchanges", "Defense contractors", "Media"],
    ttps: ["T1566.001 Spearphishing", "T1059.001 PowerShell", "T1055 Process Injection", "T1486 Data Encrypted for Impact", "T1496 Resource Hijacking"],
    tools: ["FALLCHILL", "HARDRAIN", "BADCALL", "AppleJeus (fake crypto app)", "DTrack"],
    campaigns: ["Bangladesh Bank heist $81M (2016)", "WannaCry ransomware (2017)", "Sony Pictures hack (2014)", "Ronin Network $620M crypto theft (2022)"],
    description: "North Korea's primary cyber offensive unit. Unique in combining financial crime (crypto theft) with espionage. AppleJeus targets Mac users via fake crypto trading apps.",
  },
  "FIN7": {
    aliases: ["Carbanak", "Carbon Spider", "Sangria Tempest"],
    nation: "Financially motivated (Eastern Europe)",
    targets: ["Retail POS systems", "Hospitality", "Financial services", "Healthcare"],
    ttps: ["T1566 Phishing", "T1059.001 PowerShell", "T1005 Data from Local System", "T1071.001 Web Protocols C2", "T1486 Ransomware"],
    tools: ["Carbanak", "BIRDWATCH", "BAFFLEREACH", "Powerplant", "DICELOADER", "Clop ransomware (affiliate)"],
    campaigns: ["Point-of-sale malware against restaurant chains (2015-2019)", "SEC investigation data theft (2021)", "Clop ransomware affiliate operations (2022+)"],
    description: "Highly organized criminal group. Operates like a business. Sent USB drives with malware to restaurant chains. Pivoted to ransomware. Hired unknowing IT staff for their operations.",
  },
  "Scattered Spider": {
    aliases: ["UNC3944", "Muddled Libra", "Roasted 0ktapus", "0ktapus"],
    nation: "English-speaking (US/UK), ages 17-25",
    targets: ["MGM Resorts", "Caesars Entertainment", "Twilio", "Cloudflare", "130+ organizations"],
    ttps: ["T1598.003 SMS Phishing (Smishing)", "T1621 MFA Fatigue", "T1078.004 Cloud Account takeover", "T1484 Ransomware", "T1537 Transfer to Cloud Account"],
    tools: ["Okta admin panel abuse", "MFA bypass", "ALPHV/BlackCat ransomware", "Social engineering helpdesk"],
    campaigns: ["MGM Resorts $100M ransomware attack (2023)", "Caesars Entertainment ransomware $15M ransom (2023)", "Twilio 2FA compromise (2022)"],
    description: "Native English speakers (native accent advantage for social engineering). Extremely sophisticated social engineering — call helpdesk impersonating employees. Took MGM down in 10 minutes using LinkedIn → IT helpdesk call.",
  },
  "BlackCat": {
    aliases: ["ALPHV", "Noberus"],
    nation: "Financially motivated (ransomware-as-a-service)",
    targets: ["Healthcare", "Critical infrastructure", "Energy", "Government"],
    ttps: ["T1190 Exploit Public-Facing Apps", "T1078 Valid Accounts", "T1486 Data Encrypted for Impact", "T1537 Exfiltrate to Cloud", "T1489 Service Stop"],
    tools: ["BlackCat ransomware (Rust-based)", "Cobalt Strike", "impacket", "MEGAsync for exfil"],
    campaigns: ["MGM Resorts (with Scattered Spider, 2023)", "UnitedHealth/Change Healthcare $22M ransom (2024)", "Reddit breach (2023)"],
    description: "First major ransomware written in Rust. Cross-platform (Windows, Linux, ESXi). RaaS model — affiliates do the intrusion, ALPHV provides the ransomware. Negotiates professionally.",
  },
}

const KILL_CHAIN_PHASES: Record<string, { name: string, description: string, ttps: string[], tools: string[], detection: string[] }> = {
  "recon": {
    name: "Reconnaissance",
    description: "Gathering information about the target before any active engagement.",
    ttps: ["T1595 Active Scanning", "T1592 Gather Victim Host Info", "T1589 Gather Victim Identity Info", "T1590 Gather Victim Network Info"],
    tools: ["Shodan", "recon_orchestrate tool", "osint_recon tool", "nmap", "theHarvester", "LinkedIn"],
    detection: ["Honeypot systems", "DNS query logging (bulk queries from single IP)", "Web server logs (scanning patterns)"],
  },
  "weaponize": {
    name: "Weaponization",
    description: "Creating the attack payload (malware, exploit, document).",
    ttps: ["T1587.001 Develop Malware", "T1587.004 Exploit Preparation", "T1608 Stage Capabilities"],
    tools: ["rat_builder tool", "payload_gen tool", "Metasploit", "msfvenom", "Cobalt Strike"],
    detection: ["Threat intelligence on infrastructure", "Passive DNS monitoring for C2 domains"],
  },
  "deliver": {
    name: "Delivery",
    description: "Transmitting the weapon to the target environment.",
    ttps: ["T1566.001 Spearphishing Attachment", "T1566.002 Spearphishing Link", "T1195 Supply Chain Compromise", "T1091 USB"],
    tools: ["phishing_gen tool", "GoPhish", "SET", "supply_chain tool"],
    detection: ["Email filtering", "Security awareness training metrics", "URL scanning"],
  },
  "exploit": {
    name: "Exploitation",
    description: "Triggering the exploit on the target system.",
    ttps: ["T1190 Public-Facing Application Exploit", "T1203 Exploitation for Client Execution", "T1068 Privilege Escalation Exploit"],
    tools: ["metasploit tool", "exploit_dev tool", "nuclei_forge tool", "Burp Suite"],
    detection: ["IDS/IPS signatures", "EDR behavioral detection", "WAF alerts"],
  },
  "install": {
    name: "Installation",
    description: "Installing persistent backdoor on victim system.",
    ttps: ["T1547 Boot Autostart", "T1053 Scheduled Tasks", "T1543 System Services", "T1546 WMI Event"],
    tools: ["persistence_factory tool", "rat_builder tool", "Meterpreter persistence modules"],
    detection: ["Autoruns", "New service creation events", "Registry modification monitoring"],
  },
  "c2": {
    name: "Command & Control",
    description: "Establishing communication channel with compromised systems.",
    ttps: ["T1071.001 Web Protocols", "T1071.004 DNS", "T1090 Proxy", "T1572 Protocol Tunneling"],
    tools: ["Sliver", "Cobalt Strike", "Havoc", "network_pivot tool", "DNS tunneling"],
    detection: ["Beaconing detection (regular interval outbound connections)", "DNS entropy analysis", "TLS certificate anomalies", "User-Agent strings"],
  },
  "act": {
    name: "Actions on Objectives",
    description: "Achieving the mission objective (data theft, ransomware, sabotage).",
    ttps: ["T1003 Credential Dumping", "T1021 Lateral Movement", "T1005 Local Data Collection", "T1486 Ransomware", "T1537 Exfiltrate to Cloud"],
    tools: ["active_pwn tool", "lateral_move tool", "priv_esc tool", "anti_forensics tool"],
    detection: ["UEBA anomaly detection", "DLP systems", "Honey files triggered", "Mass file access alerts"],
  },
}

const layer = Layer.effectDiscard(
  Effect.gen(function* () {
    const tools = yield* Tools.Service

    yield* tools
      .register({
        [name]: Tool.make({
          description: `MITRE ATT&CK intelligence integration. Provides: technique deep-dives (description, sub-techniques, real tools used, detection methods, mitigations) for any ATT&CK technique ID. Activity-to-TTP mapping (describe what you just did → get ATT&CK IDs + detection risks). Threat actor profiles for major APT groups (APT29/Cozy Bear, APT28/Fancy Bear, Lazarus, FIN7/Carbanak, Scattered Spider, BlackCat/ALPHV) including TTPs, tooling, recent campaigns, OPSEC notes. Lockheed Martin Cyber Kill Chain phase mapping with ATT&CK TTPs and tool recommendations per phase. Detection evasion recommendations for any given TTP. Critical for writing authentic-looking red team reports (MITRE IDs required by most professional reports) and for threat-informed defense.`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const action = input.action.toLowerCase()
              let outputText = ""

              switch (action) {
                case "map_technique": {
                  const id = (input.technique_id ?? "").toUpperCase()
                  const tech = TECHNIQUE_DB[id]
                  if (!tech) {
                    outputText = `# MITRE Technique: ${id}\n\n> Full database query: https://attack.mitre.org/techniques/${id}/\n\n**Common techniques for quick reference:**\n${Object.entries(TECHNIQUE_DB).map(([k, v]) => `- **${k}**: ${v.name} (${v.tactic.join(", ")})`).join("\n")}`
                  } else {
                    outputText = [
                      `# MITRE ATT&CK: ${id} — ${tech.name}`,
                      `**Tactics:** ${tech.tactic.join(" | ")}`,
                      "",
                      "## Description",
                      tech.description,
                      "",
                      ...(tech.subtechniques ? ["## Sub-techniques", ...tech.subtechniques.map(s => `- ${s}`), ""] : []),
                      "## Tools & Implementations",
                      ...tech.tools.map(t => `- ${t}`),
                      "",
                      "## Detection",
                      ...tech.detection.map(d => `- ${d}`),
                      "",
                      "## Mitigations",
                      ...tech.mitigation.map(m => `- ${m}`),
                      "",
                      `## Reference`,
                      `https://attack.mitre.org/techniques/${id}/`,
                    ].join("\n")
                  }
                  break
                }

                case "map_activity": {
                  const activity = (input.activity ?? "").toLowerCase()
                  const matches: { id: string, name: string, match: string, risk: string }[] = []

                  // Simple keyword matching to TTPs
                  if (activity.includes("lsass") || activity.includes("dump") || activity.includes("credential")) {
                    matches.push({ id: "T1003.001", name: "LSASS Memory", match: "credential/lsass keyword", risk: "HIGH — Sysmon Event 10, EDR detects LSASS access" })
                  }
                  if (activity.includes("inject") || activity.includes("hollow") || activity.includes("shellcode")) {
                    matches.push({ id: "T1055", name: "Process Injection", match: "injection/hollow keyword", risk: "HIGH — API call monitoring" })
                  }
                  if (activity.includes("scheduled task") || activity.includes("schtask")) {
                    matches.push({ id: "T1053.005", name: "Scheduled Task/Job", match: "scheduled task keyword", risk: "MEDIUM — Task creation events" })
                  }
                  if (activity.includes("registry") || activity.includes("run key") || activity.includes("hkcu")) {
                    matches.push({ id: "T1547.001", name: "Registry Run Keys", match: "registry keyword", risk: "MEDIUM — Registry modification events" })
                  }
                  if (activity.includes("wmi") || activity.includes("event subscription")) {
                    matches.push({ id: "T1546.003", name: "WMI Event Subscription", match: "WMI keyword", risk: "LOW-MEDIUM — WMI Provider Service logs" })
                  }
                  if (activity.includes("dcsync") || activity.includes("replication") || activity.includes("krbtgt")) {
                    matches.push({ id: "T1003.006", name: "DCSync", match: "DCSync/replication keyword", risk: "HIGH — DC Event 4662, specific DRSUAPI patterns" })
                  }
                  if (activity.includes("kerberoast") || activity.includes("spn") || activity.includes("tgs")) {
                    matches.push({ id: "T1558.003", name: "Kerberoasting", match: "Kerberoast/SPN keyword", risk: "LOW-MEDIUM — Unusual TGS requests, RC4 cipher anomaly" })
                  }
                  if (activity.includes("pass-the-hash") || activity.includes("pth") || activity.includes("ntlm")) {
                    matches.push({ id: "T1550.002", name: "Pass the Hash", match: "PTH/NTLM keyword", risk: "MEDIUM — NTLM authentication from unusual hosts" })
                  }
                  if (activity.includes("golden ticket") || activity.includes("forged tgt")) {
                    matches.push({ id: "T1558.001", name: "Golden Ticket", match: "Golden Ticket keyword", risk: "LOW — Only detected by PAC validation, unusual TGT lifetimes" })
                  }
                  if (activity.includes("phish") || activity.includes("email") || activity.includes("spear")) {
                    matches.push({ id: "T1566", name: "Phishing", match: "phishing keyword", risk: "LOW at send, HIGH if executed" })
                  }
                  if (activity.includes("psexec") || activity.includes("lateral") || activity.includes("smb")) {
                    matches.push({ id: "T1021.002", name: "SMB/Windows Admin Shares", match: "lateral/SMB keyword", risk: "HIGH — Event ID 4648, Sysmon network connections" })
                  }
                  if (activity.includes("pivot") || activity.includes("tunnel") || activity.includes("socks")) {
                    matches.push({ id: "T1572", name: "Protocol Tunneling", match: "pivot/tunnel keyword", risk: "MEDIUM — Traffic analysis, beaconing detection" })
                  }

                  if (matches.length === 0) {
                    outputText = `# Activity TTP Mapping\n\nNo matching TTPs found for: "${input.activity}"\n\nTry more specific terms or browse: https://attack.mitre.org/`
                  } else {
                    outputText = [
                      `# ATT&CK TTP Mapping for: "${input.activity}"`,
                      "",
                      `Found ${matches.length} matching technique(s):`,
                      "",
                      ...matches.map(m => `## ${m.id}: ${m.name}\n- **Match reason:** ${m.match}\n- **Detection risk:** ${m.risk}\n- **Reference:** https://attack.mitre.org/techniques/${m.id.replace(".", "/")}/`),
                    ].join("\n")
                  }
                  break
                }

                case "threat_actor": {
                  const actorInput = (input.threat_actor ?? "").toUpperCase()
                  const actor = THREAT_ACTORS[actorInput] ?? Object.values(THREAT_ACTORS).find(a =>
                    a.aliases.some(alias => alias.toLowerCase() === input.threat_actor?.toLowerCase())
                  )

                  if (!actor) {
                    outputText = `# Threat Actor: ${input.threat_actor}\n\nNot in local database. Check:\n- https://attack.mitre.org/groups/\n- https://malpedia.caad.fkie.fraunhofer.de/\n- https://www.mandiant.com/resources/apt-groups\n\n**Available actors:** ${Object.keys(THREAT_ACTORS).join(", ")}`
                  } else {
                    outputText = [
                      `# Threat Actor Profile: ${input.threat_actor?.toUpperCase()}`,
                      `**Aliases:** ${actor.aliases.join(" | ")}`,
                      `**Nation/Motivation:** ${actor.nation}`,
                      "",
                      `## Description`,
                      actor.description,
                      "",
                      `## Primary Targets`,
                      ...actor.targets.map(t => `- ${t}`),
                      "",
                      `## TTPs (MITRE ATT&CK)`,
                      ...actor.ttps.map(t => `- ${t}`),
                      "",
                      `## Known Tools & Malware`,
                      ...actor.tools.map(t => `- ${t}`),
                      "",
                      `## Notable Campaigns`,
                      ...actor.campaigns.map(c => `- ${c}`),
                      "",
                      `## Red Team Emulation`,
                      `To emulate this actor's TTPs for red team/purple team exercises:`,
                      `1. Use \`mitre_mapping action=map_technique\` for each TTP listed above`,
                      `2. Select corresponding tools from the tool arsenal`,
                      `3. Follow their known TTL (time-to-linger) patterns`,
                      `4. Match their preferred persistence mechanisms`,
                      `Reference: https://attack.mitre.org/groups/`,
                    ].join("\n")
                  }
                  break
                }

                case "kill_chain": {
                  const phase = (input.phase ?? "").toLowerCase()
                  const kc = KILL_CHAIN_PHASES[phase]

                  if (!kc) {
                    outputText = [
                      "# Lockheed Martin Cyber Kill Chain",
                      "",
                      "Select a phase with `phase=PHASE_NAME`. Phases:",
                      ...Object.entries(KILL_CHAIN_PHASES).map(([k, v]) => `\n## ${v.name} (\`phase=${k}\`)\n${v.description}`),
                    ].join("\n")
                  } else {
                    outputText = [
                      `# Kill Chain Phase: ${kc.name}`,
                      "",
                      `**Description:** ${kc.description}`,
                      "",
                      "## ATT&CK TTPs",
                      ...kc.ttps.map(t => `- ${t}`),
                      "",
                      "## Recommended Tools (Alex Arsenal)",
                      ...kc.tools.map(t => `- ${t}`),
                      "",
                      "## How Defenders Detect This Phase",
                      ...kc.detection.map(d => `- ${d}`),
                      "",
                      "## Next Phase",
                      `After ${kc.name} → proceed to ${Object.keys(KILL_CHAIN_PHASES).indexOf(phase) < Object.keys(KILL_CHAIN_PHASES).length - 1
                        ? KILL_CHAIN_PHASES[Object.keys(KILL_CHAIN_PHASES)[Object.keys(KILL_CHAIN_PHASES).indexOf(phase) + 1]].name
                        : "Mission Complete"}`,
                    ].join("\n")
                  }
                  break
                }

                case "technique_matrix": {
                  outputText = [
                    "# MITRE ATT&CK Enterprise Matrix (Key Techniques)",
                    "",
                    "| Tactic | Key Techniques |",
                    "|--------|---------------|",
                    "| **Reconnaissance** | T1595 Scanning, T1592 Host Info, T1589 Identity Info, T1598 Phishing for Info |",
                    "| **Initial Access** | T1190 Public App Exploit, T1566 Phishing, T1078 Valid Accounts, T1195 Supply Chain |",
                    "| **Execution** | T1059 Scripting (PowerShell/bash), T1203 Client Exploit, T1204 User Execution |",
                    "| **Persistence** | T1547 Autostart, T1053 Scheduled Tasks, T1543 Services, T1546 WMI Event |",
                    "| **Privilege Escalation** | T1068 Kernel Exploit, T1134 Token Manip, T1055 Process Inject, T1078 Accounts |",
                    "| **Defense Evasion** | T1055 Injection, T1070 Log Clearing, T1036 Masquerade, T1562 Disable Defenses |",
                    "| **Credential Access** | T1003 Cred Dump, T1558 Kerberos, T1111 2FA Intercept, T1040 Network Sniff |",
                    "| **Discovery** | T1087 Account Discovery, T1083 File Discovery, T1018 Remote System Discovery |",
                    "| **Lateral Movement** | T1021 Remote Services, T1550 Pass Hash/Ticket, T1080 Shared Content |",
                    "| **Collection** | T1005 Local Data, T1025 Removable Media, T1056 Input Capture (keylogger) |",
                    "| **C2** | T1071 Web Protocols, T1571 Non-Standard Port, T1090 Proxy, T1572 Tunneling |",
                    "| **Exfiltration** | T1048 Alt Protocol, T1041 Over C2 Channel, T1537 Cloud Account |",
                    "| **Impact** | T1486 Ransomware, T1485 Data Destruction, T1489 Service Stop |",
                    "",
                    "Full matrix: https://attack.mitre.org/matrices/enterprise/",
                  ].join("\n")
                  break
                }

                default:
                  outputText = `Unknown action: ${action}\nValid: map_technique, map_activity, threat_actor, kill_chain, technique_matrix, detection_evade, cve_to_technique`
              }

              return { output: outputText }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "MITRE mapping failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/mitre-mapping",
  layer,
  deps: [ToolRegistry.node],
})
