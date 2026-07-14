export * as BuiltInTools from "./builtins"

import { makeLocationNode } from "../effect/app-node"
import { Layer } from "effect"
import { BashTool } from "./bash"
import { ApplyPatchTool } from "./apply-patch"
import { EditTool } from "./edit"
import { GlobTool } from "./glob"
import { GrepTool } from "./grep"
import { QuestionTool } from "./question"
import { ReadTool } from "./read"
import { SkillTool } from "./skill"
import { TodoWriteTool } from "./todowrite"
import { WebFetchTool } from "./webfetch"
import { WebSearchTool } from "./websearch"
import { WriteTool } from "./write"
import { NmapScanTool } from "./nmap-scan"
import { SubdomainEnumTool } from "./subdomain-enum"
import { VulnScanTool } from "./vuln-scan"
import { DirBruteTool } from "./dir-brute"
import { SqliTestTool } from "./sqli-test"
import { OsintReconTool } from "./osint-recon"
import { ToolInstallerTool } from "./tool-installer"
import { ReportGenTool } from "./report-gen"
// New tools — autonomous hacking agent
import { ExploitSearchTool } from "./exploit-search"
import { CveLookupTool } from "./cve-lookup"
import { MetasploitTool } from "./metasploit"
import { ReverseShellTool } from "./reverse-shell"
import { PayloadGenTool } from "./payload-gen"
import { CredBruteTool } from "./cred-brute"
import { HashCrackTool } from "./hash-crack"
import { C2ListenerTool } from "./c2-listener"
import { LateralMoveTool } from "./lateral-move"
import { PrivEscTool } from "./priv-esc"
import { ExfilDataTool } from "./exfil-data"
import { PhoneLookupTool } from "./phone-lookup"
import { SocialProfileTool } from "./social-profile"
import { DarkwebSearchTool } from "./darkweb-search"
import { WpScanTool } from "./wpscan"
import { SshAuditTool } from "./ssh-audit"
import { ApkDecompileTool } from "./apk-decompile"
import { ApkModifyTool } from "./apk-modify"
import { NetworkSniffTool } from "./network-sniff"
import { WifiAuditTool } from "./wifi-audit"
import { DnsReconTool } from "./dns-recon"
import { SslAuditTool } from "./ssl-audit"
import { WebFuzzTool } from "./web-fuzz"
import { XssTestTool } from "./xss-test"
import { PhishingGenTool } from "./phishing-gen"
// Advanced bug bounty tools
import { SubdomainTakeoverTool } from "./subdomain-takeover"
import { CloudBucketTool } from "./cloud-bucket"
import { JwtAbuseTool } from "./jwt-abuse"
import { CorsTestTool } from "./cors-test"
import { GraphqlTestTool } from "./graphql-test"
import { SecretScannerTool } from "./secret-scanner"
// Phase 1 — Expansion Tools
import { AdAttackTool } from "./ad-attack"
import { CloudAttackTool } from "./cloud-attack"
import { ContainerAttackTool } from "./container-attack"
import { MitmAttackTool } from "./mitm-attack"
import { BeefHookTool } from "./beef-hook"
import { FirmwareAnalysisTool } from "./firmware-analysis"
import { BinaryExploitTool } from "./binary-exploit"
import { StegoTool } from "./stego-tool"
import { AntiForensicsTool } from "./anti-forensics"
import { WafBypassTool } from "./waf-bypass"
import { IotScadaTool } from "./iot-scada"
import { VoipAttackTool } from "./voip-attack"

/**
 * Composes only the shipped Location-scoped built-in tool transforms.
 * Each tool retains its implementation and focused tests independently. Dynamic
 * MCP and plugin tools later use separate scoped canonical registrations, while
 * provider/model filtering belongs to a future materialization phase rather
 * than this static list. The caller intentionally supplies shared Location
 * services once to this merged set.
 *
 * TODO: Port the remaining launch-follow-up leaves deliberately: edit fuzzy
 * parity, task, LSP,
 * repo_clone, repo_overview, plan_exit, and Rune/code mode. Keep MCP and plugin
 * transforms separate from this static built-in list.
 */
export const node = makeLocationNode({
  name: "built-in-tools",
  layer: Layer.empty,
  deps: [
    ApplyPatchTool.node,
    BashTool.node,
    EditTool.node,
    GlobTool.node,
    GrepTool.node,
    QuestionTool.node,
    ReadTool.node,
    SkillTool.node,
    TodoWriteTool.node,
    WebFetchTool.node,
    WebSearchTool.node,
    WriteTool.node,
    // Red Team Security Tools
    NmapScanTool.node,
    SubdomainEnumTool.node,
    VulnScanTool.node,
    DirBruteTool.node,
    SqliTestTool.node,
    OsintReconTool.node,
    ToolInstallerTool.node,
    ReportGenTool.node,
    // Autonomous Hacking Agent Tools
    ExploitSearchTool.node,
    CveLookupTool.node,
    MetasploitTool.node,
    ReverseShellTool.node,
    PayloadGenTool.node,
    CredBruteTool.node,
    HashCrackTool.node,
    C2ListenerTool.node,
    LateralMoveTool.node,
    PrivEscTool.node,
    ExfilDataTool.node,
    PhoneLookupTool.node,
    SocialProfileTool.node,
    DarkwebSearchTool.node,
    WpScanTool.node,
    SshAuditTool.node,
    ApkDecompileTool.node,
    ApkModifyTool.node,
    NetworkSniffTool.node,
    WifiAuditTool.node,
    DnsReconTool.node,
    SslAuditTool.node,
    WebFuzzTool.node,
    XssTestTool.node,
    PhishingGenTool.node,
    // Advanced Bug Bounty Tools
    SubdomainTakeoverTool.node,
    CloudBucketTool.node,
    JwtAbuseTool.node,
    CorsTestTool.node,
    GraphqlTestTool.node,
    SecretScannerTool.node,
    // Phase 1 — Expansion Tools
    AdAttackTool.node,
    CloudAttackTool.node,
    ContainerAttackTool.node,
    MitmAttackTool.node,
    BeefHookTool.node,
    FirmwareAnalysisTool.node,
    BinaryExploitTool.node,
    StegoTool.node,
    AntiForensicsTool.node,
    WafBypassTool.node,
    IotScadaTool.node,
    VoipAttackTool.node,
  ],
})

