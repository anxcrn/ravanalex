export * as BuiltInTools from "./builtins"

import { makeLocationNode } from "../effect/app-node"
import { Layer } from "effect"

// ─── Core Tools ───────────────────────────────────────────────────────────────
import { ApplyPatchTool } from "./apply-patch"
import { BashTool } from "./bash"
import { GlobTool } from "./glob"
import { GrepTool } from "./grep"
import { QuestionTool } from "./question"
import { ReadTool } from "./read"
import { ReadToolFileSystem } from "./read-filesystem"
import { SkillTool } from "./skill"
import { WebFetchTool } from "./webfetch"
import { WebSearchTool } from "./websearch"

// ─── Recon & OSINT ────────────────────────────────────────────────────────────
import { NmapScanTool } from "./nmap-scan"
import { SubdomainEnumTool } from "./subdomain-enum"
import { SubdomainTakeoverTool } from "./subdomain-takeover"
import { DirBruteTool } from "./dir-brute"
import { OsintReconTool } from "./osint-recon"
import { DnsReconTool } from "./dns-recon"
import { PhoneLookupTool } from "./phone-lookup"
import { SocialProfileTool } from "./social-profile"
import { DarkwebSearchTool } from "./darkweb-search"

// ─── Web Exploitation ─────────────────────────────────────────────────────────
import { SqliTestTool } from "./sqli-test"
import { XssTestTool } from "./xss-test"
import { CorsTestTool } from "./cors-test"
import { GraphqlTestTool } from "./graphql-test"
import { WafBypassTool } from "./waf-bypass"
import { WebFuzzTool } from "./web-fuzz"
import { WpScanTool } from "./wpscan"
import { JwtAbuseTool } from "./jwt-abuse"
import { PromptInjectTool } from "./prompt-inject"
import { RouterExploitTool } from "./router-exploit"
import { DbExploitTool } from "./db-exploit"
import { ApiMassacreTool } from "./api-massacre"

// ─── Vulnerability & Exploit ──────────────────────────────────────────────────
import { VulnScanTool } from "./vuln-scan"
import { ExploitSearchTool } from "./exploit-search"
import { CveLookupTool } from "./cve-lookup"
import { MetasploitTool } from "./metasploit"
import { PayloadGenTool } from "./payload-gen"
import { AutoFuzzerTool } from "./auto-fuzzer"

// ─── Credential & Auth Attacks ────────────────────────────────────────────────
import { CredBruteTool } from "./cred-brute"
import { HashCrackTool } from "./hash-crack"
import { SshAuditTool } from "./ssh-audit"
import { SslAuditTool } from "./ssl-audit"

// ─── Network Attacks ──────────────────────────────────────────────────────────
import { NetworkPivotTool } from "./network-pivot"
import { NetworkSniffTool } from "./network-sniff"
import { MitmAttackTool } from "./mitm-attack"
import { WifiAuditTool } from "./wifi-audit"
import { BtAttackTool } from "./bt-attack"
import { DdosTool } from "./ddos-tool"

// ─── Post-Exploitation ────────────────────────────────────────────────────────
import { LateralMoveTool } from "./lateral-move"
import { PrivEscTool } from "./priv-esc"
import { ExfilDataTool } from "./exfil-data"
import { AntiForensicsTool } from "./anti-forensics"
import { C2ListenerTool } from "./c2-listener"
import { RatBuilderTool } from "./rat-builder"
import { UsbPayloadTool } from "./usb-payload"

// ─── Active Directory ─────────────────────────────────────────────────────────
import { ActivePwnTool } from "./active-pwn"
import { AdAttackTool } from "./ad-attack"

// ─── Cloud & Container ────────────────────────────────────────────────────────
import { CloudAttackTool } from "./cloud-attack"
import { CloudBucketTool } from "./cloud-bucket"
import { CloudPwnTool } from "./cloud-pwn"
import { ContainerAttackTool } from "./container-attack"

// ─── Mobile ───────────────────────────────────────────────────────────────────
import { Mobile0DayTool } from "./mobile-0day"
import { ApkDecompileTool } from "./apk-decompile"
import { ApkModifyTool } from "./apk-modify"

// ─── Malware & C2 ─────────────────────────────────────────────────────────────
import { BotnetOrchestratorTool } from "./botnet-orchestrator"
import { SwarmBotnetTool } from "./swarm-botnet"
import { UefiBootkitTool } from "./uefi-bootkit"
import { PhishingGenTool } from "./phishing-gen"
import { DeepfakeGenTool } from "./deepfake-gen"
import { EmailTakeoverTool } from "./email-takeover"

// ─── Binary & Kernel ──────────────────────────────────────────────────────────
import { BinaryExploitTool } from "./binary-exploit"
import { KernelExploitTool } from "./kernel-exploit"
import { FirmwareAnalysisTool } from "./firmware-analysis"
import { VmEscapeTool } from "./vm-escape"

// ─── Hardware / RF / Physical ─────────────────────────────────────────────────
import { HardwareRfTool } from "./hardware-rf"
import { ProximityPwnTool } from "./proximity-pwn"
import { RfidNfcTool } from "./rfid-nfc"
import { IotScadaTool } from "./iot-scada"
import { OtPwnTool } from "./ot-pwn"
import { Ss7InterceptTool } from "./ss7-intercept"
import { MainframePwnTool } from "./mainframe-pwn"
import { VehiclePwnTool } from "./vehicle-pwn"
import { AerospacePwnTool } from "./aerospace-pwn"

// ─── Cryptographic & Stealth ──────────────────────────────────────────────────
import { CryptoAttackTool } from "./crypto-attack"
import { StegoTool } from "./stego-tool"
import { CovertCommsTool } from "./covert-comms"
import { QuantumHarvestTool } from "./quantum-harvest"

// ─── Social Engineering ───────────────────────────────────────────────────────
import { SocialEngineeringTool } from "./social-engineering"
import { BeefHookTool } from "./beef-hook"

// ─── Supply Chain & Web3 ──────────────────────────────────────────────────────
import { SupplyChainTool } from "./supply-chain"
import { Web3PwnTool } from "./web3-pwn"
import { SecretScannerTool } from "./secret-scanner"

// ─── Exotic / Next-Gen ────────────────────────────────────────────────────────
import { BmcPwnTool } from "./bmc-pwn"
import { SiliconExploitTool } from "./silicon-exploit"
import { BgpPwnTool } from "./bgp-pwn"
import { BiometricPwnTool } from "./biometric-pwn"
import { BioPwnTool } from "./bio-pwn"
import { KineticPwnTool } from "./kinetic-pwn"
import { HftPwnTool } from "./hft-pwn"
import { BciPwnTool } from "./bci-pwn"
import { SideChannelPwnTool } from "./side-channel-pwn"
import { TelecomCorePwnTool } from "./telecom-core-pwn"
import { AiAdversarialTool } from "./ai-adversarial"
import { VoipAttackTool } from "./voip-attack"

// ─── Intelligence & Reporting ─────────────────────────────────────────────────
import { MitreMappingTool } from "./mitre-mapping"
import { ReportGenTool } from "./report-gen"
import { ToolInstallerTool } from "./tool-installer"

// ─── Knowledge Oracle ─────────────────────────────────────────────────────────
// knowledge-oracle uses zod, not Effect, so it self-registers — referenced from skills

/**
 * ALEX FULL BUILT-IN TOOL REGISTRY — ALL 110+ TOOLS
 * Covers every offensive domain: Web, Network, Cloud, AD, Mobile,
 * Hardware/RF, Binary/Kernel, Social Engineering, Crypto, Web3,
 * Exotic/Nation-State, Intelligence, and Utility.
 */
export const node = makeLocationNode({
  name: "built-in-tools",
  layer: Layer.empty,
  deps: [
    // ── Core ──────────────────────────────────────────────────────────────
    ApplyPatchTool.node,
    BashTool.node,
    GlobTool.node,
    GrepTool.node,
    QuestionTool.node,
    ReadTool.node,
    ReadToolFileSystem.node,
    SkillTool.node,
    WebFetchTool.node,
    WebSearchTool.node,

    // ── Recon & OSINT ────────────────────────────────────────────────────
    NmapScanTool.node,
    SubdomainEnumTool.node,
    SubdomainTakeoverTool.node,
    DirBruteTool.node,
    OsintReconTool.node,
    DnsReconTool.node,
    PhoneLookupTool.node,
    SocialProfileTool.node,
    DarkwebSearchTool.node,

    // ── Web Exploitation ─────────────────────────────────────────────────
    SqliTestTool.node,
    XssTestTool.node,
    CorsTestTool.node,
    GraphqlTestTool.node,
    WafBypassTool.node,
    WebFuzzTool.node,
    WpScanTool.node,
    JwtAbuseTool.node,
    PromptInjectTool.node,
    RouterExploitTool.node,
    DbExploitTool.node,
    ApiMassacreTool.node,

    // ── Vulnerability & Exploit ──────────────────────────────────────────
    VulnScanTool.node,
    ExploitSearchTool.node,
    CveLookupTool.node,
    MetasploitTool.node,
    PayloadGenTool.node,
    AutoFuzzerTool.node,

    // ── Credential & Auth ────────────────────────────────────────────────
    CredBruteTool.node,
    HashCrackTool.node,
    SshAuditTool.node,
    SslAuditTool.node,

    // ── Network ──────────────────────────────────────────────────────────
    NetworkPivotTool.node,
    NetworkSniffTool.node,
    MitmAttackTool.node,
    WifiAuditTool.node,
    BtAttackTool.node,
    DdosTool.node,

    // ── Post-Exploitation ────────────────────────────────────────────────
    LateralMoveTool.node,
    PrivEscTool.node,
    ExfilDataTool.node,
    AntiForensicsTool.node,
    C2ListenerTool.node,
    RatBuilderTool.node,
    UsbPayloadTool.node,

    // ── Active Directory ─────────────────────────────────────────────────
    ActivePwnTool.node,
    AdAttackTool.node,

    // ── Cloud & Container ────────────────────────────────────────────────
    CloudAttackTool.node,
    CloudBucketTool.node,
    CloudPwnTool.node,
    ContainerAttackTool.node,

    // ── Mobile ───────────────────────────────────────────────────────────
    Mobile0DayTool.node,
    ApkDecompileTool.node,
    ApkModifyTool.node,

    // ── Malware & C2 ─────────────────────────────────────────────────────
    BotnetOrchestratorTool.node,
    SwarmBotnetTool.node,
    UefiBootkitTool.node,
    PhishingGenTool.node,
    DeepfakeGenTool.node,
    EmailTakeoverTool.node,

    // ── Binary & Kernel ──────────────────────────────────────────────────
    BinaryExploitTool.node,
    KernelExploitTool.node,
    FirmwareAnalysisTool.node,
    VmEscapeTool.node,

    // ── Hardware / RF / Physical ─────────────────────────────────────────
    HardwareRfTool.node,
    ProximityPwnTool.node,
    RfidNfcTool.node,
    IotScadaTool.node,
    OtPwnTool.node,
    Ss7InterceptTool.node,
    MainframePwnTool.node,
    VehiclePwnTool.node,
    AerospacePwnTool.node,

    // ── Crypto & Stealth ─────────────────────────────────────────────────
    CryptoAttackTool.node,
    StegoTool.node,
    CovertCommsTool.node,
    QuantumHarvestTool.node,

    // ── Social Engineering ───────────────────────────────────────────────
    SocialEngineeringTool.node,
    BeefHookTool.node,

    // ── Supply Chain & Web3 ──────────────────────────────────────────────
    SupplyChainTool.node,
    Web3PwnTool.node,
    SecretScannerTool.node,

    // ── Exotic / Nation-State ────────────────────────────────────────────
    BmcPwnTool.node,
    SiliconExploitTool.node,
    BgpPwnTool.node,
    BiometricPwnTool.node,
    BioPwnTool.node,
    KineticPwnTool.node,
    HftPwnTool.node,
    BciPwnTool.node,
    SideChannelPwnTool.node,
    TelecomCorePwnTool.node,
    AiAdversarialTool.node,
    VoipAttackTool.node,

    // ── Intelligence & Reporting ─────────────────────────────────────────
    MitreMappingTool.node,
    ReportGenTool.node,
    ToolInstallerTool.node,
  ],
})
