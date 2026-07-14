export * as ToolInstallerTool from "./tool-installer"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "tool_installer"

const TOOL_INSTALL_MAP: Record<string, { windows: string; linux: string; check: string }> = {
  // === NETWORK SCANNING & ENUMERATION ===
  nmap: {
    windows: "choco install nmap -y",
    linux: "sudo apt install nmap -y",
    check: "nmap --version",
  },
  masscan: {
    windows: "choco install masscan -y",
    linux: "sudo apt install masscan -y",
    check: "masscan --version",
  },
  rustscan: {
    windows: "cargo install rustscan",
    linux: "cargo install rustscan",
    check: "rustscan --version",
  },
  // === WEB VULNERABILITY SCANNING ===
  nuclei: {
    windows: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    linux: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    check: "nuclei -version",
  },
  nikto: {
    windows: "pip install nikto",
    linux: "sudo apt install nikto -y",
    check: "nikto -Version",
  },
  // === SUBDOMAIN & DNS ENUMERATION ===
  subfinder: {
    windows: "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    linux: "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    check: "subfinder -version",
  },
  amass: {
    windows: "go install github.com/owasp-amass/amass/v4/...@master",
    linux: "go install github.com/owasp-amass/amass/v4/...@master",
    check: "amass -version",
  },
  dnsx: {
    windows: "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    linux: "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    check: "dnsx -version",
  },
  dnsrecon: {
    windows: "pip install dnsrecon",
    linux: "pip install dnsrecon",
    check: "dnsrecon --version",
  },
  // === DIRECTORY BRUTE FORCING & FUZZING ===
  gobuster: {
    windows: "go install github.com/OJ/gobuster/v3@latest",
    linux: "go install github.com/OJ/gobuster/v3@latest",
    check: "gobuster version",
  },
  ffuf: {
    windows: "go install github.com/ffuf/ffuf/v2@latest",
    linux: "go install github.com/ffuf/ffuf/v2@latest",
    check: "ffuf -V",
  },
  feroxbuster: {
    windows: "cargo install feroxbuster",
    linux: "sudo apt install feroxbuster -y",
    check: "feroxbuster --version",
  },
  wfuzz: {
    windows: "pip install wfuzz",
    linux: "pip install wfuzz",
    check: "wfuzz --version",
  },
  // === SQL INJECTION ===
  sqlmap: {
    windows: "pip install sqlmap",
    linux: "pip install sqlmap",
    check: "sqlmap --version",
  },
  // === XSS & COMMAND INJECTION ===
  dalfox: {
    windows: "go install github.com/hahwul/dalfox/v2@latest",
    linux: "go install github.com/hahwul/dalfox/v2@latest",
    check: "dalfox version",
  },
  commix: {
    windows: "pip install commix",
    linux: "pip install commix",
    check: "commix --version",
  },
  // === OSINT ===
  theharvester: {
    windows: "pip install theHarvester",
    linux: "pip install theHarvester",
    check: "theHarvester --help",
  },
  whatweb: {
    windows: "gem install whatweb",
    linux: "sudo apt install whatweb -y",
    check: "whatweb --version",
  },
  httpx: {
    windows: "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
    linux: "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
    check: "httpx -version",
  },
  sherlock: {
    windows: "pip install sherlock-project",
    linux: "pip install sherlock-project",
    check: "sherlock --version",
  },
  maigret: {
    windows: "pip install maigret",
    linux: "pip install maigret",
    check: "maigret --version",
  },
  metagoofil: {
    windows: "pip install metagoofil",
    linux: "pip install metagoofil",
    check: "metagoofil --help",
  },
  photon: {
    windows: "pip install photon",
    linux: "pip install photon",
    check: "photon --version",
  },
  // === WAF DETECTION ===
  wafw00f: {
    windows: "pip install wafw00f",
    linux: "pip install wafw00f",
    check: "wafw00f --version",
  },
  // === WORDPRESS ===
  wpscan: {
    windows: "gem install wpscan",
    linux: "sudo apt install wpscan -y || gem install wpscan",
    check: "wpscan --version",
  },
  // === SSH AUDIT ===
  "ssh-audit": {
    windows: "pip install ssh-audit",
    linux: "pip install ssh-audit",
    check: "ssh-audit --version",
  },
  // === SSL/TLS ===
  sslscan: {
    windows: "choco install sslscan -y",
    linux: "sudo apt install sslscan -y",
    check: "sslscan --version",
  },
  testssl: {
    windows: "choco install testssl -y",
    linux: "sudo apt install testssl.sh -y",
    check: "testssl --version",
  },
  // === CREDENTIAL BRUTE FORCING ===
  hydra: {
    windows: "choco install hydra -y",
    linux: "sudo apt install hydra -y",
    check: "hydra -h",
  },
  medusa: {
    windows: "choco install medusa -y",
    linux: "sudo apt install medusa -y",
    check: "medusa -V",
  },
  netexec: {
    windows: "pip install netexec",
    linux: "pip install netexec",
    check: "netexec --version",
  },
  crackmapexec: {
    windows: "pip install crackmapexec",
    linux: "pip install crackmapexec",
    check: "crackmapexec --version",
  },
  // === HASH CRACKING ===
  hashcat: {
    windows: "choco install hashcat -y",
    linux: "sudo apt install hashcat -y",
    check: "hashcat --version",
  },
  john: {
    windows: "choco install john -y",
    linux: "sudo apt install john -y",
    check: "john --version",
  },
  hashid: {
    windows: "pip install hashid",
    linux: "pip install hashid",
    check: "hashid --help",
  },
  // === EXPLOITATION FRAMEWORKS ===
  metasploit: {
    windows: "choco install metasploit-framework -y",
    linux: "sudo apt install metasploit-framework -y",
    check: "msfconsole --version",
  },
  searchsploit: {
    windows: "git clone https://github.com/offensive-security/exploitdb.git C:\\exploitdb",
    linux: "sudo apt install exploitdb -y",
    check: "searchsploit --version",
  },
  // === IMPACKET (Lateral Movement / AD) ===
  impacket: {
    windows: "pip install impacket",
    linux: "pip install impacket",
    check: "psexec.py --help",
  },
  bloodhound: {
    windows: "pip install bloodhound-ce",
    linux: "pip install bloodhound",
    check: "bloodhound-python --help",
  },
  // === MOBILE / APK ===
  apktool: {
    windows: "choco install apktool -y",
    linux: "sudo apt install apktool -y",
    check: "apktool --version",
  },
  jadx: {
    windows: "choco install jadx -y",
    linux: "sudo apt install jadx -y || snap install jadx",
    check: "jadx --version",
  },
  frida: {
    windows: "pip install frida-tools",
    linux: "pip install frida-tools",
    check: "frida --version",
  },
  aapt: {
    windows: "choco install android-sdk -y",
    linux: "sudo apt install aapt -y",
    check: "aapt version",
  },
  apksigner: {
    windows: "choco install android-sdk -y",
    linux: "sudo apt install apksigner -y",
    check: "apksigner --version",
  },
  // === NETWORK CAPTURE ===
  tcpdump: {
    windows: "choco install tcpdump -y",
    linux: "sudo apt install tcpdump -y",
    check: "tcpdump --version",
  },
  tshark: {
    windows: "choco install wireshark -y",
    linux: "sudo apt install tshark -y",
    check: "tshark --version",
  },
  // === WIFI ===
  aircrack: {
    windows: "choco install aircrack-ng -y",
    linux: "sudo apt install aircrack-ng -y",
    check: "aircrack-ng --version",
  },
  reaver: {
    windows: "echo 'Reaver is Linux-only'",
    linux: "sudo apt install reaver -y",
    check: "reaver --help",
  },
  wifiphisher: {
    windows: "echo 'Wifiphisher is Linux-only'",
    linux: "sudo apt install wifiphisher -y || pip install wifiphisher",
    check: "wifiphisher --help",
  },
  // === DARK WEB / TOR ===
  tor: {
    windows: "choco install tor -y",
    linux: "sudo apt install tor -y",
    check: "tor --version",
  },
  onionscan: {
    windows: "go install github.com/s-rah/onionscan@latest",
    linux: "go install github.com/s-rah/onicscan@latest",
    check: "onionscan --version",
  },
  // === POST-EXPLOITATION ===
  linpeas: {
    windows: "echo 'LinPEAS is Linux-only'",
    linux: "curl -sL https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh -o /usr/local/bin/linpeas && chmod +x /usr/local/bin/linpeas",
    check: "test -f /usr/local/bin/linpeas",
  },
  // === TUNNELING / PIVOTING ===
  chisel: {
    windows: "choco install chisel -y",
    linux: "go install github.com/jpillora/chisel@latest",
    check: "chisel --version",
  },
  ligolo: {
    windows: "go install github.com/nicocha30/ligolo-ng@latest",
    linux: "go install github.com/nicocha30/ligolo-ng@latest",
    check: "ligolo-ng --help",
  },
  socat: {
    windows: "choco install socat -y",
    linux: "sudo apt install socat -y",
    check: "socat -V",
  },
  proxychains: {
    windows: "echo 'proxychains is Linux-only'",
    linux: "sudo apt install proxychains4 -y",
    check: "proxychains --version",
  },
  // === WORDLISTS ===
  seclists: {
    windows: "git clone https://github.com/danielmiessler/SecLists.git C:\\SecLists",
    linux: "sudo apt install seclists -y || git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists",
    check: "ls /usr/share/seclists || dir C:\\SecLists",
  },
  rockyou: {
    windows: "curl -sL https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt -o C:\\rockyou.txt",
    linux: "sudo apt install wordlists -y || curl -sL https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt -o /usr/share/wordlists/rockyou.txt",
    check: "test -f /usr/share/wordlists/rockyou.txt || test -f C:\\rockyou.txt",
  },
  // === MISCELLANEOUS ===
  curl: {
    windows: "choco install curl -y",
    linux: "sudo apt install curl -y",
    check: "curl --version",
  },
  jq: {
    windows: "choco install jq -y",
    linux: "sudo apt install jq -y",
    check: "jq --version",
  },
  git: {
    windows: "choco install git -y",
    linux: "sudo apt install git -y",
    check: "git --version",
  },
  python3: {
    windows: "choco install python3 -y",
    linux: "sudo apt install python3 python3-pip -y",
    check: "python3 --version",
  },
  go: {
    windows: "choco install golang -y",
    linux: "sudo apt install golang -y",
    check: "go version",
  },
  ruby: {
    windows: "choco install ruby -y",
    linux: "sudo apt install ruby -y",
    check: "ruby --version",
  },
  cargo: {
    windows: "choco install rust-ms -y",
    linux: "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh",
    check: "cargo --version",
  },
}

export const Input = Schema.Struct({
  tool_name: Schema.String.annotate({
    description: `Name of the security tool to check/install. Supported: ${Object.keys(TOOL_INSTALL_MAP).join(", ")}`,
  }),
  action: Schema.String.pipe(Schema.optional).annotate({
    description: "Action: 'check' (verify if installed), 'install' (install if missing), 'force' (reinstall). Default: 'install'.",
  }),
})

const Output = Schema.Struct({
  output: Schema.String,
  installed: Schema.Boolean,
})

type Output = typeof Output.Type

const layer = Layer.effectDiscard(
  Effect.gen(function* () {
    const tools = yield* Tools.Service
    const appProcess = yield* AppProcess.Service

    yield* tools
      .register({
        [name]: Tool.make({
          description: `Check if a security tool is installed and install it if missing. Self-bootstrapping capability for the red team agent. Supports: ${Object.keys(TOOL_INSTALL_MAP).join(", ")}. Automatically selects the right package manager for the platform.`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const toolInfo = TOOL_INSTALL_MAP[input.tool_name.toLowerCase()]
              if (!toolInfo) {
                return {
                  output: `Unknown tool: ${input.tool_name}. Supported tools: ${Object.keys(TOOL_INSTALL_MAP).join(", ")}. Use the bash tool to install manually.`,
                  installed: false,
                }
              }

              const action = input.action ?? "install"
              const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"

              // Check if already installed
              if (action === "check" || action === "install") {
                const checkCmd = ChildProcess.make(toolInfo.check, [], {
                  shell,
                  stdin: "ignore",
                  forceKillAfter: Duration.seconds(3),
                })
                const checkResult = yield* appProcess
                  .run(checkCmd, {
                    combineOutput: true,
                    timeout: Duration.seconds(10),
                    maxOutputBytes: 64 * 1024,
                  })
                  .pipe(
                    Effect.catchTag("AppProcessError", () =>
                      Effect.succeed(undefined),
                    ),
                  )

                if (checkResult && checkResult.exitCode === 0) {
                  const version = checkResult.output?.toString("utf8")?.trim() ?? ""
                  return {
                    output: `✅ ${input.tool_name} is already installed.\n${version}`,
                    installed: true,
                  }
                }

                if (action === "check") {
                  return {
                    output: `❌ ${input.tool_name} is NOT installed.`,
                    installed: false,
                  }
                }
              }

              // Install the tool
              const installCmd = process.platform === "win32" ? toolInfo.windows : toolInfo.linux
              const installProcess = ChildProcess.make(installCmd, [], {
                shell,
                stdin: "ignore",
                forceKillAfter: Duration.seconds(3),
              })
              const installResult = yield* appProcess
                .run(installProcess, {
                  combineOutput: true,
                  timeout: Duration.minutes(5),
                  maxOutputBytes: 512 * 1024,
                })
                .pipe(
                  Effect.catchTag("AppProcessError", () =>
                    Effect.succeed(undefined),
                  ),
                )

              if (!installResult || installResult.exitCode !== 0) {
                const errOutput = installResult?.output?.toString("utf8") ?? ""
                return {
                  output: `❌ Failed to install ${input.tool_name} via: ${installCmd}\n${errOutput}\nTry installing manually.`,
                  installed: false,
                }
              }

              return {
                output: `✅ Successfully installed ${input.tool_name} via: ${installCmd}\n${installResult.output?.toString("utf8") ?? ""}`,
                installed: true,
              }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: `Tool installer failed for ${input.tool_name}` }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/tool-installer",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
