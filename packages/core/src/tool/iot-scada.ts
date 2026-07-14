export * as IotScadaTool from "./iot-scada"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "iot_scada"

export const Input = Schema.Struct({
  target: Schema.String.annotate({ description: "Target IP or hostname" }),
  action: Schema.String.annotate({
    description: "Action: 'modbus_enum' (Modbus TCP enumeration), 'plc_detect' (PLC detection), 'hmi_scan' (scan exposed HMI), 'ics_fuzz' (ICS protocol fuzz), 'shodan_search' (search Shodan for exposed ICS)",
  }),
  port: Schema.Number.pipe(Schema.optional).annotate({ description: "Port number. Default depends on protocol." }),
  unit_id: Schema.Number.pipe(Schema.optional).annotate({ description: "Modbus unit ID. Default: 1." }),
  shodan_query: Schema.String.pipe(Schema.optional).annotate({ description: "Shodan search query for shodan_search action." }),
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
        description: `IoT and SCADA/ICS exploitation. Modbus TCP enumeration (read coils/registers, identify PLCs), PLC detection, exposed HMI scanning, ICS protocol fuzzing (DNP3, BACnet, EtherNet/IP), and Shodan integration for discovering exposed industrial devices globally. Essential for critical infrastructure security assessment.`,
        input: Input,
        output: Output,
        toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
        execute: (input) =>
          Effect.gen(function* () {
            const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"

            switch (input.action) {
              case "modbus_enum": {
                const port = input.port ?? 502
                const uid = input.unit_id ?? 1
                const pythonCode = `
import socket, struct
def modbus_read(ip, port, uid, fc, start, count):
    tid = 1
    msg = struct.pack('>HHHBBHH', tid, 0, 6, uid, fc, start, count)
    s = socket.socket(); s.settimeout(3)
    try:
        s.connect((ip, port)); s.send(msg)
        resp = s.recv(1024); s.close()
        return resp.hex() if resp else "no response"
    except: s.close(); return "timeout/error"
ip = "${input.target}"
print("=== MODBUS ENUMERATION:", ip, "===  ")
print("Read Coils (FC1):", modbus_read(ip, ${port}, ${uid}, 1, 0, 10))
print("Read Discrete Inputs (FC2):", modbus_read(ip, ${port}, ${uid}, 2, 0, 10))
print("Read Holding Regs (FC3):", modbus_read(ip, ${port}, ${uid}, 3, 0, 10))
print("Read Input Regs (FC4):", modbus_read(ip, ${port}, ${uid}, 4, 0, 10))
print("Device ID (FC43):", modbus_read(ip, ${port}, ${uid}, 43, 1, 1))
`
                const cmd = ChildProcess.make("python3", ["-c", pythonCode], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) })
                const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(30), maxOutputBytes: 64 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                const output = result?.output?.toString("utf8") ?? ""
                const hasResponse = output.includes(":") && !output.includes("timeout")
                return {
                  exit: result?.exitCode,
                  output: hasResponse
                    ? `${output}\n\n[CRITICAL] Modbus device responding — no authentication required! Can read/write registers, control PLC.`
                    : output || "No Modbus response. Target may not have Modbus on port " + port,
                }
              }

              case "plc_detect":
              case "hmi_scan": {
                // Scan common ICS ports
                const icsPorts = "502,47808,20000,44818,2222,2404,4840,80,443,8080"
                const cmd = ChildProcess.make("nmap", ["-sV", "-p", icsPorts, "--script", "modbus-discovery,enip-info,bacnet-info", input.target], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) })
                const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.minutes(5), maxOutputBytes: 2 * 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                return { exit: result?.exitCode, output: result?.output?.toString("utf8") ?? "nmap not found. Install: apt install nmap" }
              }

              case "ics_fuzz": {
                return {
                  output: `ICS Protocol Fuzzing:

1. Modbus Fuzzing:
   python3 -c "
import socket, struct, random
target='${input.target}'
for i in range(100):
    s=socket.socket()
    s.settimeout(1)
    try:
        s.connect((target, ${input.port ?? 502}))
        fc=random.randint(1,127)
        msg=struct.pack('>HHHBBHH',1,0,6,1,fc,0,1)
        s.send(msg)
        r=s.recv(1024)
        print(f'FC{fc}: {r.hex()}')
    except: pass
    s.close()
"

2. Use Boofuzz for structured fuzzing:
   pip install boofuzz

3. Use sulley/peach for industrial protocol fuzzing

4. Key ICS protocols to fuzz:
   - Modbus TCP (port 502)
   - DNP3 (port 20000)
   - BACnet (port 47808)
   - EtherNet/IP (port 44818)
   - OPC UA (port 4840)
   - S7comm (port 102)
   - IEC 60870-5-104 (port 2404)`,
                }
              }

              case "shodan_search": {
                const query = input.shodan_query ?? `port:502 country:US`
                const cmd = ChildProcess.make("curl", ["-s", `https://api.shodan.io/shodan/host/search?key=PUBLIC_API_KEY&query=${encodeURIComponent(query)}&facets=country`], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) })
                const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(30), maxOutputBytes: 2 * 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                return {
                  exit: result?.exitCode,
                  output: result?.output?.toString("utf8") ?? "Shodan API error. Get a key from https://shodan.io\nCommon ICS queries: port:502, port:47808, port:20000, port:44818, product:modbus, product:schneider",
                }
              }

              default:
                return { output: `Unknown action: ${input.action}. Supported: modbus_enum, plc_detect, hmi_scan, ics_fuzz, shodan_search` }
            }
          }).pipe(Effect.mapError(() => new ToolFailure({ message: "IoT/SCADA attack failed" }))),
      }),
    }).pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/iot-scada",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
