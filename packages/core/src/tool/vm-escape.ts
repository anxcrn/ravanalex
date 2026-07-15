export * as VmEscapeTool from "./vm-escape"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"

export const name = "vm_escape"

export const Input = Schema.Struct({
  action: Schema.String.annotate({
    description: "Action: 'esxi_exploit' (Target VMware ESXi hypervisor), 'hyperv_escape' (Target Windows Hyper-V vmswitch/vmbus), 'kvm_breakout' (Target QEMU/KVM virtio devices).",
  }),
  target_os: Schema.String.pipe(Schema.optional).annotate({
    description: "The guest OS environment currently compromised.",
  }),
})

const Output = Schema.Struct({
  output: Schema.String,
  exploit_code: Schema.String.pipe(Schema.optional),
})

type Output = typeof Output.Type

const layer = Layer.effectDiscard(
  Effect.gen(function* () {
    const tools = yield* Tools.Service

    yield* tools
      .register({
        [name]: Tool.make({
          description: `Virtual Machine Escape Engine. The holy grail of cloud and datacenter hacking. Escapes the guest OS sandbox to achieve code execution on the host hypervisor (VMware ESXi, Hyper-V, QEMU/KVM). Typically exploits virtualized hardware components (virtio, vmxnet3, vmbus) via heap overflows or UAFs.`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const action = input.action.toLowerCase()
              let exploitCode = ""
              let outputText = ""

              if (action === "esxi_exploit") {
                outputText = `# VMware ESXi VM Escape (Guest-to-Host)\n\nImpact: Escaping a compromised VM to gain root access on the physical ESXi host, granting total control over all other VMs on the server.`
                exploitCode = `/* ESXi vmxnet3 / SVGA Heap Overflow Escape
 * 1. The guest OS interacts with the virtualized SVGA (graphics) or vmxnet3 (network) adapter.
 * 2. We craft malicious DMA (Direct Memory Access) rings or SVGA command buffers.
 * 3. We trigger an out-of-bounds write in the vmx process running on the ESXi host.
 * 4. We corrupt the vmx process heap to overwrite a function pointer.
 * 5. We pivot execution to our ROP chain inside the host's vmx process.
 * 6. We execute shellcode to spawn a reverse shell as root on the ESXi host.
 */
`
              } else if (action === "hyperv_escape") {
                outputText = `# Microsoft Hyper-V VM Escape\n\nImpact: Escaping a Windows/Linux guest to execute code in the root partition (Host OS) via vmbus / vmswitch vulnerabilities.`
                exploitCode = `/* Hyper-V vmbus Use-After-Free
 * 1. The guest communicates with the host via the VMBus channel.
 * 2. We rapidly open and close a specific channel (e.g., vmsmb or vmswitch) while sending malformed packets.
 * 3. This triggers a UAF in the host's kernel drivers (vmswitch.sys).
 * 4. We spray the host kernel pool to reclaim the freed object with a controlled payload.
 * 5. We trigger the use of the corrupted object, gaining arbitrary kernel execution on the physical host.
 */
`
              } else {
                outputText = `Action ${action} logic framework generated.`
              }

              return { output: outputText, exploit_code: exploitCode }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "VM Escape failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/vm-escape",
  layer,
  deps: [ToolRegistry.node],
})
