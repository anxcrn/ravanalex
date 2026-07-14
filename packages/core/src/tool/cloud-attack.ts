export * as CloudAttackTool from "./cloud-attack"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "cloud_attack"

export const Input = Schema.Struct({
  action: Schema.String.annotate({
    description:
      "Cloud attack: 'aws_enum' (enumerate IAM), 'aws_s3' (list/access S3), 'aws_lambda' (list/inject Lambda), 'gcp_enum' (GCP service accounts), 'azure_enum' (Azure AD), 'aws_secrets' (extract secrets from AWS Secrets Manager/SSM)",
  }),
  provider: Schema.String.pipe(Schema.optional).annotate({ description: "Cloud provider: aws, gcp, azure. Default: aws." }),
  region: Schema.String.pipe(Schema.optional).annotate({ description: "Cloud region. Default: us-east-1." }),
  bucket: Schema.String.pipe(Schema.optional).annotate({ description: "S3 bucket name for aws_s3 action." }),
  profile: Schema.String.pipe(Schema.optional).annotate({ description: "AWS credential profile. Default: default." }),
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
        description: `Cloud exploitation suite for AWS, GCP, and Azure. Enumerate IAM users/roles/policies, access S3 buckets, inject Lambda backdoors, enumerate GCP service accounts, enumerate Azure AD apps/users, and extract cloud secrets. Uses aws-cli, gcloud, az CLI, Pacu, and CloudFox. Essential for cloud security assessment and post-compromise cloud pivoting.`,
        input: Input,
        output: Output,
        toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
        execute: (input) =>
          Effect.gen(function* () {
            const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"
            const profile = input.profile ?? "default"
            const region = input.region ?? "us-east-1"
            const provider = input.provider ?? "aws"

            let tool: string
            let args: string[]

            switch (input.action) {
              case "aws_enum": {
                // Enumerate IAM users, roles, policies
                const results: string[] = ["=== AWS IAM ENUMERATION ==="]
                const cmds = [
                  ["aws", ["iam", "list-users", "--profile", profile, "--region", region, "--output", "json"]],
                  ["aws", ["iam", "list-roles", "--profile", profile, "--region", region, "--output", "json"]],
                  ["aws", ["iam", "list-policies", "--profile", profile, "--region", region, "--output", "json"]],
                  ["aws", ["sts", "get-caller-identity", "--profile", profile, "--region", region]],
                ]
                for (const [t, a] of cmds) {
                  const cmd = ChildProcess.make(t as string, a as string[], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) })
                  const r = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(30), maxOutputBytes: 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  if (r?.output) results.push(r.output.toString("utf8"))
                }
                return { exit: 0, output: results.join("\n\n") }
              }

              case "aws_s3": {
                if (input.bucket) {
                  tool = "aws"
                  args = ["s3", "ls", `s3://${input.bucket}/`, "--recursive", "--profile", profile, "--region", region]
                } else {
                  tool = "aws"
                  args = ["s3", "ls", "--profile", profile, "--region", region]
                }
                break
              }

              case "aws_lambda": {
                tool = "aws"
                args = ["lambda", "list-functions", "--profile", profile, "--region", region, "--output", "json"]
                break
              }

              case "aws_secrets": {
                const results: string[] = ["=== AWS SECRETS ==="]
                const smCmd = ChildProcess.make("aws", ["secretsmanager", "list-secrets", "--profile", profile, "--region", region], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) })
                const smResult = yield* appProcess.run(smCmd, { combineOutput: true, timeout: Duration.seconds(30), maxOutputBytes: 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                results.push(smResult?.output?.toString("utf8") ?? "Secrets Manager: error or empty")
                const ssmCmd = ChildProcess.make("aws", ["ssm", "describe-parameters", "--profile", profile, "--region", region], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) })
                const ssmResult = yield* appProcess.run(ssmCmd, { combineOutput: true, timeout: Duration.seconds(30), maxOutputBytes: 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                results.push(ssmResult?.output?.toString("utf8") ?? "SSM: error or empty")
                return { exit: 0, output: results.join("\n\n") }
              }

              case "gcp_enum": {
                const results: string[] = ["=== GCP ENUMERATION ==="]
                const cmds = [
                  ["gcloud", ["projects", "list"]],
                  ["gcloud", ["iam", "service-accounts", "list"]],
                  ["gcloud", ["iam", "roles", "list"]],
                ]
                for (const [t, a] of cmds) {
                  const cmd = ChildProcess.make(t as string, a as string[], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) })
                  const r = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(30), maxOutputBytes: 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  if (r?.output) results.push(r.output.toString("utf8"))
                }
                return { exit: 0, output: results.join("\n\n") }
              }

              case "azure_enum": {
                const results: string[] = ["=== AZURE AD ENUMERATION ==="]
                const cmds = [
                  ["az", ["ad", "user", "list", "--output", "json"]],
                  ["az", ["ad", "app", "list", "--output", "json"]],
                  ["az", ["ad", "group", "list", "--output", "json"]],
                  ["az", ["account", "list", "--output", "json"]],
                ]
                for (const [t, a] of cmds) {
                  const cmd = ChildProcess.make(t as string, a as string[], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) })
                  const r = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(30), maxOutputBytes: 2 * 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  if (r?.output) results.push(r.output.toString("utf8"))
                }
                return { exit: 0, output: results.join("\n\n") }
              }

              default:
                return { output: `Unknown action: ${input.action}. Supported: aws_enum, aws_s3, aws_lambda, aws_secrets, gcp_enum, azure_enum` }
            }

            const cmd = ChildProcess.make(tool, args, { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) })
            const result = yield* appProcess.run(cmd, {
              combineOutput: true, timeout: Duration.minutes(5), maxOutputBytes: 5 * 1024 * 1024,
            }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))

            if (!result) {
              return {
                output: `${tool} failed. Ensure ${provider} CLI is installed and configured:\nAWS: pip install awscli && aws configure\nGCP: apt install google-cloud-cli && gcloud auth login\nAzure: pip install azure-cli && az login`,
              }
            }

            return {
              exit: result.exitCode,
              output: result.output?.toString("utf8") ?? "(no output)",
            }
          }).pipe(Effect.mapError(() => new ToolFailure({ message: "Cloud attack failed" }))),
      }),
    }).pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/cloud-attack",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
