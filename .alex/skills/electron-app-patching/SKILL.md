---
name: electron-app-patching
description: Methodology for extracting, modifying, and repacking Electron applications (Desktop SaaS clients) to bypass premium features or intercept traffic.
---

# ⚛️ Electron App Patching (Desktop SaaS)

Electron apps (Slack, Discord, Notion, Figma) are just Chromium browsers running Node.js. They package their source code in an pp.asar archive. If you can unpack the ASAR, you have the source code.

## PHASE 1: EXTRACTION

### Step 1: Locate the ASAR
On Windows, it's usually in:
C:\Users\<User>\AppData\Local\Programs\<AppName>\resources\app.asar
On macOS:
/Applications/<AppName>.app/Contents/Resources/app.asar

### Step 2: Unpack
You need the sar npm package.
`ash
npm install -g asar
asar extract app.asar ./app-source
`
*Note: If sar extract fails with an invalid header, the developers have likely implemented ASAR integrity checks or encrypted the archive. You will need to hook the Node.js s.readFileSync calls during runtime using Frida.*

---

## PHASE 3: ANALYSIS & PATCHING

Now you have a directory (./app-source) full of JavaScript, HTML, and CSS.

### Step 1: Bypassing Premium Checks
Search the codebase (grep -r "isPremium" .) for subscription logic.
Common patterns:
`javascript
// Original
if (user.isPremium || user.plan === "PRO") {
    enableFeatureX();
}

// Patched
if (true) {
    enableFeatureX();
}
`

### Step 2: Disabling SSL Pinning / Certificate Errors
Electron apps often ignore system proxies (like Burp Suite) and hardcode SSL certificates.
To force the app to route through Burp and ignore invalid certificates, find the pp.on('ready') or BrowserWindow initialization and inject:
`javascript
app.commandLine.appendSwitch('ignore-certificate-errors');
app.commandLine.appendSwitch('proxy-server', '127.0.0.1:8080');
`

### Step 3: Injecting a Developer Console
Most production Electron apps disable the DevTools. Re-enable them to get a live DOM inspector and JS console in the app.
Find the BrowserWindow creation:
`javascript
let mainWindow = new BrowserWindow({ ... });
// Inject this line right after:
mainWindow.webContents.openDevTools({ mode: 'detach' });
`

---

## PHASE 4: REPACKING

Once you've made your JS modifications, repack the ASAR.
`ash
asar pack ./app-source app.asar
`
Replace the original pp.asar with your modified version and restart the application.

### Defeating ASAR Integrity (If Repacking Fails)
Some apps (like Discord) verify the hash of the pp.asar file before launching.
- If it's a native launcher (C++) verifying the ASAR: You must patch the native binary (see pp-cracking-and-license-bypass) to skip the hash check.
- Alternatively, don't use ASAR at all. Simply rename the ./app-source folder to ./app and place it in the esources directory. Electron will natively run an pp folder if pp.asar is missing (unless explicitly disabled).
