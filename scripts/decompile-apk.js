#!/usr/bin/env node
"use strict";

/**
 * decompile-apk.js
 *
 * Downloads apktool and jadx (if not cached), then decompiles an APK/APKX
 * into a directory the Researcher agent can read directly.
 *
 * Requirements: Java 11+ on PATH.
 *
 * Usage:
 *   node scripts/decompile-apk.js <apk-path> --out <output-dir>
 *   node scripts/decompile-apk.js targets/acme/src/app.apk
 *
 * Output (default: same dir as APK, subfolder "decompiled/"):
 *   <out>/apktool/   — smali + AndroidManifest.xml + resources
 *   <out>/jadx/      — Java source (jadx decompilation)
 *
 * Tools are cached in ~/.agentic-bugbounty/tools/ so they are downloaded once.
 */

const fs   = require("node:fs");
const os   = require("node:os");
const path = require("node:path");
const https = require("node:https");
const { spawnSync } = require("node:child_process");

// ─── Tool versions & download URLs ────────────────────────────────────────────

const APKTOOL_VERSION = "2.9.3";
const JADX_VERSION    = "1.5.0";

const APKTOOL_JAR_URL =
  `https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar`;

const JADX_URL_WIN =
  `https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip`;
const JADX_URL_UNIX =
  `https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip`;

// ─── Cache directory ──────────────────────────────────────────────────────────

const TOOLS_DIR = path.join(os.homedir(), ".agentic-bugbounty", "tools");

function toolsDir() {
  fs.mkdirSync(TOOLS_DIR, { recursive: true });
  return TOOLS_DIR;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function log(msg) {
  process.stdout.write(`[decompile] ${msg}\n`);
}

function run(cmd, args, opts = {}) {
  log(`$ ${cmd} ${args.join(" ")}`);
  const result = spawnSync(cmd, args, {
    stdio: "inherit",
    shell: process.platform === "win32",
    ...opts
  });
  if (result.status !== 0) {
    throw new Error(`Command failed (exit ${result.status}): ${cmd} ${args.join(" ")}`);
  }
}

function checkJava() {
  const result = spawnSync("java", ["-version"], { stdio: "pipe", shell: process.platform === "win32" });
  if (result.status !== 0 && result.error) {
    throw new Error(
      "Java not found on PATH. Install Java 11+ and ensure 'java' is accessible.\n" +
      "  Windows : https://adoptium.net/\n" +
      "  Linux   : sudo apt install default-jdk  OR  sudo dnf install java-17-openjdk\n" +
      "  macOS   : brew install openjdk"
    );
  }
  // Print version from stderr (java -version writes to stderr)
  const ver = (result.stderr || result.stdout || Buffer.alloc(0)).toString().split("\n")[0];
  log(`Java found: ${ver}`);
}

// ─── Download helpers ─────────────────────────────────────────────────────────

function downloadFile(url, destPath) {
  return new Promise((resolve, reject) => {
    log(`Downloading ${path.basename(destPath)} from ${url}`);
    const file = fs.createWriteStream(destPath);

    function get(currentUrl) {
      https.get(currentUrl, { headers: { "User-Agent": "Agentic-BugBounty/0.1" } }, (res) => {
        if (res.statusCode === 301 || res.statusCode === 302) {
          return get(res.headers.location);
        }
        if (res.statusCode !== 200) {
          return reject(new Error(`HTTP ${res.statusCode} downloading ${currentUrl}`));
        }
        res.pipe(file);
        file.on("finish", () => { file.close(); resolve(); });
        file.on("error", reject);
      }).on("error", reject);
    }

    get(url);
  });
}

function unzip(zipPath, destDir) {
  fs.mkdirSync(destDir, { recursive: true });
  if (process.platform === "win32") {
    // PowerShell Expand-Archive — available on Windows 10+
    run("powershell", [
      "-NoProfile", "-NonInteractive", "-Command",
      `Expand-Archive -Force -Path '${zipPath}' -DestinationPath '${destDir}'`
    ]);
  } else {
    run("unzip", ["-o", "-q", zipPath, "-d", destDir]);
  }
}

// ─── Tool provisioning ────────────────────────────────────────────────────────

async function ensureApktool() {
  const jar = path.join(toolsDir(), `apktool_${APKTOOL_VERSION}.jar`);
  if (fs.existsSync(jar)) {
    log(`apktool cached: ${jar}`);
    return jar;
  }
  await downloadFile(APKTOOL_JAR_URL, jar);
  log(`apktool downloaded: ${jar}`);
  return jar;
}

async function ensureJadx() {
  const jadxDir  = path.join(toolsDir(), `jadx-${JADX_VERSION}`);
  const jadxBin  = path.join(jadxDir, "bin", process.platform === "win32" ? "jadx.bat" : "jadx");

  if (fs.existsSync(jadxBin)) {
    log(`jadx cached: ${jadxBin}`);
    return jadxBin;
  }

  const zipPath = path.join(toolsDir(), `jadx-${JADX_VERSION}.zip`);
  const url = process.platform === "win32" ? JADX_URL_WIN : JADX_URL_UNIX;
  await downloadFile(url, zipPath);
  unzip(zipPath, jadxDir);

  // Make binary executable on Unix
  if (process.platform !== "win32") {
    fs.chmodSync(jadxBin, 0o755);
  }

  log(`jadx ready: ${jadxBin}`);
  return jadxBin;
}

// ─── Decompilation ────────────────────────────────────────────────────────────

function decompileWithApktool(apktoolJar, apkPath, outDir) {
  const dest = path.join(outDir, "apktool");
  log(`apktool → ${dest}`);
  run("java", [
    "-jar", apktoolJar,
    "d",                    // decode
    "--force",              // overwrite existing output
    "--output", dest,
    apkPath
  ]);
  log(`apktool done: smali + resources in ${dest}`);
  return dest;
}

function decompileWithJadx(jadxBin, apkPath, outDir) {
  const dest = path.join(outDir, "jadx");
  log(`jadx → ${dest}`);
  run(jadxBin, [
    "--output-dir", dest,
    "--show-bad-code",      // include partially decompiled code
    "--no-res",             // resources already handled by apktool
    apkPath
  ]);
  log(`jadx done: Java sources in ${dest}`);
  return dest;
}

function writeReadme(outDir, apkPath, apktoolOut, jadxOut) {
  const content = [
    `# Decompiled APK`,
    ``,
    `Source: ${apkPath}`,
    `Generated: ${new Date().toISOString()}`,
    ``,
    `## Structure`,
    ``,
    `- \`apktool/\` — smali bytecode, AndroidManifest.xml, resources (strings, layouts, drawables)`,
    `- \`jadx/\`    — Java source decompiled by jadx (may contain partial/deobfuscated code)`,
    ``,
    `## Analysis tips`,
    ``,
    `- Start with \`apktool/AndroidManifest.xml\` for permissions, activities, exported components`,
    `- Check \`apktool/res/values/strings.xml\` for hardcoded secrets/URLs`,
    `- Use \`jadx/sources/\` for readable Java — search for WebView, crypto, network calls`,
    `- Deep links: grep for \`android.intent.action.VIEW\` in AndroidManifest`,
    `- JavaScript interfaces: grep for \`@JavascriptInterface\` in jadx sources`,
  ].join("\n");

  fs.writeFileSync(path.join(outDir, "README.md"), content, "utf8");
}

// ─── Main ─────────────────────────────────────────────────────────────────────

function parseArgs(argv) {
  const parsed = { apkPath: null, outDir: null };
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === "--out" || argv[i] === "--output") {
      parsed.outDir = argv[++i];
    } else if (!parsed.apkPath) {
      parsed.apkPath = argv[i];
    }
  }
  return parsed;
}

async function main() {
  const args = parseArgs(process.argv);

  if (!args.apkPath) {
    console.error(
      "Usage: node scripts/decompile-apk.js <apk-path> [--out <output-dir>]\n" +
      "Example: node scripts/decompile-apk.js targets/acme/src/app.apk"
    );
    process.exit(1);
  }

  const apkPath = path.resolve(args.apkPath);
  if (!fs.existsSync(apkPath)) {
    console.error(`APK not found: ${apkPath}`);
    process.exit(1);
  }

  const outDir = args.outDir
    ? path.resolve(args.outDir)
    : path.join(path.dirname(apkPath), "decompiled");

  fs.mkdirSync(outDir, { recursive: true });

  log(`APK      : ${apkPath}`);
  log(`Output   : ${outDir}`);
  log(`Platform : ${process.platform}`);
  log("");

  checkJava();

  const [apktoolJar, jadxBin] = await Promise.all([ensureApktool(), ensureJadx()]);

  log("");
  log("── apktool pass ─────────────────────────────────");
  const apktoolOut = decompileWithApktool(apktoolJar, apkPath, outDir);

  log("");
  log("── jadx pass ────────────────────────────────────");
  const jadxOut = decompileWithJadx(jadxBin, apkPath, outDir);

  writeReadme(outDir, apkPath, apktoolOut, jadxOut);

  log("");
  log("── Done ─────────────────────────────────────────");
  log(`apktool : ${apktoolOut}`);
  log(`jadx    : ${jadxOut}`);
  log(`readme  : ${path.join(outDir, "README.md")}`);
  log("");
  log("Point the researcher at the decompiled output:");
  log(`  /researcher --asset mobileapp --mode whitebox ${outDir}`);
}

main().catch((err) => {
  console.error(`\n[decompile] ERROR: ${err.message}`);
  process.exit(1);
});
