"use strict";

const fs = require("node:fs");
const path = require("node:path");

/**
 * Detect asset type from a directory by checking for well-known marker files.
 * Returns one of: "browserext" | "mobileapp" | "executable" | "webapp"
 */
function detectAssetType(dirPath) {
  const entries = safeReaddir(dirPath);

  // Chrome/Firefox/Edge extension — manifest.json with manifest_version field
  // Search up to 3 levels deep (some repos put built manifests in browsers/chrome/ etc.)
  if (findExtensionManifest(dirPath, 3)) return "browserext";

  // _locales/ directory is exclusive to browser extensions
  if (entries.includes("_locales")) return "browserext";

  // Android — AndroidManifest.xml or build.gradle / build.gradle.kts
  if (
    entries.includes("AndroidManifest.xml") ||
    entries.includes("build.gradle") ||
    entries.includes("build.gradle.kts") ||
    entries.some((e) => e.endsWith(".apk"))
  ) {
    return "mobileapp";
  }

  // iOS — .xcodeproj / .xcworkspace folder or .ipa
  if (
    entries.some((e) => e.endsWith(".xcodeproj") || e.endsWith(".xcworkspace") || e.endsWith(".ipa"))
  ) {
    return "mobileapp";
  }

  // Executable — ELF / PE / Mach-O binaries or .exe / .elf / .bin files
  if (entries.some((e) => /\.(exe|elf|bin|out|dylib|so)$/i.test(e))) {
    return "executable";
  }
  // Check first-level binary files by magic bytes
  for (const entry of entries) {
    const fullPath = path.join(dirPath, entry);
    if (isRegularFile(fullPath) && hasBinaryMagic(fullPath)) return "executable";
  }

  // Web app — check for framework markers before falling back
  if (
    entries.includes("package.json") ||
    entries.includes("next.config.js") || entries.includes("next.config.ts") ||
    entries.includes("vite.config.js") || entries.includes("vite.config.ts") ||
    entries.includes("nuxt.config.js") || entries.includes("nuxt.config.ts") ||
    entries.includes("angular.json") ||
    entries.includes("vue.config.js") ||
    entries.includes("webpack.config.js") ||
    entries.includes("requirements.txt") ||
    entries.includes("Pipfile") ||
    entries.includes("manage.py") ||       // Django
    entries.includes("config.ru") ||       // Rails / Rack
    entries.includes("Gemfile") ||
    entries.includes("composer.json") ||   // PHP
    entries.includes("pom.xml") ||         // Java/Spring
    entries.includes("go.mod") ||
    entries.includes("Cargo.toml")
  ) {
    return "webapp";
  }

  // Default fallback
  return "webapp";
}

/**
 * Scan each immediate subdirectory of srcDir and return a list of detected assets.
 * If srcDir itself looks like an asset root, returns a single-item list for srcDir.
 *
 * Returns: Array<{ asset_type: string, source_path: string }>
 *   source_path is relative to targetDir (e.g. "./src" or "./src/my-ext")
 */
function detectAssetsInSrcDir(srcDir, targetDir) {
  if (!fs.existsSync(srcDir)) return [];

  const entries = safeReaddir(srcDir);
  if (entries.length === 0) return [];

  // Detect APK/APKX files directly in srcDir — each one is a standalone mobile asset
  const apkFiles = entries.filter((e) => /\.(apk|apkx)$/i.test(e) && isRegularFile(path.join(srcDir, e)));
  if (apkFiles.length > 0) {
    return apkFiles.map((f) => ({
      asset_type: "mobileapp",
      source_path: relTo(path.join(srcDir, f), targetDir)
    }));
  }

  // If srcDir itself is an asset root, don't recurse into subdirs
  const directType = detectAssetType(srcDir);
  const subdirs = entries.filter((e) => isDirectory(path.join(srcDir, e)));

  // Heuristic: if the directory has typical project root files treat it as one asset
  if (isProjectRoot(entries) || subdirs.length === 0) {
    return [{ asset_type: directType, source_path: relTo(srcDir, targetDir) }];
  }

  // Otherwise scan each subdirectory and collect results
  const results = [];
  for (const sub of subdirs) {
    const subPath = path.join(srcDir, sub);
    const subEntries = safeReaddir(subPath);
    if (subEntries.length === 0) continue;
    // Also check for APK files inside subdirectories
    const subApks = subEntries.filter((e) => /\.(apk|apkx)$/i.test(e) && isRegularFile(path.join(subPath, e)));
    if (subApks.length > 0) {
      for (const apk of subApks) {
        results.push({ asset_type: "mobileapp", source_path: relTo(path.join(subPath, apk), targetDir) });
      }
      continue;
    }
    const type = detectAssetType(subPath);
    results.push({ asset_type: type, source_path: relTo(subPath, targetDir) });
  }

  return results.length > 0 ? results : [{ asset_type: directType, source_path: relTo(srcDir, targetDir) }];
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function findExtensionManifest(dirPath, maxDepth) {
  if (maxDepth < 0) return false;
  const entries = safeReaddir(dirPath);
  if (entries.includes("manifest.json")) {
    try {
      const manifest = JSON.parse(fs.readFileSync(path.join(dirPath, "manifest.json"), "utf8"));
      if (manifest.manifest_version) return true;
    } catch {
      // not valid — keep searching
    }
  }
  for (const entry of entries) {
    const sub = path.join(dirPath, entry);
    if (isDirectory(sub) && findExtensionManifest(sub, maxDepth - 1)) return true;
  }
  return false;
}

function safeReaddir(dirPath) {
  try {
    return fs.readdirSync(dirPath);
  } catch {
    return [];
  }
}

function isDirectory(p) {
  try {
    return fs.statSync(p).isDirectory();
  } catch {
    return false;
  }
}

function isRegularFile(p) {
  try {
    return fs.statSync(p).isFile();
  } catch {
    return false;
  }
}

function hasBinaryMagic(filePath) {
  try {
    const buf = Buffer.alloc(4);
    const fd = fs.openSync(filePath, "r");
    const bytesRead = fs.readSync(fd, buf, 0, 4, 0);
    fs.closeSync(fd);
    if (bytesRead < 2) return false;
    // ELF: 0x7f 45 4c 46
    if (buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) return true;
    // PE (Windows): MZ
    if (buf[0] === 0x4d && buf[1] === 0x5a) return true;
    // Mach-O: 0xCE/0xCF/0xCA/0xFE
    if ((buf[0] === 0xce || buf[0] === 0xcf) && buf[1] === 0xfa) return true;
  } catch {
    // ignore
  }
  return false;
}

function isProjectRoot(entries) {
  const rootMarkers = new Set([
    "package.json", "manifest.json", "build.gradle", "build.gradle.kts",
    "AndroidManifest.xml", "Makefile", "CMakeLists.txt", "setup.py",
    "Cargo.toml", "go.mod", "pom.xml"
  ]);
  return entries.some((e) => rootMarkers.has(e));
}

function relTo(absPath, basePath) {
  const rel = path.relative(basePath, absPath).replace(/\\/g, "/");
  return rel.startsWith(".") ? rel : `./${rel}`;
}

/**
 * Return a human-readable description of an asset based on its directory contents.
 * Used by the setup wizard to explain what was detected.
 */
function describeAsset(dirPath, assetType) {
  const entries = safeReaddir(dirPath);
  const hints = [];

  if (assetType === "browserext") {
    // Find the manifest and read name/version
    const manifestPath = findManifestPath(dirPath, 3);
    if (manifestPath) {
      try {
        const m = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
        if (m.name) hints.push(`name: "${m.name}"`);
        if (m.version) hints.push(`v${m.version}`);
        if (m.manifest_version) hints.push(`MV${m.manifest_version}`);
      } catch { /**/ }
    }
  } else if (assetType === "mobileapp") {
    const ext = path.extname(dirPath).toLowerCase();
    if (ext === ".apk" || ext === ".apkx") {
      hints.push(`APK: ${path.basename(dirPath)}`);
    } else if (entries.some((e) => e.endsWith(".xcodeproj") || e.endsWith(".xcworkspace"))) {
      hints.push("iOS");
    } else {
      hints.push("Android");
    }
  } else if (assetType === "webapp") {
    if (entries.includes("next.config.js") || entries.includes("next.config.ts")) hints.push("Next.js");
    else if (entries.includes("angular.json")) hints.push("Angular");
    else if (entries.includes("nuxt.config.js") || entries.includes("nuxt.config.ts")) hints.push("Nuxt");
    else if (entries.includes("vue.config.js")) hints.push("Vue");
    else if (entries.includes("manage.py")) hints.push("Django");
    else if (entries.includes("config.ru") || entries.includes("Gemfile")) hints.push("Rails/Ruby");
    else if (entries.includes("go.mod")) hints.push("Go");
    else if (entries.includes("pom.xml")) hints.push("Java/Spring");
    else if (entries.includes("Cargo.toml")) hints.push("Rust");
    else if (entries.includes("composer.json")) hints.push("PHP");
    else if (entries.includes("requirements.txt") || entries.includes("Pipfile")) hints.push("Python");
    else if (entries.includes("package.json")) hints.push("Node.js");
  }

  const label = { webapp: "Web App", browserext: "Chrome Extension", mobileapp: "Mobile App", executable: "Executable" }[assetType] || assetType;
  return hints.length > 0 ? `${label} (${hints.join(", ")})` : label;
}

function findManifestPath(dirPath, maxDepth) {
  if (maxDepth < 0) return null;
  const entries = safeReaddir(dirPath);
  if (entries.includes("manifest.json")) {
    const p = path.join(dirPath, "manifest.json");
    try {
      const m = JSON.parse(fs.readFileSync(p, "utf8"));
      if (m.manifest_version) return p;
    } catch { /**/ }
  }
  for (const entry of entries) {
    const sub = path.join(dirPath, entry);
    if (isDirectory(sub)) {
      const found = findManifestPath(sub, maxDepth - 1);
      if (found) return found;
    }
  }
  return null;
}

module.exports = { detectAssetType, detectAssetsInSrcDir, describeAsset };
