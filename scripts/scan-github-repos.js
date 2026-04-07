#!/usr/bin/env node
"use strict";
const fs   = require("node:fs");
const path = require("node:path");
const https = require("node:https");

function parseArgs(argv) {
  const args = { target: null, noLlm: false };
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === "--target") args.target = argv[++i];
    if (argv[i] === "--no-llm") args.noLlm = true;
  }
  return args;
}

function fetchJson(url) {
  return new Promise((resolve, reject) => {
    const opts = {
      headers: {
        "User-Agent": "agentic-bugbounty/1.0",
        "Accept": "application/vnd.github.v3+json"
      }
    };
    https.get(url, opts, (res) => {
      let data = "";
      res.on("data", (c) => { data += c; });
      res.on("end", () => {
        if (res.statusCode === 404) { resolve(null); return; }
        if (res.statusCode === 403 || res.statusCode === 429) {
          reject(new Error(`GitHub API rate limit (HTTP ${res.statusCode})`)); return;
        }
        if (res.statusCode !== 200) {
          reject(new Error(`HTTP ${res.statusCode} for ${url}`)); return;
        }
        try { resolve(JSON.parse(data)); } catch (e) { reject(e); }
      });
    }).on("error", reject);
  });
}

function extractGithubUrls(scopeSnapshot) {
  const urls = new Set();
  const urlRe = /https?:\/\/github\.com\/([a-zA-Z0-9_.-]+)\/([a-zA-Z0-9_.-]+)/gi;
  const items = [
    ...(scopeSnapshot.in_scope    || []),
    ...(scopeSnapshot.wildcards   || []),
    ...(scopeSnapshot.web_app     || []),
    ...(scopeSnapshot.source_code || [])
  ];
  for (const item of items) {
    const text = typeof item === "string" ? item : JSON.stringify(item);
    for (const match of text.matchAll(urlRe)) {
      const owner = match[1];
      const repo  = match[2].replace(/\.git$/, "");
      // Skip obvious non-repos (e.g. github.com/duckduckgo without a repo name)
      if (owner && repo && repo !== owner) {
        urls.add(`https://github.com/${owner}/${repo}`);
      }
    }
  }
  return [...urls];
}

async function fetchRepoMeta(owner, repo) {
  const meta = await fetchJson(`https://api.github.com/repos/${owner}/${repo}`);
  if (!meta) return null;

  const contents = await fetchJson(
    `https://api.github.com/repos/${owner}/${repo}/contents`
  ).catch(() => []);
  const rootFiles = Array.isArray(contents) ? contents.map((f) => f.name) : [];

  const stack = [];
  if (rootFiles.includes("package.json"))                          stack.push("nodejs");
  if (rootFiles.includes("pom.xml") || rootFiles.includes("build.gradle")) stack.push("java");
  if (rootFiles.includes("go.mod"))                                stack.push("golang");
  if (rootFiles.includes("requirements.txt") || rootFiles.includes("setup.py") || rootFiles.includes("pyproject.toml")) stack.push("python");
  if (rootFiles.includes("Gemfile"))                               stack.push("ruby");
  if (rootFiles.includes("composer.json"))                         stack.push("php");
  if (rootFiles.includes("Cargo.toml"))                            stack.push("rust");

  return {
    url:            `https://github.com/${owner}/${repo}`,
    owner,
    repo,
    language:       meta.language || null,
    stack,
    size_kb:        meta.size,
    stars:          meta.stargazers_count,
    pushed_at:      meta.pushed_at,
    topics:         meta.topics || [],
    description:    meta.description || "",
    default_branch: meta.default_branch || "main",
    rank:           null,
    rank_rationale: null
  };
}

function simpleRank(repos) {
  const WEB_STACKS      = new Set(["nodejs", "python", "php", "java", "ruby"]);
  const HIGH_VALUE_TOPICS = new Set(["api", "auth", "payments", "authentication", "oauth", "rest", "backend"]);

  return repos
    .map((r) => {
      let score = 0;
      const daysSincePush = (Date.now() - new Date(r.pushed_at).getTime()) / 86400000;
      if (daysSincePush < 180)       score += 3;
      else if (daysSincePush < 730)  score += 1;
      if (r.stack.some((s) => WEB_STACKS.has(s))) score += 2;
      if (r.size_kb > 500)           score += 1;
      score += r.topics.filter((t) => HIGH_VALUE_TOPICS.has(t.toLowerCase())).length;
      return { ...r, rank: score, rank_rationale: `heuristic score ${score}` };
    })
    .sort((a, b) => b.rank - a.rank)
    .map((r, i) => ({ ...r, rank: i + 1 }));
}

async function main() {
  const args = parseArgs(process.argv);
  if (!args.target) {
    console.error("Usage: scan-github-repos.js --target <name>");
    process.exit(1);
  }

  const targetDir  = path.resolve("targets", args.target);
  const intelDir   = path.join(targetDir, "intelligence");
  const outputPath = path.join(intelDir, "github_repos.json");

  // Try multiple scope file locations
  const scopeCandidates = [
    path.join(intelDir, "h1_scope_snapshot.json"),
    path.join(intelDir, "scope_snapshot.json"),
    path.join(targetDir, "scope.json")
  ];
  const scopePath = scopeCandidates.find((p) => fs.existsSync(p));

  if (!scopePath) {
    console.log(`No scope snapshot found for target "${args.target}" — skipping repo scan`);
    process.exit(0);
  }

  let scopeSnapshot;
  try {
    scopeSnapshot = JSON.parse(fs.readFileSync(scopePath, "utf8"));
  } catch (err) {
    console.error(`Could not read scope file: ${err.message}`);
    process.exit(1);
  }

  const githubUrls = extractGithubUrls(scopeSnapshot);
  console.log(`Found ${githubUrls.length} GitHub URL(s) in scope`);

  if (githubUrls.length === 0) {
    fs.mkdirSync(intelDir, { recursive: true });
    fs.writeFileSync(outputPath, JSON.stringify({ repos: [], scanned_at: new Date().toISOString() }, null, 2), "utf8");
    console.log("No GitHub repos found — wrote empty result");
    process.exit(0);
  }

  const repos = [];
  for (const url of githubUrls) {
    const match = url.match(/github\.com\/([^/]+)\/([^/]+)/);
    if (!match) continue;
    const [, owner, repo] = match;
    console.log(`  Fetching metadata: ${owner}/${repo}`);
    try {
      const meta = await fetchRepoMeta(owner, repo);
      if (meta) repos.push(meta);
    } catch (err) {
      console.warn(`  Warning: ${err.message}`);
    }
  }

  const ranked = simpleRank(repos);
  fs.mkdirSync(intelDir, { recursive: true });
  fs.writeFileSync(outputPath, JSON.stringify({ repos: ranked, scanned_at: new Date().toISOString() }, null, 2), "utf8");
  console.log(`Wrote ${ranked.length} repo(s) to ${outputPath}`);
}

main().catch((err) => { console.error(err.message); process.exit(1); });
