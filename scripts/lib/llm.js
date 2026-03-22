"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

// ─── Config ───────────────────────────────────────────────────────────────────

function loadOpenRouterConfig() {
  const configPath = path.resolve(__dirname, "../../config/openrouter.json");
  try {
    return JSON.parse(fs.readFileSync(configPath, "utf8"));
  } catch {
    return {
      free_models: [
        "meta-llama/llama-3.3-70b-instruct:free",
        "qwen/qwen3-coder:free",
        "google/gemma-3-27b-it:free"
      ],
      researcher_model: "openai/gpt-oss-120b:free",
      api_keys_env: ["OPENROUTER_API_KEY_1", "OPENROUTER_API_KEY_2", "OPENROUTER_API_KEY_3", "OPENROUTER_API_KEY_4", "OPENROUTER_API_KEY_5", "OPENROUTER_API_KEY"],
      retry_on_status: [401, 429, 503, 502]
    };
  }
}

const OPENROUTER_CONFIG = loadOpenRouterConfig();

// ─── Flavour ──────────────────────────────────────────────────────────────────

const FLAVOUR = {
  gemini_try: [
    "asking gemini. it usually knows things.",
    "routing to gemini. the oracle is in.",
    "gemini on the line. let's see what it says.",
    "pinging the big G. stand by.",
    "«Gemini, this is Mother. What do you see?» — opening the pod bay doors to the oracle.",
    "«I'm sorry, Dave. I'm afraid I can't do that.» just kidding. connecting to gemini.",
    "gemini, manifest. *kamehameha loading*",
    "«It's not possible.» «No, it's necessary.» — routing to gemini.",
    "«By your powers combined, I am Captain Gemini!» summoning the oracle.",
    "gemini: «I'm ready to make a contract.» *madoka magica flashbacks*",
    "«The cake is a lie.» but gemini is real. connecting.",
    "gemini, respond. *guitar riff from interstellar*",
  ],
  gemini_ok: [
    "gemini delivered. moving on.",
    "the oracle has spoken.",
    "gemini came through. good.",
    "«I've seen things you people wouldn't believe.» gemini has answered.",
    "gemini: «You've got me? Who's got you?» — response received.",
    "omae wa mou shindeiru. gemini delivered the fatal blow.",
    "«The spice must flow.» and gemini delivered.",
    "gemini: «I'm not in danger, Skyler. I am the danger.» response acquired.",
    "«Yare yare daze.» gemini actually came through.",
    "gemini performed a perfect shoryuken. data extracted.",
    "«I drink and I know things.» gemini knows things. moving on.",
  ],
  gemini_fail: [
    "gemini went dark. switching lanes.",
    "gemini shrugged. trying openrouter.",
    "gemini is not available. escalating to plan B.",
    "no response from gemini. pivoting.",
    "«What's happening?» «Gemini's dead, Dave.» — initiating fallback.",
    "gemini pulled a berserk eclipse. moving on.",
    "«I'm afraid. I'm afraid, Dave.» gemini has left the chat.",
    "gemini: «You can't handle the truth!» — or any response. switching.",
    "gemini: «I'm tired, boss.» *green mile vibes* — rotating out.",
    "gemini went full evangelion. instrumentality aborted. switching.",
    "«What we've got here is failure to communicate.» gemini silent.",
    "gemini caught the ace attorney objection. no response given.",
  ],
  openrouter_try: [
    "trying {model} via openrouter...",
    "routing to {model}...",
    "spinning up {model}...",
    "{model} — you're up.",
    "«Engage.» — calling {model}.",
    "{model}, i choose you! *pokeball throw*",
    "«Now I am become Death, the destroyer of worlds.» let's see what {model} becomes.",
    "activating {model}. *domain expansion*",
    "«To infinity and beyond!» — routing to {model}.",
    "{model}, launch! *gundam launch sequence*",
    "«Do or do not. There is no try.» trying {model} anyway.",
    "summoning {model} from the warp. *40k noises*",
    "{model}: «I'm here to chew bubblegum and answer queries. and I'm all out of bubblegum.»",
    "«I need a weapon.» here's {model}. make it count.",
    "activating {model}. *kaio-ken times four*",
  ],
  openrouter_ok: [
    "{model} delivered. done.",
    "got a response from {model}.",
    "{model} came through.",
    "«I'll be back.» — and {model} was. response received.",
    "{model} performed a perfect rasengan. data extracted.",
    "«It's alive! It's alive!» — {model} speaks.",
    "{model}: «There is no spoon.» and yet, we have a response.",
    "{model} pulled a levi squad. mission accomplished.",
    "«I see this as an absolute win.» {model} delivered.",
    "{model} went plus ultra. response acquired.",
    "«You've got a friend in me.» {model} came through.",
    "{model}: «I'm the one who knocks.» and knock it did. response ready.",
    "{model} did a backflip, snapped the bad guy's neck, and saved the day. response received.",
  ],
  openrouter_fail: [
    "{model} failed ({reason}). next.",
    "{model} is busy or banned ({reason}). rotating.",
    "{model} down ({reason}). trying the next one.",
    "rotating away from {model}: {reason}.",
    "{model} pulled a bankai it couldn't handle ({reason}).",
    "«Houston, we have a problem.» {model} is {reason}.",
    "{model} has become a berserker ({reason}). ejecting.",
    "«I'm giving it all she's got, captain!» but {model} failed ({reason}).",
    "{model} attempted a genkidama but dropped it ({reason}).",
    "«My disappointment is immeasurable and my day is ruined.» {model} failed ({reason}).",
    "{model} went the way of serenity. got canceled too soon ({reason}).",
    "{model} chose the red pill and fell into the void ({reason}).",
    "«You have no power here!» {model} failed ({reason}). rotating.",
    "{model} tried to run before it could walk. fell flat ({reason}).",
  ],
  key_rotate: [
    "key …{key} exhausted on {model}. rotating to next key.",
    "switching api key (…{key} failed on {model}).",
    "key rotation triggered. {model} rejected …{key}.",
    "«This key was made for walking.» …{key} walked right out on {model}.",
    "…{key} has left the genjutsu. rotating.",
    "«The prime directive of API keys: don't fail.» …{key} failed on {model}.",
    "key …{key} got thanos snapped on {model}. rotating.",
    "«One does not simply walk into Mordor.» …{key} didn't even make it past {model}.",
    "…{key} pulled a saturn v. exploded mid-launch on {model}.",
    "«I've made a huge mistake.» using key …{key} on {model}. rotating.",
    "key …{key} went to the shadow realm on {model}. next.",
  ],
  all_failed: [
    "every model and key has been tried. nothing worked. check your api keys and try again.",
    "full fallback chain exhausted. no llm responded. giving up.",
    "all backends down. either the internet is on fire or your keys are wrong.",
    "«It's a system failure, all systems. We're dead in the water.» — all models offline.",
    "the last starfighter has fallen. all models have failed.",
    "«You were the chosen one!» — but all models failed the test.",
    "genjutsu kai. reality check: no API key worked. aborting.",
    "«Open the pod bay doors, HAL.» *silence* — total system failure.",
    "«So long and thanks for all the fish.» the models have left the planet.",
    "all models have joined the great gig in the sky. check your keys.",
    "«What is dead may never die.» but also never responds. all models failed.",
    "the council of models has spoken. and they said nothing. aborting.",
    "«I find your lack of faith disturbing.» but also your lack of working API keys.",
    "every model has fallen. *roundabout to be continued meme*",
  ],
  researcher_start: [
    "dual researcher online. spinning up {model} for second opinion.",
    "calling {model} for a second pass. what did the first miss?",
    "second researcher engaged ({model}). let's see if there's anything left.",
    "bringing in {model} for cross-verification.",
    "«We need a second opinion.» summoning {model}.",
    "{model} joins the party as second researcher. *final fantasy fanfare*",
    "«There is another Skywalker.» bringing in {model} for verification.",
    "activating backup. {model}, you're the phantom menace's only hope.",
    "«I've got a bad feeling about this.» better bring in {model} for backup.",
    "deploying second researcher: {model}. *metal gear solid alert sound*",
    "{model}: «I'll try spinning, that's a good trick!» double-checking results.",
    "second researcher {model} has entered the arena. *mortal kombat voice*",
    "«Just when I thought I was out, they pull me back in.» {model} joins as second researcher.",
  ],
  researcher_fallback: [
    "primary model failed. falling back to free model chain.",
    "switching to fallback chain for researcher pass.",
    "{model} unavailable. trying alternatives.",
    "«Execute Order 66.» on the primary model. falling back.",
    "primary model went supernova. engaging fallback chain.",
    "«If you strike me down, I shall become more powerful than you can possibly imagine.» — primary model failed. fallback engaged.",
    "primary model pulled a joker: «Why so serious?» then died. fallback time.",
    "«I'll be what I wanna be.» switching to fallback chain.",
    "primary model caught the soap. it's over. engaging fallback.",
    "«You're gonna need a bigger boat.» fallback chain deploying.",
    "primary model: «I'm not feeling so good, Mr. Stark.» fallback engaged.",
    "«We're gonna need a montage.» assembling fallback models.",
  ],
};

function flavour(category, vars = {}) {
  const lines = FLAVOUR[category];
  if (!lines || lines.length === 0) return "";
  let line = lines[Math.floor(Math.random() * lines.length)];
  for (const [k, v] of Object.entries(vars)) {
    line = line.replace(new RegExp(`\\{${k}\\}`, "g"), v);
  }
  return line;
}

function log(msg) {
  process.stdout.write(`  \x1b[2m[llm] ${msg}\x1b[0m\n`);
}

// ─── Key helpers ──────────────────────────────────────────────────────────────

function getApiKeys() {
  const keys = [];
  for (const envVar of (OPENROUTER_CONFIG.api_keys_env || [])) {
    const val = process.env[envVar];
    if (val && val.trim()) keys.push(val.trim());
  }
  return [...new Set(keys)];
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Call a free LLM expecting a JSON object back.
 * Chain: Gemini CLI → OpenRouter model×key matrix.
 */
async function callLLMJson(prompt, { timeoutMs = 120000 } = {}) {
  const fullPrompt = `${prompt}\n\nRespond ONLY with a valid JSON object. No markdown, no explanation, no code fences.`;

  // 1. Gemini CLI
  log(flavour("gemini_try"));
  try {
    const result = callGeminiCli(fullPrompt, timeoutMs);
    log(flavour("gemini_ok"));
    return result;
  } catch (e) {
    log(flavour("gemini_fail") + ` (${e.message.slice(0, 80)})`);
  }

  // 2. OpenRouter key×model matrix
  const apiKeys = getApiKeys();
  if (apiKeys.length === 0) {
    const msg = flavour("all_failed");
    log(msg);
    throw new Error("All LLM backends failed. Gemini CLI unavailable and no OPENROUTER_API_KEY* env vars are set.");
  }

  log(`  ${apiKeys.length} api key(s) loaded. trying ${(OPENROUTER_CONFIG.free_models || []).length} free models...`);

  const models = OPENROUTER_CONFIG.free_models || [];
  for (const model of models) {
    for (const key of apiKeys) {
      log(flavour("openrouter_try", { model }));
      try {
        const result = await callOpenRouter(fullPrompt, model, key, timeoutMs);
        log(flavour("openrouter_ok", { model }));
        return result;
      } catch (e) {
        const reason = e.message.slice(0, 60);
        log(flavour("openrouter_fail", { model, reason }));
        if (apiKeys.length > 1 && apiKeys.indexOf(key) < apiKeys.length - 1) {
          log(flavour("key_rotate", { key: key.slice(-4), model }));
        }
      }
    }
  }

  log(flavour("all_failed"));
  throw new Error("All LLM backends exhausted (Gemini CLI + all OpenRouter free models × all keys).");
}

/**
 * Synchronous Gemini call via ccw cli subprocess.
 * NOTE: intentionally synchronous. Do not convert to async.
 */
function callGeminiCli(prompt, timeoutMs) {
  const result = spawnSync(
    "ccw",
    ["cli", "-p", prompt, "--tool", "gemini", "--mode", "analysis"],
    { encoding: "utf8", timeout: timeoutMs, windowsHide: true }
  );
  if (result.status !== 0 || result.error) {
    const errMsg = result.stderr || result.error?.message || `exit code ${result.status}`;
    throw new Error(`ccw cli failed: ${errMsg}`);
  }
  return extractJson(result.stdout || "");
}

/**
 * Call one OpenRouter model with one API key, expect JSON back.
 */
async function callOpenRouter(prompt, model, apiKey, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch("https://openrouter.ai/api/v1/chat/completions", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${apiKey}`,
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/agentic-bugbounty",
        "X-Title": "Agentic BugBounty"
      },
      body: JSON.stringify({
        model,
        messages: [{ role: "user", content: prompt }],
        temperature: 0.2,
        response_format: { type: "json_object" }
      }),
      signal: controller.signal
    });
    clearTimeout(timer);
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new Error(`HTTP ${res.status}${body ? ": " + body.slice(0, 120) : ""}`);
    }
    const data = await res.json();
    const content = data.choices?.[0]?.message?.content;
    if (!content) throw new Error("Empty response from OpenRouter");
    return extractJson(content);
  } catch (err) {
    clearTimeout(timer);
    throw err;
  }
}

/**
 * Call a specific OpenRouter model for the dual researcher pass.
 * Rotates all API keys on failure, falls back to free model chain.
 * Returns raw text — no JSON parsing.
 */
async function callResearcherModel(prompt, { model, timeoutMs = 300000 } = {}) {
  const primaryModel = model || OPENROUTER_CONFIG.researcher_model || "openai/gpt-oss-120b:free";
  const apiKeys = getApiKeys();
  if (apiKeys.length === 0) {
    throw new Error("OPENROUTER_API_KEY* not set — cannot call secondary researcher model");
  }

  log(flavour("researcher_start", { model: primaryModel }));
  log(`  ${apiKeys.length} api key(s) available for rotation`);

  // Try primary model with all keys
  for (const key of apiKeys) {
    log(`  trying ${primaryModel} (key …${key.slice(-4)})`);
    try {
      const result = await callOpenRouterRaw(prompt, primaryModel, key, timeoutMs);
      log(flavour("openrouter_ok", { model: primaryModel }));
      return result;
    } catch (e) {
      const reason = e.message.slice(0, 60);
      log(flavour("openrouter_fail", { model: primaryModel, reason }));
      if (apiKeys.indexOf(key) < apiKeys.length - 1) {
        log(flavour("key_rotate", { key: key.slice(-4), model: primaryModel }));
      }
    }
  }

  // Fallback to free model chain
  log(flavour("researcher_fallback", { model: primaryModel }));
  const models = OPENROUTER_CONFIG.free_models || [];
  for (const fallbackModel of models) {
    if (fallbackModel === primaryModel) continue;
    for (const key of apiKeys) {
      log(flavour("openrouter_try", { model: fallbackModel }));
      try {
        const result = await callOpenRouterRaw(prompt, fallbackModel, key, timeoutMs);
        log(flavour("openrouter_ok", { model: fallbackModel }));
        return result;
      } catch (e) {
        const reason = e.message.slice(0, 60);
        log(flavour("openrouter_fail", { model: fallbackModel, reason }));
      }
    }
  }

  log(flavour("all_failed"));
  throw new Error("All researcher model backends exhausted.");
}

/**
 * Raw OpenRouter call — returns text, no JSON parsing.
 */
async function callOpenRouterRaw(prompt, model, apiKey, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch("https://openrouter.ai/api/v1/chat/completions", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${apiKey}`,
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/agentic-bugbounty",
        "X-Title": "Agentic BugBounty Dual Researcher"
      },
      body: JSON.stringify({
        model,
        messages: [{ role: "user", content: prompt }],
        temperature: 0.4
      }),
      signal: controller.signal
    });
    clearTimeout(timer);
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new Error(`HTTP ${res.status}${body ? ": " + body.slice(0, 120) : ""}`);
    }
    const data = await res.json();
    return data.choices?.[0]?.message?.content || "";
  } catch (err) {
    clearTimeout(timer);
    throw err;
  }
}

/**
 * Extract the first complete JSON object or array from arbitrary text.
 * Uses brace-matching — handles multi-block LLM responses robustly.
 */
function extractJson(text) {
  const openBrace = text.indexOf("{");
  const openBracket = text.indexOf("[");

  let start;
  if (openBrace === -1 && openBracket === -1) {
    throw new Error("No JSON found in LLM response");
  } else if (openBrace === -1) {
    start = openBracket;
  } else if (openBracket === -1) {
    start = openBrace;
  } else {
    start = Math.min(openBrace, openBracket);
  }

  const opener = text[start];
  const closer = opener === "{" ? "}" : "]";
  let depth = 0;
  let inString = false;
  let escape = false;

  for (let i = start; i < text.length; i++) {
    const ch = text[i];
    if (escape) { escape = false; continue; }
    if (ch === "\\") { escape = true; continue; }
    if (ch === '"') { inString = !inString; continue; }
    if (inString) continue;
    if (ch === opener) depth++;
    else if (ch === closer) {
      depth--;
      if (depth === 0) return JSON.parse(text.slice(start, i + 1));
    }
  }
  throw new Error("Unterminated JSON in LLM response");
}

module.exports = { callLLMJson, callResearcherModel };
