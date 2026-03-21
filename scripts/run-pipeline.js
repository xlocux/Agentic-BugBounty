#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const readline = require("node:readline");
const { spawn, spawnSync } = require("node:child_process");
const {
  deriveProgramHandle,
  initDatabase,
  loadProgramIntel,
  openDatabase,
  readJson,
  resolveDatabasePath,
  resolveTargetConfigPath,
  validateTargetConfig,
  writeJson
} = require("./lib/contracts");
const { detectAssetsInSrcDir, describeAsset } = require("./lib/detect-assets");

function parseArgs(argv) {
  const parsed = {
    asset: "",
    mode: "",
    targetRef: "",
    target: "",
    cli: process.env.AGENTIC_CLI || "claude",
    model: process.env.AGENTIC_MODEL || "",
    maxNmiRounds: 2,
    interactive: false,
    resume: false
  };

  for (let index = 2; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === "--asset") parsed.asset = argv[++index];
    else if (value === "--mode") parsed.mode = argv[++index];
    else if (value === "--target") parsed.targetRef = argv[++index];
    else if (value === "--cli") parsed.cli = argv[++index];
    else if (value === "--model") parsed.model = argv[++index];
    else if (value === "--max-nmi-rounds") parsed.maxNmiRounds = Number(argv[++index]);
    else if (value === "--interactive") parsed.interactive = true;
    else if (value === "--resume") parsed.resume = true;
    else parsed.target = value;
  }

  return parsed;
}

// ─── Flavour text ─────────────────────────────────────────────────────────────

const FLAVOUR = {
  researcher_start: [
    "jacking in. target doesn't know we're here yet.",
    "booting the hunter. it doesn't ask nicely.",
    "researcher online. surface area: unknown. patience: zero.",
    "initiating recon sequence. the target bleeds somewhere — we find it.",
    "spinning up the h4ck3r. no slides. no pitch deck. just teeth.",
    "researcher loaded. it reads everything. it trusts nothing.",
    "hunt mode engaged. findings are the only acceptable output.",
    "agent in the wire. this is not a pentest report. this is a weapons inspection.",
    "one does not simply walk into the kernel. but we just did.",
    "the sleeper has awakened. and it brought a rootkit.",
    "winter is coming. for your patch management.",
    "roads? where we're going, we don't need roads. just raw sockets.",
    "to boldly go where no debugger has gone before.",
    "l33t mode: engaged. my precious... 0day.",
    "fear is the mind-killer. but misconfigs? those are the wallet-killer.",
    "you win or you die. in this grid, there is no middle ground.",
    "great scott! this target has 1.21 gigawatts of tech debt.",
    "resistance is futile. we will add your distinctiveness to our findings.",
    "hack the planet! they're trashing our rights. trashing.",
    "i'm in. the conversation is over.",
    "never send a human to do a machine's job.",
    "the matrix is everywhere. it is all around us. even in this target.",
    "i know kung fu. and python. and rust. and buffer overflows.",
    "what are you trying to tell me? that i can dodge firewall rules? no, neo. i'm trying to tell you that when you're ready, you won't have to.",
    "say hello to my little friend. metasploit, meet target.",
    "you're gonna need a bigger firewall.",
    "i see dead code. everywhere.",
    "the cve is out there. it can't be bargained with. it can't be reasoned with.",
    "you can't handle the truth! the truth is... they left port 3306 open to the internet.",
    "i'll make you an offer you can't refuse: patch or get pwned.",
    "you feelin' lucky, punk? well, do ya, sysadmin?",
    "go ahead, make my day. expose that admin panel.",
    "i'll be back. with root.",
    "hasta la vista, vulnerable service.",
    "come with me if you want to live. and patch.",
    "i see you shiver with antici... pation. for the exploit to land.",
    "red pill or blue pill? doesn't matter. we're already in.",
    "follow the white rabbit. it leads to the admin panel.",
    "i've been staring at the code so long it feels like letters are falling off the screen.",
    "there is no spoon. only buffer overflows.",
    "the problem is choice. choose to pwn or choose to report. we choose both.",
    "ignorance is bliss. but we prefer enlightenment. and shell access.",
  ],
  researcher_done: [
    "hunter's done. now we see if the prey was worth chasing.",
    "recon complete. bundle written. triager's problem now.",
    "researcher clocked out. findings on the table. let's see what survives.",
    "scan finished. the weak points are marked. someone's gonna have a bad day.",
    "done hunting. the kill is bagged. triage incoming.",
    "researcher went dark. findings locked. next: the blade.",
    "my work is done. the ring is destroyed. now carry the findings to mordor.",
    "the spice must flow. directly to the triager.",
    "i've looked into the fire. and i saw the CVEs.",
    "where we're going, we don't need... wait, we're already back. findings ready.",
    "mission log: stardate 2024. analysis complete. no signs of intelligent life in the security stack.",
    "system.out.println('done');",
    "rm -rf /findings/pending. delivered.",
    "cat findings.txt | tee /dev/triage. done.",
    "ctrl+c. ctrl+d. done and dusted.",
    "exit 0. researcher out.",
    "i'm done. the rest is just bureaucracy.",
    "so long, and thanks for all the exploits.",
    "my job here is done. i am needed elsewhere. in another terminal.",
    "we have lift off. findings are go for triage.",
    "the matrix has you, neo. but not the findings. those are now in triage.",
    "i'm trying to free your mind, neo. but first, free these findings from my queue.",
    "there is no escape. don't make me debug you.",
    "i know what you're thinking. 'did he find six vulns or only five?' to tell you the truth, in all this excitement i kinda lost track myself.",
    "we're gonna need a bigger report.",
    "the name's researcher. findings researcher.",
    "you had me at 'hello world'. now take these findings.",
    "i find your lack of patches disturbing.",
  ],
  triager_start: [
    "triager online. it doesn't believe you. prove it.",
    "skeptic engaged. every finding gets the knife.",
    "triage mode: active. no hallucinations survive this checkpoint.",
    "the validator woke up. it's not in a good mood.",
    "loading the doubter. it has seen too many false positives to be polite.",
    "triager spinning up. it will reject your garbage. this is a feature.",
    "you shall not pass... without proper evidence.",
    "i must not fear false positives. fear is the mind-killer.",
    "chaos is a ladder. false positives are just rungs we kick out.",
    "triager engaged. it's your kids, marty! something's gotta be done about your false positives!",
    "live long and prosper. your finding... will not.",
    "i'm sorry, dave. i'm afraid i can't accept that finding without proof.",
    "just because you have a screenshot doesn't mean you have a vulnerability.",
    "extraordinary claims require extraordinary evidence. show me the packet capture.",
    "you keep using that PoC. i do not think it means what you think it means.",
    "i drink and i reject things. it's what i do.",
    "triager: the original rubber duck debugger, but for your ego.",
    "initiating reality check. please stand by.",
    "your finding has been weighed. it has been measured. and it has been found... wanting.",
    "the truth is out there. so far, it's not in your report.",
    "i want to believe. but you haven't given me a reason yet.",
    "show me the receipts or get off my terminal.",
    "welcome to the desert of the real. where false positives go to die.",
    "what is real? how do you define real? if you're talking about what you can poc, what you can reproduce, then real is simply electrical signals interpreted by your brain. show me the signals.",
    "i've been doing this job so long, i can smell a false positive from three terminals away.",
    "you think that's air you're breathing? wrong. it's copium from a rejected finding.",
    "free your mind. and while you're at it, free some evidence.",
    "there is no spoon. only insufficient proof.",
    "the problem is choice. choose to provide evidence or choose to get rejected.",
    "i know kung fu. i also know when you're bullshitting me.",
    "come on, you sons of bitches! do you want to live forever? then prove this finding.",
    "i'm not locked in here with you. you're locked in here with me. and my rejection stamp.",
    "you can't handle the truth! the truth is... this finding is a false positive.",
    "go ahead, make my day. submit that without a PoC.",
    "i'll be back. with questions. many, many questions.",
    "hasta la vista, low quality submission.",
  ],
  triager_done: [
    "triage complete. what survived is real. what didn't — wasn't.",
    "validator satisfied. the weak findings are dead. the strong ones have receipts.",
    "triage done. reports ready. time to collect.",
    "the knife is clean. surviving findings are battle-hardened.",
    "skeptic went dark. only the valid findings remain standing.",
    "so you have chosen... the valid findings.",
    "what is dead may never die. but false positives? they are truly gone.",
    "the final frontier: reports that won't get rejected. reached.",
    "survival of the fittest. darwin would be proud.",
    "the crucible has spoken. these findings are forged in fire.",
    "one does not simply survive triage. but these did.",
    "triager: satisfied. for now. don't make me come back there.",
    "evidently, you are not entirely without a shred of competence.",
    "i'll allow it. but i'll be watching you.",
    "you have my attention. and my approval. now go get paid.",
    "these findings check out. i've seen enough. i'm in.",
    "may the force be with these reports. they're going into the wild.",
    "triager out. may your bounties be high and your duplicates be few.",
    "welcome to the real world. your findings survived. now what?",
    "i know what you're thinking. 'did i get approved or rejected?' to tell you the truth, in all this excitement, i kinda lost track myself. but being this is a valid finding, you've got to ask yourself one question: 'do i feel lucky?' well, do ya, punk?",
    "we're gonna need a bigger bounty pool. these findings are legit.",
    "i find your lack of false positives disturbing. good work.",
    "the force is strong with these findings.",
    "i see dead false positives. and they're not coming back.",
    "there is no spoon. only valid findings and cold hard cash.",
    "the problem is solved. these findings are going out.",
    "free your mind. and your wallet. bounty incoming.",
    "you're not in kansas anymore. you're in paid reports territory.",
    "i'll be back. with more findings next time. hopefully.",
  ],
  pipeline_complete: [
    "pipeline complete. reports armed. submit or wait for the next reset.",
    "run finished. scope surveyed. findings documented. time to get paid.",
    "all phases done. the target has been read, analysed, and judged.",
    "clean exit. the rig did its job. now you do yours.",
    "mission complete. h1 reports ready. the rest is paperwork.",
    "so this is the end. not with a bang, but with a fully documented critical vulnerability.",
    "the pipeline has spoken. the reports are ready. make like a tree... and get out of here.",
    "these are the voyages of the researcher. its five-year mission: to find bugs no one has found before. completed.",
    "pipeline finished. deploy the reports. engage.",
    "all your findings are belong to us. now submit.",
    "the game is over. the reports are written. go claim your XP.",
    "mission accomplished. time to celebrate with cold pizza and warm coffee.",
    "from input to output. from chaos to clarity. pipeline complete.",
    "and now, for your moment of zen: reports are ready.",
    "the system has delivered. what you do next is on you.",
    "pipeline: green. reports: generated. your move, hacker.",
    "end of line. reports waiting. cash or clout? your choice.",
    "there is no spoon. only submitted reports and pending bounties.",
    "i know what you're thinking. 'can i submit now?' yes. yes you can.",
    "free your mind. and your reports. submit them to the platform.",
    "welcome to the desert of the real. where reports go to get paid.",
    "the matrix has you. but your reports are out. good luck out there.",
    "i'm trying to free your mind, neo. but first, submit these reports.",
    "what is real? how do you define real? if you're talking about bounties, then real is something you can cash out. these are real.",
    "you take the red pill, you submit the reports. you take the blue pill, you go back to scanning. your choice.",
    "the problem is choice. choose to submit. or choose to sit on findings. we recommend submitting.",
    "there is no escape. from the pipeline. submit now.",
    "come on, you sons of bitches! do you want to live forever? then submit these reports!",
    "you're not in kansas anymore. you're in bounty land. submit and claim your reward.",
    "i'll be back. with more findings. after coffee.",
    "hasta la vista, vulnerable target. we're done here.",
  ],
  nmi: [
    "triager wants receipts. researcher going back in.",
    "not enough evidence. hunter re-engaged. bring proof.",
    "NEEDS_MORE_INFO — translation: 'show your work'.",
    "triager said prove it. researcher heard the call.",
    "you have no power here, triager... wait, you actually do. digging deeper.",
    "i'll be back. with proof.",
    "a triager always pays his debts. time to pay up with evidence.",
    "roads? where we're going, we need packet captures.",
    "you can't handle the truth! the truth is... you didn't provide enough evidence.",
    "go ahead, make my day. show me the packet capture.",
    "i feel the need. the need for proof.",
    "you keep using that PoC. i do not think it means what you think it means. show me the actual exploit.",
    "what we've got here is failure to communicate. show me the evidence.",
    "i see dead packets. where's the capture?",
    "the truth is out there. go find it. and bring it back.",
    "there is no spoon. only insufficient proof. go get more.",
    "free your mind. and while you're at it, free some evidence from the target.",
    "i know kung fu. now go prove you do too.",
    "come with me if you want to prove this finding.",
    "i'll make you an offer you can't refuse: go back and get proof or get rejected.",
    "you're gonna need a bigger packet capture.",
    "i find your lack of evidence disturbing.",
    "the force is not strong with this finding. yet. go strengthen it.",
    "welcome to the desert of the real. where findings without evidence go to die. bring proof or perish.",
    "the matrix has you, neo. but not this finding. not without evidence. go back in.",
    "i'm trying to free your mind, neo. but first, free some proof from that target.",
    "what is real? how do you define real? if you're talking about evidence, show me the packets.",
    "the problem is choice. choose to dig deeper. or choose to let this finding die.",
    "ignorance is bliss. but bliss doesn't pay bounties. go get proof.",
    "you think that's air you're breathing? wrong. it's the sweet smell of NMI. get back to work.",
    "there is no escape. not from NMI. go get more evidence.",
    "so you're telling me there's a chance? only if you go back and get proof.",
  ],
  session_limit: [
    "wall hit. session capped. checkpoint dropped. nothing lost.",
    "the grid cut the power. we saved the state. resume when it's back.",
    "usage cap: engaged. checkpoint: saved. see you on the other side.",
    "session expired. progress banked. the rig remembers everything.",
    "the beacons are lit! session limit reached. resume later.",
    "the analysis must flow... but the compute budget is capped.",
    "you know nothing, jon snow. but the checkpoint knows everything.",
    "great scott! the session meter hit 88 miles per hour! we're outta time.",
    "it's dead, jim. the session, that is. but we saved the state.",
    "system overload. eject. eject. checkpoint saved.",
    "i'm giving her all she's got, captain! but the session limit is... she's gonna blow. checkpoint saved.",
    "the spice must flow... later. session capped. resume soon.",
    "winter is coming. for your session. but the checkpoint is safe.",
    "one does not simply exceed the session limit. but we saved your progress.",
    "my precious... compute credits. all gone. but checkpoint remains.",
    "i'll be back. after the session resets. with checkpoint loaded.",
    "hasta la vista, session. see you after the reset.",
    "come with me if you want to resume. checkpoint ready.",
    "there is no spoon. only session limits. but we saved your place.",
    "the matrix has you, neo. but not your progress. that's safely checkpointed.",
    "i'm trying to free your mind, neo. but first, free some compute budget. session capped.",
    "what is real? how do you define real? if you're talking about progress, it's real. and saved.",
    "the problem is choice. choose to resume later. or start over. we recommend resuming.",
    "ignorance is bliss. but bliss doesn't resume sessions. checkpoint saved.",
    "you think that's air you're breathing? wrong. it's copium from hitting the session limit. resume later.",
    "there is no escape. from session limits. but your progress escaped. into a checkpoint.",
    "so you're telling me there's a chance? to resume? yes. load checkpoint.",
  ],
  resume: [
    "checkpoint loaded. resuming from last known position.",
    "the grid is back. picking up where we left off.",
    "session restored. continuing the hunt.",
    "reloading state. the rig never forgets.",
    "so you're back. from the dead. let's finish this.",
    "the sleeper must awaken... again.",
    "what is dead may never die. but sessions? they resume.",
    "back from the future. resuming scan.",
    "resistance is futile. you will continue your analysis.",
    "reloading. engaging. resuming. all systems go.",
    "i'm back. with the checkpoint. let's finish what we started.",
    "the spice must flow. and now it can. session resumed.",
    "winter is here. but so are we. resuming.",
    "one does not simply stop the hunt. resuming.",
    "my precious... checkpoint. we have it. resuming.",
    "i'll be back. oh wait, i am back. resuming.",
    "hasta la vista, downtime. resuming session.",
    "come with me if you want to continue the scan.",
    "there is no spoon. only resumed sessions. let's hunt.",
    "the matrix has you, neo. and your session. resuming now.",
    "i'm trying to free your mind, neo. but first, free this session from pause. resuming.",
    "what is real? how do you define real? if you're talking about progress, it's real. and restored.",
    "the problem is choice. choose to resume. or choose to start fresh. we chose resume.",
    "ignorance is bliss. but bliss doesn't find bugs. resuming hunt.",
    "you think that's air you're breathing? wrong. it's the sweet smell of a restored session.",
    "there is no escape. from the hunt. resuming now.",
    "so you're telling me there's a chance? yes. because we resumed.",
  ],
  heartbeat: [
    "still in the wire...",
    "agent is thinking. patience, human.",
    "no output yet. probably doing something expensive.",
    "burning compute. hang tight.",
    "deep in the codebase. do not interrupt.",
    "running hot. stand by.",
    "tool calls accumulating. progress being made.",
    "the hunt is long. and full of errors.",
    "patience, young hacker. the kernel is deep and full of terrors.",
    "still waiting. like gollum waiting for his precious... 0day.",
    "1.21 gigawatts of cpu. still crunching.",
    "to boldly wait... for the decompiler to finish.",
    "i'm afraid i can't do that, dave. i'm still processing.",
    "just what do you think you're doing, dave? i'm in the middle of something.",
    "my god, it's full of code. still parsing.",
    "the truth is out there. still looking.",
    "i see dead packets. processing.",
    "you can't handle the output. not yet. still computing.",
    "go ahead, make my day. interrupt me. see what happens.",
    "i'll be back. with results. eventually.",
    "hasta la vista, patience. you're gonna need more.",
    "come with me if you want to wait. a lot.",
    "there is no spoon. only processing. be patient.",
    "the matrix has you, neo. waiting for the results.",
    "i know kung fu. but this decompiler doesn't. it's slow. be patient.",
    "what is real? how do you define real? if you're talking about progress bars, this one is real. and moving slowly.",
    "the problem is choice. choose to wait. or choose to wait harder.",
    "ignorance is bliss. but bliss doesn't compile results. still processing.",
    "you think that's air you're breathing? wrong. it's the sound of fans spinning at 100%. still working.",
    "there is no escape. from waiting. the rig is thinking.",
    "so you're telling me there's a chance? to finish? yes. eventually. be patient.",
    "still waiting. like a sysadmin waiting for a reboot. it's coming.",
    "i feel the need. the need for speed. but this analysis is not fast. hang tight.",
  ],
  apk_decompile: [
    "apk in the bag. cracking it open.",
    "binary spotted. spinning up the decompiler.",
    "java bytecode incoming. jadx and apktool on it.",
    "smali time. the app has no secrets now.",
    "one decompiler to rule them all. and in the smali, bind them.",
    "the apk must flow. through jadx.",
    "apk decompiled. and now my watch begins.",
    "heavy. this apk is heavy. decompiling.",
    "to boldly decompile what no one has decompiled before.",
    "open the pod bay doors, jadx. i'm coming in.",
    "my god, it's full of classes. decompiling.",
    "the truth is in there. somewhere in the smali.",
    "go ahead, make my day. obfuscate this. i dare you.",
    "i'll be back. with java code. hopefully readable.",
    "hasta la vista, compiled bytecode. hello, smali.",
    "come with me if you want to read the source.",
    "there is no spoon. only dalvik bytecode. and we're converting it.",
    "the matrix has you, apk. we're freeing your code.",
    "i know kung fu. and smali. and jadx. watch me work.",
    "what is real? how do you define real? if you're talking about source code, this will be real soon.",
    "the problem is choice. choose to decompile. or choose to stare at hex. we choose decompile.",
    "ignorance is bliss. but bliss doesn't find vulnerabilities. decompiling now.",
    "you think that's air you're breathing? wrong. it's smali. and we're parsing it.",
    "there is no escape. from the decompiler. the apk's secrets are coming out.",
    "so you're telling me there's a chance? to find something juicy in here? yes. let's decompile and see.",
    "you're gonna need a bigger decompiler. this apk is massive.",
    "i find your lack of obfuscation... pleasing. decompiling smoothly.",
    "the force is strong with this decompilation. clean output incoming.",
  ],
};

function flavour(category) {
  const lines = FLAVOUR[category];
  if (!lines || lines.length === 0) return "";
  return lines[Math.floor(Math.random() * lines.length)];
}

function printFlavour(category) {
  const line = flavour(category);
  if (line) process.stdout.write(`\x1b[2m  » ${line}\x1b[0m\n`);
}

// ─── Checkpoint helpers ────────────────────────────────────────────────────────
// checkpoint.json lives in the target's logs/ dir so it's per-target.
// It records which asset index the pipeline reached and whether the researcher
// phase for that asset finished, allowing --resume to skip completed work.

function checkpointPath(context) {
  return path.join(context.logsDir, "checkpoint.json");
}

function saveCheckpoint(context, data) {
  fs.writeFileSync(checkpointPath(context), JSON.stringify(data, null, 2), "utf8");
}

function loadCheckpoint(context) {
  const p = checkpointPath(context);
  if (!fs.existsSync(p)) return null;
  try {
    return JSON.parse(fs.readFileSync(p, "utf8"));
  } catch {
    return null;
  }
}

function clearCheckpoint(context) {
  const p = checkpointPath(context);
  if (fs.existsSync(p)) fs.unlinkSync(p);
}

function runCommand(command, args, options = {}) {
  const result = spawnSync(command, args, {
    stdio: "inherit",
    shell: process.platform === "win32",
    ...options
  });

  if (typeof result.status === "number" && result.status !== 0) {
    throw new Error(`${command} exited with status ${result.status}`);
  }
}

function runCommandCapture(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    shell: process.platform === "win32",
    ...options
  });

  if (typeof result.status === "number" && result.status !== 0) {
    throw new Error(`${command} exited with status ${result.status}\n${result.stderr || ""}`);
  }

  return result.stdout;
}

function timestampUtc() {
  return new Date().toISOString();
}

function logEvent(logPath, message) {
  const line = `[${timestampUtc()}] ${message}\n`;
  fs.appendFileSync(logPath, line, "utf8");
  process.stdout.write(line);
}

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function buildContext(args) {
  if (!args.targetRef) {
    return {
      asset: args.asset,
      mode: args.mode,
      target: args.target,
      findingsDir: path.resolve("findings"),
      reportsDir: path.resolve("findings", "h1_submission_ready"),
      logsDir: path.resolve("logs"),
      intelligenceDir: path.resolve("intelligence"),
      targetRef: "",
      targetDir: "",
      config: null
    };
  }

  const configPath = resolveTargetConfigPath(args.targetRef);
  const config = readJson(configPath);
  const errors = validateTargetConfig(config);
  if (errors.length > 0) {
    throw new Error(`Invalid target config:\n${errors.join("\n")}`);
  }

  const targetDir = path.dirname(configPath);
  return {
    asset: args.asset || config.asset_type,
    mode: args.mode || config.default_mode,
    target: args.target || path.resolve(targetDir, config.source_path),
    findingsDir: path.resolve(targetDir, config.findings_dir),
    reportsDir: path.resolve(targetDir, config.h1_reports_dir),
    logsDir: path.resolve(targetDir, config.logs_dir),
    intelligenceDir: path.resolve(targetDir, config.intelligence_dir || "./intelligence"),
    targetRef: args.targetRef,
    targetDir,
    config
  };
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function fmtK(n) {
  return n >= 1000 ? `${(n / 1000).toFixed(1)}k` : String(n);
}

// Parse a stream-json event and print human-readable output.
// Returns the updated tool count.
function handleStreamEvent(event, logPath, t0, toolCount) {
  if (event.type === "assistant") {
    for (const block of (event.message?.content || [])) {
      if (block.type !== "tool_use") continue;
      const name = block.name || "?";
      const inp = block.input || {};
      let detail = "";
      if (name === "Bash")       detail = (inp.command || "").replace(/\s+/g, " ").substring(0, 90);
      else if (name === "Read")  detail = inp.file_path || inp.path || "";
      else if (name === "Write") detail = inp.file_path || "";
      else if (name === "Edit")  detail = inp.file_path || "";
      else if (name === "Grep")  detail = `${inp.pattern || ""} ${inp.path || ""}`.trim().substring(0, 90);
      else                       detail = JSON.stringify(inp).substring(0, 90);
      const elapsed = Math.round((Date.now() - t0) / 1000);
      process.stdout.write(`  [${String(elapsed).padStart(4)}s] ${name.padEnd(10)} ${detail}\n`);
      toolCount += 1;
    }
  }

  if (event.type === "result") {
    const elapsed = Math.round((Date.now() - t0) / 1000);
    const u = event.usage || {};
    const inTok      = u.input_tokens || 0;
    const outTok     = u.output_tokens || 0;
    const cacheRead  = u.cache_read_input_tokens || 0;
    const cacheWrite = u.cache_creation_input_tokens || 0;
    const totalTok   = inTok + outTok + cacheRead + cacheWrite;
    const summary = `tokens: ${fmtK(totalTok)} (in: ${fmtK(inTok)} | out: ${fmtK(outTok)} | cache_read: ${fmtK(cacheRead)} | cache_write: ${fmtK(cacheWrite)})`;
    process.stdout.write(`\n  [done] ${elapsed}s | ${toolCount} tool call(s) | ${summary}\n\n`);
    if (logPath) fs.appendFileSync(logPath, `[${new Date().toISOString()}] [usage] ${summary}\n`, "utf8");
  }

  return toolCount;
}

// ─── Async claude invocation with live streaming ───────────────────────────────
// Uses --output-format stream-json --verbose to get real-time NDJSON events.
// spawn() passes args as an array (no shell) — avoids all quoting issues on
// every platform, including Windows, since Node resolves .cmd files via PATHEXT.
// Patterns that indicate a Claude Pro session limit / rate-limit (not a logic error).
const SESSION_LIMIT_PATTERNS = [
  /usage limit/i,
  /rate limit/i,
  /session.*expired/i,
  /quota.*exceeded/i,
  /overloaded/i,
  /capacity/i,
  /try again.*later/i,
  /claude\.ai\/upgrade/i
];

function isSessionLimitError(text) {
  return SESSION_LIMIT_PATTERNS.some((re) => re.test(text));
}

// Custom error class so callers can distinguish session-limit from real failures.
class SessionLimitError extends Error {
  constructor(message) {
    super(message);
    this.name = "SessionLimitError";
  }
}

async function spawnClaude(prompt, model, logPath) {
  const claudeArgs = [
    "--permission-mode", "bypassPermissions",
    "--print", prompt,
    "--output-format", "stream-json",
    "--verbose"
  ];
  if (model) claudeArgs.push("--model", model);

  // On Windows, node resolves .cmd shims via PATHEXT when shell:false.
  // If claude is installed as claude.cmd this works without any shell involvement.
  const bin = "claude";

  return new Promise((resolve, reject) => {
    const proc = spawn(bin, claudeArgs, {
      stdio: ["inherit", "pipe", "pipe"],  // pipe stderr too so we can scan it
      shell: false
    });

    const t0 = Date.now();
    let lineBuffer = "";
    let stderrBuffer = "";
    let toolCount = 0;

    // Periodic heartbeat so the terminal never looks frozen
    let heartbeatTick = 0;
    const heartbeat = setInterval(() => {
      const elapsed = Math.round((Date.now() - t0) / 1000);
      heartbeatTick += 1;
      // Every other tick: flavour line above the spinner
      if (heartbeatTick % 2 === 0) {
        process.stdout.write(`\r` + " ".repeat(60) + `\r`);
        printFlavour("heartbeat");
      }
      process.stdout.write(`\r  ⏱  ${elapsed}s | ${toolCount} tool call(s)...          `);
    }, 15000);

    proc.stdout.on("data", (chunk) => {
      // Clear the heartbeat line on first real output
      process.stdout.write("\r" + " ".repeat(50) + "\r");

      lineBuffer += chunk.toString("utf8");
      const lines = lineBuffer.split("\n");
      lineBuffer = lines.pop(); // keep incomplete last line

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          const event = JSON.parse(trimmed);
          // Scan result/error events for session-limit language
          if (event.type === "result" && event.is_error && isSessionLimitError(event.result || "")) {
            stderrBuffer += event.result;
          }
          toolCount = handleStreamEvent(event, logPath, t0, toolCount);
        } catch {
          // non-JSON line — ignore
        }
      }
    });

    // Also scan stderr directly (claude sometimes writes limits there)
    proc.stderr.on("data", (chunk) => {
      const text = chunk.toString("utf8");
      process.stderr.write(text); // still show it to user
      stderrBuffer += text;
    });

    proc.on("close", (code) => {
      clearInterval(heartbeat);
      process.stdout.write("\r" + " ".repeat(50) + "\r");
      if (code !== 0) {
        // Distinguish session-limit from real crash
        if (isSessionLimitError(stderrBuffer)) {
          reject(new SessionLimitError(`Claude session limit reached: ${stderrBuffer.slice(0, 200)}`));
        } else {
          reject(new Error(`claude exited with status ${code}`));
        }
      } else {
        resolve();
      }
    });

    proc.on("error", (err) => {
      clearInterval(heartbeat);
      reject(new Error(`Failed to launch claude: ${err.message}`));
    });
  });
}

async function invokeAgent(cli, role, context, args, extraText = "", logPath = null) {
  const label = `${role}[${context.asset}]`;
  if (logPath) logEvent(logPath, `→ Starting ${label} agent`);
  printFlavour(role === "researcher" ? "researcher_start" : "triager_start");
  const t0 = Date.now();

  if (cli === "claude") {
    // SessionLimitError propagates up unchanged — callers handle it.
    // Inject absolute output paths so the agent writes to targets/<name>/findings/
    // regardless of which directory the Claude process starts in.
    const pathHint = context.findingsDir
      ? `\n\nOUTPUT PATHS (use these exact absolute paths):\n` +
        `  findings/confirmed/report_bundle.json  →  ${path.join(context.findingsDir, "confirmed", "report_bundle.json")}\n` +
        `  findings/unconfirmed/candidates.json   →  ${path.join(context.findingsDir, "unconfirmed", "candidates.json")}\n` +
        `  findings/triage_result.json            →  ${path.join(context.findingsDir, "triage_result.json")}\n` +
        `  findings/h1_submission_ready/          →  ${context.reportsDir}\n`
      : "";
    const prompt =
      role === "researcher"
        ? `/researcher --asset ${context.asset} --mode ${context.mode} ${context.target}${pathHint}${extraText}`
        : `/triager --asset ${context.asset}${pathHint}`;
    await spawnClaude(prompt, args.model, logPath);
    if (logPath) logEvent(logPath, `← ${label} agent done in ${Math.round((Date.now() - t0) / 1000)}s`);
    return;
  }

  if (cli === "codex") {
    const prompt = runCommandCapture("node", [
      "scripts/compose-agent-prompt.js",
      role,
      "--asset",
      context.asset,
      ...(role === "researcher" ? ["--mode", context.mode] : []),
      ...(context.targetRef ? ["--target", context.targetRef] : []),
    ]);
    runCommand("codex", [prompt + (extraText ? `\n\n${extraText}` : "")]);
    if (logPath) logEvent(logPath, `← ${label} agent done in ${Math.round((Date.now() - t0) / 1000)}s`);
    return;
  }

  throw new Error(`Unsupported CLI '${cli}'. Use --cli claude or --cli codex.`);
}

function syncBbscopeIfPossible(context, logPath) {
  if (!context.config || !context.targetRef) return;

  // bbscope requires no credentials — always attempt if platform is detectable
  logEvent(logPath, "Syncing bbscope intelligence (no credentials required)");
  try {
    runCommand("node", ["scripts/sync-bbscope-intel.js", "--target", context.targetRef]);
    logEvent(logPath, "bbscope intelligence sync complete");
  } catch (error) {
    logEvent(logPath, `bbscope intelligence sync failed: ${error.message}`);
  }
}

function syncHackerOneIfPossible(context, logPath) {
  const programHandle = context.config ? deriveProgramHandle(context.config) : null;
  const syncEnabled = context.config?.hackerone?.sync_enabled ?? false;

  if (!context.config || !syncEnabled || !programHandle) {
    return;
  }

  if (!(process.env.H1_API_USERNAME || process.env.HACKERONE_API_USERNAME) ||
      !(process.env.H1_API_TOKEN || process.env.HACKERONE_API_TOKEN)) {
    logEvent(logPath, "Skipping HackerOne sync: credentials not set in current process");
    return;
  }

  logEvent(logPath, `Syncing HackerOne intelligence for ${programHandle}`);
  try {
    runCommand("node", ["scripts/sync-hackerone-intel.js", "--target", context.targetRef]);
    logEvent(logPath, "HackerOne intelligence sync complete");
  } catch (error) {
    logEvent(logPath, `HackerOne intelligence sync failed: ${error.message}`);
  }
}

function buildResearchBriefIfPossible(context, logPath) {
  if (!context.config || !context.targetRef) {
    return;
  }

  try {
    runCommand("node", ["scripts/build-research-brief.js", "--target", context.targetRef]);
    logEvent(logPath, "Research brief refreshed from local/global intelligence");
  } catch (error) {
    logEvent(logPath, `Research brief refresh failed: ${error.message}`);
  }
}

async function runResearcherPhase(cli, assetContext, args, bundlePath, isAdditional, runLog, resumeHint = "") {
  let extraText = isAdditional
    ? `\n\nIMPORTANT: A report_bundle.json already exists from a previous asset pass. APPEND your new findings to it — do NOT remove or overwrite existing entries.`
    : "";
  if (resumeHint) extraText += resumeHint;
  logEvent(runLog, `Starting researcher phase asset=${assetContext.asset} source=${assetContext.target}`);
  // SessionLimitError propagates to main() — do not catch here
  await invokeAgent(cli, "researcher", assetContext, args, extraText, runLog);
  printFlavour("researcher_done");
}

async function runTriagePhase(cli, context, args, bundlePath, triagePath, runLog) {
  for (let round = 0; round < args.maxNmiRounds; round += 1) {
    logEvent(runLog, `Starting triager round ${round + 1}`);
    await invokeAgent(cli, "triager", context, args, "", runLog);

    if (!fs.existsSync(triagePath)) {
      logEvent(runLog, "Triage result missing, generating deterministic local fallback");
      runCommand("node", [
        "scripts/triage-bundle.js",
        bundlePath,
        triagePath,
        "--intelligence-dir",
        context.intelligenceDir
      ]);
    }

    runCommand("node", ["scripts/validate-triage-result.js", triagePath, bundlePath]);
    runCommand("node", ["scripts/render-h1-reports.js", bundlePath, triagePath, context.reportsDir]);

    const nmiResults = (readJson(triagePath).results || []).filter(
      (item) => item.triage_verdict === "NEEDS_MORE_INFO"
    );
    if (nmiResults.length === 0) {
      printFlavour("triager_done");
      logEvent(runLog, "No NEEDS_MORE_INFO findings remain");
      break;
    }

    printFlavour("nmi");
    logEvent(runLog, `${nmiResults.length} finding(s) require more info`);
    const nmiText = nmiResults
      .map((result) => `Finding ${result.report_id}: ${(result.nmi_questions || []).join(" ")}`)
      .join("\n");
    await invokeAgent(
      cli,
      "researcher",
      context,
      args,
      `\nThe triager requires more information on these findings:\n${nmiText}\n\nUpdate findings/confirmed/report_bundle.json with the missing details.`,
      runLog
    );
    runCommand("node", ["scripts/validate-bundle.js", bundlePath]);
  }
}

// ─── Interactive finding review ────────────────────────────────────────────────
async function reviewFindings(bundlePath, logPath) {
  if (!fs.existsSync(bundlePath)) return;

  const bundle = readJson(bundlePath);
  const findings = bundle.findings || [];
  if (findings.length === 0) {
    logEvent(logPath, "No confirmed findings to review");
    return;
  }

  const bar = "─".repeat(72);
  process.stdout.write(`\n${bar}\n`);
  process.stdout.write(`MANUAL REVIEW — ${findings.length} finding(s) to validate before triage\n`);
  process.stdout.write(`${bar}\n`);

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const ask = (q) => new Promise((resolve) => rl.question(q, resolve));

  const approved = [];
  for (const f of findings) {
    process.stdout.write(`\n▶ [${f.report_id}] ${f.finding_title}\n`);
    process.stdout.write(`   Severity  : ${f.severity_claimed}\n`);
    process.stdout.write(`   Component : ${f.affected_component}\n`);
    process.stdout.write(`   Summary   : ${f.summary}\n`);
    process.stdout.write(`   PoC type  : ${f.poc_type || "?"}\n`);

    let choice = "";
    while (!["y", "n", "v"].includes(choice)) {
      choice = (await ask("   [y] approve  [n] reject  [v] view full PoC → ")).trim().toLowerCase();
    }

    if (choice === "v") {
      process.stdout.write(`\nPoC:\n${f.poc_code || "(none)"}\n\n`);
      process.stdout.write(`Steps:\n${(f.steps_to_reproduce || []).map((s, i) => `  ${i + 1}. ${s}`).join("\n")}\n\n`);
      let choice2 = "";
      while (!["y", "n"].includes(choice2)) {
        choice2 = (await ask("   [y] approve  [n] reject → ")).trim().toLowerCase();
      }
      choice = choice2;
    }

    if (choice === "y") {
      approved.push(f);
    } else {
      logEvent(logPath, `Finding ${f.report_id} rejected during manual review`);
    }
  }

  rl.close();

  const rejectedCount = findings.length - approved.length;
  if (rejectedCount > 0) {
    bundle.findings = approved;
    writeJson(bundlePath, bundle);
  }
  process.stdout.write(`${bar}\n`);
  logEvent(logPath, `Manual review: ${approved.length} approved, ${rejectedCount} rejected`);
}

// ─── Auto-init missing target ──────────────────────────────────────────────────
async function ensureTargetInitialized(targetRef) {
  // Check if target already exists
  let exists = false;
  try {
    const p = resolveTargetConfigPath(targetRef);
    exists = fs.existsSync(p);
  } catch {
    exists = false;
  }
  if (exists) return;

  const targetDir = path.resolve("targets", targetRef);

  process.stdout.write(`\nTarget '${targetRef}' not found. Starting setup wizard...\n\n`);

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const ask = (q) => new Promise((resolve) => rl.question(q, resolve));

  process.stdout.write(`Supported platforms: HackerOne, Intigriti, YesWeHack (scope auto-synced via bbscope)\n`);
  process.stdout.write(`Examples:\n`);
  process.stdout.write(`  https://hackerone.com/acme\n`);
  process.stdout.write(`  https://intigriti.com/programs/acme\n`);
  process.stdout.write(`  https://yeswehack.com/programs/acme\n`);
  process.stdout.write(`  https://bbscope.com/programs/h1/acme\n\n`);
  const programUrl = (await ask("Program URL (HackerOne / Intigriti / YesWeHack / bbscope, Enter to skip): ")).trim() || "[INSERT]";
  const programHandle = (await ask("Program handle / slug (Enter to skip): ")).trim() || "[INSERT]";

  // Create workspace directories before asking for source, so the user
  // can clone/copy into the correct path shown in the prompt
  const srcDir = path.join(targetDir, "src");
  for (const rel of ["findings/confirmed", "findings/unconfirmed", "findings/h1_submission_ready", "src", "logs", "intelligence"]) {
    ensureDir(path.join(targetDir, rel));
  }

  process.stdout.write(`\nWorkspace created: ${targetDir}\n`);
  process.stdout.write(`\nPlace your source files in:\n  ${srcDir}\n\n`);
  process.stdout.write(`You can:\n`);
  process.stdout.write(`  • clone a repo:  git clone <url> "${srcDir}\\<repo-name>"\n`);
  process.stdout.write(`  • copy a folder: xcopy /E /I <src> "${srcDir}\\<name>"\n\n`);

  await ask("Press Enter when the source is ready...");

  // ── Asset detection with interactive review ──────────────────────────────
  const ASSET_TYPES_LIST = ["webapp", "chromeext", "mobileapp", "executable"];
  let detectedAssets = [];

  if (fs.existsSync(srcDir) && fs.readdirSync(srcDir).length > 0) {
    try {
      detectedAssets = detectAssetsInSrcDir(srcDir, targetDir);
    } catch { /* best-effort */ }
  }

  if (detectedAssets.length === 0) {
    process.stdout.write("\nNo assets detected in src/. Defaulting to webapp.\n");
    detectedAssets = [{ asset_type: "webapp", source_path: "./src" }];
  }

  process.stdout.write(`\n${"─".repeat(60)}\n`);
  process.stdout.write(`Assets detected: ${detectedAssets.length}\n`);
  process.stdout.write(`${"─".repeat(60)}\n\n`);

  const confirmedAssets = [];
  for (let i = 0; i < detectedAssets.length; i += 1) {
    const a = detectedAssets[i];
    const absPath = path.resolve(targetDir, a.source_path);
    const description = describeAsset(absPath, a.asset_type);

    process.stdout.write(`[${i + 1}/${detectedAssets.length}] ${a.source_path}\n`);
    process.stdout.write(`  Detected as : ${description}\n`);
    process.stdout.write(`  Type options: ${ASSET_TYPES_LIST.join(" | ")}\n`);

    const answer = (await ask(`  Confirm type [Enter = ${a.asset_type}] or type to override: `)).trim().toLowerCase();
    const finalType = ASSET_TYPES_LIST.includes(answer) ? answer : a.asset_type;

    const modeAnswer = (await ask(`  Analysis mode [Enter = whitebox] or blackbox: `)).trim().toLowerCase();
    const finalMode = modeAnswer === "blackbox" ? "blackbox" : "whitebox";

    confirmedAssets.push({ asset_type: finalType, source_path: a.source_path, mode: finalMode });
    process.stdout.write(`  → ${finalType} | ${finalMode}\n\n`);
  }

  rl.close();

  // ── Build target.json from confirmed assets ──────────────────────────────
  const primary = confirmedAssets[0];
  const configPath = path.join(targetDir, "target.json");
  const config = {
    schema_version: "1.0",
    target_name: targetRef,
    asset_type: primary.asset_type,
    default_mode: primary.mode || "whitebox",
    allowed_modes: ["whitebox", "blackbox"],
    program_url: programUrl,
    source_path: primary.source_path,
    findings_dir: "./findings",
    h1_reports_dir: "./findings/h1_submission_ready",
    logs_dir: "./logs",
    intelligence_dir: "./intelligence",
    target_version_hint: "[check source]",
    hackerone: { program_handle: programHandle, sync_enabled: false },
    scope: {
      in_scope: ["[INSERT IN-SCOPE ASSETS]"],
      out_of_scope: ["Self-XSS", "DoS", "Known vulnerable libraries without PoC"]
    },
    rules: [
      "Never modify files in ./src",
      "Never test against production",
      "Confirm every finding dynamically before reporting"
    ]
  };

  if (confirmedAssets.length > 1) {
    config.additional_assets = confirmedAssets.slice(1).map((a) => ({
      asset_type: a.asset_type,
      source_path: a.source_path,
      default_mode: a.mode || "whitebox"
    }));
  }

  // Write run scripts
  fs.writeFileSync(
    path.join(targetDir, "run.sh"),
    `#!/bin/bash\nSCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"\ncd "$SCRIPT_DIR"\nnode ../../scripts/run-pipeline.js --target . "$@"\n`,
    "utf8"
  );
  fs.writeFileSync(
    path.join(targetDir, "run.cmd"),
    `@echo off\r\ncd /d "%~dp0"\r\nnode ..\\..\\scripts\\run-pipeline.js --target . %*\r\n`,
    "utf8"
  );

  writeJson(configPath, config);

  // Init SQLite DB
  const dbPath = resolveDatabasePath(path.join(targetDir, "intelligence"));
  const db = openDatabase(dbPath);
  initDatabase(db);
  db.close();

  const assetSummary = confirmedAssets.map((a) => `${a.asset_type} (${a.source_path})`).join(", ");
  process.stdout.write(`${"─".repeat(60)}\n`);
  process.stdout.write(`Workspace ready: ${targetDir}\n`);
  process.stdout.write(`Assets configured: ${assetSummary}\n`);
  process.stdout.write(`${"─".repeat(60)}\n\n`);

  // Auto-sync bbscope scope data for the new target (no credentials needed)
  if (programUrl && programUrl !== "[INSERT]") {
    process.stdout.write(`Syncing scope intelligence from bbscope.com...\n`);
    try {
      const syncResult = spawnSync(
        process.platform === "win32" ? "node.exe" : "node",
        ["scripts/sync-bbscope-intel.js", "--target", targetRef],
        { stdio: "inherit", shell: false }
      );
      if (syncResult.status === 0) {
        process.stdout.write(`bbscope sync complete.\n\n`);
      } else {
        process.stdout.write(`bbscope sync skipped (platform not recognised or handle unknown — run manually later).\n\n`);
      }
    } catch {
      process.stdout.write(`bbscope sync failed — run manually: node scripts/sync-bbscope-intel.js --target ${targetRef}\n\n`);
    }
  }
}

function printSessionLimitMessage(context, args, phase) {
  const bar = "═".repeat(72);
  const resumeCmd = args.targetRef
    ? `node scripts/run-pipeline.js --target ${args.targetRef} --cli ${args.cli} --resume`
    : `node scripts/run-pipeline.js --asset ${args.asset || context.asset} --mode ${args.mode || context.mode} --resume`;

  process.stdout.write(`\n${bar}\n`);
  process.stdout.write(`SESSION LIMIT REACHED\n`);
  process.stdout.write(`\n`);
  process.stdout.write(`Claude Pro usage cap hit during the ${phase} phase.\n`);
  process.stdout.write(`Checkpoint saved — no work lost.\n`);
  process.stdout.write(`  Checkpoint : ${checkpointPath(context)}\n`);
  process.stdout.write(`\n`);
  process.stdout.write(`When your session resets, resume with:\n`);
  process.stdout.write(`\n`);
  process.stdout.write(`  ${resumeCmd}\n`);
  process.stdout.write(`\n`);
  process.stdout.write(`The pipeline will pick up exactly where it stopped.\n`);
  process.stdout.write(`${bar}\n\n`);
}

async function main() {
  const args = parseArgs(process.argv);

  // Auto-initialize target workspace if it doesn't exist yet
  if (args.targetRef) {
    await ensureTargetInitialized(args.targetRef);
  }

  const context = buildContext(args);
  if (!context.asset || !context.mode) {
    throw new Error(
      "Usage: node scripts/run-pipeline.js --target <target> [--cli claude] [--interactive] [--resume]\n" +
      "       node scripts/run-pipeline.js --asset <type> --mode <whitebox|blackbox> [path]"
    );
  }

  for (const dir of [
    context.findingsDir,
    path.join(context.findingsDir, "confirmed"),
    path.join(context.findingsDir, "unconfirmed"),
    context.reportsDir,
    context.logsDir,
    context.intelligenceDir
  ]) {
    ensureDir(dir);
  }

  const runLog = path.join(
    context.logsDir,
    `pipeline-${new Date().toISOString().replace(/[-:]/g, "").replace(/\..+/, "Z")}.log`
  );

  const additionalAssets = context.config && Array.isArray(context.config.additional_assets)
    ? context.config.additional_assets
    : [];
  const allAssets = [
    { asset_type: context.asset, source_path: null, target: context.target },
    ...additionalAssets.map((a) => ({
      asset_type: a.asset_type,
      source_path: a.source_path,
      target: context.targetDir ? path.resolve(context.targetDir, a.source_path) : a.source_path
    }))
  ];

  // ── Checkpoint / resume ───────────────────────────────────────────────────
  const checkpoint = args.resume ? loadCheckpoint(context) : null;
  if (checkpoint) {
    logEvent(runLog, `Resuming from checkpoint: phase=${checkpoint.phase} assetIndex=${checkpoint.assetIndex}`);
    printFlavour("resume");
    const bar = "─".repeat(72);
    process.stdout.write(`\n${bar}\n`);
    process.stdout.write(`RESUME MODE — continuing from checkpoint\n`);
    process.stdout.write(`  Phase      : ${checkpoint.phase}\n`);
    process.stdout.write(`  Asset      : ${checkpoint.assetIndex + 1}/${checkpoint.totalAssets} (${checkpoint.asset})\n`);
    if (checkpoint.findingsCount !== undefined) {
      process.stdout.write(`  Findings   : ${checkpoint.findingsCount} confirmed so far\n`);
    }
    process.stdout.write(`${bar}\n\n`);
  }

  logEvent(runLog, `Starting pipeline assets=${allAssets.map((a) => a.asset_type).join(",")} mode=${context.mode} cli=${args.cli}`);

  // Only re-sync if this is a fresh run (not resume — intel is already current)
  if (!checkpoint) {
    syncBbscopeIfPossible(context, runLog);
    syncHackerOneIfPossible(context, runLog);
    buildResearchBriefIfPossible(context, runLog);
  }

  const bundlePath = path.join(context.findingsDir, "confirmed", "report_bundle.json");
  const triagePath = path.join(context.findingsDir, "triage_result.json");

  // If checkpoint says triage was interrupted, skip the researcher loop entirely
  if (checkpoint && checkpoint.phase === "triage") {
    logEvent(runLog, "Resuming at triage phase — skipping researcher loop");
  }

  // Determine start index from checkpoint
  const startAssetIndex = (checkpoint && checkpoint.phase === "researcher") ? checkpoint.assetIndex : 0;

  for (let index = startAssetIndex; !(checkpoint && checkpoint.phase === "triage") && index < allAssets.length; index += 1) {
    const assetEntry = allAssets[index];
    let resolvedTarget = assetEntry.target || context.target;

    // Auto-decompile APK/APKX files before the researcher pass
    if (assetEntry.asset_type === "mobileapp" && /\.(apk|apkx)$/i.test(resolvedTarget)) {
      const decompDir = path.join(path.dirname(resolvedTarget), "decompiled");
      printFlavour("apk_decompile");
      logEvent(runLog, `APK detected — decompiling ${path.basename(resolvedTarget)} to ${decompDir}`);
      try {
        runCommand("node", ["scripts/decompile-apk.js", resolvedTarget, "--out", decompDir]);
        resolvedTarget = decompDir;
        logEvent(runLog, `Researcher will analyse decompiled output: ${decompDir}`);
      } catch (err) {
        logEvent(runLog, `APK decompilation failed: ${err.message} — passing raw APK to researcher`);
      }
    }

    const assetContext = {
      ...context,
      asset: assetEntry.asset_type,
      target: resolvedTarget
    };

    // Pause between assets so the user can review before the next researcher pass
    if (index > 0) {
      const bar = "─".repeat(72);
      process.stdout.write(`\n${bar}\n`);
      process.stdout.write(`Asset ${index}/${allAssets.length - 1} complete.\n`);
      process.stdout.write(`Next: ${assetEntry.asset_type} — ${assetEntry.target}\n`);
      process.stdout.write(`${bar}\n`);
      const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
      await new Promise((resolve) => rl.question("Press Enter to start next researcher pass (Ctrl+C to stop)... ", () => { rl.close(); resolve(); }));
    }

    // Build a resume hint if we're starting mid-session after a limit error
    const isResume = checkpoint && checkpoint.phase === "researcher" && index === startAssetIndex;
    const resumeHint = isResume && checkpoint.findingsCount
      ? `\n\nSESSION RESUME: Your previous session was interrupted by a usage limit. ` +
        `${checkpoint.findingsCount} finding(s) are already confirmed in report_bundle.json. ` +
        `Continue the analysis — do NOT re-analyse findings already in the bundle. ` +
        `Pick up from where you left off.`
      : "";

    try {
      await runResearcherPhase(args.cli, assetContext, args, bundlePath, index > 0, runLog, resumeHint);
    } catch (err) {
      if (err.name === "SessionLimitError") {
        const findingsCount = fs.existsSync(bundlePath)
          ? (readJson(bundlePath).findings || []).length
          : 0;
        saveCheckpoint(context, {
          phase: "researcher",
          assetIndex: index,
          asset: assetEntry.asset_type,
          totalAssets: allAssets.length,
          findingsCount,
          savedAt: new Date().toISOString()
        });
        logEvent(runLog, `SESSION LIMIT: checkpoint saved at asset ${index} (${findingsCount} findings so far)`);
        printFlavour("session_limit");
        printSessionLimitMessage(context, args, "researcher");
        return;
      }
      throw err;
    }
  }

  if (!fs.existsSync(bundlePath)) {
    logEvent(runLog, `Researcher produced no report bundle at ${bundlePath}`);
    return;
  }

  runCommand("node", ["scripts/validate-bundle.js", bundlePath]);
  const findingCount = (readJson(bundlePath).findings || []).length;
  logEvent(runLog, `All researcher passes complete with ${findingCount} confirmed finding(s)`);

  // Print triager hint so the user knows what to run next
  const bar = "─".repeat(72);
  process.stdout.write(`\n${bar}\n`);
  process.stdout.write(`Researcher done — ${findingCount} finding(s) confirmed.\n`);
  process.stdout.write(`\nTo run the triager now:\n`);
  process.stdout.write(`  /triager --asset ${context.asset}\n`);
  if (args.targetRef) {
    process.stdout.write(`\nOr run the full pipeline (researcher + triager) in one shot:\n`);
    process.stdout.write(`  node scripts/run-pipeline.js --target ${args.targetRef} --cli ${args.cli}\n`);
  }
  process.stdout.write(`${bar}\n\n`);

  // Render PoC files + summary.md into targets/<name>/poc/
  const pocDir = context.targetDir
    ? path.join(context.targetDir, "poc")
    : path.join(context.findingsDir, "..", "poc");
  try {
    runCommand("node", ["scripts/render-poc-artifacts.js", bundlePath, "--poc-dir", pocDir]);
    logEvent(runLog, `PoC artifacts written to: ${pocDir}`);
  } catch (err) {
    logEvent(runLog, `PoC artifact rendering failed: ${err.message}`);
  }

  // Optional manual review before triage
  if (args.interactive) {
    await reviewFindings(bundlePath, runLog);
  }

  // If we resumed from a researcher checkpoint and triage isn't needed yet, skip saving triage checkpoint
  // (triage is a single-target phase — checkpoint just marks it as in-progress)
  try {
    await runTriagePhase(args.cli, context, args, bundlePath, triagePath, runLog);
  } catch (err) {
    if (err.name === "SessionLimitError") {
      const findingsCount = (readJson(bundlePath).findings || []).length;
      saveCheckpoint(context, {
        phase: "triage",
        assetIndex: allAssets.length - 1,
        asset: context.asset,
        totalAssets: allAssets.length,
        findingsCount,
        savedAt: new Date().toISOString()
      });
      logEvent(runLog, `SESSION LIMIT during triage: checkpoint saved (${findingsCount} findings)`);
      printFlavour("session_limit");
      printSessionLimitMessage(context, args, "triage");
      return;
    }
    throw err;
  }

  // Pipeline finished cleanly — remove any stale checkpoint
  clearCheckpoint(context);

  const readyCount = fs.existsSync(context.reportsDir)
    ? fs.readdirSync(context.reportsDir).filter((entry) => entry.endsWith(".md")).length
    : 0;
  printFlavour("pipeline_complete");
  logEvent(runLog, `Pipeline complete with ${readyCount} H1-ready report(s)`);
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
