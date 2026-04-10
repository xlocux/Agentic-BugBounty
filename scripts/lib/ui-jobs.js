"use strict";
const fs     = require("node:fs");
const path   = require("node:path");
const { spawn } = require("node:child_process");

let _seq = 0;

function logsDir() {
  return process.env.UI_LOGS_DIR || path.resolve(__dirname, "../../logs/ui");
}
function jobsFile() { return path.join(logsDir(), "jobs.json"); }

function ensureDir() { fs.mkdirSync(logsDir(), { recursive: true }); }

function loadJobs() {
  ensureDir();
  try { return JSON.parse(fs.readFileSync(jobsFile(), "utf8")); }
  catch { return []; }
}

function saveJobs(jobs) {
  ensureDir();
  fs.writeFileSync(jobsFile(), JSON.stringify(jobs, null, 2), "utf8");
}

function createJob({ target, script, args = [] }) {
  const id  = `job-${Date.now()}-${++_seq}-${target}`;
  const job = {
    id, target, script, args,
    pid: null, started: null, finished: null,
    status: "pending",
    log_file: path.join(logsDir(), `${id}.log`),
    byte_offset: 0
  };
  const jobs = loadJobs();
  jobs.unshift(job);
  saveJobs(jobs);
  return job;
}

function _updateJob(id, patch) {
  const jobs = loadJobs();
  const idx  = jobs.findIndex(j => j.id === id);
  if (idx === -1) return null;
  Object.assign(jobs[idx], patch);
  saveJobs(jobs);
  return jobs[idx];
}

function startJob(job) {
  ensureDir();
  const logStream = fs.createWriteStream(job.log_file, { flags: "a" });
  const child = spawn(job.script, job.args, {
    stdio: ["ignore", "pipe", "pipe"],
    shell: false,
    detached: false
  });
  job.pid     = child.pid;
  job.status  = "running";
  job.started = new Date().toISOString();
  _updateJob(job.id, { pid: job.pid, status: "running", started: job.started });

  child.stdout.on("data", chunk => logStream.write(chunk));
  child.stderr.on("data", chunk => logStream.write(chunk));
  child.on("close", code => {
    logStream.end();
    _updateJob(job.id, {
      status:   code === 0 ? "done" : "error",
      finished: new Date().toISOString(),
      exit_code: code
    });
  });
  return job;
}

function stopJob(id) {
  const job = getJob(id);
  if (!job || !job.pid) return;
  if (["done", "error", "stopped"].includes(job.status)) return;
  try { process.kill(job.pid, "SIGTERM"); } catch {}
  _updateJob(id, { status: "stopped", finished: new Date().toISOString() });
}

function getJob(id) {
  return loadJobs().find(j => j.id === id) || null;
}

function reconcileJobs() {
  const jobs = loadJobs();
  let changed = false;
  for (const job of jobs) {
    if (job.status !== "running") continue;
    const alive = job.pid && (() => { try { process.kill(job.pid, 0); return true; } catch { return false; } })();
    if (!alive) {
      job.status = "error";
      job.finished = job.finished || new Date().toISOString();
      job.exit_code = job.exit_code ?? -1;
      changed = true;
    }
  }
  if (changed) saveJobs(jobs);
}

function listJobs() {
  reconcileJobs();
  return loadJobs();
}

// Tail log file from byteOffset, calling onLine for each new line.
// Calls onDone when job status is done/error/stopped.
// Returns a cancel function.
function tailJob(id, fromByte, onLine, onDone) {
  let offset   = fromByte || 0;
  let cancelled = false;

  function poll() {
    if (cancelled) return;
    const job = getJob(id);
    if (!job) { onDone({ exit_code: -1 }); return; }

    let stat;
    try { stat = fs.statSync(job.log_file); } catch { stat = { size: 0 }; }

    if (stat.size > offset) {
      const buf = Buffer.allocUnsafe(stat.size - offset);
      const fd  = fs.openSync(job.log_file, "r");
      fs.readSync(fd, buf, 0, buf.length, offset);
      fs.closeSync(fd);
      offset = stat.size;
      _updateJob(id, { byte_offset: offset });

      const lines = buf.toString("utf8").split("\n");
      for (const line of lines) {
        if (line.trim()) onLine(line, offset);
      }
    }

    if (["done", "error", "stopped"].includes(job.status)) {
      if (!cancelled) onDone({ exit_code: job.exit_code ?? 0 });
      return;
    }
    setTimeout(poll, 250);
  }

  setTimeout(poll, 100);
  return () => { cancelled = true; };
}

module.exports = { createJob, startJob, stopJob, getJob, listJobs, tailJob };
