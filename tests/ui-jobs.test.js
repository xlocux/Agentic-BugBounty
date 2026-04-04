"use strict";
const test   = require("node:test");
const assert = require("node:assert/strict");
const fs     = require("node:fs");
const os     = require("node:os");
const path   = require("node:path");

// Redirect JOBS_FILE to a temp dir for each test
function makeTmpJobs() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "uijobs-"));
  process.env.UI_LOGS_DIR = dir;
  return dir;
}

const { createJob, startJob, stopJob, getJob, listJobs } = require("../scripts/lib/ui-jobs");

test("createJob returns object with required fields", () => {
  makeTmpJobs();
  const job = createJob({ target: "acme", script: "test", args: ["--flag"] });
  assert.ok(typeof job.id === "string");
  assert.equal(job.target, "acme");
  assert.equal(job.script, "test");
  assert.deepEqual(job.args, ["--flag"]);
  assert.equal(job.status, "pending");
  assert.equal(job.pid, null);
  assert.ok(typeof job.log_file === "string");
});

test("listJobs returns empty array when no jobs file", () => {
  makeTmpJobs();
  const jobs = listJobs();
  assert.deepEqual(jobs, []);
});

test("getJob returns null for unknown id", () => {
  makeTmpJobs();
  assert.equal(getJob("nonexistent"), null);
});

test("startJob spawns process and sets status to running", (t, done) => {
  makeTmpJobs();
  const job = createJob({ target: "test", script: "node", args: ["-e", "console.log('hello'); process.exit(0)"] });
  startJob(job);
  assert.equal(job.status, "running");
  assert.ok(job.pid > 0);
  // wait for completion
  setTimeout(() => {
    const updated = getJob(job.id);
    assert.ok(["running", "done"].includes(updated.status));
    done();
  }, 500);
});

test("stopJob sends SIGTERM and sets status to stopped", (t, done) => {
  makeTmpJobs();
  const job = createJob({ target: "test", script: "node", args: ["-e", "setTimeout(()=>{},60000)"] });
  startJob(job);
  assert.equal(job.status, "running");
  stopJob(job.id);
  setTimeout(() => {
    const updated = getJob(job.id);
    assert.ok(["stopped", "error"].includes(updated.status));
    done();
  }, 400);
});
