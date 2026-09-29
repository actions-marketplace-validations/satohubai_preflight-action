// Offline end-to-end tests for template-drift mode. `node --test test/drift.test.mjs`.
// Runs src/main.mjs as a child process against two in-test HTTP servers: a fake
// GitHub REST API and a fake Sato Hub drift endpoint. Both close when done.

import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { markerFor, pendingChanges, issueFor } from "../src/drift.mjs";

const MAIN = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "main.mjs");
const BANNED = /\b(safe|safely|unsafe|secure|insecure|malicious|best|guaranteed)\b/i;

const CHANGES = [
  { key: "template:base-guarded-trader/plain-ts@sha256:bbb", kind: "template_update", title: "Template base-guarded-trader/plain-ts has a newer green version", body_markdown: "Version 0.2.0 is green.\n\nRun `npx create-sato-agent update`.", evidence_urls: ["https://satohub.ai/create/templates"] },
  { key: "broken:viem@2.40.0", kind: "upstream_break", title: "viem 2.40.0 broke the template build", body_markdown: "The latest lane went red on viem 2.40.0.", evidence_urls: ["https://github.com/satohubai/sato-agent-templates/actions/runs/1"] },
];

function fakeGitHub() {
  const issues = [];
  const calls = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (d) => (body += d));
    req.on("end", () => {
      const u = new URL(req.url, "http://x");
      calls.push({ method: req.method, path: u.pathname, query: u.search, ua: req.headers["user-agent"] });
      const send = (code, j) => { res.writeHead(code, { "content-type": "application/json" }); res.end(JSON.stringify(j)); };
      if (req.method === "GET" && u.pathname === "/repos/o/r/issues") {
        assert.equal(u.searchParams.get("state"), "all");
        const label = u.searchParams.get("labels");
        const page = Number(u.searchParams.get("page") || 1);
        const rows = issues.filter((i) => !label || i.labels.includes(label));
        return send(200, rows.slice((page - 1) * 100, page * 100));
      }
      if (req.method === "POST" && u.pathname === "/repos/o/r/issues") {
        const j = JSON.parse(body);
        const n = issues.length + 1;
        issues.push({ number: n, state: "open", title: j.title, body: j.body, labels: j.labels || [], html_url: `https://github.com/o/r/issues/${n}` });
        return send(201, issues[n - 1]);
      }
      if (u.pathname.startsWith("/search/")) return send(200, { items: [] });
      send(404, { message: "not found" });
    });
  });
  return { server, issues, calls };
}

function fakeDrift(changes, status = 200) {
  const seen = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (d) => (body += d));
    req.on("end", () => {
      seen.push({ path: req.url, body: JSON.parse(body || "null"), ua: req.headers["user-agent"] });
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(status === 200 ? {
        schema: "sato.template-drift/v1",
        template: { id: "base-guarded-trader", framework: "plain-ts", pinned_version: "0.1.0", pinned_digest: "sha256:aaa", latest_version: "0.2.0", latest_digest: "sha256:bbb", latest_last_green: "2026-09-27" },
        changes,
      } : { error: "down" }));
    });
  });
  return { server, seen };
}

const listen = (s) => new Promise((r) => s.listen(0, "127.0.0.1", () => r(`http://127.0.0.1:${s.address().port}`)));
const close = (s) => new Promise((r) => s.close(r));

function run(env) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [MAIN], { env: { PATH: process.env.PATH, ...env } });
    let out = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (out += d));
    p.on("close", (code) => resolve({ code, out }));
  });
}

function workspace({ create = true } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "sato-drift-"));
  if (create) {
    writeFileSync(join(dir, "sato.create.json"), JSON.stringify({ template: "base-guarded-trader", framework: "plain-ts", version: "0.1.0" }));
    writeFileSync(join(dir, "sato.lock.json"), JSON.stringify({ packages: { viem: "2.40.0" } }));
  }
  writeFileSync(join(dir, "summary.md"), "");
  return dir;
}

async function setup(changes, driftStatus = 200) {
  const gh = fakeGitHub();
  const dr = fakeDrift(changes, driftStatus);
  const ghUrl = await listen(gh.server);
  const drUrl = await listen(dr.server);
  const ws = workspace();
  const env = (extra = {}) => ({
    INPUT_MODE: "template-drift", INPUT_API: drUrl, "INPUT_GITHUB-TOKEN": "test-token",
    GITHUB_API_URL: ghUrl, GITHUB_REPOSITORY: "o/r", GITHUB_WORKSPACE: ws,
    GITHUB_STEP_SUMMARY: join(ws, "summary.md"), ...extra,
  });
  const done = async () => { await close(gh.server); await close(dr.server); rmSync(ws, { recursive: true, force: true }); };
  return { gh, dr, ws, env, done };
}

test("first run opens one issue per change; a second run opens none", async () => {
  const t = await setup(CHANGES);
  try {
    const a = await run(t.env());
    assert.equal(a.code, 0, a.out);
    assert.equal(t.gh.issues.length, 2);
    for (const c of CHANGES) {
      const hits = t.gh.issues.filter((i) => i.body.includes(`<!-- sato-drift:${c.key} -->`));
      assert.equal(hits.length, 1, c.key);
      assert.deepEqual(hits[0].labels, ["sato-drift"]);
      assert.doesNotMatch(hits[0].body + hits[0].title, BANNED);
    }
    // Only create + lock are sent, with the published UA.
    assert.deepEqual(Object.keys(t.dr.seen[0].body).sort(), ["create", "lock"]);
    assert.equal(t.dr.seen[0].path, "/api/create/drift");
    assert.match(t.dr.seen[0].ua, /^satohub-preflight-action\//);
    // Never a pull request, never a comment.
    assert.ok(!t.gh.calls.some((c) => c.path.includes("/pulls") || c.path.includes("/comments")));
    const summary = readFileSync(join(t.ws, "summary.md"), "utf8");
    assert.match(summary, /Sato template drift/);
    assert.doesNotMatch(summary, BANNED);

    const posts = t.gh.calls.filter((c) => c.method === "POST").length;
    const b = await run(t.env());
    assert.equal(b.code, 0, b.out);
    assert.equal(t.gh.issues.length, 2);
    assert.equal(t.gh.calls.filter((c) => c.method === "POST").length, posts);
  } finally { await t.done(); }
});

test("a closed issue is not reopened or duplicated, even without its label", async () => {
  const t = await setup(CHANGES);
  try {
    t.gh.issues.push({ number: 1, state: "closed", title: "old", body: `${markerFor(CHANGES[0].key)}\nwon't do`, labels: [], html_url: "x" });
    const a = await run(t.env());
    assert.equal(a.code, 0, a.out);
    assert.equal(t.gh.issues.length, 2); // only the second change was opened
    assert.equal(t.gh.issues[0].state, "closed");
    assert.ok(t.gh.issues[1].body.includes(markerFor(CHANGES[1].key)));
    assert.ok(!t.gh.calls.some((c) => c.method === "PATCH"));
  } finally { await t.done(); }
});

test("no sato.create.json: a notice and exit 0, nothing called", async () => {
  const t = await setup(CHANGES);
  try {
    rmSync(join(t.ws, "sato.create.json"));
    const a = await run(t.env());
    assert.equal(a.code, 0);
    assert.match(a.out, /::notice::.*no sato\.create\.json/);
    assert.equal(t.dr.seen.length, 0);
    assert.equal(t.gh.calls.length, 0);
  } finally { await t.done(); }
});

test("drift API down: a warning, no issues, exit 0 — non-zero only with fail_on_error", async () => {
  const t = await setup(CHANGES, 503);
  try {
    const a = await run(t.env());
    assert.equal(a.code, 0, a.out);
    assert.match(a.out, /::warning::.*drift endpoint/);
    assert.equal(t.gh.issues.length, 0);
    const b = await run(t.env({ INPUT_FAIL_ON_ERROR: "true" }));
    assert.equal(b.code, 1, b.out);
    assert.equal(t.gh.issues.length, 0);
  } finally { await t.done(); }
});

test("drift API unreachable (closed port): warning, exit 0", async () => {
  const t = await setup(CHANGES);
  try {
    const a = await run(t.env({ INPUT_API: "http://127.0.0.1:1" }));
    assert.equal(a.code, 0, a.out);
    assert.match(a.out, /::warning::/);
    assert.equal(t.gh.issues.length, 0);
  } finally { await t.done(); }
});

test("no changes: nothing opened", async () => {
  const t = await setup([]);
  try {
    const a = await run(t.env());
    assert.equal(a.code, 0, a.out);
    assert.equal(t.gh.calls.length, 0);
  } finally { await t.done(); }
});

test("pure helpers: pendingChanges dedups keys; issueFor carries marker and label", () => {
  const dup = [CHANGES[0], CHANGES[0], { kind: "x" }];
  assert.equal(pendingChanges(dup, []).length, 1);
  assert.equal(pendingChanges(CHANGES, [`x ${markerFor(CHANGES[1].key)} y`]).length, 1);
  const i = issueFor(CHANGES[0]);
  assert.ok(i.body.startsWith(`<!-- sato-drift:${CHANGES[0].key} -->`));
  assert.deepEqual(i.labels, ["sato-drift"]);
  assert.ok(!markerFor("a--b>").slice(4, -4).includes("--"));
});
