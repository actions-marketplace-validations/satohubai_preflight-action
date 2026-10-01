// Offline tests for Sato Check diff mode. `node --test test/custody.test.mjs`.
// No network: git, fetch and the event file are injected.

import test from "node:test";
import assert from "node:assert/strict";
import {
  classifyPath, changedPackages, changedServers, buildRequest, renderReport,
  shouldFail, collect, runCustody, upsertComment, MARKER, UA, repoHeader, postInstall, fetchProfile,
} from "../src/custody.mjs";

const BANNED = /\b(safe|safely|unsafe|secure|insecure|malicious|malware|scam|trusted|trustworthy|passed|risk-free|guaranteed)\b/i;

const pkgBefore = JSON.stringify({ dependencies: { viem: "^2.0.0", left: "1.0.0" }, devDependencies: { typescript: "^5.0.0" } });
const pkgAfter = JSON.stringify({ dependencies: { viem: "^2.1.0", "solana-agent-kit": "^1.0.0", local: "file:../x" }, devDependencies: { typescript: "^5.0.0" } });

const answer = (egress = "not_observed") => ({
  schema: "sato.custody/v1",
  subjects: [{
    subject: { kind: "package", id: "npm:viem", name: "viem" },
    summary: { key_access: "reads", key_egress: egress, fund_action_count: 0, notable: false, version: "2.1.0", as_of: "2026-09-25", method_version: "1", check_url: "https://satohub.ai/check/npm:viem" },
    answers: { key_access: "Yes — it reads private-key material.", key_egress: "Not observed.", fund_actions: "None found.", changes: "No earlier profile." },
  }],
  unresolved: [{ input: "local", reason: "not a registry install" }],
  has_observed_key_egress: egress === "observed",
});

test("classifies the files diff mode reads", () => {
  assert.equal(classifyPath("package.json"), "package");
  assert.equal(classifyPath("apps/web/package.json"), "package");
  assert.equal(classifyPath("node_modules/x/package.json"), null);
  assert.equal(classifyPath(".mcp.json"), "mcp");
  assert.equal(classifyPath("claude_desktop_config.json"), "mcp");
  assert.equal(classifyPath("skills/foo/SKILL.md"), "skill");
  assert.equal(classifyPath(".claude/skills/bar/SKILL.md"), "skill");
  assert.equal(classifyPath("docs/SKILL.md"), null);
  assert.equal(classifyPath("README.md"), null);
});

test("package.json: only added or re-versioned registry deps", () => {
  const c = changedPackages(pkgBefore, pkgAfter);
  assert.deepEqual(c.map((x) => x.name).sort(), ["solana-agent-kit", "viem"]);
  assert.equal(c.find((x) => x.name === "viem").from, "^2.0.0");
  assert.equal(c.find((x) => x.name === "solana-agent-kit").from, null);
  assert.deepEqual(changedPackages("", "not json"), []);
});

test("MCP config: only added or changed server blocks", () => {
  const before = JSON.stringify({ mcpServers: { a: { command: "npx", args: ["-y", "a"] }, b: { command: "npx", args: ["b"] } } });
  const after = JSON.stringify({ mcpServers: { a: { command: "npx", args: ["-y", "a"] }, b: { command: "npx", args: ["b@2"] }, c: { url: "https://x" } } });
  assert.deepEqual(Object.keys(changedServers(before, after)).sort(), ["b", "c"]);
});

test("builds one install command and one config", () => {
  const body = buildRequest({ packages: changedPackages(pkgBefore, pkgAfter), servers: { c: { url: "https://x" } } });
  assert.equal(body.command, "npm install viem@2.1.0 solana-agent-kit@1.0.0");
  assert.deepEqual(JSON.parse(body.config), { mcpServers: { c: { url: "https://x" } } });
  assert.equal(buildRequest({ packages: [], servers: {} }), null);
});

test("report carries the four answers, the marker and no judging words", () => {
  const md = renderReport(answer(), { changes: ["`viem` ^2.0.0 → ^2.1.0"] });
  assert.ok(md.startsWith(MARKER));
  for (const q of ["Does it take your key?", "Does your key leave?", "Can it move funds on its own?", "What changed?"]) assert.ok(md.includes(q), q);
  assert.ok(md.includes("What changed in this PR"));
  assert.ok(md.includes("Not checked: `local`"));
  const text = md.replace(/not a safety rating/g, "");
  assert.ok(!BANNED.test(text), `banned word in: ${text.match(BANNED)}`);
  assert.ok(!BANNED.test(renderReport(null, { error: "HTTP 503", localSkills: 1 }).replace(/not a safety rating/g, "")));
});

test("only an observed egress with the opt-in fails", () => {
  assert.equal(shouldFail(answer("observed"), ["no", "key_egress_observed"]), true);
  assert.equal(shouldFail(answer("observed"), ["no"]), false);
  assert.equal(shouldFail(answer("unknown"), ["key_egress_observed"]), false);
  assert.equal(shouldFail(null, ["key_egress_observed"]), false);
});

test("collect merges manifests and lists skill dirs", () => {
  const now = { "package.json": pkgAfter, "skills/x/SKILL.md": "# x" };
  const got = collect(["package.json", "skills/x/SKILL.md", "src/a.ts"], (p) => (p === "package.json" ? pkgBefore : ""), (p) => now[p] ?? "");
  assert.equal(got.packages.length, 2);
  assert.deepEqual(got.skills, ["skills/x"]);
});

function harness({ status = 200, json = answer(), throwFetch = false, commentStatus = 201, existing = [] } = {}) {
  const calls = [];
  const fetchFn = async (url, init = {}) => {
    calls.push({ url, init });
    if (url.includes("/api/check/install")) {
      if (throwFetch) throw new Error("timeout");
      return { status, ok: status === 200, json: async () => json };
    }
    if (url.includes("/comments?")) return { ok: true, status: 200, json: async () => existing };
    return { ok: commentStatus < 300, status: commentStatus, json: async () => ({}) };
  };
  const logs = [];
  const summaries = [];
  const io = {
    fetch: fetchFn,
    log: (m) => logs.push(m),
    summary: (m) => summaries.push(m),
    readDiff: () => ({ files: ["package.json"], before: () => pkgBefore }),
    readNow: () => pkgAfter,
    readEvent: () => JSON.stringify({ pull_request: { number: 7 } }),
  };
  const env = { GITHUB_EVENT_NAME: "pull_request", GITHUB_BASE_REF: "main", GITHUB_REPOSITORY: "o/r", GITHUB_EVENT_PATH: "/e.json" };
  return { calls, logs, summaries, io, env };
}

test("runCustody: posts once with our UA, writes summary and a sticky comment", async () => {
  const h = harness();
  const r = await runCustody({ api: "https://satohub.ai", failOn: ["no"], token: "t", env: h.env, io: h.io });
  assert.equal(r.code, 0);
  const post = h.calls.find((c) => c.url.endsWith("/api/check/install"));
  assert.equal(post.init.headers["user-agent"], UA);
  assert.ok(post.init.signal, "request carries a timeout signal");
  assert.equal(h.summaries.length, 1);
  assert.ok(h.calls.some((c) => c.url.endsWith("/issues/7/comments") && c.init.method === "POST"));
});

test("runCustody: updates the existing sticky comment instead of adding one", async () => {
  const h = harness({ existing: [{ id: 99, body: `${MARKER}\nold` }] });
  await runCustody({ api: "https://satohub.ai", token: "t", env: h.env, io: h.io });
  assert.ok(h.calls.some((c) => c.url.endsWith("/issues/comments/99") && c.init.method === "PATCH"));
});

test("runCustody fails open: API down, 5xx, comment 403, not a PR", async () => {
  for (const opts of [{ throwFetch: true }, { status: 503, json: { error: "down" } }, { commentStatus: 403 }]) {
    const h = harness(opts);
    const r = await runCustody({ api: "https://satohub.ai", failOn: ["key_egress_observed"], token: "t", env: h.env, io: h.io });
    assert.equal(r.code, 0, JSON.stringify(opts));
  }
  const h = harness();
  const r = await runCustody({ api: "x", env: { GITHUB_EVENT_NAME: "push" }, io: h.io });
  assert.equal(r.code, 0);
  assert.equal(h.calls.length, 0);
});

test("runCustody fails only on observed egress with opt-in", async () => {
  const h = harness({ json: answer("observed") });
  assert.equal((await runCustody({ api: "https://satohub.ai", failOn: ["key_egress_observed"], env: h.env, io: h.io })).code, 1);
  const h2 = harness({ json: answer("observed") });
  assert.equal((await runCustody({ api: "https://satohub.ai", failOn: ["no"], env: h2.env, io: h2.io })).code, 0);
});

test("upsertComment reports a missing permission instead of throwing", async () => {
  const out = await upsertComment({ repo: "o/r", pr: 1, token: "t", body: "x", fetchFn: async () => ({ ok: false, status: 403 }) });
  assert.match(out, /HTTP 403/);
});

test("repoHeader: sends GITHUB_REPOSITORY as x-sato-repo, and nothing when it is absent or malformed", () => {
  assert.deepEqual(repoHeader({ GITHUB_REPOSITORY: "acme/widgets" }), { "x-sato-repo": "acme/widgets" });
  assert.deepEqual(repoHeader({ GITHUB_REPOSITORY: " satohubai/sato-agent-templates " }), { "x-sato-repo": "satohubai/sato-agent-templates" });
  assert.deepEqual(repoHeader({}), {});
  for (const bad of ["", "acme", "acme/", "a/b/c", "https://example.com/a/b", "a b/c"]) assert.deepEqual(repoHeader({ GITHUB_REPOSITORY: bad }), {}, bad);
});

test("every call to the Sato Hub API carries x-sato-repo (install check, profile read)", async () => {
  const prev = process.env.GITHUB_REPOSITORY;
  process.env.GITHUB_REPOSITORY = "acme/widgets";
  try {
    const seen = [];
    const f = async (url, init) => { seen.push({ url, h: init.headers }); return { status: 200, json: async () => ({ profile: {} }) }; };
    await postInstall("https://satohub.ai", {}, f);
    await fetchProfile("https://satohub.ai", "npm:x", f);
    assert.equal(seen.length, 2);
    for (const c of seen) assert.equal(c.h["x-sato-repo"], "acme/widgets", c.url);
  } finally {
    if (prev === undefined) delete process.env.GITHUB_REPOSITORY; else process.env.GITHUB_REPOSITORY = prev;
  }
});
