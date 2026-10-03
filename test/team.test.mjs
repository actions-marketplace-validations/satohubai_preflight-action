// Offline tests for Sato Check Team mode (v1.4). `node --test test/team.test.mjs`.
import test from "node:test";
import assert from "node:assert/strict";
import { readPackageTargets, repoVisibility, teamHeaders, buildTeamRequest, sarifFromResults, renderTeam, runTeam, REPO_HEADER, VISIBILITY_HEADER } from "../src/team.mjs";

const BANNED = /\b(safe|safely|unsafe|secure|insecure|malicious|malware|scam|trusted|trustworthy|passed|risk-free|guaranteed|audited)\b/i;
const KEY = "sk_sato_" + "a".repeat(64);
const PKG = JSON.stringify({ dependencies: { viem: "^2.0.0", "@acme/wallet": "1.0.0", local: "file:../x", ws: "workspace:*" }, devDependencies: { typescript: "5" } });

const result = (over = {}) => ({
  schema: "sato.custody/v1",
  summary: { total: 3, profiled: 3, unresolved: 0, matched: 1 },
  exit_code: 1,
  results: [
    { subject: { id: "npm:@acme/wallet", name: "@acme/wallet" }, check_url: "https://satohub.ai/check/x", policy: { ok: false, violations: [{ rule: "key_egress_observed", detail: "A planted test key was sent to collector.example.net.", evidence_rule: "O-canary-egress" }] } },
    { subject: { id: "npm:viem", name: "viem" }, check_url: "https://satohub.ai/check/y", policy: { ok: true, violations: [] } },
  ],
  unresolved: [],
  caveat: "A profile describes what we read and ran, with dates.",
  team: { plan: "Sato Check Team", repo: "acme/app", repo_registered: true, inventory_targets: 3, org_policy: { applied: true, ignored: { allow_hosts: ["evil.example"], allow_subjects: [] }, waived: [{ subject: "npm:old", rule: "new_host", reason: "Reviewed with the maintainer", expires_at: "2026-11-01T00:00:00Z" }], expired_waivers: 0 }, run_id: 7 },
  ...over,
});

function harness(over = {}) {
  const calls = [];
  const logs = [];
  const files = {};
  const io = {
    log: (l) => logs.push(l),
    fetch: async (url, init) => { calls.push({ url, init }); return over.response ?? new Response(JSON.stringify(result()), { status: 200 }); },
    readFile: (p) => (p.endsWith("package.json") ? PKG : null),
    readPolicy: () => over.policy ?? { policy: null },
    readEvent: () => JSON.stringify({ repository: { private: true } }),
    writeFile: (p, c) => { files[p] = c; },
    summary: (md) => logs.push(`SUMMARY:${md}`),
  };
  return { calls, logs, files, io, env: { GITHUB_REPOSITORY: "acme/app", GITHUB_EVENT_PATH: "/e", RUNNER_TEMP: "/tmp" } };
}

test("dependency names come from package.json; local and workspace specifiers are not installs", () => {
  assert.deepEqual(readPackageTargets(PKG), ["@acme/wallet", "typescript", "viem"]);
  assert.deepEqual(readPackageTargets("not json"), []);
});

test("visibility is read from the event payload", () => {
  assert.equal(repoVisibility({ repository: { visibility: "internal", private: true } }), "internal");
  assert.equal(repoVisibility({ repository: { private: true } }), "private");
  assert.equal(repoVisibility({ repository: { private: false } }), "public");
  assert.equal(repoVisibility(null), "unknown");
});

test("the key travels only as a bearer token, with the repo and its visibility named", () => {
  const h = teamHeaders({ key: KEY, repo: "acme/app", visibility: "private", ua: "ua/1" });
  assert.equal(h.authorization, `Bearer ${KEY}`);
  assert.equal(h[REPO_HEADER], "acme/app");
  assert.equal(h[VISIBILITY_HEADER], "private");
  assert.equal(JSON.stringify(buildTeamRequest({ targets: ["a"], policy: null })), '{"targets":["a"]}');
  assert.equal(Object.values(h).filter((v) => String(v).includes(KEY)).length, 1);
});

test("with no key nothing runs and nothing is sent", async () => {
  const h = harness();
  const r = await runTeam({ api: "https://satohub.ai", key: "", env: h.env, io: h.io });
  assert.equal(r.skipped, "no key");
  assert.equal(h.calls.length, 0);
});

test("a keyed run masks the key, posts once with the repo headers, writes SARIF and fails on the API's exit_code", async () => {
  const h = harness();
  const r = await runTeam({ api: "https://satohub.ai/", key: KEY, env: h.env, io: h.io });
  assert.equal(h.logs[0], `::add-mask::${KEY}`);
  assert.equal(h.calls.length, 1);
  assert.equal(h.calls[0].url, "https://satohub.ai/api/check/batch");
  assert.equal(h.calls[0].init.headers[REPO_HEADER], "acme/app");
  assert.equal(h.calls[0].init.headers[VISIBILITY_HEADER], "private");
  assert.deepEqual(JSON.parse(h.calls[0].init.body).targets, ["@acme/wallet", "typescript", "viem"]);
  assert.equal(r.code, 1);
  assert.equal(r.registered, true);
  assert.equal(r.violations, 1);
  const sarif = JSON.parse(Object.values(h.files)[0]);
  assert.equal(sarif.version, "2.1.0");
  assert.equal(sarif.runs[0].results.length, 1);
  assert.equal(sarif.runs[0].results[0].ruleId, "sato-check/key_egress_observed");
  assert.ok(h.logs.some((l) => l.startsWith("::error::Sato Check policy")));
  assert.ok(!h.logs.join("\n").replace(`::add-mask::${KEY}`, "").includes(KEY), "the key appears nowhere else in the log");
});

test("the repo's own .sato/policy.json is sent for the server to merge with the org policy", async () => {
  const h = harness({ policy: { policy: { version: 1, fail_on: ["new_host"] } } });
  await runTeam({ api: "https://satohub.ai", key: KEY, env: h.env, io: h.io });
  assert.deepEqual(JSON.parse(h.calls[0].init.body).policy, { version: 1, fail_on: ["new_host"] });
});

test("it fails open: unreachable API, rejected key, other plan answers, odd bodies never fail the build", async () => {
  for (const response of [new Response("{}", { status: 401 }), new Response("{}", { status: 503 }), new Response("nope", { status: 200 }), new Response(JSON.stringify({ error: "x" }), { status: 400 })]) {
    const h = harness({ response });
    const r = await runTeam({ api: "https://satohub.ai", key: KEY, env: h.env, io: h.io });
    assert.equal(r.code, 0);
    assert.ok(r.skipped);
  }
  const h = harness();
  h.io.fetch = async () => { throw new Error("ECONNRESET"); };
  assert.equal((await runTeam({ api: "https://satohub.ai", key: KEY, env: h.env, io: h.io })).code, 0);
});

test("a quota refusal is reported, the check still counts, and exit_code 0 passes the build", async () => {
  const refused = result({ exit_code: 0, summary: { total: 3, profiled: 3, unresolved: 0, matched: 0 }, results: [], team: { plan: "Sato Check Team", repo: "acme/app", repo_registered: false, refused: { error: "The repo inventory: 10 of 10 used on the Sato Check Team plan.", rule: "check_repos", limit: 10, observed: 10 }, org_policy: { applied: false, ignored: { allow_hosts: [], allow_subjects: [] }, waived: [], expired_waivers: 0 } } });
  const h = harness({ response: new Response(JSON.stringify(refused), { status: 200 }) });
  const r = await runTeam({ api: "https://satohub.ai", key: KEY, env: h.env, io: h.io });
  assert.equal(r.code, 0);
  assert.equal(r.registered, false);
  assert.ok(h.logs.some((l) => /rule check_repos, limit 10, observed 10/.test(l)));
});

test("a repo with no manifest, or no dependencies, sends nothing", async () => {
  const none = harness();
  none.io.readFile = () => null;
  assert.equal((await runTeam({ api: "https://satohub.ai", key: KEY, env: none.env, io: none.io })).skipped, "no manifest");
  assert.equal(none.calls.length, 0);
  const empty = harness();
  empty.io.readFile = () => "{}";
  assert.equal((await runTeam({ api: "https://satohub.ai", key: KEY, env: empty.env, io: empty.io })).skipped, "no dependencies");
  assert.equal(empty.calls.length, 0);
});

test("the summary and SARIF describe and never judge", () => {
  const text = renderTeam(result()) + JSON.stringify(sarifFromResults(result().results));
  assert.ok(!BANNED.test(text.replace(/not a rating/g, "")), "no banned word");
  assert.match(renderTeam(result()), /Waived: `npm:old` `new_host` until 2026-11-01 — Reviewed with the maintainer/);
  assert.match(renderTeam(result()), /allow-list entries the org policy does not cover were ignored: `evil.example`/);
});
