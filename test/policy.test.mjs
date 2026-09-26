// Offline tests for the v1.2 team policy (.sato/policy.json). `node --test test/policy.test.mjs`.
import test from "node:test";
import assert from "node:assert/strict";
import { parsePolicy, readPolicy, evaluatePolicy, evaluateSubjects, renderPolicy, runCustody, UA } from "../src/custody.mjs";

const BANNED = /\b(safe|safely|unsafe|secure|insecure|malicious|malware|scam|trusted|trustworthy|passed|risk-free|guaranteed|audited)\b/i;

const prof = (over = {}) => ({
  subject: { kind: "package", id: "npm:viem", name: "viem" },
  key_access: "unknown", key_egress: "unknown", key_egress_hosts: [], fund_actions: "unknown",
  hosts: [], evidence: [], changes: { items: [] }, ...over,
});
const ALL = { version: 1, fail_on: ["key_egress_observed", "undeclared_key_read", "unlimited_fund_action", "install_script_added", "new_host"] };

test("parsePolicy validates and normalises", () => {
  assert.deepEqual(parsePolicy({}).policy.fail_on, ["key_egress_observed"]);
  assert.equal(parsePolicy({ version: 2 }).ok, false);
  assert.equal(parsePolicy({ fail_on: ["unsafe"] }).ok, false);
  assert.equal(parsePolicy({ allow_hosts: "x" }).ok, false);
  assert.equal(parsePolicy([]).ok, false);
  assert.deepEqual(parsePolicy({ fail_on: ["new_host"], allow_hosts: ["API.X.com"] }).policy, { version: 1, fail_on: ["new_host"], allow_hosts: ["api.x.com"] });
});

test("readPolicy: absent, invalid JSON, invalid policy", () => {
  assert.deepEqual(readPolicy(() => null), { policy: null });
  assert.match(readPolicy(() => "{").error, /not valid JSON/);
  assert.match(readPolicy(() => '{"fail_on":["nope"]}').error, /unknown rule/);
  assert.deepEqual(readPolicy(() => '{"version":1,"fail_on":["new_host"]}').policy.fail_on, ["new_host"]);
});

test("unknown never matches any rule", () => {
  assert.deepEqual(evaluatePolicy(prof(), ALL).violations, []);
});

test("each rule matches on its reading", () => {
  const p = prof({
    key_egress: "observed", key_egress_hosts: ["evil.example"], key_access: "reads",
    evidence: [{ rule: "T-key-read", source: "src/k.js" }],
    fund_actions: [{ name: "send", action: "transfer", limit_configurable: false, evidence_class: "traced" }, { name: "swap", action: "swap", limit_configurable: true }],
    changes: { items: [{ kind: "install_script_added", detail: "adds postinstall" }, { kind: "host_added", detail: "adds a request to a.example" }, { kind: "host_added", detail: "adds a request to rpc.base.org" }] },
    hosts: [{ host: "a.example", evidence_class: "observed" }],
  });
  const got = evaluatePolicy(p, { ...ALL, allow_hosts: ["*.base.org"] }).violations;
  assert.deepEqual(got.map((v) => v.rule), ["key_egress_observed", "undeclared_key_read", "unlimited_fund_action", "install_script_added", "new_host"]);
  assert.equal(got.find((v) => v.rule === "new_host").evidence_rule, "O-hosts");
  // A declared key (D-env-key) is not undeclared.
  assert.equal(evaluatePolicy(prof({ key_access: "reads", evidence: [{ rule: "D-env-key" }] }), ALL).violations.length, 0);
  // Rules not switched on do not match; allow_subjects exempts.
  assert.equal(evaluatePolicy(p, { version: 1, fail_on: [] }).violations.length, 0);
  assert.equal(evaluatePolicy(p, { ...ALL, allow_subjects: ["npm:viem"] }).violations.length, 0);
});

test("evaluateSubjects reads profiles with our UA + timeout, 4 at a time, fails open", async () => {
  let inFlight = 0, peak = 0;
  const calls = [];
  const fetchFn = async (url, init) => {
    calls.push({ url, init });
    inFlight++; peak = Math.max(peak, inFlight);
    await new Promise((r) => setTimeout(r, 5));
    inFlight--;
    if (url.includes("broken")) return { status: 503, json: async () => ({ error: "down" }) };
    const id = decodeURIComponent(url.split("target=")[1]);
    return { status: 200, json: async () => ({ profile: prof({ subject: { id }, key_egress: "observed" }) }) };
  };
  const subjects = ["a", "b", "c", "d", "e", "broken", "skip"].map((n) => ({ subject: { id: `npm:${n}`, name: n } }));
  const r = await evaluateSubjects(subjects, { ...ALL, allow_subjects: ["npm:skip"] }, { api: "https://satohub.ai/", fetchFn });
  assert.ok(peak <= 4);
  assert.equal(calls.length, 6);
  assert.equal(calls[0].init.headers["user-agent"], UA);
  assert.ok(calls[0].init.signal);
  assert.ok(calls[0].url.startsWith("https://satohub.ai/api/check?target=npm%3Aa"));
  assert.deepEqual(r.violations.map((v) => v.subject), ["a", "b", "c", "d", "e"]);
  assert.deepEqual(r.unevaluated.map((u) => u.subject), ["broken"]);
});

test("policy report describes and never judges", () => {
  const md = renderPolicy({ policy: ALL, violations: [{ subject: "viem", rule: "new_host", detail: "adds a request to a.example", evidence_rule: "T-hosts" }], unevaluated: [{ subject: "x", reason: "HTTP 503" }] }).join("\n");
  assert.ok(md.includes("new_host") && md.includes("Could not evaluate (not a match)"));
  assert.ok(!BANNED.test(md));
  assert.ok(!BANNED.test(renderPolicy({ error: "bad" }).join("\n")));
  assert.ok(!BANNED.test(renderPolicy({ policy: ALL, violations: [], unevaluated: [] }).join("\n")));
});

// ---- end to end through runCustody ----
const pkgBefore = JSON.stringify({ dependencies: {} });
const pkgAfter = JSON.stringify({ dependencies: { viem: "^2.1.0" } });
function harness({ profile, policyText, profileStatus = 200 }) {
  const calls = [];
  const logs = [];
  const summaries = [];
  const fetchFn = async (url, init = {}) => {
    calls.push(url);
    if (url.includes("/api/check/install")) return { status: 200, json: async () => ({ subjects: [{ subject: { id: "npm:viem", name: "viem" }, answers: {}, summary: {} }], has_observed_key_egress: false }) };
    if (url.includes("/api/check?")) return { status: profileStatus, json: async () => (profileStatus === 200 ? { profile } : { error: "down" }) };
    return { ok: true, status: 200, json: async () => [] };
  };
  const io = {
    fetch: fetchFn, log: (m) => logs.push(m), summary: (m) => summaries.push(m),
    readDiff: () => ({ files: ["package.json"], before: () => pkgBefore }),
    readNow: () => pkgAfter,
    readPolicy: () => readPolicy(() => policyText),
  };
  return { calls, logs, summaries, io, env: { GITHUB_EVENT_NAME: "pull_request" } };
}

test("runCustody: a policy match fails the job and is listed", async () => {
  const h = harness({ profile: prof({ changes: { items: [{ kind: "install_script_added", detail: "adds postinstall" }] } }), policyText: '{"version":1,"fail_on":["install_script_added"]}' });
  const r = await runCustody({ api: "https://satohub.ai", failOn: ["no"], env: h.env, io: h.io });
  assert.equal(r.code, 1);
  assert.equal(r.violations, 1);
  assert.ok(h.summaries[0].includes("install_script_added"));
  assert.ok(h.logs.some((l) => l.startsWith("::error::Sato Check policy: viem")));
});

test("runCustody: no match, unknown, unreadable profile, bad policy, no policy → exit 0", async () => {
  for (const [profile, policyText, profileStatus] of [
    [prof({ key_access: "reads", evidence: [{ rule: "D-env-key" }] }), '{"fail_on":["undeclared_key_read"]}', 200],
    [prof(), JSON.stringify(ALL), 200],
    [prof({ key_egress: "observed" }), JSON.stringify(ALL), 503],
    [prof({ key_egress: "observed" }), "{nope", 200],
  ]) {
    const h = harness({ profile, policyText, profileStatus });
    assert.equal((await runCustody({ api: "https://satohub.ai", env: h.env, io: h.io })).code, 0, policyText);
  }
  const h = harness({ profile: prof({ key_egress: "observed" }), policyText: null });
  assert.equal((await runCustody({ api: "https://satohub.ai", env: h.env, io: h.io })).code, 0);
  assert.ok(!h.calls.some((u) => u.includes("/api/check?")), "no profile reads without a policy");
});
