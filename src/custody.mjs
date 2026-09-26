// Sato Check diff mode (v1.1) — on a pull request, read only the dependencies
// the PR ADDS or CHANGES and ask Sato Hub's custody check the four questions
// about each: does it take your key, does your key leave, can it move funds on
// its own, what changed.
//
// Everything here fails open. An unreachable API, a shallow clone, a missing
// token or an answer of `unknown` is reported and never reddens a build. The one
// thing that can fail a job is `fail_on` containing `key_egress_observed` AND the
// API reporting has_observed_key_egress — a planted key seen leaving in a run.
//
// Pure functions are exported for tests; runCustody() does the I/O.

import { execFileSync } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";

// SATO_CHECK_UA lets Sato Hub's own CI identify itself, so it is not counted as outside use.
export const UA = process.env.SATO_CHECK_UA || "satohub-preflight-action/1.2";
export const POLICY_PATH = ".sato/policy.json";
export const PROFILE_CONCURRENCY = 4;
export const TIMEOUT_MS = 30_000;
export const MARKER = "<!-- sato-check:preflight-action -->";
export const MAX_COMMAND_BYTES = 15_000;

// The sentences are the API's own (lib/custody/wording.ts on Sato Hub); this file
// adds only labels and the disclaimer, quoted verbatim.
export const QUESTION_LABELS = {
  key_access: "Does it take your key?",
  key_egress: "Does your key leave?",
  fund_actions: "Can it move funds on its own?",
  changes: "What changed?",
};
export const DISCLAIMER =
  'A profile describes what we read and ran, with dates. It is not a safety rating, an audit or an endorsement, and "not found" is not "not there".';

const CONFIG_FILES = [".mcp.json", "claude_desktop_config.json"];

// ---------- which files matter ----------

export function classifyPath(p) {
  const base = p.split("/").pop();
  if (base === "package.json" && !p.includes("node_modules/")) return "package";
  if (CONFIG_FILES.includes(base)) return "mcp";
  if (base === "SKILL.md" && (/(^|\/)skills\//.test(p))) return "skill";
  return null;
}

// ---------- package.json: added or version-changed deps ----------

function depsOf(text) {
  try {
    const j = JSON.parse(text || "{}");
    return { ...(j.devDependencies || {}), ...(j.dependencies || {}) };
  } catch {
    return null;
  }
}

/** [{name, from, to}] for deps added or re-versioned between two package.json texts. */
export function changedPackages(beforeText, afterText) {
  const after = depsOf(afterText);
  if (!after) return [];
  const before = depsOf(beforeText) || {};
  const out = [];
  for (const [name, to] of Object.entries(after)) {
    const from = before[name] ?? null;
    if (from === to) continue;
    // Local and workspace specifiers are not installs from a registry.
    if (/^(file:|link:|workspace:|portal:)/.test(String(to))) continue;
    out.push({ name, from, to: String(to) });
  }
  return out;
}

// ---------- MCP configs: added or changed server blocks ----------

function serversOf(text) {
  try {
    const j = JSON.parse(text || "{}");
    return j && typeof j.mcpServers === "object" && j.mcpServers ? j.mcpServers : null;
  } catch {
    return null;
  }
}

/** { name: block } for mcpServers entries added or changed. */
export function changedServers(beforeText, afterText) {
  const after = serversOf(afterText);
  if (!after) return {};
  const before = serversOf(beforeText) || {};
  const out = {};
  for (const [name, block] of Object.entries(after)) {
    if (JSON.stringify(before[name]) !== JSON.stringify(block)) out[name] = block;
  }
  return out;
}

// ---------- building the request ----------

/** Spec for an npm install: `name@range` minus a leading ^ or ~ so it is one token. */
function spec({ name, to }) {
  const v = String(to).replace(/^[\^~]/, "");
  if (/^(https?:|git\+|github:)/.test(v)) return v; // a URL spec is its own target
  return v && v !== "*" && v !== "latest" ? `${name}@${v}` : name;
}

/**
 * One body for POST /api/check/install from everything the PR changed.
 * Returns null when there is nothing to check.
 */
export function buildRequest({ packages = [], servers = {} }) {
  const lines = [];
  if (packages.length) lines.push(`npm install ${packages.map(spec).join(" ")}`);
  // A SKILL.md in this repo is local code, not a registry install, so there is no
  // target to send; it is listed under "what changed" and noted in the report.
  const command = lines.join("\n");
  const hasServers = Object.keys(servers).length > 0;
  if (!command && !hasServers) return null;
  const body = {};
  if (command) body.command = command.slice(0, MAX_COMMAND_BYTES);
  if (hasServers) body.config = JSON.stringify({ mcpServers: servers }).slice(0, MAX_COMMAND_BYTES);
  return body;
}

// ---------- the report ----------

const cell = (s) => String(s ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");

export function subjectName(sub) {
  const s = sub?.subject || {};
  return s.name || s.id || s.target || "unnamed";
}

/** Markdown for the job summary and the PR comment. */
export function renderReport(res, { changes = [], api = "https://satohub.ai", error = null, localSkills = 0, policy = null } = {}) {
  const base = api.replace(/\/$/, "");
  const out = [MARKER, "## Sato Check — dependencies changed in this PR", ""];
  if (changes.length) {
    out.push("**What changed in this PR**", "");
    for (const c of changes) out.push(`- ${c}`);
    out.push("");
  }
  if (error) {
    out.push(`_Sato Check could not answer: ${cell(error)}. Every answer below is unknown; the build is not failed over it._`, "");
  } else if (res) {
    if (res.has_observed_key_egress) {
      out.push("**A planted key was seen leaving during one of our runs for a dependency below.** The answer names the host.", "");
    }
    for (const s of res.subjects || []) {
      const url = s.summary?.check_url;
      const name = subjectName(s);
      out.push(`### ${url ? `[\`${name}\`](${url})` : `\`${name}\``}${s.summary?.version ? ` · ${s.summary.version}` : ""}`, "");
      out.push("| question | answer |", "|---|---|");
      for (const k of Object.keys(QUESTION_LABELS)) {
        out.push(`| ${QUESTION_LABELS[k]} | ${cell(s.answers?.[k] ?? "Unknown.")} |`);
      }
      if (s.summary?.as_of) out.push("", `_As of ${s.summary.as_of} · method ${s.summary.method_version ?? "?"}_`);
      out.push("");
    }
    if (!(res.subjects || []).length) out.push("_No changed dependency resolved to a checkable target._", "");
    if (res.unresolved?.length) {
      out.push(`_Not checked: ${res.unresolved.map((u) => `\`${cell(u.input)}\` (${cell(u.reason)})`).join(", ")}_`, "");
    }
  }
  out.push(...renderPolicy(policy));
  if (localSkills) out.push(`_${localSkills} skill file(s) in this repo changed. A local SKILL.md is not a registry install, so Sato Check has no record to read for it — review it in the diff._`, "");
  out.push(`> ${DISCLAIMER}`, "", `[Sato Check](${base}/check)`);
  return out.join("\n");
}

/** Human "what changed" lines from the diff itself (not the API). */
export function changeLines({ packages = [], servers = {}, skills = [] }) {
  const lines = [];
  for (const p of packages) lines.push(p.from ? `\`${p.name}\` ${p.from} → ${p.to}` : `\`${p.name}\` added at ${p.to}`);
  for (const n of Object.keys(servers)) lines.push(`MCP server \`${n}\` added or changed`);
  for (const s of skills) lines.push(`skill \`${s}\` added or changed`);
  return lines;
}

/** Exit decision: only an observed egress with the opt-in fails. */
export function shouldFail(res, failOnList) {
  return failOnList.includes("key_egress_observed") && res?.has_observed_key_egress === true;
}


// ---------- team policy (.sato/policy.json, v1.2) ----------
// Mirrors lib/custody/policy.ts on Sato Hub (the action cannot import the app).
// A policy names which custody FACTS a team wants a build stopped for. A match
// is reported by the rule that matched and its evidence; `unknown` never matches.

export const POLICY_RULES = ["key_egress_observed", "undeclared_key_read", "unlimited_fund_action", "install_script_added", "new_host"];
export const RULE_TEXT = {
  key_egress_observed: "a planted test key was seen leaving during a run",
  undeclared_key_read: "code reads key material and the setup does not ask for a key",
  unlimited_fund_action: "a fund-moving action with no configurable limit found",
  install_script_added: "this version adds an install script",
  new_host: "this version adds a request to a host not in allow_hosts",
};

const strList = (v, name) => {
  if (v == null) return [];
  if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) return { error: `\`${name}\` must be an array of strings.` };
  return v.map((s) => s.trim()).filter(Boolean).slice(0, 500);
};

/** Validate a policy object. Returns {ok, policy} | {ok:false, error}. */
export function parsePolicy(input) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) return { ok: false, error: "the policy must be a JSON object" };
  if (input.version !== undefined && input.version !== 1) return { ok: false, error: "only policy `version: 1` is understood" };
  const fail = input.fail_on === undefined ? ["key_egress_observed"] : strList(input.fail_on, "fail_on");
  if (!Array.isArray(fail)) return { ok: false, error: fail.error };
  for (const r of fail) if (!POLICY_RULES.includes(r)) return { ok: false, error: `unknown rule "${r}" (rules: ${POLICY_RULES.join(", ")})` };
  const hosts = strList(input.allow_hosts, "allow_hosts");
  if (!Array.isArray(hosts)) return { ok: false, error: hosts.error };
  const subjects = strList(input.allow_subjects, "allow_subjects");
  if (!Array.isArray(subjects)) return { ok: false, error: subjects.error };
  return {
    ok: true,
    policy: {
      version: 1,
      fail_on: POLICY_RULES.filter((r) => fail.includes(r)),
      ...(hosts.length ? { allow_hosts: hosts.map((h) => h.toLowerCase()) } : {}),
      ...(subjects.length ? { allow_subjects: subjects } : {}),
    },
  };
}

/** Read .sato/policy.json. {policy:null} when absent; {policy:null, error} when unreadable. */
export function readPolicy(readFile = (p) => (existsSync(p) ? readFileSync(p, "utf8") : null), path = POLICY_PATH) {
  let text;
  try { text = readFile(path); } catch (e) { return { policy: null, error: `could not read ${path} (${e?.message || e})` }; }
  if (text == null || text === "") return { policy: null };
  let json;
  try { json = JSON.parse(text); } catch { return { policy: null, error: `${path} is not valid JSON` }; }
  const r = parsePolicy(json);
  return r.ok ? { policy: r.policy } : { policy: null, error: `${path}: ${r.error}` };
}

function hostAllowed(host, allow) {
  const h = String(host).toLowerCase();
  return (allow || []).some((a) => (a.startsWith("*.") ? h === a.slice(2) || h.endsWith(a.slice(1)) : h === a));
}

/** Which of the policy's rules this profile's readings match. Same semantics as the app. */
export function evaluatePolicy(profile, policy) {
  const on = new Set(policy.fail_on || []);
  const v = [];
  if (!profile || typeof profile !== "object") return { ok: true, violations: [] };
  if ((policy.allow_subjects || []).includes(profile.subject?.id)) return { ok: true, violations: [] };
  const evidence = Array.isArray(profile.evidence) ? profile.evidence : [];
  if (on.has("key_egress_observed") && profile.key_egress === "observed") {
    v.push({ rule: "key_egress_observed", detail: `A planted test key was sent to ${(profile.key_egress_hosts || []).join(", ") || "an outside host"}.`, evidence_rule: "O-canary-egress" });
  }
  if (on.has("undeclared_key_read") && profile.key_access === "reads" && !evidence.some((e) => e.rule === "D-env-key")) {
    const read = evidence.find((e) => e.rule === "T-key-read");
    v.push({ rule: "undeclared_key_read", detail: `Code reads key material and the setup does not ask for a key${read ? ` (${read.source})` : ""}.`, evidence_rule: read?.rule ?? "T-key-read" });
  }
  if (on.has("unlimited_fund_action") && Array.isArray(profile.fund_actions)) {
    for (const a of profile.fund_actions.filter((a) => a.limit_configurable === false)) {
      v.push({ rule: "unlimited_fund_action", detail: `${a.name} (${a.action}) — no configurable limit found.`, evidence_rule: a.evidence_class === "declared" ? "D-fund-tool" : "N-unlimited-fund-action" });
    }
  }
  const items = Array.isArray(profile.changes?.items) ? profile.changes.items : [];
  if (on.has("install_script_added")) {
    for (const c of items.filter((c) => c.kind === "install_script_added")) v.push({ rule: "install_script_added", detail: c.detail, evidence_rule: "T-install-script" });
  }
  if (on.has("new_host")) {
    for (const c of items.filter((c) => c.kind === "host_added")) {
      const host = String(c.detail || "").replace(/^adds a request to /, "").trim();
      if (hostAllowed(host, policy.allow_hosts)) continue;
      const h = (profile.hosts || []).find((x) => x.host === host);
      v.push({ rule: "new_host", detail: c.detail, evidence_rule: h?.evidence_class === "observed" ? "O-hosts" : "T-hosts" });
    }
  }
  return { ok: v.length === 0, violations: v };
}

/** GET /api/check?target=<id> → the full profile. Throws on anything but a 200 with a profile. */
export async function fetchProfile(api, id, fetchFn = fetch) {
  const res = await fetchFn(`${api.replace(/\/$/, "")}/api/check?target=${encodeURIComponent(id)}`, {
    headers: { "user-agent": UA, accept: "application/json" },
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  const json = await res.json().catch(() => null);
  if (res.status !== 200 || !json?.profile) throw new Error(json?.error || `HTTP ${res.status}`);
  return json.profile;
}

/**
 * Evaluate every subject the install check answered for against the policy.
 * The install response carries summaries only, so each profile is read from
 * GET /api/check (4 at a time). A read that fails is "could not evaluate" —
 * never a match.
 */
export async function evaluateSubjects(subjects, policy, { api, fetchFn = fetch, concurrency = PROFILE_CONCURRENCY } = {}) {
  const violations = [];
  const unevaluated = [];
  const list = (subjects || []).filter((s) => s?.subject?.id && !(policy.allow_subjects || []).includes(s.subject.id));
  let next = 0;
  const worker = async () => {
    while (next < list.length) {
      const s = list[next++];
      try {
        const profile = await fetchProfile(api, s.subject.id, fetchFn);
        for (const v of evaluatePolicy(profile, policy).violations) violations.push({ subject: subjectName(s), id: s.subject.id, ...v });
      } catch (e) {
        unevaluated.push({ subject: subjectName(s), reason: e?.message || String(e) });
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, list.length) }, worker));
  const order = (x) => list.findIndex((s) => s.subject.id === x.id);
  violations.sort((a, b) => order(a) - order(b));
  return { violations, unevaluated };
}

/** Markdown section for the policy outcome. */
export function renderPolicy(policyOut) {
  if (!policyOut) return [];
  const out = ["**Team policy (`.sato/policy.json`)**", ""];
  if (policyOut.error) {
    out.push(`_The policy file could not be used: ${cell(policyOut.error)}. No policy rule was applied; the build is not failed over it._`, "");
    return out;
  }
  out.push(`Rules on: ${policyOut.policy.fail_on.map((r) => `\`${r}\``).join(", ") || "none"}.`, "");
  if (policyOut.violations.length) {
    out.push("| dependency | rule matched | what the reading says | evidence |", "|---|---|---|---|");
    for (const v of policyOut.violations) out.push(`| \`${cell(v.subject)}\` | \`${v.rule}\` — ${RULE_TEXT[v.rule]} | ${cell(v.detail)} | \`${v.evidence_rule}\` |`);
    out.push("");
  } else {
    out.push("_No reading matched a rule in the policy. An `unknown` answer never matches._", "");
  }
  if (policyOut.unevaluated.length) {
    out.push(`_Could not evaluate (not a match): ${policyOut.unevaluated.map((u) => `\`${cell(u.subject)}\` (${cell(u.reason)})`).join(", ")}_`, "");
  }
  return out;
}

// ---------- I/O ----------

function git(args) {
  return execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], maxBuffer: 16 * 1024 * 1024 });
}

/** Changed files vs the base ref, plus a reader for the base version. Throws when git cannot tell. */
export function readDiff(baseRef, gitFn = git) {
  const ref = `origin/${baseRef}`;
  try { gitFn(["rev-parse", "--verify", ref]); } catch {
    gitFn(["fetch", "--no-tags", "--depth=1", "origin", `${baseRef}:refs/remotes/origin/${baseRef}`]);
  }
  let names;
  try { names = gitFn(["diff", "--name-only", `${ref}...HEAD`]); } catch { names = gitFn(["diff", "--name-only", ref, "HEAD"]); }
  const files = names.split("\n").map((s) => s.trim()).filter(Boolean);
  const before = (p) => { try { return gitFn(["show", `${ref}:${p}`]); } catch { return ""; } };
  return { files, before };
}

export function collect(files, before, readNow = (p) => (existsSync(p) ? readFileSync(p, "utf8") : "")) {
  const packages = [];
  const servers = {};
  const skills = [];
  for (const f of files) {
    const kind = classifyPath(f);
    if (kind === "package") packages.push(...changedPackages(before(f), readNow(f)));
    else if (kind === "mcp") Object.assign(servers, changedServers(before(f), readNow(f)));
    else if (kind === "skill" && readNow(f)) skills.push(f.replace(/\/SKILL\.md$/, ""));
  }
  // One entry per package name across several manifests.
  const seen = new Set();
  return { packages: packages.filter((p) => !seen.has(p.name) && seen.add(p.name)), servers, skills };
}

export async function postInstall(api, body, fetchFn = fetch) {
  const res = await fetchFn(`${api.replace(/\/$/, "")}/api/check/install`, {
    method: "POST",
    headers: { "content-type": "application/json", "user-agent": UA },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  const json = await res.json().catch(() => null);
  if (res.status !== 200 || !json) throw new Error(json?.error || `HTTP ${res.status}`);
  return json;
}

/** Create or update the one sticky comment. Returns "created" | "updated" | a reason string. */
export async function upsertComment({ repo, pr, token, body, fetchFn = fetch, apiUrl = "https://api.github.com" }) {
  const h = { authorization: `Bearer ${token}`, accept: "application/vnd.github+json", "user-agent": UA, "content-type": "application/json" };
  const sig = () => AbortSignal.timeout(TIMEOUT_MS);
  const list = await fetchFn(`${apiUrl}/repos/${repo}/issues/${pr}/comments?per_page=100`, { headers: h, signal: sig() });
  if (!list.ok) return `could not list comments (HTTP ${list.status})`;
  const existing = ((await list.json()) || []).find((c) => typeof c.body === "string" && c.body.includes(MARKER));
  const url = existing ? `${apiUrl}/repos/${repo}/issues/comments/${existing.id}` : `${apiUrl}/repos/${repo}/issues/${pr}/comments`;
  const r = await fetchFn(url, { method: existing ? "PATCH" : "POST", headers: h, body: JSON.stringify({ body }), signal: sig() });
  if (!r.ok) return `could not ${existing ? "update" : "post"} the comment (HTTP ${r.status}) — the token needs pull-requests: write`;
  return existing ? "updated" : "created";
}

/**
 * Runs diff mode. Never throws. Returns { code, report, subjects, egress }.
 * `io` lets tests inject git/fetch/env.
 */
export async function runCustody({ api, failOn = [], token = "", env = process.env, io = {} } = {}) {
  const log = io.log || console.log;
  const fetchFn = io.fetch || fetch;
  const summary = io.summary || (() => {});
  if (env.GITHUB_EVENT_NAME !== "pull_request" && env.GITHUB_EVENT_NAME !== "pull_request_target") {
    return { code: 0, skipped: "not a pull request" };
  }
  let diff;
  try {
    diff = (io.readDiff || readDiff)(env.GITHUB_BASE_REF || "main");
  } catch (e) {
    log(`::notice::Sato Check: could not diff against the base ref (${e?.message || e}). Use actions/checkout with fetch-depth: 0. Not failing the build.`);
    return { code: 0, skipped: "no diff" };
  }
  const found = collect(diff.files, diff.before, io.readNow);
  const body = buildRequest(found);
  if (!body && !found.skills.length) {
    log("Sato Check: no dependency manifest, MCP config or skill changed in this PR.");
    return { code: 0, skipped: "nothing changed" };
  }
  const changes = changeLines(found);
  let res = null;
  let error = null;
  if (body) try {
    res = await postInstall(api, body, fetchFn);
  } catch (e) {
    error = e?.message || String(e);
    log(`::warning::Sato Check was unreachable or refused (${error}). Reported as unknown; not failing the build.`);
  }
  let policyOut = null;
  const pol = (io.readPolicy || readPolicy)();
  if (pol.error) {
    policyOut = { error: pol.error };
    log(`::warning::Sato Check: ${pol.error}. No policy rule applied; not failing the build over it.`);
  } else if (pol.policy) {
    const ev = res ? await evaluateSubjects(res.subjects, pol.policy, { api, fetchFn }) : { violations: [], unevaluated: [] };
    policyOut = { policy: pol.policy, ...ev };
  }
  const report = renderReport(res, { changes, api, error, localSkills: found.skills.length, policy: policyOut });
  summary(report);

  if (token) {
    let pr = null;
    try { pr = JSON.parse((io.readEvent || ((p) => readFileSync(p, "utf8")))(env.GITHUB_EVENT_PATH))?.pull_request?.number ?? null; } catch { /* no event */ }
    if (pr && env.GITHUB_REPOSITORY) {
      try {
        const out = await upsertComment({ repo: env.GITHUB_REPOSITORY, pr, token, body: report, fetchFn, apiUrl: env.GITHUB_API_URL || "https://api.github.com" });
        if (out !== "created" && out !== "updated") log(`::notice::Sato Check: ${out}. The job summary carries the same report.`);
      } catch (e) {
        log(`::notice::Sato Check: the PR comment failed (${e?.message || e}). The job summary carries the same report.`);
      }
    }
  }

  const egress = res?.has_observed_key_egress === true;
  if (policyOut?.violations?.length) {
    for (const v of policyOut.violations) log(`::error::Sato Check policy: ${v.subject} matched \`${v.rule}\` (${RULE_TEXT[v.rule]}): ${v.detail}`);
    return { code: 1, report, subjects: res?.subjects?.length ?? 0, egress, violations: policyOut.violations.length };
  }
  if (shouldFail(res, failOn)) {
    log("::error::Sato Check: a planted key was seen leaving during a run for a dependency this PR adds or changes, and fail_on includes key_egress_observed. See the job summary for the host.");
    return { code: 1, report, subjects: res?.subjects?.length ?? 0, egress };
  }
  return { code: 0, report, subjects: res?.subjects?.length ?? 0, egress };
}
