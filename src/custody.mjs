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

export const UA = "satohub-preflight-action/1.1";
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
export function renderReport(res, { changes = [], api = "https://satohub.ai", error = null, localSkills = 0 } = {}) {
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
  const report = renderReport(res, { changes, api, error, localSkills: found.skills.length });
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
  if (shouldFail(res, failOn)) {
    log("::error::Sato Check: a planted key was seen leaving during a run for a dependency this PR adds or changes, and fail_on includes key_egress_observed. See the job summary for the host.");
    return { code: 1, report, subjects: res?.subjects?.length ?? 0, egress };
  }
  return { code: 0, report, subjects: res?.subjects?.length ?? 0, egress };
}
