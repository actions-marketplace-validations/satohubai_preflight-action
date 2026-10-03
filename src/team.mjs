// Sato Check Team mode (v1.4) — the keyed half of the Action.
//
// With a Sato API key (input `sato-api-key` or env SATO_API_KEY) on a Sato Check
// Team plan, the Action sends the repo's dependency list to POST /api/check/batch
// with the key and two headers naming the repo. The server then:
//   - registers the repo in the account's inventory (repo name + visibility +
//     the dependencies named), so a custody change on one reaches the owner,
//   - merges the account's org policy with this repo's .sato/policy.json (the
//     repo can only tighten it) and applies any waivers,
//   - appends the run to the account's run history.
//
// WITHOUT A KEY NOTHING HERE RUNS and the Action behaves exactly as v1.2: no
// repo name leaves the runner, no inventory exists, and the free path is intact.
//
// EVERYTHING FAILS OPEN. An unreachable API, a 401, a plan without the feature or
// a quota refusal is reported and never reddens a build. The one thing that fails
// the job is the API's own `exit_code: 1` — a policy rule YOUR team wrote matched
// a reading. A match names a fact; it is not a rating of the dependency.
//
// The key is masked in the log before anything else, and is sent only as
// `Authorization: Bearer`.

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { resolve as resolvePath } from "node:path";
import { UA, TIMEOUT_MS, readPolicy } from "./custody.mjs";

export const REPO_HEADER = "x-sato-repo";
export const VISIBILITY_HEADER = "x-sato-repo-visibility";

/** Dependency names from a package.json text. Local and workspace specifiers are not installs. */
export function readPackageTargets(text) {
  let j;
  try { j = JSON.parse(text || "{}"); } catch { return []; }
  const deps = { ...(j.devDependencies || {}), ...(j.dependencies || {}) };
  return Object.entries(deps)
    .filter(([, v]) => !/^(file:|link:|workspace:|portal:)/.test(String(v)))
    .map(([name]) => name)
    .sort();
}

/** public | private | internal | unknown, from the workflow's event payload. */
export function repoVisibility(event) {
  const r = event?.repository;
  if (r?.visibility === "public" || r?.visibility === "private" || r?.visibility === "internal") return r.visibility;
  if (r?.private === true) return "private";
  if (r?.private === false) return "public";
  return "unknown";
}

export function buildTeamRequest({ targets, policy }) {
  const body = { targets };
  if (policy) body.policy = policy;
  return body;
}

export function teamHeaders({ key, repo, visibility, ua = UA }) {
  return {
    "content-type": "application/json",
    "user-agent": ua,
    authorization: `Bearer ${key}`,
    ...(repo ? { [REPO_HEADER]: repo, [VISIBILITY_HEADER]: visibility || "unknown" } : {}),
  };
}

/** SARIF 2.1.0: one `error` per policy match left AFTER the org merge and waivers. A description, never a verdict. */
export function sarifFromResults(results, uri = "package.json") {
  const loc = [{ physicalLocation: { artifactLocation: { uri } } }];
  const findings = (results || []).flatMap((r) =>
    (r.policy?.violations || []).map((v) => ({
      ruleId: `sato-check/${v.rule}`,
      level: "error",
      message: { text: `${r.subject?.id} — Sato Check policy rule ${v.rule} matched (evidence ${v.evidence_rule}): ${v.detail} A description of what was read, not a rating. ${r.check_url}` },
      locations: loc,
      properties: { rule: v.rule, evidence_rule: v.evidence_rule, subject: r.subject?.id, check_url: r.check_url },
    })),
  );
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{ tool: { driver: { name: "Sato Check", informationUri: "https://satohub.ai/check", rules: [] } }, results: findings }],
  };
}

const cell = (s) => String(s ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");

/** Markdown for the job summary. Quotes the API's own wording where it has some. */
export function renderTeam(res) {
  const t = res.team || {};
  const out = ["## Sato Check Team", ""];
  out.push(`**${res.summary.profiled} of ${res.summary.total} checked** · ${res.summary.matched} policy match${res.summary.matched === 1 ? "" : "es"} · plan: ${cell(t.plan || "—")}`, "");
  if (t.repo_registered) out.push(`Inventory: \`${cell(t.repo)}\` is registered (${t.inventory_targets ?? "?"} dependencies). A change to one reaches your alert endpoints.`, "");
  else if (t.refused) out.push(`Inventory: not registered. ${cell(t.refused.error)} (rule \`${t.refused.rule}\`, limit ${t.refused.limit}, observed ${t.refused.observed}).`, "");
  else if (t.note) out.push(`Inventory: ${cell(t.note)}`, "");
  const ignored = [...(t.org_policy?.ignored?.allow_hosts || []), ...(t.org_policy?.ignored?.allow_subjects || [])];
  if (t.org_policy?.applied) out.push(`Org policy applied.${ignored.length ? ` This repo's allow-list entries the org policy does not cover were ignored: ${ignored.map((x) => `\`${cell(x)}\``).join(", ")}.` : ""}`, "");
  const rows = (res.results || []).flatMap((r) => (r.policy?.violations || []).map((v) => `| \`${cell(r.subject?.id)}\` | \`${v.rule}\` | ${cell(v.detail)} | \`${v.evidence_rule}\` |`));
  if (rows.length) out.push("| dependency | rule | what was read | evidence |", "|---|---|---|---|", ...rows, "");
  else out.push("_No reading matched a rule in the effective policy. An `unknown` answer never matches._", "");
  for (const w of t.org_policy?.waived || []) out.push(`- Waived: \`${cell(w.subject)}\` \`${w.rule}\` until ${cell(String(w.expires_at).slice(0, 10))} — ${cell(w.reason)}`);
  if (t.org_policy?.waived?.length) out.push("");
  if (res.unresolved?.length) out.push(`_Not evaluated: ${res.unresolved.map((u) => `\`${cell(u.input)}\` (${cell(u.reason)})`).join(", ")}_`, "");
  out.push(`> ${res.caveat || ""}`);
  return out.join("\n");
}

async function post(api, key, body, headers, fetchFn) {
  const res = await fetchFn(`${api.replace(/\/$/, "")}/api/check/batch`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(Math.max(TIMEOUT_MS, 60_000)),
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* leave null */ }
  return { status: res.status, json };
}

/**
 * Runs team mode. Never throws. Returns { code, skipped?, registered, sarif, violations }.
 * `io` lets tests inject fetch / file reads / the event payload.
 */
export async function runTeam({ api, key, manifest = "package.json", env = process.env, io = {} } = {}) {
  const log = io.log || console.log;
  const fetchFn = io.fetch || fetch;
  const summary = io.summary || (() => {});
  if (!key) return { code: 0, skipped: "no key", registered: false, sarif: "", violations: 0 };
  log(`::add-mask::${key}`);

  const read = io.readFile || ((p) => (existsSync(p) ? readFileSync(p, "utf8") : null));
  const text = read(resolvePath(process.cwd(), manifest));
  if (text == null) {
    log(`::notice::Sato Check Team: no ${manifest} to read, so there is nothing to register. Not failing the build.`);
    return { code: 0, skipped: "no manifest", registered: false, sarif: "", violations: 0 };
  }
  if (!/package\.json$/i.test(manifest)) {
    log("::notice::Sato Check Team reads package.json manifests in this release. Not failing the build.");
    return { code: 0, skipped: "manifest kind", registered: false, sarif: "", violations: 0 };
  }
  const targets = readPackageTargets(text);
  if (!targets.length) {
    log("Sato Check Team: the manifest names no dependencies.");
    return { code: 0, skipped: "no dependencies", registered: false, sarif: "", violations: 0 };
  }

  const pol = (io.readPolicy || readPolicy)();
  if (pol.error) log(`::warning::Sato Check: ${pol.error}. This repo's policy file was not sent; the org policy, if any, still applies.`);
  let event = null;
  try { event = JSON.parse((io.readEvent || ((p) => readFileSync(p, "utf8")))(env.GITHUB_EVENT_PATH)); } catch { /* no event payload */ }
  const headers = teamHeaders({ key, repo: env.GITHUB_REPOSITORY || "", visibility: repoVisibility(event) });

  let out;
  try {
    out = await post(api, key, buildTeamRequest({ targets, policy: pol.policy }), headers, fetchFn);
  } catch (e) {
    log(`::warning::Sato Check Team was unreachable (${e?.message || e}). Not failing the build.`);
    return { code: 0, skipped: "unreachable", registered: false, sarif: "", violations: 0 };
  }
  if (out.status === 401) {
    log("::warning::Sato Check Team: the API key was not accepted (unknown or revoked). The free checks above still ran. Not failing the build.");
    return { code: 0, skipped: "key", registered: false, sarif: "", violations: 0 };
  }
  if (out.status !== 200 || !out.json?.summary) {
    log(`::warning::Sato Check Team: the API answered ${out.status}${out.json?.error ? ` — ${out.json.error}` : ""}. Not failing the build.`);
    return { code: 0, skipped: `http ${out.status}`, registered: false, sarif: "", violations: 0 };
  }

  const res = out.json;
  const t = res.team;
  if (t?.refused) log(`::notice::Sato Check Team: ${t.refused.error} (rule ${t.refused.rule}, limit ${t.refused.limit}, observed ${t.refused.observed}). The check ran in full.`);
  summary(renderTeam(res));

  let sarif = "";
  const violations = res.results.reduce((n, r) => n + (r.policy?.violations?.length || 0), 0);
  try {
    const path = resolvePath(env.RUNNER_TEMP || process.cwd(), "sato-check.sarif");
    (io.writeFile || writeFileSync)(path, JSON.stringify(sarifFromResults(res.results, manifest), null, 2));
    sarif = path;
  } catch { /* the summary still carries the result */ }

  for (const r of res.results) {
    for (const v of r.policy?.violations || []) {
      log(`::error::Sato Check policy: ${r.subject?.name || r.subject?.id} matched \`${v.rule}\`: ${v.detail}`);
    }
  }
  return { code: res.exit_code === 1 ? 1 : 0, registered: Boolean(t?.repo_registered), sarif, violations, report: renderTeam(res) };
}
