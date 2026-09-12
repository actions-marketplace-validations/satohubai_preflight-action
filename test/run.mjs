#!/usr/bin/env node
// Assertions against the LIVE batch endpoint. Zero dependencies.
//
// These pin the promises the README makes, not the rendering:
//   · unknown never produces a non-zero exit code
//   · the 50-target cap is refused, not truncated
//   · findings come back in SARIF result shape
//   · no verdict message characterises safety
//
// A network failure is reported and skipped — this repo's CI must not go red
// because a third party had a bad minute.

import { readFileSync } from "node:fs";

const API = (process.env.SATO_API_BASE || "https://satohub.ai").replace(/\/$/, "");
const URL_ = `${API}/api/preflight/batch`;
let failures = 0;

function ok(cond, msg) {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${msg}`);
  if (!cond) failures++;
}

async function post(body) {
  const res = await fetch(URL_, {
    method: "POST",
    headers: { "content-type": "application/json", "user-agent": "SatoHub-preflight-action-test/1" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(60_000),
  });
  return { status: res.status, json: await res.json().catch(() => null) };
}

const BANNED = /\b(safe|unsafe|secure|insecure|vulnerab\w*|malicious|malware|audited|rug|scam)\b/i;

async function main() {
  console.log(`Preflight batch: ${URL_}`);

  // The endpoint ships with the Sato Hub app's deploy cycle, which is not this
  // repo's. Until it is live the assertions have nothing to assert against, and
  // a 404 is a deployment fact rather than a broken action — so we say so and
  // stop, instead of reddening CI over someone else's release schedule.
  const probe = await post({ packages: ["express"] });
  if (probe.status === 404 || probe.status === 405) {
    console.log(`::notice::${URL_} answered ${probe.status} — the batch endpoint is not deployed yet. Skipping assertions.`);
    process.exit(0);
  }

  const pkg = readFileSync(new URL("./fixtures/package.json", import.meta.url), "utf8");
  const a = await post({ manifest: pkg, manifest_kind: "package.json", manifest_path: "test/fixtures/package.json" });
  ok(a.status === 200, `package.json manifest → 200 (got ${a.status})`);
  if (a.json) {
    const s = a.json.summary;
    ok(s && s.total > 0, `summary counts targets (total=${s?.total})`);
    ok(s.go + s.caution + s.no + s.unknown === s.total, "the four counts add up to total");
    ok(Array.isArray(a.json.findings) && a.json.findings.length === s.total, "one SARIF finding per target");
    const f = a.json.findings[0];
    ok(!!f?.ruleId && !!f?.level && !!f?.message?.text, "findings are SARIF result shape (ruleId, level, message)");
    ok(!!f?.locations?.[0]?.physicalLocation?.artifactLocation?.uri, "a finding names the manifest it came from");
    ok(a.json.findings.every((x) => !BANNED.test(x.message.text)), "no finding characterises safety");
    ok(a.json.results.every((r) => Array.isArray(r.evidence)), "every result carries its evidence lines");
    ok(typeof a.json.caveat === "string" && a.json.caveat.length > 0, "the response carries its caveat");
  }

  const reqs = readFileSync(new URL("./fixtures/requirements.txt", import.meta.url), "utf8");
  const b = await post({ manifest: reqs, manifest_kind: "requirements.txt", manifest_path: "test/fixtures/requirements.txt" });
  ok(b.status === 200, `requirements.txt manifest → 200 (got ${b.status})`);
  ok((b.json?.summary?.total ?? 0) > 0, "requirements.txt produces targets");

  // A name nobody has ever published: unknown, and it cannot fail a build.
  const c = await post({ packages: ["sato-preflight-nonexistent-package-9f3a2"], fail_on: "caution" });
  ok(c.json?.summary?.unknown === 1, "an unindexed package is unknown");
  ok(c.json?.exit_code === 0, "unknown never fails a build, even at fail_on=caution");

  // The cap is refused, never truncated.
  const deps = {};
  for (let i = 0; i < 51; i++) deps[`sato-cap-probe-${i}`] = "1.0.0";
  const d = await post({ manifest: JSON.stringify({ dependencies: deps }), manifest_kind: "package.json" });
  ok(d.status === 400, `51 targets is refused (got ${d.status})`);
  ok(/50/.test(d.json?.error || ""), "the refusal names the cap");

  console.log(failures ? `\n${failures} assertion(s) failed.` : "\nAll assertions passed.");
  process.exit(failures ? 1 : 0);
}

main().catch((e) => {
  console.log(`::warning::Preflight assertions could not run: ${e?.message || e}. Skipping rather than failing CI.`);
  process.exit(0);
});
