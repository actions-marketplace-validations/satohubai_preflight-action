# Sato Preflight — a GitHub Action

Run [Sato Hub Preflight](https://satohub.ai/preflight) over your dependency
manifest on every push. It prints what Sato Hub has **on record** for each name —
is it a listing we track, is it active, when was it last checked — as a table in
the job summary and as annotations on the manifest lines.

```yaml
- uses: satohubai/preflight-action@v1
  with:
    manifest: package.json
```

No build step, no dependencies, no token. One HTTPS call.

---

## What a verdict is, and what it is not

A Preflight verdict is **a description of evidence**. Each result names what was
checked, which field it was read from, and when that field was written.

| | verdict | what it means |
|---|---|---|
| 🟢 | `go` | The listing is active, scores in the High Sato Score tier, and carries at least one earned check — a reproduced install, a fresh successful daily probe, or a sustained observed success rate. |
| 🟡 | `caution` | Something resolved, but it did not clear the `go` bar. Most of the index sits here, because most projects have never been independently checked. |
| 🔴 | `no` | The listing is retired, a probed endpoint did not answer, or the observed record is mostly failure attributed to the host. |
| ⚪ | `unknown` | Sato Hub holds no record of this target. |

**This is not a vulnerability scanner.** It is not a security review, not a
licence checker, not malware detection, and not an opinion about whether a
package is safe to install. `go` does not mean safe. `no` does not mean
dangerous. If you want CVE scanning, run a CVE scanner — this answers a
different question.

**`unknown` never fails a build**, at any `fail_on` setting. A package Sato Hub
has never heard of is unknown, which is a fact about our index rather than about
your dependency. An action that could redden your build over a name we simply do
not index would not deserve to stay in your workflow.

**Your manifest is never turned into traffic.** Package names are parsed and
looked up against records Sato Hub already holds; nothing in your manifest is
fetched, resolved or contacted. Only the `endpoints` and `agents` inputs — which
you type on purpose — reach a live probe.

---

## Inputs

| input | default | what it does |
|---|---|---|
| `manifest` | `package.json` | Path to the manifest. `package.json` or `requirements.txt`. `false` to skip. |
| `manifest-kind` | inferred | Force `package.json` or `requirements.txt`. |
| `packages` | — | Extra package names, newline- or comma-separated. |
| `repos` | — | GitHub repositories (`owner/name` or URL). |
| `endpoints` | — | `https` MCP endpoints. The only input that causes a live probe. |
| `agents` | — | ERC-8004 references, `<chain>:<id>` (e.g. `base:42`). |
| `fail_on` | `no` | `no` · `caution` · `none`. Which verdict exits non-zero. |
| `annotations` | `true` | Emit annotations on the manifest lines. |
| `api` | `https://satohub.ai` | API base URL. |
| `custody` | `true` | On `pull_request`, run Sato Check diff mode (below). `false` to skip. |
| `github-token` | `${{ github.token }}` | Posts one sticky PR comment. Needs `pull-requests: write`; without it the report goes to the job summary only. |
| `fail-on` | — | Alias for `fail_on`. Both accept a comma list; add `key_egress_observed` to fail when Sato Check saw a planted key leave. |

---

## Sato Check diff mode (v1.1)

On a pull request, the action reads only what the PR **adds or changes**:

- `package.json` `dependencies` / `devDependencies` added or re-versioned (against the base branch),
- `mcpServers` blocks added or changed in `.mcp.json` or `claude_desktop_config.json`,
- `SKILL.md` files under `skills/` or `.claude/skills/` (listed as changed; a local skill file is not a registry install, so there is no record to read for it).

It sends them as one install command / config to `POST https://satohub.ai/api/check/install`
and writes the four answers per dependency — *Does it take your key? Does your key
leave? Can it move funds on its own? What changed?* — to the job summary and to one
sticky PR comment that is updated on every push.

A profile describes what Sato Hub read and ran, with dates. It is not a safety
rating, an audit or an endorsement, and "not found" is not "not there".

**It fails open.** An unreachable API, a shallow clone, a missing token or an
answer of `unknown` is reported and never fails the job. The only failure is the
one you opt into: `fail_on: no,key_egress_observed` fails when a planted key was
seen leaving during one of Sato Hub's runs for a dependency the PR brings in.

```yaml
name: preflight
on: [pull_request]
permissions:
  contents: read
  pull-requests: write   # for the sticky comment; optional
jobs:
  preflight:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0     # diff mode compares against the base branch
      - uses: satohubai/preflight-action@v1
        with:
          manifest: package.json
          fail_on: none,key_egress_observed
```

Up to **50 targets** per run. Over the cap the API refuses rather than
truncating — a clean summary over a silent subset would be believed.

## Outputs

`verdict` (the most severe seen) · `go` · `caution` · `no` · `unknown` ·
`total` · `sarif` (path to a SARIF 2.1 log) · `report` (the markdown).

---

## Recipes

**Warn, never block** — the setting most repos want:

```yaml
- uses: satohubai/preflight-action@v1
  with:
    fail_on: none
```

**A Python project:**

```yaml
- uses: satohubai/preflight-action@v1
  with:
    manifest: requirements.txt
```

**Upload to GitHub code scanning:**

```yaml
- uses: satohubai/preflight-action@v1
  id: preflight
  with: { fail_on: none }
- uses: github/codeql-action/upload-sarif@v3
  if: steps.preflight.outputs.sarif != ''
  with:
    sarif_file: ${{ steps.preflight.outputs.sarif }}
```

**Check the MCP endpoint you are about to ship against:**

```yaml
- uses: satohubai/preflight-action@v1
  with:
    manifest: "false"
    endpoints: "https://mcp.example.com/v1"
```

---

## Badges

Any repo can embed a Preflight badge — no account, no setup:

```markdown
[![preflight](https://satohub.ai/api/badge/preflight/repo/coinbase/agentkit)](https://satohub.ai/preflight)
[![preflight](https://satohub.ai/api/badge/preflight/package/solana-agent-kit)](https://satohub.ai/preflight)
```

Badges cover `repo` and `package` only. A badge is rendered by whoever opens a
README, at a rate nobody controls — a badge that ran the endpoint lane would
turn every README view into a live probe of somebody's server.

---

## The API underneath

`POST https://satohub.ai/api/preflight/batch`

```json
{ "manifest": "<raw package.json text>", "manifest_kind": "package.json", "fail_on": "no" }
```

returns `{ summary, exit_code, results[], findings[], skipped[], caveat }`,
where `findings` are SARIF `results` entries. Single targets:
`GET /api/preflight?package=…` · `?repo=…` · `?endpoint=…` · `?agent=…` ·
`?token=…&chain=…`. Full reference: <https://satohub.ai/preflight> ·
methodology (every rule a verdict can cite): <https://satohub.ai/preflight/methodology>.

## Licence

MIT. Data from <https://satohub.ai>.
