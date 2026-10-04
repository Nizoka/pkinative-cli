---
name: release-audit
description: Pre-release audit of pkinative-cli — two parallel auditors (claims vs code; help text, surface matrices, samples and secret hygiene), an adversarial verifier, an agent-autonomy pass and a GO/NO-GO ledger under .audit/<version>/. Run by the maintainer before every release; never invoked by the model on its own.
disable-model-invocation: true
allowed-tools: Read, Grep, Glob, Bash(npm run *), Bash(npx tsx scripts/*), Bash(npx vitest *), Bash(node dist/cli.cjs *), Bash(git diff*), Bash(git log*), Bash(git show*), Bash(git describe*), Agent
argument-hint: [release-notes/vX.Y.Z.md] [previous-tag]
---

# Release audit

Audit the release described by `$0` (default: the newest `release-notes/v*.md`) against everything that changed since `$1` (default: the previous `v*` tag from `git describe --tags --abbrev=0`, or the root commit for the first release). The audit produces findings, never fixes: every fix goes through the normal edit → gate loop afterwards, and the ledger records what was fixed.

Read `ledger.md` first for the ledger and verdict formats. Each phase below hands a template to the agents it spawns; the agents return findings, you file them.

## Ledger location

`.audit/<version>/` — git-ignored (check `.gitignore` covers it before writing; it is NOT under `test-output/`, which Claude Code is denied to Read), so nothing here is ever committed. One Markdown file per report: auditor-a, auditor-b, verifier-1, auditor-d, verifier-2, then the ledger and the verdict (formats in `ledger.md`).

## Phase A and B — two auditors, in parallel

Spawn both with the Agent tool in the same message (distinct angles; neither sees the other's report):

- **Auditor A — claims vs code.** Template: `auditor-a.md`. Every claim in the release note and the top CHANGELOG entry is checked against `src/commands/`, `src/utils/`, `src/core-bridge/` and `tests/`; at least one assertion per claim is *reproduced with a command* (a test, a script, the BUILT binary `node dist/cli.cjs …`), not inferred from reading. Its brief includes the refusal posture and the secret hygiene of `key` and `p12`.
- **Auditor B — help text, matrices and release surfaces.** Template: `auditor-b.md`. Every command's `--help` against the registry, the surface matrix `docs/data/core-exports.json`, the engine-surface matrix `tests/regression/engine-surface.json`, the sample baseline, the README, the publish workflow, the CHANGELOG and the release note — every surface a human, an agent or the release pipeline reads — compared with the behaviour that actually shipped.

Both write their report in the finding format of `ledger.md` (id, severity, claim, evidence command, observed, expected).

## Phase C — adversarial verifier

Spawn one verifier (template: `verifier.md`) with both reports. It re-derives every finding from scratch — re-runs the evidence command, reads the cited lines — and stamps each one `CONFIRMED | DOWNGRADED | REJECTED | DUPLICATE` with a one-line justification. Auditors have about 10 % false findings; the verifier exists to keep them out of the ledger. A finding the verifier cannot reproduce is `REJECTED`, not "probably fine".

## Phase D — agent-autonomy pass, then verify

**The mechanical half is `npm run gate`; do not re-derive it.** That every registered command has a help block (`tests/docs/usage.test.ts`), that every runtime export of pkinative is reached by a command (`tests/docs/surface.test.ts`), that every engine change named in pkinative's changelog is held by a test (`tests/regression/engine-surface.test.ts`) and that every sample still prints its pinned bytes (`tests/regression/samples.test.ts`, `npm run verify:samples`) is decided on every run. Cite the test instead of re-deriving it.

Spawn Auditor D (template: `auditor-b.md`, section "Autonomy pass") for what no test can decide: *can an agent that has only the published surfaces (`pkinative --help`, `pkinative <command> --help`, `pkinative schema`, `pkinative explain`, `pkinative doctor`, the README and `samples/`) drive every feature the release note names without reading `src/`?* Is each sentence of the help text true, is the advice still the best advice, and does the remedy `explain` prints match what the error says? Then a second verifier pass (template: `verifier.md`) over its findings.

## Phase E — GO / NO-GO

Merge the confirmed findings into the ledger, then write the verdict file (both formats are in `ledger.md`):

- **GO** — no CONFIRMED finding of severity `blocker`; every `major` has a fix commit or an explicit maintainer waiver in the ledger.
- **NO-GO** — otherwise. List the blockers first, each with its evidence command, so the fix loop starts from the ledger, not from memory.

Report the verdict, the counts per severity and per stamp, and the ledger path. Do not push, tag, open a PR or publish: the maintainer takes over from `GO` — squash-merges the `release/vX.Y.Z` pull request, publishes the GitHub Release, and `.github/workflows/publish.yml` publishes to npm.

## Known blind spots

Add a check for each of these to the auditor briefs; they are where an audit of a CLI over an engine misses something.

- Help text drifts from the registry: a flag added to `src/commands/registry.ts` but described nowhere in `src/commands/usage.ts`, or described with a stale default, passes every test that only proves a help block exists.
- The surface matrices are generated (`npm run surface:build`): a matrix regenerated after the code but never reviewed proves consistency, not correctness. Read the `via` of each new export in `docs/data/core-exports.json` against the command that claims it.
- The sample baseline (`tests/regression/baselines/samples.sha256.json`) proves byte identity for the samples only; a behaviour change on a flag no sample exercises is invisible to it, and a regenerated baseline hides a change nobody declared.
- Secret hygiene is a negative property: no test proves a password, a private key or a PKCS#12 MAC key never reaches stdout, stderr or a `--json` envelope unless one looks for it. Run `key` and `p12` with a known password and grep every output stream for it.
- Refusal posture: a config file must not relax a check (`src/utils/config.ts`), argv must not carry a password (`src/utils/secrets.ts`), and nothing reaches the network. Try each from a `.pkinativerc.json` and the command line, not only from the tests.
- CI assumptions live outside the repo: trusted publishing needs npm >= 11.5.1 on the runner, the `npm-publish` environment and the `release: published` trigger; a green local gate proves nothing about the publish job.
- Auditors have ~10 % false findings — never file an unverified finding, and never let a `REJECTED` one reach the verdict.
- Publish-related strings in a shell command trip the guard hook (`.claude/hooks/guard.mjs`): anything containing `npm publish`, `gh release`, `git push` or `git tag <name>` inside a segment, a `$( )`, or an interpreter payload is refused. Write such strings into files with Edit or Write, never through `echo` or a heredoc.
