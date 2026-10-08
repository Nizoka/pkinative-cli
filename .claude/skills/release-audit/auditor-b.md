# Auditor B — help text, matrices and release surfaces

You audit one release of pkinative-cli. Your angle: **does everything a reader, an agent or the release pipeline consumes describe the behaviour that actually shipped?** Another auditor checks the claims against the code; you check the surfaces against the claims and against the code where the two disagree.

## Surfaces to cover

| Surface | Where | What to check |
|---|---|---|
| Help text | `src/commands/usage.ts`, `node dist/cli.cjs <command> --help` | Every command and subcommand of `src/commands/registry.ts` has a help block; every flag the registry accepts is described, with its real default; no flag is described that the registry refuses |
| Completion and schema | `src/commands/completion.ts`, `src/commands/schema.ts` | The same commands and flags as the registry; the schema's version is the package version |
| Explain | `src/commands/explain.ts`, `node dist/cli.cjs explain --list --json` | Every code the CLI can print is listed; the remedy says what the thrown message implies |
| Surface matrix | `docs/data/core-exports.json` | Regenerated (`npm run surface:build` then `git diff --stat`); counts match pkinative's `docs/data/pkinative/api.frozen.json`; each export's `via` names a command that really calls it |
| Engine-surface matrix | `tests/regression/engine-surface.json` | Every item of pkinative's changelog (`docs/data/pkinative/changelog-<engine>.md`) maps to a test that exists and asserts that behaviour, not merely mentions it |
| Sample baseline | `samples/`, `tests/regression/baselines/samples.sha256.json` | Every command has a `.sh` and `.ps1` pair that say the same thing; `npm run verify:samples` passes; a changed fingerprint is declared in the CHANGELOG |
| README | `README.md` (grep `^## ` first, read by section) | Every example runs as written against `dist/cli.cjs`; the command list matches the registry; the offline and secret-intake statements are true |
| Publish workflow | `.github/workflows/publish.yml` | Triggered on `release: published` only; runs in the `npm-publish` environment; publishes through Trusted Publishing (`id-token: write`, no `NODE_AUTH_TOKEN` secret) with provenance; npm >= 11.5.1; actions pinned by SHA; the gate runs before the publish |
| CHANGELOG and release note | `CHANGELOG.md`, `release-notes/v<version>.md` | Same version, same date, same claims; every user-visible change in the diff is named; the pkinative version the release is built on is stated |
| Governance | `SECURITY.md`, `docs/.well-known/security.txt`, `.github/SECURITY-INSIGHTS.yml` | The same reporting channel everywhere; `Expires` in the future; no statement the workflows do not back |

## Method

1. Start from the release note's claims (number them `B-01`, …) and map each to the surfaces above. A claim with no surface is a finding (`major` when the feature is public).
2. For each surface, run the regenerator where one exists and diff; where none exists, read the surface and the code side by side. Quote the line numbers.
3. Reproduce at least one assertion per surface with a command (`npm run verify:samples`, `npm run surface:build`, `npx vitest run tests/docs`, `node dist/cli.cjs <command> --help`, a `node -e` over a JSON surface).

## Autonomy pass (Phase D)

When invoked for Phase D, ignore the table above and answer one question: **can an agent that has only the published surfaces use every feature without reading `src/`?** For every feature in the release note, write the command you would run from `pkinative --help`, `pkinative <command> --help`, `pkinative schema`, `pkinative explain`, the README and `samples/` alone, then run it against `dist/cli.cjs` with the fixtures of `tests/fixtures/`. A command that needs `src/` to get right is a finding; name the sentence that was missing. Then provoke one failure per command and check that `pkinative explain <code>` tells the agent what to do next.

## Output

Write `.audit/<version>/auditor-b.md` (or `auditor-d.md` for the autonomy pass) in the finding format of `ledger.md`, every row with its evidence command. Finish with the three-line summary: surfaces checked, findings by severity, anything left unverified and why.

Do not fix anything. Do not push, tag or publish. Never put `npm publish`, `gh release`, `git push` or `git tag <name>` in a shell command — the guard hook refuses the whole command.
