<!--
Thank you for contributing to pkinative-cli. Describe the change, then walk
the checklist. The items mirror CONTRIBUTING.md §Pull Request Checklist word
for word; keep the two in step when you change either.
-->

## What and why

<!-- One paragraph: what changes, why, and which issue it closes (`Closes #…`). -->

## Checklist

- [ ] `npm run gate` passes — the CI profile in one command (`npm run gate:fast` for a quick loop while iterating)
- [ ] All tests pass (`npm run test`), and coverage stays at 100 % (`npm run test:coverage`)
- [ ] Type check passes (`npm run typecheck:all`)
- [ ] Lint passes (`npm run lint`)
- [ ] New code has tests, and every new error mapping, refusal or limit is raised by at least one of them
- [ ] No `any` types introduced
- [ ] No new runtime dependencies added (`pkinative` stays the only one)
- [ ] No network access, no secret accepted on argv, no key material printed, and no check a config file can relax
- [ ] A new or changed command updates its help text (`src/commands/usage.ts`), the registry, completion and schema, and the docs that describe it
- [ ] If a command's output changed: samples regenerated (`npm run samples:generate`) and `npm run verify:samples` passes; an intended output change is declared in the CHANGELOG
- [ ] If the engine surface changed (a pkinative bump, a new export reached): `npm run surface:build` re-run and the diff of `docs/data/core-exports.json` and `tests/regression/engine-surface.json` reviewed
- [ ] If docs, README, AGENTS.md, CLAUDE.md or `.claude/` changed: `npm run verify:docs` passes
- [ ] CHANGELOG.md updated if user-facing changes
- [ ] No `Co-Authored-By` trailer and no "generated with" footer on any commit or in this description
- [ ] For releases: follow [Release](../CONTRIBUTING.md#release) — the branch is `release/vX.Y.Z`, the title `release: vX.Y.Z — …`, and the release note is written

<!--
Pull requests, tags, GitHub Releases and npm publishes are the maintainer's
acts, never an agent's (.github/AGENT_RULES.md §5).
-->
