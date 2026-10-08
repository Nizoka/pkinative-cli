# Release pull-request template

The body of the release pull request. `scripts/release-prepare.ts` copies the fenced block below into `release-notes/draft/PR-vX.Y.Z.md` and resolves `X.Y.Z` and `YYYY-MM-DD`; you fill the rest and the maintainer pastes the result into the GitHub pull request.

**The per-version bodies are committed**: they are the auditable record of what each release claimed and what was actually run.

**Keep the section order.** The release audit (`/release-audit`) reads *Independent audit* and *Validation* by name.

**Every figure comes from a command run on the release branch.** A command that was not run is marked `not run`, never guessed.

---

```markdown
# release: vX.Y.Z — <headline>

> **Branch:** `release/vX.Y.Z` → `main`
> **Type:** <Major | Minor | Patch> release (<compatibility statement>)
> **Engine:** pkinative <range>

## Summary

<!-- One paragraph. Counts: N commands · N subcommands · N/N engine exports reached · N tests · N % statements · N samples. -->

## Changes

### Commands and flags

### Engine surface

### Tooling (scripts/)

### CI and repository (.github/, root)

### Agent layer (.claude/, AGENTS.md, governance)

### Tests

### Documentation

## Independent audit

`/release-audit release-notes/vX.Y.Z.md` — <PENDING | GO | NO-GO>

## Validation (what actually ran, on <OS>, Node <version>)

| Command | Result |
|---|---|
| `npx tsx scripts/gate.ts --publish --require-all` | <the gate's summary line> |
| `npm run test:coverage` | <N tests across M files; statements / branches / functions / lines> |
| `npm run verify:docs` | <N rules, 0 findings> |
| `npx tsx scripts/verify-samples.ts` | <N samples match their baseline> |
| `npx tsx scripts/package-files.ts` | <N files, exactly the manifest> |
| `npx tsx scripts/smoke-install.ts` | <the installed bin answers> |
| `npm ls --omit=dev --all` | <pkinative alone> |

## Backward compatibility

<!-- Commands, flags, exit codes, E_* classes and JSON members: unchanged, or the exact list of what moved and the migration. -->

## Out of scope (tracked in ROADMAP.md)

## Human-in-the-loop — steps for the maintainer

1. Squash-merge to `main` with the title `release: vX.Y.Z — <headline>`, once the required checks are green.
2. Publish the GitHub Release (title `vX.Y.Z — <headline>`, body = `release-notes/vX.Y.Z.md`, new tag `vX.Y.Z` on the merge commit).
3. Approve the `npm-publish` environment; `publish.yml` then publishes and attests. Afterwards `npm view pkinative-cli version` names X.Y.Z and `npx tsx scripts/check-npm-drift.ts` is clean.
4. <Anything version-specific.>

## Self-review checklist

- [ ] Every count above was produced by a command on this branch, not typed from memory.
- [ ] `git diff --stat` of the bump reads as the bump and the regenerated files, nothing else.
- [ ] The release note and the CHANGELOG entry carry the same bullets.
- [ ] No `Co-Authored-By` trailer and no "generated with" footer anywhere on the branch.
- [ ] The audit ledger is summarised above with a fix commit for every confirmed blocker and major — or the section says PENDING and this PR is not ready to merge.
```
