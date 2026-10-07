# Contributing to pkinative-cli

Thank you for helping. pkinative-cli is a thin front end: a change in PKI behaviour belongs to [pkinative](https://github.com/Nizoka/pkinative); a change in how that behaviour reaches the command line belongs here.

## Development setup

### Requirements

- Node.js `^22.22.2 || ^24.14.1 || >=25.8.2` (`.nvmrc` says 22; `.npmrc` sets `engine-strict`, so an older Node refuses the install).
- npm 10. Nothing else: `npm ci` installs the whole toolchain, and `ignore-scripts` keeps every lifecycle script off.
- OpenSSL 3 for the interoperability suite (optional locally, required in CI).

### First pull request in ten minutes

```sh
git clone https://github.com/Nizoka/pkinative-cli && cd pkinative-cli
npm ci
npm run hooks:install          # optional: lint + CRLF guard on commit, the fast gate on push
npm run gate:fast              # typecheck, lint, tests, docs — green before you start
```

Sign your commits if you can (`git commit -S`); write them as [Conventional Commits](#commit-messages).

## Build, test, check

| Task | Command |
|---|---|
| Build `dist/cli.cjs` | `npm run build` |
| All tests with coverage (100 % on four axes) | `npm run test:coverage` |
| One suite | `npx vitest run tests/commands/cert.test.ts` |
| Lint, type-check | `npm run lint`, `npm run typecheck:all` |
| Documentation held to the source | `npm run verify:docs` |
| Samples against the built CLI | `npm run build && npm run verify:samples` |
| THE gate | `npm run gate` (`npx tsx scripts/gate.ts --fast \| --publish --require-all`) |

On Windows, run from the upper-case drive path (`D:\…`), and call `npx tsx scripts/gate.ts --fast` rather than `npm run gate -- --fast` (PowerShell swallows `--`).

## Code style

- TypeScript strict with `noUncheckedIndexedAccess` and `exactOptionalPropertyTypes`; type-aware ESLint; 4 spaces; LF.
- No `any`, no non-null assertion, no `console.*` in `src/` (output goes through `src/utils/io.ts`), relative imports with `.js`.
- No comment that restates the code; a comment says why when the why is not obvious.
- Every engine call inside `guard()` with `parseOptions(ctx)`; every new flag in `src/commands/registry.ts` and the help text.

## Adding or changing a command

Follow [AGENTS.md §Architecture](AGENTS.md#architecture): handler, registry, help, `loadCommand`, `RUNTIME_VIA` + `npm run surface:build`, tests at 100 %, a sample (`npm run samples:generate`, then `npx tsx scripts/verify-samples.ts --update` with the reason in the release note), README and `docs/KNOWLEDGE_BASE.md` (`npm run docs:build`).

Before proposing a feature, check that pkinative provides it and does not refuse it by doctrine (no network, no key generation, no PKCS#8/#12 writer, no legacy PKCS#12 schemes, no default RSA scheme).

## Fixtures

`tests/fixtures/pki/` is a TEST-ONLY PKI produced by OpenSSL with `scripts/fixtures/make-test-pki.sh`, pinned in `tests/fixtures/SHA256SUMS` and described in `tests/fixtures/PROVENANCE.md`.
Add a fixture by extending the script, generating the one new file, adding its checksum and its row; never regenerate the existing files in place.

## Security

Never paste a real key, password or certificate chain into an issue. Report vulnerabilities privately ([SECURITY.md](SECURITY.md)).

## Branch strategy

`main` receives squash merges only. Work on `feat/…`, `fix/…`, `docs/…`; a release on `release/vX.Y.Z`.

## Pull Request Checklist

`.github/pull_request_template.md` carries the same items; `npm run verify:docs` holds the two lists word for word.

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
- [ ] For releases: follow [Release](#release) — the branch is `release/vX.Y.Z`, the title `release: vX.Y.Z — …`, and the release note is written

## Commit messages

Conventional Commits with a scope: `feat(cert): …`, `fix(io): …`, `test(fuzz): …`, `docs: …`, `ci: …`, `chore(deps): …`. The subject says what changes for a user; the body says why.
No `Co-Authored-By` trailer — for people or tools.

## Release

The version bump is mechanical; the judgement goes into the release note.

1. Branch from `main`: `release/vX.Y.Z`.
2. `npx tsx scripts/release-prepare.ts --version X.Y.Z` bumps `package.json`, the lockfile, `CITATION.cff`, `llms.txt` and the SECURITY.md table, and scaffolds `release-notes/vX.Y.Z.md` and `release-notes/draft/PR-vX.Y.Z.md`. `git diff --stat` must read as the bump and nothing else.
3. Write the release note and the `CHANGELOG.md` entry (`## [X.Y.Z] – YYYY-MM-DD`).
4. Run the mutation campaign (`npm run mutate`, a few hours): every mutant killed, or recorded with its argument in `scripts/data/mutation-equivalents.json`. Then the pre-release audit (`/release-audit`: two auditors, an adversarial verifier, a GO/NO-GO ledger under `.audit/`). Fix what survives.
5. `npx tsx scripts/gate.ts --publish --require-all`.
6. Fill `release-notes/draft/PR-vX.Y.Z.md`: paste the figures the gate printed; anything not run is `not run`, never a guess. These bodies are committed: they are the auditable record of what each release claimed.
7. Squash-merge with the title `release: vX.Y.Z — <headline>`.
8. The maintainer publishes the GitHub Release (title `vX.Y.Z — <headline>`, body = the release note, new tag `vX.Y.Z` on the merge commit). Publishing it starts `publish.yml`: `guard` checks the tag against `package.json`; `build` runs the publish gate and packs once; `publish` waits for the `npm-publish` reviewer, re-checks the digests and publishes with provenance; `attest` compares the registry's bytes, attests the tarball and the SBOMs and attaches them to the Release.
9. Once, after the first green `publish` run: in the npm package settings, require two-factor authentication **and disallow tokens**, so Trusted Publishing from `publish.yml` is the only path; then deprecate the `0.0.1` name reservation (`npm deprecate pkinative-cli@0.0.1 "name reservation; install 1.0.0 or later"`). An `ENEEDAUTH` or a 404 on upload means the Trusted Publishing entry does not name exactly this repository, `publish.yml` and `npm-publish`: fix it on npmjs.com and re-run; never add an `NPM_TOKEN` secret.

### Bumping the engine

A pkinative minor can add exports, codes or diagnostics. Bumping `^1.x`:

1. Copy the registries of the new tag into `docs/data/pkinative/` (`git show vX.Y.Z:<path>`), including the new CHANGELOG entry as `changelog-X.Y.Z.md`.
2. `npx vitest run tests/docs/surface.test.ts` names every export the CLI does not reach yet; reach each one (a command or a flag), then `npm run surface:build`.
3. Map every bullet of the new CHANGELOG entry in `scripts/build-engine-surface.ts` to a test or a typed waiver.
4. `PKI_TO_CLI` must cover any new code (`tsc` fails otherwise).

### Branch protection

The rules for `main` are versioned in [.github/rulesets/main.json](.github/rulesets/main.json): no deletion, no force-push, pull request required (squash only, threads resolved, stale reviews dismissed), CodeQL results required, and the status checks of `ci.yml`, `conformance.yml`, `sample-regression.yml` and `dependency-review.yml` required and up to date.
No required workflow is path-filtered: GitHub would leave a filtered-out check pending forever. The tag rules ([.github/rulesets/tags.json](.github/rulesets/tags.json)) forbid deleting, moving or updating a `v*` tag.

**Import the rulesets after the first push to `main`**, never before (Settings → Rules → Rulesets → Import a ruleset): a ruleset that requires a pull request leaves no legal path to seed the branch. Single-maintainer choices, as in pkinative: zero required approvals, and an admin bypass in pull-request mode only. **Signed commits are not required.** GitHub checks every commit of the head branch, so one unsigned commit of a first-time contributor would block the squash merge; sign yours anyway.

Settings outside the rulesets, set once:

- Dependency graph **on** (`dependency-review` needs it); private vulnerability reporting **on**, with Dependabot alerts and security updates, and secret scanning with push protection.
- Code scanning: the CodeQL **advanced** set-up (`codeql.yml`), not the default one.
- Release immutability **off** (`publish.yml` attaches files after the Release is published).
- Environment `npm-publish`: the maintainer as required reviewer, deployments limited to tags matching `v*`.
- Actions → General: workflow permissions read-only; Actions may not create or approve pull requests.

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
