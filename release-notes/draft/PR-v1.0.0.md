# release: v1.0.0 — the whole engine, offline

> **Branch:** `release/v1.0.0` → `main`
> **Type:** Major release (the first; `main` holds only the initial commit)
> **Engine:** pkinative ^1.0.0

## Summary

The first release of pkinative-cli: every export of pkinative 1.0.0 reached by a command, offline, with pkinative as the one runtime dependency and one process contract (stdout artefact or report, one JSON envelope on stderr, exit 0/1/2, 130/143 on a signal).
Passwords never on argv and key material never in output; outputs created exclusively or replaced atomically; every engine bound behind a `--max-*` flag that a configuration file cannot set.

Counts: 18 commands · 47 subcommands · 294/294 engine exports reached (117 runtime, 177 types) · 55/55 engine CHANGELOG bullets mapped · 520 tests across 37 files · 100 % statements, branches, functions and lines · 57 samples.

## Changes

### Commands and flags

`pem`, `oid`, `fingerprint`, `asn1`; `cert`, `csr`; `chain`, `crl`, `ocsp`; `cms`, `tsp`; `key`, `p12`; `doctor`, `limits`, `explain`, `schema`, `completion` — README §Commands and `release-notes/v1.0.0.md`.

### Engine surface

pkinative `^1.0.0`; `docs/data/core-exports.json` traces each export to its command, `tests/regression/engine-surface.json` each bullet of the engine's 1.0.0 CHANGELOG to a test or a typed waiver. The registries of the engine's v1.0.0 tag are vendored under `docs/data/pkinative/`.

### Tooling (scripts/)

`gate.ts` (fast, ci and publish profiles, `--require-all`), `verify-docs.ts` (10 rules), `package-files.ts`, `smoke-install.ts`, `release-prepare.ts`, `check-npm-drift.ts`, the surface and engine-surface builders, the sample plan and verifier, `build-docs.ts`, `build-claude-rules.ts`, `verify-issue.mjs`.

### CI and repository (.github/, root)

Ten workflows, every action SHA-pinned and every job behind harden-runner: `ci.yml` (Linux Node 22 and 24, Windows, macOS, runtimes, workflow lint with zizmor, actionlint and reuse), `conformance.yml`, `sample-regression.yml`, `codeql.yml`, `dependency-review.yml`, `audit.yml`, `scorecard.yml`, `docs.yml`, `node-current.yml`, and `publish.yml` in four jobs on `release: published`. Rulesets for `main` and `v*` tags under `.github/rulesets/`.

### Agent layer (.claude/, AGENTS.md, governance)

`AGENTS.md` as the single source, `CLAUDE.md` importing it, `.github/instructions/` compiled to `.claude/rules/`, the PreToolUse guard over Bash and PowerShell, attribution off, the release-audit skill, `AGENT_RULES.md`, `ai-governance.json`, issue drafts under `.github/drafts/`.

### Tests

Unit, in-process command, library-parity, built-binary, seeded fuzz, OpenSSL interop, surface and engine-surface matrices, sample regression, and the tooling, workflow and guard invariants.

### Documentation

README, `docs/KNOWLEDGE_BASE.md`, `docs/AGENT_CONTRACT.md`, `docs/THREAT_MODEL.md`, ADRs 0001–0006, SECURITY.md with §Release integrity, CONTRIBUTING.md, CHANGELOG.md, ROADMAP.md, CITATION.cff, llms.txt, THIRD-PARTY-NOTICES.md.

## Independent audit

`/release-audit release-notes/v1.0.0.md` — PENDING

The skill is the maintainer's to run (`disable-model-invocation`). Before it, the agent checked its documented blind spots by hand on the built binary: no `test-only-password` and no private scalar in any stdout, stderr or `--json` envelope of `key inspect`, `key check`, `p12 inspect`, `p12 open` and `p12 bags`; a `.pkinativerc.json` setting `overwrite` is refused with `E_USAGE`; `--password` on argv exits 2.

## Validation (what actually ran, on Windows 11, Node 22.17.0)

| Command | Result |
|---|---|
| `npx tsx scripts/gate.ts --publish` | `gate: 13 passed, 1 skipped` — `node-floor` skipped: Node.js 22.17.0 is below the security floor |
| `npx tsx scripts/gate.ts --publish --require-all` | not green on this machine: `node-floor` fails, as designed, on Node.js 22.17.0; to be run on Node ≥ 22.22.2 (CI and `publish.yml` do) |
| `npm run test:coverage` | 520 tests across 37 files; 100 / 100 / 100 / 100 % statements / branches / functions / lines |
| `npm run verify:docs` | 10 rules, 0 findings |
| `npx tsx scripts/verify-samples.ts` | 57 samples match their baseline |
| `npx tsx scripts/package-files.ts` | 10 files, exactly the `docs/data/package-files.json` list |
| `npx tsx scripts/smoke-install.ts` | the packed tarball installs; the installed bin answers `--version`, `doctor` and `cert inspect`; `node_modules` holds pkinative and pkinative-cli |
| `npm pack --dry-run` | 10 files, 102 477 bytes packed, 393 942 unpacked |
| `npm ls --omit=dev --all` | `pkinative@1.0.0` alone |
| actionlint 1.7.12, zizmor 1.30.1 (`--offline`) | no finding (shellcheck not run locally) |

## Backward compatibility

None to keep: the first release. From here on, commands, flags, exit codes, `E_*` classes and JSON members are the API (`release-notes/TEMPLATE.md` §Conventions).

## Out of scope (tracked in ROADMAP.md)

Mutation testing, certificate linting (zlint, pkilint) in `conformance.yml`, Node.js 26 as a blocking line, and any network layer.

## Human-in-the-loop — steps for the maintainer

1. Push `main` (the initial commit) and `release/v1.0.0`; open this pull request.
2. Wait for the first run of every workflow; then import `.github/rulesets/main.json` and `tags.json` (Settings → Rules → Rulesets), and set the repository settings of CONTRIBUTING.md §Branch protection.
3. On npmjs.com, configure Trusted Publishing for `pkinative-cli`: repository `Nizoka/pkinative-cli`, workflow `publish.yml`, environment `npm-publish`.
4. Run `/release-audit release-notes/v1.0.0.md`; fix what it confirms.
5. Squash-merge with the title `release: v1.0.0 — the whole engine, offline`, once the required checks are green.
6. Publish the GitHub Release `v1.0.0 — the whole engine, offline` (body = `release-notes/v1.0.0.md`, new tag `v1.0.0` on the merge commit); approve `npm-publish`. Afterwards `npm view pkinative-cli version` names 1.0.0 and `npx tsx scripts/check-npm-drift.ts` is clean.
7. Require 2FA and disallow tokens on the npm package; deprecate the `0.0.1` name reservation.

## Self-review checklist

- [x] Every count above was produced by a command on this branch, not typed from memory.
- [x] The release note and the CHANGELOG entry describe the same release, section by section; the CHANGELOG is the per-line record.
- [x] No `Co-Authored-By` trailer and no "generated with" footer anywhere on the branch.
- [ ] The audit ledger is summarised above — PENDING: this PR is not ready to merge until it is.
