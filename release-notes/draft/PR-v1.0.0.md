# release: v1.0.0 — the whole engine, offline

> **Branch:** `release/v1.0.0` → `main`
> **Type:** Major release (the first; `main` holds only the initial commit)
> **Engine:** pkinative ^1.0.0

## Summary

The first release of pkinative-cli: every export of pkinative 1.0.0 reached by a command, offline, with pkinative as the one runtime dependency and one process contract (stdout artefact or report, one JSON envelope on stderr, exit 0/1/2, 130/143 on a signal).
Passwords never on argv and key material never in output; outputs created exclusively or replaced atomically; every engine bound behind a `--max-*` flag; a configuration file that sets presentation only ([ADR 0007](../../docs/adr/0007-configuration-is-presentation-only.md)); a parser that holds every invocation to the registry, aliases included.

Counts: 18 commands · 47 subcommands (53 invocations) · 294/294 engine exports reached (117 runtime, 177 types) · 55/55 engine CHANGELOG bullets mapped · 688 tests across 50 files · 100 % statements, branches, functions and lines · every mutant of `src/` killed or argued equivalent · 57 samples · 12 `schema` subjects, including the `--json` report and `--summary` shape of every invocation.

## Changes

### Commands and flags

`pem`, `oid`, `fingerprint`, `asn1`; `cert`, `csr`; `chain`, `crl`, `ocsp`; `cms`, `tsp`; `key`, `p12`; `doctor`, `limits`, `explain`, `schema`, `completion` — README §Commands and `release-notes/v1.0.0.md`.

### Engine surface

pkinative `^1.0.0`; `docs/data/core-exports.json` traces each export to its command, `tests/regression/engine-surface.json` each bullet of the engine's 1.0.0 CHANGELOG to a test or a typed waiver. The registries of the engine's v1.0.0 tag are vendored under `docs/data/pkinative/`.

### Tooling (scripts/)

`gate.ts` (fast, ci and publish profiles, `--require-all`; `lint:certs` in the publish profile), `verify-docs.ts` (10 rules), `mutate.ts` and `lib/mutation.ts` (ported from pkinative; reviewed equivalents in `data/mutation-equivalents.json`), `build-report-schemas.ts` (the report schemas, from the types), `validators/pkilint-driver.py`, `package-files.ts`, `smoke-install.ts`, `release-prepare.ts`, `check-npm-drift.ts`, the surface and engine-surface builders, the sample plan and verifier, `build-docs.ts`, `build-claude-rules.ts`, `verify-issue.mjs`.

### CI and repository (.github/, root)

Ten workflows, every action SHA-pinned and every job behind harden-runner: `ci.yml` (Linux Node 22 and 24, Windows, macOS, runtimes, workflow lint with zizmor, actionlint and reuse), `conformance.yml` (OpenSSL interop, zlint v3.7.2 and pkilint 0.13.3 over every certificate the CLI creates), `sample-regression.yml`, `codeql.yml`, `dependency-review.yml`, `audit.yml`, `scorecard.yml`, `docs.yml`, `node-current.yml`, and `publish.yml` in four jobs on `release: published`. Rulesets for `main` and `v*` tags under `.github/rulesets/`.

### Agent layer (.claude/, AGENTS.md, governance)

`AGENTS.md` as the single source, `CLAUDE.md` importing it, `.github/instructions/` compiled to `.claude/rules/`, the PreToolUse guard over Bash and PowerShell, attribution off, the release-audit skill, `AGENT_RULES.md`, `ai-governance.json`, issue drafts under `.github/drafts/`.

### Tests

Unit, in-process command, library-parity, built-binary (PowerShell completion run in pwsh), seeded fuzz, OpenSSL interop, zlint and pkilint over created certificates, report schemas validated against every sample, surface and engine-surface matrices, sample regression, mutation testing, and the tooling, workflow and guard invariants.

### Documentation

README, `docs/KNOWLEDGE_BASE.md`, `docs/AGENT_CONTRACT.md`, `docs/THREAT_MODEL.md`, ADRs 0001–0007, SECURITY.md with §Release integrity, CONTRIBUTING.md, CHANGELOG.md, ROADMAP.md, CITATION.cff, llms.txt, THIRD-PARTY-NOTICES.md.

## Independent audit

Agent-run, before the maintainer's `/release-audit`: two rounds, each with two independent auditors (A: claims against code; B: help, matrices, release pipeline, gaps) and an adversarial verifier that confirmed or refuted every finding on the built binary.

| Round | Verdict | Confirmed | Resolution |
|---|---|---|---|
| 1 | NO-GO | 2 blockers, 6 majors, ~15 minors | all fixed (config allow-list, parser enforcement, PKCS#12 flow, generated report schemas, remedies) |
| 2 | NO-GO | 1 blocker (an alias bypassed the operand check), 3 majors (`-f` ignored; `cert encode` SKI of nothing; specs not closed), 16 minors, 3 nits, 3 notes; 1 rejected | all fixed in e4c3eb8..4b9422e, one regression test per finding |
| 3 | **GO** | every round-2 finding re-verified fixed on the built binary (119 alias/long-form pairs over the 53 invocations, ~80 spec probes, planted configs); 0 blockers, 0 majors; 2 minors (the argument after `--password-stdin` echoed when it starts with `-`, over-redacted when it is a substring) and 4 nits | all fixed in e292123 and d152225 |

`/release-audit release-notes/v1.0.0.md` — PENDING: the skill is the maintainer's to run (`disable-model-invocation`).

## Validation (what actually ran, on Windows 11, Node 22.23.2)

| Command | Result |
|---|---|
| `npx tsx scripts/gate.ts --publish --require-all` (with `ZLINT`, `PKILINT_PYTHON`) | `gate: 15 passed, 0 skipped` — typecheck, lint, build, dist-check, smoke, bundle-size (452 KiB), bundle-check, node-floor, test:coverage, interop, lint:certs, verify:docs, verify:samples, check:package, smoke:install |
| `npm run test:coverage` | 688 tests across 50 files (1 skipped: bash completion on Windows); 100 / 100 / 100 / 100 % statements / branches / functions / lines |
| `npx tsx scripts/mutate.ts --files <the 21 modules this loop touched>` | 1 626 mutants: every one killed, timed out, refused by the compiler or a reviewed equivalent (8, in `scripts/data/mutation-equivalents.json`); the 4 survivors of the first run were killed by d152225 and 2a8bfec, and the re-run of `src/cli.ts` and `src/utils/x509-spec.ts` scores 100 %. The full campaign over the 45 modules of `src/` at 629d6a9: 2 518 mutants, 0 survived |
| `npm run verify:docs` | 10 rules, 0 findings |
| `npx tsx scripts/verify-samples.ts` | 57 samples match their baseline |
| `npx tsx scripts/package-files.ts` | 11 files, exactly the `docs/data/package-files.json` list |
| `npx tsx scripts/smoke-install.ts` | the packed tarball installs; the installed bin answers `--version`, `doctor` and `cert inspect`; `node_modules` holds pkinative and pkinative-cli |
| `npm pack --dry-run` | 11 files, 123 827 bytes packed, 527 908 unpacked |
| `npm ls --omit=dev --all` | `pkinative@1.0.0` alone |
| actionlint 1.7.12, zizmor 1.30.1 (`--offline`) | no finding (shellcheck not run locally) |

## Backward compatibility

None to keep: the first release. From here on, commands, flags, exit codes, `E_*` classes and JSON members are the API (`release-notes/TEMPLATE.md` §Conventions).

## Out of scope (tracked in ROADMAP.md)

Node.js 26 as a blocking line (LTS on 2026-10-28: `node-current.yml` tracks it), coverage-guided fuzzing (ADR 0006). A network layer is never in scope (ADR 0004; ROADMAP §Never).

## Human-in-the-loop — steps for the maintainer

1. Push `main` (the initial commit). In Settings, enable the Dependency graph and private vulnerability reporting (`dependency-review.yml` fails on a pull request without the graph), and set the repository settings of CONTRIBUTING.md §Branch protection.
2. Create the environment `npm-publish` (the maintainer as required reviewer, deployments limited to tags matching `v*`: CONTRIBUTING.md §Branch protection).
3. Push `release/v1.0.0`; open this pull request.
4. Wait for the first run of every workflow; then import `.github/rulesets/main.json` and `tags.json` (Settings → Rules → Rulesets).
5. On npmjs.com, configure Trusted Publishing for `pkinative-cli`: repository `Nizoka/pkinative-cli`, workflow `publish.yml`, environment `npm-publish`.
6. Run `/release-audit release-notes/v1.0.0.md`; fix what it confirms.
7. On the publish day, set the date (currently 2026-10-04) in `CHANGELOG.md` `[1.0.0]`, `release-notes/v1.0.0.md` and `CITATION.cff` `date-released`; commit on the branch.
8. Squash-merge with the title `release: v1.0.0 — the whole engine, offline`, once the required checks are green.
9. Publish the GitHub Release `v1.0.0 — the whole engine, offline` (body = `release-notes/v1.0.0.md`, new tag `v1.0.0` on the merge commit, created by the Release itself: nobody pushes a tag); `publish.yml` runs on `release: published`; approve `npm-publish`. Afterwards `npm view pkinative-cli version` names 1.0.0 and `npx tsx scripts/check-npm-drift.ts` is clean.
10. Require 2FA and disallow tokens on the npm package; deprecate the `0.0.1` name reservation.

## Self-review checklist

- [x] Every count above was produced by a command on this branch, not typed from memory.
- [x] The release note and the CHANGELOG entry describe the same release, section by section; the CHANGELOG is the per-line record.
- [x] No `Co-Authored-By` trailer and no "generated with" footer anywhere on the branch.
- [x] The agent audit is summarised above: three rounds, final verdict GO, every confirmed finding fixed with its regression test.
- [ ] `/release-audit release-notes/v1.0.0.md`, run by the maintainer — PENDING: this PR is not ready to merge until it is.
