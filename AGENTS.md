# AGENTS.md

Condensed, editor-agnostic guidance for AI coding agents working **on** pkinative-cli (Cursor, Aider, Claude Code, Copilot, Continue, Zed, Cline, Windsurf, Goose, Gemini CLI, …).
Canonical detail: [.github/copilot-instructions.md](.github/copilot-instructions.md) + [.github/instructions/](.github/instructions/).
Claude Code loads [CLAUDE.md](CLAUDE.md), which imports this file. Keep the three consistent.
Agents that **drive** the CLI from a pipeline read [docs/AGENT_CONTRACT.md](docs/AGENT_CONTRACT.md) (envelopes, error codes, token economy) instead.

## Mission and constraints

pkinative-cli is the official terminal front end of the [pkinative](https://github.com/Nizoka/pkinative) PKI engine: 18 commands
that reach every one of its 294 exports — ASN.1, OIDs, PEM, fingerprints, X.509 certificates and requests, path validation,
CRL and OCSP, CMS SignedData, RFC 3161 time-stamps, PKCS#8 and PKCS#12 — with an agent-first process contract.

- **One runtime dependency.** `pkinative` is the ONLY runtime dependency; all PKI logic lives there. Proposing another runtime package is a hard block.
- **One import point.** Every `pkinative` symbol enters through `src/core-bridge/index.ts`; ESLint `no-restricted-imports` and `tests/docs/surface.test.ts` refuse any other.
- **The whole surface, proven.** `docs/data/core-exports.json` maps each of the 294 exports to the subcommands that reach it; a new engine export fails the suite until a command reaches it.
- **Agent-first.** stdout = artefact or report, stderr = diagnostics and the `--json` envelope, exit 0/1/2 (130/143 on a signal), 13 stable `E_*` classes carrying pkinative's `PKI_*` code verbatim.
- **Offline, always.** No command opens a socket: CRLs, OCSP responses and time-stamps are files the caller fetched; requests are files the caller sends.
- **Secrets stay secret.** A password is never accepted on argv (`--password-file`, `--password-stdin`, `PKINATIVE_PASSWORD`); `key` and `p12` reports are allow-list views that never carry a key byte.
- **Refusals are inherited, never lifted.** pkinative's doctrine (no key generation, no PKCS#8/#12 writing, PBES2 and PBMAC1 only, SHA-1 only under `--allow-sha1`, RSA only with an explicit scheme) is the CLI's.
  A config file is presentation only (ADR 0007): `json`, `pretty`, `quiet`, `no-color`, `format`, `encoding`, `fields`, `summary`, `strict`; every other key is refused, so it can never change an input, trust, time, a bound or an output.
- **ESM-first TypeScript strict.** Relative imports carry `.js`; no `any`; no `console.*` in `src/` (every byte goes through `utils/io.ts`); `const` and `readonly` by default.
- **Human-in-the-loop.** Agents draft and verify; the maintainer pushes, opens PRs/issues, tags and publishes (see Governance).
- **English everywhere.** Code, comments, tests, samples, docs and release notes are English.

## The gate

`npm run gate` is THE quality gate (`scripts/gate.ts`; the step list is its `STEPS` table). Logs land in `test-output/.gate/<step>.log`; the summary is one line per step.

| Profile | Command | Runs |
|---|---|---|
| Fast — before every commit | `npm run gate:fast` | typecheck:all, lint, test, verify:docs |
| CI — the default | `npm run gate` | typecheck:all, lint, build, dist-check, smoke, bundle-size, bundle-check, node-floor, test:coverage (built-binary suites required), interop, verify:docs, verify:samples, check:package |
| Publish — release branches | `npx tsx scripts/gate.ts --publish --require-all` | the CI steps, lint:certs (zlint and pkilint over the certificates `cert create` writes) and smoke:install (the packed tarball installed and run); `--require-all` fails a skip — OpenSSL or a linter missing, or Node.js below the floor |

PowerShell swallows a bare `--`, so pass flags by calling the script: `npx tsx scripts/gate.ts --fast`, `--only <step>`.
One suite: `npx vitest run tests/<path>.test.ts` (dot reporter). Smoke-test the **built** CLI (`node dist/cli.cjs …`) before claiming a change works.

## Where is what

| Path | Purpose | Read first |
|---|---|---|
| `src/cli.ts` | `run(argv, io)`: global flags, subcommand dispatch, unknown-flag refusal, config merge, envelopes, exit code | `cli-design.instructions.md` |
| `src/bin.ts` | The process wrapper: EPIPE → exit 0, SIGINT/SIGTERM → remove the half-written file, exit 130/143 | `cli-design.instructions.md` |
| `src/commands/registry.ts` | THE surface table: commands, subcommands, flags (parser, help parity, completions, manifest) | `commands.instructions.md` |
| `src/commands/usage.ts` | Hand-written help, held to the registry by `tests/docs/usage.test.ts` | `commands.instructions.md` |
| `src/commands/<name>.ts` | One file per command | `commands.instructions.md` |
| `src/utils/` | args, io (exclusive or atomic writes), pkierr (57 codes → 13 classes), wire (ADR 0018), secrets, signer, spki, x509-spec, key-views, render | `security.instructions.md` |
| `src/core-bridge/index.ts` | The single `pkinative` import point, grouped by capability | `copilot-instructions.md` |
| `docs/data/pkinative/` | pkinative's registries at the immutable `v1.0.0` tag (errors, reasons, diagnostics, limits, defaults, surfaces, api.frozen, changelog) | — |
| `scripts/` | gate, verify-docs, surface and engine-surface builders, sample plan and verifier, package-files, smoke-install, release-prepare, agents:rules | `testing.instructions.md` |
| `tests/` | `commands/`, `utils/`, `docs/` (surface, usage, fixtures), `regression/` (samples, engine surface), `parity/`, `fuzz/`, `integration/` (built binary), `interop/` (OpenSSL) | `testing.instructions.md` |
| `tests/fixtures/pki/` | A TEST-ONLY PKI produced by OpenSSL, pinned by `SHA256SUMS` | `tests/fixtures/PROVENANCE.md` |
| `samples/` | One `.sh` + `.ps1` pair per subcommand (`doctor` excepted), generated from `scripts/lib/sample-plan.ts` | — |

## Architecture

`argv → parseArgs (registry booleans) → locate command and subcommand → refuse unknown flags → config merge → global options → loadCommand() → command → stdout / stderr → exit code`.
Commands are thin: read inputs through `utils/pki-input.ts` (PEM or DER, capped), call the bridge inside `guard()`, emit a report (`emitReport`) or an artefact (`emitArtifact`).

Adding or changing a subcommand touches ALL of these (the tests named fail on a missed step):

1. `src/commands/<name>.ts`, `src/commands/registry.ts` (its flags), `src/commands/usage.ts` (its help) and `src/cli.ts` (`loadCommand()`) — `tests/docs/usage.test.ts`.
2. `scripts/lib/surface.ts` `RUNTIME_VIA` for every engine export it reaches, then `npm run surface:build` — `tests/docs/surface.test.ts`.
3. Tests under `tests/commands/` at 100 % coverage; a sample in `scripts/lib/sample-plan.ts`, then `npm run samples:generate` and `npx tsx scripts/verify-samples.ts --update` — `tests/regression/samples.test.ts`.
4. README command reference, `docs/KNOWLEDGE_BASE.md`, `docs/AGENT_CONTRACT.md` when the contract moves, `llms.txt` — `npm run verify:docs`.

## Consumer contract in brief

`--json` → the report on stdout (ADR 0018 wire form: bigint → decimal string, bytes → lowercase hex) and `{ ok, command, …, diagnostics }` on stderr;
failures `{ ok: false, command, error: { code, message, pkiCode?, detail?, remedy?, reasons? }, diagnostics }` with one of
`E_USAGE`, `E_INPUT`, `E_PARSE`, `E_IO`, `E_SECURITY`, `E_LIMIT`, `E_UNSUPPORTED`, `E_CRYPTO`, `E_PASSWORD`, `E_NOT_FOUND`, `E_VERIFY_FAILED`, `E_CHECK_FAILED`, `E_RUNTIME`.
`--dry-run` validates without writing; `--summary` / `--fields` shrink stdout JSON; `pkinative schema <subject>` and `pkinative explain <code>` describe every shape and code.

## Never touch

- `release-notes/v*.md` of already-shipped versions (read-only history); `docs/data/pkinative/` (copied from the engine's tag, never edited).
- `tests/fixtures/pki/` (regenerating makes new keys: new fixtures, new `SHA256SUMS`, a new `PROVENANCE.md` row).
- `dist/`, `coverage/`, `test-output/`, `node_modules/`, `package-lock.json` (npm owns it), and the generated files below.

## Generated files

| File | Regenerate with |
|---|---|
| `.claude/rules/*.md` | `npm run agents:rules` (from `.github/instructions/*.instructions.md`; drift fails `verify:docs`) |
| `docs/data/core-exports.json`, `tests/regression/engine-surface.json` | `npm run surface:build` |
| `samples/**/*.sh`, `samples/**/*.ps1`, `samples/inputs/` | `npm run samples:generate` |
| `tests/regression/baselines/samples.sha256.json` | `npm run build && npx tsx scripts/verify-samples.ts --update` — only with the reason in the release note |
| `docs/data/errors.json`, `docs/data/package-files.json`, the generated sections of `docs/KNOWLEDGE_BASE.md` | `npm run docs:build` |
| `src/generated/report-schemas.ts` (every report, `--summary` and status schema) | `npm run schemas:build` (drift fails `verify:docs`) |

## Counts and versions

18 commands, 53 invocations (commands and subcommands), 13 error classes, 294 engine exports reached, 22 limit flags, 12 schema subjects, 57 pinned samples.
`npm run verify:docs` holds every count quoted in the docs to the source. Coverage: 100 % on statements, branches, functions and lines, never lowered.
Engine: pkinative 1.0.0 (`^1.0.0`); Node.js `^22.22.2 || ^24.14.1 || >=25.8.2` (CVE-2026-21713).

## Releasing

Follow CONTRIBUTING.md §Release and `scripts/release-prepare.ts`; Conventional Commits (`feat(scope):`, `fix(scope):`, `docs:`, `chore:`), never with a `Co-Authored-By` trailer.
Every runtime change gets a CHANGELOG line and a line in the next `release-notes/vX.Y.Z.md`.
`/release-audit` (Claude Code skill) runs the pre-release audit; the maintainer merges and publishes the GitHub Release, which creates the tag and starts `publish.yml`.

## Governance

Human-in-the-loop, enforced: agents never push, never open PRs/issues/releases, never publish, never tag, and never add `Co-Authored-By` trailers.
Protocol: [.github/AGENT_RULES.md](.github/AGENT_RULES.md); machine-readable policy: [.github/ai-governance.json](.github/ai-governance.json).
Issue drafts go to `.github/drafts/` for a human to submit.

## Ecosystem

- [pkinative](https://github.com/Nizoka/pkinative) — the zero-dependency PKI engine this CLI wraps; every PKI behaviour is upstream.
- [pdfnative-cli](https://github.com/Nizoka/pdfnative-cli), [zipnative-cli](https://github.com/Nizoka/zipnative-cli) — sibling CLIs built on the same contract.

See also: [ROADMAP.md](ROADMAP.md), [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), [llms.txt](llms.txt).
