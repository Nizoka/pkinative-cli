---
paths:
  - "tests/**"
  - "vitest.config.ts"
  - "scripts/**"
---
<!-- GENERATED from .github/instructions/testing.instructions.md by scripts/build-claude-rules.ts — do not edit -->

# Testing

## Suites

- `tests/commands/` drive the CLI in-process with `cli(argv, { stdin, env, cwd })` from `tests/helpers/io.ts`: no process, no real stdout; assert on `code`, `stdout`, `stderr`, `envelope(stderr)`.
- `tests/utils/` unit-test the helpers; `tests/docs/` hold the surface matrix, the help text and the fixtures to their sources.
- `tests/parity/` compare the CLI's `--json` with pkinative's own result; `tests/fuzz/` are seeded (`tests/helpers/prng.ts`), so a failure reproduces from its seed.
- `tests/integration/` run `dist/cli.cjs` (skipped without a build, required under `GATE_REQUIRE_ARTIFACTS=1`); `tests/interop/` run OpenSSL 3 (required under `REQUIRE_INTEROP=1`).
- `tests/regression/` pin the samples and map the engine's CHANGELOG bullets to tests or typed waivers.
- `tests/tools/` hold the release tooling (gate, bundle probe, package files, npm drift, release-prepare, verify-docs), the workflows and rulesets, the agent guard hook and the issue-draft verifier to their invariants.

## Rules

- Coverage is 100 % on all four axes, never lowered; `src/bin.ts` is the only exclusion (the built-binary suite runs it).
- Time is pinned: `--at 2027-01-01T00:00:00Z` (`AT` in the helpers) inside the fixtures' 2026–2046 validity; `TZ=UTC` in vitest.
- Fixtures under `tests/fixtures/pki/` come from OpenSSL (`scripts/fixtures/make-test-pki.sh`), are TEST-ONLY, LF, and pinned in `SHA256SUMS` with a `PROVENANCE.md` row. A test never calls OpenSSL to make a fixture.
- Outputs go to `emptyDir()` temp directories, never the repository.
- A sample change re-pins `tests/regression/baselines/samples.sha256.json` only with the reason in the release note.

## Commands

`npx vitest run tests/<path>.test.ts`; `npm run test:coverage`; `npm run build && npx tsx scripts/verify-samples.ts`. On Windows, run from `D:\` (upper-case drive letter).
