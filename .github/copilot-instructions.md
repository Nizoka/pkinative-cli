# pkinative-cli — instructions for coding agents

pkinative-cli is the official command line of [pkinative](https://github.com/Nizoka/pkinative), a zero-dependency PKI engine.
It is a thin, strict front end: every PKI decision is the engine's; the CLI reads inputs, calls the engine, and reports.

## Non-negotiables

1. **One runtime dependency, one import point.** `pkinative` only, imported in `src/core-bridge/index.ts` only.
2. **The whole surface, and only it.** Every engine export is reached by a command (`docs/data/core-exports.json`); nothing the engine refuses by doctrine is added by the CLI (no key generation, no PKCS#8/#12 writing, no network).
3. **Offline.** No socket, no fetch, no DNS. Revocation evidence and time-stamps are files.
4. **Secrets.** Never accept a password on argv; never print, log or envelope key material; `key`/`p12` reports are allow-list views (`src/utils/key-views.ts`).
5. **Process contract.** stdout carries the artefact or the report; stderr carries diagnostics and the single `--json` envelope; exit 0 success, 1 failure, 2 usage, 130/143 signals.
6. **Errors.** Every engine call runs inside `guard()`/`guardAsync()` (`src/utils/pkierr.ts`): the 57 `PKI_*` codes map to 13 `E_*` classes with the engine code verbatim in `pkiCode`. A new `E_RUNTIME` in the fuzz suite is a bug.
7. **Writes.** Through `writeOutput` only: exclusive (`lstat` + `wx`) by default, atomic (temp + rename) with `--overwrite`, removed on a signal.
8. **Strict TypeScript.** `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, no `any`, no non-null assertion, no `console.*` in `src/`, relative imports with `.js`.
9. **100 % coverage** on statements, branches, functions and lines; a branch no input can reach is removed, not excused.
10. **Human-in-the-loop.** Agents never push, tag, publish or open PRs/issues/releases, and never add `Co-Authored-By` trailers.

## Where to look

- Surface: `src/commands/registry.ts` (commands, subcommands, flags); help: `src/commands/usage.ts`.
- Engine data at the pinned tag: `docs/data/pkinative/` (never edit).
- Proof of coverage: `scripts/lib/surface.ts` (`RUNTIME_VIA`), `tests/docs/surface.test.ts`, `tests/regression/engine-surface.json`.
- Area rules: `.github/instructions/` — cli-design, commands, testing, security.

## Before you say "done"

`npm run gate:fast` green, then `npm run build` and the change exercised on `node dist/cli.cjs`; for a command change, the sample plan, the help text, the surface map and the docs updated together (AGENTS.md §Architecture).
