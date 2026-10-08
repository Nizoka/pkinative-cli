---
status: accepted
date: 2026-10-04
since: 1.0.0
---

# One runtime dependency, imported through one module

## Context and Problem Statement

pkinative-cli exists to put pkinative on the command line. Every additional runtime package would add supply-chain risk, a second source of PKI behaviour, and a second release cadence to track. And a CLI that imports the engine from many files cannot prove which of the engine's exports it reaches.

## Decision Outcome

- `pkinative` is the only runtime dependency (`npm ls --omit=dev` shows it alone). Everything else the CLI needs comes from Node.js built-ins.
- `src/core-bridge/index.ts` is the only module that imports `pkinative`; ESLint `no-restricted-imports` refuses any other, and `tests/docs/surface.test.ts` checks it from the source.
- The bundle keeps `pkinative` external, so a user's `npm update` adopts the engine's security fixes without a CLI release; `tests/integration/built-binary.test.ts` refuses a bundle that inlines it.
- `scripts/lib/surface.ts` maps each runtime export to the subcommands that reach it; the test refuses an export that is re-exported but used by no command, and an installed engine whose surface differs from the pinned one.

### Consequences

- Good: one dependency to audit; a verifiable claim that the whole engine is reachable.
- Bad: features the engine does not provide (network fetching, key generation) cannot be added by pulling a package; they wait for the engine, or stay out by doctrine ([ADR 0004](0004-offline-and-inherited-refusals.md)).
