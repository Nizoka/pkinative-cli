---
status: accepted
date: 2026-10-04
since: 1.0.0
---

# JSON reports are the engine's results in pkinative's wire form

## Context and Problem Statement

pkinative's results hold `bigint` and `Uint8Array`, which `JSON.stringify` refuses or renders uselessly. pkinative's ADR 0018 reserved a convention for its satellites: `bigint` → decimal string, bytes → lowercase hex, `epochMilliseconds` stays a number, absent optional members omitted, member names unchanged. A CLI could instead invent its own report shapes per command.

## Decision Outcome

- `--json` reports are the engine's result passed through `toWire()` (`src/utils/wire.ts`): the same member names, the same nesting, nothing added. `tests/parity/library.test.ts` holds ten commands to it.
- Where a command must wrap several results (`{ blocks }`, `{ oids }`, `{ valid, reasons }`), the wrapper is documented and the wrapped values keep the wire form.
- Two deliberate exceptions, because the engine objects carry secrets: `key` and `p12` reports are allow-list views ([ADR 0003](0003-secrets-never-on-argv-never-in-output.md)).
- `--summary` and `--fields` shrink a report for token economy; they never rename a member.

### Consequences

- Good: an agent that knows pkinative's TypeScript types knows the CLI's JSON; engine documentation applies unchanged.
- Bad: reports can be large (a certificate carries its DER in hex at several levels); `--summary` and `--fields` are the remedy.
