---
status: accepted
date: 2026-10-04
since: 1.0.0
---

# Seeded fuzzing at the CLI boundary; coverage-guided fuzzing stays in the engine

## Context and Problem Statement

pkinative fuzzes its parsers with ClusterFuzzLite and Jazzer.js over eight targets. The CLI adds no parser of its own beyond argv, PEM sniffing, JSON specs and its configuration file; everything else is the engine's.

## Decision Outcome

- `tests/fuzz/fuzz.test.ts` runs seeded campaigns at the CLI boundary: 400 random argv over the whole surface, and mutated inputs (bit flips, truncation, length damage, insertion, noise) through eleven readers and two verdicts. The invariant is the process contract: exit 0, 1 or 2 and a stable `E_*` class, never `E_RUNTIME`.
- Seeds are fixed, so every failure reproduces; the campaign runs in every gate.
- Coverage-guided fuzzing of DER and PEM is not duplicated: it targets code that lives in pkinative and is fuzzed there with the engine pinned.

### Consequences

- Good: the CLI's own mapping and I/O layers are exercised on hostile input on every commit, at no infrastructure cost.
- Bad: a coverage-guided campaign would explore the argv and spec parsers more deeply; revisit if the CLI grows a parser of its own.
