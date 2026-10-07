# Architecture decision records

One file per decision, numbered without gaps, each opening with a `status` (`proposed`, `accepted`, `superseded`, `deprecated`), the date and the version it applies from (`npm run verify:docs`, rule `adr`). A decision is amended by a new ADR that supersedes it, never by rewriting history. The engine's own decisions live in [pkinative's ADRs](https://github.com/Nizoka/pkinative/tree/main/docs/adr); where a CLI decision rests on one, it says so.

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-one-runtime-dependency-one-bridge.md) | One runtime dependency, imported through one module | accepted |
| [0002](0002-json-wire-form.md) | JSON reports are the engine's results in pkinative's wire form | accepted |
| [0003](0003-secrets-never-on-argv-never-in-output.md) | Secrets never on argv, never in output | accepted |
| [0004](0004-offline-and-inherited-refusals.md) | Offline, and pkinative's refusals are the CLI's | accepted |
| [0005](0005-release-integrity.md) | Release integrity: the bytes that passed the gate are the bytes published | accepted |
| [0006](0006-seeded-fuzzing-not-coverage-guided.md) | Seeded fuzzing at the CLI boundary; coverage-guided fuzzing stays in the engine | accepted |
| [0007](0007-configuration-is-presentation-only.md) | The configuration file is presentation only | accepted |
