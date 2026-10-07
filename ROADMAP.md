# Roadmap

pkinative-cli follows its engine. A pkinative minor that adds exports, codes or diagnostics is adopted by a CLI minor that reaches them ([CONTRIBUTING.md §Bumping the engine](CONTRIBUTING.md#bumping-the-engine)); the CLI does not grow capabilities the engine does not have.

## 1.0.0 — the whole engine, offline

- [x] Every runtime export of pkinative 1.0.0 reached by a command, proven by the surface matrix, each `via` held to the command's code
- [x] The process contract: stdout artefact, stderr envelope, exit 0/1/2, 130/143; the registry enforced (single values, operands)
- [x] A JSON Schema, generated from the types and held to every sample, for every report, `--summary` shape and envelope field
- [x] Secrets never on argv and never in output; the configuration file presentation only ([ADR 0007](docs/adr/0007-configuration-is-presentation-only.md))
- [x] Samples per subcommand, library parity, seeded fuzzing, OpenSSL interop, linted certificates (zlint, pkilint), mutation testing
- [x] Completion for bash, zsh, fish and PowerShell, values included
- [x] Publication from CI only: Trusted Publishing, provenance, SBOMs, Sigstore attestation

## 1.0.x — maintenance

- [ ] Make the Node.js 26 run blocking once Node.js 26 is LTS (2026-10-28)
- [ ] Attach a `SHA256SUMS` file to each GitHub Release (`publish.yml`, after its first run)

## Later, each behind its own ADR

- Anything pkinative adds in its own minors.
- Coverage-guided fuzzing of the CLI's own parsers, should they grow ([ADR 0006](docs/adr/0006-seeded-fuzzing-not-coverage-guided.md)).
- SLSA Build Level 3: the build and its provenance moved to a trusted reusable builder the project's own workflow cannot influence ([ADR 0005](docs/adr/0005-release-integrity.md) stops at Level 2).

## Never

What the engine refuses by doctrine stays refused here: key generation, a PKCS#8 or PKCS#12 writer, legacy PKCS#12 ciphers and MACs, a default RSA scheme, and a secret on the command line.
And no network: the CLI judges the evidence it is given and never fetches it ([ADR 0004](docs/adr/0004-offline-and-inherited-refusals.md)).
