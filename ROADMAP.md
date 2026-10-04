# Roadmap

pkinative-cli follows its engine. A pkinative minor that adds exports, codes or diagnostics is adopted by a CLI minor that reaches them ([CONTRIBUTING.md §Bumping the engine](CONTRIBUTING.md#bumping-the-engine)); the CLI does not grow capabilities the engine does not have.

## 1.0.0 — the whole engine, offline *(released)*

- [x] Every runtime export of pkinative 1.0.0 reached by a command, proven by the surface matrix
- [x] The process contract: stdout artefact, stderr envelope, exit 0/1/2, 130/143
- [x] Secrets never on argv and never in output
- [x] Samples per subcommand, library parity, seeded fuzzing, OpenSSL interop
- [x] Publication from CI only: Trusted Publishing, provenance, SBOMs, Sigstore attestation

## 1.0.x — maintenance

- [ ] Make the Node.js 26 run blocking once Node.js 26 is LTS (2026-10-28)
- [ ] Port pkinative's mutation testing (`scripts/mutate.ts`) as a pre-release step
- [ ] Linters on the certificates the CLI creates (`zlint`, `pkilint`) in `conformance.yml`

## Later, each behind its own ADR

- An opt-in network layer (fetching OCSP answers, CRLs and time-stamps) with an SSRF guard, as the sibling CLIs have. 1.0 is offline by decision ([ADR 0004](docs/adr/0004-offline-and-inherited-refusals.md)); a network layer must keep `--json` verdicts reproducible.
- Anything pkinative adds in its own minors.

## Never

What the engine refuses by doctrine stays refused here: key generation, a PKCS#8 or PKCS#12 writer, legacy PKCS#12 ciphers and MACs, a default RSA scheme, and a secret on the command line.
