# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).
The `0.0.1` on npm is an empty name reservation, never a release.

## [Unreleased]

## [1.0.0] – 2026-10-04

The first release: the whole of [pkinative 1.0.0](https://github.com/Nizoka/pkinative/releases/tag/v1.0.0) on the command line, offline, under one `--json` contract.

### Added

- **feat(encodings):** `pem` (decode, encode, strict or lax), `oid` (name, encode, decode, validate, list), `fingerprint` (SHA-1/256/384/512, Web Crypto or pure TypeScript, RFC 5280 key identifiers, SHAKE256) and `asn1` (an `asn1parse`-style tree, typed reads at a node path, DER re-encoding, and DER from a JSON node spec).
- **feat(cert):** `cert inspect`, `create` from a JSON spec (verified under its issuer before it is written), `encode` for every X.509 building block, `decode-extension`, `verify-signature`, `check-name`, `match-name` and `check-purpose`; `csr inspect`, `create` and `verify`.
- **feat(chain):** `chain verify` (path building, signatures, RFC 5280 validation, server name, purposes, policy inputs, CRL and OCSP revocation in one verdict), `chain build` and `chain validate`.
- **feat(revocation):** `crl inspect`, `find`, `verify-signature` and `check` (with a delta CRL); `ocsp request`, `cert-id`, `inspect`, `verify-signature` and `check` (CA or authorised delegate).
- **feat(signatures):** `cms sign` (attached, detached or from a digest; ESS signing-certificate-v2 and algorithm protection), `verify`, `inspect`, `verify-signer`, `add-attribute` and `add-timestamp`; `tsp request`, `inspect` and `verify`.
- **feat(keys):** `key inspect` and `check` for PKCS#8, encrypted or not; `p12 inspect`, `verify-mac`, `bags` and `open` (PBES2 and PBMAC1). Signers come from `--key` or `--p12`; the algorithm follows the key, and RSA needs `--rsa-scheme pkcs1|pss`.
- **feat(meta):** `doctor` (Node.js security floor, engine, Web Crypto capabilities), `limits` (the 22 bounds and their `--max-*` flags), `explain` (13 `E_*` classes, 57 `PKI_*` codes, 43 reasons, 97 diagnostics), `schema` (manifest, catalogues and JSON Schemas, draft 2020-12, including the `--json` report and `--summary` shape of every invocation, generated from the types and held to every sample) and `completion` (bash, zsh, fish, PowerShell: commands and subcommands after global flags, flags, the values of enumerated flags such as `--format text|json` under every spelling (`-f`), paths after a file flag (PowerShell included) and the shell names after `completion`; the `completion` sample re-pinned for it).
- **feat(core):** the process contract — the artefact or report on stdout, one JSON envelope on stderr under `--json`, exit 0/1/2 and 130/143 on a signal; pkinative's `PKI_*` code carried verbatim beside the CLI class; reports in pkinative's ADR 0018 wire form; `--fields`, `--summary` and `--pretty`; `.pkinativerc.json` presentation defaults.

### Security

- **feat(security):** passwords come from `--password-file`, `--password-stdin` or `PKINATIVE_PASSWORD` only; `--password` and its aliases are refused before any command runs (CWE-214).
- **feat(security):** key and PKCS#12 reports are built from an allow-list; no report contains a private key byte, and signing keys are imported non-extractable (CWE-312).
- **feat(security):** outputs are created exclusively and refuse a symbolic link as the output path; `--overwrite` replaces atomically; a file being written is removed on SIGINT or SIGTERM (CWE-59, CWE-367).
- **feat(security):** every pkinative bound is reachable through a `--max-*` flag and every input is capped before it is read (CWE-400, CWE-770).
- **feat(security):** the parser enforces the registry: an alias is its flag (`-i` obeys every rule of `--input`, `-f` and `-q` beat a config file), and a single-value flag given twice, a switch given twice, a flag under both its names, a surplus argument, an argument beside `--input` or `--path` (or a code beside `explain --list`), `--password-stdin=<value>` and a date that does not exist are `E_USAGE` (never echoed), so no verdict depends on the order or the spelling of the flags; a password is never read from stdin when an input is.
- **fix(p12):** `p12 open --certs-out` writes nothing from a file that did not open; `p12 verify-mac` on a file without a MAC is a verdict (exit 1) that asks for no password, not a usage error; a wrong password is `E_PASSWORD` with the same remedy in every `p12` subcommand; a token typed after `--password-stdin` is never echoed, and `-o -` beside `--password-stdin` is stdout, not a second reader of stdin; legacy PKCS#12 is `E_SECURITY` everywhere with the two-step OpenSSL conversion as `remedy`; a `--p12` signer obeys the same `--rsa-scheme`, `--salt-length` and `--hash` rules as `--key`, and passes `--salt-length` through.
- **fix(cert):** `cert create`, `csr create` and `cert encode` specs are closed objects, as `schema cert-spec` and `cert-encode-spec` declare them: an unknown member, a non-boolean `critical` and a malformed instant are `E_INPUT`; `cert encode extensions` refuses `"subjectKeyIdentifier": true`, which has no key to hash; `cert encode signature-algorithm` refuses `--spec`.
- **fix(errors):** remedies name CLI flags only (`--allow-unverified-integrity`, `--allow-trailing`, `--max-<limit>` for `PKI_LIMIT_EXCEEDED`) and the command that failed; a legacy-encrypted PKCS#8 key gets the `openssl pkcs8 -topk8 -v2 aes-256-cbc` re-encryption, a legacy PKCS#12 the two-step conversion; `detail.limit` names every bound as `pkinative limits` does, with `detail.flag` beside it; `chain` envelopes carry `signaturesChecked`; `chain verify --ocsp-nonce` takes 1–32 octets like `ocsp`; `ocsp` nonces are bounded to 1–32 octets (RFC 8954) with their own message; a fixed cap (the 64 KiB password) offers no fake flag; inputs are read only from regular files, bounded through the descriptor, and read to the end when one call returns less.
- **feat(security):** `.pkinativerc.json` is presentation only: an allow-list of nine keys, every other key, a value of the wrong type and a section that names no subcommand refused, so a file planted in a repository can never change an input, a trust anchor, the validation time, a tolerance, a bound or where output is written — it may choose a report format or an artefact encoding, and `strict` only tightens; the applied file is named in the envelope ([ADR 0007](docs/adr/0007-configuration-is-presentation-only.md); CWE-15, CWE-807).
- **feat(security):** no network access, no key generation, no PKCS#8 or PKCS#12 writer, no legacy PKCS#12 scheme and no default RSA scheme — the engine's refusals, kept ([ADR 0004](docs/adr/0004-offline-and-inherited-refusals.md)).

### Tests and conformance

- **test(surface):** each of pkinative's 294 exports is traced to the command that reaches it (`docs/data/core-exports.json`); each of the 55 bullets of the engine's 1.0.0 CHANGELOG is mapped to a test or a typed waiver (`tests/regression/engine-surface.json`).
- **test(proofs):** library parity for the JSON reports, the built binary driven end to end, seeded fuzzing of argv and hostile inputs, and OpenSSL 3 reading and verifying what the CLI writes.
- **test(lint):** zlint v3.7.2 and DigiCert pkilint lint every certificate `cert create` writes — CA and leaf, ECDSA, RSA PKCS#1, RSA-PSS and Ed25519 — with no error and every warning reviewed (`scripts/data/lint-waivers.json`); required by `conformance.yml` and the publish gate.
- **test(mutation):** `npm run mutate` (ported from pkinative) mutates every module of `src/` and requires each mutant killed or argued equivalent in `scripts/data/mutation-equivalents.json`.
- **test(regression):** one pinned sample per subcommand (`doctor` excepted: it reports on the host), run against the built CLI (`samples/`, `.sh` and `.ps1`).
- 100 % statement, branch, function and line coverage.

### Documentation

- **docs:** README, `docs/KNOWLEDGE_BASE.md`, `docs/AGENT_CONTRACT.md`, `docs/THREAT_MODEL.md`, six ADRs, `SECURITY.md` with the release verification commands, and the agent layer (`AGENTS.md`, `.github/instructions/`, `.claude/`).

[Unreleased]: https://github.com/Nizoka/pkinative-cli/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Nizoka/pkinative-cli/releases/tag/v1.0.0
