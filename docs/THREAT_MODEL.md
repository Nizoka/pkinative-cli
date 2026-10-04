# Threat model

Scope: the boundary pkinative-cli adds around the pkinative engine — argv, environment, files, stdin, configuration, outputs, process signals and the build that ships it.
The engine's own threat model (parsers, path validation, cryptography) is pkinative's; this document cites it where the CLI depends on it.

## Assets

| Asset | Why it matters |
|---|---|
| Private keys and passwords | Disclosure lets an attacker sign as the user |
| Verdicts (`valid`, reasons, exit code) | A wrong "valid" makes a pipeline trust a forged or revoked object |
| Output files | Overwriting or redirecting them can destroy data or plant artefacts |
| The published package | A compromised tarball runs on every user's machine |

## Actors

- **The user**, who runs the CLI with their own authority over their filesystem.
- **A hostile input author**, who controls a certificate, CRL, OCSP response, CMS message, PKCS#12 file, JSON spec or PEM text the user processes.
- **A hostile repository**, which a user clones and in which they run the CLI (a planted `.pkinativerc.json`, planted symlinks).
- **A local observer**, another user of the machine who can list processes.
- **A supply-chain attacker**, who targets dependencies, CI or the registry.

## STRIDE

| Threat | Vector | Control | Verified by |
|---|---|---|---|
| **S**poofing a signer | Forged certificate, CMS or time-stamp | Every verdict is the engine's (path, signature, revocation, purposes); the CLI never short-circuits one | `tests/parity/library.test.ts`, engine conformance |
| Spoofing an OCSP responder | Response signed by an unauthorised key | RFC 6960 §4.2.2.2 authorisation: the CA or a delegate it issued with OCSPSigning, unless `--responder-trusted` | `tests/commands/revocation.test.ts` |
| **T**ampering with a verdict via config | Planted `.pkinativerc.json` setting `allow-sha1`, a raised `max-*`, `ber`, `pem-mode`, `overwrite` | Those keys are refused in any config file | `tests/utils/config.test.ts` |
| Tampering by typo | `--alow-sha1` silently ignored | Unknown flags are usage errors | `tests/utils/args.test.ts`, `tests/cli.test.ts` |
| Tampering with outputs | Existing file, planted (dangling) symlink at `-o` | `lstat` + `open(wx)`; `--overwrite` = temp + rename (replaces the link) | `tests/utils/io.test.ts` |
| **R**epudiation | A pipeline cannot tell why a verdict failed | Stable `E_*` class, engine `pkiCode`, full `reasons`, diagnostics in the envelope | `tests/utils/output.test.ts`, `docs/AGENT_CONTRACT.md` |
| **I**nformation disclosure: passwords | `--password x` visible in `ps` and history | Literal password flags refused; file, stdin or environment only | `tests/utils/misc.test.ts`, built-binary refusal posture |
| Information disclosure: keys | A report serialising `PrivateKeyInfo.der` or a keyBag | Allow-list views in `key-views.ts` | `tests/commands/keys.test.ts` ("never prints a key byte") |
| Information disclosure: engine defaults | pkinative's `console.warn` diagnostic sink | Every engine call receives the CLI's `onDiagnostic` | Code review rule (`commands.instructions.md`), fuzz stderr checks |
| **D**enial of service | Oversized input, deep nesting, KDF iteration bombs, huge CRLs | `--max-input-bytes` before reading; the 22 engine limits; `maxDepth` on specs; `maxPkcs12KdfIterations` | `tests/utils/pki-input.test.ts`, `tests/commands/keys.test.ts`, fuzz suite |
| Denial of service: hangs | Waiting on an interactive stdin | Refused with a usage error unless `-` is explicit | `tests/utils/io.test.ts` |
| **E**levation via network | SSRF through an AIA, CRL DP or TSA URL | No network code exists | `src/` imports (`tests/docs/surface.test.ts` bridge rule), review |
| Elevation via code loading | A config or spec that loads code | No plugin, codec or `eval`; specs are data | ESLint `no-eval`, `no-new-func` |
| Supply chain | Malicious dependency or build | One runtime dependency; `ignore-scripts`; SHA-pinned actions; four-job publish with provenance, SBOMs and Sigstore attestation | `.github/workflows/`, `tests/integration/built-binary.test.ts` (engine kept external) |

## Residual risks

- **Engine defects.** A wrong verdict inside pkinative is a wrong verdict of the CLI. Mitigation: the CLI pins `^1.0.0`, inherits security fixes in minors, and tests the engine surface it adopts.
- **Trust anchors are the user's.** The CLI has no built-in trust store; a pipeline that passes a hostile `--trust` file trusts it.
- **Revocation freshness is the caller's.** Stale CRLs and OCSP answers are refused per their `nextUpdate`, but fetching fresh ones is outside the CLI by design.
- **The host.** A compromised Node.js runtime or Web Crypto implementation defeats every control; `pkinative doctor` checks the Node.js security floor only.
