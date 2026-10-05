# Security Policy

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Report it through [GitHub private vulnerability reporting](https://github.com/Nizoka/pkinative-cli/security/advisories/new).
Acknowledgement within 48 hours; a fix for a critical issue is the priority of the next release. A vulnerability in PKI *logic* (parsing, path validation, signatures, revocation, PKCS#12) belongs to the engine: report it at [pkinative](https://github.com/Nizoka/pkinative/security/advisories/new); we will coordinate.

[`docs/.well-known/security.txt`](docs/.well-known/security.txt) (RFC 9116) carries the same contact.

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | ✅ |
| < 1.0 | ❌ (never published) |

## Security model

pkinative-cli is a thin front end over [pkinative](https://github.com/Nizoka/pkinative). Every cryptographic decision is the engine's; see [its security policy](https://github.com/Nizoka/pkinative/blob/main/SECURITY.md).
The CLI's own attack surface is the boundary between the operating system and the engine: argv, files, stdin, environment variables, configuration, output files and process signals.
The threat model is [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

### Offline, always

No module of `src/` imports a network API. The CLI never fetches a CRL, an OCSP response, a time-stamp, an intermediate or an AIA URL: revocation evidence and time-stamps are files the caller supplies, and requests (`ocsp request`, `tsp request`) are files the caller sends.
There is therefore no SSRF surface, no DNS dependency, and no verdict that changes with the network.

### Secrets

- **No password on argv.** `--password`, `--pass`, `--passin` and `--key-password` are refused (exit 2) before any command runs: argv is readable by other users (`ps`, `/proc/<pid>/cmdline`) and lands in shell history.
  The sources are `--password-file <file>` (first line), `--password-stdin`, and `PKINATIVE_PASSWORD`; giving two is a usage error.
- **No key byte in any output.** Private keys are imported by pkinative into non-extractable Web Crypto keys. `key` and `p12` reports are built field by field from an allow-list (`src/utils/key-views.ts`) instead of serialising the engine objects, because `PrivateKeyInfo.der`, PKCS#12 keyBag and secretBag values and the authenticated safe hold plaintext.
  A test over a PKCS#12 holding an *unencrypted* keyBag proves that no key byte, scalar or JWK form reaches stdout or stderr in any mode.
- The CLI derives a public key from an unencrypted PKCS#8 with `node:crypto` only to name the subject key of a certificate or request; it never exports a private key and has no key-writing command.
- Passwords never appear in messages, envelopes or diagnostics; a wrong password is `E_PASSWORD` with the engine's fixed message.

### Inputs

- Every PKI read is bounded by `--max-input-bytes` (pkinative's `maxInputBytes`, 64 MiB) **before** the file is read (`stat`), and stdin is counted as it streams. Content to sign or time-stamp and JSON specs are bounded by `--max-content-size` (1 GiB).
- The 22 bounds of pkinative's `DEFAULT_PKI_LIMITS` (depth, nodes, chain length, KDF iterations, PKCS#12 bags, …) are flags; each is a positive integer, there is no "unbounded".
- JSON specs are depth-bounded by `maxDepth`; flag names `__proto__`, `constructor` and `prototype` are refused, and parsed flags live in a null-prototype record.
- Unknown flags are refused, so a misspelt security flag (`--alow-sha1`) is an error, not a silent no-op.

### Configuration cannot relax a check

`.pkinativerc.json` (found by walking up from the working directory) is presentation only ([ADR 0007](docs/adr/0007-configuration-is-presentation-only.md)): it may set `json`, `pretty`, `quiet`, `no-color`, `format`, `encoding`, `fields`, `summary` and `strict`, and nothing else.
Any other key — an input, a trust anchor, the validation time, a tolerance, a `--no-*` or `--*-trusted` switch, a bound, an output path, a password source, and every flag added later — makes the command fail with `E_USAGE`:
a configuration file planted in a cloned repository must never change what a command reads, trusts, when it judges, or where it writes. The file that supplied defaults is named in the `--json` envelope (`config`) and in a note on stderr.

### Writes

- Without `--overwrite`, an output is created exclusively: `lstat` refuses any existing path — a dangling symlink included, which Windows' `CREATE_NEW` would otherwise follow — and `open(wx)` closes the race on POSIX.
- With `--overwrite`, the bytes go to a temporary file in the same directory, then `rename` replaces the target in one step: a reader never sees half a file, and a symlink at the target is replaced, not followed.
- A file being written when SIGINT or SIGTERM arrives is removed; the process exits 130 or 143. A closed pipe (EPIPE) ends the process quietly with exit 0.

### Refusals inherited from the engine

The CLI never lifts what pkinative refuses by doctrine: no SHA-1 signature made or accepted without `--allow-sha1`; no RC2/3DES PKCS#12 and no RFC 7292 Appendix B MAC (`E_SECURITY`, with the two-step OpenSSL conversion as `remedy`, no flag lifts it);
no default RSA signature scheme (`--rsa-scheme` is required); no key generation; no PKCS#8 or PKCS#12 writer. A created certificate, request or SignedData is verified before it is written, so a key that does not belong to its certificate is refused.

### Code safety

TypeScript strict (`noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`), type-aware ESLint, no `eval`, no dynamic code loading, no `console.*` in `src/`, one runtime dependency imported through one module.
Coverage is 100 % on statements, branches, functions and lines; a seeded fuzz suite holds that no argv or input yields an unmapped failure (`E_RUNTIME`).

### Node.js floor

`engines.node` is `^22.22.2 || ^24.14.1 || >=25.8.2`, the first releases that fix CVE-2026-21713 (a variable-time comparison of PKCS#12 MACs in Web Crypto). `pkinative doctor` reports a runtime below it.

## Release integrity

Releases are published only by `.github/workflows/publish.yml`, on a published GitHub Release, in four jobs:

1. **guard** — the tag must equal `package.json`'s version; no token.
2. **build** — the full publish gate (`--publish --require-all`, OpenSSL interop required), `npm pack` once, SHA-256 and SHA-512 of the tarball passed on; no `id-token`.
3. **publish** — in the `npm-publish` environment (a maintainer approves), the tarball's digests re-checked, an npm client pinned by its integrity, `npm publish --provenance` through npm Trusted Publishing (OIDC, no stored token).
4. **attest** — the tarball re-downloaded from the registry and compared, `npm audit signatures`, CycloneDX and SPDX SBOMs, a Sigstore build-provenance attestation, all attached to the GitHub Release.

Every action is pinned by commit SHA, every job starts with harden-runner, checkouts never persist credentials, and `npm ci --ignore-scripts` is the only install.

To verify an installed release:

```sh
npm view pkinative-cli@1.0.0 dist.integrity
npm audit signatures            # in a project that installed it
gh attestation verify pkinative-cli-1.0.0.tgz --repo Nizoka/pkinative-cli
```

## Disclosure

We follow coordinated disclosure: a fix is released before the advisory is published, and the reporter is credited unless they ask otherwise.
