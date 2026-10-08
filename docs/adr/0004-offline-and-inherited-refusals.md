---
status: accepted
date: 2026-10-04
since: 1.0.0
---

# Offline, and pkinative's refusals are the CLI's

## Context and Problem Statement

Sibling CLIs fetch OCSP answers and time-stamps behind opt-in flags. pkinative does no I/O at all (its ADR 0006) and refuses several capabilities by doctrine: key generation, PKCS#8/#12 writing, legacy PKCS#12 ciphers and MACs, a default RSA scheme, SHA-1 without consent. A CLI could fill those gaps with `node:crypto` or `fetch`.

## Decision Outcome

- **No network in 1.0.** The CLI writes OCSP and time-stamp requests and judges the answers the caller fetched. No SSRF guard is needed because no request is ever made.
- **No capability the engine refuses.** No key generation, no key or PKCS#12 writer, no RC2/3DES or Appendix B MAC, no default RSA scheme (`--rsa-scheme` is required), no SHA-1 signature without `--allow-sha1`.
- **No relaxation from configuration.** `--allow-*`, `--max-*`, `--ber`, `--pem-mode`, `--overwrite` and passwords are command-line only.
- **Host primitives, never a PKI decision.** `node:crypto` is used for exactly five things: deriving the SPKI of an *unencrypted* PKCS#8 the user supplied, to name the subject key of a certificate or request (the engine never exports a key, and the user already holds both halves); and the CSPRNG (`webcrypto.getRandomValues`, `randomBytes`) for the serial number `cert create` draws when the spec names none, the nonce of an OCSP or time-stamp request, and the suffix of the temporary file behind `--overwrite`. `node:net` supplies `isIPv4`/`isIPv6` for name parsing. The CLI keeps two tables of its own — the SPKI algorithm and curve OIDs in `src/utils/spki.ts`, the RFC 4514 short names in `src/utils/names.ts` — to classify a structure and present a name; they decide nothing the engine decides, and they go the day the engine exports the same.

### Consequences

- Good: verdicts are reproducible offline; the security surface is the file system only.
- Bad: users fetch revocation evidence themselves. This is permanent (ROADMAP.md §Never): a verdict the CLI prints is always a function of the files it was given.
