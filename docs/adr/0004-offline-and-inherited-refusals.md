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
- One narrow use of `node:crypto` is accepted: deriving the SPKI of an *unencrypted* PKCS#8 the user supplied, to name the subject key of a certificate or request (the engine never exports a key, and the user already holds both halves).

### Consequences

- Good: verdicts are reproducible offline; the security surface is the file system only.
- Bad: users fetch revocation evidence themselves; a future opt-in network layer would need its own ADR and guard.
