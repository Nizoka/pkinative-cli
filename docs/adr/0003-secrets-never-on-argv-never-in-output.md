---
status: accepted
date: 2026-10-04
since: 1.0.0
---

# Secrets never on argv, never in output

## Context and Problem Statement

Commands that sign or open PKCS#8 and PKCS#12 need passwords and hold private keys. argv is readable by other local users and lands in shell history. Several engine objects carry plaintext key bytes: `PrivateKeyInfo.der`, PKCS#12 keyBag and secretBag values, and the authenticated safe of an unencrypted PKCS#12. Serialising them, as [ADR 0002](0002-json-wire-form.md) does for every other result, would print private keys.

## Decision Outcome

- Passwords come from `--password-file`, `--password-stdin` or `PKINATIVE_PASSWORD`; `--password`, `--pass`, `--passin` and `--key-password` are refused with exit 2 before any command runs.
- `key` and `p12` reports are built field by field from an allow-list (`src/utils/key-views.ts`); signing keys are described (algorithm, type, `extractable: false`, usages), never exported.
- `tests/commands/keys.test.ts` runs every `p12` reader over a PKCS#12 holding an unencrypted keyBag, in text and JSON, and asserts that neither the PKCS#8 bytes, the private scalar (hex, base64) nor its JWK form appears in stdout or stderr.

### Consequences

- Good: a log of a CLI run can be shared; an agent transcript never holds a key.
- Bad: `p12 bags` cannot extract a key; that would be a writer, which the engine refuses by doctrine (its ADR 0003).
