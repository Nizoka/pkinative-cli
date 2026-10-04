---
description: "Use when touching passwords, signing keys, PKCS#12 or key reports, file writes, input bounds, error mapping or anything security-relevant in pkinative-cli."
applyTo: "src/utils/secrets.ts,src/utils/signer.ts,src/utils/key-views.ts,src/utils/io.ts,src/utils/inflight.ts,src/utils/limits.ts,src/utils/pkierr.ts,src/commands/key.ts,src/commands/p12.ts,SECURITY.md,docs/THREAT_MODEL.md"
---
# Security

## Secrets

- Passwords: `--password-file`, `--password-stdin` or `PKINATIVE_PASSWORD`, one source per run; `--password`, `--pass`, `--passin`, `--key-password` are refused before anything runs.
- A password never reaches stdout, stderr, an envelope, an error message or a log. Decryption failures surface as the engine's `PKI_CRYPTO_DECRYPTION_FAILED` (`E_PASSWORD`).
- Key material never leaves pkinative's non-extractable Web Crypto keys. `PrivateKeyInfo.der`, keyBag and secretBag values and `authenticatedSafe` hold plaintext: reports over them are built field by field in `key-views.ts`, and `tests/commands/keys.test.ts` proves no key byte, scalar or JWK form is printed.
- The CLI derives a public key from an unencrypted PKCS#8 with `node:crypto` only to name the subject key of a certificate or request; it never exports a private key.

## Inputs and bounds

- Every PKI read is capped by `--max-input-bytes` (stat before read); content by `--max-content-size`; the 22 pkinative limits are `--max-*` flags; specs are depth-bounded by `maxDepth`.
- Raising a bound is a command-line decision only; a config file cannot.

## Writes

- `writeOutput`: `lstat` then `open(wx)` refuses an existing path, a dangling symlink included (Windows' CREATE_NEW follows one); `--overwrite` writes a temp file then renames; an interrupted write is removed (`inflight.ts`).

## Errors

- `PKI_TO_CLI` is exhaustive by type (`satisfies Record<PkiErrorCode, …>`); filesystem errors become `E_IO` without echoing the OS message.
- The fuzz suite asserts that no input produces `E_RUNTIME`.
