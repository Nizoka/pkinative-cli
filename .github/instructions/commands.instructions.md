---
description: "Use when adding or changing a pkinative-cli command or subcommand, its flags, its help text, its report rendering or the engine exports it reaches."
applyTo: "src/commands/**,src/core-bridge/**,src/utils/pki-input.ts,src/utils/render.ts,src/utils/spki.ts,src/utils/x509-spec.ts,src/utils/names.ts,scripts/lib/surface.ts"
---
# Commands

## Shape of a command

- `src/commands/<name>.ts` exports one `async (ctx: Ctx) => Promise<void>` that switches on `ctx.command` (`"cert inspect"`).
- Inputs: `readPkiObject` / `readPkiObjects` / `readPkiBundle` (PEM sniffed, DER otherwise, capped by `--max-input-bytes`); content and specs through `readContentBytes` (`--max-content-size`).
- Every engine call goes through `guard('Cannot …', () => …)` with `parseOptions(ctx)` spread into its options: encoding rules, limits, `--strict` and the diagnostic sink. An engine call without `onDiagnostic` would print through pkinative's `console.warn` default.
- Outputs: `emitReport(ctx, engineResult, textRenderer, summary?)` — the JSON is the engine result itself; `emitArtifact(ctx, der, { label, defaultEncoding })`.

## Adding a subcommand

The four steps of AGENTS.md §Architecture, in order (handler, registry, help and `loadCommand`; `RUNTIME_VIA` and `surface:build`; tests, sample and re-pin with a reason; README, knowledge base, `llms.txt` and `verify:docs`); the tests named there fail on a missed step.

## Doctrine inherited from pkinative

- No key generation, no key export, no PKCS#8/#12 writer, no network, no legacy PKCS#12 cipher or MAC, no SHA-1 signature without `--allow-sha1`.
- RSA signing requires `--rsa-scheme`: pkinative has no default RSA scheme (its ADR 0015), and the CLI does not invent one.
- An encrypted key's type comes from the certificate or public key the command has, or `--key-type`; never from guessing by repeated decryption.
- A created certificate, request or signature is verified before it is written: a key that does not match is `E_INPUT`.
