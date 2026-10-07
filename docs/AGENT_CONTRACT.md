# Agent contract

How a program — a CI step, a script, an AI agent — drives pkinative-cli. Everything here is stable across 1.x; fields are only ever added.
Machine forms: `pkinative schema manifest`, `pkinative schema status`, `pkinative schema error`, `pkinative schema errors`, and for every invocation `pkinative schema report <command> [<subcommand>]` and `pkinative schema summary …`.

## 1. Streams and exit codes

| Channel | Carries |
|---|---|
| stdout | The artefact (PEM, DER, hex) or the report (text, or JSON with `--json`) — nothing else, ever |
| stderr | Diagnostics, notes, and under `--json` exactly one JSON envelope as the last line |
| exit | `0` success · `1` any failure but usage · `2` usage error · `130`/`143` interrupted |

A negative verdict (`chain verify`, `cms verify`, `ocsp check`, …) prints its full report on stdout **and** exits 1 with an envelope: read both.

## 2. Envelopes (stderr, `--json` or `PKINATIVE_JSON=1`)

Success:

```json
{"ok":true,"command":"cert create","serialNumber":"5a","selfSigned":true,"bytes":433,"encoding":"pem","diagnostics":[]}
```

Failure:

```json
{"ok":false,"command":"chain verify","error":{"code":"E_VERIFY_FAILED","message":"…","reasons":[{"code":"PKI_REASON_REVOKED","path":"crl", "…":"…"}]},"diagnostics":[]}
```

| Field | Present | Meaning |
|---|---|---|
| `error.code` | always | One of the 13 classes below — branch on this |
| `error.pkiCode` | engine failures | pkinative's frozen `PKI_*` code, verbatim — the exact cause |
| `error.detail` | when known | `limit`/`flag`/`configured`/`observed`, `offset`, `path`, `algorithm` |
| `error.remedy` | when a flag lifts it | The CLI flag(s) that change the outcome, e.g. `--allow-sha1`, `--ber`, `--max-depth <value>` |
| `error.reasons` | negative verdicts | The engine's `PkiReason` list in the wire form |
| `diagnostics` | always | Every `PkiDiagnostic` the engine emitted: `{ code, severity, message, standard, path, offset? }` |
| `config` | a config file supplied defaults | The `.pkinativerc.json` that did; it can only set presentation keys (ADR 0007) |

Command-specific success fields (`valid`, `pathLength`, `output`, `bytes` — the DER length of an artefact, `encoding`, `nonce`, `count`, `dryRun`, …) are listed, with their JSON Schemas, by `pkinative schema manifest` under each invocation's `status`. The stdout report of every invocation is described by `pkinative schema report <command> [<subcommand>]`, its `--summary` shape by `pkinative schema summary …`; both are generated from the TypeScript types and held to every sample, and objects are open (fields are only ever added).

## 3. Error classes

| Class | Exit | When |
|---|---|---|
| `E_USAGE` | 2 | Missing, unknown or invalid flag, argument or option — including a single-value flag given twice, a surplus argument, an argument beside the flag it stands for, and a date that does not exist; also an engine `PKI_API_MISUSE` / `PKI_INVALID_OPTION` |
| `E_INPUT` | 1 | A spec, label or value is unacceptable; a key does not belong to its certificate |
| `E_PARSE` | 1 | The bytes are not the DER, PEM or JSON they claim to be |
| `E_IO` | 1 | Filesystem failure, including a refused overwrite (`remedy: --overwrite`) |
| `E_SECURITY` | 1 | A policy refusal: SHA-1, a legacy PKCS#12 cipher or MAC |
| `E_LIMIT` | 1 | A bound was exceeded: `detail.limit` names it as `pkinative limits` does (`maxDepth`, `maxInputBytes`, `maxContentSize`; `fixed` for a cap no flag lifts), `detail.flag` and `remedy` name the flag that raises it |
| `E_UNSUPPORTED` | 1 | Algorithm, key or structure not supported |
| `E_CRYPTO` | 1 | Web Crypto could not run the operation |
| `E_PASSWORD` | 1 | Wrong password, or a MAC that does not match it |
| `E_NOT_FOUND` | 1 | A named item is absent (extension, block, signer, code) |
| `E_VERIFY_FAILED` | 1 | A signature, chain, request, time-stamp or MAC verdict is negative |
| `E_CHECK_FAILED` | 1 | A check returned reasons, or `--strict` escalated a warning |
| `E_RUNTIME` | 1 | Anything else; the fuzz suite holds that no input reaches it |

`pkinative explain <code>` explains any class or engine code; `pkinative schema errors` gives the whole 57 → 13 mapping.

## 4. The wire form

JSON reports are the engine's own results under pkinative's ADR 0018 convention ([ADR 0002](adr/0002-json-wire-form.md)): `bigint` → decimal string, `Uint8Array` → lowercase hex, `epochMilliseconds` stays a number, absent optional members are omitted, member names are unchanged.
The CLI adds nothing to an engine result except where it is a CLI view: `key` and `p12` reports are allow-list views that never carry key bytes, and command-level wrappers (`{ blocks }`, `{ oids }`, `{ valid, reasons }`) are documented per command.

## 5. Token economy

| Flag | Effect |
|---|---|
| `--summary` | The command's minimal JSON shape (codes instead of full reasons, names instead of objects) |
| `--fields a,b.c` | Keep only these dot-paths; a segment on an array maps over it; unknown paths are omitted |
| (default under `--json`) | Compact JSON, no indentation; `--pretty` indents |
| `--quiet` | No text notes or diagnostics on stderr (the envelope still carries diagnostics) |

## 6. Inputs an agent should know

- Time: `--at <ISO 8601 | epoch ms | now>`, UTC unless zoned. Pin it for reproducible verdicts.
- Secrets: `PKINATIVE_PASSWORD`, `--password-file` or `--password-stdin` — never a flag value (refused, exit 2).
- `--dry-run` validates every input and writes nothing.
- `--help` is text for people, whatever `--json` says; the machine form of every command, flag and operand is `pkinative schema manifest`.
- Each flag is given once unless the manifest marks it `repeatable`; a subcommand takes at most `operands.max` positional arguments. Anything else is exit 2, so a verdict never depends on argument order.
- Specs (`cert create`, `csr create`, `asn1 encode`, `cert encode`) are JSON files or stdin (`-`); their schemas: `pkinative schema cert-spec | csr-spec | asn1-spec | cert-encode-spec` (one `$defs` entry per `cert encode` structure).

## 7. Recommended loop

1. `pkinative doctor --json` once per environment.
2. Run the command with `--json` (and `--summary` when only the verdict matters).
3. Exit 0: use stdout. Exit 1: read `error.code`, then `error.pkiCode` and `error.reasons`; `error.remedy` names the flag that would change the outcome — apply it only when the input is trusted and the policy allows it.
4. Exit 2: fix the invocation (`pkinative <command> --help`); never retry unchanged.

## 8. Governance

An agent working **on** this repository follows [AGENTS.md](https://github.com/Nizoka/pkinative-cli/blob/main/AGENTS.md) and [.github/AGENT_RULES.md](https://github.com/Nizoka/pkinative-cli/blob/main/.github/AGENT_RULES.md): it drafts and verifies; the maintainer pushes, tags and publishes.
