# pkinative-cli

The official command line for [pkinative](https://github.com/Nizoka/pkinative), the zero-dependency PKI engine.
Inspect and verify X.509 certificates, requests, CRLs, OCSP responses, CMS signatures and RFC 3161 time-stamps;
build and validate certification paths; issue certificates and requests; sign CMS; open PKCS#8 and PKCS#12;
decode and encode ASN.1, PEM and OIDs — offline, with a stable `--json` contract for scripts and AI agents.

- **The whole engine.** 18 commands reach every one of pkinative 1.0.0's 294 exports, and a test proves it ([`docs/data/core-exports.json`](docs/data/core-exports.json)).
- **One runtime dependency:** `pkinative`. No network, ever.
- **Agent-first.** stdout carries the artefact or the report, stderr one JSON envelope with a stable `E_*` class and pkinative's `PKI_*` code verbatim; exit 0/1/2.
- **Secure by default.** Passwords never on the command line; no `key` or `p12` report prints key material; SHA-1 and lifted bounds only on an explicit command-line flag, legacy PKCS#12 never; a config file sets presentation only.
- **Proven.** 100 % coverage on four axes, a seeded fuzz suite, CLI ⇔ library parity tests, pinned samples per subcommand, and OpenSSL verifying what the CLI writes.

## Installation

```sh
npm install --global pkinative-cli
pkinative doctor
```

Node.js `^22.22.2 || ^24.14.1 || >=25.8.2` — the first releases that fix CVE-2026-21713 (a variable-time PKCS#12 MAC comparison in Web Crypto). `pkinative doctor` checks it.

## Quick start

```sh
# What is this certificate?
pkinative cert inspect server.pem

# Is it valid for this host, now, with revocation?
pkinative chain verify server.pem --untrusted intermediate.pem --trust root.pem \
  --host www.example.com --crl ca.crl --require-revocation

# Issue a self-signed CA, then a leaf under it
pkinative cert create --spec ca.json --key ca.key -o ca.pem
pkinative cert create --spec leaf.json --key ca.key --issuer ca.pem --public-key leaf.csr -o leaf.pem

# Sign and verify a file
pkinative cms sign --content report.pdf --cert signer.pem --key signer.key --detached -o report.p7s
pkinative cms verify report.p7s --content report.pdf --trust root.pem

# Machine-readable everything
pkinative chain verify server.pem --trust root.pem --json --summary
```

Every subcommand has a runnable example in [`samples/`](samples/) (`.sh` and `.ps1`), and those examples are the ones CI runs.

## What pkinative-cli will NOT do

The CLI inherits pkinative's doctrine; each refusal is deliberate and recorded in the engine's ADRs.

- **No network.** It never fetches a CRL, an OCSP response, a time-stamp or an intermediate. You fetch them; it judges them. `ocsp request` and `tsp request` write the requests you send yourself.
- **No key generation and no key export.** Bring keys from your HSM, KMS or `openssl genpkey`; the CLI imports them into non-extractable Web Crypto keys.
- **No PKCS#8 or PKCS#12 writer**, and no RC2 / 3DES / RFC 7292 Appendix B MAC: PKCS#12 means PBES2 and PBMAC1.
- **No default RSA signature scheme.** An RSA key signs only with `--rsa-scheme pkcs1|pss`.
- **No SHA-1 signature, made or accepted,** without `--allow-sha1`.
- **No secret on argv.** `--password` is refused; use `--password-file`, `--password-stdin` or `PKINATIVE_PASSWORD`.

## Commands

| Group | Commands |
|---|---|
| Encodings | `pem`, `oid`, `fingerprint`, `asn1` |
| Certificates | `cert`, `csr` |
| Paths & revocation | `chain`, `crl`, `ocsp` |
| Signatures & time-stamps | `cms`, `tsp` |
| Keys | `key`, `p12` |
| Meta | `doctor`, `limits`, `explain`, `schema`, `completion` |

`pkinative <command> --help` prints the full options of a command. The mapping from each command to the engine functions it calls is in [docs/KNOWLEDGE_BASE.md §8](docs/KNOWLEDGE_BASE.md#8-pkinative-api-mapping).

### `pkinative pem`

`decode` lists the blocks of an RFC 7468 text (or extracts one with `--index`); `encode` wraps DER bytes. `--pem-mode lax` tolerates whitespace and missing padding.

### `pkinative oid`

`name`, `encode` (content octets, or `--tlv`, `--relative`), `decode`, `validate` (exit 1 on an invalid OID) and `list` (the registry pkinative knows).

### `pkinative fingerprint`

SHA-1/256/384/512 fingerprints (pure TypeScript, or `--webcrypto`), the RFC 5280 key identifier of a certificate, request or public key (`--key-id`), and SHAKE256 (`--shake256 <bytes>`).

### `pkinative asn1`

`decode` prints the node tree like `openssl asn1parse`, reads one node with a typed reader (`--path 0.4.0 --read time`), or re-encodes it byte for byte; `encode` turns a JSON node spec into DER (`pkinative schema asn1-spec`).

### `pkinative cert`

`inspect` (one extension with `--extension`), `create` from a JSON spec (`pkinative schema cert-spec`; the result is verified under `--issuer` before it is written),
`encode` (every X.509 building block), `decode-extension`, `verify-signature`, `check-name` (RFC 6125 host or IP), `match-name` and `check-purpose`.

### `pkinative csr`

`inspect`, `create` from a JSON spec (`pkinative schema csr-spec`) and `verify` (the proof of possession) for PKCS#10 requests.

### `pkinative chain`

`verify` is the one-call verdict: path building, every signature, RFC 5280 validation, server name, purposes, policy inputs and — with `--crl` / `--ocsp` — revocation.
`build` finds a path; `validate` validates a path you ordered, verifying each link's signature first. Time is `--at` (ISO 8601, UTC unless zoned).

### `pkinative crl`

`inspect`, `find` (a serial, by hex or by certificate), `verify-signature` and `check` (a certificate's status from a CRL and an optional `--delta`).

### `pkinative ocsp`

`request` and `cert-id` write what you send; `inspect`, `verify-signature` and `check` judge the answer. `check` accepts the CA itself or a delegate it issued with OCSPSigning (RFC 6960 §4.2.2.2), unless `--responder-trusted`.

### `pkinative cms`

`sign` (attached, `--detached`, or a precomputed `--content-digest`; ESS signing-certificate-v2 and CMS algorithm protection by default), `verify` (signatures, chains, time-stamps, revocation),
`inspect`, `verify-signer`, `add-attribute` and `add-timestamp`.

### `pkinative tsp`

`request` (from data or a digest, with nonce and policy), `inspect` (a response, a token or a TSTInfo) and `verify` (against the request, the data or the digest you name).

### `pkinative key`

`inspect` describes a PKCS#8 key, encrypted or not, without a password; `check` imports or decrypts it to prove it is usable. No report contains a key byte.

### `pkinative p12`

`inspect` (no password), `verify-mac`, `bags` and `open` (verify, decrypt, import the key, `--certs-out` the certificates). PBES2 and PBMAC1 only.

### `pkinative doctor`

Offline preflight: the Node.js security floor, the installed pkinative, and whether Web Crypto can verify, sign and decrypt. Exit 1 when a check fails.

### `pkinative limits`

The 22 pkinative security bounds with the `--max-*` flag that raises each, its default, the effective value and its CWE.

### `pkinative explain`

Explains any code: the 13 `E_*` classes, and pkinative's 57 `PKI_*` errors (with the CLI class and the flag that lifts the refusal), 43 `PKI_REASON_*` reasons and 97 `PKI_DIAG_*` diagnostics.

### `pkinative schema`

The capability manifest, the error catalogue, the limits, and JSON Schemas (draft 2020-12) of the envelopes, the specs and the config file.

### `pkinative completion`

Shell completion for bash, zsh, fish and PowerShell.

## Global options

| Option | Effect |
|---|---|
| `--json` | Compact JSON report on stdout, one envelope on stderr (also `PKINATIVE_JSON=1`) |
| `--fields a,b.c`, `--summary`, `--pretty` | Shrink or indent JSON reports |
| `--quiet`, `-q` | No notes or diagnostics on stderr (errors still print) |
| `--dry-run` | Validate everything, write nothing |
| `--strict` | Escalate the first engine warning to `E_CHECK_FAILED` |
| `--ber` | Accept BER as well as DER |
| `--pem-mode strict\|lax` | PEM reading discipline |
| `--allow-sha1` | Accept or produce SHA-1 signatures (legacy material only) |
| `--overwrite` | Replace an existing output file, atomically |
| `--max-<limit> <n>`, `--max-content-size <size>` | Raise or lower a bound (`pkinative limits`) |
| `--config <file>`, `--no-config` | `.pkinativerc.json` presentation defaults only (`json`, `pretty`, `quiet`, `no-color`, `format`, `encoding`, `fields`, `summary`, `strict`) |

## Driving pkinative-cli from scripts and AI agents

```sh
$ pkinative chain verify revoked.pem --trust root.pem --crl ca.crl --json --summary
{"valid":false,"reasons":["PKI_REASON_REVOKED"],"path":["CN=revoked.example.test",…]}
# stderr:
{"ok":false,"command":"chain verify","error":{"code":"E_VERIFY_FAILED","message":"…","reasons":[…]},"diagnostics":[…]}
```

Reports use pkinative's wire convention (ADR 0018): `bigint` → decimal string, bytes → lowercase hex, instants in epoch milliseconds, member names unchanged.
The full contract — envelopes, every error class, the token-economy flags — is [docs/AGENT_CONTRACT.md](docs/AGENT_CONTRACT.md); `pkinative schema manifest` is its machine form.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Any failure but usage: parse, I/O, policy, a negative verdict (the report is printed first) |
| 2 | Usage error (`E_USAGE`) |
| 130 / 143 | Interrupted by SIGINT / SIGTERM; a file being written is removed |

## Security

Report vulnerabilities privately: see [SECURITY.md](SECURITY.md). The CLI's threat model is [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
Every release is published from CI with npm provenance, a Sigstore attestation and SBOMs.

## Documentation

- [docs/KNOWLEDGE_BASE.md](docs/KNOWLEDGE_BASE.md) — architecture, every command in depth, the engine mapping.
- [docs/AGENT_CONTRACT.md](docs/AGENT_CONTRACT.md) — the process contract for automation.
- [docs/adr/](docs/adr/) — the decisions behind the CLI.
- [CHANGELOG.md](CHANGELOG.md), [ROADMAP.md](ROADMAP.md), [CONTRIBUTING.md](CONTRIBUTING.md), [SUPPORT.md](SUPPORT.md).

## Related projects

- [pkinative](https://github.com/Nizoka/pkinative) — the engine.
- [pdfnative-cli](https://github.com/Nizoka/pdfnative-cli) and [zipnative-cli](https://github.com/Nizoka/zipnative-cli) — sibling CLIs on the same contract.

## License

[MIT](LICENSE) © 2026 Nizoka — Plika.
