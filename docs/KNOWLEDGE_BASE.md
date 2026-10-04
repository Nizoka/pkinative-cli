# pkinative-cli knowledge base

The deep reference. The README is the tour; [AGENT_CONTRACT.md](AGENT_CONTRACT.md) is the process contract; `pkinative <command> --help` is the option reference.

## 1. What the CLI is

pkinative-cli is a thin, strict front end over [pkinative](https://github.com/Nizoka/pkinative) 1.0.0. Every PKI decision — parsing, path validation, revocation, signature verification, CMS, time-stamps, key import — is the engine's.
The CLI adds what a library deliberately does not do: read files and stdin, sniff PEM, bound reads, turn options into flags, write artefacts safely, render reports, and map every failure to a stable class.

It is offline by construction: no module of `src/` imports a network API, and revocation evidence and time-stamps are files the caller supplies.

## 2. Architecture

```
argv ─► parseArgs (registry booleans) ─► command + subcommand ─► unknown-flag refusal ─► .pkinativerc.json merge
     ─► global options (--json, --strict, --ber, --max-*, …) ─► loadCommand() ─► handler(ctx)
handler: read (pki-input: PEM sniff, cap) ─► guard(engine call, parseOptions(ctx)) ─► emitReport | emitArtifact
run() ─► success envelope | failure envelope ─► exit code      bin.ts: EPIPE → 0, SIGINT/SIGTERM → cleanup, 130/143
```

| Module | Role |
|---|---|
| `src/cli.ts` | `run(argv, io)`: dispatch, envelopes, exit code; never calls `process.exit` |
| `src/bin.ts` | The process wrapper (the only file touching `process` events) |
| `src/context.ts` | `Ctx`: io, flags, global options, collected diagnostics, status fields; `parseOptions(ctx)` for every engine call |
| `src/commands/registry.ts` | Commands, subcommands and flags: the parser's booleans, the unknown-flag refusal, completions, the manifest |
| `src/core-bridge/index.ts` | The single import of `pkinative`, grouped by capability |
| `src/utils/pkierr.ts` | `PKI_TO_CLI` (57 → 13), `PKI_REMEDY`, `guard()` |
| `src/utils/wire.ts` | `toWire()`: the ADR 0018 wire form |
| `src/utils/io.ts`, `inflight.ts` | Bounded reads; exclusive or atomic writes; signal cleanup |
| `src/utils/pki-input.ts` | PEM/DER sniffing, labels, bundles |
| `src/utils/signer.ts`, `spki.ts` | Signing keys from PKCS#8 or PKCS#12; key types from SPKI |
| `src/utils/x509-spec.ts`, `names.ts` | The JSON specs of `cert create`, `csr create`, `cert encode` |
| `src/utils/key-views.ts` | Secret-free views of keys and PKCS#12 |

## 3. Inputs

- A PKI input is a path, `-` for stdin, or stdin when the path is absent (refused on an interactive terminal). It is PEM when its first non-blank bytes are `-----BEGIN `, DER otherwise.
- Where one object is expected, a PEM file with several matching blocks is refused (`E_INPUT`) rather than reduced to its first block; `pem decode --index` extracts one.
- Repeatable inputs (`--trust`, `--untrusted`, `--chain`, `--crl`, `--ocsp`) accept PEM bundles.
- Every PKI read is capped by `--max-input-bytes` (64 MiB, pkinative's `maxInputBytes`) before a byte is buffered; content to sign or time-stamp and JSON specs by `--max-content-size` (1 GiB).

## 4. Outputs

- **Reports** (`inspect`, `verify`, `check`, …): text by default; with `--json` or `--format json`, the engine's result in the wire form. `--summary` gives each command's minimal shape; `--fields` projects dot-paths.
- **Artefacts** (`create`, `sign`, `request`, `encode`, `add-*`): `--encoding pem|der|hex` to `--output` or stdout. Raw DER to a terminal is refused. `--dry-run` validates and writes nothing.
- **Writes** are exclusive by default (an existing path, a dangling symlink included, is refused) and atomic with `--overwrite` (temp file, then rename). A write interrupted by a signal is removed.

## 5. Commands in depth

| Invocation | Engine path | Fails with |
|---|---|---|
| `pem decode`, `pem encode` | RFC 7468 strict or lax | `E_PARSE`, `E_INPUT`, `E_NOT_FOUND` (index) |
| `oid name / encode / decode / validate / list` | X.660 dotted form, X.690 §8.19–8.20 | `E_PARSE`, `E_CHECK_FAILED` (validate) |
| `fingerprint` | FIPS 180-4 / 202 digests, RFC 5280 §4.2.1.2 key identifier | `E_PARSE` |
| `asn1 decode / encode` | X.690 DER (BER with `--ber`), 11 typed readers, 18 encoders | `E_PARSE`, `E_INPUT`, `E_LIMIT` |
| `cert inspect / create / encode / decode-extension` | RFC 5280 reader and writer | `E_PARSE`, `E_INPUT` (key/issuer mismatch) |
| `cert verify-signature / check-name / match-name / check-purpose` | Signatures, RFC 6125, RFC 5280 §4.2.1.12 | `E_VERIFY_FAILED`, `E_CHECK_FAILED` |
| `csr inspect / create / verify` | RFC 2986 | `E_VERIFY_FAILED`, `E_INPUT` |
| `chain verify / build / validate` | RFC 5280 §6 with revocation | `E_VERIFY_FAILED` |
| `crl inspect / find / verify-signature / check` | RFC 5280 §5, delta CRLs | `E_VERIFY_FAILED`, `E_CHECK_FAILED`, `E_INPUT` (not a delta) |
| `ocsp request / cert-id / inspect / verify-signature / check` | RFC 6960 | `E_VERIFY_FAILED`, `E_CHECK_FAILED` |
| `cms sign / verify / inspect / verify-signer / add-attribute / add-timestamp` | RFC 5652, 5035, 6211, 3161 | `E_VERIFY_FAILED`, `E_INPUT` |
| `tsp request / inspect / verify` | RFC 3161 | `E_VERIFY_FAILED`, `E_USAGE` (nothing stamped named) |
| `key inspect / check` | RFC 5958, RFC 8018 PBES2 | `E_PASSWORD`, `E_USAGE` (type, scheme) |
| `p12 inspect / verify-mac / bags / open` | RFC 7292 with PBES2, RFC 9579 PBMAC1 | `E_SECURITY` (legacy), `E_PASSWORD`, `E_VERIFY_FAILED` |
| `doctor`, `limits`, `explain`, `schema`, `completion` | Meta | `E_CHECK_FAILED` (doctor), `E_NOT_FOUND` (explain) |

### Signing keys

`cert create`, `csr create`, `cert encode signature-algorithm` and `cms sign` take `--key <pkcs8>` (plain or encrypted) or `--p12 <file>`.
The algorithm follows the key: ECDSA on the key's curve with the curve's hash (or `--hash`), Ed25519 and Ed448 without a hash, RSA only with `--rsa-scheme pkcs1|pss`.
An encrypted key reveals its type only once decrypted, and pkinative decrypts into a key for one algorithm, so the type comes from the issuer certificate, `--cert`, `--public-key`, or `--key-type`.

### Revocation

`chain verify` takes CRLs and OCSP responses as files; `--require-revocation` turns an unknown status into a failure. `crl check` and `ocsp check` decide one certificate's status.
`ocsp check` recomputes the CertID with the responder's hash, finds the signer among `--responder`, the embedded certificates and the issuer, and authorises it per RFC 6960 §4.2.2.2.

## 6. Error model

<!-- BEGIN GENERATED: error-classes -->
| Class | Exit | PKI_* codes | Meaning |
|---|---|---|---|
| `E_USAGE` | 2 | 3 | A flag, argument or option value is missing or invalid (exit 2). |
| `E_INPUT` | 1 | 5 | A value you supplied is not acceptable: a spec document, a label, a range, a key that does not match. |
| `E_PARSE` | 1 | 35 | The bytes are not the DER, PEM or JSON structure they claim to be. |
| `E_IO` | 1 | 0 | A filesystem or stream failure, including a refused overwrite. |
| `E_SECURITY` | 1 | 3 | A security policy refused the input: SHA-1 without --allow-sha1, PBES1, a legacy PKCS#12 MAC. |
| `E_LIMIT` | 1 | 1 | A named bound was exceeded: one of the 22 pkinative limits, or --max-content-size. |
| `E_UNSUPPORTED` | 1 | 6 | The runtime or pkinative does not support the algorithm, key or structure. |
| `E_CRYPTO` | 1 | 1 | Web Crypto could not run the operation the input requires. |
| `E_PASSWORD` | 1 | 1 | A password is wrong, or a MAC does not match it. |
| `E_NOT_FOUND` | 1 | 0 | A named item does not exist: an extension, a PEM block, a signer, a code. |
| `E_VERIFY_FAILED` | 1 | 0 | A signature, chain, request, time-stamp or MAC verdict is negative; the report says why. |
| `E_CHECK_FAILED` | 1 | 1 | A check returned reasons (revocation, OCSP, name, purpose) or --strict escalated a warning. |
| `E_RUNTIME` | 1 | 1 | Anything else (exit 1); PKINATIVE_DEBUG=1 prints the stack. |
<!-- END GENERATED: error-classes -->

Every engine failure keeps pkinative's own code in `pkiCode`; `pkinative explain <code>` prints its registry entry and the CLI flag that lifts it, and `pkinative schema errors` the whole mapping.

## 7. Limits

The 22 bounds of pkinative's `DEFAULT_PKI_LIMITS` are `--max-*` flags (`pkinative limits` lists them with their CWE). A bound is a positive integer; there is no "unbounded".
A config file can never set one: raising a bound is a decision taken on the command line, for input the caller trusts.

## 8. pkinative API mapping

Every runtime export of pkinative 1.0.0 and the invocations that call it (`*` = every command that reads or reports PKI objects).
The 177 type exports are reached through the inputs and reports of these calls; [`docs/data/core-exports.json`](data/core-exports.json) lists all 294.

<!-- BEGIN GENERATED: api-mapping -->
| Export | Kind | Reached by |
|---|---|---|
| `ANY_EXTENDED_KEY_USAGE` | constant | `cert check-purpose`, `cert create` |
| `DEFAULT_PKI_LIMITS` | constant | *, `limits` |
| `KEY_PURPOSES` | constant | `cert check-purpose`, `cert create`, `chain verify` |
| `KEY_USAGE_BITS` | constant | `cert create`, `cert encode` |
| `OCSP_NONCE_OID` | constant | `ocsp inspect` |
| `OID_REGISTRY` | constant | `cert create`, `oid list` |
| `PkiCertificateError` | class | *, `explain` |
| `PkiCmsError` | class | *, `explain` |
| `PkiCryptoError` | class | *, `explain` |
| `PkiEncodingError` | class | *, `explain` |
| `PkiError` | class | *, `explain` |
| `PkiKeyError` | class | *, `explain` |
| `PkiLimitError` | class | *, `explain` |
| `addTimeStampToken` | function | `cms add-timestamp` |
| `addUnsignedAttribute` | function | `cms add-attribute` |
| `buildCertificatePath` | function | `chain build` |
| `canDecrypt` | function | `doctor` |
| `canSign` | function | `doctor` |
| `canVerify` | function | `doctor` |
| `checkExtendedKeyUsage` | function | `cert check-purpose`, `ocsp check` |
| `checkOcspStatus` | function | `ocsp check` |
| `checkRevocation` | function | `crl check` |
| `checkServerName` | function | `cert check-name` |
| `computeFingerprint` | function | `cert inspect`, `fingerprint`, `tsp request` |
| `computeFingerprintAsync` | function | `fingerprint` |
| `computeKeyIdentifier` | function | `cert create`, `fingerprint` |
| `createCertificate` | function | `cert create` |
| `createCertificationRequest` | function | `csr create` |
| `createOcspRequest` | function | `ocsp request` |
| `createSignedData` | function | `cms sign` |
| `createTimeStampRequest` | function | `tsp request` |
| `decodeAsn1` | function | `asn1 decode`, `oid decode` |
| `decodeAsn1Sequence` | function | `asn1 decode` |
| `decodeExtensionValue` | function | `cert decode-extension` |
| `decodeOid` | function | `oid decode` |
| `decodePem` | function | *, `pem decode` |
| `decryptPrivateKey` | function | `cert create`, `cms sign`, `csr create`, `key check` |
| `encodeAlgorithmIdentifier` | function | `cert encode` |
| `encodeAsn1Node` | function | `asn1 decode` |
| `encodeAttribute` | function | `cert encode` |
| `encodeAuthorityKeyIdentifier` | function | `cert create`, `cert encode` |
| `encodeBasicConstraints` | function | `cert create`, `cert encode`, `csr create` |
| `encodeBitString` | function | `asn1 encode` |
| `encodeBoolean` | function | `asn1 encode` |
| `encodeDistinguishedName` | function | `cert create`, `cert encode` |
| `encodeEnumerated` | function | `asn1 encode` |
| `encodeExplicit` | function | `asn1 encode` |
| `encodeExtendedKeyUsage` | function | `cert create`, `cert encode`, `csr create` |
| `encodeExtension` | function | `cert encode` |
| `encodeExtensions` | function | `cert encode` |
| `encodeImplicit` | function | `asn1 encode` |
| `encodeInteger` | function | `asn1 encode` |
| `encodeKeyUsage` | function | `cert create`, `cert encode`, `csr create` |
| `encodeNameAttribute` | function | `cert encode` |
| `encodeNamedBits` | function | `asn1 encode` |
| `encodeNull` | function | `asn1 encode` |
| `encodeObjectIdentifier` | function | `asn1 encode`, `oid encode` |
| `encodeOcspCertId` | function | `ocsp cert-id`, `ocsp check` |
| `encodeOctetString` | function | `asn1 encode` |
| `encodeOid` | function | `oid encode` |
| `encodePem` | function | *, `pem encode` |
| `encodeRelativeOid` | function | `asn1 encode`, `oid encode` |
| `encodeSequence` | function | `asn1 encode` |
| `encodeSet` | function | `asn1 encode` |
| `encodeSetOf` | function | `asn1 encode` |
| `encodeSignatureAlgorithm` | function | `cert encode` |
| `encodeString` | function | `asn1 encode` |
| `encodeSubjectAltName` | function | `cert create`, `cert encode`, `csr create` |
| `encodeSubjectKeyIdentifier` | function | `cert create`, `cert encode`, `csr create` |
| `encodeSubjectPublicKeyInfo` | function | `cert encode` |
| `encodeTime` | function | `asn1 encode` |
| `encodeTlv` | function | `asn1 encode` |
| `encodeValidity` | function | `cert encode` |
| `findRevocation` | function | `crl find` |
| `formatDistinguishedName` | function | *, `cert inspect` |
| `formatFingerprint` | function | `cert inspect`, `fingerprint` |
| `getExtension` | function | `cert create`, `cert inspect` |
| `getOidName` | function | `asn1 decode`, `cert inspect`, `explain`, `oid name` |
| `importPrivateKey` | function | `cert create`, `cms sign`, `csr create`, `key check` |
| `isValidOid` | function | `oid validate` |
| `matchDnsName` | function | `cert match-name` |
| `openPkcs12` | function | `cert create`, `cms sign`, `p12 open` |
| `openSafeContents` | function | `p12 bags` |
| `parseCertificate` | function | *, `cert inspect` |
| `parseCertificateList` | function | `crl check`, `crl inspect` |
| `parseCertificationRequest` | function | `cert create`, `csr inspect`, `fingerprint` |
| `parseEncryptedPrivateKeyInfo` | function | `key inspect` |
| `parseOcspResponse` | function | `ocsp check`, `ocsp inspect` |
| `parsePkcs12` | function | `p12 bags`, `p12 inspect`, `p12 verify-mac` |
| `parsePrivateKeyInfo` | function | `cert create`, `key inspect` |
| `parseSignedData` | function | `cms inspect`, `cms sign` |
| `parseTimeStampResponse` | function | `cms add-timestamp`, `tsp inspect` |
| `parseTimeStampToken` | function | `tsp inspect` |
| `parseTstInfo` | function | `tsp inspect` |
| `readBitString` | function | `asn1 decode`, `fingerprint` |
| `readBoolean` | function | `asn1 decode` |
| `readEnumerated` | function | `asn1 decode` |
| `readInteger` | function | `asn1 decode` |
| `readNull` | function | `asn1 decode` |
| `readObjectIdentifier` | function | `asn1 decode`, `oid decode` |
| `readOctetString` | function | `asn1 decode`, `ocsp check` |
| `readRelativeOid` | function | `asn1 decode`, `oid decode` |
| `readSmallInteger` | function | `asn1 decode` |
| `readString` | function | `asn1 decode` |
| `readTime` | function | `asn1 decode` |
| `shake256` | function | `fingerprint` |
| `validateCertificatePath` | function | `chain validate` |
| `verifyCertificateChain` | function | `chain verify` |
| `verifyCertificateSignature` | function | `cert create`, `cert verify-signature`, `chain validate`, `ocsp check` |
| `verifyCertificationRequest` | function | `csr create`, `csr verify` |
| `verifyCrlSignature` | function | `crl check`, `crl verify-signature` |
| `verifyOcspSignature` | function | `ocsp check`, `ocsp verify-signature` |
| `verifyPkcs12Mac` | function | `p12 verify-mac` |
| `verifySelfSignature` | function | `cert create`, `cert verify-signature` |
| `verifySignedData` | function | `cms verify` |
| `verifySignerInfoSignature` | function | `cms sign`, `cms verify-signer` |
| `verifyTimeStampToken` | function | `tsp verify` |
<!-- END GENERATED: api-mapping -->

## 9. Security model

See [SECURITY.md](../SECURITY.md) and [THREAT_MODEL.md](THREAT_MODEL.md). In short: no network; no secret on argv; no key byte in any output; exclusive or atomic writes; every read bounded; refusals inherited from the engine and impossible to relax from a config file.

## 10. Proofs

| Proof | Where |
|---|---|
| 100 % coverage (statements, branches, functions, lines) | `vitest.config.ts`, the gate |
| Every engine export reached and used | `tests/docs/surface.test.ts` |
| Every 1.0.0 engine change tested or waived | `tests/regression/engine-surface.json` |
| CLI output equals the library's result | `tests/parity/library.test.ts` |
| No input produces an unmapped failure | `tests/fuzz/fuzz.test.ts` (seeded) |
| The built bundle behaves | `tests/integration/built-binary.test.ts` |
| OpenSSL accepts what the CLI writes | `tests/interop/openssl.test.ts` |
| Every subcommand's output pinned | `scripts/verify-samples.ts`, `tests/regression/baselines/samples.sha256.json` |
| Help text held to the registry | `tests/docs/usage.test.ts` |
