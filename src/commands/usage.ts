// Hand-written help text, one block per command. tests/docs/usage.test.ts
// holds each block to the registry: every flag listed here is declared there
// and vice versa, boolean flags never show a <value>, lines stay ≤ 80 columns.

import { COMMANDS } from './registry.js';

export const GLOBAL_USAGE = `\
Global options (any command):
  --json            Agent mode: JSON report on stdout, one JSON envelope on
                    stderr ({ ok, command, ... } or { ok: false, error })
  --pretty          Indent JSON output
  --fields <a,b.c>  Keep only these dot-paths of a JSON report
  --summary         Print the command's minimal JSON shape
  --quiet,   -q     No notes or diagnostics on stderr (errors still print)
  --no-color        No ANSI colour (also NO_COLOR; FORCE_COLOR forces it)
  --dry-run         Validate everything, write nothing
  --strict          Escalate the first engine warning to E_CHECK_FAILED
  --ber             Accept BER as well as DER (common in CMS)
  --pem-mode <strict|lax>  PEM reading: RFC 7468 strict (default) or lax
  --allow-sha1      Accept SHA-1 signatures (legacy material you trust)
  --overwrite       Replace an existing --output file (atomic rename)
  --config <file>   Use this .pkinativerc.json (default: nearest upward);
                    presentation defaults only (json, pretty, quiet,
                    no-color, format, encoding, fields, summary, strict)
  --no-config       Ignore any .pkinativerc.json
  --max-content-size <size>  Bound on content read whole (default 1 GiB)
  --max-<limit> <n>          The 22 pkinative limits, e.g. --max-input-bytes,
                    --max-depth, --max-chain-length (see: pkinative limits)

Exit codes:
  0  success                 1  failure (any E_* class but E_USAGE)
  2  usage error (E_USAGE)   130 / 143  interrupted by SIGINT / SIGTERM
                                        (a file being written is removed)

Environment:
  PKINATIVE_JSON=1      same as --json       PKINATIVE_QUIET=1  --quiet
  PKINATIVE_PASSWORD    password source (never accepted on the command line)
  PKINATIVE_DEBUG=1     stack traces on stderr
  NO_COLOR / FORCE_COLOR / TERM=dumb         colour of the text output
`;

/** The command list of the top-level help, grouped, derived from the registry. */
export function commandList(): string {
    const groups = new Map<string, string[]>();
    for (const c of COMMANDS) {
        const lines = groups.get(c.group) ?? [];
        lines.push(`  ${c.name.padEnd(13)}${c.summary}`);
        groups.set(c.group, lines);
    }
    const body = [...groups].map(([group, lines]) => ` ${group}\n${lines.join('\n')}`).join('\n\n');
    return `Commands (${COMMANDS.length}):\n\n${body}\n`;
}

export const USAGE = `\
pkinative-cli — Official CLI for pkinative (X.509, CMS, PKCS, ASN.1)

Usage:
  pkinative <command> [<subcommand>] [options]

${commandList()}
Options:
  --help,    -h   Show this help, or a command's help
  --version, -V   Show the version (with --json: CLI and engine versions)

${GLOBAL_USAGE}
Offline, always: no command opens a socket or fetches anything.
Scripts and AI agents: docs/AGENT_CONTRACT.md (shipped in the package) and
\`pkinative schema manifest\`.
Run \`pkinative <command> --help\` for a command's options.
`;

const LIMITS_USAGE = `\
pkinative limits — The 22 pkinative security bounds

Usage:
  pkinative limits [--max-<limit> <n>]... [--format text|json]

Prints every bound of pkinative's DEFAULT_PKI_LIMITS with the flag that raises
it, its default, the effective value under the --max-* flags given and its
CWE (--format json adds what it guards), plus the CLI's own
--max-content-size.

Options:
  --format, -f <text|json>  Report format (json under --json)

Raise a bound only for input you trust; a config file can never raise one.
`;

const PEM_USAGE = `\
pkinative pem — RFC 7468 textual encoding

Usage:
  pkinative pem decode [<file>] [--index <n> [--encoding pem|der|hex] [-o f]]
  pkinative pem encode [<file>] --label <LABEL> [-o <file>]

decode lists every block (label, size, offset, headers); with --index it
writes that block's bytes (DER by default). encode wraps DER bytes in one block.

decode options:
  --input,  -i <file>       PEM text (default: the positional, or stdin)
  --label <LABEL>           Refuse any block with another label
  --index <n>               Extract block n (from 0)
  --encoding <pem|der|hex>  Output encoding of the extracted block (default der)
  --output, -o <file>       Write the block to a file (default: stdout)
  --format, -f <text|json>  Report format of the listing

encode options:
  --input,  -i <file>       DER bytes (default: the positional, or stdin)
  --label <LABEL>           The block label, e.g. CERTIFICATE (required)
  --output, -o <file>       Write the PEM text to a file (default: stdout)

--pem-mode lax (global) tolerates whitespace, line length and RFC 1421 headers;
a missing base64 padding ("=") is refused in both modes: restore it first.
`;

const OID_USAGE = `\
pkinative oid — Object identifiers

Usage:
  pkinative oid name <oid>...                 Registered name of each OID
  pkinative oid encode <oid> [--tlv] [--relative] [--encoding hex|der|pem]
  pkinative oid decode <hex> [--tlv] [--relative]
  pkinative oid decode --input <file> --tlv
  pkinative oid validate <oid>...             Exit 1 (E_CHECK_FAILED) if invalid
  pkinative oid list [--filter <text>]        The registry pkinative knows

encode:
  --tlv                     Whole TLV (tag 06, or 0D with --relative) rather
                            than the content octets
  --relative                RELATIVE-OID (X.690 §8.20); needs --tlv
  --encoding <pem|der|hex>  Output encoding (default hex)
  --label <LABEL>           PEM label with --encoding pem
  --output, -o <file>       Write to a file (default: stdout)

decode:
  --tlv                     The bytes are a whole TLV, not the content octets
  --relative                Decode a RELATIVE-OID (X.690 §8.20)
  --input, -i <file>        Read the bytes from a file

list:
  --filter <text>           Keep entries whose OID, name or standard contains it

name / decode / validate / list:
  --format, -f <text|json>  Report format (json under --json)
`;

const FINGERPRINT_USAGE = `\
pkinative fingerprint — Digests of PKI objects

Usage:
  pkinative fingerprint [<file>] [--alg SHA-256] [--separator :] [--case upper]
  pkinative fingerprint [<file>] --key-id [--alg SHA-1|SHA-256]
  pkinative fingerprint [<file>] --shake256 <bytes>

The input is one PEM block or DER object (certificate, request, CRL, ...).

Options:
  --input, -i <file>        The object (default: the positional, or stdin)
  --alg <SHA-1|SHA-256|SHA-384|SHA-512>   Digest (default SHA-256; SHA-1 for
                            --key-id, which RFC 5280 §4.2.1.2 specifies)
  --separator <text>        Between bytes (default ":"; "" for none)
  --case <upper|lower>      Hex letter case (default upper)
  --webcrypto               Digest with Web Crypto instead of the pure-TS path
  --key-id                  Key identifier of the public key of a
                            certificate, request or PUBLIC KEY
  --shake256 <bytes>        SHAKE256 of the input, this many bytes (max 1 MiB)
  --format, -f <text|json>  Report format (json under --json)
`;

const ASN1_USAGE = `\
pkinative asn1 — DER/BER decoding and encoding (ITU-T X.690)

Usage:
  pkinative asn1 decode [<file>] [--path i.j.k] [--read <type>] [--reencode]
  pkinative asn1 decode [<file>] --sequence [--allow-trailing]
  pkinative asn1 encode --spec <spec.json> [--encoding der|hex|pem]

decode prints the node tree (offset, depth, lengths, tag, value). PEM input
is accepted (one block). --ber accepts BER (global option).

decode options:
  --input, -i <file>        The object (default: the positional, or stdin)
  --path <i.j.k>            Select a node by child indices from the root
  --read <type>             Read the node: boolean, integer, small-integer,
                            enumerated, null, bit-string, octet-string, oid,
                            relative-oid, string, time
  --string-type <type>      With --read string on an IMPLICIT-tagged node: the
                            string type (utf8, numeric, printable, teletex,
                            ia5, visible, universal, bmp)
  --time-type <UTCTime|GeneralizedTime>   With --read time on an
                            IMPLICIT-tagged node: the time type
  --reencode                Re-encode the node (byte-identical for DER)
  --sequence                Decode concatenated top-level objects
  --allow-trailing          Ignore bytes after the first object
  --encoding <pem|der|hex>  --reencode output encoding (default der)
  --label <LABEL>           PEM label with --encoding pem
  --output, -o <file>       --reencode output file (default: stdout)
  --format, -f <text|json>  Report format (json under --json)

encode options:
  --spec <file>             JSON node spec ("-" = stdin); types: boolean,
                            integer, enumerated, null, bit-string, named-bits,
                            octet-string, oid, relative-oid, string, time,
                            sequence, set, set-of, explicit, implicit, tlv, der
  --encoding <pem|der|hex>  Output encoding (default der)
  --label <LABEL>           PEM label with --encoding pem
  --output, -o <file>       Write to a file (default: stdout)

See: pkinative schema asn1-spec
`;

const SIGNING_USAGE = `\
Signing key (cert create, cert encode signature-algorithm, csr create,
cms sign):
  --key <file>              PKCS#8 private key, plain or PBES2-encrypted
  --p12 <file>              PKCS#12 file holding one key (PBES2 / PBMAC1)
  --key-type <type>         Type of an encrypted key when no certificate or
                            public key tells it: ec-p256, ec-p384, ec-p521,
                            ed25519, ed448, rsa, rsa-pss
  --hash <SHA-256|SHA-384|SHA-512>  Digest (default: the curve's, or SHA-256;
                            SHA-1 only with --allow-sha1)
  --rsa-scheme <pkcs1|pss>  REQUIRED for an RSA key: there is no default
  --salt-length <n>         RSA-PSS salt length (default: the hash length)
  --password-file <file>    Key or PKCS#12 password: first line of the file
  --password-stdin          ... or the first line of stdin
                            (or PKINATIVE_PASSWORD; never on the command line)
`;

const CERT_USAGE = `\
pkinative cert — X.509 certificates (RFC 5280)

Usage:
  pkinative cert inspect [<file>] [--extension <kind>] [--raw-extensions]
  pkinative cert create --spec <spec.json> --key <key> [--issuer <ca.pem>]
                        [--public-key <file>] [-o <file>]
  pkinative cert encode <structure> --spec <spec.json>
  pkinative cert encode signature-algorithm --key <key> [--rsa-scheme <s>]
  pkinative cert decode-extension --oid <oid> --value <hex> [--critical]
  pkinative cert verify-signature [<file>] [--issuer <file>]
  pkinative cert check-name [<file>] --host <name> | --ip <address>
  pkinative cert match-name <presented> <reference> [--no-wildcards]
  pkinative cert check-purpose [<file>] --purpose <name|oid|any>
                               [--chain <file>]...

inspect:
  --input, -i <file>        The certificate, PEM or DER (default: positional)
  --extension <kind>        Print one decoded extension (E_NOT_FOUND if absent)
  --raw-extensions          Keep every extension undecoded
  --format, -f <text|json>  Report format (json under --json)

create (the spec: subject, issuer, serialNumber, notBefore, notAfter or
validityDays, extensions; see: pkinative schema cert-spec; defaults when
omitted: a random 127-bit serialNumber, notBefore now, validityDays 365):
  --spec <file>             JSON spec ("-" = stdin)
  --issuer <file>           Issuer certificate; omitted = self-signed
  --public-key <file>       Subject key: a certificate, request or PUBLIC KEY
                            (default: derived from an unencrypted --key when
                            self-signed)
  --output, -o <file>       Output file (default: stdout)
  --encoding <pem|der|hex>  Output encoding (default pem)
  The new certificate is verified against --issuer (or itself) before it is
  written: a key that does not belong to the issuer is refused (E_INPUT).

encode <structure>: name, name-attribute, validity, spki,
  algorithm-identifier, attribute, extension, extensions, basic-constraints,
  key-usage, extended-key-usage, subject-alt-name, subject-key-identifier,
  authority-key-identifier, signature-algorithm (from the signing key)
  Members of each spec: pkinative schema cert-encode-spec ($defs/<structure>)
  --spec <file>             JSON value of the structure ("-" = stdin)
  --output, -o <file>       Output file      --encoding <pem|der|hex> (hex)
  --label <LABEL>           PEM label with --encoding pem

decode-extension:
  --oid <oid>               The extension OID
  --value <hex>             The extnValue content (or --input <file>, DER)
  --input, -i <file>        Read the value from a file
  --critical                Decode as a critical extension

verify-signature:           exit 1 (E_VERIFY_FAILED) when it does not verify
  --issuer <file>           The issuer certificate (default: self-signature)
  --allow-algorithm-mismatch  Accept tbs and outer algorithms that differ

check-name:                 exit 1 (E_CHECK_FAILED) on a mismatch
  --host <name>             DNS reference identity
  --ip <address>            IPv4 or IPv6 reference identity
  --chain <file>            Issuers for name constraints (repeatable)
  --allow-cn-fallback       Accept a commonName when there is no SAN
  --no-wildcards            Refuse wildcard names

match-name:                 exit 1 (E_CHECK_FAILED) on a mismatch
  --no-wildcards            Refuse wildcard names

check-purpose:              exit 1 (E_CHECK_FAILED) when the purpose fails
  --purpose <name|oid|any>  serverAuth, clientAuth, codeSigning,
                            emailProtection, timeStamping, ocspSigning, any
  --chain <file>            The issuers, leaf first order (repeatable)
  --no-restrict-issuers     Do not require the purpose in issuer EKUs
  --require-explicit-purpose  Refuse a certificate without an EKU

verify-signature / check-name / check-purpose:
  --input, -i <file>        The certificate (default: the positional)

decode-extension / verify-signature / check-name / match-name / check-purpose:
  --format, -f <text|json>  Report format (json under --json)

${SIGNING_USAGE}`;

const CSR_USAGE = `\
pkinative csr — PKCS#10 certification requests (RFC 2986)

Usage:
  pkinative csr inspect [<file>] [--raw-extensions]
  pkinative csr create --spec <spec.json> --key <key> [--public-key <file>]
  pkinative csr verify [<file>]

inspect / verify:
  --input, -i <file>        The request, PEM or DER (default: the positional)
  --format, -f <text|json>  Report format (json under --json)
  verify exits 1 (E_VERIFY_FAILED) when the self-signature does not verify.

inspect:
  --raw-extensions          Keep requested extensions undecoded

create (the spec: { "subject": {...}, "extensions": {...} }):
  --spec <file>             JSON spec ("-" = stdin)
  --public-key <file>       The key to certify (default: derived from an
                            unencrypted --key)
  --output, -o <file>       Output file (default: stdout)
  --encoding <pem|der|hex>  Output encoding (default pem)

${SIGNING_USAGE}`;

const CHAIN_USAGE = `\
pkinative chain — Certification paths (RFC 5280 §6)

Usage:
  pkinative chain verify [<leaf>] --trust <roots> [--untrusted <file>]...
                         [--host <name> | --ip <address>] [--purpose <p>]...
                         [--crl <file>]... [--ocsp <file>]...
                         [--require-revocation] [--at <instant>]
  pkinative chain build [<leaf>] --trust <roots> [--untrusted <file>]...
  pkinative chain validate --path <leaf> --path <ca>... --trust <roots>

verify is the one-call verdict: path building, every signature, RFC 5280
validation, the server name (RFC 6125), the purposes and, with CRLs or OCSP
responses, revocation. build finds a path without checking signatures: its
verdict is the path, so valid is false with PKI_REASON_SIGNATURE_NOT_CHECKED
and the envelope says signaturesChecked: false.
validate takes the path in order and verifies each link's signature first.
A negative verdict prints the report, then exits 1 (E_VERIFY_FAILED).

Inputs:
  --input, -i <file>        verify, build: the leaf (default: the positional)
  --trust <file>            Trust anchors, PEM bundle or DER (repeatable)
  --untrusted <file>        verify, build: intermediate candidates (repeatable)
  --path <file>             validate: the path, leaf first (repeatable)
  --at <instant>            Validation time: ISO 8601 (UTC unless zoned),
                            epoch milliseconds or "now" (default now)

Checks:
  --purpose <name|oid>      Required extended key usage (repeatable):
                            serverAuth, clientAuth, codeSigning, ...
  --host <name>             verify: the DNS name the leaf must hold
  --ip <address>            verify: the IP address the leaf must hold
  --policy <oid>            Initial policy set (repeatable)
  --require-explicit-policy --inhibit-policy-mapping --inhibit-any-policy
                            RFC 5280 §6.1.1 policy inputs

Revocation (verify):
  --crl <file>              CRLs, PEM bundle or DER (repeatable)
  --ocsp <file>             OCSP responses, DER (repeatable)
  --ocsp-nonce <hex>        The nonce the OCSP request carried
  --require-ocsp-nonce      Refuse an OCSP response without that nonce
  --require-revocation      Fail when a certificate's status is unknown

  --no-signatures           validate: skip the link signatures (structural)
  --format, -f <text|json>  Report format (json under --json)

Offline: CRLs and OCSP responses are files you fetched; nothing is fetched.
`;

const CRL_USAGE = `\
pkinative crl — Certificate revocation lists (RFC 5280 §5)

Usage:
  pkinative crl inspect [<crl>]
  pkinative crl find [<crl>] --serial <hex> | --cert <file>
  pkinative crl verify-signature [<crl>] --issuer <ca>
  pkinative crl check [<crl>] --cert <file> [--issuer <ca>] [--delta <crl>]
                      [--at <instant>] [--stale-tolerance <ms>]

find reports whether a serial is listed (exit 0 either way). check is the
verdict: listed, stale, wrong scope or unverified is exit 1 (E_CHECK_FAILED).
With --issuer the CRL signature is verified; without it, it counts as unchecked.

Options:
  --input, -i <file>        The CRL, PEM or DER (default: the positional)
  --serial <hex>            find: the serial number, hexadecimal
  --cert <file>             find, check: the certificate to look up or check
  --issuer <file>           verify-signature, check: the CRL issuer
  --delta <file>            check: a delta CRL to apply on top
  --at <instant>            check: decision time (default now)
  --stale-tolerance <ms>    check: accept a CRL this long past nextUpdate
  --format, -f <text|json>  Report format (json under --json)
`;

const OCSP_USAGE = `\
pkinative ocsp — Online Certificate Status Protocol (RFC 6960), offline

Usage:
  pkinative ocsp request --cert <file> --issuer <ca> [--hash SHA-1|SHA-256]
                         [--nonce <hex>|random] [-o req.der]
  pkinative ocsp cert-id --cert <file> --issuer <ca> [--hash SHA-1|SHA-256]
  pkinative ocsp inspect [<response>]
  pkinative ocsp verify-signature [<response>] [--responder <cert>]
  pkinative ocsp check [<response>] --cert <file> --issuer <ca>
                       [--responder <cert>] [--nonce <hex>] [--at <instant>]

The CLI writes the request and judges the response; sending the request is
yours (curl --data-binary @req.der -H 'Content-Type: application/ocsp-request').

request / cert-id:
  --cert <file>             The certificate (or the positional)
  --issuer <file>           Its issuer
  --hash <SHA-1|SHA-256>    CertID hash (default SHA-1, as responders expect)
  --output, -o <file>       Output file (default: stdout)
  --encoding <pem|der|hex>  Output encoding (request: der, cert-id: hex)
  --label <LABEL>           PEM label with --encoding pem

request:
  --nonce <hex|random>      A nonce extension of 1 to 32 octets (RFC 8954),
                            printed in the status

inspect / verify-signature / check:
  --input, -i <file>        The response, DER (default: the positional)
  --format, -f <text|json>  Report format (json under --json)

verify-signature / check:
  --responder <file>        The responder certificate (default: the
                            certificates the response embeds; check also
                            tries the issuer)

check:
  --cert <file>             The certificate whose status is asked
  --issuer <file>           Its issuer
  --responder-trusted       Trust the responder out of band; otherwise it
                            must be the CA or a delegate the CA issued with
                            the OCSPSigning purpose (RFC 6960 §4.2.2.2)
  --hash <SHA-1|SHA-256>    CertID hash (default: the response's own)
  --nonce <hex>             The nonce the request carried
  --require-nonce           Refuse a response without that nonce
  --at <instant>            Decision time (default now)
  --stale-tolerance <ms>    Accept an answer this long past nextUpdate
  --future-tolerance <ms>   Accept a thisUpdate this far ahead (60000)

check exits 1 (E_CHECK_FAILED) unless the answer is a clean, signed,
authorised "good" for this certificate.
`;

const CMS_USAGE = `\
pkinative cms — CMS SignedData (RFC 5652, RFC 5035, RFC 6211)

Usage:
  pkinative cms sign --content <file> --cert <cert> --key <key> [--detached]
                     [--chain <file>]... [-o out.p7s]
  pkinative cms verify [<p7s>] [--content <file>] --trust <roots>
  pkinative cms inspect [<p7s>]
  pkinative cms verify-signer [<p7s>] --cert <cert> [--signer-index <n>]
  pkinative cms add-attribute [<p7s>] --attribute <der> [--signer-index <n>]
  pkinative cms add-timestamp [<p7s>] --token <tst|tsr> [--signer-index <n>]

sign (the new signature is verified under --cert before it is written):
  --content <file>          The content to sign
  --content-digest <hex>    Sign a precomputed digest instead (needs --detached)
  --cert <file>             The signer certificate (or the one in --p12)
  --chain <file>            Certificates to embed (repeatable)
  --crl <file>              CRLs to embed (repeatable)
  --detached                Leave the content out of the SignedData
  --content-type <oid>      eContentType (default id-data)
  --sid <issuer-serial|ski> Signer identifier form (default issuer-serial)
  --signing-time <instant|now|none>   signingTime attribute (default now)
  --no-signing-certificate  Omit ESS signing-certificate-v2 (RFC 5035)
  --no-algorithm-protection Omit CMS algorithm protection (RFC 6211)
  --signed-attribute <file>     Extra signed attribute, DER (repeatable)
  --unsigned-attribute <file>   Extra unsigned attribute, DER (repeatable)
  --output, -o <file>       Output file (default: stdout)
  --encoding <pem|der|hex>  Output encoding (default der; PEM label CMS)

verify (exit 1, E_VERIFY_FAILED, unless every signer verifies):
  --input, -i <file>        The SignedData, PEM or DER (default: positional)
  --content <file>          The content of a detached signature
  --content-digest <hex>    ... or its digest
  --trust <file>            Trust anchors (repeatable, required)
  --untrusted <file>        Extra certificates for the chains (repeatable)
  --purpose <name|oid>      Required extended key usage (repeatable)
  --crl <file> --ocsp <file> --require-revocation   Revocation evidence
  --at <instant>            Validation time (default now)
  --at-timestamp            Validate at the signer's verified time-stamp
  --require-signing-certificate  --require-algorithm-protection
  --allow-trailing          Accept bytes after the SignedData

verify-signer / add-attribute / add-timestamp:
  --signer-index <n>        Which signer (default 0)

verify-signer:
  --cert <file>             The signer certificate
  --content <file>          The content of a detached signature

add-attribute:
  --attribute <file>        One Attribute, DER

add-timestamp:
  --token <file>            A TimeStampToken or TimeStampResp that stamps the
                            signer's SIGNATURE VALUE (cms inspect --fields
                            signerInfos.signature, hash it, request the
                            time-stamp over that digest); a token over the
                            content is refused before anything is written
                            (E_INPUT, PKI_REASON_TSP_IMPRINT_MISMATCH)

add-attribute / add-timestamp:
  --output, -o <file>       Output file (default: stdout)
  --encoding <pem|der|hex>  Output encoding (default der)

verify / inspect / verify-signer:
  --format, -f <text|json>  Report format (json under --json)

${SIGNING_USAGE}`;

const TSP_USAGE = `\
pkinative tsp — RFC 3161 time-stamping, offline

Usage:
  pkinative tsp request --data <file> | --digest <hex> [--hash SHA-256]
                        [--nonce <n>|random] [--policy <oid>] [-o req.tsq]
  pkinative tsp inspect [<file>] [--as response|token|tstinfo]
  pkinative tsp verify --response <tsr> | --token <tst> --trust <roots>
                       (--request <tsq> | --data <file> | --digest <hex>)

The CLI writes the request and judges the answer; posting it to a TSA is yours
(curl --data-binary @req.tsq -H 'Content-Type: application/timestamp-query').

request:
  --data <file>             The data to time-stamp (hashed with --hash)
  --digest <hex>            ... or its digest
  --hash <SHA-256|SHA-384|SHA-512>  Imprint hash (default SHA-256)
  --nonce <n|random>        A nonce (decimal, 0x-hex, or random 63 bits)
  --policy <oid>            Requested TSA policy
  --no-cert-req             Do not ask the TSA to embed its certificate
  --output, -o <file>       Output file      --encoding <pem|der|hex> (der)
  --label <LABEL>           PEM label with --encoding pem

inspect:
  --input, -i <file>        The object (default: the positional)
  --as <response|token|tstinfo>   Skip the detection

verify (exit 1, E_VERIFY_FAILED, unless the time-stamp verifies):
  --response <file>         A TimeStampResp (or the positional)
  --token <file>            ... or a bare TimeStampToken
  --request <file>          The request: nonce and imprint must match it
  --data <file>             The time-stamped data
  --digest <hex>            ... or its digest
  --trust <file>            Trust anchors (repeatable, required)
  --untrusted <file>        Extra certificates (repeatable)
  --crl <file> --ocsp <file> --require-revocation   Revocation evidence
  --at <instant>            Validation time (default now)
  --allow-noncritical-eku   Accept a TSA whose timeStamping EKU is not critical
  --format, -f <text|json>  Report format (json under --json)
`;

const KEY_USAGE = `\
pkinative key — PKCS#8 private keys (RFC 5958, PBES2 per RFC 8018)

Usage:
  pkinative key inspect [<file>]
  pkinative key check [<file>] [--key-type <type>] [--rsa-scheme pkcs1|pss]

inspect describes a key (algorithm, curve, attributes, or the PBES2
parameters of an encrypted key) without a password. check imports it, or
decrypts it, into a non-extractable Web Crypto key to prove it is usable.
No report ever contains a key byte.

Options:
  --input, -i <file>        The key, PEM or DER (default: the positional)
  --key-type <type>         check: type of an encrypted key: ec-p256,
                            ec-p384, ec-p521, ed25519, ed448, rsa, rsa-pss
  --hash <SHA-256|SHA-384|SHA-512>  check: the digest the key will sign with
  --rsa-scheme <pkcs1|pss>  check: REQUIRED for an RSA key
  --salt-length <n>         check: RSA-PSS salt length
  --password-file <file>    check: the password, first line of the file
  --password-stdin          check: ... or the first line of stdin
                            (or PKINATIVE_PASSWORD; never on the command line)
  --format, -f <text|json>  Report format (json under --json)
`;

const P12_USAGE = `\
pkinative p12 — PKCS#12 (RFC 7292), PBES2 and PBMAC1 (RFC 9579) only

Usage:
  pkinative p12 inspect [<file>]
  pkinative p12 verify-mac [<file>]
  pkinative p12 bags [<file>]
  pkinative p12 open [<file>] [--certs-out <bundle.pem>] [--rsa-scheme ...]

inspect needs no password; the others read it from --password-file,
--password-stdin or PKINATIVE_PASSWORD. The legacy RC2 / 3DES ciphers and the
RFC 7292 Appendix B MAC are refused by doctrine (E_SECURITY); convert once
with OpenSSL 3.4 or later:
  openssl pkcs12 -in legacy.p12 -legacy -aes256 -out bundle.pem
  openssl pkcs12 -export -in bundle.pem -pbmac1_pbkdf2 -out modern.p12
(then delete bundle.pem). A wrong password is E_PASSWORD; a file without a
checkable MAC opens only with --allow-unverified-integrity. --certs-out is
written only from a file that opened. No report ever contains a key byte.

Options:
  --input, -i <file>        The PKCS#12 file (default: the positional)
  --password-file <file>    verify-mac, bags, open: the password, first line
  --password-stdin          verify-mac, bags, open: ... or stdin's first line
  --allow-unverified-integrity  open: accept a file whose MAC cannot be checked
  --rsa-scheme <pkcs1|pss>  open: import an RSA key for this scheme
  --hash <SHA-256|SHA-384|SHA-512>  open: the RSA key's digest (default SHA-256)
  --certs-out <file>        open: write the certificates and CRLs as PEM
  --format, -f <text|json>  Report format (json under --json)

verify-mac exits 1: E_PASSWORD when the MAC does not match (a wrong password
or an altered file), E_VERIFY_FAILED when the file carries no MAC; open exits 1
(E_PASSWORD on a MAC mismatch) unless everything opened.
`;

const DOCTOR_USAGE = `\
pkinative doctor — Offline preflight of the runtime

Usage:
  pkinative doctor [--format text|json]

Checks the Node.js security floor (CVE-2026-21713), the installed pkinative
against the range this CLI was built for, and whether Web Crypto can verify,
sign and decrypt. Exit 1 (E_CHECK_FAILED) when a check fails. Never online.

Options:
  --format, -f <text|json>  Report format (json under --json)
`;

const EXPLAIN_USAGE = `\
pkinative explain — Explain a code

Usage:
  pkinative explain <code>
  pkinative explain --list [--kind error|reason|diagnostic|cli]

Covers the CLI's E_* classes and pkinative's PKI_* errors (with the CLI class
and the flag that lifts each refusal), PKI_REASON_* reasons and PKI_DIAG_*
diagnostics, from the registries of the pinned pkinative release.

Options:
  --list                    List every code
  --kind <error|reason|diagnostic|cli>  With --list: one family only
  --format, -f <text|json>  Report format (json under --json)
`;

const SCHEMA_USAGE = `\
pkinative schema — The machine contract

Usage:
  pkinative schema [list]
  pkinative schema <subject>
  pkinative schema report <command> [<subcommand>]
  pkinative schema summary <command> [<subcommand>]

Subjects:
  manifest    Commands, flags, exit codes, error classes, the wire form
  errors      E_* classes and the 57 PKI_* to E_* mappings with remedies
  limits      The 22 limits: flag, kind, effective value
  status      JSON Schema of the --json success envelope
  error       JSON Schema of the --json failure envelope
  asn1-spec   JSON Schema of the asn1 encode spec
  cert-spec   JSON Schema of the cert create spec
  csr-spec    JSON Schema of the csr create spec
  config      JSON Schema of .pkinativerc.json
  cert-encode-spec  JSON Schema of each cert encode spec ($defs/<structure>)
  report      JSON Schema of the --json report of an invocation
  summary     JSON Schema of its --summary shape

JSON Schemas are draft 2020-12 with an $id versioned by the CLI release.
Report and summary schemas are generated from the TypeScript types and held
to every sample; the manifest lists each invocation's flags, operands,
outputs and envelope status fields.
`;

const COMPLETION_USAGE = `\
pkinative completion — Shell completion

Usage:
  pkinative completion <bash|zsh|fish|powershell>

Install:
  pkinative completion bash > /etc/bash_completion.d/pkinative
  pkinative completion zsh  > "\${fpath[1]}/_pkinative"
  pkinative completion fish > ~/.config/fish/completions/pkinative.fish
  pkinative completion powershell >> $PROFILE
`;

export const COMMAND_USAGE: Readonly<Record<string, string>> = {
    doctor: DOCTOR_USAGE,
    explain: EXPLAIN_USAGE,
    schema: SCHEMA_USAGE,
    completion: COMPLETION_USAGE,
    key: KEY_USAGE,
    p12: P12_USAGE,
    cms: CMS_USAGE,
    tsp: TSP_USAGE,
    crl: CRL_USAGE,
    ocsp: OCSP_USAGE,
    chain: CHAIN_USAGE,
    cert: CERT_USAGE,
    csr: CSR_USAGE,
    pem: PEM_USAGE,
    oid: OID_USAGE,
    fingerprint: FINGERPRINT_USAGE,
    asn1: ASN1_USAGE,
    limits: LIMITS_USAGE,
};
