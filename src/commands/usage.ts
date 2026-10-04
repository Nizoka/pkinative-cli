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
  --config <file>   Use this .pkinativerc.json (default: nearest upward)
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
        lines.push(`  ${c.name.padEnd(12)}${c.summary}`);
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
For autonomous/agent usage see AGENTS.md.
Run \`pkinative <command> --help\` for a command's options.
`;

const LIMITS_USAGE = `\
pkinative limits — The 22 pkinative security bounds

Usage:
  pkinative limits [--max-<limit> <n>]... [--format text|json]

Prints every bound of pkinative's DEFAULT_PKI_LIMITS with the flag that raises
it, its default, the effective value under the --max-* flags given, its CWE
and what it guards, plus the CLI's own --max-content-size.

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

--pem-mode lax tolerates whitespace and missing padding (global option).
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

encode / decode:
  --tlv                     Whole TLV (tag 06, or 0D with --relative) rather
                            than the content octets
  --relative                RELATIVE-OID (X.690 §8.20); needs --tlv
  --input,  -i <file>       decode: read the bytes from a file
  --encoding <pem|der|hex>  encode: output encoding (default hex)
  --output, -o <file>       encode: write to a file (default: stdout)

list:
  --filter <text>           Keep entries whose OID, name or standard contains it

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

export const COMMAND_USAGE: Readonly<Record<string, string>> = {
    pem: PEM_USAGE,
    oid: OID_USAGE,
    fingerprint: FINGERPRINT_USAGE,
    asn1: ASN1_USAGE,
    limits: LIMITS_USAGE,
};
