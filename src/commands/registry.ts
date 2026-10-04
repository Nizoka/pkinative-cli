// The single source of the CLI surface: every command, subcommand and flag.
// The parser (which flags are boolean), the unknown-flag refusal, the shell
// completions, the `schema manifest` subject and the docs-parity tests all
// derive from these tables. Pure data: no command code is loaded from here.

import { LIMIT_FLAG_NAMES } from '../utils/limits.js';

export interface FlagSpec {
    /** Long name, bare (no dashes). */
    readonly name: string;
    /** One-letter alias, bare. */
    readonly alias?: string;
    /** Value placeholder; absent for a boolean flag. */
    readonly value?: string;
    /** May be given several times. */
    readonly repeatable?: boolean;
}

export interface SubcommandSpec {
    readonly name: string;
    readonly summary: string;
    readonly flags: readonly FlagSpec[];
}

export interface CommandSpec {
    readonly name: string;
    readonly group: CommandGroup;
    readonly summary: string;
    /** Subcommands; empty when the command takes none. */
    readonly subcommands: readonly SubcommandSpec[];
    /** The command's own flags when it has no subcommands. */
    readonly flags: readonly FlagSpec[];
}

export type CommandGroup = 'Encodings' | 'Certificates' | 'Paths & revocation' | 'Signatures & time-stamps' | 'Keys' | 'Meta';

export const GLOBAL_FLAGS: readonly FlagSpec[] = [
    { name: 'help', alias: 'h' },
    { name: 'version', alias: 'V' },
    { name: 'json' },
    { name: 'pretty' },
    { name: 'quiet', alias: 'q' },
    { name: 'no-color' },
    { name: 'dry-run' },
    { name: 'strict' },
    { name: 'ber' },
    { name: 'pem-mode', value: 'strict|lax' },
    { name: 'allow-sha1' },
    { name: 'overwrite' },
    { name: 'config', value: 'file' },
    { name: 'no-config' },
    { name: 'fields', value: 'a,b.c' },
    { name: 'summary' },
    { name: 'max-content-size', value: 'size' },
    ...LIMIT_FLAG_NAMES.map((name) => ({ name, value: 'n' })),
];

// Shared flag specs, so the same flag reads the same everywhere.
const input: FlagSpec = { name: 'input', alias: 'i', value: 'file' };
const output: FlagSpec = { name: 'output', alias: 'o', value: 'file' };
const encoding: FlagSpec = { name: 'encoding', value: 'pem|der|hex' };
const format: FlagSpec = { name: 'format', alias: 'f', value: 'text|json' };
const label: FlagSpec = { name: 'label', value: 'LABEL' };
const artefact: readonly FlagSpec[] = [output, encoding];
const signing: readonly FlagSpec[] = [
    { name: 'key', value: 'file' },
    { name: 'p12', value: 'file' },
    { name: 'key-type', value: 'type' },
    { name: 'hash', value: 'SHA-256|SHA-384|SHA-512' },
    { name: 'rsa-scheme', value: 'pkcs1|pss' },
    { name: 'salt-length', value: 'n' },
    { name: 'password-file', value: 'file' },
    { name: 'password-stdin' },
];
const chainFlag: FlagSpec = { name: 'chain', value: 'file', repeatable: true };

export const COMMANDS: readonly CommandSpec[] = [
    {
        name: 'pem', group: 'Encodings', summary: 'Decode or encode RFC 7468 PEM text', flags: [], subcommands: [
            { name: 'decode', summary: 'List the PEM blocks, or extract one as DER', flags: [input, format, label, { name: 'index', value: 'n' }, ...artefact] },
            { name: 'encode', summary: 'Wrap DER bytes in a PEM block', flags: [input, output, label] },
        ],
    },
    {
        name: 'oid', group: 'Encodings', summary: 'Name, encode, decode, validate and list object identifiers', flags: [], subcommands: [
            { name: 'name', summary: 'The registered name of each OID', flags: [format] },
            { name: 'encode', summary: 'Encode a dotted OID (content octets, or TLV)', flags: [{ name: 'tlv' }, { name: 'relative' }, ...artefact] },
            { name: 'decode', summary: 'Decode OID bytes (hex argument or --input file)', flags: [input, { name: 'tlv' }, { name: 'relative' }, format] },
            { name: 'validate', summary: 'Check dotted OIDs; exit 1 when one is invalid', flags: [format] },
            { name: 'list', summary: 'The OID registry, optionally filtered', flags: [{ name: 'filter', value: 'text' }, format] },
        ],
    },
    {
        name: 'fingerprint', group: 'Encodings', summary: 'Fingerprint, key identifier or SHAKE256 of an object', subcommands: [], flags: [
            input, format,
            { name: 'alg', value: 'SHA-1|SHA-256|SHA-384|SHA-512' },
            { name: 'separator', value: 'text' },
            { name: 'case', value: 'upper|lower' },
            { name: 'webcrypto' },
            { name: 'key-id' },
            { name: 'shake256', value: 'bytes' },
        ],
    },
    {
        name: 'asn1', group: 'Encodings', summary: 'Decode DER/BER to a tree, read a value, or encode a JSON spec', flags: [], subcommands: [
            {
                name: 'decode', summary: 'Print the ASN.1 tree, read one node, or re-encode it', flags: [
                    input, format, { name: 'sequence' }, { name: 'allow-trailing' }, { name: 'path', value: 'i.j.k' },
                    { name: 'read', value: 'type' }, { name: 'string-type', value: 'type' }, { name: 'time-type', value: 'UTCTime|GeneralizedTime' },
                    { name: 'reencode' }, ...artefact,
                ],
            },
            { name: 'encode', summary: 'Encode a JSON node spec to DER', flags: [{ name: 'spec', value: 'file' }, ...artefact, label] },
        ],
    },
    {
        name: 'cert', group: 'Certificates', summary: 'Inspect, create, encode, verify and check X.509 certificates', flags: [], subcommands: [
            { name: 'inspect', summary: 'Decode a certificate (one extension with --extension)', flags: [input, format, { name: 'raw-extensions' }, { name: 'extension', value: 'kind' }] },
            { name: 'create', summary: 'Issue a certificate from a JSON spec', flags: [{ name: 'spec', value: 'file' }, { name: 'issuer', value: 'file' }, { name: 'public-key', value: 'file' }, ...signing, ...artefact] },
            { name: 'encode', summary: 'Encode one X.509 building block to DER', flags: [{ name: 'spec', value: 'file' }, ...signing, ...artefact] },
            { name: 'decode-extension', summary: 'Decode an extension value by OID', flags: [{ name: 'oid', value: 'oid' }, { name: 'value', value: 'hex' }, input, { name: 'critical' }, format] },
            { name: 'verify-signature', summary: 'Verify a signature against its issuer (or itself)', flags: [input, { name: 'issuer', value: 'file' }, { name: 'allow-algorithm-mismatch' }, format] },
            { name: 'check-name', summary: 'Check a certificate against a host name or IP (RFC 6125)', flags: [input, { name: 'host', value: 'name' }, { name: 'ip', value: 'address' }, chainFlag, { name: 'allow-cn-fallback' }, { name: 'no-wildcards' }, format] },
            { name: 'match-name', summary: 'Match a presented DNS name against a reference', flags: [{ name: 'no-wildcards' }, format] },
            { name: 'check-purpose', summary: 'Check extended key usage along a path', flags: [input, chainFlag, { name: 'purpose', value: 'name|oid' }, { name: 'no-restrict-issuers' }, { name: 'require-explicit-purpose' }, format] },
        ],
    },
    {
        name: 'csr', group: 'Certificates', summary: 'Inspect, create and verify PKCS#10 requests', flags: [], subcommands: [
            { name: 'inspect', summary: 'Decode a request', flags: [input, format, { name: 'raw-extensions' }] },
            { name: 'create', summary: 'Create a request from a JSON spec', flags: [{ name: 'spec', value: 'file' }, { name: 'public-key', value: 'file' }, ...signing, ...artefact] },
            { name: 'verify', summary: 'Verify the request self-signature', flags: [input, format] },
        ],
    },
    { name: 'limits', group: 'Meta', summary: 'The 22 pkinative security bounds: flags, defaults, effective', subcommands: [], flags: [format] },
];

/** Every command name, in table order. */
export function commandNames(): readonly string[] {
    return COMMANDS.map((c) => c.name);
}

export function findCommand(name: string): CommandSpec | undefined {
    return COMMANDS.find((c) => c.name === name);
}

/** Every flag spec any command or subcommand declares. */
export function allFlagSpecs(): readonly FlagSpec[] {
    return [...GLOBAL_FLAGS, ...COMMANDS.flatMap((c) => [...c.flags, ...c.subcommands.flatMap((s) => s.flags)])];
}

/** Every boolean flag name and alias the parser must never read a value for. */
export function booleanFlags(): ReadonlySet<string> {
    const out = new Set<string>();
    for (const f of allFlagSpecs()) {
        if (f.value !== undefined) continue;
        out.add(f.name);
        if (f.alias !== undefined) out.add(f.alias);
    }
    return out;
}

/** The flags of a command, or of one of its subcommands (validated by the dispatcher). */
export function commandFlags(command: CommandSpec, sub: string | undefined): readonly FlagSpec[] {
    return sub === undefined ? command.flags : (command.subcommands.find((s) => s.name === sub) as SubcommandSpec).flags;
}

/** Every flag name and alias accepted by a command or subcommand, global ones included. */
export function knownFlags(command: CommandSpec, sub: string | undefined): ReadonlySet<string> {
    const out = new Set<string>();
    for (const f of [...GLOBAL_FLAGS, ...commandFlags(command, sub)]) {
        out.add(f.name);
        if (f.alias !== undefined) out.add(f.alias);
    }
    return out;
}
