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

/**
 * The positional arguments an invocation takes. By default a subcommand that
 * declares --input takes at most one, standing for that flag; any other takes
 * none. An operand and the flag it stands for are never both given.
 */
export interface OperandSpec {
    /** The most positionals accepted (Infinity for a list). */
    readonly max: number;
    /** The flags an operand cannot be given with: the flag it stands for (--input, --path), or one that excludes it (explain --list). */
    readonly for?: readonly string[];
}

export interface SubcommandSpec {
    readonly name: string;
    readonly summary: string;
    readonly flags: readonly FlagSpec[];
    readonly operands?: OperandSpec;
}

export interface CommandSpec {
    readonly name: string;
    readonly group: CommandGroup;
    readonly summary: string;
    /** Subcommands; empty when the command takes none. */
    readonly subcommands: readonly SubcommandSpec[];
    /** The command's own flags when it has no subcommands. */
    readonly flags: readonly FlagSpec[];
    /** The command's operands when it has no subcommands. */
    readonly operands?: OperandSpec;
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
/** The building blocks `cert encode <structure>` encodes; `pkinative schema cert-encode-spec` describes each spec. */
export const CERT_ENCODE_STRUCTURES = [
    'name', 'name-attribute', 'validity', 'spki', 'algorithm-identifier', 'attribute', 'extension', 'extensions',
    'basic-constraints', 'key-usage', 'extended-key-usage', 'subject-alt-name', 'subject-key-identifier',
    'authority-key-identifier', 'signature-algorithm',
] as const;

/** Any number of positionals (dotted OIDs, path files). */
const LIST: OperandSpec = { max: Number.POSITIVE_INFINITY };
const chainFlag: FlagSpec = { name: 'chain', value: 'file', repeatable: true };
const pathInputs: readonly FlagSpec[] = [
    { name: 'trust', value: 'file', repeatable: true },
    { name: 'at', value: 'instant' },
    { name: 'purpose', value: 'name|oid', repeatable: true },
    { name: 'policy', value: 'oid', repeatable: true },
    { name: 'require-explicit-policy' },
    { name: 'inhibit-policy-mapping' },
    { name: 'inhibit-any-policy' },
];

export const COMMANDS: readonly CommandSpec[] = [
    {
        name: 'pem', group: 'Encodings', summary: 'Decode or encode RFC 7468 PEM text', flags: [], subcommands: [
            { name: 'decode', summary: 'List the PEM blocks, or extract one as DER', flags: [input, format, label, { name: 'index', value: 'n' }, ...artefact] },
            { name: 'encode', summary: 'Wrap DER bytes in a PEM block', flags: [input, output, label] },
        ],
    },
    {
        name: 'oid', group: 'Encodings', summary: 'Name, encode, decode, validate and list object identifiers', flags: [], subcommands: [
            { name: 'name', summary: 'The registered name of each OID', flags: [format], operands: LIST },
            { name: 'encode', summary: 'Encode a dotted OID (content octets, or TLV)', flags: [{ name: 'tlv' }, { name: 'relative' }, ...artefact], operands: LIST },
            { name: 'decode', summary: 'Decode OID bytes (hex argument or --input file)', flags: [input, { name: 'tlv' }, { name: 'relative' }, format] },
            { name: 'validate', summary: 'Check dotted OIDs; exit 1 when one is invalid', flags: [format], operands: LIST },
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
            { name: 'encode', summary: 'Encode a JSON node spec to DER', flags: [{ name: 'spec', value: 'file' }, ...artefact, label], operands: { max: 1, for: ['spec'] } },
        ],
    },
    {
        name: 'cert', group: 'Certificates', summary: 'Inspect, create, encode, verify and check X.509 certificates', flags: [], subcommands: [
            { name: 'inspect', summary: 'Decode a certificate (one extension with --extension)', flags: [input, format, { name: 'raw-extensions' }, { name: 'extension', value: 'kind' }] },
            { name: 'create', summary: 'Issue a certificate from a JSON spec', flags: [{ name: 'spec', value: 'file' }, { name: 'issuer', value: 'file' }, { name: 'public-key', value: 'file' }, ...signing, ...artefact] },
            { name: 'encode', summary: 'Encode one X.509 building block to DER', flags: [{ name: 'spec', value: 'file' }, ...signing, ...artefact], operands: { max: 1 } },
            { name: 'decode-extension', summary: 'Decode an extension value by OID', flags: [{ name: 'oid', value: 'oid' }, { name: 'value', value: 'hex' }, input, { name: 'critical' }, format], operands: { max: 0 } },
            { name: 'verify-signature', summary: 'Verify a signature against its issuer (or itself)', flags: [input, { name: 'issuer', value: 'file' }, { name: 'allow-algorithm-mismatch' }, format] },
            { name: 'check-name', summary: 'Check a certificate against a host name or IP (RFC 6125)', flags: [input, { name: 'host', value: 'name' }, { name: 'ip', value: 'address' }, chainFlag, { name: 'allow-cn-fallback' }, { name: 'no-wildcards' }, format] },
            { name: 'match-name', summary: 'Match a presented DNS name against a reference', flags: [{ name: 'no-wildcards' }, format], operands: { max: 2 } },
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
    {
        name: 'chain', group: 'Paths & revocation', summary: 'Verify, build and validate certification paths (RFC 5280)', flags: [], subcommands: [
            { name: 'verify', summary: 'One-call verdict: path, signatures, name, purpose, revocation', flags: [input, ...pathInputs, { name: 'untrusted', value: 'file', repeatable: true }, { name: 'host', value: 'name' }, { name: 'ip', value: 'address' }, { name: 'crl', value: 'file', repeatable: true }, { name: 'ocsp', value: 'file', repeatable: true }, { name: 'ocsp-nonce', value: 'hex' }, { name: 'require-ocsp-nonce' }, { name: 'require-revocation' }, format] },
            { name: 'build', summary: 'Find a path from the leaf to a trust anchor', flags: [input, ...pathInputs, { name: 'untrusted', value: 'file', repeatable: true }, format] },
            { name: 'validate', summary: 'Validate a given path, leaf first, signatures included', flags: [{ name: 'path', value: 'file', repeatable: true }, ...pathInputs, { name: 'no-signatures' }, format], operands: { ...LIST, for: ['path'] } },
        ],
    },
    {
        name: 'crl', group: 'Paths & revocation', summary: 'Inspect, search, verify and apply certificate revocation lists', flags: [], subcommands: [
            { name: 'inspect', summary: 'Decode a CRL', flags: [input, format] },
            { name: 'find', summary: 'Look a serial number up in a CRL', flags: [input, { name: 'serial', value: 'hex' }, { name: 'cert', value: 'file' }, format] },
            { name: 'verify-signature', summary: 'Verify the CRL signature against its issuer', flags: [input, { name: 'issuer', value: 'file' }, format] },
            { name: 'check', summary: 'Decide a certificate status from a CRL (and a delta)', flags: [input, { name: 'cert', value: 'file' }, { name: 'issuer', value: 'file' }, { name: 'delta', value: 'file' }, { name: 'at', value: 'instant' }, { name: 'stale-tolerance', value: 'ms' }, format] },
        ],
    },
    {
        name: 'ocsp', group: 'Paths & revocation', summary: 'Build OCSP requests and judge OCSP responses (RFC 6960)', flags: [], subcommands: [
            { name: 'request', summary: 'Build an OCSP request for a certificate', flags: [{ name: 'cert', value: 'file' }, { name: 'issuer', value: 'file' }, { name: 'hash', value: 'SHA-1|SHA-256' }, { name: 'nonce', value: 'hex|random' }, ...artefact], operands: { max: 1, for: ['cert'] } },
            { name: 'cert-id', summary: 'Encode the CertID of a certificate', flags: [{ name: 'cert', value: 'file' }, { name: 'issuer', value: 'file' }, { name: 'hash', value: 'SHA-1|SHA-256' }, ...artefact], operands: { max: 1, for: ['cert'] } },
            { name: 'inspect', summary: 'Decode an OCSP response', flags: [input, format] },
            { name: 'verify-signature', summary: 'Verify the responder signature', flags: [input, { name: 'responder', value: 'file' }, format] },
            { name: 'check', summary: 'Decide a certificate status from an OCSP response', flags: [input, { name: 'cert', value: 'file' }, { name: 'issuer', value: 'file' }, { name: 'responder', value: 'file' }, { name: 'responder-trusted' }, { name: 'hash', value: 'SHA-1|SHA-256' }, { name: 'nonce', value: 'hex' }, { name: 'require-nonce' }, { name: 'at', value: 'instant' }, { name: 'stale-tolerance', value: 'ms' }, { name: 'future-tolerance', value: 'ms' }, format] },
        ],
    },
    {
        name: 'cms', group: 'Signatures & time-stamps', summary: 'Sign, verify and inspect CMS SignedData (RFC 5652)', flags: [], subcommands: [
            { name: 'sign', summary: 'Sign content into a SignedData', flags: [{ name: 'content', value: 'file' }, { name: 'content-digest', value: 'hex' }, { name: 'cert', value: 'file' }, chainFlag, { name: 'crl', value: 'file', repeatable: true }, { name: 'detached' }, { name: 'content-type', value: 'oid' }, { name: 'sid', value: 'issuer-serial|ski' }, { name: 'signing-time', value: 'instant|now|none' }, { name: 'no-signing-certificate' }, { name: 'no-algorithm-protection' }, { name: 'signed-attribute', value: 'file', repeatable: true }, { name: 'unsigned-attribute', value: 'file', repeatable: true }, ...signing, ...artefact] },
            { name: 'verify', summary: 'Verify a SignedData: signatures, chains, time-stamps', flags: [input, { name: 'content', value: 'file' }, { name: 'content-digest', value: 'hex' }, { name: 'trust', value: 'file', repeatable: true }, { name: 'untrusted', value: 'file', repeatable: true }, { name: 'purpose', value: 'name|oid', repeatable: true }, { name: 'crl', value: 'file', repeatable: true }, { name: 'ocsp', value: 'file', repeatable: true }, { name: 'require-revocation' }, { name: 'at', value: 'instant' }, { name: 'at-timestamp' }, { name: 'require-signing-certificate' }, { name: 'require-algorithm-protection' }, { name: 'allow-trailing' }, format] },
            { name: 'inspect', summary: 'Decode a SignedData', flags: [input, { name: 'allow-trailing' }, format] },
            { name: 'verify-signer', summary: 'Verify one signer signature against a certificate', flags: [input, { name: 'cert', value: 'file' }, { name: 'signer-index', value: 'n' }, { name: 'content', value: 'file' }, format] },
            { name: 'add-attribute', summary: 'Add an unsigned attribute to a signer', flags: [input, { name: 'signer-index', value: 'n' }, { name: 'attribute', value: 'file' }, ...artefact] },
            { name: 'add-timestamp', summary: 'Add an RFC 3161 counter time-stamp to a signer', flags: [input, { name: 'signer-index', value: 'n' }, { name: 'token', value: 'file' }, ...artefact] },
        ],
    },
    {
        name: 'tsp', group: 'Signatures & time-stamps', summary: 'RFC 3161 time-stamp requests, tokens and verdicts', flags: [], subcommands: [
            { name: 'request', summary: 'Build a time-stamp request', flags: [{ name: 'data', value: 'file' }, { name: 'digest', value: 'hex' }, { name: 'hash', value: 'SHA-256|SHA-384|SHA-512' }, { name: 'nonce', value: 'n|random' }, { name: 'policy', value: 'oid' }, { name: 'no-cert-req' }, ...artefact] },
            { name: 'inspect', summary: 'Decode a response, a token or a TSTInfo', flags: [input, { name: 'as', value: 'response|token|tstinfo' }, format] },
            { name: 'verify', summary: 'Verify a time-stamp token or response', flags: [{ name: 'token', value: 'file' }, { name: 'response', value: 'file' }, { name: 'request', value: 'file' }, { name: 'data', value: 'file' }, { name: 'digest', value: 'hex' }, { name: 'trust', value: 'file', repeatable: true }, { name: 'untrusted', value: 'file', repeatable: true }, { name: 'crl', value: 'file', repeatable: true }, { name: 'ocsp', value: 'file', repeatable: true }, { name: 'require-revocation' }, { name: 'at', value: 'instant' }, { name: 'allow-noncritical-eku' }, format], operands: { max: 1, for: ['response', 'token'] } },
        ],
    },
    {
        name: 'key', group: 'Keys', summary: 'Inspect and test-import PKCS#8 private keys (never printed)', flags: [], subcommands: [
            { name: 'inspect', summary: 'Describe a key: algorithm, curve, encryption', flags: [input, format] },
            { name: 'check', summary: 'Import or decrypt a key to prove it is usable', flags: [input, { name: 'key-type', value: 'type' }, { name: 'hash', value: 'SHA-256|SHA-384|SHA-512' }, { name: 'rsa-scheme', value: 'pkcs1|pss' }, { name: 'salt-length', value: 'n' }, { name: 'password-file', value: 'file' }, { name: 'password-stdin' }, format] },
        ],
    },
    {
        name: 'p12', group: 'Keys', summary: 'Inspect, verify and open PKCS#12 files (PBES2, PBMAC1)', flags: [], subcommands: [
            { name: 'inspect', summary: 'Describe the structure without the password', flags: [input, format] },
            { name: 'verify-mac', summary: 'Verify the integrity MAC', flags: [input, { name: 'password-file', value: 'file' }, { name: 'password-stdin' }, format] },
            { name: 'bags', summary: 'List every bag, decrypting the encrypted contents', flags: [input, { name: 'password-file', value: 'file' }, { name: 'password-stdin' }, format] },
            { name: 'open', summary: 'Open: verify, decrypt, import keys, export certificates', flags: [input, { name: 'password-file', value: 'file' }, { name: 'password-stdin' }, { name: 'allow-unverified-integrity' }, { name: 'rsa-scheme', value: 'pkcs1|pss' }, { name: 'hash', value: 'SHA-256|SHA-384|SHA-512' }, { name: 'certs-out', value: 'file' }, format] },
        ],
    },
    { name: 'doctor', group: 'Meta', summary: 'Offline preflight: Node.js floor, pkinative, Web Crypto', subcommands: [], flags: [format] },
    { name: 'limits', group: 'Meta', summary: 'The 22 pkinative security bounds: flags, defaults, effective', subcommands: [], flags: [format] },
    { name: 'explain', group: 'Meta', summary: 'Explain any E_*, PKI_*, PKI_REASON_* or PKI_DIAG_* code', subcommands: [], flags: [{ name: 'list' }, { name: 'kind', value: 'error|reason|diagnostic|cli' }, format], operands: { max: 1, for: ['list'] } },
    { name: 'schema', group: 'Meta', summary: 'JSON Schemas, the capability manifest, the error catalogue', subcommands: [], flags: [], operands: { max: 3 } },
    { name: 'completion', group: 'Meta', summary: 'Shell completion script (bash, zsh, fish, powershell)', subcommands: [], flags: [], operands: { max: 1 } },
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

/** The sections a configuration file may scope: every command, and every "command subcommand". */
export function configSections(): ReadonlySet<string> {
    return new Set(COMMANDS.flatMap((c) => [c.name, ...c.subcommands.map((s) => `${c.name} ${s.name}`)]));
}

/** The flags that may be given several times (a repeatable flag has no alias: tests/docs/usage.test.ts). */
export function repeatableFlags(command: CommandSpec, sub: string | undefined): ReadonlySet<string> {
    const out = new Set<string>();
    for (const f of [...GLOBAL_FLAGS, ...commandFlags(command, sub)]) {
        if (f.repeatable === true) out.add(f.name);
    }
    return out;
}

/** The flag specs that carry an alias, so a flag and its alias are never both given. */
export function aliasedFlags(command: CommandSpec, sub: string | undefined): readonly FlagSpec[] {
    return [...GLOBAL_FLAGS, ...commandFlags(command, sub)].filter((f) => f.alias !== undefined);
}

/** The operand rule of an invocation (see OperandSpec). */
export function operandRule(command: CommandSpec, sub: string | undefined): OperandSpec {
    const spec = sub === undefined ? command.operands : (command.subcommands.find((s) => s.name === sub) as SubcommandSpec).operands;
    if (spec !== undefined) return spec;
    return commandFlags(command, sub).some((f) => f.name === 'input') ? { max: 1, for: ['input'] } : { max: 0 };
}
