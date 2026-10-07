// `pkinative schema <subject>` — the machine contract, printed: JSON Schemas
// (draft 2020-12, versioned $id) of every input document and envelope, the
// capability manifest, the error catalogue and the limits.

import type { Ctx } from '../context.js';
import { INVOCATIONS, REPORT_DEFS, type InvocationShape } from '../generated/report-schemas.js';
import { CliError, ErrorCode, ERROR_CODES, usageError } from '../utils/error.js';
import { effectiveLimits, LIMIT_FLAGS } from '../utils/limits.js';
import { PKI_REMEDY, PKI_TO_CLI } from '../utils/pkierr.js';
import { serializeJson } from '../utils/projection.js';
import { CLI_VERSION, engineVersion } from '../utils/version.js';
import { CONFIG_KEYS, isConfigKey } from '../utils/config.js';
import { CLI_CODE_MEANING } from './explain.js';
import { COMMANDS, GLOBAL_FLAGS, allFlagSpecs, operandRule, type CERT_ENCODE_STRUCTURES, type FlagSpec, type OperandSpec } from './registry.js';

const DIALECT = 'https://json-schema.org/draft/2020-12/schema';
const ID = (subject: string): string => `https://github.com/Nizoka/pkinative-cli/schema/${subject}/${CLI_VERSION}`;

const hex = { type: 'string', pattern: '^(0x)?[0-9a-fA-F:\\s]*$' };
const oid = { type: 'string', pattern: '^\\d+(\\.\\d+)+$' };
const instant = { oneOf: [{ type: 'string' }, { type: 'integer' }], description: 'ISO 8601 (UTC unless zoned) or epoch milliseconds' };
const errorCode = { enum: ERROR_CODES };

const nameSchema = {
    oneOf: [
        { type: 'object', minProperties: 1, additionalProperties: { type: 'string' }, description: 'One attribute per RDN, most significant first: { "C": "FR", "CN": "x" }' },
        {
            type: 'array', minItems: 1, items: {
                type: 'array', minItems: 1, items: {
                    type: 'object', required: ['type', 'value'], additionalProperties: false,
                    properties: { type: { type: 'string' }, value: { type: 'string' }, stringType: { enum: ['utf8', 'printable', 'ia5', 'numeric'] } },
                },
            },
        },
    ],
};

const listOrObject = (key: string, items: object) => ({
    oneOf: [
        { type: 'array', items },
        { type: 'object', required: [key], properties: { [key]: { type: 'array', items }, critical: { type: 'boolean' } }, additionalProperties: false },
    ],
});

const generalNameKinds = {
    dns: { type: 'array', items: { type: 'string' } },
    email: { type: 'array', items: { type: 'string' } },
    uri: { type: 'array', items: { type: 'string' } },
    ip: { type: 'array', items: { type: 'string' } },
    registeredId: { type: 'array', items: oid },
    directoryName: { type: 'array', items: { $ref: '#/$defs/name' } },
};
/** GeneralNames alone (cert encode subject-alt-name), and as an extension, which also carries its criticality. */
const generalNames = { type: 'object', additionalProperties: false, properties: generalNameKinds };
const altNameExtension = { type: 'object', additionalProperties: false, properties: { ...generalNameKinds, critical: { type: 'boolean' } } };

const extensions = {
    type: 'object', additionalProperties: false,
    properties: {
        basicConstraints: { type: 'object', required: ['ca'], additionalProperties: false, properties: { ca: { type: 'boolean' }, pathLen: { type: 'integer', minimum: 0 }, critical: { type: 'boolean' } } },
        keyUsage: listOrObject('usages', { type: 'string' }),
        extendedKeyUsage: listOrObject('purposes', { type: 'string' }),
        subjectAltName: altNameExtension,
        issuerAltName: altNameExtension,
        subjectKeyIdentifier: { oneOf: [{ type: 'boolean' }, hex] },
        authorityKeyIdentifier: { oneOf: [{ type: 'boolean' }, hex] },
        raw: { type: 'array', items: { type: 'object', required: ['oid', 'value'], additionalProperties: false, properties: { oid, critical: { type: 'boolean' }, value: hex } } },
    },
};

function asn1Spec(): object {
    const tag = { type: 'integer', minimum: 0 };
    const cls = { enum: ['universal', 'application', 'context', 'private'] };
    const node = (type: string, properties: object, required: string[] = []) => ({
        type: 'object', required: ['type', ...required], additionalProperties: false, properties: { type: { const: type }, ...properties },
    });
    const integer = { oneOf: [{ type: 'integer' }, { type: 'string', pattern: '^-?(\\d+|0x[0-9a-fA-F]+)$' }] };
    return {
        $schema: DIALECT, $id: ID('asn1-spec'), title: 'asn1 encode node spec', $ref: '#/$defs/node',
        $defs: {
            node: {
                oneOf: [
                    node('boolean', { value: { type: 'boolean' } }, ['value']),
                    node('integer', { value: integer }, ['value']),
                    node('enumerated', { value: integer }, ['value']),
                    node('null', {}),
                    node('bit-string', { hex, unusedBits: { type: 'integer', minimum: 0, maximum: 7 } }, ['hex']),
                    node('named-bits', { bits: { type: 'array', items: { type: 'integer', minimum: 0 } } }, ['bits']),
                    node('octet-string', { hex }, ['hex']),
                    node('oid', { value: oid }, ['value']),
                    node('relative-oid', { value: { type: 'string' } }, ['value']),
                    node('string', { stringType: { enum: ['utf8', 'numeric', 'printable', 'teletex', 'ia5', 'visible', 'universal', 'bmp'] }, value: { type: 'string' } }, ['stringType', 'value']),
                    node('time', { value: instant, timeType: { enum: ['UTCTime', 'GeneralizedTime', 'rfc5280'] } }, ['value']),
                    node('sequence', { children: { type: 'array', items: { $ref: '#/$defs/node' } } }, ['children']),
                    node('set', { children: { type: 'array', items: { $ref: '#/$defs/node' } } }, ['children']),
                    node('set-of', { children: { type: 'array', items: { $ref: '#/$defs/node' } } }, ['children']),
                    node('explicit', { tag, class: cls, inner: { $ref: '#/$defs/node' } }, ['tag', 'inner']),
                    node('implicit', { tag, class: cls, inner: { $ref: '#/$defs/node' } }, ['tag', 'inner']),
                    node('tlv', { tag, class: cls, constructed: { type: 'boolean' }, hex }, ['tag', 'class', 'constructed', 'hex']),
                    node('der', { hex }, ['hex']),
                ],
            },
        },
    };
}

function certSpec(): object {
    return {
        $schema: DIALECT, $id: ID('cert-spec'), title: 'cert create spec', type: 'object', required: ['subject'], additionalProperties: false,
        properties: {
            serialNumber: { description: 'Positive serial number; omitted or "random": 127 random bits from the host CSPRNG', default: 'random', oneOf: [{ const: 'random' }, { type: 'integer', minimum: 1 }, { type: 'string', pattern: '^([1-9]\\d*|0x0*[1-9a-fA-F][0-9a-fA-F]*)$' }] },
            subject: { $ref: '#/$defs/name' },
            issuer: { $ref: '#/$defs/name' },
            notBefore: { ...instant, description: 'Start of validity (default: now)' },
            notAfter: { ...instant, description: 'End of validity; or validityDays' },
            validityDays: { type: 'integer', minimum: 1, description: 'Days of validity from notBefore', default: 365 },
            extensions,
        },
        $defs: { name: nameSchema },
    };
}

function csrSpec(): object {
    return {
        $schema: DIALECT, $id: ID('csr-spec'), title: 'csr create spec', type: 'object', required: ['subject'], additionalProperties: false,
        properties: { subject: { $ref: '#/$defs/name' }, extensions },
        $defs: { name: nameSchema },
    };
}

/** One schema per `cert encode <structure>` spec (audit B-05). */
function certEncodeSpec(): object {
    const obj = (properties: object, required: string[]): object => ({ type: 'object', required, additionalProperties: false, properties });
    const keyId = obj({ keyIdentifier: hex }, ['keyIdentifier']);
    const strings = { type: 'array', items: { type: 'string' } };
    const structures: Record<(typeof CERT_ENCODE_STRUCTURES)[number], object> = {
        'name': { $ref: '#/$defs/name' },
        'name-attribute': obj({ type: { type: 'string', description: 'short name (CN, O, C, …) or dotted OID' }, value: { type: 'string' }, stringType: { enum: ['utf8', 'printable', 'ia5', 'numeric'] } }, ['type', 'value']),
        'validity': { ...obj({ notBefore: instant, notAfter: instant, validityDays: { type: 'integer', minimum: 1 } }, ['notBefore']), not: { required: ['notAfter', 'validityDays'] }, description: 'notBefore, then notAfter or validityDays (default 365)' },
        'spki': obj({ algorithm: oid, publicKey: hex, parameters: hex }, ['algorithm', 'publicKey']),
        'algorithm-identifier': obj({ oid, parameters: hex }, ['oid']),
        'attribute': obj({ oid, values: { type: 'array', items: hex } }, ['oid', 'values']),
        'extension': obj({ oid, critical: { type: 'boolean' }, value: hex }, ['oid', 'value']),
        'extensions': extensions,
        'basic-constraints': obj({ ca: { type: 'boolean' }, pathLen: { type: 'integer', minimum: 0 } }, ['ca']),
        'key-usage': { ...strings, description: 'key usage names, e.g. ["digitalSignature", "keyCertSign"]' },
        'extended-key-usage': { ...strings, description: 'purpose names (serverAuth, …) or dotted OIDs' },
        'subject-alt-name': generalNames,
        'subject-key-identifier': keyId,
        'authority-key-identifier': keyId,
        'signature-algorithm': { not: {}, description: 'takes no --spec: the signer flags (--key or --p12, --rsa-scheme, --hash) decide it' },
    };
    return {
        $schema: DIALECT, $id: ID('cert-encode-spec'), title: 'cert encode <structure> --spec',
        description: 'One definition per structure: pkinative cert encode <structure> --spec <file> expects $defs/<structure>.',
        $defs: { ...structures, name: nameSchema },
    };
}

/** The named types `schema` references, closed over their own references. */
function defsFor(root: unknown): Record<string, object> {
    const out: Record<string, object> = {};
    const visit = (node: unknown): void => {
        if (Array.isArray(node)) {
            node.forEach(visit);
        } else if (node !== null && typeof node === 'object') {
            for (const [key, value] of Object.entries(node)) {
                if (key === '$ref' && typeof value === 'string') {
                    const name = value.replace('#/$defs/', '');
                    const def = REPORT_DEFS[name];
                    if (def !== undefined && out[name] === undefined) {
                        out[name] = def;
                        visit(def);
                    }
                } else {
                    visit(value);
                }
            }
        }
    };
    visit(root);
    return out;
}

/** `schema report <command> [<subcommand>]` and `schema summary …`: the generated shape of an invocation's stdout JSON. */
function reportSchema(ctx: Ctx, kind: 'report' | 'summary'): object {
    const invocation = ctx.args.positionals.slice(1).join(' ');
    const shape = INVOCATIONS[invocation];
    if (shape === undefined) {
        throw usageError(`schema ${kind} takes an invocation, e.g. "schema ${kind} cert inspect" or "schema ${kind} fingerprint"; got "${invocation}".`);
    }
    const body = kind === 'report' ? shape.report : shape.summary;
    if (body === undefined) {
        throw new CliError(`"${invocation}" has no ${kind === 'report' ? 'JSON report' : '--summary shape'}: it prints ${shape.outputs.join(' or ')}.`, 1, ErrorCode.NOT_FOUND);
    }
    return {
        $schema: DIALECT, $id: ID(`${kind}/${invocation.replace(' ', '/')}`),
        title: `pkinative ${invocation} --json${kind === 'summary' ? ' --summary' : ''} (stdout)`,
        description: 'Generated from the TypeScript types (scripts/build-report-schemas.ts), in the ADR 0018 wire form: bigint → decimal string, bytes → lowercase hex. Objects are open: fields are only ever added.',
        ...body,
        $defs: defsFor(body),
    };
}

function configSchema(): object {
    // The presentation keys a scope declares; any other key is refused (ADR 0007).
    const allowed = (flags: readonly FlagSpec[]): object => ({
        type: 'object',
        additionalProperties: false,
        properties: Object.fromEntries(flags.filter((f) => isConfigKey(f.name)).map((f) => [f.name, f.value === undefined ? { type: 'boolean' } : { type: ['string', 'number'] }])),
    });
    const sections: Array<[string, object]> = COMMANDS.flatMap((c) => [
        [c.name, allowed([...GLOBAL_FLAGS, ...c.flags, ...c.subcommands.flatMap((s) => s.flags)])] as [string, object],
        ...c.subcommands.map((s) => [`${c.name} ${s.name}`, allowed([...GLOBAL_FLAGS, ...s.flags])] as [string, object]),
    ]);
    // A top-level key is a default for every invocation that declares the flag (format, encoding included).
    const top = allowed(allFlagSpecs()) as { properties: object };
    return {
        $schema: DIALECT, $id: ID('config'), title: '.pkinativerc.json', type: 'object', additionalProperties: false,
        description: `Presentation defaults only (ADR 0007): ${CONFIG_KEYS.join(', ')}. A key naming a command ("cert") or a subcommand ("cert inspect") scopes its object; a default applies only where the subcommand declares the flag. Inputs, trust, time, bounds, relaxations, outputs and passwords are command-line only.`,
        properties: { ...top.properties, ...Object.fromEntries(sections) },
    };
}

function statusSchema(): object {
    return {
        $schema: DIALECT, $id: ID('status'), title: '--json success envelope (stderr)', type: 'object', required: ['ok', 'command', 'diagnostics'],
        description: 'The fields an invocation adds (valid, bytes, output, …) are listed per invocation by `pkinative schema manifest` (status) with their schemas.',
        properties: { ok: { const: true }, command: { type: 'string' }, diagnostics: { type: 'array', items: { $ref: '#/$defs/diagnostic' } }, config: { type: 'string', description: 'the .pkinativerc.json that supplied defaults (ADR 0007)' } },
        additionalProperties: true,
        $defs: { diagnostic: { type: 'object', required: ['code', 'severity', 'message', 'standard', 'path'], properties: { code: { type: 'string' }, severity: { enum: ['warning', 'info'] }, message: { type: 'string' }, standard: { type: 'string' }, path: { type: 'string' }, offset: { type: 'integer' } } } },
    };
}

function errorSchema(): object {
    return {
        $schema: DIALECT, $id: ID('error'), title: '--json failure envelope (stderr)', type: 'object', required: ['ok', 'command', 'error', 'diagnostics'],
        properties: {
            ok: { const: false },
            command: { type: ['string', 'null'] },
            error: {
                type: 'object', required: ['code', 'message'], additionalProperties: false,
                properties: { code: errorCode, message: { type: 'string' }, pkiCode: { type: 'string', pattern: '^PKI_' }, detail: { type: 'object' }, remedy: { type: 'string' }, reasons: { type: 'array' } },
            },
            diagnostics: { type: 'array' },
            config: { type: 'string', description: 'the .pkinativerc.json that supplied defaults (ADR 0007)' },
        },
    };
}

/** One invocation as the manifest describes it: flags, operands, what stdout carries, the status fields. */
function invocationEntry(name: string, summary: string, flags: readonly FlagSpec[], operands: OperandSpec, invocation: string): object {
    // Every invocation has a shape: tests/regression/report-schemas.test.ts holds the two lists equal.
    const shape = INVOCATIONS[invocation] as InvocationShape;
    return {
        name,
        summary,
        flags,
        operands: { max: Number.isFinite(operands.max) ? operands.max : null, ...(operands.for !== undefined ? { for: operands.for } : {}) },
        outputs: shape.outputs,
        report: shape.report !== undefined,
        summaryShape: shape.summary !== undefined,
        status: shape.status,
    };
}

export function manifest(): object {
    return {
        name: 'pkinative-cli',
        version: CLI_VERSION,
        pkinative: engineVersion(),
        offline: true,
        wire: { bigint: 'decimal string', bytes: 'lowercase hex', epochMilliseconds: 'number', absentOptional: 'omitted', memberNames: 'unchanged (pkinative ADR 0018)' },
        exitCodes: { 0: 'success', 1: 'failure (any E_* but E_USAGE)', 2: 'usage error (E_USAGE)', 130: 'SIGINT', 143: 'SIGTERM' },
        errorCodes: ERROR_CODES.map((code) => ({ code, meaning: CLI_CODE_MEANING[code] })),
        globalFlags: GLOBAL_FLAGS,
        commands: COMMANDS.map((c) => ({
            name: c.name,
            group: c.group,
            summary: c.summary,
            ...(c.subcommands.length > 0
                ? { subcommands: c.subcommands.map((s) => invocationEntry(s.name, s.summary, s.flags, operandRule(c, s.name), `${c.name} ${s.name}`)) }
                : invocationEntry(c.name, c.summary, c.flags, operandRule(c, undefined), c.name)),
        })),
        schemas: SUBJECTS.filter((s) => s.kind === 'schema').map((s) => s.name),
        reports: 'pkinative schema report <command> [<subcommand>]; pkinative schema summary <command> [<subcommand>]',
    };
}

function errorsCatalogue(): object {
    return {
        schemaVersion: 1,
        pkinative: '1.0.0',
        cliCodes: ERROR_CODES.map((code) => ({ code, meaning: CLI_CODE_MEANING[code] })),
        pkiToCli: Object.entries(PKI_TO_CLI).map(([pkiCode, [cliCode, exitCode]]) => ({
            pkiCode,
            cliCode,
            exitCode,
            ...(Object.hasOwn(PKI_REMEDY, pkiCode) ? { remedy: PKI_REMEDY[pkiCode as keyof typeof PKI_REMEDY] } : {}),
        })),
    };
}

export interface Subject {
    readonly name: string;
    readonly kind: 'schema' | 'document';
    readonly summary: string;
    readonly build: (ctx: Ctx) => object;
}

export const SUBJECTS: readonly Subject[] = [
    { name: 'manifest', kind: 'document', summary: 'Commands, flags, exit codes, error classes, wire form', build: () => manifest() },
    { name: 'errors', kind: 'document', summary: 'E_* classes and the 57 PKI_* → E_* mappings with remedies', build: () => errorsCatalogue() },
    { name: 'limits', kind: 'document', summary: 'The 22 limits: flag, kind, effective value', build: (ctx) => ({ limits: LIMIT_FLAGS.map((l) => ({ limit: l.key, flag: `--${l.flag}`, kind: l.kind, value: effectiveLimits(ctx.opts.limits)[l.key] })) }) },
    { name: 'status', kind: 'schema', summary: 'The --json success envelope', build: () => statusSchema() },
    { name: 'error', kind: 'schema', summary: 'The --json failure envelope', build: () => errorSchema() },
    { name: 'asn1-spec', kind: 'schema', summary: 'The asn1 encode node spec', build: () => asn1Spec() },
    { name: 'cert-spec', kind: 'schema', summary: 'The cert create spec', build: () => certSpec() },
    { name: 'csr-spec', kind: 'schema', summary: 'The csr create spec', build: () => csrSpec() },
    { name: 'config', kind: 'schema', summary: 'The .pkinativerc.json file', build: () => configSchema() },
    { name: 'cert-encode-spec', kind: 'schema', summary: 'The cert encode spec of each structure', build: () => certEncodeSpec() },
    { name: 'report', kind: 'schema', summary: 'report <command> [<sub>]: the --json report on stdout', build: (ctx) => reportSchema(ctx, 'report') },
    { name: 'summary', kind: 'schema', summary: 'summary <command> [<sub>]: the --summary shape', build: (ctx) => reportSchema(ctx, 'summary') },
];

export async function schema(ctx: Ctx): Promise<void> {
    const [subject] = ctx.args.positionals;
    if (subject !== 'report' && subject !== 'summary' && ctx.args.positionals.length > 1) throw usageError(`schema ${String(subject)} takes no further argument.`);
    if (subject === undefined || subject === 'list') {
        const rows = SUBJECTS.map((s) => ({ name: s.name, kind: s.kind, summary: s.summary }));
        const width = Math.max(...rows.map((r) => r.name.length));
        ctx.io.stdout.write(ctx.opts.json ? serializeJson({ subjects: rows }, ctx.opts.pretty) + '\n' : rows.map((r) => `${r.name.padEnd(width)} ${r.kind.padEnd(9)} ${r.summary}`).join('\n') + '\n');
        return;
    }
    const found = SUBJECTS.find((s) => s.name === subject);
    if (found === undefined) throw usageError(`Unknown schema subject "${subject}". Subjects: ${SUBJECTS.map((s) => s.name).join(', ')}.`);
    ctx.io.stdout.write(serializeJson(found.build(ctx), ctx.opts.pretty || !ctx.opts.json) + '\n');
}
