// `pkinative asn1 decode|encode` — the X.690 layer of pkinative, exposed.
//   decode   the node tree (like `openssl asn1parse`), one node read with a
//            typed reader (--read), or a node re-encoded byte for byte
//   encode   a JSON node spec → DER through the engine's encoders

import {
    decodeAsn1,
    decodeAsn1Sequence,
    encodeAsn1Node,
    getOidName,
    readBitString,
    readBoolean,
    readEnumerated,
    readInteger,
    readNull,
    readObjectIdentifier,
    readOctetString,
    readRelativeOid,
    readSmallInteger,
    readString,
    readTime,
    type Asn1Node,
    type Asn1StringType,
    type PkiParseOptions,
} from '../core-bridge/index.js';
import { parseOptions, type Ctx } from '../context.js';
import { getChoiceFlag, getStringFlag, hasFlag } from '../utils/args.js';
import { CliError, ErrorCode, usageError } from '../utils/error.js';
import { emitArtifact, emitReport } from '../utils/output.js';
import { guard } from '../utils/pkierr.js';
import { LABELS, readPkiObject } from '../utils/pki-input.js';
import { toHex, toWire } from '../utils/wire.js';
import { encodeSpec, readSpec } from './asn1-spec.js';

export const READ_TYPES = [
    'boolean', 'integer', 'small-integer', 'enumerated', 'null', 'bit-string',
    'octet-string', 'oid', 'relative-oid', 'string', 'time',
] as const;
export type ReadType = (typeof READ_TYPES)[number];

export const STRING_TYPES: readonly Asn1StringType[] = ['utf8', 'numeric', 'printable', 'teletex', 'ia5', 'visible', 'universal', 'bmp'];

const UNIVERSAL_NAMES: Readonly<Record<number, string>> = {
    1: 'BOOLEAN', 2: 'INTEGER', 3: 'BIT STRING', 4: 'OCTET STRING', 5: 'NULL', 6: 'OBJECT IDENTIFIER',
    10: 'ENUMERATED', 12: 'UTF8String', 13: 'RELATIVE-OID', 16: 'SEQUENCE', 17: 'SET', 18: 'NumericString',
    19: 'PrintableString', 20: 'TeletexString', 22: 'IA5String', 23: 'UTCTime', 24: 'GeneralizedTime',
    26: 'VisibleString', 28: 'UniversalString', 30: 'BMPString',
};

/** `SEQUENCE`, `[0]`, `[APPLICATION 3]`, `UNIVERSAL 99`. */
export function tagName(node: Asn1Node): string {
    switch (node.tagClass) {
        case 'universal': return UNIVERSAL_NAMES[node.tagNumber] ?? `UNIVERSAL ${node.tagNumber}`;
        case 'context': return `[${node.tagNumber}]`;
        default: return `[${node.tagClass.toUpperCase()} ${node.tagNumber}]`;
    }
}

const PREVIEW_BYTES = 32;

function hexPreview(bytes: Uint8Array): string {
    return bytes.length > PREVIEW_BYTES ? `${toHex(bytes.subarray(0, PREVIEW_BYTES))}… (${bytes.length} bytes)` : toHex(bytes);
}

/** A short rendering of a primitive universal value, or undefined when the reader refuses it. */
function preview(node: Asn1Node, opts: PkiParseOptions): string | undefined {
    if (node.tagClass !== 'universal' || node.constructed) return undefined;
    try {
        switch (node.tagNumber) {
            case 1: return String(readBoolean(node, opts));
            case 2: return readInteger(node, opts).toString();
            case 3: {
                const bits = readBitString(node, opts);
                return `${hexPreview(bits.bytes)}${bits.unusedBits > 0 ? ` (${bits.unusedBits} unused bits)` : ''}`;
            }
            case 4: return hexPreview(readOctetString(node, opts));
            case 5: return String(readNull(node));
            case 6: {
                const oid = readObjectIdentifier(node, opts);
                const name = getOidName(oid);
                return name === undefined ? oid : `${oid} (${name})`;
            }
            case 10: return readEnumerated(node, opts).toString();
            case 13: return readRelativeOid(node, opts);
            case 23:
            case 24: return readTime(node, opts).text;
            default: return node.tagNumber in UNIVERSAL_NAMES ? JSON.stringify(readString(node, opts).value) : undefined;
        }
    } catch {
        return `<unreadable: ${hexPreview(node.content)}>`;
    }
}

/** One line per node: offset, depth, header and content lengths, tag, value. */
export function renderTree(roots: readonly Asn1Node[], opts: PkiParseOptions): string {
    const lines: string[] = [];
    const walk = (node: Asn1Node, depth: number): void => {
        const kind = node.constructed ? 'cons' : 'prim';
        const len = node.indefinite ? 'inf' : String(node.contentLength);
        const value = preview(node, opts);
        lines.push(`${String(node.offset).padStart(5)}:d=${depth}  hl=${node.headerLength} l=${len.padStart(4)} ${kind}: ${'  '.repeat(depth)}${tagName(node)}${value !== undefined ? `  ${value}` : ''}`);
        for (const child of node.children) walk(child, depth + 1);
    };
    for (const root of roots) walk(root, 0);
    return lines.join('\n');
}

/** Follow `--path i.j.k` through the children. */
export function selectNode(root: Asn1Node, path: string): Asn1Node {
    let node = root;
    for (const step of path.split('.')) {
        if (!/^\d+$/.test(step)) throw usageError(`--path expects dot-separated child indices such as 0.2.1, got "${path}".`);
        const child = node.children[Number(step)];
        if (child === undefined) {
            throw new CliError(`--path ${path}: the node at step "${step}" has ${node.children.length} child(ren).`, 1, ErrorCode.NOT_FOUND);
        }
        node = child;
    }
    return node;
}

function readValue(ctx: Ctx, node: Asn1Node, type: ReadType): unknown {
    const opts = parseOptions(ctx);
    return guard(`Cannot read the node as ${type}`, () => {
        switch (type) {
            case 'boolean': return readBoolean(node, opts);
            case 'integer': return readInteger(node, opts);
            case 'small-integer': return readSmallInteger(node);
            case 'enumerated': return readEnumerated(node, opts);
            case 'null': return readNull(node);
            case 'bit-string': return readBitString(node, opts);
            case 'octet-string': return readOctetString(node, opts);
            case 'oid': return readObjectIdentifier(node, opts);
            case 'relative-oid': return readRelativeOid(node, opts);
            case 'string': {
                const stringType = getChoiceFlag(ctx.args.flags, 'string-type', STRING_TYPES);
                return readString(node, { ...opts, ...(stringType !== undefined ? { stringType } : {}) });
            }
            default: {
                const timeType = getChoiceFlag(ctx.args.flags, 'time-type', ['UTCTime', 'GeneralizedTime'] as const);
                return readTime(node, { ...opts, ...(timeType !== undefined ? { timeType } : {}) });
            }
        }
    });
}

async function decode(ctx: Ctx): Promise<void> {
    const path = getStringFlag(ctx.args.flags, 'input') ?? ctx.args.positionals[0];
    const obj = await readPkiObject(ctx, path, 'DER input', LABELS.any);
    const opts = { ...parseOptions(ctx), allowTrailingData: hasFlag(ctx.args.flags, 'allow-trailing') };
    const nodePath = getStringFlag(ctx.args.flags, 'path');
    const read = getChoiceFlag(ctx.args.flags, 'read', READ_TYPES);
    const reencode = hasFlag(ctx.args.flags, 'reencode');

    if (hasFlag(ctx.args.flags, 'sequence')) {
        if (nodePath !== undefined || read !== undefined || reencode) throw usageError('--sequence lists every top-level object; --path, --read and --reencode work on one tree.');
        const nodes = guard('Cannot decode the input', () => decodeAsn1Sequence(obj.der, opts));
        ctx.status['nodes'] = nodes.length;
        emitReport(ctx, { nodes }, () => renderTree(nodes, opts));
        return;
    }

    const root = guard('Cannot decode the input', () => decodeAsn1(obj.der, opts));
    const node = nodePath === undefined ? root : selectNode(root, nodePath);
    if (read !== undefined && reencode) throw usageError('--read and --reencode are separate modes; pass one.');
    if (reencode) {
        const der = guard('Cannot re-encode the node', () => encodeAsn1Node(node));
        ctx.status['identical'] = toHex(der) === toHex(node.bytes);
        await emitArtifact(ctx, der, { label: obj.label, defaultEncoding: 'der' });
        return;
    }
    if (read !== undefined) {
        const value = readValue(ctx, node, read);
        emitReport(ctx, { type: read, value }, () => {
            const wire = toWire(value);
            return typeof wire === 'object' && wire !== null ? JSON.stringify(wire, null, 2) : String(wire);
        });
        return;
    }
    emitReport(ctx, node, () => renderTree([node], opts));
}

async function encode(ctx: Ctx): Promise<void> {
    const specPath = getStringFlag(ctx.args.flags, 'spec') ?? ctx.args.positionals[0];
    if (specPath === undefined) throw usageError('asn1 encode needs --spec <file.json> (or "-" for stdin).');
    const spec = await readSpec(ctx, specPath);
    const der = encodeSpec(ctx, spec);
    await emitArtifact(ctx, der, { label: undefined, defaultEncoding: 'der' });
}

export async function asn1(ctx: Ctx): Promise<void> {
    if (ctx.command === 'asn1 decode') return decode(ctx);
    return encode(ctx);
}
