// `pkinative oid name|encode|decode|validate|list` — object identifiers.

import {
    decodeAsn1,
    decodeOid,
    encodeObjectIdentifier,
    encodeOid,
    encodeRelativeOid,
    getOidName,
    isValidOid,
    OID_REGISTRY,
    readObjectIdentifier,
    readRelativeOid,
} from '../core-bridge/index.js';
import { parseOptions, type Ctx } from '../context.js';
import { getStringFlag, hasFlag } from '../utils/args.js';
import { CliError, ErrorCode, usageError } from '../utils/error.js';
import { emitArtifact, emitReport } from '../utils/output.js';
import { guard } from '../utils/pkierr.js';
import { readPkiBytes } from '../utils/pki-input.js';
import { fromHex } from '../utils/wire.js';

function oids(ctx: Ctx): readonly string[] {
    if (ctx.args.positionals.length === 0) throw usageError(`${ctx.command} needs at least one dotted OID argument.`);
    return ctx.args.positionals;
}

async function name(ctx: Ctx): Promise<void> {
    const rows = oids(ctx).map((dotted) => {
        const n = getOidName(dotted);
        return { oid: dotted, ...(n !== undefined ? { name: n } : {}) };
    });
    emitReport(ctx, { oids: rows }, () => rows.map((r) => `${r.oid}  ${r.name ?? '(not registered)'}`).join('\n'));
}

async function encode(ctx: Ctx): Promise<void> {
    const [first, ...extra] = oids(ctx);
    if (extra.length > 0) throw usageError('oid encode takes exactly one OID.');
    const relative = hasFlag(ctx.args.flags, 'relative');
    const tlv = hasFlag(ctx.args.flags, 'tlv');
    if (relative && !tlv) throw usageError('--relative needs --tlv: pkinative encodes a RELATIVE-OID as a whole TLV only.');
    const value = first as string;
    const der = guard(`Cannot encode ${value}`, () => (relative ? encodeRelativeOid(value) : tlv ? encodeObjectIdentifier(value) : encodeOid(value)));
    ctx.status['oid'] = value;
    await emitArtifact(ctx, der, { label: undefined, defaultEncoding: 'hex' });
}

async function decode(ctx: Ctx): Promise<void> {
    const path = getStringFlag(ctx.args.flags, 'input');
    const [hex] = ctx.args.positionals;
    if ((path === undefined) === (hex === undefined)) throw usageError('oid decode takes a hex argument or --input <file>, not both.');
    let bytes: Uint8Array;
    if (hex !== undefined) {
        const parsed = fromHex(hex);
        if (parsed === undefined) throw usageError(`"${hex}" is not hexadecimal.`);
        bytes = parsed;
    } else {
        bytes = await readPkiBytes(ctx, path, 'OID bytes');
    }
    const relative = hasFlag(ctx.args.flags, 'relative');
    const tlv = hasFlag(ctx.args.flags, 'tlv');
    if (relative && !tlv) throw usageError('--relative needs --tlv: pkinative decodes a RELATIVE-OID from its TLV only.');
    const opts = parseOptions(ctx);
    const dotted = guard('Cannot decode the OID', () => {
        if (!tlv) return decodeOid(bytes, opts);
        const node = decodeAsn1(bytes, opts);
        return relative ? readRelativeOid(node, opts) : readObjectIdentifier(node, opts);
    });
    const n = relative ? undefined : getOidName(dotted);
    const report = { oid: dotted, ...(n !== undefined ? { name: n } : {}) };
    emitReport(ctx, report, () => (n !== undefined ? `${dotted}  ${n}` : dotted));
}

async function validate(ctx: Ctx): Promise<void> {
    const rows = oids(ctx).map((dotted) => ({ oid: dotted, valid: isValidOid(dotted) }));
    emitReport(ctx, { oids: rows }, () => rows.map((r) => `${r.valid ? ctx.color.ok('valid  ') : ctx.color.bad('invalid')}  ${r.oid}`).join('\n'));
    const invalid = rows.filter((r) => !r.valid).map((r) => r.oid);
    if (invalid.length > 0) {
        throw new CliError(`Invalid OID(s): ${invalid.join(', ')}`, 1, ErrorCode.CHECK_FAILED);
    }
}

async function list(ctx: Ctx): Promise<void> {
    const filter = getStringFlag(ctx.args.flags, 'filter')?.toLowerCase();
    const rows = filter === undefined
        ? OID_REGISTRY
        : OID_REGISTRY.filter((e) => [e.oid, e.name, e.standard].some((v) => v.toLowerCase().includes(filter)));
    ctx.status['count'] = rows.length;
    emitReport(ctx, { registry: rows }, () => rows.map((e) => `${e.oid.padEnd(26)} ${e.name.padEnd(36)} ${e.standard}`).join('\n'));
}

export async function oid(ctx: Ctx): Promise<void> {
    switch (ctx.command) {
        case 'oid name': return name(ctx);
        case 'oid encode': return encode(ctx);
        case 'oid decode': return decode(ctx);
        case 'oid validate': return validate(ctx);
        default: return list(ctx);
    }
}
