// `pkinative pem decode|encode` — RFC 7468 textual encoding.

import { decodePem, type PemBlock } from '../core-bridge/index.js';
import { parseOptions, type Ctx } from '../context.js';
import { getIntFlag, getStringFlag } from '../utils/args.js';
import { CliError, ErrorCode, usageError } from '../utils/error.js';
import { emitArtifact, emitReport } from '../utils/output.js';
import { guard } from '../utils/pkierr.js';
import { looksLikePem, readPkiBytes } from '../utils/pki-input.js';

function inputPath(ctx: Ctx): string | undefined {
    return getStringFlag(ctx.args.flags, 'input') ?? ctx.args.positionals[0];
}

async function decode(ctx: Ctx): Promise<void> {
    const bytes = await readPkiBytes(ctx, inputPath(ctx), 'PEM text');
    const label = getStringFlag(ctx.args.flags, 'label');
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    const blocks = guard('Cannot decode PEM', () => decodePem(text, {
        ...parseOptions(ctx),
        mode: ctx.opts.pemMode,
        ...(label !== undefined ? { label } : {}),
    }));
    const index = getIntFlag(ctx.args.flags, 'index');
    if (index === undefined && ctx.args.flags['output'] !== undefined) {
        throw usageError('pem decode --output needs --index <n>: without it, the command lists the blocks on stdout.');
    }
    if (index !== undefined) {
        const block = blocks[index];
        if (block === undefined) {
            throw new CliError(`--index ${index} is out of range: the text holds ${blocks.length} block(s).`, 1, ErrorCode.NOT_FOUND);
        }
        ctx.status['label'] = block.label;
        await emitArtifact(ctx, block.bytes, { label: block.label, defaultEncoding: 'der' });
        return;
    }
    const rows = blocks.map((b: PemBlock, i) => ({ index: i, ...b }));
    ctx.status['blocks'] = rows.length;
    emitReport(ctx, { blocks: rows }, () => rows.map((b) => {
        const headers = b.headers.length > 0 ? `  headers: ${b.headers.map(([k]) => k).join(', ')}` : '';
        return `#${b.index}  ${b.label}  ${b.bytes.length} bytes  at offset ${b.offset}${headers}`;
    }).join('\n'), () => ({ blocks: rows.map((b) => ({ index: b.index, label: b.label, size: b.bytes.length })) }));
}

async function encode(ctx: Ctx): Promise<void> {
    const label = getStringFlag(ctx.args.flags, 'label');
    if (label === undefined) throw usageError('pem encode needs --label <LABEL> (e.g. CERTIFICATE, PRIVATE KEY).');
    const der = await readPkiBytes(ctx, inputPath(ctx), 'DER input');
    if (looksLikePem(der)) {
        throw new CliError('The input is already PEM text; pem encode takes DER bytes.', 1, ErrorCode.INPUT, { remedy: 'pkinative pem decode --index 0 --encoding der' });
    }
    await emitArtifact(ctx, der, { label, defaultEncoding: 'pem' });
}

export async function pem(ctx: Ctx): Promise<void> {
    if (ctx.command === 'pem decode') return decode(ctx);
    return encode(ctx);
}
