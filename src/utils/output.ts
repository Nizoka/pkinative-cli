// What a command emits. A report (an engine result) goes to stdout as text
// or as JSON in the ADR 0018 wire form; an artefact (DER bytes) goes to a
// file or to stdout as PEM, DER or hex. Diagnostics and envelopes never
// touch stdout.

import { encodePem } from '../core-bridge/index.js';
import type { Ctx } from '../context.js';
import { getChoiceFlag, getStringFlag } from './args.js';
import { usageError } from './error.js';
import { writeOutput } from './io.js';
import { guard } from './pkierr.js';
import { selectFields, serializeJson } from './projection.js';
import { toHex, toWire } from './wire.js';

export type ReportFormat = 'text' | 'json';

/** `--format` for a report command: json under the global --json, text otherwise. */
export function reportFormat(ctx: Ctx): ReportFormat {
    return getChoiceFlag(ctx.args.flags, 'format', ['text', 'json'] as const) ?? (ctx.opts.json ? 'json' : 'text');
}

/**
 * Emit a report. JSON honours --summary (when the command supplies one) and
 * --fields; text calls the command's renderer.
 */
export function emitReport(ctx: Ctx, value: unknown, text: () => string, summary?: () => unknown): void {
    if (reportFormat(ctx) === 'json') {
        let out: unknown = toWire(value);
        if (summary !== undefined && ctx.opts.summary) out = toWire(summary());
        if (ctx.opts.fields !== undefined) out = selectFields(out, ctx.opts.fields);
        ctx.io.stdout.write(serializeJson(out, ctx.opts.pretty || !ctx.opts.json) + '\n');
        return;
    }
    const body = text();
    ctx.io.stdout.write(body.endsWith('\n') ? body : body + '\n');
}

export type ArtifactEncoding = 'pem' | 'der' | 'hex';

export interface ArtifactOptions {
    /** PEM label; required unless the caller supplies --label. */
    readonly label: string | undefined;
    /** Encoding when --encoding is absent. */
    readonly defaultEncoding: ArtifactEncoding;
}

/** Render DER as the requested text or binary form. */
export function renderArtifact(der: Uint8Array, encoding: ArtifactEncoding, label: string | undefined): string | Uint8Array {
    if (encoding === 'der') return der;
    if (encoding === 'hex') return toHex(der) + '\n';
    if (label === undefined) throw usageError('--encoding pem needs a PEM label: pass --label <LABEL>, or use --encoding der|hex.');
    return guard('Cannot encode PEM', () => encodePem(label, der));
}

/**
 * Write an artefact to --output or stdout. Raw DER is refused on an
 * interactive terminal (it would garble it); --dry-run writes nothing.
 */
export async function emitArtifact(ctx: Ctx, der: Uint8Array, options: ArtifactOptions): Promise<void> {
    const encoding = getChoiceFlag(ctx.args.flags, 'encoding', ['pem', 'der', 'hex'] as const, options.defaultEncoding);
    const path = getStringFlag(ctx.args.flags, 'output', 'o');
    const label = getStringFlag(ctx.args.flags, 'label') ?? options.label;
    const data = renderArtifact(der, encoding, label);
    if (encoding === 'der' && (path === undefined || path === '-') && ctx.io.stdout.isTTY === true) {
        throw usageError('Refusing to write binary DER to a terminal: pass --output <file>, or --encoding pem|hex.');
    }
    ctx.status['bytes'] = der.length;
    ctx.status['encoding'] = encoding;
    if (path !== undefined && path !== '-') ctx.status['output'] = path;
    if (ctx.opts.dryRun) {
        ctx.status['dryRun'] = true;
        return;
    }
    await writeOutput(ctx.io, path, data, { overwrite: ctx.opts.overwrite });
}

/** A line on stderr unless --quiet. Never used for errors or envelopes. */
export function note(ctx: Ctx, line: string): void {
    if (!ctx.opts.quiet && !ctx.opts.json) ctx.io.stderr.write(line + '\n');
}
