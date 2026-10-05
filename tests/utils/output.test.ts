import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { DEFAULT_MAX_CONTENT_SIZE, maxInputBytes, parseOptions } from '../../src/context.js';
import { buildErrorEnvelope, buildStatusEnvelope, formatDiagnostic } from '../../src/utils/agent.js';
import { CliError } from '../../src/utils/error.js';
import { emitArtifact, emitReport, note, renderArtifact, reportFormat } from '../../src/utils/output.js';
import { makeCtx } from '../helpers/ctx.js';
import { emptyDir } from '../helpers/io.js';

describe('global options', () => {
    it('parses every global flag', () => {
        const ctx = makeCtx(['--json', '--pretty', '-q', '--dry-run', '--strict', '--ber', '--pem-mode', 'lax', '--allow-sha1', '--overwrite',
            '--fields', 'a,b', '--summary', '--max-depth', '4', '--max-content-size', '2k']);
        expect(ctx.opts).toEqual({
            json: true, pretty: true, quiet: true, dryRun: true, strict: true, ber: true, pemMode: 'lax', allowSha1: true,
            overwrite: true, fields: ['a', 'b'], summary: true, limits: { maxDepth: 4 }, maxContentSize: 2048,
        });
        expect(parseOptions(ctx)).toMatchObject({ encodingRules: 'ber', limits: { maxDepth: 4 }, strict: true });
        expect(maxInputBytes(ctx, 7)).toBe(7);
    });

    it('defaults, and honours the environment', () => {
        const ctx = makeCtx([], { env: { PKINATIVE_JSON: '1', PKINATIVE_QUIET: '1' } });
        expect(ctx.opts).toMatchObject({ json: true, quiet: true, pemMode: 'strict', fields: undefined, limits: undefined, maxContentSize: DEFAULT_MAX_CONTENT_SIZE });
        expect(parseOptions(ctx).encodingRules).toBe('der');
        expect(maxInputBytes(makeCtx(['--max-input-bytes', '10']), 7)).toBe(10);
    });

    it('routes diagnostics into the context', () => {
        const ctx = makeCtx();
        const d = { code: 'PKI_DIAG_X', severity: 'warning', message: 'm', standard: 's', path: 'p', offset: 0 };
        parseOptions(ctx).onDiagnostic?.(d as never);
        expect(ctx.diagnostics).toEqual([d]);
    });
});

describe('emitReport', () => {
    const value = { serial: 10n, der: new Uint8Array([1]), nested: { a: 1, b: 2 } };

    it('writes text by default, newline-terminated', () => {
        const ctx = makeCtx();
        emitReport(ctx, value, () => 'hello');
        emitReport(ctx, value, () => 'world\n');
        expect(ctx.mem.stdout()).toBe('hello\nworld\n');
        expect(reportFormat(ctx)).toBe('text');
    });

    it('writes compact wire JSON under --json, pretty under --format json', () => {
        const json = makeCtx(['--json']);
        emitReport(json, value, () => 'x');
        expect(json.mem.stdout()).toBe('{"serial":"10","der":"01","nested":{"a":1,"b":2}}\n');
        const fmt = makeCtx(['--format', 'json']);
        emitReport(fmt, value, () => 'x');
        expect(fmt.mem.stdout()).toContain('\n  "serial": "10"');
        expect(reportFormat(makeCtx(['--json', '--format', 'text']))).toBe('text');
    });

    it('applies --summary then --fields', () => {
        const ctx = makeCtx(['--json', '--summary', '--fields', 'n']);
        emitReport(ctx, value, () => 'x', () => ({ n: 1n, m: 2 }));
        expect(ctx.mem.stdout()).toBe('{"n":"1"}\n');
        const noSummary = makeCtx(['--json', '--summary']);
        emitReport(noSummary, { a: 1 }, () => 'x');
        expect(noSummary.mem.stdout()).toBe('{"a":1}\n');
    });
});

describe('emitArtifact', () => {
    const der = new Uint8Array([0x30, 0x00]);

    it('renders PEM, DER and hex', () => {
        expect(renderArtifact(der, 'pem', 'TEST')).toBe('-----BEGIN TEST-----\nMAA=\n-----END TEST-----\n');
        expect(renderArtifact(der, 'der', undefined)).toBe(der);
        expect(renderArtifact(der, 'hex', undefined)).toBe('3000\n');
        expect(() => renderArtifact(der, 'pem', undefined)).toThrow(/needs a PEM label/);
        expect(() => renderArtifact(der, 'pem', 'bad-label-')).toThrow(/Cannot encode PEM/);
    });

    it('writes the default encoding to stdout and records the status', async () => {
        const ctx = makeCtx();
        await emitArtifact(ctx, der, { label: 'X', defaultEncoding: 'pem' });
        expect(ctx.mem.stdout()).toContain('BEGIN X');
        expect(ctx.status).toEqual({ bytes: 2, encoding: 'pem' });
    });

    it('honours --encoding, --label and --output', async () => {
        const dir = emptyDir();
        const out = join(dir, 'o.pem');
        const ctx = makeCtx(['--encoding', 'pem', '--label', 'MINE', '-o', out]);
        await emitArtifact(ctx, der, { label: undefined, defaultEncoding: 'der' });
        expect(readFileSync(out, 'utf8')).toContain('BEGIN MINE');
        expect(ctx.status['output']).toBe(out);
    });

    it('refuses raw DER on a terminal, but not into a file or as hex', async () => {
        await expect(emitArtifact(makeCtx([], { stdoutTTY: true }), der, { label: undefined, defaultEncoding: 'der' })).rejects.toThrow(/terminal/);
        await expect(emitArtifact(makeCtx(['-o', '-'], { stdoutTTY: true }), der, { label: undefined, defaultEncoding: 'der' })).rejects.toThrow(/terminal/);
        const file = join(emptyDir(), 'x.der');
        await emitArtifact(makeCtx(['-o', file], { stdoutTTY: true }), der, { label: undefined, defaultEncoding: 'der' });
        expect(new Uint8Array(readFileSync(file))).toEqual(der);
        const hex = makeCtx(['--encoding', 'hex'], { stdoutTTY: true });
        await emitArtifact(hex, der, { label: undefined, defaultEncoding: 'der' });
        expect(hex.mem.stdout()).toBe('3000\n');
    });

    it('records no output path for stdout, absent or "-"', async () => {
        for (const argv of [[], ['-o', '-']]) {
            const ctx = makeCtx(argv);
            await emitArtifact(ctx, der, { label: 'X', defaultEncoding: 'pem' });
            expect(Object.hasOwn(ctx.status, 'output'), argv.join(' ')).toBe(false);
        }
    });

    it('writes nothing under --dry-run', async () => {
        const ctx = makeCtx(['--dry-run']);
        await emitArtifact(ctx, der, { label: 'X', defaultEncoding: 'pem' });
        expect(ctx.mem.stdout()).toBe('');
        expect(ctx.status['dryRun']).toBe(true);
    });
});

describe('note', () => {
    it('prints unless quiet or json', () => {
        const ctx = makeCtx();
        note(ctx, 'n');
        expect(ctx.mem.stderr()).toBe('n\n');
        for (const flag of ['-q', '--json']) {
            const silent = makeCtx([flag]);
            note(silent, 'n');
            expect(silent.mem.stderr()).toBe('');
        }
    });
});

describe('envelopes', () => {
    const diag = { code: 'PKI_DIAG_X', severity: 'warning', message: 'm', standard: 'RFC 5280', path: 'tbs.issuer', offset: 3 } as never;

    it('builds the failure envelope from a CliError', () => {
        const e = new CliError('bad', 1, 'E_VERIFY_FAILED', { pkiCode: 'PKI_X', detail: { n: 1 }, remedy: 'r', reasons: [{ code: 'R', n: 1n }] });
        expect(buildErrorEnvelope('chain verify', e, [diag])).toEqual({
            ok: false, command: 'chain verify',
            error: { code: 'E_VERIFY_FAILED', message: 'bad', pkiCode: 'PKI_X', detail: { n: 1 }, remedy: 'r', reasons: [{ code: 'R', n: '1' }] },
            diagnostics: [diag],
        });
        expect(buildErrorEnvelope(null, new CliError('u', 2), [])).toEqual({ ok: false, command: null, error: { code: 'E_USAGE', message: 'u' }, diagnostics: [] });
    });

    it('builds the failure envelope from anything else', () => {
        expect(buildErrorEnvelope('x', new Error('boom'), []).error).toEqual({ code: 'E_RUNTIME', message: 'boom' });
        expect(buildErrorEnvelope('x', 'str', []).error.message).toBe('str');
    });

    it('builds the success envelope', () => {
        expect(buildStatusEnvelope('pem encode', { bytes: 2n }, [])).toEqual({ ok: true, command: 'pem encode', bytes: '2', diagnostics: [] });
    });

    it('formats a diagnostic line', () => {
        expect(formatDiagnostic(diag)).toBe('warning PKI_DIAG_X at tbs.issuer: m (RFC 5280)');
        expect(formatDiagnostic({ ...(diag as object), path: '' } as never)).toBe('warning PKI_DIAG_X: m (RFC 5280)');
    });
});
