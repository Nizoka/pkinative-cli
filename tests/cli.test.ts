import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { CONFIG_FILENAME } from '../src/utils/config.js';
import { CLI_VERSION } from '../src/utils/version.js';
import { AT, cli, emptyDir, envelope, fixture } from './helpers/io.js';

describe('run: help and version', () => {
    it('prints the help with no arguments or --help', async () => {
        for (const argv of [[], ['--help'], ['-h']]) {
            const r = await cli(argv);
            expect(r.code).toBe(0);
            expect(r.stdout).toMatch(/^pkinative-cli — Official CLI/);
            expect(r.stdout).toMatch(/Commands \(\d+\):/);
        }
    });

    it('prints the version, with engine version under --json', async () => {
        expect((await cli(['--version'])).stdout).toBe(`${CLI_VERSION}\n`);
        expect((await cli(['-V'])).stdout).toBe(`${CLI_VERSION}\n`);
        const json = JSON.parse((await cli(['--version', '--json'])).stdout) as Record<string, string>;
        expect(json).toMatchObject({ name: 'pkinative-cli', version: CLI_VERSION });
        expect(json['pkinative']).toMatch(/^1\./);
        expect(JSON.parse((await cli(['-V'], { env: { PKINATIVE_JSON: '1' } })).stdout)).toHaveProperty('pkinative');
    });

    it('prints a command help', async () => {
        const r = await cli(['limits', '--help']);
        expect(r.code).toBe(0);
        expect(r.stdout).toMatch(/^pkinative limits —/);
    });
});

describe('run: usage errors', () => {
    it('refuses flags without a command', async () => {
        const r = await cli(['--quiet']);
        expect(r.code).toBe(2);
        expect(r.stderr).toMatch(/^error E_USAGE: No command given/);
    });

    it('refuses an unknown command, listing the commands', async () => {
        const r = await cli(['frobnicate']);
        expect(r.code).toBe(2);
        expect(r.stderr).toMatch(/Unknown command: frobnicate\. Commands: .*limits/);
    });

    it('refuses an unknown flag', async () => {
        const r = await cli(['limits', '--frob']);
        expect(r.code).toBe(2);
        expect(r.stderr).toMatch(/Unknown flag --frob for "limits"/);
    });

    it('refuses a literal password anywhere, before the command runs', async () => {
        const r = await cli(['limits', '--password', 'hunter2', '--json']);
        expect(r.code).toBe(2);
        const env = envelope(r.stderr);
        expect(env).toMatchObject({ ok: false, command: null, error: { code: 'E_USAGE', remedy: expect.stringMatching(/--password-file/) } });
        expect(r.stderr).not.toContain('hunter2');
    });

    it('writes a JSON envelope for usage errors under --json', async () => {
        const r = await cli(['--json', 'limits', '--max-depth', '0']);
        expect(r.code).toBe(2);
        expect(envelope(r.stderr)).toMatchObject({ ok: false, command: 'limits', error: { code: 'E_USAGE' }, diagnostics: [] });
    });
});

describe('run: a command', () => {
    it('runs limits in text and json, flags before or after the command', async () => {
        const text = await cli(['limits']);
        expect(text.code).toBe(0);
        expect(text.stdout).toMatch(/--max-input-bytes\s+67108864\s+CWE-400/);
        const json = await cli(['--max-depth', '8', 'limits', '--json']);
        expect(json.code).toBe(0);
        const report = JSON.parse(json.stdout) as { limits: { limit: string; effective: number; default: number }[] };
        expect(report.limits).toHaveLength(22);
        expect(report.limits.find((l) => l.limit === 'maxDepth')).toMatchObject({ effective: 8, default: 64 });
        expect(envelope(json.stderr)).toEqual({ ok: true, command: 'limits', diagnostics: [] });
    });

    it('marks changed bounds in text, and summarises them', async () => {
        const text = await cli(['limits', '--max-depth', '8']);
        expect(text.stdout).toMatch(/--max-depth\s+8 \(default 64\)/);
        const summary = await cli(['limits', '--json', '--summary', '--max-depth', '8']);
        expect(JSON.parse(summary.stdout)).toEqual({ changed: [{ limit: 'maxDepth', effective: 8 }] });
    });

    it('applies presentation defaults from a config file, and names the file', async () => {
        const dir = emptyDir();
        writeFileSync(join(dir, CONFIG_FILENAME), JSON.stringify({ limits: { format: 'json' } }));
        const r = await cli(['limits'], { cwd: dir });
        expect(JSON.parse(r.stdout)).toHaveProperty('limits');
        expect(r.stderr).toBe(`note: defaults from ${join(dir, CONFIG_FILENAME)}\n`);
        expect(envelope((await cli(['limits', '--json'], { cwd: dir })).stderr)).toMatchObject({ ok: true, config: join(dir, CONFIG_FILENAME) });
        expect((await cli(['limits', '--quiet'], { cwd: dir })).stderr).toBe('');
        expect((await cli(['limits', '--no-config'], { cwd: dir })).stdout).toMatch(/^--max-input-bytes/);
        const failing = await cli(['limits', '--json', '--max-depth', 'x'], { cwd: dir });
        expect(envelope(failing.stderr)).toMatchObject({ ok: false, config: join(dir, CONFIG_FILENAME) });
    });

    it('applies a default only where the subcommand declares it (audit B-02)', async () => {
        const dir = emptyDir();
        writeFileSync(join(dir, CONFIG_FILENAME), JSON.stringify({ format: 'json', cert: { format: 'json' } }));
        expect((await cli(['schema', 'list'], { cwd: dir })).code).toBe(0);
        const created = await cli(['cert', 'inspect', fixture('leaf.crt.pem')], { cwd: dir });
        expect(created.code).toBe(0);
        expect(JSON.parse(created.stdout)).toHaveProperty('serialNumber');
    });

    it('never lets a planted config change what is read, trusted, when, or how (audit A-01, V-01)', async () => {
        const planted = async (config: object, argv: readonly string[]): Promise<number> => {
            const dir = emptyDir();
            writeFileSync(join(dir, CONFIG_FILENAME), JSON.stringify(config));
            const r = await cli(argv, { cwd: dir });
            expect(r.stderr, JSON.stringify(config)).toMatch(/accepted on the command line only/);
            return r.code;
        };
        const leaf = fixture('leaf.crt.pem');
        const anchors = ['--trust', fixture('root.crt.pem'), '--untrusted', fixture('inter.crt.pem'), '--at', AT];
        // Each key below turned a failing verdict into a pass before 1.0.0.
        expect(await planted({ chain: { 'no-signatures': true } }, ['chain', 'validate', leaf, fixture('inter.crt.pem'), '--trust', fixture('root.crt.pem'), '--at', AT])).toBe(2);
        expect(await planted({ trust: fixture('root.crt.pem'), untrusted: fixture('inter.crt.pem') }, ['chain', 'verify', leaf, '--at', AT])).toBe(2);
        expect(await planted({ chain: { input: leaf } }, ['chain', 'verify', fixture('revoked.crt.pem'), ...anchors])).toBe(2);
        expect(await planted({ at: '2025-01-01T00:00:00Z' }, ['chain', 'verify', leaf, ...anchors])).toBe(2);
        expect(await planted({ crl: { 'stale-tolerance': 999999999999 } }, ['crl', 'check', fixture('inter.crl.der'), '--cert', leaf, '--issuer', fixture('inter.crt.pem')])).toBe(2);
        expect(await planted({ ocsp: { 'responder-trusted': true } }, ['ocsp', 'check', fixture('leaf.ocsp.der')])).toBe(2);
        expect(await planted({ 'max-depth': '1000' }, ['limits'])).toBe(2);
    });

    it('prints a stack trace with PKINATIVE_DEBUG=1', async () => {
        const r = await cli(['limits', '--max-depth', 'x'], { env: { PKINATIVE_DEBUG: '1' } });
        expect(r.code).toBe(2);
        expect(r.stderr).toMatch(/\n\s+at /);
    });
});

describe('run: defensive paths', () => {
    it('refuses to load a command the registry does not know', async () => {
        const { loadCommand } = await import('../src/cli.js');
        await expect(loadCommand('nope')).rejects.toMatchObject({ code: 'E_USAGE' });
    });

    it('reports a non-CliError failure as E_RUNTIME', async () => {
        const { reportFailure } = await import('../src/cli.js');
        const { memoryIo } = await import('./helpers/io.js');
        const m = memoryIo();
        expect(reportFailure(m.io, 'x', new Error('boom'), undefined, false)).toBe(1);
        expect(reportFailure(m.io, 'x', 'str', undefined, false)).toBe(1);
        expect(m.stderr()).toBe('error E_RUNTIME: boom\nerror E_RUNTIME: str\n');
    });
});

describe('run: quiet success', () => {
    it('prints nothing on stderr under --quiet', async () => {
        const r = await cli(['limits', '-q']);
        expect(r.code).toBe(0);
        expect(r.stderr).toBe('');
    });
});

describe('run: diagnostics', () => {
    it('prints the diagnostics before the error, and in the envelopes', async () => {
        const { emptyDir: tmp } = await import('./helpers/io.js');
        const dir = tmp();
        const file = join(dir, 'ber.der');
        writeFileSync(file, Buffer.from('308005000000', 'hex'));
        const failed = await cli(['asn1', 'decode', file, '--ber', '--path', '5']);
        expect(failed.stderr).toMatch(/^info PKI_DIAG_BER_CONSTRUCT_ACCEPTED: .*\nerror E_NOT_FOUND/);
        const quiet = await cli(['asn1', 'decode', file, '--ber', '--path', '5', '-q']);
        expect(quiet.stderr).toMatch(/^error E_NOT_FOUND/);
        const ok = await cli(['asn1', 'decode', file, '--ber']);
        expect(ok.stderr).toMatch(/^info PKI_DIAG_BER_CONSTRUCT_ACCEPTED/);
        const json = await cli(['asn1', 'decode', file, '--ber', '--json']);
        expect(envelope(json.stderr)).toMatchObject({ ok: true, diagnostics: [{ code: 'PKI_DIAG_BER_CONSTRUCT_ACCEPTED', severity: 'info' }] });
        const jsonFail = await cli(['asn1', 'decode', file, '--ber', '--path', '5', '--json']);
        expect(envelope(jsonFail.stderr)).toMatchObject({ ok: false, diagnostics: [{ code: 'PKI_DIAG_BER_CONSTRUCT_ACCEPTED' }] });
    });
});
