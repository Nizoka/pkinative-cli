import { describe, expect, it, vi } from 'vitest';
import { ENGINE_RANGE, NODE_RANGE, runChecks } from '../../src/commands/doctor.js';
import { catalogue } from '../../src/commands/explain.js';
import { SUBJECTS } from '../../src/commands/schema.js';
import { COMMANDS } from '../../src/commands/registry.js';
import { parseVersion, satisfies } from '../../src/utils/engines.js';
import { cli, envelope } from '../helpers/io.js';

const ALL_OK = { node: '24.14.1', engine: '1.0.0', canVerify: true, canSign: true, canDecrypt: true };

describe('version ranges', () => {
    it('evaluates ^, >= and exact clauses', () => {
        expect(satisfies('22.22.2', NODE_RANGE)).toBe(true);
        expect(satisfies('22.17.0', NODE_RANGE)).toBe(false);
        expect(satisfies('23.0.0', NODE_RANGE)).toBe(false);
        expect(satisfies('26.0.0', NODE_RANGE)).toBe(true);
        expect(satisfies('v24.20.0', NODE_RANGE)).toBe(true);
        expect(satisfies('1.4.0', ENGINE_RANGE)).toBe(true);
        expect(satisfies('2.0.0', ENGINE_RANGE)).toBe(false);
        expect(satisfies('0.3.9', '^0.3.1')).toBe(true);
        expect(satisfies('0.4.0', '^0.3.1')).toBe(false);
        expect(satisfies('1.2.3', '1.2.3')).toBe(true);
        expect(satisfies('not-a-version', '^1.0.0')).toBe(false);
        expect(() => satisfies('1.0.0', '~1.0.0')).toThrow(/Unsupported version range/);
        expect(parseVersion('x')).toBeUndefined();
    });
});

describe('doctor', () => {
    it('reads the running Node.js version', async () => {
        const { nodeVersion } = await import('../../src/utils/version.js');
        expect(nodeVersion()).toBe(process.versions.node);
    });

    it('passes a sound runtime and names each failing check', () => {
        expect(runChecks(ALL_OK).every((c) => c.ok)).toBe(true);
        const bad = runChecks({ node: '22.17.0', engine: '2.0.0', canVerify: false, canSign: false, canDecrypt: false });
        expect(bad.filter((c) => !c.ok).map((c) => c.name)).toEqual(['node', 'pkinative', 'verify', 'sign', 'decrypt']);
        expect(bad[0]?.detail).toMatch(/CVE-2026-21713/);
    });

    it('reports on both sides of the Node.js floor', async () => {
        const version = await import('../../src/utils/version.js');
        const spy = vi.spyOn(version, 'nodeVersion');
        try {
            spy.mockReturnValue('24.14.1');
            const ok = await cli(['doctor', '--json', '--max-depth', '9']);
            expect(ok.code).toBe(0);
            expect(JSON.parse(ok.stdout)).toMatchObject({ ok: true, node: '24.14.1', offline: true, commands: COMMANDS.length, changedLimits: [{ limit: 'maxDepth', value: 9 }] });
            const text = await cli(['doctor', '--max-depth', '9']);
            expect(text.stdout).toMatch(/^pkinative-cli \d+\.\d+\.\d+ \(pkinative 1\./);
            expect(text.stdout).toContain('info  limit     maxDepth = 9');
            spy.mockReturnValue('22.17.0');
            const fail = await cli(['doctor', '--json', '--summary']);
            expect(fail.code).toBe(1);
            expect(JSON.parse(fail.stdout)).toEqual({ ok: false, failed: ['node'] });
            expect(envelope(fail.stderr)).toMatchObject({ error: { code: 'E_CHECK_FAILED' } });
            expect((await cli(['doctor'])).stdout).toMatch(/FAIL {2}node/);
        } finally {
            spy.mockRestore();
        }
    });
});

describe('explain', () => {
    it('explains every family of codes', async () => {
        expect((await cli(['explain', 'PKI_ASN1_TRUNCATED', '--json'])).stdout).toMatch(/"cliCode":"E_PARSE"/);
        expect((await cli(['explain', 'pki_crypto_algorithm_refused'])).stdout).toContain('cliRemedy: --allow-sha1');
        expect((await cli(['explain', 'PKI_REASON_REVOKED'])).stdout).toMatch(/kind: reason/);
        expect((await cli(['explain', 'PKI_DIAG_SERIAL_TOO_LONG'])).stdout).toMatch(/kind: diagnostic/);
        expect((await cli(['explain', 'E_USAGE'])).stdout).toMatch(/pkiCodes: PKI_INVALID_OPTION, PKI_API_MISUSE, PKI_LIMIT_INVALID/);
    });

    it('lists codes, by family', async () => {
        const all = JSON.parse((await cli(['explain', '--list', '--json'])).stdout).codes;
        expect(all).toHaveLength(13 + 57 + 43 + 97);
        expect(JSON.parse((await cli(['explain', '--list', '--kind', 'reason', '--json', '--summary'])).stdout).codes).toHaveLength(43);
        expect((await cli(['explain', '--list', '--kind', 'cli'])).stdout.split('\n')[0]).toMatch(/^E_USAGE +cli$/);
    });

    it('refuses an unknown or missing code', async () => {
        expect(envelope((await cli(['explain', 'PKI_NOPE', '--json'])).stderr)).toMatchObject({ error: { code: 'E_NOT_FOUND' } });
        expect((await cli(['explain'])).code).toBe(2);
        expect((await cli(['explain', 'A', 'B'])).code).toBe(2);
        expect(new Set(catalogue().map((e) => e.code)).size).toBe(catalogue().length);
    });
});

describe('schema', () => {
    it('lists the subjects', async () => {
        expect((await cli(['schema'])).stdout.split('\n')[0]).toMatch(/^manifest +document/);
        expect(JSON.parse((await cli(['schema', 'list', '--json'])).stdout).subjects).toHaveLength(SUBJECTS.length);
    });

    it('prints every subject as JSON, schemas with a versioned $id', async () => {
        for (const s of SUBJECTS) {
            const doc = JSON.parse((await cli(['schema', s.name, '--json'])).stdout) as Record<string, unknown>;
            if (s.kind === 'schema') {
                expect(doc['$schema'], s.name).toBe('https://json-schema.org/draft/2020-12/schema');
                expect(doc['$id'], s.name).toMatch(new RegExp(`/schema/${s.name}/\\d+\\.\\d+\\.\\d+$`));
            }
        }
    });

    it('derives the manifest from the registry', async () => {
        const manifest = JSON.parse((await cli(['schema', 'manifest'])).stdout);
        expect(manifest.commands.map((c: { name: string }) => c.name)).toEqual(COMMANDS.map((c) => c.name));
        expect(manifest.errorCodes).toHaveLength(13);
        expect(manifest.offline).toBe(true);
        const errors = JSON.parse((await cli(['schema', 'errors'])).stdout);
        expect(errors.pkiToCli).toHaveLength(57);
        expect(JSON.parse((await cli(['schema', 'limits', '--max-depth', '7'])).stdout).limits.find((l: { limit: string }) => l.limit === 'maxDepth').value).toBe(7);
        const config = JSON.parse((await cli(['schema', 'config'])).stdout);
        expect(config.properties).toHaveProperty('pretty');
        expect(config.properties).not.toHaveProperty('allow-sha1');
        expect(config.properties.cert.properties).toHaveProperty('encoding');
    });

    it('refuses an unknown subject', async () => {
        expect((await cli(['schema', 'frob'])).code).toBe(2);
        expect((await cli(['schema', 'a', 'b'])).code).toBe(2);
    });
});

describe('completion', () => {
    it('emits a script for each shell with every command and subcommand', async () => {
        for (const shell of ['bash', 'zsh', 'fish', 'powershell', 'pwsh']) {
            const out = (await cli(['completion', shell])).stdout;
            for (const c of COMMANDS) expect(out, `${shell} ${c.name}`).toContain(c.name);
            expect(out, shell).toContain('verify-signature');
            expect(out, shell).toMatch(/--trust|-l trust/);
        }
        expect((await cli(['completion', 'fish'])).stdout).toContain('-l input -s i -r -F');
    });

    it('refuses an unknown or missing shell', async () => {
        expect((await cli(['completion'])).code).toBe(2);
        expect((await cli(['completion', 'tcsh'])).stderr).toMatch(/Unsupported shell/);
    });
});
