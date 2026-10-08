// The published artefact, run as a user runs it: `node dist/cli.cjs`. Skipped
// when dist/ is absent, unless GATE_REQUIRE_ARTIFACTS=1 (the gate and CI set
// it), where a missing build is a failure rather than a silent skip.

import { spawn, spawnSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { COMMANDS } from '../../src/commands/registry.js';
import { emptyDir, fixture } from '../helpers/io.js';

const BIN = join(process.cwd(), 'dist', 'cli.cjs');
const built = existsSync(BIN);
const required = process.env['GATE_REQUIRE_ARTIFACTS'] === '1';

function run(args: string[], env: Record<string, string> = {}): { code: number | null; stdout: string; stderr: string; ms: number } {
    const start = Date.now();
    const r = spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8', env: { ...process.env, NO_COLOR: '1', ...env }, cwd: emptyDir() });
    return { code: r.status, stdout: r.stdout, stderr: r.stderr, ms: Date.now() - start };
}

describe('built binary', () => {
    it('exists when the gate requires it', () => {
        if (required) expect(built, 'dist/cli.cjs: run npm run build').toBe(true);
    });

    it.runIf(built)('starts with a shebang and keeps pkinative external', () => {
        const text = readFileSync(BIN, 'utf8');
        expect(text.startsWith('#!/usr/bin/env node\n')).toBe(true);
        expect(text).toMatch(/require\(["']pkinative["']\)/);
        expect(text).not.toMatch(/-----BEGIN [A-Z ]+-----/);
        expect(text).not.toMatch(/Co-Authored-By/i);
        expect(text).not.toMatch(/console\.(log|warn|error)\(/);
    });

    it.runIf(built)('prints its version and every command', () => {
        const pkg = JSON.parse(readFileSync('package.json', 'utf8')) as { version: string };
        expect(run(['--version']).stdout).toBe(`${pkg.version}\n`);
        const help = run(['--help']);
        expect(help.code).toBe(0);
        for (const c of COMMANDS) expect(help.stdout, c.name).toContain(`  ${c.name} `);
        const manifest = JSON.parse(run(['schema', 'manifest']).stdout) as { commands: unknown[] };
        expect(manifest.commands).toHaveLength(COMMANDS.length);
    });

    it.runIf(built)('starts within the budget', () => {
        run(['--version']);
        const { ms } = run(['--version']);
        expect(ms).toBeLessThan(3000);
    });

    it.runIf(built)('runs a real verification end to end', () => {
        const r = run(['chain', 'verify', fixture('leaf.crt.pem'), '--untrusted', fixture('inter.crt.pem'), '--trust', fixture('root.crt.pem'), '--at', '2027-01-01', '--json']);
        expect(r.code).toBe(0);
        expect(JSON.parse(r.stdout)).toMatchObject({ valid: true });
        expect(JSON.parse(r.stderr.trim())).toMatchObject({ ok: true, command: 'chain verify' });
    });

    it.runIf(built)('holds its refusal posture', () => {
        expect(run(['limits', '--password', 'x']).code).toBe(2);
        const legacy = run(['p12', 'verify-mac', fixture('legacy.p12'), '--json'], { PKINATIVE_PASSWORD: 'test-only-password' });
        expect(legacy.code).toBe(1);
        expect(JSON.parse(legacy.stderr.trim())).toMatchObject({ error: { code: 'E_SECURITY' } });
        const spec = join(emptyDir(), 's.json');
        writeFileSync(spec, JSON.stringify({ subject: { CN: 'x' } }));
        const sha1 = run(['cert', 'create', '--spec', spec, '--key', fixture('leaf.key.pem'), '--hash', 'SHA-1']);
        expect(sha1.code).toBe(2);
        expect(run(['frobnicate']).code).toBe(2);
    });

    it.runIf(built)('ends quietly when the reader closes the pipe', async () => {
        const child = spawn(process.execPath, [BIN, 'explain', '--list'], { stdio: ['ignore', 'pipe', 'pipe'] });
        let stderr = '';
        child.stderr.on('data', (d: Buffer) => { stderr += d.toString(); });
        child.stdout.once('data', () => child.stdout.destroy());
        const code = await new Promise<number | null>((resolve) => child.on('close', resolve));
        expect(code).toBe(0);
        expect(stderr).toBe('');
    });
});
