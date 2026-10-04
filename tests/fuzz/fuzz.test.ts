// Seeded fuzzing of the CLI boundary. Whatever argv or bytes arrive, the CLI
// answers with exit 0, 1 or 2 and, under --json, one envelope whose class is
// a stable E_* code — never E_RUNTIME, which would mean an unmapped failure.

import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { COMMANDS, GLOBAL_FLAGS } from '../../src/commands/registry.js';
import { ERROR_CODES } from '../../src/utils/error.js';
import { cli, emptyDir, fixture, fixtureBytes } from '../helpers/io.js';
import { mutate, pick, prng } from '../helpers/prng.js';

function lastEnvelope(stderr: string): Record<string, unknown> | undefined {
    const line = stderr.trim().split('\n').pop();
    if (line === undefined || !line.startsWith('{')) return undefined;
    return JSON.parse(line) as Record<string, unknown>;
}

function expectStableFailure(code: number, stderr: string, label: string): void {
    expect([0, 1, 2], label).toContain(code);
    if (code === 0) return;
    const env = lastEnvelope(stderr);
    expect(env, `${label}: no envelope in ${stderr}`).toBeDefined();
    const error = (env as { error: { code: string } }).error;
    expect(ERROR_CODES, label).toContain(error.code);
    expect(error.code, `${label}: ${JSON.stringify(error)}`).not.toBe('E_RUNTIME');
}

describe('argv fuzzing', () => {
    it('answers any argv with a stable code', async () => {
        const rand = prng(0x5eed_0001);
        const out = emptyDir();
        const files = [fixture('leaf.crt.pem'), fixture('inter.crl.der'), fixture('attached.p7s'), fixture('leaf.p12'), fixture('content.txt'), join(out, 'missing')];
        const words = COMMANDS.flatMap((c) => [c.name, ...c.subcommands.map((s) => s.name)]);
        const flags = [...new Set([...GLOBAL_FLAGS, ...COMMANDS.flatMap((c) => [...c.flags, ...c.subcommands.flatMap((s) => s.flags)])].map((f) => f.name))];
        const values = ['-', '0', '1', '-1', 'x', 'pem', 'der', 'hex', 'SHA-256', '2027-01-01', '__proto__', '1.2.3', 'zz', '9'.repeat(30), ...files];
        for (let i = 0; i < 400; i++) {
            const argv: string[] = [];
            const length = 1 + Math.floor(rand() * 6);
            for (let k = 0; k < length; k++) {
                const r = rand();
                if (r < 0.35) argv.push(pick(rand, words));
                else if (r < 0.75) {
                    const name = pick(rand, flags);
                    // Every output goes to the scratch directory, never the repository.
                    if (name === 'output' || name === 'certs-out') argv.push(`--${name}`, join(out, `o${i}`));
                    else argv.push(rand() < 0.3 ? `--${name}=${pick(rand, values)}` : `--${name}`);
                } else argv.push(pick(rand, values));
            }
            if (argv.some((a) => a === '--password-stdin')) continue;
            const r = await cli([...argv, '--json'], { stdin: '' });
            expectStableFailure(r.code, r.stderr, `#${i} ${argv.join(' ')}`);
        }
    });
});

describe('input fuzzing', () => {
    const cases: [argv: string[], fixture: string][] = [
        [['cert', 'inspect'], 'leaf.crt.der'],
        [['csr', 'inspect'], 'leaf.csr.der'],
        [['crl', 'inspect'], 'inter.crl.der'],
        [['ocsp', 'inspect'], 'leaf.ocsp.der'],
        [['cms', 'inspect'], 'attached.p7s'],
        [['tsp', 'inspect'], 'content.tsr'],
        [['p12', 'inspect'], 'leaf.p12'],
        [['key', 'inspect'], 'leaf.key.der'],
        [['asn1', 'decode'], 'root.crt.der'],
        [['fingerprint', '--key-id'], 'leaf.crt.der'],
        [['pem', 'decode'], 'leaf.crt.pem'],
    ];

    for (const [argv, name] of cases) {
        it(`answers hostile ${name} for ${argv.join(' ')} with a stable code`, async () => {
            const rand = prng(name.length * 7919 + argv.length);
            const dir = emptyDir();
            const original = fixtureBytes(name);
            for (let i = 0; i < 40; i++) {
                const path = join(dir, `m${i}`);
                writeFileSync(path, mutate(rand, original));
                const r = await cli([...argv.slice(0, 2), path, ...argv.slice(2), '--json']);
                expectStableFailure(r.code, r.stderr, `${argv.join(' ')} #${i}`);
            }
        });
    }

    it('answers hostile verification inputs with a stable code', async () => {
        const rand = prng(0x5eed_0002);
        const dir = emptyDir();
        for (let i = 0; i < 30; i++) {
            const leaf = join(dir, `leaf${i}`);
            const crl = join(dir, `crl${i}`);
            writeFileSync(leaf, mutate(rand, fixtureBytes('leaf.crt.der')));
            writeFileSync(crl, mutate(rand, fixtureBytes('inter.crl.der')));
            const chain = await cli(['chain', 'verify', leaf, '--untrusted', fixture('inter.crt.der'), '--trust', fixture('root.crt.der'), '--crl', crl, '--at', '2027-01-01', '--json']);
            expectStableFailure(chain.code, chain.stderr, `chain #${i}`);
            const p7 = join(dir, `p7${i}`);
            writeFileSync(p7, mutate(rand, fixtureBytes('attached.p7s')));
            const cms = await cli(['cms', 'verify', p7, '--trust', fixture('root.crt.der'), '--at', '2027-01-01', '--json']);
            expectStableFailure(cms.code, cms.stderr, `cms #${i}`);
        }
    });
});
