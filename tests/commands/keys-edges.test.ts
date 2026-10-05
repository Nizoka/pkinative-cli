// Password sources, verdicts and output switches of `key check` and `p12`,
// pinned exactly. No report here carries a key byte (key-views.ts).

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { cli, emptyDir, envelope, fixture } from '../helpers/io.js';

const PASSWORD = 'test-only-password';
const ENV = { PKINATIVE_PASSWORD: PASSWORD };

describe('--password-stdin beside an input file', () => {
    it('key check reads the password from stdin when the key is a file', async () => {
        const r = await cli(['key', 'check', fixture('leaf.key.enc.pem'), '--key-type', 'ec-p256', '--password-stdin', '--json'], { stdin: `${PASSWORD}\n` });
        expect(r.code).toBe(0);
        expect(JSON.parse(r.stdout)).toMatchObject({ imported: true, encrypted: true });
    });

    it('p12 verify-mac reads the password from stdin when the file is named', async () => {
        const r = await cli(['p12', 'verify-mac', fixture('leaf.p12'), '--password-stdin', '--json'], { stdin: `${PASSWORD}\n` });
        expect(r.code).toBe(0);
        expect(JSON.parse(r.stdout)).toEqual({ valid: true });
    });

    it('p12 refuses --password-stdin when the file itself comes from stdin', async () => {
        for (const argv of [['p12', 'verify-mac'], ['p12', 'verify-mac', '-']]) {
            const r = await cli([...argv, '--password-stdin', '--json'], { stdin: readFileSync(fixture('leaf.p12')) });
            expect(r.code, argv.join(' ')).toBe(2);
            expect(envelope(r.stderr), argv.join(' ')).toMatchObject({ error: { code: 'E_USAGE' } });
        }
    });
});

describe('p12 verify-mac verdict', () => {
    it('exits 0 on a matching MAC', async () => {
        const r = await cli(['p12', 'verify-mac', fixture('leaf.p12'), '--json'], { env: ENV });
        expect(r.code).toBe(0);
        expect(envelope(r.stderr)).toMatchObject({ ok: true, command: 'p12 verify-mac' });
    });
});

describe('p12 open', () => {
    it('imports an RSA key under the scheme asked for', async () => {
        const pkcs1 = await cli(['p12', 'open', fixture('rsa.p12'), '--rsa-scheme', 'pkcs1', '--json'], { env: ENV });
        expect(pkcs1.code).toBe(0);
        expect(JSON.parse(pkcs1.stdout).keys[0].signingKey.algorithm).toMatchObject({ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' });
        const pss = await cli(['p12', 'open', fixture('rsa.p12'), '--rsa-scheme', 'pss', '--hash', 'SHA-384', '--json'], { env: ENV });
        expect(pss.code).toBe(0);
        expect(JSON.parse(pss.stdout).keys[0].signingKey.algorithm).toMatchObject({ name: 'RSA-PSS', hash: 'SHA-384' });
    });

    it('writes certificates only to --certs-out, and not under --dry-run', async () => {
        const plain = await cli(['p12', 'open', fixture('leaf.p12'), '--json'], { env: ENV });
        expect(plain.code).toBe(0);
        expect(JSON.parse(plain.stdout)).toMatchObject({ valid: true });
        expect(plain.stdout).not.toContain('BEGIN CERTIFICATE');
        const text = await cli(['p12', 'open', fixture('leaf.p12')], { env: ENV });
        expect(text.stdout).not.toContain('BEGIN CERTIFICATE');
        const out = join(emptyDir(), 'dry.pem');
        const dry = await cli(['p12', 'open', fixture('leaf.p12'), '--certs-out', out, '--dry-run', '--json'], { env: ENV });
        expect(dry.code).toBe(0);
        expect(existsSync(out)).toBe(false);
        expect(dry.stdout).not.toContain('BEGIN CERTIFICATE');
        expect(envelope(dry.stderr)).not.toHaveProperty('certsOut');
    });
});
