// Interoperability: what the CLI writes, a foreign implementation (OpenSSL)
// reads and verifies. Skipped when openssl is absent, unless REQUIRE_INTEROP=1
// (the conformance workflow sets it), where an absent tool is a failure.

import { execFileSync, spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { cli, emptyDir, fixture } from '../helpers/io.js';

const probe = spawnSync('openssl', ['version'], { encoding: 'utf8' });
const available = probe.status === 0;
const required = process.env['REQUIRE_INTEROP'] === '1';

function openssl(args: string[]): string {
    return execFileSync('openssl', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}

describe('OpenSSL interoperability', () => {
    it('has OpenSSL when interop is required', () => {
        if (required) expect(available, 'openssl is required (REQUIRE_INTEROP=1)').toBe(true);
    });

    it.runIf(available)('accepts the certificates and requests the CLI writes', async () => {
        const dir = emptyDir();
        const spec = join(dir, 'ca.json');
        writeFileSync(spec, JSON.stringify({ serialNumber: 1, subject: { C: 'FR', O: 'Interop', CN: 'Interop CA' }, notBefore: '2026-01-01T00:00:00Z', validityDays: 3650, extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] } }));
        for (const [key, extra] of [[fixture('leaf.key.pem'), []], [fixture('rsa.key.pem'), ['--rsa-scheme', 'pkcs1']], [fixture('rsa.key.pem'), ['--rsa-scheme', 'pss']], [fixture('ed25519.key.pem'), []]] as const) {
            const ca = join(dir, `ca-${extra.join('')}-${key.length}.pem`);
            expect((await cli(['cert', 'create', '--spec', spec, '--key', key, '-o', ca, '--overwrite', ...extra])).code).toBe(0);
            expect(openssl(['verify', '-CAfile', ca, ca]).trim()).toMatch(/: OK$/);
            const leafSpec = join(dir, 'leaf.json');
            writeFileSync(leafSpec, JSON.stringify({ subject: { CN: 'interop.example.test' }, notBefore: '2026-01-01T00:00:00Z', validityDays: 3650, extensions: { keyUsage: ['digitalSignature'], extendedKeyUsage: ['serverAuth'], subjectAltName: { dns: ['interop.example.test'], ip: ['192.0.2.9', '2001:db8::9'] } } }));
            const leaf = join(dir, 'leaf.pem');
            expect((await cli(['cert', 'create', '--spec', leafSpec, '--key', key, '--issuer', ca, '--public-key', fixture('leaf.pub.pem'), '-o', leaf, '--overwrite', ...extra])).code).toBe(0);
            expect(openssl(['verify', '-CAfile', ca, '-purpose', 'sslserver', leaf]).trim()).toMatch(/: OK$/);
            expect(openssl(['x509', '-in', leaf, '-noout', '-ext', 'subjectAltName'])).toMatch(/IP Address:2001:DB8:0:0:0:0:0:9/);
        }
        const csrSpec = join(dir, 'csr.json');
        writeFileSync(csrSpec, JSON.stringify({ subject: { CN: 'req.example.test' }, extensions: { subjectAltName: { dns: ['req.example.test'] } } }));
        const csr = join(dir, 'r.csr');
        expect((await cli(['csr', 'create', '--spec', csrSpec, '--key', fixture('leaf.key.pem'), '-o', csr])).code).toBe(0);
        expect(spawnSync('openssl', ['req', '-in', csr, '-noout', '-verify'], { encoding: 'utf8' }).stderr + spawnSync('openssl', ['req', '-in', csr, '-noout', '-verify'], { encoding: 'utf8' }).stdout).toMatch(/verify OK/i);
    });

    it.runIf(available)('verifies the CMS signatures the CLI writes', async () => {
        const dir = emptyDir();
        for (const detached of [false, true]) {
            const p7 = join(dir, `s${detached}.p7s`);
            expect((await cli(['cms', 'sign', '--content', fixture('content.txt'), '--cert', fixture('leaf.crt.pem'), '--key', fixture('leaf.key.pem'), '--chain', fixture('inter.crt.pem'), '-o', p7, ...(detached ? ['--detached'] : [])])).code).toBe(0);
            const args = ['cms', '-verify', '-binary', '-inform', 'DER', '-in', p7, '-CAfile', fixture('root.crt.pem'), '-purpose', 'any', '-out', join(dir, 'out.txt')];
            const r = spawnSync('openssl', detached ? [...args, '-content', fixture('content.txt')] : args, { encoding: 'utf8' });
            expect(r.stderr, r.stderr).toMatch(/Verification successful/);
        }
    });

    it.runIf(available)('reads the OCSP and time-stamp requests the CLI writes', async () => {
        const dir = emptyDir();
        const req = join(dir, 'req.der');
        expect((await cli(['ocsp', 'request', '--cert', fixture('leaf.crt.pem'), '--issuer', fixture('inter.crt.pem'), '--nonce', 'random', '-o', req])).code).toBe(0);
        expect(openssl(['ocsp', '-reqin', req, '-req_text'])).toMatch(/Serial Number: 1001/);
        const tsq = join(dir, 'req.tsq');
        expect((await cli(['tsp', 'request', '--data', fixture('content.txt'), '--nonce', '42', '-o', tsq])).code).toBe(0);
        expect(openssl(['ts', '-query', '-in', tsq, '-text'])).toMatch(/Nonce: 0x2A/);
    });
});
