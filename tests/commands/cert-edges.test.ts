// Edges of cert, csr and the x509 spec helpers that a passing exit code alone
// would not prove: each test pins one decision the command takes.
import { webcrypto } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { decodePem, parseCertificate, parseCertificationRequest } from 'pkinative';
import { serialNumber, validity } from '../../src/utils/x509-spec.js';
import { cli, emptyDir, envelope, fixture, fixtureBytes } from '../helpers/io.js';

const PASSWORD = 'test-only-password';

function file(dir: string, name: string, content: string | object): string {
    const path = join(dir, name);
    writeFileSync(path, typeof content === 'string' ? content : JSON.stringify(content));
    return path;
}

function pemCert(text: string) {
    return parseCertificate(decodePem(text)[0]!.bytes, { onDiagnostic: () => undefined });
}

/** Length of the DER element at `offset`: header size and end offset. */
function element(der: Uint8Array, offset: number): { end: number } {
    const first = der[offset + 1] as number;
    if (first < 0x80) return { end: offset + 2 + first };
    const n = first & 0x7f;
    let length = 0;
    for (let i = 0; i < n; i++) length = length * 256 + (der[offset + 2 + i] as number);
    return { end: offset + 2 + n + length };
}

function sequence(body: Uint8Array): Uint8Array {
    const n = body.length;
    const length = n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : [0x82, n >> 8, n & 0xff];
    return Uint8Array.from([0x30, ...length, ...body]);
}

/** The certificate with its outer signatureAlgorithm replaced; tbsCertificate and signature unchanged. */
function withOuterAlgorithm(der: Uint8Array, algorithm: Uint8Array): Uint8Array {
    const tbsAt = der[1] as number >= 0x80 ? 2 + ((der[1] as number) & 0x7f) : 2;
    const tbsEnd = element(der, tbsAt).end;
    const algEnd = element(der, tbsEnd).end;
    return sequence(Uint8Array.from([...der.subarray(tbsAt, tbsEnd), ...algorithm, ...der.subarray(algEnd)]));
}

describe('cert verify-signature: the algorithm match', () => {
    it('refuses differing signatureAlgorithm fields unless --allow-algorithm-mismatch', async () => {
        const dir = emptyDir();
        // ecdsa-with-SHA256 with an explicit NULL: the signature still verifies, the fields differ.
        const path = join(dir, 'mismatch.der');
        writeFileSync(path, withOuterAlgorithm(fixtureBytes('leaf.crt.der'), Buffer.from('300c06082a8648ce3d0403020500', 'hex')));
        const strict = await cli(['cert', 'verify-signature', path, '--issuer', fixture('inter.crt.pem'), '--json']);
        expect(strict.code).toBe(1);
        expect(JSON.parse(strict.stdout)).toEqual({ valid: false, selfSigned: false });
        expect(envelope(strict.stderr)).toMatchObject({ error: { code: 'E_VERIFY_FAILED' } });
        const lenient = await cli(['cert', 'verify-signature', path, '--issuer', fixture('inter.crt.pem'), '--allow-algorithm-mismatch', '--json']);
        expect(lenient.code).toBe(0);
        expect(JSON.parse(lenient.stdout)).toEqual({ valid: true, selfSigned: false });
    });
});

describe('cert check-name / match-name / check-purpose: options that change the verdict', () => {
    it('gives the commonName fallback the path when one --chain certificate is given', async () => {
        const base = ['cert', 'check-name', fixture('ed25519.crt.pem'), '--host', 'Test Ed25519 Root', '--allow-cn-fallback'];
        // Without a path the fallback cannot apply name constraints, so it refuses.
        expect((await cli(base)).code).toBe(1);
        const withPath = await cli([...base, '--chain', fixture('root.crt.pem')]);
        expect(withPath.code).toBe(0);
        expect(withPath.stdout).toBe('name Test Ed25519 Root: valid\n');
    });

    it('exits 0 on a match', async () => {
        const r = await cli(['cert', 'match-name', '*.example.test', 'a.example.test', '--json']);
        expect(r.code).toBe(0);
        expect(JSON.parse(r.stdout)).toEqual({ match: true });
        expect(envelope(r.stderr)).toMatchObject({ ok: true });
    });

    it('holds the issuers to the purpose unless --no-restrict-issuers', async () => {
        // tsa.crt.pem carries the extended key usage timeStamping only.
        const base = ['cert', 'check-purpose', fixture('leaf.crt.pem'), '--purpose', 'serverAuth', '--chain', fixture('tsa.crt.pem')];
        const restricted = await cli([...base, '--json']);
        expect(restricted.code).toBe(1);
        expect(envelope(restricted.stderr)).toMatchObject({ error: { code: 'E_CHECK_FAILED', reasons: [{ code: 'PKI_REASON_PURPOSE_NOT_PERMITTED', path: 'path[1].extKeyUsage' }] } });
        const free = await cli([...base, '--no-restrict-issuers', '--json']);
        expect(free.code).toBe(0);
        expect(JSON.parse(free.stdout)).toEqual({ valid: true, reasons: [] });
    });
});

describe('cert encode: the structure name', () => {
    it('refuses an unknown structure even with a spec', async () => {
        const dir = emptyDir();
        const r = await cli(['cert', 'encode', 'frob', '--spec', file(dir, 's.json', { keyIdentifier: 'a1b2' }), '--json']);
        expect(r.code).toBe(2);
        expect(r.stdout).toBe('');
        expect(envelope(r.stderr)).toMatchObject({ error: { code: 'E_USAGE', message: expect.stringContaining('cert encode takes one structure') } });
    });
});

describe('cert create: issuer, key hint and status', () => {
    it('derives the key type of an encrypted self-signing key from --public-key', async () => {
        const dir = emptyDir();
        const spec = file(dir, 's.json', { subject: { CN: 'self' }, notBefore: '2026-01-01T00:00:00Z' });
        const r = await cli(['cert', 'create', '--spec', spec, '--key', fixture('leaf.key.enc.pem'), '--public-key', fixture('leaf.pub.pem'), '--json'], { env: { PKINATIVE_PASSWORD: PASSWORD } });
        expect(r.code).toBe(0);
        expect(envelope(r.stderr)).toMatchObject({ ok: true, selfSigned: true, signatureVerified: true });
        expect(pemCert(r.stdout).signatureAlgorithm.oid).toBe('1.2.840.10045.4.3.2');
    });

    it('takes no key type from --public-key when the spec names another issuer', async () => {
        const dir = emptyDir();
        const spec = file(dir, 's.json', { subject: { CN: 'x' }, issuer: { CN: 'Someone Else' }, notBefore: '2026-01-01T00:00:00Z' });
        const r = await cli(['cert', 'create', '--spec', spec, '--key', fixture('leaf.key.enc.pem'), '--public-key', fixture('leaf.pub.pem'), '--json'], { env: { PKINATIVE_PASSWORD: PASSWORD } });
        expect(r.code).toBe(2);
        expect(envelope(r.stderr)).toMatchObject({ error: { code: 'E_USAGE', message: expect.stringMatching(/needs its type/) } });
    });

    it('reads the password from stdin when the spec is a file', async () => {
        const dir = emptyDir();
        const spec = file(dir, 's.json', { subject: { CN: 'stdin' }, notBefore: '2026-01-01T00:00:00Z' });
        const r = await cli(['cert', 'create', '--spec', spec, '--key', fixture('leaf.key.enc.pem'), '--key-type', 'ec-p256', '--public-key', fixture('leaf.pub.pem'), '--password-stdin'], { stdin: `${PASSWORD}\n` });
        expect(r.code).toBe(0);
        expect(pemCert(r.stdout).subject.rdns).toHaveLength(1);
    });

    it('writes the issuer the spec names', async () => {
        const dir = emptyDir();
        const spec = file(dir, 's.json', { subject: { CN: 'x' }, issuer: { O: 'Elsewhere', CN: 'Someone Else' }, notBefore: '2026-01-01T00:00:00Z' });
        const r = await cli(['cert', 'create', '--spec', spec, '--key', fixture('leaf.key.pem'), '--public-key', fixture('ed25519.crt.pem')]);
        expect(r.code).toBe(0);
        const cert = pemCert(r.stdout);
        expect(cert.issuer.rdns.flat().map((a) => a.value?.value)).toEqual(['Elsewhere', 'Someone Else']);
        expect(cert.subject.rdns.flat().map((a) => a.value?.value)).toEqual(['x']);
    });

    it('warns about an unverified signature only when the issuer comes from the spec', async () => {
        const dir = emptyDir();
        const self = await cli(['cert', 'create', '--spec', file(dir, 'self.json', { subject: { CN: 'x' }, notBefore: '2026-01-01T00:00:00Z' }), '--key', fixture('ed25519.key.pem')]);
        expect(self.code).toBe(0);
        expect(self.stderr).toBe('');
        const issued = await cli(['cert', 'create', '--spec', file(dir, 'leaf.json', { subject: { CN: 'l' }, notBefore: '2026-01-01T00:00:00Z' }), '--key', fixture('ed25519.key.pem'), '--issuer', fixture('ed25519.crt.pem'), '--public-key', fixture('leaf.pub.pem')]);
        expect(issued.code).toBe(0);
        expect(issued.stderr).toBe('');
    });

    it('writes the extendedKeyUsage the spec asks for', async () => {
        const dir = emptyDir();
        const spec = file(dir, 's.json', { subject: { CN: 'eku' }, notBefore: '2026-01-01T00:00:00Z', extensions: { extendedKeyUsage: ['serverAuth', 'codeSigning'] } });
        const r = await cli(['cert', 'create', '--spec', spec, '--key', fixture('ed25519.key.pem')]);
        expect(r.code).toBe(0);
        const eku = pemCert(r.stdout).extensions.find((e) => e.kind === 'extendedKeyUsage');
        expect(eku?.kind === 'extendedKeyUsage' && eku.purposes).toEqual(['1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.3']);
    });
});

describe('csr: verdict and password source', () => {
    it('exits 0 on a valid request', async () => {
        const r = await cli(['csr', 'verify', fixture('leaf.csr.der'), '--json']);
        expect(r.code).toBe(0);
        expect(envelope(r.stderr)).toMatchObject({ ok: true });
    });

    it('reads the password from stdin when the spec is a file', async () => {
        const dir = emptyDir();
        const spec = file(dir, 's.json', { subject: { CN: 'req' }, extensions: { subjectAltName: { dns: ['req.example.test'] } } });
        const r = await cli(['csr', 'create', '--spec', spec, '--key', fixture('leaf.key.enc.pem'), '--public-key', fixture('leaf.pub.pem'), '--password-stdin', '-o', join(dir, 'req.pem')], { stdin: `${PASSWORD}\n` });
        expect(r.code).toBe(0);
        // One extension is one extension request.
        const req = parseCertificationRequest(decodePem(readFileSync(join(dir, 'req.pem'), 'utf8'))[0]!.bytes);
        expect(req.extensions?.map((e) => e.kind)).toEqual(['subjectAltName']);
    });
});

describe('x509 spec: serial number and default validity', () => {
    afterEach(() => {
        vi.restoreAllMocks();
    });

    it('draws a positive 16-octet serial whose first octet is in 0x01..0x7f and odd', () => {
        vi.spyOn(webcrypto, 'getRandomValues').mockImplementation(<T extends ArrayBufferView | null>(array: T): T => {
            const bytes = array as unknown as Uint8Array;
            for (let i = 0; i < bytes.length; i++) bytes[i] = i === 0 ? 0xf0 : 0x10 + i;
            return array;
        });
        const expected = BigInt(`0x71${Array.from({ length: 15 }, (_, i) => (0x11 + i).toString(16)).join('')}`);
        expect(serialNumber(undefined)).toBe(expected);
        expect(serialNumber('random')).toBe(expected);
    });

    it('starts the validity at the current second when notBefore is absent', () => {
        const v = validity({}, () => 1_700_000_000_999);
        expect(v.notBefore).toBe(1_700_000_000_000);
        expect(v.notAfter).toBe(1_700_000_000_000 + 365 * 86_400_000);
    });
});
