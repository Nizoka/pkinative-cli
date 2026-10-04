import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parseOcspResponse } from 'pkinative';
import { AT, cli, emptyDir, envelope, fixture, fixtureBytes } from '../helpers/io.js';

describe('crl', () => {
    it('inspects a CRL', async () => {
        const r = await cli(['crl', 'inspect', fixture('inter.crl.pem')]);
        expect(r.stdout).toMatch(/^CRL v2\n {2}Issuer: {7}CN=Test Intermediate CA/);
        expect(r.stdout).toContain('Entries:      1');
        expect(r.stdout).toContain('CRL number:   1');
        const summary = JSON.parse((await cli(['crl', 'inspect', fixture('inter.crl.der'), '--json', '--summary'])).stdout);
        expect(summary).toMatchObject({ crlNumber: '1', entries: 1, delta: false });
    });

    it('finds a serial, by hex or by certificate', async () => {
        expect((await cli(['crl', 'find', fixture('inter.crl.der'), '--serial', '1002'])).stdout).toBe('revoked 2026-06-01T00:00:00.000Z (keyCompromise)\n');
        expect((await cli(['crl', 'find', fixture('inter.crl.der'), '--cert', fixture('leaf.crt.pem')])).stdout).toBe('not listed\n');
        const json = await cli(['crl', 'find', fixture('inter.crl.der'), '--cert', fixture('revoked.crt.pem'), '--json']);
        expect(JSON.parse(json.stdout)).toMatchObject({ revoked: true, entry: { serialNumber: { hex: '1002' }, reason: 'keyCompromise' } });
        expect(envelope(json.stderr)).toMatchObject({ revoked: true });
        expect((await cli(['crl', 'find', fixture('inter.crl.der')])).code).toBe(2);
        expect((await cli(['crl', 'find', fixture('inter.crl.der'), '--serial', 'zz'])).code).toBe(2);
        expect((await cli(['crl', 'find', fixture('inter.crl.der'), '--serial', ''])).code).toBe(2);
    });

    it('verifies the CRL signature', async () => {
        expect((await cli(['crl', 'verify-signature', fixture('inter.crl.der'), '--issuer', fixture('inter.crt.pem')])).stdout).toBe('CRL signature: valid\n');
        const bad = await cli(['crl', 'verify-signature', fixture('inter.crl.der'), '--issuer', fixture('root.crt.pem'), '--json']);
        expect(bad.code).toBe(1);
        expect(envelope(bad.stderr)).toMatchObject({ error: { code: 'E_VERIFY_FAILED' } });
        expect((await cli(['crl', 'verify-signature', fixture('inter.crl.der')])).code).toBe(2);
    });

    it('checks a certificate against the CRL', async () => {
        const good = await cli(['crl', 'check', fixture('inter.crl.der'), '--cert', fixture('leaf.crt.pem'), '--issuer', fixture('inter.crt.pem'), '--at', AT, '--json']);
        expect(good.code).toBe(0);
        expect(JSON.parse(good.stdout)).toEqual({ valid: true, reasons: [], signatureVerified: true });
        const revoked = await cli(['crl', 'check', fixture('inter.crl.pem'), '--cert', fixture('revoked.crt.pem'), '--issuer', fixture('inter.crt.pem'), '--at', AT, '--json']);
        expect(revoked.code).toBe(1);
        expect(envelope(revoked.stderr)).toMatchObject({ error: { code: 'E_CHECK_FAILED', reasons: [{ code: 'PKI_REASON_REVOKED' }] } });
        const unverified = await cli(['crl', 'check', fixture('inter.crl.der'), '--cert', fixture('leaf.crt.pem'), '--at', AT, '--json']);
        expect(JSON.parse(unverified.stdout)).toMatchObject({ signatureVerified: null });
        const badSig = await cli(['crl', 'check', fixture('inter.crl.der'), '--cert', fixture('leaf.crt.pem'), '--issuer', fixture('root.crt.pem'), '--at', AT]);
        expect(badSig.code).toBe(1);
        expect((await cli(['crl', 'check', fixture('inter.crl.der')])).code).toBe(2);
    });

    it('applies a delta CRL, and refuses a base CRL given as one', async () => {
        const dir = emptyDir();
        const issue = async (serial: string): Promise<string> => {
            const spec = join(dir, `${serial}.json`);
            writeFileSync(spec, JSON.stringify({ serialNumber: serial, subject: { CN: serial }, notBefore: '2026-01-01T00:00:00Z' }));
            const r = await cli(['cert', 'create', '--spec', spec, '--key', fixture('ed25519.key.pem'), '--issuer', fixture('ed25519.crt.pem'), '--public-key', fixture('leaf.pub.pem'), '-o', join(dir, `${serial}.pem`)]);
            expect(r.code).toBe(0);
            return join(dir, `${serial}.pem`);
        };
        const inDelta = await issue('0x99');
        const clean = await issue('0x22');
        const base = ['crl', 'check', fixture('ed25519.crl.der'), '--issuer', fixture('ed25519.crt.pem'), '--at', AT];
        expect((await cli([...base, '--cert', inDelta])).code).toBe(0);
        const revoked = await cli([...base, '--cert', inDelta, '--delta', fixture('ed25519-delta.crl.der'), '--json']);
        expect(revoked.code).toBe(1);
        expect(JSON.parse(revoked.stdout).reasons.map((r: { code: string }) => r.code)).toContain('PKI_REASON_REVOKED');
        expect((await cli([...base, '--cert', clean, '--delta', fixture('ed25519-delta.crl.der')])).code).toBe(0);
        const unverified = await cli(['crl', 'check', fixture('ed25519.crl.der'), '--cert', clean, '--delta', fixture('ed25519-delta.crl.der'), '--at', AT]);
        expect(unverified.code).toBe(1);
        const notDelta = await cli([...base, '--cert', clean, '--delta', fixture('ed25519.crl.der'), '--json']);
        expect(envelope(notDelta.stderr)).toMatchObject({ error: { code: 'E_INPUT', message: expect.stringMatching(/not a delta CRL/) } });
    });

    it('judges staleness', async () => {
        const stale = await cli(['crl', 'check', fixture('inter.crl.der'), '--cert', fixture('leaf.crt.pem'), '--issuer', fixture('inter.crt.pem'), '--at', '2047-01-01', '--stale-tolerance', '1000']);
        expect(stale.stdout).toMatch(/PKI_REASON_/);
        expect((await cli(['crl', 'check', fixture('inter.crl.der'), '--cert', fixture('leaf.crt.pem'), '--issuer', fixture('inter.crt.pem')])).code).toBe(0);
    });
});

describe('ocsp', () => {
    it('builds a request, with nonces and hashes, and its CertID', async () => {
        const der = await cli(['ocsp', 'request', '--cert', fixture('leaf.crt.pem'), '--issuer', fixture('inter.crt.pem'), '--encoding', 'hex']);
        expect(der.stdout).toMatch(/^30[0-9a-f]+\n$/);
        const nonce = await cli(['ocsp', 'request', fixture('leaf.crt.pem'), '--issuer', fixture('inter.crt.pem'), '--nonce', 'a1b2', '--hash', 'SHA-256', '--encoding', 'hex', '--json']);
        expect(envelope(nonce.stderr)).toMatchObject({ nonce: 'a1b2' });
        expect(nonce.stdout).toContain('0402a1b2');
        const random = await cli(['ocsp', 'request', fixture('leaf.crt.pem'), '--issuer', fixture('inter.crt.pem'), '--nonce', 'random', '--encoding', 'hex', '--json']);
        expect(envelope(random.stderr)['nonce']).toMatch(/^[0-9a-f]{32}$/);
        expect((await cli(['ocsp', 'request', fixture('leaf.crt.pem'), '--issuer', fixture('inter.crt.pem'), '--nonce', 'zz'])).code).toBe(2);
        expect((await cli(['ocsp', 'request', fixture('leaf.crt.pem')])).stderr).toMatch(/needs --issuer/);
        expect((await cli(['ocsp', 'cert-id', '--cert', fixture('leaf.crt.pem'), '--issuer', fixture('inter.crt.pem')])).stdout).toMatch(/^303b300906052b0e03021a0500/);
        expect((await cli(['ocsp', 'cert-id', '--cert', fixture('leaf.crt.pem'), '--issuer', fixture('inter.crt.pem'), '--hash', 'SHA-256'])).stdout).toMatch(/^3057/);
    });

    it('inspects a response', async () => {
        const r = await cli(['ocsp', 'inspect', fixture('leaf.ocsp.der')]);
        expect(r.stdout).toMatch(/^OCSP response: successful\n/);
        expect(r.stdout).toContain('serial 1001: good');
        expect(r.stdout).toContain('Nonce:        present');
        expect((await cli(['ocsp', 'inspect', fixture('revoked.ocsp.der')])).stdout).toMatch(/serial 1002: revoked at 2026-06-01T00:00:00\.000Z/);
        expect((await cli(['ocsp', 'inspect', fixture('revoked.ocsp.der')])).stdout).toContain('Nonce:        absent');
        const summary = JSON.parse((await cli(['ocsp', 'inspect', fixture('leaf.ocsp.der'), '--json', '--summary'])).stdout);
        expect(summary).toEqual({ status: 'successful', responses: [{ serial: '1001', status: 'good' }] });
    });

    it('handles a non-successful response', async () => {
        const dir = emptyDir();
        // OCSPResponse { responseStatus tryLater (3) } with no responseBytes.
        const path = join(dir, 'later.der');
        writeFileSync(path, Buffer.from('30030a0103', 'hex'));
        expect((await cli(['ocsp', 'inspect', path])).stdout).toBe('OCSP response: tryLater\n');
        expect(JSON.parse((await cli(['ocsp', 'inspect', path, '--json', '--summary'])).stdout)).toEqual({ status: 'tryLater', responses: [] });
        expect((await cli(['ocsp', 'verify-signature', path])).stderr).toMatch(/carries no signed answer/);
        const check = await cli(['ocsp', 'check', path, '--cert', fixture('leaf.crt.pem'), '--issuer', fixture('inter.crt.pem'), '--at', AT, '--json']);
        expect(check.code).toBe(1);
        expect(JSON.parse(check.stdout)).toMatchObject({ valid: false, status: null, signatureVerified: false, responderAuthorized: false });
        expect((await cli(['ocsp', 'check', path, '--cert', fixture('leaf.crt.pem'), '--issuer', fixture('inter.crt.pem'), '--at', AT])).stdout).toMatch(/OCSP, no answer/);
    });

    it('verifies the responder signature', async () => {
        expect((await cli(['ocsp', 'verify-signature', fixture('leaf.ocsp.der'), '--json'])).stdout).toBe('{"valid":true,"signer":"CN=Test OCSP Responder,O=pkinative-cli test,C=FR"}\n');
        expect((await cli(['ocsp', 'verify-signature', fixture('leaf.ocsp.der'), '--responder', fixture('ocsp.crt.pem')])).code).toBe(0);
        const wrong = await cli(['ocsp', 'verify-signature', fixture('leaf.ocsp.der'), '--responder', fixture('root.crt.pem')]);
        expect(wrong.code).toBe(1);
        expect(wrong.stdout).toBe('OCSP signature: INVALID\n');
    });

    it('checks a good and a revoked status', async () => {
        const good = await cli(['ocsp', 'check', fixture('leaf.ocsp.der'), '--cert', fixture('leaf.crt.pem'), '--issuer', fixture('inter.crt.pem'), '--at', AT, '--json']);
        expect(good.code).toBe(0);
        expect(JSON.parse(good.stdout)).toEqual({ valid: true, reasons: [], status: 'good', signatureVerified: true, responderAuthorized: true });
        const revoked = await cli(['ocsp', 'check', fixture('revoked.ocsp.der'), '--cert', fixture('revoked.crt.pem'), '--issuer', fixture('inter.crt.pem'), '--at', AT, '--json']);
        expect(revoked.code).toBe(1);
        expect(envelope(revoked.stderr)).toMatchObject({ error: { code: 'E_CHECK_FAILED', reasons: [{ code: 'PKI_REASON_REVOKED' }] } });
    });

    it('refuses an unauthorised responder unless trusted out of band', async () => {
        const base = ['ocsp', 'check', fixture('leaf.ocsp.der'), '--cert', fixture('leaf.crt.pem'), '--issuer', fixture('root.crt.pem'), '--at', AT, '--hash', 'SHA-256', '--json'];
        const r = await cli(base);
        expect(r.code).toBe(1);
        expect(JSON.parse(r.stdout)).toMatchObject({ signatureVerified: true, responderAuthorized: false });
        const trusted = await cli([...base, '--responder-trusted']);
        expect(JSON.parse(trusted.stdout)).toMatchObject({ responderAuthorized: true });
    });

    it('treats the CA itself as an authorised responder', async () => {
        const base = ['ocsp', 'check', fixture('leaf.ocsp.der'), '--cert', fixture('leaf.crt.pem'), '--issuer', fixture('ocsp.crt.pem'), '--responder', fixture('ocsp.crt.pem'), '--at', AT, '--json'];
        expect(JSON.parse((await cli(base)).stdout)).toMatchObject({ responderAuthorized: true });
    });

    it('checks nonces, freshness and a mismatched CertID', async () => {
        const base = ['ocsp', 'check', fixture('leaf.ocsp.der'), '--cert', fixture('leaf.crt.pem'), '--issuer', fixture('inter.crt.pem')];
        expect((await cli([...base, '--at', AT, '--nonce', '00'])).code).toBe(1);
        expect((await cli([...base.slice(0, 2), fixture('revoked.ocsp.der'), ...base.slice(3), '--at', AT, '--require-nonce'])).code).toBe(1);
        expect((await cli([...base, '--at', '2047-01-01', '--stale-tolerance', '1'])).code).toBe(1);
        expect((await cli([...base, '--at', '2026-01-01', '--future-tolerance', '1'])).code).toBe(1);
        expect((await cli([...base, '--at', AT, '--hash', 'SHA-1'])).code).toBe(1);
        expect((await cli([...base])).code).toBe(0);
        const other = await cli(['ocsp', 'check', fixture('leaf.ocsp.der'), '--cert', fixture('rsa.crt.pem'), '--issuer', fixture('inter.crt.pem'), '--at', AT, '--json']);
        expect(JSON.parse(other.stdout)).toMatchObject({ valid: false, status: null });
        expect((await cli(['ocsp', 'check', fixture('leaf.ocsp.der'), '--cert', fixture('leaf.crt.pem')])).code).toBe(2);
    });

    it('falls back to SHA-1 for a CertID hash it does not know', async () => {
        const real = parseOcspResponse(fixtureBytes('leaf.ocsp.der'));
        expect(real.basicResponse?.responses[0]?.certId.hashAlgorithm.oid).toBe('2.16.840.1.101.3.4.2.1');
        const der = Buffer.from(fixtureBytes('leaf.ocsp.der'));
        const at = der.indexOf(Buffer.from('608648016503040201', 'hex'));
        der[at + 8] = 0x02;
        const dir = emptyDir();
        writeFileSync(join(dir, 'odd.der'), der);
        const r = await cli(['ocsp', 'check', join(dir, 'odd.der'), '--cert', fixture('leaf.crt.pem'), '--issuer', fixture('inter.crt.pem'), '--at', AT, '--json']);
        expect(r.code).toBe(1);
    });
});
