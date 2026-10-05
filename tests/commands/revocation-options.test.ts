// The options of crl and ocsp proven by a verdict they change: tolerances,
// the issuer of an indirect CRL entry, the OCSP signer and the nonce bounds.
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { AT, cli, emptyDir, envelope, fixture } from '../helpers/io.js';

/** Both fixtures were issued at this instant and stay fresh until NEXT_UPDATE. */
const THIS_UPDATE = Date.parse('2026-10-04T19:05:34Z');
const NEXT_UPDATE = Date.parse('2046-09-29T19:05:34Z');
const iso = (ms: number): string => new Date(ms).toISOString();

function tlv(tag: number, ...parts: readonly (Uint8Array | readonly number[])[]): Uint8Array {
    const body = parts.flatMap((p) => [...p]);
    const n = body.length;
    const length = n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : [0x82, n >> 8, n & 0xff];
    return Uint8Array.from([tag, ...length, ...body]);
}

const ascii = (text: string): number[] => [...Buffer.from(text, 'ascii')];
const name = (cn: string): Uint8Array => tlv(0x30, tlv(0x31, tlv(0x30, [0x06, 0x03, 0x55, 0x04, 0x03], tlv(0x0c, ascii(cn)))));

/**
 * An indirect CRL (issuingDistributionPoint indirectCRL TRUE) by "CN=Indirect CA"
 * revoking serial 0x1002 with no certificateIssuer: the entry belongs to the
 * CRL issuer, not to the Test Intermediate CA that issued revoked.crt.pem.
 * The signature is a placeholder: crl find does not verify it.
 */
function indirectCrl(): Uint8Array {
    const ecdsaSha256 = tlv(0x30, [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]);
    const idp = tlv(0x30, [0x06, 0x03, 0x55, 0x1d, 0x1c], [0x01, 0x01, 0xff], tlv(0x04, tlv(0x30, [0x84, 0x01, 0xff])));
    const tbs = tlv(0x30,
        [0x02, 0x01, 0x01],
        ecdsaSha256,
        name('Indirect CA'),
        tlv(0x17, ascii('261004190534Z')),
        tlv(0x30, tlv(0x30, [0x02, 0x02, 0x10, 0x02], tlv(0x17, ascii('260601000000Z')))),
        tlv(0xa0, tlv(0x30, idp)));
    return tlv(0x30, tbs, ecdsaSha256, [0x03, 0x01, 0x00]);
}

describe('crl: options that change the answer', () => {
    it('matches an indirect CRL entry against the issuer of --cert', async () => {
        const dir = emptyDir();
        const path = join(dir, 'indirect.crl');
        writeFileSync(path, indirectCrl());
        // By serial alone the entry is the CRL issuer's own: it is listed.
        expect((await cli(['crl', 'find', path, '--serial', '1002'])).stdout).toMatch(/^revoked 2026-06-01T00:00:00\.000Z/);
        // revoked.crt.pem has serial 0x1002 too, but another issuer: not this entry.
        const byCert = await cli(['crl', 'find', path, '--cert', fixture('revoked.crt.pem'), '--json']);
        expect(byCert.code).toBe(0);
        expect(JSON.parse(byCert.stdout)).toEqual({ revoked: false });
        expect(envelope(byCert.stderr)).toMatchObject({ revoked: false });
    });

    it('exits 0 on a valid CRL signature', async () => {
        const r = await cli(['crl', 'verify-signature', fixture('inter.crl.der'), '--issuer', fixture('inter.crt.pem'), '--json']);
        expect(r.code).toBe(0);
        expect(JSON.parse(r.stdout)).toEqual({ valid: true });
    });

    it('accepts a CRL past nextUpdate within --stale-tolerance', async () => {
        const base = ['crl', 'check', fixture('inter.crl.der'), '--cert', fixture('leaf.crt.pem'), '--issuer', fixture('inter.crt.pem'), '--at', iso(NEXT_UPDATE + 1000)];
        expect((await cli(base)).code).toBe(1);
        const tolerated = await cli([...base, '--stale-tolerance', '60000', '--json']);
        expect(tolerated.code).toBe(0);
        expect(JSON.parse(tolerated.stdout)).toEqual({ valid: true, reasons: [], signatureVerified: true });
    });
});

describe('ocsp: options that change the answer', () => {
    const base = ['ocsp', 'check', fixture('leaf.ocsp.der'), '--cert', fixture('leaf.crt.pem'), '--issuer', fixture('inter.crt.pem')];

    it('accepts an answer past nextUpdate within --stale-tolerance', async () => {
        const at = ['--at', iso(NEXT_UPDATE + 1000)];
        expect((await cli([...base, ...at])).code).toBe(1);
        expect((await cli([...base, ...at, '--stale-tolerance', '60000'])).code).toBe(0);
    });

    it('accepts a thisUpdate ahead of --at within --future-tolerance, beyond the one-minute default', async () => {
        const at = ['--at', iso(THIS_UPDATE - 120_000)];
        expect((await cli([...base, ...at])).code).toBe(1);
        expect((await cli([...base, ...at, '--future-tolerance', '300000'])).code).toBe(0);
    });

    it('builds the CertID with the --hash asked for, SHA-1 by default', async () => {
        const sha256 = await cli(['ocsp', 'request', fixture('leaf.crt.pem'), '--issuer', fixture('inter.crt.pem'), '--hash', 'SHA-256', '--encoding', 'hex']);
        expect(sha256.stdout).toContain('0609608648016503040201');
        expect(sha256.stdout).not.toContain('06052b0e03021a');
        const sha1 = await cli(['ocsp', 'request', fixture('leaf.crt.pem'), '--issuer', fixture('inter.crt.pem'), '--encoding', 'hex']);
        expect(sha1.stdout).toContain('06052b0e03021a');
    });

    it('takes a nonce of 1 to 32 octets', async () => {
        const request = ['ocsp', 'request', fixture('leaf.crt.pem'), '--issuer', fixture('inter.crt.pem'), '--encoding', 'hex', '--json'];
        const max = await cli([...request, '--nonce', 'ab'.repeat(32)]);
        expect(max.code).toBe(0);
        expect(envelope(max.stderr)).toMatchObject({ nonce: 'ab'.repeat(32) });
        expect((await cli([...request, '--nonce', '01'])).code).toBe(0);
        // An empty nonce is a usage error, before any check compares it with the response's.
        const empty = await cli([...base, '--at', AT, '--nonce', '0x', '--json']);
        expect(empty.code).toBe(2);
        expect(envelope(empty.stderr)).toMatchObject({ error: { code: 'E_USAGE', message: expect.stringMatching(/1 to 32 octets/) } });
    });

    it('hands the signer to the status check, which notes a responder ID that does not name it', async () => {
        // A certificate for the responder's own key under another name: it verifies the
        // signature, but the response's responderID names the real responder.
        const dir = emptyDir();
        const spec = join(dir, 's.json');
        writeFileSync(spec, JSON.stringify({ subject: { CN: 'Not The Responder' }, notBefore: '2026-01-01T00:00:00Z', validityDays: 3650 }));
        const impostor = join(dir, 'impostor.pem');
        expect((await cli(['cert', 'create', '--spec', spec, '--key', fixture('ed25519.key.pem'), '--issuer', fixture('ed25519.crt.pem'), '--public-key', fixture('ocsp.crt.pem'), '-o', impostor])).code).toBe(0);
        const r = await cli([...base, '--at', AT, '--responder', impostor, '--responder-trusted', '--json']);
        expect(r.code).toBe(0);
        expect(JSON.parse(r.stdout)).toMatchObject({ valid: true, signatureVerified: true, responderAuthorized: true });
        expect(envelope(r.stderr)).toMatchObject({ ok: true, diagnostics: [{ code: 'PKI_DIAG_OCSP_RESPONDER_ID_MISMATCH' }] });
        const genuine = await cli([...base, '--at', AT, '--json']);
        expect(envelope(genuine.stderr)).toMatchObject({ ok: true, diagnostics: [] });
    });
});
