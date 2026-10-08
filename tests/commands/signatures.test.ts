import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { encodeAttribute, encodeObjectIdentifier, parseSignedData } from 'pkinative';
import { AT, cli, emptyDir, envelope, fixture, fixtureBytes } from '../helpers/io.js';

const ENV = { PKINATIVE_PASSWORD: 'test-only-password' };
const TRUST = ['--trust', fixture('root.crt.pem')];

describe('cms inspect', () => {
    it('decodes attached and detached SignedData', async () => {
        const r = await cli(['cms', 'inspect', fixture('attached.p7s')]);
        expect(r.stdout).toMatch(/^SignedData v1\n {2}Content type: {2}data\n {2}Content: {7}27 bytes/);
        expect(r.stdout).toContain('Signer 0: issuer CN=Test Intermediate CA,O=pkinative-cli test,C=FR, serial 1001');
        expect(JSON.parse((await cli(['cms', 'inspect', fixture('detached.p7s'), '--json', '--summary'])).stdout))
            .toEqual({ contentType: '1.2.840.113549.1.7.1', detached: true, certificates: 2, signers: 1 });
        expect((await cli(['cms', 'inspect', fixture('detached.p7s')])).stdout).toContain('Content:       detached');
    });

    it('refuses trailing bytes unless allowed', async () => {
        const dir = emptyDir();
        writeFileSync(join(dir, 't.p7s'), Buffer.concat([fixtureBytes('attached.p7s'), Buffer.from([0])]));
        expect((await cli(['cms', 'inspect', join(dir, 't.p7s')])).code).toBe(1);
        expect((await cli(['cms', 'inspect', join(dir, 't.p7s'), '--allow-trailing'])).code).toBe(0);
    });
});

describe('cms verify', () => {
    it('verifies attached and detached signatures', async () => {
        expect((await cli(['cms', 'verify', fixture('attached.p7s'), ...TRUST, '--at', AT])).stdout).toMatch(/^signature: valid\n {2}signer 0: valid — CN=example\.test/);
        const detached = await cli(['cms', 'verify', fixture('detached.p7s'), '--content', fixture('content.txt'), ...TRUST, '--at', AT, '--purpose', 'emailProtection', '--json']);
        expect(detached.code).toBe(0);
        expect(envelope(detached.stderr)).toMatchObject({ ok: true, valid: true });
        const summary = JSON.parse((await cli(['cms', 'verify', fixture('attached.p7s'), ...TRUST, '--at', AT, '--json', '--summary'])).stdout);
        expect(summary).toEqual({ valid: true, reasons: [], signers: [{ index: 0, valid: true, reasons: [] }] });
    });

    it('fails a detached signature without its content, or with other content', async () => {
        const none = await cli(['cms', 'verify', fixture('detached.p7s'), ...TRUST, '--at', AT, '--json']);
        expect(none.code).toBe(1);
        expect(envelope(none.stderr)).toMatchObject({ error: { code: 'E_VERIFY_FAILED' } });
        const other = await cli(['cms', 'verify', fixture('detached.p7s'), '--content', fixture('leaf.crt.der'), ...TRUST, '--at', AT]);
        expect(other.code).toBe(1);
        expect(other.stdout).toMatch(/signer 0: INVALID/);
    });

    it('verifies a detached signature against a digest', async () => {
        const { createHash } = await import('node:crypto');
        const digest = createHash('sha256').update(readFileSync(fixture('content.txt'))).digest('hex');
        expect((await cli(['cms', 'verify', fixture('detached.p7s'), '--content-digest', digest, ...TRUST, '--at', AT])).code).toBe(0);
        expect((await cli(['cms', 'verify', fixture('detached.p7s'), '--content-digest', digest, '--content', fixture('content.txt'), ...TRUST])).code).toBe(2);
        expect((await cli(['cms', 'verify', fixture('detached.p7s'), '--content-digest', 'zz', ...TRUST])).code).toBe(2);
    });

    it('applies the policy flags and revocation evidence', async () => {
        const r = await cli(['cms', 'verify', fixture('attached.p7s'), ...TRUST, '--untrusted', fixture('inter.crt.pem'), '--at', AT,
            '--crl', fixture('inter.crl.der'), '--ocsp', fixture('leaf.ocsp.der'), '--require-signing-certificate', '--at-timestamp', '--allow-trailing']);
        expect(r.code).toBe(1);
        expect((await cli(['cms', 'verify', fixture('attached.p7s'), ...TRUST, '--at', AT, '--require-algorithm-protection', '--require-revocation'])).code).toBe(1);
        expect((await cli(['cms', 'verify', fixture('attached.p7s')])).stderr).toMatch(/needs --trust/);
    });
});

describe('cms sign', () => {
    it('signs attached content, verified by pkinative', async () => {
        const dir = emptyDir();
        const out = join(dir, 's.p7s');
        const r = await cli(['cms', 'sign', '--content', fixture('content.txt'), '--cert', fixture('leaf.crt.pem'), '--key', fixture('leaf.key.pem'), '--chain', fixture('inter.crt.pem'), '-o', out, '--json']);
        expect(r.code).toBe(0);
        expect(envelope(r.stderr)).toMatchObject({ ok: true, detached: false, output: out });
        expect((await cli(['cms', 'verify', out, ...TRUST, '--require-signing-certificate', '--require-algorithm-protection'])).code).toBe(0);
        expect(parseSignedData(new Uint8Array(readFileSync(out))).certificates).toHaveLength(2);
    });

    it('signs detached, from an encrypted key or a PKCS#12, with every option', async () => {
        const dir = emptyDir();
        const attr = join(dir, 'attr.der');
        writeFileSync(attr, encodeAttribute('1.2.3.4', [encodeObjectIdentifier('1.2.3.4.5')]));
        const enc = await cli(['cms', 'sign', '--content', fixture('content.txt'), '--cert', fixture('leaf.crt.pem'), '--key', fixture('leaf.key.enc.pem'), '--detached',
            '--sid', 'ski', '--signing-time', '2027-01-01T00:00:00.500Z', '--content-type', '1.2.840.113549.1.7.1', '--crl', fixture('inter.crl.pem'),
            '--signed-attribute', attr, '--unsigned-attribute', attr, '--encoding', 'pem', '-o', join(dir, 'e.pem')], { env: ENV });
        expect(enc.code).toBe(0);
        const sd = parseSignedData(new Uint8Array((await cli(['pem', 'decode', join(dir, 'e.pem'), '--index', '0'])).stdoutBytes));
        expect(sd.signerInfos[0]?.sid.kind).toBe('subjectKeyIdentifier');
        expect(sd.signerInfos[0]?.signingTime?.epochMilliseconds).toBe(Date.UTC(2027, 0, 1));
        expect(sd.crls).toHaveLength(1);
        expect((await cli(['cms', 'inspect', join(dir, 'e.pem')])).stdout).toMatch(/Signer 0: key id [0-9a-f]+/);
        const p12 = await cli(['cms', 'sign', '--content', fixture('content.txt'), '--p12', fixture('leaf.p12'), '--signing-time', 'none',
            '--no-signing-certificate', '--no-algorithm-protection', '-o', join(dir, 'p.p7s')], { env: ENV });
        expect(p12.code).toBe(0);
        const plain = parseSignedData(new Uint8Array(readFileSync(join(dir, 'p.p7s'))));
        expect(plain.signerInfos[0]?.signingTime).toBeUndefined();
        expect(plain.signerInfos[0]?.signingCertificate).toBeUndefined();
        expect(plain.certificates).toHaveLength(2);
    });

    it('holds a --p12 signer to the same flag rules as --key (audit A-12)', async () => {
        const sign = (args: string[]) => cli(['cms', 'sign', '--content', fixture('content.txt'), '--dry-run', '--json', ...args], { env: ENV });
        for (const flags of [['--rsa-scheme', 'pss'], ['--rsa-scheme', 'pkcs1']]) {
            const viaP12 = await sign(['--p12', fixture('leaf.p12'), ...flags]);
            const viaKey = await sign(['--key', fixture('leaf.key.pem'), '--cert', fixture('leaf.crt.pem'), ...flags]);
            expect([viaP12.code, viaKey.code], flags.join(' ')).toEqual([2, 2]);
            expect(viaP12.stderr).toMatch(/apply to RSA keys only/);
        }
        expect((await sign(['--p12', fixture('rsa.p12'), '--rsa-scheme', 'pkcs1', '--salt-length', '32'])).stderr).toMatch(/--salt-length applies to --rsa-scheme pss only/);
        expect((await sign(['--p12', fixture('rsa.p12'), '--salt-length', '32'])).stderr).toMatch(/--salt-length applies to --rsa-scheme pss only/);
        const pss = await sign(['--p12', fixture('rsa.p12'), '--rsa-scheme', 'pss', '--salt-length', '20']);
        expect(pss.code).toBe(0);
        expect((await sign(['--p12', fixture('ed25519.p12'), '--hash', 'SHA-256'])).stderr).toMatch(/--hash does not apply to Ed25519/);
        expect((await sign(['--p12', fixture('ed25519.p12')])).code).toBe(0);
    });

    it('signs a precomputed digest', async () => {
        const { createHash } = await import('node:crypto');
        const digest = createHash('sha256').update(readFileSync(fixture('content.txt'))).digest('hex');
        const dir = emptyDir();
        const r = await cli(['cms', 'sign', '--content-digest', digest, '--detached', '--cert', fixture('leaf.crt.pem'), '--key', fixture('leaf.key.pem'), '-o', join(dir, 'd.p7s')]);
        expect(r.code).toBe(0);
        expect((await cli(['cms', 'verify', join(dir, 'd.p7s'), '--content', fixture('content.txt'), ...TRUST, '--untrusted', fixture('inter.crt.pem')])).code).toBe(0);
    });

    it('refuses incomplete input and a foreign key', async () => {
        expect((await cli(['cms', 'sign', '--cert', fixture('leaf.crt.pem'), '--key', fixture('leaf.key.pem')])).stderr).toMatch(/needs --content/);
        expect((await cli(['cms', 'sign', '--content-digest', '00', '--cert', fixture('leaf.crt.pem'), '--key', fixture('leaf.key.pem')])).stderr).toMatch(/needs --detached/);
        expect((await cli(['cms', 'sign', '--content', fixture('content.txt'), '--key', fixture('leaf.key.pem')])).stderr).toMatch(/needs the signer certificate/);
        const foreign = await cli(['cms', 'sign', '--content', fixture('content.txt'), '--cert', fixture('rsa.crt.pem'), '--key', fixture('leaf.key.pem'), '--json']);
        expect(foreign.code).toBe(1);
        expect(envelope(foreign.stderr)).toMatchObject({ error: { code: 'E_INPUT', message: expect.stringMatching(/does not belong to the signer certificate/) } });
    });
});

describe('cms signer operations', () => {
    it('verifies one signer against a certificate', async () => {
        expect((await cli(['cms', 'verify-signer', fixture('attached.p7s'), '--cert', fixture('leaf.crt.pem')])).stdout).toBe('signer 0 signature: valid\n');
        expect((await cli(['cms', 'verify-signer', fixture('detached.p7s'), '--cert', fixture('leaf.crt.pem'), '--content', fixture('content.txt'), '--signer-index', '0'])).code).toBe(0);
        const bad = await cli(['cms', 'verify-signer', fixture('attached.p7s'), '--cert', fixture('rsa.crt.pem'), '--json']);
        expect(bad.code).toBe(1);
        expect(JSON.parse(bad.stdout)).toEqual({ valid: false, index: 0 });
        expect((await cli(['cms', 'verify-signer', fixture('attached.p7s')])).code).toBe(2);
        expect((await cli(['cms', 'verify-signer', fixture('attached.p7s'), '--cert', fixture('leaf.crt.pem'), '--signer-index', '4', '--json'])).stderr).toMatch(/E_NOT_FOUND/);
    });

    it('adds an unsigned attribute and a time-stamp', async () => {
        const dir = emptyDir();
        const attr = join(dir, 'a.der');
        writeFileSync(attr, encodeAttribute('1.2.3.4', [encodeObjectIdentifier('1.2.3.4.5')]));
        const withAttr = await cli(['cms', 'add-attribute', fixture('attached.p7s'), '--attribute', attr, '-o', join(dir, 'a.p7s')]);
        expect(withAttr.code).toBe(0);
        expect(parseSignedData(new Uint8Array(readFileSync(join(dir, 'a.p7s')))).signerInfos[0]?.unsignedAttributes).toHaveLength(1);
        // The fixture token stamps content.txt, not the signature value: refused before anything is written (audit D-57).
        for (const token of ['content.tsr', 'content.tst']) {
            const r = await cli(['cms', 'add-timestamp', fixture('attached.p7s'), '--token', fixture(token), '-o', join(dir, `${token}.p7s`), '--json']);
            expect(r.code, token).toBe(1);
            expect(envelope(r.stderr)).toMatchObject({ error: { code: 'E_INPUT', message: expect.stringMatching(/signature value/), remedy: expect.stringMatching(/tsp request --digest/), reasons: [{ code: 'PKI_REASON_TSP_IMPRINT_MISMATCH' }] } });
            expect(existsSync(join(dir, `${token}.p7s`)), token).toBe(false);
        }
        // A token over the signature value is accepted: a TSTInfo built with asn1 encode and signed as id-ct-TSTInfo by the CLI itself.
        const signature = parseSignedData(new Uint8Array(readFileSync(fixture('attached.p7s')))).signerInfos[0]?.signature ?? new Uint8Array();
        const imprint = createHash('sha256').update(signature).digest('hex');
        writeFileSync(join(dir, 'tstinfo.json'), JSON.stringify({ type: 'sequence', children: [
            { type: 'integer', value: 1 }, { type: 'oid', value: '1.3.6.1.4.1.99999.1' },
            { type: 'sequence', children: [{ type: 'sequence', children: [{ type: 'oid', value: '2.16.840.1.101.3.4.2.1' }, { type: 'null' }] }, { type: 'octet-string', hex: imprint }] },
            { type: 'integer', value: 7 }, { type: 'time', timeType: 'GeneralizedTime', value: AT },
        ] }));
        expect((await cli(['asn1', 'encode', '--spec', join(dir, 'tstinfo.json'), '-o', join(dir, 'tstinfo.der')])).code).toBe(0);
        expect((await cli(['cms', 'sign', '--content', join(dir, 'tstinfo.der'), '--content-type', '1.2.840.113549.1.9.16.1.4', '--key', fixture('leaf.key.pem'), '--cert', fixture('leaf.crt.pem'), '--signing-time', AT, '-o', join(dir, 'over-signature.tst')])).code).toBe(0);
        const stamped = await cli(['cms', 'add-timestamp', fixture('attached.p7s'), '--token', join(dir, 'over-signature.tst'), '-o', join(dir, 'stamped.p7s')]);
        expect(stamped.code).toBe(0);
        expect(parseSignedData(new Uint8Array(readFileSync(join(dir, 'stamped.p7s')))).signerInfos[0]?.timeStampTokens).toHaveLength(1);
        expect((await cli(['cms', 'add-attribute', fixture('attached.p7s')])).code).toBe(2);
        expect((await cli(['cms', 'add-timestamp', fixture('attached.p7s')])).code).toBe(2);
    });

    it('refuses a time-stamp response that carries no token', async () => {
        const dir = emptyDir();
        // TimeStampResp { status { rejection (2) } }
        writeFileSync(join(dir, 'rej.tsr'), Buffer.from('30053003020102', 'hex'));
        const r = await cli(['cms', 'add-timestamp', fixture('attached.p7s'), '--token', join(dir, 'rej.tsr'), '--json']);
        expect(envelope(r.stderr)).toMatchObject({ error: { code: 'E_INPUT', message: expect.stringMatching(/"rejection": it carries no token/) } });
    });
});

describe('tsp --strict', () => {
    // content.tsr and content.tst carry a CMS SET that is not DER-sorted: a warning the engine reports through onDiagnostic.
    it('escalates a warning a verify report collects, not only one raised while parsing (audit F-25)', async () => {
        const base = ['tsp', 'verify', '--response', fixture('content.tsr'), '--data', fixture('content.txt'), '--trust', fixture('root.crt.pem'), '--untrusted', fixture('tsa.crt.pem'), '--at', AT, '--json'];
        const lenient = await cli(base);
        expect(lenient.code).toBe(0);
        expect(envelope(lenient.stderr).diagnostics).toEqual(expect.arrayContaining([expect.objectContaining({ severity: 'warning' })]));
        const strict = await cli([...base, '--strict']);
        expect(strict.code).toBe(1);
        expect(strict.stdout).toBe('');
        expect(envelope(strict.stderr)).toMatchObject({ error: { code: 'E_CHECK_FAILED', pkiCode: 'PKI_STRICT_DIAGNOSTIC', message: expect.stringMatching(/--strict: the engine warned PKI_DIAG_/), remedy: expect.stringMatching(/drop --strict/) } });
    });

    it('surfaces the strict refusal through the auto-detection of tsp inspect (audit F-27)', async () => {
        const r = await cli(['tsp', 'inspect', fixture('content.tst'), '--strict', '--json']);
        expect(envelope(r.stderr)).toMatchObject({ error: { code: 'E_CHECK_FAILED', pkiCode: 'PKI_STRICT_DIAGNOSTIC' } });
        expect((await cli(['tsp', 'inspect', fixture('content.tst'), '--as', 'token', '--strict', '--json'])).code).toBe(1);
        expect((await cli(['tsp', 'inspect', fixture('content.tst'), '--json'])).code).toBe(0);
    });

    it('escalates the warning of a SignedData under cms verify (audit F-26: verifySignedData has no sink, the CLI parses first)', async () => {
        const r = await cli(['cms', 'verify', fixture('content.tst'), '--trust', fixture('root.crt.pem'), '--untrusted', fixture('tsa.crt.pem'), '--at', AT, '--strict', '--json']);
        expect(r.code).toBe(1);
        expect(envelope(r.stderr)).toMatchObject({ error: { code: 'E_CHECK_FAILED', pkiCode: 'PKI_STRICT_DIAGNOSTIC' } });
    });

    it('does not escalate a report without a warning', async () => {
        expect((await cli(['cms', 'verify', fixture('attached.p7s'), '--trust', fixture('root.crt.pem'), '--at', AT, '--strict'])).code).toBe(0);
    });
});

describe('tsp', () => {
    it('builds requests from data or a digest', async () => {
        const r = await cli(['tsp', 'request', '--data', fixture('content.txt'), '--encoding', 'hex']);
        expect(r.stdout).toMatch(/^30[0-9a-f]+\n$/);
        expect(r.stdout).toContain('b1a1c762480b580288e0737422f01130e824c8014422371ae571880dfc642533');
        const full = await cli(['tsp', 'request', '--digest', '00'.repeat(48), '--hash', 'SHA-384', '--nonce', '0x2a', '--policy', '1.2.3', '--no-cert-req', '--encoding', 'hex', '--json']);
        expect(full.code).toBe(0);
        expect(envelope(full.stderr)).toMatchObject({ nonce: '42' });
        const random = await cli(['tsp', 'request', '--data', fixture('content.txt'), '--nonce', 'random', '--encoding', 'hex', '--json']);
        expect(envelope(random.stderr)['nonce']).toMatch(/^\d+$/);
        expect((await cli(['tsp', 'request'])).code).toBe(2);
        expect((await cli(['tsp', 'request', '--data', fixture('content.txt'), '--digest', '00'])).code).toBe(2);
        expect((await cli(['tsp', 'request', '--digest', 'zz'])).code).toBe(2);
        expect((await cli(['tsp', 'request', '--digest', '00', '--nonce', 'x'])).code).toBe(2);
    });

    it('inspects responses, tokens and TSTInfo', async () => {
        const response = await cli(['tsp', 'inspect', fixture('content.tsr')]);
        expect(response.stdout).toMatch(/^TimeStampResp: granted\n {2}Gen time: {3}/);
        expect(response.stdout).toContain('TSA:        DirName:CN=Test TSA');
        expect((await cli(['tsp', 'inspect', fixture('content.tst')])).stdout).toMatch(/^TimeStampToken\n/);
        expect(JSON.parse((await cli(['tsp', 'inspect', fixture('content.tst'), '--json', '--summary'])).stdout)).toMatchObject({ as: 'token', serialNumber: '02' });
        const tst = (await cli(['asn1', 'decode', fixture('content.tst'), '--path', '1.0.2.1.0', '--reencode', '--encoding', 'der', '-o', join(emptyDir(), 'x')])).code;
        expect(tst).toBe(0);
    });

    it('inspects a bare TSTInfo and a rejection, and refuses anything else', async () => {
        const dir = emptyDir();
        const info = join(dir, 'info.der');
        const pathHex = (await cli(['asn1', 'decode', fixture('content.tst'), '--path', '1.0.2.1.0', '--read', 'octet-string'])).stdout.trim();
        writeFileSync(info, Buffer.from(pathHex, 'hex'));
        expect((await cli(['tsp', 'inspect', info])).stdout).toMatch(/^TSTInfo\n {2}Gen time/);
        expect((await cli(['tsp', 'inspect', info, '--as', 'tstinfo', '--json'])).code).toBe(0);
        writeFileSync(join(dir, 'rej.tsr'), Buffer.from('300c300a0201023000030201ff'.slice(0, 0) + '30053003020102', 'hex'));
        expect((await cli(['tsp', 'inspect', join(dir, 'rej.tsr')])).stdout).toBe('TimeStampResp: rejection\n');
        writeFileSync(join(dir, 'bad.der'), Buffer.from('0500', 'hex'));
        expect((await cli(['tsp', 'inspect', join(dir, 'bad.der')])).stderr).toMatch(/not a TimeStampResp, a TimeStampToken or a TSTInfo/);
        expect((await cli(['tsp', 'inspect', join(dir, 'bad.der'), '--as', 'token'])).stderr).toMatch(/as a token/);
    });

    it('verifies a response against its request and data', async () => {
        const r = await cli(['tsp', 'verify', '--response', fixture('content.tsr'), '--request', fixture('content.tsq'), '--data', fixture('content.txt'), ...TRUST, '--untrusted', fixture('inter.crt.pem'), '--at', AT]);
        expect(r.code).toBe(0);
        expect(r.stdout).toMatch(/^time-stamp: valid\n {2}Gen time: {3}2026-/);
        expect(r.stdout).toContain('TSA:        CN=Test TSA');
        const token = await cli(['tsp', 'verify', '--token', fixture('content.tst'), '--digest', 'b1a1c762480b580288e0737422f01130e824c8014422371ae571880dfc642533', ...TRUST, '--at', AT, '--json', '--summary']);
        expect(JSON.parse(token.stdout)).toMatchObject({ valid: true, reasons: [] });
        expect((await cli(['tsp', 'verify', fixture('content.tsr'), '--data', fixture('content.txt'), ...TRUST, '--at', AT, '--crl', fixture('inter.crl.der'), '--allow-noncritical-eku'])).code).toBe(0);
        const foreign = await cli(['tsp', 'verify', fixture('content.tsr'), '--data', fixture('content.txt'), ...TRUST, '--at', AT, '--ocsp', fixture('leaf.ocsp.der'), '--json']);
        expect(JSON.parse(foreign.stdout).reasons.map((r: { code: string }) => r.code)).toContain('PKI_REASON_REVOCATION_MISMATCH');
    });

    it('fails other data, missing anchors and ambiguous inputs', async () => {
        const wrong = await cli(['tsp', 'verify', '--response', fixture('content.tsr'), '--data', fixture('leaf.crt.der'), ...TRUST, '--at', AT, '--json']);
        expect(wrong.code).toBe(1);
        expect(envelope(wrong.stderr)).toMatchObject({ error: { code: 'E_VERIFY_FAILED' } });
        expect((await cli(['tsp', 'verify', '--response', fixture('content.tsr'), '--request', fixture('content.tsq'), ...TRUST, '--at', AT, '--require-revocation'])).stdout).toMatch(/^time-stamp: INVALID/);
        expect((await cli(['tsp', 'verify', '--response', fixture('content.tsr'), ...TRUST, '--at', AT])).stderr).toMatch(/needs what was stamped/);
        expect((await cli(['tsp', 'verify', '--response', fixture('content.tsr')])).stderr).toMatch(/needs --trust/);
        expect((await cli(['tsp', 'verify', ...TRUST])).code).toBe(2);
        expect((await cli(['tsp', 'verify', '--token', fixture('content.tst'), '--response', fixture('content.tsr'), ...TRUST])).code).toBe(2);
    });
});

describe('verdict diagnostics and Ed448', () => {
    it('routes the diagnostics of a verdict to the envelope', async () => {
        const r = await cli(['tsp', 'verify', fixture('content.tsr'), '--data', fixture('content.txt'), ...TRUST, '--at', AT, '--json']);
        expect(envelope(r.stderr)).toMatchObject({ ok: true, diagnostics: [{ code: 'PKI_DIAG_CMS_SET_NOT_SORTED' }] });
        const text = await cli(['tsp', 'verify', fixture('content.tsr'), '--data', fixture('content.txt'), ...TRUST, '--at', AT]);
        expect(text.stderr).toMatch(/^warning PKI_DIAG_CMS_SET_NOT_SORTED/);
    });

    it('signs and verifies CMS with an Ed448 signer', async () => {
        const { generateKeyPairSync } = await import('node:crypto');
        const dir = emptyDir();
        const { privateKey } = generateKeyPairSync('ed448');
        writeFileSync(join(dir, 'k.der'), privateKey.export({ type: 'pkcs8', format: 'der' }));
        writeFileSync(join(dir, 's.json'), JSON.stringify({ subject: { CN: 'ed448' }, notBefore: '2026-01-01T00:00:00Z', extensions: { basicConstraints: { ca: true }, keyUsage: ['digitalSignature', 'keyCertSign'] } }));
        expect((await cli(['cert', 'create', '--spec', join(dir, 's.json'), '--key', join(dir, 'k.der'), '-o', join(dir, 'c.pem')])).code).toBe(0);
        expect((await cli(['cms', 'sign', '--content', fixture('content.txt'), '--cert', join(dir, 'c.pem'), '--key', join(dir, 'k.der'), '-o', join(dir, 's.p7s')])).code).toBe(0);
        expect((await cli(['cms', 'verify', join(dir, 's.p7s'), '--trust', join(dir, 'c.pem'), '--at', AT])).code).toBe(0);
    });
});
