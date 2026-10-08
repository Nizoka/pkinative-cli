import type { KeyObject } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { decodePem, parseCertificate, parseCertificationRequest, verifyCertificateSignature, verifySelfSignature } from 'pkinative';
import { cli, emptyDir, envelope, fixture, fixtureBytes } from '../helpers/io.js';
import { validate } from '../helpers/json-schema.js';

const PASSWORD = 'test-only-password';

function file(dir: string, name: string, content: string | object): string {
    const path = join(dir, name);
    writeFileSync(path, typeof content === 'string' ? content : JSON.stringify(content));
    return path;
}

function pemCert(text: string) {
    return parseCertificate(decodePem(text)[0]!.bytes);
}

const CA_SPEC = {
    serialNumber: '0x42',
    subject: { C: 'FR', O: 'Demo', CN: 'Demo CA' },
    notBefore: '2026-01-01T00:00:00Z',
    validityDays: 3650,
    extensions: { basicConstraints: { ca: true, pathLen: 1 }, keyUsage: ['keyCertSign', 'cRLSign'] },
};

describe('cert inspect', () => {
    it('renders a certificate as text', async () => {
        const r = await cli(['cert', 'inspect', fixture('leaf.crt.pem')]);
        expect(r.code).toBe(0);
        expect(r.stdout).toContain('Serial:     1001 (4097)');
        expect(r.stdout).toContain('Issuer:     CN=Test Intermediate CA,O=pkinative-cli test,C=FR');
        expect(r.stdout).toContain('Public key: ec P-256 (uncompressed)');
        expect(r.stdout).toContain('subjectAltName: DNS:example.test, DNS:*.wild.example.test, IP:192.0.2.1, email:leaf@example.test');
        expect(r.stdout).toContain('extKeyUsage: serverAuth, clientAuth, emailProtection');
        expect(r.stdout).toContain('cRLDistributionPoints: URI:http://crl.example.test/inter.crl');
        expect(r.stdout).toContain('authorityInfoAccess: ocsp URI:http://ocsp.example.test');
        expect(r.stdout).toContain('keyUsage (critical): digitalSignature');
        expect(r.stdout).toContain('authorityKeyIdentifier: keyid:');
    });

    it('renders RSA and Ed25519 keys', async () => {
        expect((await cli(['cert', 'inspect', fixture('rsa.crt.der')])).stdout).toContain('Public key: rsa 2048 bits');
        expect((await cli(['cert', 'inspect', fixture('ed25519.crt.pem')])).stdout).toContain('Public key: ed25519');
    });

    it('emits the wire form, a summary and a projection', async () => {
        const json = JSON.parse((await cli(['cert', 'inspect', fixture('leaf.crt.der'), '--json'])).stdout);
        expect(json.serialNumber).toEqual({ bytes: '1001', hex: '1001', value: '4097' });
        expect(json.validity.notBefore.epochMilliseconds).toBe(Date.UTC(2026, 0, 1));
        const summary = JSON.parse((await cli(['cert', 'inspect', fixture('leaf.crt.der'), '--json', '--summary'])).stdout);
        expect(summary).toMatchObject({ serialNumber: '1001', subject: 'CN=example.test,O=pkinative-cli test,C=FR', publicKey: 'ec' });
        expect(summary.extensions).toContain('subjectAltName');
        const fields = JSON.parse((await cli(['cert', 'inspect', fixture('leaf.crt.der'), '--json', '--fields', 'serialNumber.hex'])).stdout);
        expect(fields).toEqual({ serialNumber: { hex: '1001' } });
    });

    it('prints one extension, or E_NOT_FOUND', async () => {
        expect((await cli(['cert', 'inspect', fixture('leaf.crt.der'), '--extension', 'basicConstraints'])).stdout).toBe('basicConstraints (critical): CA=false\n');
        const json = JSON.parse((await cli(['cert', 'inspect', fixture('leaf.crt.der'), '--extension', 'subjectAltName', '--json'])).stdout);
        expect(json.names[2]).toMatchObject({ kind: 'iPAddress', address: '192.0.2.1' });
        const missing = await cli(['cert', 'inspect', fixture('leaf.crt.der'), '--extension', 'nameConstraints', '--json']);
        expect(envelope(missing.stderr)).toMatchObject({ error: { code: 'E_NOT_FOUND' } });
        expect((await cli(['cert', 'inspect', fixture('leaf.crt.der'), '--extension', 'frob'])).code).toBe(2);
        expect((await cli(['cert', 'inspect', fixture('leaf.crt.der'), '--extension', 'keyUsage', '--raw-extensions'])).code).toBe(2);
    });

    it('keeps extensions raw on request', async () => {
        const r = await cli(['cert', 'inspect', fixture('leaf.crt.der'), '--raw-extensions']);
        expect(r.stdout).toMatch(/basicConstraints \(critical\): 2 bytes/);
    });

    it('refuses something that is not a certificate', async () => {
        const r = await cli(['cert', 'inspect', fixture('leaf.csr.der'), '--json']);
        expect(r.code).toBe(1);
        expect(envelope(r.stderr)).toMatchObject({ error: { code: 'E_PARSE' } });
    });
});

describe('cert decode-extension', () => {
    it('decodes a value given as hex or as a file', async () => {
        const r = await cli(['cert', 'decode-extension', '--oid', '2.5.29.19', '--value', '30030101ff', '--critical']);
        expect(r.stdout).toBe('basicConstraints (critical): CA=true\n');
        const dir = emptyDir();
        const p = join(dir, 'v.der');
        writeFileSync(p, Buffer.from('300a06082b06010505070301', 'hex'));
        expect((await cli(['cert', 'decode-extension', '--oid', '2.5.29.37', '-i', p])).stdout).toBe('extKeyUsage: serverAuth\n');
        expect((await cli(['cert', 'decode-extension', '--oid', '1.2.3.4', '--value', '0500'])).stdout).toBe('1.2.3.4: 2 bytes\n');
        // A malformed value gets a remedy of its own, not cert inspect's --raw-extensions (audit B-07).
        const malformed = envelope((await cli(['cert', 'decode-extension', '--oid', '2.5.29.9', '--value', '300f300d0603550406310613024652', '--json'])).stderr);
        expect(malformed).toMatchObject({ error: { code: 'E_PARSE', pkiCode: 'PKI_X509_EXTENSION_MALFORMED', remedy: expect.stringMatching(/asn1 decode/) } });
        expect(JSON.stringify(malformed)).not.toContain('--raw-extensions');
    });

    it('decodes a subjectDirectoryAttributes value', async () => {
        // SubjectDirectoryAttributes ::= SEQUENCE OF Attribute { type 2.5.4.6, values SET { PrintableString "FR" } } (RFC 5280 §4.2.1.8).
        const r = await cli(['cert', 'decode-extension', '--oid', '2.5.29.9', '--value', '300d300b0603550406310413024652', '--json']);
        expect(r.code).toBe(0);
        expect(JSON.parse(r.stdout)).toMatchObject({ kind: 'subjectDirectoryAttributes' });
    });

    it('refuses missing or ambiguous input', async () => {
        expect((await cli(['cert', 'decode-extension', '--value', '00'])).code).toBe(2);
        expect((await cli(['cert', 'decode-extension', '--oid', '2.5.29.19'])).code).toBe(2);
        expect((await cli(['cert', 'decode-extension', '--oid', '2.5.29.19', '--value', 'zz'])).code).toBe(2);
        expect((await cli(['cert', 'decode-extension', '--oid', '2.5.29.19', '--value', '0500'])).stderr).toMatch(/E_PARSE/);
    });
});

describe('cert verify-signature', () => {
    it('verifies against the issuer, and self-signatures', async () => {
        const ok = await cli(['cert', 'verify-signature', fixture('leaf.crt.pem'), '--issuer', fixture('inter.crt.pem')]);
        expect(ok.code).toBe(0);
        expect(ok.stdout).toBe('signature: valid\n');
        expect((await cli(['cert', 'verify-signature', fixture('root.crt.der'), '--json'])).stdout).toBe('{"valid":true,"selfSigned":true}\n');
    });

    it('fails with E_VERIFY_FAILED against the wrong issuer', async () => {
        const r = await cli(['cert', 'verify-signature', fixture('leaf.crt.pem'), '--issuer', fixture('root.crt.pem'), '--json']);
        expect(r.code).toBe(1);
        expect(JSON.parse(r.stdout)).toEqual({ valid: false, selfSigned: false });
        expect(envelope(r.stderr)).toMatchObject({ error: { code: 'E_VERIFY_FAILED' } });
        expect((await cli(['cert', 'verify-signature', fixture('leaf.crt.pem')])).stdout).toBe('self-signature: INVALID\n');
        expect((await cli(['cert', 'verify-signature', fixture('leaf.crt.pem'), '--issuer', fixture('inter.crt.pem'), '--allow-algorithm-mismatch'])).code).toBe(0);
    });
});

describe('cert check-name / match-name / check-purpose', () => {
    it('checks DNS names, wildcards and IP addresses', async () => {
        expect((await cli(['cert', 'check-name', fixture('leaf.crt.pem'), '--host', 'example.test'])).stdout).toBe('name example.test: valid\n');
        expect((await cli(['cert', 'check-name', fixture('leaf.crt.pem'), '--host', 'a.wild.example.test'])).code).toBe(0);
        expect((await cli(['cert', 'check-name', fixture('leaf.crt.pem'), '--ip', '192.0.2.1'])).code).toBe(0);
        expect((await cli(['cert', 'check-name', fixture('leaf.crt.pem'), '--host', 'a.wild.example.test', '--chain', fixture('inter.crt.pem')])).code).toBe(0);
        const noWild = await cli(['cert', 'check-name', fixture('leaf.crt.pem'), '--host', 'a.wild.example.test', '--no-wildcards', '--json']);
        expect(noWild.code).toBe(1);
        expect(envelope(noWild.stderr)).toMatchObject({ error: { code: 'E_CHECK_FAILED', reasons: [{ code: expect.stringMatching(/^PKI_REASON_/) }] } });
        expect((await cli(['cert', 'check-name', fixture('leaf.crt.pem'), '--host', 'other.test'])).stdout).toMatch(/INVALID\n {2}PKI_REASON_/);
        expect((await cli(['cert', 'check-name', fixture('ed25519.crt.pem'), '--host', 'Test Ed25519 Root', '--allow-cn-fallback'])).code).toBe(1);
    });

    it('refuses a missing or double reference identity, and a bad IP', async () => {
        expect((await cli(['cert', 'check-name', fixture('leaf.crt.pem')])).code).toBe(2);
        expect((await cli(['cert', 'check-name', fixture('leaf.crt.pem'), '--host', 'a', '--ip', '192.0.2.1'])).code).toBe(2);
        expect((await cli(['cert', 'check-name', fixture('leaf.crt.pem'), '--ip', '999.1.1.1'])).stderr).toMatch(/not an IPv4 or IPv6 address/);
    });

    it('matches presented names', async () => {
        expect((await cli(['cert', 'match-name', '*.example.test', 'a.example.test'])).stdout).toBe('match\n');
        const no = await cli(['cert', 'match-name', '*.example.test', 'a.example.test', '--no-wildcards', '--json']);
        expect(no.code).toBe(1);
        expect(JSON.parse(no.stdout)).toEqual({ match: false });
        expect((await cli(['cert', 'match-name', 'a'])).code).toBe(2);
    });

    it('checks purposes along a path', async () => {
        expect((await cli(['cert', 'check-purpose', fixture('leaf.crt.pem'), '--purpose', 'serverAuth', '--chain', fixture('inter.crt.pem')])).code).toBe(0);
        expect((await cli(['cert', 'check-purpose', fixture('leaf.crt.pem'), '--purpose', '1.3.6.1.5.5.7.3.4'])).code).toBe(0);
        const bad = await cli(['cert', 'check-purpose', fixture('leaf.crt.pem'), '--purpose', 'codeSigning']);
        expect(bad.code).toBe(1);
        expect(bad.stderr).toMatch(/E_CHECK_FAILED/);
        expect((await cli(['cert', 'check-purpose', fixture('root.crt.pem'), '--purpose', 'any', '--require-explicit-purpose'])).code).toBe(1);
        expect((await cli(['cert', 'check-purpose', fixture('leaf.crt.pem'), '--purpose', 'serverAuth', '--no-restrict-issuers'])).code).toBe(0);
        expect((await cli(['cert', 'check-purpose', fixture('leaf.crt.pem')])).code).toBe(2);
        expect((await cli(['cert', 'check-purpose', fixture('leaf.crt.pem'), '--purpose', 'frob'])).stderr).toMatch(/unknown purpose/);
    });
});

describe('cert create', () => {
    it('creates a self-signed CA from an unencrypted key, verified by pkinative', async () => {
        const dir = emptyDir();
        const r = await cli(['cert', 'create', '--spec', file(dir, 'ca.json', CA_SPEC), '--key', fixture('ed25519.key.pem'), '--json']);
        expect(r.code).toBe(0);
        const ca = pemCert(r.stdout);
        expect(await verifySelfSignature(ca)).toBe(true);
        expect(ca.serialNumber.hex).toBe('42');
        expect(ca.validity.notAfter.epochMilliseconds - ca.validity.notBefore.epochMilliseconds).toBe(3650 * 86_400_000);
        expect(ca.extensions.map((e) => e.kind)).toEqual(['basicConstraints', 'keyUsage', 'subjectKeyIdentifier', 'authorityKeyIdentifier']);
        expect(envelope(r.stderr)).toMatchObject({ ok: true, command: 'cert create', serialNumber: '42', selfSigned: true, encoding: 'pem' });
    });

    it('issues under an issuer with every extension form', async () => {
        const dir = emptyDir();
        const caPem = (await cli(['cert', 'create', '--spec', file(dir, 'ca.json', CA_SPEC), '--key', fixture('ed25519.key.pem')])).stdout;
        const caPath = file(dir, 'ca.pem', caPem);
        const spec = {
            serialNumber: '123456789',
            subject: [[{ type: 'C', value: 'FR' }], [{ type: 'organizationName', value: 'Demo' }], [{ type: '2.5.4.3', value: 'svc.example.test', stringType: 'utf8' }]],
            notBefore: '2026-01-01T00:00:00Z',
            notAfter: Date.UTC(2027, 0, 1),
            extensions: {
                basicConstraints: { ca: false, critical: true },
                keyUsage: { usages: ['digitalSignature'], critical: true },
                extendedKeyUsage: { purposes: ['serverAuth', 'any', '1.2.3.4'], critical: false },
                subjectAltName: { dns: ['svc.example.test'], email: ['a@example.test'], uri: ['https://example.test/'], ip: ['2001:db8::1', '192.0.2.7', '::ffff:192.0.2.8'], registeredId: ['1.2.3'], directoryName: [{ CN: 'dir' }] },
                issuerAltName: { dns: ['ca.example.test'] },
                subjectKeyIdentifier: 'a1b2',
                authorityKeyIdentifier: true,
                raw: [{ oid: '1.2.3.4.5', value: '0500' }],
            },
        };
        const r = await cli(['cert', 'create', '--spec', file(dir, 'leaf.json', spec), '--key', fixture('ed25519.key.pem'), '--issuer', caPath, '--public-key', fixture('leaf.pub.pem'), '--encoding', 'der', '-o', join(dir, 'leaf.der')]);
        expect(r.code).toBe(0);
        const leaf = parseCertificate(new Uint8Array(readFileSync(join(dir, 'leaf.der'))));
        expect(await verifyCertificateSignature(leaf, pemCert(caPem))).toBe(true);
        expect(leaf.serialNumber.value).toBe(123456789n);
        const san = leaf.extensions.find((e) => e.kind === 'subjectAltName');
        expect(san?.kind === 'subjectAltName' && san.names.map((n) => n.kind)).toEqual(['dNSName', 'rfc822Name', 'uniformResourceIdentifier', 'iPAddress', 'iPAddress', 'iPAddress', 'registeredID', 'directoryName']);
        const text = (await cli(['cert', 'inspect', join(dir, 'leaf.der')])).stdout;
        expect(text).toContain('IP:2001:db8::1, IP:192.0.2.7, IP:::ffff:c000:208');
        expect(text).toContain('subjectKeyIdentifier: A1:B2');
        expect(text).toContain('issuerAltName: DNS:ca.example.test');
        expect(text).toContain('RID:1.2.3, DirName:CN=dir');
    });

    it('decrypts an encrypted issuer key with the issuer certificate as type hint', async () => {
        const dir = emptyDir();
        const spec = { serialNumber: 9, subject: { CN: 'x.example.test' }, notBefore: '2026-01-01T00:00:00Z', extensions: { subjectKeyIdentifier: false, authorityKeyIdentifier: false } };
        const r = await cli(['cert', 'create', '--spec', file(dir, 's.json', spec), '--key', fixture('leaf.key.enc.pem'), '--issuer', fixture('leaf.crt.pem'), '--public-key', fixture('ed25519.crt.pem'), '--json'], { env: { PKINATIVE_PASSWORD: PASSWORD } });
        expect(r.code).toBe(0);
        const cert = pemCert(r.stdout);
        expect(cert.extensions).toEqual([]);
        expect(await verifyCertificateSignature(cert, parseCertificate(fixtureBytes('leaf.crt.der')))).toBe(true);
        expect(cert.signatureAlgorithm.oid).toBe('1.2.840.10045.4.3.2');
    });

    it('signs with RSA only under an explicit scheme, and with a chosen hash', async () => {
        const dir = emptyDir();
        const spec = file(dir, 's.json', { subject: { CN: 'rsa' }, notBefore: '2026-01-01T00:00:00Z', serialNumber: 'random' });
        const missing = await cli(['cert', 'create', '--spec', spec, '--key', fixture('rsa.key.pem'), '--json']);
        expect(missing.code).toBe(2);
        expect(envelope(missing.stderr)).toMatchObject({ error: { code: 'E_USAGE', remedy: '--rsa-scheme pkcs1|pss' } });
        const pss = await cli(['cert', 'create', '--spec', spec, '--key', fixture('rsa.key.pem'), '--rsa-scheme', 'pss', '--hash', 'SHA-384', '--salt-length', '48']);
        expect(pss.code).toBe(0);
        expect(pemCert(pss.stdout).signatureAlgorithm.oid).toBe('1.2.840.113549.1.1.10');
        const pkcs1 = await cli(['cert', 'create', '--spec', spec, '--key', fixture('rsa.key.enc.pem'), '--key-type', 'rsa', '--rsa-scheme', 'pkcs1', '--public-key', fixture('rsa.crt.pem'), '--password-file', file(dir, 'pw', `${PASSWORD}\n`)]);
        expect(pkcs1.code).toBe(0);
        expect(pemCert(pkcs1.stdout).signatureAlgorithm.oid).toBe('1.2.840.113549.1.1.11');
        expect((await cli(['cert', 'create', '--spec', spec, '--key', fixture('rsa.key.pem'), '--rsa-scheme', 'pkcs1', '--salt-length', '1'])).code).toBe(2);
    });

    it('signs from a PKCS#12 file, re-targeting the ECDSA hash', async () => {
        const dir = emptyDir();
        const spec = file(dir, 's.json', { subject: { CN: 'p12' }, notBefore: '2026-01-01T00:00:00Z' });
        const r = await cli(['cert', 'create', '--spec', spec, '--p12', fixture('leaf.p12'), '--issuer', fixture('leaf.crt.pem'), '--public-key', fixture('ed25519.crt.pem'), '--hash', 'SHA-384'], { env: { PKINATIVE_PASSWORD: PASSWORD } });
        expect(r.code).toBe(0);
        expect(pemCert(r.stdout).signatureAlgorithm.oid).toBe('1.2.840.10045.4.3.3');
        const wrong = await cli(['cert', 'create', '--spec', spec, '--p12', fixture('leaf.p12'), '--issuer', fixture('leaf.crt.pem'), '--public-key', fixture('ed25519.crt.pem'), '--json'], { env: { PKINATIVE_PASSWORD: 'nope' } });
        expect(wrong.code).toBe(1);
        expect(envelope(wrong.stderr)).toMatchObject({ error: { code: 'E_PASSWORD' } });
        expect((await cli(['cert', 'create', '--spec', spec, '--p12', fixture('leaf.p12')])).stderr).toMatch(/needs its password/);
    });

    it('refuses a key that does not belong to the issuer', async () => {
        const dir = emptyDir();
        const spec = file(dir, 's.json', { subject: { CN: 'x' }, notBefore: '2026-01-01T00:00:00Z' });
        const r = await cli(['cert', 'create', '--spec', spec, '--key', fixture('leaf.key.pem'), '--issuer', fixture('inter.crt.pem'), '--public-key', fixture('leaf.pub.pem'), '--json']);
        expect(r.code).toBe(1);
        expect(envelope(r.stderr)).toMatchObject({ error: { code: 'E_INPUT', message: expect.stringMatching(/does not belong to the --issuer/) } });
        const self = await cli(['cert', 'create', '--spec', spec, '--key', fixture('leaf.key.pem'), '--public-key', fixture('ed25519.crt.pem')]);
        expect(self.stderr).toMatch(/does not match the subject public key/);
    });

    it('accepts a named issuer without verifying it', async () => {
        const dir = emptyDir();
        const spec = file(dir, 's.json', { subject: { CN: 'x' }, issuer: { CN: 'Someone Else' }, notBefore: '2026-01-01T00:00:00Z', extensions: { authorityKeyIdentifier: 'aa' } });
        const r = await cli(['cert', 'create', '--spec', spec, '--key', fixture('leaf.key.pem'), '--public-key', fixture('ed25519.crt.pem'), '--json']);
        expect(r.code).toBe(0);
        // Said plainly, never implied (audit A-07): the status and a warning.
        expect(envelope(r.stderr)).toMatchObject({ selfSigned: false, signatureVerified: false });
        expect(pemCert(r.stdout).issuer.rdns).toHaveLength(1);
        const text = await cli(['cert', 'create', '--spec', spec, '--key', fixture('leaf.key.pem'), '--public-key', fixture('ed25519.crt.pem')]);
        expect(text.stderr).toMatch(/^warning: the issuer comes from the spec, so the signature was not verified/);
        const issued = await cli(['cert', 'create', '--spec', file(dir, 'self.json', { subject: { CN: 'x' }, notBefore: '2026-01-01T00:00:00Z' }), '--key', fixture('ed25519.key.pem'), '--json']);
        expect(envelope(issued.stderr)).toMatchObject({ selfSigned: true, signatureVerified: true });
    });

    it('refuses incomplete or contradictory input', async () => {
        const dir = emptyDir();
        const ok = { subject: { CN: 'x' }, notBefore: '2026-01-01T00:00:00Z' };
        const run = (spec: object, extra: string[] = []) => cli(['cert', 'create', '--spec', file(dir, `s${Math.random()}.json`, spec), '--key', fixture('leaf.key.pem'), ...extra]);
        expect((await cli(['cert', 'create', '--key', fixture('leaf.key.pem')])).code).toBe(2);
        expect((await run({ notBefore: '2026-01-01T00:00:00Z' })).stderr).toMatch(/spec subject: is required/);
        expect((await run({ ...ok, issuer: { CN: 'a' } }, ['--issuer', fixture('inter.crt.pem')])).stderr).toMatch(/comes from --issuer/);
        expect((await run(ok, ['--issuer', fixture('inter.crt.pem')])).stderr).toMatch(/subject public key is needed/);
        expect((await run({ ...ok, serialNumber: 'abc' })).stderr).toMatch(/serialNumber/);
        expect((await run({ ...ok, validityDays: 0 })).stderr).toMatch(/validityDays/);
        expect((await run({ ...ok, notAfter: '2027-01-01T00:00:00Z', validityDays: 1 })).stderr).toMatch(/not both/);
        expect((await run({ ...ok, notBefore: true })).stderr).toMatch(/expected an instant/);
        expect((await run({ ...ok, extensions: [] })).stderr).toMatch(/extensions: expected an object/);
        expect((await run({ ...ok, extensions: { frob: 1 } })).stderr).toMatch(/unknown extension/);
        expect((await run({ ...ok, extensions: { basicConstraints: { ca: 'yes' } } })).stderr).toMatch(/basicConstraints/);
        expect((await run({ ...ok, extensions: { basicConstraints: { ca: true, pathLen: 'x' } } })).stderr).toMatch(/pathLen/);
        expect((await run({ ...ok, extensions: { basicConstraints: { ca: false, pathLen: 1 } } })).stderr).toMatch(/PKI_API_MISUSE/);
        expect((await run({ ...ok, extensions: { keyUsage: ['frob'] } })).stderr).toMatch(/unknown key usage/);
        expect((await run({ ...ok, extensions: { keyUsage: 'x' } })).stderr).toMatch(/expected an array/);
        expect((await run({ ...ok, extensions: { keyUsage: { usages: [1] } } })).stderr).toMatch(/array of strings/);
        expect((await run({ ...ok, extensions: { keyUsage: { usages: ['cRLSign'], critical: 'no' } } })).stderr).toMatch(/critical: expected a boolean/);
        expect((await run({ ...ok, extensions: { subjectAltName: [] } })).stderr).toMatch(/expected \{ "dns"/);
        expect((await run({ ...ok, extensions: { subjectAltName: { directoryName: {} } } })).stderr).toMatch(/array of names/);
        expect((await run({ ...ok, extensions: { subjectAltName: {} } })).stderr).toMatch(/PKI_API_MISUSE/);
        expect((await run({ ...ok, extensions: { subjectKeyIdentifier: 'zz' } })).stderr).toMatch(/hexadecimal/);
        expect((await run({ ...ok, issuer: { CN: 'other' }, extensions: { authorityKeyIdentifier: true } }, ['--public-key', fixture('leaf.pub.pem')])).stderr).toMatch(/cannot be computed here/);
        expect((await run({ ...ok, extensions: { raw: {} } })).stderr).toMatch(/raw: expected an array/);
        expect((await run({ ...ok, extensions: { raw: [{ value: '00' }] } })).stderr).toMatch(/raw\[0\]/);
        expect((await run({ ...ok, subject: { CN: 5 } })).stderr).toMatch(/expected a string/);
        expect((await run({ ...ok, subject: {} })).stderr).toMatch(/at least one RDN/);
        expect((await run({ ...ok, subject: [] })).stderr).toMatch(/at least one RDN/);
        expect((await run({ ...ok, subject: [[]] })).stderr).toMatch(/non-empty array/);
        expect((await run({ ...ok, subject: [['x']] })).stderr).toMatch(/expected \{ "type"/);
        expect((await run({ ...ok, subject: [[{ type: 'CN' }]] })).stderr).toMatch(/must be strings/);
        expect((await run({ ...ok, subject: [[{ type: 'CN', value: 'x', stringType: 'bmp' }]] })).stderr).toMatch(/stringType/);
        expect((await run({ ...ok, subject: { FROB: 'x' } })).stderr).toMatch(/unknown attribute type "FROB"/);
        expect((await run({ ...ok, subject: 'CN=x' })).stderr).toMatch(/expected an object such as/);
        expect((await cli(['cert', 'create', '--spec', '-', '--key', fixture('leaf.key.pem')], { stdin: '[1]' })).stderr).toMatch(/expected a JSON object/);
        expect((await cli(['cert', 'create', '--spec', '-', '--key', fixture('leaf.key.pem')], { stdin: '{x' })).stderr).toMatch(/not valid UTF-8 JSON/);
    });

    it('refuses signer misconfigurations', async () => {
        const dir = emptyDir();
        const spec = file(dir, 's.json', { subject: { CN: 'x' }, notBefore: '2026-01-01T00:00:00Z' });
        const base = ['cert', 'create', '--spec', spec];
        expect((await cli(base)).stderr).toMatch(/needs a signing key/);
        expect((await cli([...base, '--key', fixture('leaf.key.pem'), '--p12', fixture('leaf.p12')])).code).toBe(2);
        expect((await cli([...base, '--key', fixture('leaf.key.enc.pem')])).stderr).toMatch(/encrypted: give its password/);
        expect((await cli([...base, '--key', fixture('leaf.key.enc.pem')], { env: { PKINATIVE_PASSWORD: PASSWORD } })).stderr).toMatch(/needs its type/);
        expect((await cli([...base, '--key', fixture('leaf.key.enc.pem'), '--key-type', 'ec-p256', '--public-key', fixture('leaf.pub.pem')], { env: { PKINATIVE_PASSWORD: 'wrong' } })).stderr).toMatch(/E_PASSWORD/);
        expect((await cli([...base, '--key', fixture('leaf.key.pem'), '--hash', 'SHA-1'])).stderr).toMatch(/--allow-sha1/);
        expect(envelope((await cli([...base, '--key', fixture('leaf.key.pem'), '--hash', 'SHA-1', '--json'])).stderr)).toMatchObject({ error: { code: 'E_USAGE', remedy: '--allow-sha1' } });
        expect((await cli([...base, '--key', fixture('leaf.key.pem'), '--hash', 'SHA-1', '--allow-sha1'])).code).toBe(0);
        expect((await cli([...base, '--key', fixture('ed25519.key.pem'), '--hash', 'SHA-256'])).stderr).toMatch(/does not apply to Ed25519/);
        expect((await cli([...base, '--key', fixture('leaf.key.pem'), '--rsa-scheme', 'pss'])).stderr).toMatch(/RSA keys only/);
        expect((await cli([...base, '--key', fixture('leaf.crt.pem')])).stderr).toMatch(/holds no PRIVATE KEY or ENCRYPTED PRIVATE KEY/);
        expect((await cli([...base, '--key', fixture('leaf.key.der')])).code).toBe(0);
    });
});

describe('cert encode', () => {
    const dir = emptyDir();
    const enc = (structure: string, spec: unknown, extra: string[] = []) => cli(['cert', 'encode', structure, '--spec', file(dir, `${structure}${Math.random()}.json`, spec as object), ...extra]);

    it('encodes every building block', async () => {
        expect((await enc('name', { CN: 'x' })).stdout).toBe('300c310a300806035504030c0178\n');
        expect((await enc('name-attribute', { type: 'C', value: 'FR' })).stdout).toBe('3009060355040613024652\n');
        expect((await enc('validity', { notBefore: '2026-01-01T00:00:00Z', notAfter: '2027-01-01T00:00:00Z' })).stdout).toMatch(/^301e170d/);
        expect((await enc('spki', { algorithm: '1.3.101.112', publicKey: '00'.repeat(32) })).stdout).toMatch(/^302a300506032b6570032100/);
        expect((await enc('spki', { algorithm: '1.2.840.10045.2.1', parameters: '06082a8648ce3d030107', publicKey: '04' })).code).toBe(0);
        expect((await enc('algorithm-identifier', { oid: '1.2.840.113549.1.1.11', parameters: '0500' })).stdout).toBe('300d06092a864886f70d01010b0500\n');
        expect((await enc('algorithm-identifier', { oid: '1.3.101.112' })).stdout).toBe('300506032b6570\n');
        expect((await enc('attribute', { oid: '1.2.840.113549.1.9.14', values: ['3000'] })).stdout).toBe('300f06092a864886f70d01090e31023000\n');
        expect((await enc('extension', { oid: '2.5.29.19', critical: true, value: '3000' })).stdout).toBe('300c0603551d130101ff04023000\n');
        expect((await enc('extensions', { basicConstraints: { ca: true } })).stdout).toMatch(/^30/);
        expect((await enc('basic-constraints', { ca: true, pathLen: 0 })).stdout).toBe('30060101ff020100\n');
        expect((await enc('basic-constraints', { ca: false })).stdout).toBe('3000\n');
        expect((await enc('key-usage', ['digitalSignature'])).stdout).toBe('03020780\n');
        expect((await enc('extended-key-usage', ['serverAuth'])).stdout).toBe('300a06082b06010505070301\n');
        expect((await enc('subject-alt-name', { dns: ['a.test'] })).stdout).toBe('30088206612e74657374\n');
        expect((await enc('subject-key-identifier', { keyIdentifier: 'a1b2' })).stdout).toBe('0402a1b2\n');
        expect((await enc('authority-key-identifier', { keyIdentifier: 'a1b2' })).stdout).toBe('30048002a1b2\n');
    });

    it('encodes the signature algorithm of a key', async () => {
        expect((await cli(['cert', 'encode', 'signature-algorithm', '--key', fixture('ed25519.key.pem')])).stdout).toBe('300506032b6570\n');
        expect((await cli(['cert', 'encode', 'signature-algorithm', '--key', fixture('leaf.key.pem'), '--encoding', 'der', '-o', join(dir, 'alg.der')])).code).toBe(0);
    });

    it('refuses an unknown structure or a bad spec', async () => {
        expect((await cli(['cert', 'encode'])).code).toBe(2);
        expect((await cli(['cert', 'encode', 'frob'])).code).toBe(2);
        expect((await cli(['cert', 'encode', 'name'])).stderr).toMatch(/needs --spec/);
        expect((await enc('validity', [1])).stderr).toMatch(/expected a JSON object/);
        expect((await enc('attribute', { oid: '1.2', values: 'x' })).stderr).toMatch(/array of hex strings/);
        // Required members are named, as E_INPUT, never the engine's "undefined" OID (audit B-05).
        for (const [structure, spec, path] of [
            ['spki', { publicKey: '00' }, 'algorithm'], ['algorithm-identifier', {}, 'oid'], ['attribute', { values: [] }, 'oid'],
            ['extension', { oid: 'x', value: '00' }, 'oid'], ['basic-constraints', { ca: 'yes' }, 'ca'], ['basic-constraints', { ca: true, pathLen: -1 }, 'pathLen'],
            ['basic-constraints', { ca: true, pathLen: 'x' }, 'pathLen'], ['validity', { notAfter: '2027-01-01T00:00:00Z' }, 'notBefore'],
        ] as const) {
            const r = await enc(structure, spec, ['--json']);
            expect(envelope(r.stderr), `${structure} ${JSON.stringify(spec)}`).toMatchObject({ error: { code: 'E_INPUT', message: expect.stringContaining(`spec ${path}:`) } });
        }
        expect((await enc('key-usage', { usages: [] })).stderr).toMatch(/array of strings/);
        expect((await enc('spki', { algorithm: '1.2', publicKey: 'zz' })).stderr).toMatch(/hexadecimal/);
    });

    it('accepts exactly what schema cert-encode-spec declares (audit B2-03, B2-04)', async () => {
        const doc = JSON.parse((await cli(['schema', 'cert-encode-spec'])).stdout) as { $defs: Record<string, Record<string, unknown>> };
        const accepted: [string, unknown][] = [
            ['name-attribute', { type: 'CN', value: 'x', stringType: 'utf8' }],
            ['validity', { notBefore: '2027-01-01T00:00:00Z', validityDays: 30 }],
            ['extension', { oid: '1.2.3', critical: false, value: '0500' }],
            ['extensions', { subjectAltName: { dns: ['a.test'], critical: true }, keyUsage: { usages: ['digitalSignature'], critical: true }, raw: [{ oid: '1.2.3', critical: false, value: '0500' }] }],
            ['extensions', { subjectKeyIdentifier: 'a1b2', authorityKeyIdentifier: false }],
        ];
        for (const [structure, spec] of accepted) {
            expect(validate(spec, doc.$defs[structure] as Record<string, unknown>, doc.$defs), `${structure} ${JSON.stringify(spec)}`).toEqual([]);
            expect((await enc(structure, spec)).code, `${structure} ${JSON.stringify(spec)}`).toBe(0);
        }
        // Each refusal is E_INPUT naming the member, and the schema refuses the same spec.
        const refused: [string, unknown, string][] = [
            // The path names the member exactly: top level, and nested (mutation testing).
            ['extension', { oid: '1.2.3', critical: 'true', value: '0500' }, 'spec critical: expected a boolean'],
            ['extensions', { keyUsage: { usages: ['digitalSignature'], critical: 'true' } }, 'spec extensions.keyUsage.critical: expected a boolean'],
            ['extension', { oid: '1.2.3', value: '0500', critcal: true }, 'critcal: unknown member'],
            ['validity', { notBefore: '2027-01-01T00:00:00Z', notafter: '2028-01-01T00:00:00Z' }, 'notafter: unknown member'],
            ['spki', { algorithm: '1.3.101.112', publicKey: '00', curve: 'x' }, 'curve: unknown member'],
            ['algorithm-identifier', { oid: '1.3.101.112', params: '0500' }, 'params: unknown member'],
            ['attribute', { oid: '1.2.3', values: [], critical: true }, 'critical: unknown member'],
            ['basic-constraints', { ca: true, critical: true }, 'critical: unknown member'],
            ['subject-key-identifier', { keyIdentifier: 'a1b2', critical: false }, 'critical: unknown member'],
            ['authority-key-identifier', { keyIdentifier: 'a1b2', issuer: 'x' }, 'issuer: unknown member'],
            ['subject-alt-name', { dns: ['a.test'], critical: true }, 'critical: unknown member'],
            ['name-attribute', { type: 'CN', value: 'x', critical: true }, 'critical: unknown member'],
            ['extensions', { basicConstraints: { ca: true, pathlen: 1 } }, 'extensions.basicConstraints.pathlen: unknown member'],
            ['extensions', { keyUsage: { usages: ['digitalSignature'], critcal: true } }, 'extensions.keyUsage.critcal: unknown member'],
            ['extensions', { subjectAltName: { dns: ['a.test'], DNS: ['b.test'] } }, 'extensions.subjectAltName.DNS: unknown member'],
            ['extensions', { raw: [{ oid: '1.2.3', value: '0500', critical: false, x: 1 }] }, 'extensions.raw[0].x: unknown member'],
            // No subject key here: the identifier cannot be computed, never SHA-1 of nothing.
            ['extensions', { subjectKeyIdentifier: true }, 'extensions.subjectKeyIdentifier: cannot be computed here'],
        ];
        for (const [structure, spec, message] of refused) {
            const r = await enc(structure, spec, ['--json']);
            expect(r.code, `${structure} ${JSON.stringify(spec)}`).toBe(1);
            expect(envelope(r.stderr), `${structure} ${JSON.stringify(spec)}`).toMatchObject({ error: { code: 'E_INPUT', message: expect.stringContaining(message) } });
            if (!message.includes('cannot be computed')) {
                expect(validate(spec, doc.$defs[structure] as Record<string, unknown>, doc.$defs), `${structure} ${JSON.stringify(spec)}`).not.toEqual([]);
            }
        }
        // An extension's criticality is what the spec says.
        expect((await enc('extension', { oid: '2.5.29.19', critical: false, value: '3000' })).stdout).toBe('30090603551d1304023000\n');
    });

    it('refuses a misspelt cert create member, and a malformed instant as a defect of the spec (audit B2-04, A2-06)', async () => {
        const create = (spec: object) => cli(['cert', 'create', '--spec', file(dir, `c${Math.random()}.json`, spec), '--key', fixture('ed25519.key.pem'), '--json']);
        expect(envelope((await create({ subject: { CN: 'x' }, notAfer: '2028-01-01T00:00:00Z' })).stderr)).toMatchObject({ error: { code: 'E_INPUT', message: expect.stringContaining('spec notAfer: unknown member') } });
        const instant = await create({ subject: { CN: 'x' }, notBefore: '2027-02-31T00:00:00Z' });
        expect(instant.code).toBe(1);
        expect(envelope(instant.stderr)).toMatchObject({ error: { code: 'E_INPUT', message: expect.stringContaining('spec notBefore: expected an instant') } });
    });

    it('refuses a spec for the signature algorithm, which the signer flags decide (audit B2-04)', async () => {
        const r = await cli(['cert', 'encode', 'signature-algorithm', '--key', fixture('ed25519.key.pem'), '--spec', file(dir, 'sig.json', {})]);
        expect(r.code).toBe(2);
        expect(r.stderr).toMatch(/takes no --spec/);
    });
});

describe('csr', () => {
    it('inspects a request', async () => {
        const r = await cli(['csr', 'inspect', fixture('leaf.csr.pem')]);
        expect(r.stdout).toContain('Subject:    CN=csr.example.test,O=pkinative-cli test,C=FR');
        expect(r.stdout).toContain('subjectAltName: DNS:csr.example.test');
        expect(r.stdout).toContain('Attributes: extensionRequest');
        const summary = JSON.parse((await cli(['csr', 'inspect', fixture('leaf.csr.der'), '--json', '--summary'])).stdout);
        expect(summary).toEqual({ subject: 'CN=csr.example.test,O=pkinative-cli test,C=FR', publicKey: 'ec', extensions: ['subjectAltName'] });
        expect((await cli(['csr', 'inspect', fixture('leaf.csr.der'), '--raw-extensions'])).stdout).toMatch(/subjectAltName: \d+ bytes/);
    });

    it('verifies a request, and fails on a tampered one', async () => {
        expect((await cli(['csr', 'verify', fixture('leaf.csr.pem')])).stdout).toBe('request signature: valid\n');
        const der = Buffer.from(fixtureBytes('leaf.csr.der'));
        der[der.length - 5] = (der[der.length - 5] as number) ^ 0xff;
        const dir = emptyDir();
        writeFileSync(join(dir, 'bad.der'), der);
        const bad = await cli(['csr', 'verify', join(dir, 'bad.der'), '--json', '--summary']);
        expect(bad.code).toBe(1);
        expect(JSON.parse(bad.stdout)).toMatchObject({ valid: false });
        expect(envelope(bad.stderr)).toMatchObject({ error: { code: 'E_VERIFY_FAILED' } });
    });

    it('creates a request from a plain key, or from an encrypted one with its public key', async () => {
        const dir = emptyDir();
        const spec = file(dir, 's.json', { subject: { CN: 'req.example.test' }, extensions: { subjectAltName: { dns: ['req.example.test'] }, subjectKeyIdentifier: true } });
        const r = await cli(['csr', 'create', '--spec', spec, '--key', fixture('leaf.key.pem')]);
        expect(r.code).toBe(0);
        const req = parseCertificationRequest(decodePem(r.stdout)[0]!.bytes);
        expect(req.extensions?.map((e) => e.kind)).toEqual(['subjectAltName', 'subjectKeyIdentifier']);
        const enc = await cli(['csr', 'create', '--spec', spec, '--key', fixture('leaf.key.enc.pem'), '--public-key', fixture('leaf.csr.pem')], { env: { PKINATIVE_PASSWORD: PASSWORD } });
        expect(enc.code).toBe(0);
        const bare = await cli(['csr', 'create', '--spec', file(dir, 'b.json', { subject: { CN: 'bare' } }), '--key', fixture('ed25519.key.pem'), '--encoding', 'der', '-o', join(dir, 'bare.der')]);
        expect(bare.code).toBe(0);
        expect(parseCertificationRequest(new Uint8Array(readFileSync(join(dir, 'bare.der')))).extensions).toBeUndefined();
    });

    it('refuses an incomplete spec, a missing public key and a mismatched key', async () => {
        const dir = emptyDir();
        expect((await cli(['csr', 'create', '--key', fixture('leaf.key.pem')])).code).toBe(2);
        expect((await cli(['csr', 'create', '--spec', file(dir, 'a.json', { extensions: {} }), '--key', fixture('leaf.key.pem')])).stderr).toMatch(/subject: is required/);
        expect((await cli(['csr', 'create', '--spec', file(dir, 'b.json', { subject: { CN: 'x' }, notBefore: 1 }), '--key', fixture('leaf.key.pem')])).stderr).toMatch(/only "subject" and "extensions"/);
        const spec = file(dir, 'c.json', { subject: { CN: 'x' } });
        expect((await cli(['csr', 'create', '--spec', spec, '--key', fixture('leaf.key.enc.pem'), '--key-type', 'ec-p256'], { env: { PKINATIVE_PASSWORD: PASSWORD } })).stderr).toMatch(/public key is needed/);
        const mismatch = await cli(['csr', 'create', '--spec', spec, '--key', fixture('leaf.key.pem'), '--public-key', fixture('ed25519.crt.pem'), '--json']);
        expect(envelope(mismatch.stderr)).toMatchObject({ error: { code: 'E_INPUT', message: expect.stringMatching(/does not match/) } });
    });
});

describe('cert and signer edge paths', () => {
    it('renders a name mismatch as text', async () => {
        expect((await cli(['cert', 'match-name', 'a.test', 'b.test'])).stdout).toBe('no match\n');
    });

    it('computes the AKI of an issuer without a subjectKeyIdentifier', async () => {
        const dir = emptyDir();
        const caPem = (await cli(['cert', 'create', '--spec', file(dir, 'ca.json', { ...CA_SPEC, extensions: { ...CA_SPEC.extensions, subjectKeyIdentifier: false } }), '--key', fixture('ed25519.key.pem')])).stdout;
        const r = await cli(['cert', 'create', '--spec', file(dir, 'l.json', { subject: { CN: 'l' }, notBefore: '2026-01-01T00:00:00Z' }), '--key', fixture('ed25519.key.pem'), '--issuer', file(dir, 'ca.pem', caPem), '--public-key', fixture('leaf.pub.pem')]);
        expect(r.code).toBe(0);
        expect(pemCert(r.stdout).extensions.map((e) => e.kind)).toContain('authorityKeyIdentifier');
    });

    it('summarises a request without extensions', async () => {
        const dir = emptyDir();
        const req = await cli(['csr', 'create', '--spec', file(dir, 'b.json', { subject: { CN: 'bare' } }), '--key', fixture('ed25519.key.pem'), '-o', join(dir, 'bare.pem')]);
        expect(req.code).toBe(0);
        expect(JSON.parse((await cli(['csr', 'inspect', join(dir, 'bare.pem'), '--json', '--summary'])).stdout).extensions).toEqual([]);
    });

    it('refuses a non-string hex value', async () => {
        const dir = emptyDir();
        const r = await cli(['cert', 'create', '--spec', file(dir, 's.json', { subject: { CN: 'x' }, notBefore: '2026-01-01T00:00:00Z', extensions: { raw: [{ oid: '1.2.3', value: 5 }] } }), '--key', fixture('leaf.key.pem')]);
        expect(r.stderr).toMatch(/raw\[0\]\.value: expected a hexadecimal string/);
    });

    it('refuses a DER key that is neither PKCS#8 nor encrypted PKCS#8', async () => {
        const { createPrivateKey } = await import('node:crypto');
        const dir = emptyDir();
        const sec1 = createPrivateKey(readFileSync(fixture('leaf.key.pem'))).export({ type: 'sec1', format: 'der' });
        writeFileSync(join(dir, 'sec1.der'), sec1);
        const r = await cli(['cert', 'create', '--spec', file(dir, 's.json', { subject: { CN: 'x' } }), '--key', join(dir, 'sec1.der'), '--json']);
        expect(r.code).toBe(1);
        expect(envelope(r.stderr)).toMatchObject({ error: { code: 'E_PARSE', message: expect.stringMatching(/PKCS#8 expected/) } });
    });

    it('decrypts an encrypted DER key', async () => {
        const { createPrivateKey } = await import('node:crypto');
        const dir = emptyDir();
        const der = createPrivateKey(readFileSync(fixture('leaf.key.pem'))).export({ type: 'pkcs8', format: 'der', cipher: 'aes-256-cbc', passphrase: PASSWORD });
        writeFileSync(join(dir, 'enc.der'), der);
        const r = await cli(['cert', 'create', '--spec', file(dir, 's.json', { subject: { CN: 'x' }, notBefore: '2026-01-01T00:00:00Z' }), '--key', join(dir, 'enc.der'), '--key-type', 'ec-p256', '--public-key', fixture('leaf.pub.pem')], { env: { PKINATIVE_PASSWORD: PASSWORD } });
        expect(r.code).toBe(0);
    });

    it('refuses a PKCS#12 file without a usable key', async () => {
        const dir = emptyDir();
        const r = await cli(['cert', 'create', '--spec', file(dir, 's.json', { subject: { CN: 'x' } }), '--p12', fixture('certs-only.p12'), '--json'], { env: { PKINATIVE_PASSWORD: PASSWORD } });
        expect(r.code).toBe(1);
        expect(envelope(r.stderr)).toMatchObject({ error: { code: 'E_INPUT', message: expect.stringMatching(/holds 0 usable keys/) } });
    });
});

describe('signature algorithm selection', () => {
    async function generated(type: string, options: object = {}): Promise<string> {
        const { generateKeyPairSync } = await import('node:crypto');
        const { privateKey } = generateKeyPairSync(type as 'ec', options as never) as unknown as { privateKey: KeyObject };
        const dir = emptyDir();
        writeFileSync(join(dir, 'k.der'), privateKey.export({ type: 'pkcs8', format: 'der' }));
        return join(dir, 'k.der');
    }

    async function create(key: string, extra: string[] = [], env: Record<string, string> = {}) {
        const dir = emptyDir();
        return cli(['cert', 'create', '--spec', file(dir, 's.json', { subject: { CN: 'k' }, notBefore: '2026-01-01T00:00:00Z' }), '--key', key, '--json', ...extra], { env });
    }

    it('signs with Ed448, without a hash', async () => {
        const key = await generated('ed448');
        const r = await create(key);
        expect(r.code).toBe(0);
        expect(pemCert(r.stdout).signatureAlgorithm.oid).toBe('1.3.101.113');
        expect(envelope((await create(key, ['--hash', 'SHA-512'])).stderr)).toMatchObject({ error: { message: expect.stringMatching(/does not apply to Ed448/) } });
    });

    it('signs with an id-RSASSA-PSS key by RSA-PSS only', async () => {
        const key = await generated('rsa-pss', { modulusLength: 2048 });
        const r = await create(key);
        expect(r.code).toBe(0);
        expect(pemCert(r.stdout).signatureAlgorithm.oid).toBe('1.2.840.113549.1.1.10');
        expect(envelope((await create(key, ['--rsa-scheme', 'pkcs1'])).stderr)).toMatchObject({ error: { message: expect.stringMatching(/RSA-PSS only/) } });
    });

    it('refuses keys Web Crypto cannot sign with', async () => {
        expect(envelope((await create(await generated('ec', { namedCurve: 'secp256k1' }))).stderr)).toMatchObject({ error: { code: 'E_UNSUPPORTED', message: expect.stringMatching(/P-256, P-384, P-521/) } });
        expect(envelope((await create(await generated('x25519'))).stderr)).toMatchObject({ error: { code: 'E_UNSUPPORTED', message: expect.stringMatching(/1\.3\.101\.110/) } });
    });

    it('opens an RSA PKCS#12 key only with a scheme', async () => {
        const env = { PKINATIVE_PASSWORD: PASSWORD };
        const dir = emptyDir();
        const spec = file(dir, 's.json', { subject: { CN: 'k' }, notBefore: '2026-01-01T00:00:00Z' });
        const base = ['cert', 'create', '--spec', spec, '--p12', fixture('rsa.p12'), '--issuer', fixture('rsa.crt.pem'), '--public-key', fixture('leaf.pub.pem'), '--json'];
        const noScheme = await cli(base, { env });
        expect(noScheme.code).toBe(2);
        expect(envelope(noScheme.stderr)).toMatchObject({ error: { code: 'E_USAGE', message: expect.stringMatching(/--rsa-scheme/) } });
        const pkcs1 = await cli([...base, '--rsa-scheme', 'pkcs1'], { env });
        expect(pkcs1.code).toBe(0);
        expect(pemCert(pkcs1.stdout).signatureAlgorithm.oid).toBe('1.2.840.113549.1.1.11');
        const pss = await cli([...base, '--rsa-scheme', 'pss', '--hash', 'SHA-512'], { env });
        expect((await cli([...base, '--rsa-scheme', 'pss'], { env })).code).toBe(0);
        expect(pemCert(pss.stdout).signatureAlgorithm.oid).toBe('1.2.840.113549.1.1.10');
    });

    it('signs from a PKCS#12 EC key with its own hash, and refuses a legacy file', async () => {
        const env = { PKINATIVE_PASSWORD: PASSWORD };
        const dir = emptyDir();
        const spec = file(dir, 's.json', { subject: { CN: 'k' }, notBefore: '2026-01-01T00:00:00Z' });
        const ok = await cli(['cert', 'create', '--spec', spec, '--p12', fixture('leaf.p12'), '--issuer', fixture('leaf.crt.pem'), '--public-key', fixture('ed25519.crt.pem')], { env });
        expect(pemCert(ok.stdout).signatureAlgorithm.oid).toBe('1.2.840.10045.4.3.2');
        const legacy = await cli(['cert', 'create', '--spec', spec, '--p12', fixture('legacy.p12'), '--json'], { env });
        expect(legacy.code).toBe(1);
        expect(envelope(legacy.stderr)).toMatchObject({ error: { code: 'E_SECURITY', reasons: expect.any(Array), remedy: expect.stringContaining('-legacy -aes256') } });
    });
});

describe('strict mode', () => {
    it('escalates the first engine warning to E_CHECK_FAILED', async () => {
        expect((await cli(['cert', 'inspect', fixture('revoked.crt.pem')])).code).toBe(0);
        const r = await cli(['cert', 'inspect', fixture('revoked.crt.pem'), '--strict', '--json']);
        expect(r.code).toBe(1);
        expect(envelope(r.stderr)).toMatchObject({ error: { code: 'E_CHECK_FAILED', pkiCode: 'PKI_STRICT_DIAGNOSTIC', remedy: expect.stringMatching(/drop --strict/) } });
    });
});
