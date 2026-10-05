import { createPrivateKey } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { cli, emptyDir, envelope, fixture, fixtureBytes } from '../helpers/io.js';

const ENV = { PKINATIVE_PASSWORD: 'test-only-password' };

/** Every encoding of the leaf private key a careless report could leak. */
function leafSecrets(): string[] {
    const jwk = createPrivateKey(readFileSync(fixture('leaf.key.pem'))).export({ format: 'jwk' });
    const scalar = Buffer.from(jwk.d as string, 'base64url');
    return [Buffer.from(fixtureBytes('leaf.key.der')).toString('hex'), scalar.toString('hex'), scalar.toString('base64'), jwk.d as string];
}

function expectNoSecret(...outputs: string[]): void {
    for (const secret of leafSecrets()) {
        for (const out of outputs) expect(out.toLowerCase().includes(secret.toLowerCase()), 'a private key byte reached the output').toBe(false);
    }
}

describe('key', () => {
    it('describes plain and encrypted keys without their bytes', async () => {
        const plain = await cli(['key', 'inspect', fixture('leaf.key.pem'), '--json']);
        expect(JSON.parse(plain.stdout)).toEqual({ format: 'pkcs8', version: 0, kind: 'ec', curve: 'P-256', algorithm: '1.2.840.10045.2.1', attributes: [], publicKey: false });
        const der = await cli(['key', 'inspect', fixture('leaf.key.der')]);
        expect(der.stdout).toContain('kind: "ec"');
        const enc = JSON.parse((await cli(['key', 'inspect', fixture('leaf.key.enc.pem'), '--json'])).stdout);
        expect(enc).toMatchObject({ format: 'encrypted-pkcs8', encryption: { pbes2: { iterations: 2048, prf: 'SHA-256', keyBits: 256 } } });
        expect((await cli(['key', 'inspect', fixture('rsa.key.pem')])).stdout).toContain('kind: "rsa"');
        expectNoSecret(plain.stdout, der.stdout, plain.stderr);
    });

    it('describes an encrypted DER key', async () => {
        const dir = emptyDir();
        const der = createPrivateKey(readFileSync(fixture('leaf.key.pem'))).export({ type: 'pkcs8', format: 'der', cipher: 'aes-256-cbc', passphrase: 'x' });
        writeFileSync(join(dir, 'e.der'), der);
        expect(JSON.parse((await cli(['key', 'inspect', join(dir, 'e.der'), '--json'])).stdout).format).toBe('encrypted-pkcs8');
    });

    it('checks that a key imports or decrypts', async () => {
        const plain = await cli(['key', 'check', fixture('leaf.key.pem'), '--json']);
        expect(JSON.parse(plain.stdout)).toMatchObject({ imported: true, encrypted: false, key: { type: 'private', extractable: false, usages: ['sign'] } });
        const enc = await cli(['key', 'check', fixture('leaf.key.enc.pem'), '--key-type', 'ec-p256'], { env: ENV });
        expect(enc.stdout).toMatch(/^key imported \(decrypted\): \{"name":"ECDSA"/);
        const rsa = await cli(['key', 'check', fixture('rsa.key.pem'), '--rsa-scheme', 'pss', '--hash', 'SHA-512', '--salt-length', '64', '--json']);
        expect(JSON.parse(rsa.stdout).algorithm).toEqual({ name: 'RSA-PSS', hash: 'SHA-512', saltLength: 64 });
        expect((await cli(['key', 'check', fixture('leaf.key.enc.pem'), '--key-type', 'ec-p256'], { env: { PKINATIVE_PASSWORD: 'wrong' } })).stderr).toMatch(/E_PASSWORD/);
        expect((await cli(['key', 'check', fixture('rsa.key.pem')])).code).toBe(2);
        expectNoSecret(plain.stdout, enc.stdout);
    });

    it('reads the password from a file, and refuses --password-stdin with a stdin key', async () => {
        const dir = emptyDir();
        writeFileSync(join(dir, 'pw'), 'test-only-password\n');
        expect((await cli(['key', 'check', fixture('leaf.key.enc.pem'), '--key-type', 'ec-p256', '--password-file', join(dir, 'pw')])).code).toBe(0);
        expect((await cli(['key', 'check', '--password-stdin'], { stdin: 'x' })).stderr).toMatch(/cannot come from stdin/);
    });
});

describe('p12', () => {
    it('inspects without a password', async () => {
        const r = await cli(['p12', 'inspect', fixture('leaf.p12')]);
        expect(r.stdout).toBe('PKCS#12 v3, MAC: pbmac1, 2048 iterations\n  authSafe[0]: encrypted (PBES2 (PBKDF2 with HMAC-SHA-256, AES-256-CBC))\n  authSafe[1]: 1 bag(s): pkcs8ShroudedKeyBag\n');
        const json = JSON.parse((await cli(['p12', 'inspect', fixture('leaf.p12'), '--json'])).stdout);
        expect(json.mac).toMatchObject({ kind: 'pbmac1', pbmac1: { prf: 'SHA-256', hmac: 'SHA-256' } });
        expect((await cli(['p12', 'inspect', fixture('legacy.p12')])).stdout).toMatch(/MAC: pkcs12-kdf/);
    });

    it('inspects a file without a MAC', async () => {
        expect((await cli(['p12', 'inspect', fixture('nomac.p12')])).stdout).toContain('MAC: none\n  authSafe[0]: 1 bag(s): certBag');
    });

    it('verifies the MAC', async () => {
        expect((await cli(['p12', 'verify-mac', fixture('leaf.p12')], { env: ENV })).stdout).toBe('MAC: valid\n');
        const wrong = await cli(['p12', 'verify-mac', fixture('leaf.p12'), '--json'], { env: { PKINATIVE_PASSWORD: 'nope' } });
        expect(wrong.code).toBe(1);
        // One class for a wrong password across the p12 subcommands (audit A-05).
        expect(envelope(wrong.stderr)).toMatchObject({ error: { code: 'E_PASSWORD' } });
        // A legacy MAC: E_SECURITY with the CLI remedy, never a library option name (audit B-10).
        const legacy = await cli(['p12', 'verify-mac', fixture('legacy.p12'), '--json'], { env: ENV });
        expect(envelope(legacy.stderr)).toMatchObject({ error: { code: 'E_SECURITY', pkiCode: 'PKI_KEY_MAC_UNSUPPORTED', remedy: expect.stringContaining('--allow-unverified-integrity') } });
        expect((await cli(['p12', 'verify-mac', fixture('leaf.p12')])).stderr).toMatch(/needs the password/);
        // No MAC at all is a verdict, exit 1 — not a usage error (audit A-03).
        const none = await cli(['p12', 'verify-mac', fixture('nomac.p12'), '--json'], { env: ENV });
        expect(none.code).toBe(1);
        expect(JSON.parse(none.stdout)).toEqual({ valid: false, mac: null });
        expect(envelope(none.stderr)).toMatchObject({ error: { code: 'E_VERIFY_FAILED', remedy: expect.stringContaining('--allow-unverified-integrity') } });
        expect((await cli(['p12', 'verify-mac', fixture('nomac.p12')], { env: ENV })).stdout).toMatch(/MAC \(none present\)/);
    });

    it('converts legacy PKCS#12 with the two-step OpenSSL remedy (engine 1.0.0 item 53)', async () => {
        for (const sub of ['open', 'bags']) {
            const r = await cli(['p12', sub, fixture('legacy.p12'), '--json'], { env: ENV });
            expect(envelope(r.stderr), sub).toMatchObject({ error: { code: 'E_SECURITY', remedy: expect.stringContaining('openssl pkcs12 -in legacy.p12 -legacy -aes256 -out bundle.pem') } });
            expect(envelope(r.stderr).error, sub).toMatchObject({ remedy: expect.stringContaining('-pbmac1_pbkdf2 -out modern.p12') });
        }
    });

    it('writes --certs-out only from a file that opened (audit A-02)', async () => {
        const dir = emptyDir();
        const out = join(dir, 'certs.pem');
        const nomac = await cli(['p12', 'open', fixture('nomac.p12'), '--certs-out', out, '--json'], { env: ENV });
        expect(nomac.code).toBe(1);
        expect(envelope(nomac.stderr)).toMatchObject({ error: { code: 'E_VERIFY_FAILED', remedy: expect.stringContaining('--allow-unverified-integrity') } });
        expect(existsSync(out)).toBe(false);
        const wrong = await cli(['p12', 'open', fixture('leaf.p12'), '--certs-out', out, '--json'], { env: { PKINATIVE_PASSWORD: 'nope' } });
        expect(envelope(wrong.stderr)).toMatchObject({ error: { code: 'E_PASSWORD' } });
        expect(existsSync(out)).toBe(false);
        expect((await cli(['p12', 'open', fixture('leaf.p12'), '--certs-out', out], { env: ENV })).code).toBe(0);
        expect(readFileSync(out, 'utf8')).toMatch(/^-----BEGIN CERTIFICATE-----/);
    });

    it('lists every bag, decrypting the encrypted contents', async () => {
        const r = await cli(['p12', 'bags', fixture('leaf.p12')], { env: ENV });
        expect(r.stdout).toBe([
            'authSafe[0].bags[0]: certBag CN=example.test,O=pkinative-cli test,C=FR "test leaf"',
            'authSafe[0].bags[1]: certBag CN=Test Intermediate CA,O=pkinative-cli test,C=FR',
            'authSafe[1].bags[0]: pkcs8ShroudedKeyBag "test leaf"',
            '',
        ].join('\n'));
    });

    it('opens a file, imports its key and exports its certificates', async () => {
        const dir = emptyDir();
        const r = await cli(['p12', 'open', fixture('leaf.p12'), '--certs-out', join(dir, 'certs.pem'), '--json'], { env: ENV });
        expect(r.code).toBe(0);
        const report = JSON.parse(r.stdout);
        expect(report).toMatchObject({ valid: true, integrity: 'verified', crls: 0, reasons: [] });
        expect(report.keys[0]).toMatchObject({ friendlyName: 'test leaf', certificate: 'CN=example.test,O=pkinative-cli test,C=FR', signingKey: { key: { extractable: false } } });
        expect(readFileSync(join(dir, 'certs.pem'), 'utf8').match(/BEGIN CERTIFICATE/g)).toHaveLength(2);
        expect(envelope(r.stderr)).toMatchObject({ certsOut: join(dir, 'certs.pem') });
        expect((await cli(['p12', 'open', fixture('leaf.p12')], { env: ENV })).stdout).toMatch(/^PKCS#12 \(integrity verified\): valid\n {2}key authSafe\[1\]\.bags\[0\] — CN=example\.test/);
        const dry = await cli(['p12', 'open', fixture('leaf.p12'), '--certs-out', join(dir, 'dry.pem'), '--dry-run'], { env: ENV });
        expect(dry.code).toBe(0);
    });

    it('needs a scheme for an RSA key, and reports failures by class', async () => {
        const rsa = await cli(['p12', 'open', fixture('rsa.p12'), '--json'], { env: ENV });
        expect(rsa.code).toBe(2);
        expect(envelope(rsa.stderr)).toMatchObject({ error: { code: 'E_USAGE', remedy: '--rsa-scheme pkcs1|pss' } });
        expect((await cli(['p12', 'open', fixture('rsa.p12'), '--rsa-scheme', 'pkcs1'], { env: ENV })).code).toBe(0);
        expect((await cli(['p12', 'open', fixture('rsa.p12'), '--rsa-scheme', 'pss', '--hash', 'SHA-384'], { env: ENV })).code).toBe(0);
        const wrong = await cli(['p12', 'open', fixture('leaf.p12'), '--json'], { env: { PKINATIVE_PASSWORD: 'nope' } });
        expect(envelope(wrong.stderr)).toMatchObject({ error: { code: 'E_PASSWORD' } });
        const legacy = await cli(['p12', 'open', fixture('legacy.p12'), '--allow-unverified-integrity'], { env: ENV });
        expect(legacy.code).toBe(1);
        expect(legacy.stdout).toMatch(/\(not imported\)/);
    });

    it('never prints a key byte, even from an unencrypted keyBag', async () => {
        const outputs: string[] = [];
        for (const argv of [['p12', 'inspect'], ['p12', 'bags'], ['p12', 'open']]) {
            for (const mode of [[], ['--json'], ['--json', '--pretty']]) {
                const r = await cli([...argv, fixture('plain-keybag.p12'), ...mode], { env: ENV });
                expect(r.code, argv.join(' ')).toBe(0);
                outputs.push(r.stdout, r.stderr);
            }
        }
        expect(outputs.join('')).toContain('keyBag');
        expectNoSecret(...outputs);
    });
});

describe('key views', () => {
    it('lists PKCS#8 attributes and survives an unreadable certificate bag', async () => {
        const { privateKeyView, bagView } = await import('../../src/utils/key-views.js');
        const { pemBundle } = await import('../../src/commands/p12.js');
        expect(privateKeyView({ version: 1, kind: 'ed25519', curve: undefined, algorithm: { oid: '1.3.101.112' }, attributes: [{ oid: '1.2.3' }], publicKey: { bytes: new Uint8Array(32), unusedBits: 0 } } as never))
            .toEqual({ format: 'pkcs8', version: 1, kind: 'ed25519', algorithm: '1.3.101.112', attributes: ['1.2.3'], publicKey: true });
        expect(bagView({ path: 'p', kind: 'certBag', oid: '1.2', certificateDer: new Uint8Array([0x30, 0x00]) } as never, {})).toMatchObject({ certificate: { unreadable: true, bytes: 2 } });
        expect(bagView({ path: 'p', kind: 'crlBag', oid: '1.2', crlDer: new Uint8Array(5) } as never, {})).toEqual({ path: 'p', kind: 'crlBag', oid: '1.2', crlBytes: 5 });
        const { encryptionView } = await import('../../src/utils/key-views.js');
        expect(encryptionView({ scheme: 's', algorithm: { oid: '1.2' }, pbes2: { iterations: 1, prf: 'SHA-256', keyBits: 128, cipherOid: '1.2.3.4', salt: new Uint8Array(8) } } as never))
            .toMatchObject({ pbes2: { cipher: '1.2.3.4', saltBytes: 8 } });
        expect(encryptionView({ scheme: 'pbeWithSHA1', algorithm: { oid: '1.2' }, pbes2: undefined } as never)).toEqual({ scheme: 'pbeWithSHA1', algorithm: '1.2' });
        expect(pemBundle([new Uint8Array([0x30, 0x00])], [new Uint8Array([0x30, 0x00])])).toBe('-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----\n-----BEGIN X509 CRL-----\nMAA=\n-----END X509 CRL-----\n');
    });

    it('renders a plain key check as text', async () => {
        expect((await cli(['key', 'check', fixture('ed25519.key.pem')])).stdout).toBe('key imported: {"name":"Ed25519"} (private, non-extractable)\n');
    });
});

describe('engine bounds through the CLI', () => {
    it('bounds the PBKDF2 work of a whole PKCS#12', async () => {
        const r = await cli(['p12', 'open', fixture('leaf.p12'), '--max-pkcs12-kdf-iterations', '1000', '--json'], { env: ENV });
        expect(r.code).toBe(1);
        expect(envelope(r.stderr)).toMatchObject({ error: { reasons: [{ code: 'PKI_REASON_INPUT_MALFORMED', errorCode: 'PKI_LIMIT_EXCEEDED', path: 'pkcs12' }] } });
    });
});
