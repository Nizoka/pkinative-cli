import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { INVOCATIONS } from '../../src/generated/report-schemas.js';
import { AT, cli, emptyDir, envelope, fixture, fixtureBytes } from '../helpers/io.js';

const TRUST = ['--trust', fixture('root.crt.pem')];
const INTER = ['--untrusted', fixture('inter.crt.pem')];

describe('chain verify', () => {
    it('verifies the leaf with revocation, name and purpose', async () => {
        const r = await cli(['chain', 'verify', fixture('leaf.crt.pem'), ...TRUST, ...INTER, '--at', AT,
            '--host', 'a.wild.example.test', '--purpose', 'serverAuth', '--crl', fixture('inter.crl.pem'), '--ocsp', fixture('leaf.ocsp.der'), '--require-revocation']);
        expect(r.code).toBe(0);
        expect(r.stdout).toBe([
            'chain: valid',
            'Path:',
            '  0: CN=example.test,O=pkinative-cli test,C=FR  (serial 1001)',
            '  1: CN=Test Intermediate CA,O=pkinative-cli test,C=FR  (serial 02)',
            '  2: CN=Test Root CA,O=pkinative-cli test,C=FR  (serial 01)',
            '',
        ].join('\n'));
    });

    it('emits the report, the summary and the status envelope', async () => {
        const r = await cli(['chain', 'verify', '-i', fixture('leaf.crt.der'), ...TRUST, ...INTER, '--at', AT, '--json']);
        const report = JSON.parse(r.stdout);
        expect(report).toMatchObject({ valid: true, reasons: [], explored: expect.any(Number), signatureVerifications: 2 });
        expect(report.path).toHaveLength(3);
        expect(envelope(r.stderr)).toMatchObject({ ok: true, command: 'chain verify', valid: true, pathLength: 3, signaturesChecked: true });
        const summary = JSON.parse((await cli(['chain', 'verify', fixture('leaf.crt.der'), ...TRUST, ...INTER, '--at', AT, '--json', '--summary'])).stdout);
        expect(summary).toMatchObject({ valid: true, reasons: [], path: ['CN=example.test,O=pkinative-cli test,C=FR', expect.any(String), expect.any(String)] });
    });

    it('fails a revoked certificate, by CRL and by OCSP', async () => {
        for (const evidence of [['--crl', fixture('inter.crl.der')], ['--ocsp', fixture('revoked.ocsp.der')]]) {
            const r = await cli(['chain', 'verify', fixture('revoked.crt.pem'), ...TRUST, ...INTER, '--at', AT, ...evidence, '--json']);
            expect(r.code).toBe(1);
            expect(JSON.parse(r.stdout).reasons.map((x: { code: string }) => x.code)).toContain('PKI_REASON_REVOKED');
            expect(envelope(r.stderr)).toMatchObject({ ok: false, error: { code: 'E_VERIFY_FAILED' }, diagnostics: expect.any(Array) });
        }
    });

    it('fails an expired path, a wrong name, a wrong purpose, a missing anchor', async () => {
        const expired = await cli(['chain', 'verify', fixture('leaf.crt.pem'), ...TRUST, ...INTER, '--at', '2050-01-01']);
        expect(expired.code).toBe(1);
        expect(expired.stdout).toMatch(/^chain: INVALID\n {2}PKI_REASON_EXPIRED/);
        expect((await cli(['chain', 'verify', fixture('leaf.crt.pem'), ...TRUST, ...INTER, '--at', AT, '--ip', '192.0.2.99'])).code).toBe(1);
        expect((await cli(['chain', 'verify', fixture('leaf.crt.pem'), ...TRUST, ...INTER, '--at', AT, '--purpose', 'codeSigning'])).code).toBe(1);
        const summary = await cli(['chain', 'verify', fixture('leaf.crt.pem'), ...TRUST, ...INTER, '--at', '2050-01-01', '--json', '--summary']);
        expect(JSON.parse(summary.stdout).reasons).toContain('PKI_REASON_EXPIRED');
        const lost = await cli(['chain', 'verify', fixture('leaf.crt.pem'), ...TRUST, '--at', AT]);
        expect(lost.code).toBe(1);
        expect(lost.stdout).toMatch(/^chain: INVALID/);
        expect(lost.stdout).toContain('PKI_REASON_NO_TRUST_ANCHOR');
        // The members chain adds beside the engine report are in the generated summary schema (audit D-73).
        const summaryKeys = Object.keys(JSON.parse(summary.stdout) as object);
        const schema = INVOCATIONS['chain verify']?.summary as { properties?: Record<string, unknown> } | undefined;
        for (const key of summaryKeys) expect(Object.keys(schema?.properties ?? {}), key).toContain(key);
    });

    it('requires revocation evidence when asked, and checks the OCSP nonce', async () => {
        expect((await cli(['chain', 'verify', fixture('leaf.crt.pem'), ...TRUST, ...INTER, '--at', AT, '--require-revocation'])).code).toBe(1);
        const nonce = await cli(['chain', 'verify', fixture('leaf.crt.pem'), ...TRUST, ...INTER, '--at', AT, '--ocsp', fixture('leaf.ocsp.der'), '--ocsp-nonce', '00', '--require-ocsp-nonce', '--json']);
        expect(nonce.code).toBe(1);
        expect((await cli(['chain', 'verify', fixture('leaf.crt.pem'), ...TRUST, '--ocsp-nonce', 'zz'])).code).toBe(2);
        // The bound of ocsp request and ocsp check: 1 to 32 octets (audit A2-10).
        for (const value of ['', 'ab'.repeat(33)]) {
            const r = await cli(['chain', 'verify', fixture('leaf.crt.pem'), ...TRUST, '--ocsp-nonce', value]);
            expect(r.code, value).toBe(2);
            expect(r.stderr, value).toMatch(/--ocsp-nonce takes 1 to 32 octets/);
        }
        expect((await cli(['chain', 'verify', fixture('leaf.crt.pem'), ...TRUST, '--ocsp-nonce', 'zz'])).stderr).toMatch(/--ocsp-nonce expects hexadecimal/);
    });

    it('applies the policy inputs', async () => {
        const r = await cli(['chain', 'verify', fixture('leaf.crt.pem'), ...TRUST, ...INTER, '--at', AT, '--policy', '2.5.29.32.0', '--require-explicit-policy', '--inhibit-policy-mapping', '--inhibit-any-policy']);
        expect(r.code).toBe(1);
        expect(r.stdout).toMatch(/PKI_REASON_/);
    });

    it('refuses missing anchors and a double reference identity', async () => {
        expect((await cli(['chain', 'verify', fixture('leaf.crt.pem')])).stderr).toMatch(/needs --trust/);
        expect((await cli(['chain', 'verify', fixture('leaf.crt.pem'), ...TRUST, '--host', 'a', '--ip', '192.0.2.1'])).code).toBe(2);
    });

    it('reads anchors and candidates from one PEM bundle', async () => {
        const dir = emptyDir();
        const bundle = join(dir, 'b.pem');
        writeFileSync(bundle, readFileSync(fixture('root.crt.pem'), 'utf8') + readFileSync(fixture('inter.crt.pem'), 'utf8'));
        expect((await cli(['chain', 'verify', fixture('leaf.crt.pem'), '--trust', fixture('root.crt.pem'), '--untrusted', bundle, '--at', AT])).code).toBe(0);
    });
});

describe('chain build', () => {
    it('finds the path without checking signatures', async () => {
        const r = await cli(['chain', 'build', fixture('leaf.crt.pem'), ...TRUST, ...INTER, '--at', AT, '--purpose', 'clientAuth', '--json']);
        expect(r.code).toBe(0);
        const report = JSON.parse(r.stdout);
        expect(report).toMatchObject({ valid: false, signaturesChecked: false });
        expect(report.reasons.every((x: { code: string }) => x.code === 'PKI_REASON_SIGNATURE_NOT_CHECKED')).toBe(true);
        expect(report.path).toHaveLength(3);
        expect((await cli(['chain', 'build', fixture('leaf.crt.pem'), ...TRUST, ...INTER, '--at', AT])).stdout).toMatch(/^path \(signatures not checked\): valid\n/);
    });

    it('fails when no path reaches an anchor', async () => {
        const r = await cli(['chain', 'build', fixture('leaf.crt.pem'), '--trust', fixture('ed25519.crt.pem'), '--at', AT, '--json']);
        expect(r.code).toBe(1);
        expect(envelope(r.stderr)).toMatchObject({ error: { code: 'E_VERIFY_FAILED' } });
        const text = await cli(['chain', 'build', fixture('leaf.crt.pem'), '--trust', fixture('ed25519.crt.pem'), '--at', AT]);
        expect(text.stdout).toMatch(/^path \(signatures not checked\): INVALID\n/);
        expect(text.stdout).toContain('PKI_REASON_NO_TRUST_ANCHOR at path[0]');
        expect(text.stdout).toContain('Path:\n  0: CN=example.test');
    });
});

describe('chain validate', () => {
    it('validates a given path with its signatures', async () => {
        const r = await cli(['chain', 'validate', '--path', fixture('leaf.crt.pem'), '--path', fixture('inter.crt.der'), ...TRUST, '--at', AT, '--json']);
        expect(r.code).toBe(0);
        expect(JSON.parse(r.stdout)).toMatchObject({ valid: true, signaturesChecked: true });
        expect((await cli(['chain', 'validate', fixture('leaf.crt.pem'), fixture('inter.crt.pem'), ...TRUST, '--at', AT])).code).toBe(0);
    });

    it('fails a path whose link signature is wrong', async () => {
        const r = await cli(['chain', 'validate', '--path', fixture('leaf.crt.pem'), '--path', fixture('rsa.crt.pem'), ...TRUST, '--at', AT]);
        expect(r.code).toBe(1);
    });

    it('validates the structure only with --no-signatures', async () => {
        const r = await cli(['chain', 'validate', '--path', fixture('leaf.crt.pem'), '--path', fixture('inter.crt.pem'), ...TRUST, '--at', AT, '--no-signatures', '--json']);
        expect(r.code).toBe(0);
        expect(JSON.parse(r.stdout)).toMatchObject({ valid: false, signaturesChecked: false });
        // The envelope says so too: an ok:true envelope never reads as a verified chain (audit A2-09).
        expect(envelope(r.stderr)).toMatchObject({ ok: true, signaturesChecked: false });
        const expired = await cli(['chain', 'validate', '--path', fixture('leaf.crt.pem'), ...TRUST, '--at', '2050-01-01', '--no-signatures']);
        expect(expired.code).toBe(1);
        // A forged signature passes a structural check, so the headline never says just "valid" (audit A-15).
        const tampered = fixtureBytes('leaf.crt.der').slice();
        tampered[tampered.length - 1] = (tampered[tampered.length - 1] as number) ^ 1;
        const forged = await cli(['chain', 'validate', '-', fixture('inter.crt.pem'), ...TRUST, '--at', AT, '--no-signatures'], { stdin: tampered });
        expect(forged.stdout).toMatch(/^path structure \(signatures NOT checked\): valid\n/);
    });

    it('needs a path', async () => {
        expect((await cli(['chain', 'validate', ...TRUST])).code).toBe(2);
    });

    it('uses the current time without --at', async () => {
        expect((await cli(['chain', 'validate', '--path', fixture('leaf.crt.pem'), '--path', fixture('inter.crt.pem'), ...TRUST])).code).toBe(0);
    });
});
