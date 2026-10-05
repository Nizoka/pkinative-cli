// The purpose and policy inputs of chain verify / build, proven by a verdict
// they change: a dropped --purpose or --policy would let these paths pass.
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { AT, cli, emptyDir, envelope, fixture } from '../helpers/io.js';

/** A CA (Ed25519, self-signed) and a leaf under it that carries certificatePolicies 1.2.3.4. */
async function policyPki(): Promise<{ ca: string; leaf: string }> {
    const dir = emptyDir();
    const write = (name: string, spec: object): string => {
        const path = join(dir, name);
        writeFileSync(path, JSON.stringify(spec));
        return path;
    };
    const ca = join(dir, 'ca.pem');
    const caSpec = write('ca.json', {
        serialNumber: '0x51', subject: { CN: 'Policy CA' }, notBefore: '2026-01-01T00:00:00Z', validityDays: 3650,
        extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
    });
    expect((await cli(['cert', 'create', '--spec', caSpec, '--key', fixture('ed25519.key.pem'), '-o', ca])).code).toBe(0);
    const leaf = join(dir, 'leaf.pem');
    // certificatePolicies: SEQUENCE { PolicyInformation { policyIdentifier 1.2.3.4 } }.
    const leafSpec = write('leaf.json', {
        serialNumber: '0x52', subject: { CN: 'policy.example.test' }, notBefore: '2026-01-01T00:00:00Z', validityDays: 3650,
        extensions: { extendedKeyUsage: ['serverAuth'], raw: [{ oid: '2.5.29.32', value: '3007300506032a0304' }] },
    });
    expect((await cli(['cert', 'create', '--spec', leafSpec, '--key', fixture('ed25519.key.pem'), '--issuer', ca, '--public-key', fixture('leaf.pub.pem'), '-o', leaf])).code).toBe(0);
    return { ca, leaf };
}

describe('chain: the initial policy set', () => {
    it('accepts a path under the asked policy and refuses one outside it', async () => {
        const { ca, leaf } = await policyPki();
        for (const command of ['verify', 'build']) {
            const base = ['chain', command, leaf, '--trust', ca, '--at', AT, '--require-explicit-policy'];
            expect((await cli([...base, '--policy', '1.2.3.4'])).code, command).toBe(0);
            const other = await cli([...base, '--policy', '1.2.3.5', '--json']);
            expect(other.code, command).toBe(1);
            expect(JSON.parse(other.stdout).reasons.map((r: { code: string }) => r.code), command).toContain('PKI_REASON_NO_VALID_POLICY');
        }
        expect((await cli(['chain', 'validate', leaf, '--trust', ca, '--at', AT, '--require-explicit-policy', '--policy', '1.2.3.5'])).code).toBe(1);
        expect((await cli(['chain', 'validate', leaf, '--trust', ca, '--at', AT, '--require-explicit-policy', '--policy', '1.2.3.4'])).code).toBe(0);
    });
});

describe('chain: the purposes', () => {
    it('holds a path to every --purpose', async () => {
        const { ca, leaf } = await policyPki();
        expect((await cli(['chain', 'verify', leaf, '--trust', ca, '--at', AT, '--purpose', 'serverAuth'])).code).toBe(0);
        const wrong = await cli(['chain', 'verify', leaf, '--trust', ca, '--at', AT, '--purpose', 'serverAuth', '--purpose', 'codeSigning', '--json']);
        expect(wrong.code).toBe(1);
        expect(envelope(wrong.stderr)).toMatchObject({ error: { code: 'E_VERIFY_FAILED', reasons: [{ code: 'PKI_REASON_PURPOSE_NOT_PERMITTED' }] } });
    });

    it('applies --purpose to a built path', async () => {
        // A trust anchor given as the leaf is a complete path, so build judges its purpose;
        // tsa.crt.pem carries the extended key usage timeStamping only.
        const base = ['chain', 'build', fixture('tsa.crt.pem'), '--trust', fixture('tsa.crt.pem'), '--at', AT];
        expect((await cli([...base, '--purpose', 'timeStamping'])).code).toBe(0);
        const wrong = await cli([...base, '--purpose', 'codeSigning', '--json']);
        expect(wrong.code).toBe(1);
        expect(JSON.parse(wrong.stdout).reasons.map((r: { code: string }) => r.code)).toEqual(['PKI_REASON_PURPOSE_NOT_PERMITTED']);
    });
});
