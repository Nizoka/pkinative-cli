// Differential parity: the CLI's --json report is the library's own result in
// the ADR 0018 wire form, nothing added, nothing lost. Each case computes the
// result with pkinative directly and compares it with what the CLI printed.

import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import * as pki from 'pkinative';
import { toWire } from '../../src/utils/wire.js';
import { AT, cli, fixture, fixtureBytes } from '../helpers/io.js';

const quiet = { onDiagnostic: () => undefined };
const pem = (name: string) => pki.decodePem(readFileSync(fixture(name), 'utf8'))[0]!.bytes;
const json = async (argv: string[]) => JSON.parse((await cli([...argv, '--json'])).stdout) as unknown;

describe('CLI ⇔ library parity', () => {
    it('cert inspect', async () => {
        expect(await json(['cert', 'inspect', fixture('leaf.crt.der')])).toEqual(toWire(pki.parseCertificate(fixtureBytes('leaf.crt.der'), quiet)));
    });

    it('csr inspect', async () => {
        expect(await json(['csr', 'inspect', fixture('leaf.csr.der')])).toEqual(toWire(pki.parseCertificationRequest(fixtureBytes('leaf.csr.der'), quiet)));
    });

    it('crl inspect and find', async () => {
        expect(await json(['crl', 'inspect', fixture('inter.crl.der')])).toEqual(toWire(pki.parseCertificateList(fixtureBytes('inter.crl.der'), quiet)));
        const entry = pki.findRevocation(fixtureBytes('inter.crl.der'), new Uint8Array([0x10, 0x02]), quiet);
        expect(await json(['crl', 'find', fixture('inter.crl.der'), '--serial', '1002'])).toEqual(toWire({ revoked: true, entry }));
    });

    it('ocsp inspect', async () => {
        expect(await json(['ocsp', 'inspect', fixture('leaf.ocsp.der')])).toEqual(toWire(pki.parseOcspResponse(fixtureBytes('leaf.ocsp.der'), quiet)));
    });

    it('cms inspect and verify', async () => {
        expect(await json(['cms', 'inspect', fixture('attached.p7s')])).toEqual(toWire(pki.parseSignedData(fixtureBytes('attached.p7s'), { ...quiet, allowTrailingData: false })));
        const report = await pki.verifySignedData({
            signedData: fixtureBytes('attached.p7s'), certificates: [], trustAnchors: [pki.parseCertificate(fixtureBytes('root.crt.der'), quiet)],
            crls: [], ocspResponses: [], requireRevocation: false, at: Date.parse(AT), atTimeStamp: false, allowSha1: false,
            requireSigningCertificate: false, requireAlgorithmProtection: false, allowTrailingData: false, encodingRules: 'der',
        });
        expect(await json(['cms', 'verify', fixture('attached.p7s'), '--trust', fixture('root.crt.der'), '--at', AT])).toEqual(toWire(report));
    });

    it('tsp inspect', async () => {
        const r = pki.parseTimeStampResponse(fixtureBytes('content.tsr'), quiet);
        expect(await json(['tsp', 'inspect', fixture('content.tsr')])).toEqual(toWire({ as: 'response', status: r.status, failInfo: r.failInfo, token: r.token }));
    });

    it('chain verify', async () => {
        const anchor = pki.parseCertificate(fixtureBytes('root.crt.der'), quiet);
        const report = await pki.verifyCertificateChain({
            leaf: pki.parseCertificate(fixtureBytes('leaf.crt.der'), quiet),
            candidates: [pki.parseCertificate(fixtureBytes('inter.crt.der'), quiet)],
            trustAnchors: [anchor], at: Date.parse(AT), crls: [], ocspResponses: [], requireOcspNonce: false, requireRevocation: false,
            allowSha1: false, requireExplicitPolicy: false, inhibitPolicyMapping: false, inhibitAnyPolicy: false, ...quiet,
        });
        const cli = await json(['chain', 'verify', fixture('leaf.crt.der'), '--untrusted', fixture('inter.crt.der'), '--trust', fixture('root.crt.der'), '--at', AT]) as Record<string, unknown>;
        expect(cli).toEqual(toWire(report));
    });

    it('asn1 decode and pem decode', async () => {
        expect(await json(['asn1', 'decode', fixture('root.crt.der')])).toEqual(toWire(pki.decodeAsn1(fixtureBytes('root.crt.der'), quiet)));
        const blocks = pki.decodePem(readFileSync(fixture('leaf.crt.pem'), 'utf8'), quiet).map((b, index) => ({ index, ...b }));
        expect(await json(['pem', 'decode', fixture('leaf.crt.pem')])).toEqual(toWire({ blocks }));
    });

    it('oid list', async () => {
        expect(await json(['oid', 'list'])).toEqual(toWire({ registry: pki.OID_REGISTRY }));
    });

    it('fingerprint', async () => {
        const digest = pki.computeFingerprint(pem('leaf.crt.pem'), 'SHA-256');
        expect(await json(['fingerprint', fixture('leaf.crt.pem')])).toMatchObject({ fingerprint: pki.formatFingerprint(digest), hex: Buffer.from(digest).toString('hex') });
    });
});
