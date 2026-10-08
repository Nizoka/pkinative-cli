import { join } from 'node:path';
import { writeFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { renderReport, renderSignedData } from '../../src/commands/cms.js';
import { renderTstInfo, renderVerify } from '../../src/commands/tsp.js';
import { makeCtx } from '../helpers/ctx.js';
import { AT, cli, emptyDir, fixture } from '../helpers/io.js';

const time = (ms: number) => ({ type: 'UTCTime', epochMilliseconds: ms, text: '' });
const alg = (oid: string) => ({ oid, parameters: undefined, der: new Uint8Array() });

describe('signature renderings', () => {
    it('renders unknown OIDs, no signing time and time-stamps', () => {
        const text = renderSignedData({
            version: 3, contentType: '1.2.3.4', content: new Uint8Array(2), digestAlgorithms: [alg('1.2.3.5')],
            certificates: [], crls: [], ocspResponses: [],
            signerInfos: [{ sid: { kind: 'subjectKeyIdentifier', keyIdentifier: new Uint8Array([0xab]) }, digestAlgorithm: alg('1.2.3.5'), signatureAlgorithm: alg('1.2.3.6'), signingTime: undefined, timeStampTokens: [new Uint8Array()] }],
        } as never);
        expect(text).toContain('Content type:  1.2.3.4');
        expect(text).toContain('Digests:       1.2.3.5');
        expect(text).toContain('Signer 0: key id ab\n    1.2.3.5 / 1.2.3.6, 1 time-stamp(s)');
    });

    it('renders a CMS verdict without signer certificate or time', () => {
        const text = renderReport(makeCtx(), { valid: false, reasons: [], signers: [{ index: 0, valid: false, certificate: undefined, signingTime: undefined, reasons: [] }] } as never);
        expect(text).toBe('signature: INVALID\n  signer 0: INVALID');
    });

    it('renders a TSTInfo without accuracy, nonce or TSA name, and a bare verdict', () => {
        const lines = renderTstInfo({ genTime: time(0), accuracy: undefined, policy: '1.2', serialNumber: { hex: '01' }, messageImprint: { hashAlgorithm: alg('1.2.9'), hashedMessage: new Uint8Array([1]) }, nonce: undefined, tsa: undefined } as never);
        expect(lines).toContain('  Imprint:    1.2.9 01');
        expect(lines).toContain('  Nonce:      (none)');
        expect(lines).toContain('  TSA:        (not named)');
        expect(lines[0]).toBe('  Gen time:   1970-01-01T00:00:00.000Z');
        expect(renderVerify(makeCtx(), { valid: false, reasons: [], genTime: undefined, tsaCertificate: undefined } as never)).toBe('time-stamp: INVALID');
    });

    it('renders a rejection with its failure information', async () => {
        const dir = emptyDir();
        writeFileSync(join(dir, 'rej.tsr'), Buffer.from('3009300702010203020780', 'hex'));
        expect((await cli(['tsp', 'inspect', join(dir, 'rej.tsr')])).stdout).toBe('TimeStampResp: rejection (badAlg)\n');
    });

    it('summarises negative verdicts', async () => {
        const cms = JSON.parse((await cli(['cms', 'verify', fixture('detached.p7s'), '--content', fixture('leaf.crt.der'), '--trust', fixture('root.crt.pem'), '--at', AT, '--json', '--summary'])).stdout);
        expect(cms.valid).toBe(false);
        expect(cms.signers[0].reasons.length).toBeGreaterThan(0);
        const tsp = JSON.parse((await cli(['tsp', 'verify', fixture('content.tsr'), '--data', fixture('leaf.crt.der'), '--trust', fixture('root.crt.pem'), '--at', AT, '--json', '--summary'])).stdout);
        expect(tsp.valid).toBe(false);
        expect(tsp.reasons.length).toBeGreaterThan(0);
    });
});

describe('remaining verify paths', () => {
    it('summarises a rejection, verifies at the current time, and under --ber', async () => {
        const dir = emptyDir();
        writeFileSync(join(dir, 'rej.tsr'), Buffer.from('3009300702010203020780', 'hex'));
        expect(JSON.parse((await cli(['tsp', 'inspect', join(dir, 'rej.tsr'), '--json', '--summary'])).stdout)).toEqual({ as: 'response' });
        expect((await cli(['tsp', 'verify', fixture('content.tsr'), '--data', fixture('content.txt'), '--trust', fixture('root.crt.pem')])).code).toBe(0);
        expect((await cli(['cms', 'verify', fixture('attached.p7s'), '--trust', fixture('root.crt.pem'), '--at', AT, '--ber'])).code).toBe(0);
    });
});
