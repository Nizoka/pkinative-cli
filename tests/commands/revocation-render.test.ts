import { describe, expect, it } from 'vitest';
import { renderCrl, renderEntry } from '../../src/commands/crl.js';
import { renderOcsp } from '../../src/commands/ocsp.js';
import { cli, fixture } from '../helpers/io.js';

const time = (ms: number) => ({ type: 'UTCTime', epochMilliseconds: ms, text: '' });

describe('revocation renderings', () => {
    it('renders a delta CRL', async () => {
        const r = await cli(['crl', 'inspect', fixture('ed25519-delta.crl.der')]);
        expect(r.stdout).toMatch(/^CRL v2 \(delta\)/);
        expect(r.stdout).toContain('CRL number:   2 (base 1)');
    });

    it('renders a CRL without nextUpdate or number', () => {
        const text = renderCrl({ version: 1, isDelta: false, issuer: { rdns: [], der: new Uint8Array([0x30, 0]) }, thisUpdate: time(0), nextUpdate: undefined, crlNumber: undefined, baseCrlNumber: undefined, entryCount: 0, extensions: [] } as never);
        expect(text).toContain('Next update:  (none)');
        expect(text).toContain('CRL number:   (none)');
    });

    it('renders an entry without a reason', () => {
        expect(renderEntry({ revocationDate: time(0), reason: undefined } as never)).toBe('revoked 1970-01-01T00:00:00.000Z');
        expect(renderEntry(undefined)).toBe('not listed');
    });

    it('renders a responder by key and an answer without nextUpdate', () => {
        const text = renderOcsp({
            status: 'successful',
            basicResponse: {
                responderId: { kind: 'byKey', keyHash: new Uint8Array(20) },
                producedAt: time(0),
                certificates: [],
                extensions: [],
                responses: [{ certId: { serialNumber: { hex: '05' } }, status: { kind: 'unknown' }, thisUpdate: time(0), nextUpdate: undefined }],
            },
        } as never);
        expect(text).toContain('Responder:    by key');
        expect(text).toContain('serial 05: unknown  (this 1970-01-01T00:00:00.000Z)');
    });
});
