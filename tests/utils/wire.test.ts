import { describe, expect, it } from 'vitest';
import { PkiEncodingError, importPrivateKey, decodePem, parseCertificate } from 'pkinative';
import { readFileSync } from 'node:fs';
import { fromHex, toHex, toWire } from '../../src/utils/wire.js';
import { fixture, fixtureBytes } from '../helpers/io.js';

describe('toHex / fromHex', () => {
    it('round-trips bytes', () => {
        expect(toHex(new Uint8Array([0, 15, 255]))).toBe('000fff');
        expect(fromHex('0x00:0F ff')).toEqual(new Uint8Array([0, 15, 255]));
        expect(fromHex('')).toEqual(new Uint8Array());
        expect(fromHex('abc')).toBeUndefined();
        expect(fromHex('zz')).toBeUndefined();
    });
});

describe('toWire (ADR 0018)', () => {
    it('converts bigint, bytes, numbers and omits absent members', () => {
        expect(toWire({ a: 10n, b: new Uint8Array([1, 2]), c: 5, d: undefined, e: null, f: 'x', g: true, h: () => 1, i: Symbol('s') }))
            .toEqual({ a: '10', b: '0102', c: 5, e: null, f: 'x', g: true });
        expect(toWire([undefined, 1n, () => 1])).toEqual([null, '1', null]);
        expect(toWire(Infinity)).toBe('Infinity');
        expect(toWire(undefined)).toBeNull();
    });

    it('converts maps, sets and errors', () => {
        expect(toWire(new Map([['k', 1n]]))).toEqual({ k: '1' });
        expect(toWire(new Set([new Uint8Array([9])]))).toEqual(['09']);
        expect(toWire(new PkiEncodingError('PKI_OID_INVALID', 'bad oid'))).toEqual({ name: 'PkiEncodingError', message: 'bad oid', code: 'PKI_OID_INVALID' });
        expect(toWire(new Error('plain'))).toEqual({ name: 'Error', message: 'plain' });
    });

    it('describes a CryptoKey without its material', async () => {
        const key = await importPrivateKey(decodePem(readFileSync(fixture('leaf.key.pem'), 'utf8'))[0]!.bytes);
        expect(Object.prototype.toString.call(key.key)).toBe('[object CryptoKey]');
        expect(toWire(key)).toMatchObject({ key: { type: 'private', algorithm: 'ECDSA', extractable: false, usages: ['sign'] } });
    });

    it('serialises a parsed certificate to JSON', () => {
        const cert = parseCertificate(fixtureBytes('leaf.crt.der'));
        const wire = toWire(cert) as Record<string, unknown>;
        expect(wire['serialNumber']).toMatchObject({ hex: '1001', value: '4097' });
        expect(() => JSON.stringify(wire)).not.toThrow();
    });

    it('refuses a cycle, but accepts a shared subtree', () => {
        const a: Record<string, unknown> = {};
        a['self'] = a;
        expect(() => toWire(a)).toThrow(/cyclic/);
        const shared = { v: 1 };
        expect(toWire({ x: shared, y: shared })).toEqual({ x: { v: 1 }, y: { v: 1 } });
    });
});
