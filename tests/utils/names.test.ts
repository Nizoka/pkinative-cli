import { describe, expect, it } from 'vitest';
import { attributeType, parseIp, parseNameSpec } from '../../src/utils/names.js';

describe('parseIp', () => {
    const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
    it('reads IPv4 and every IPv6 spelling', () => {
        expect(hex(parseIp('192.0.2.1', 'x'))).toBe('c0000201');
        expect(hex(parseIp('2001:db8:0:0:0:0:0:1', 'x'))).toBe('20010db8000000000000000000000001');
        expect(hex(parseIp('2001:db8::1', 'x'))).toBe('20010db8000000000000000000000001');
        expect(hex(parseIp('::', 'x'))).toBe('0'.repeat(32));
        expect(hex(parseIp('::1', 'x'))).toBe(`${'0'.repeat(30)}01`);
        expect(hex(parseIp('fe80::', 'x'))).toBe(`fe80${'0'.repeat(28)}`);
        expect(hex(parseIp('::ffff:192.0.2.1', 'x'))).toBe('00000000000000000000ffffc0000201');
        expect(hex(parseIp('::192.0.2.1', 'x'))).toBe('000000000000000000000000c0000201');
        expect(() => parseIp('1.2.3', 'x')).toThrow(/not an IPv4 or IPv6 address/);
    });
});

describe('names', () => {
    it('resolves attribute types', () => {
        expect(attributeType('cn', 'p')).toBe('2.5.4.3');
        expect(attributeType('1.2.3', 'p')).toBe('1.2.3');
        expect(attributeType('countryName', 'p')).toBe('2.5.4.6');
    });

    it('parses multi-valued RDNs', () => {
        expect(parseNameSpec([[{ type: 'CN', value: 'a' }, { type: 'O', value: 'b' }]], 'n')).toEqual([[{ type: '2.5.4.3', value: 'a' }, { type: '2.5.4.10', value: 'b' }]]);
    });
});
