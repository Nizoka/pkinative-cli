import { describe, expect, it } from 'vitest';
import { palette } from '../../src/utils/colors.js';
import { extensionLine, generalName, publicKeyLine, reasonLine, renderVerdict } from '../../src/utils/render.js';

const base = { critical: false, valueDer: new Uint8Array(3) };
const node = { tagClass: 'context', tagNumber: 0, constructed: false, offset: 0, headerLength: 2, contentLength: 0, indefinite: false, bytes: new Uint8Array(), content: new Uint8Array(), children: [] };

describe('generalName', () => {
    it('renders every GeneralName form', () => {
        expect(generalName({ kind: 'iPAddress', version: 4, address: '10.0.0.0', mask: '255.0.0.0', bytes: new Uint8Array() } as never)).toBe('IP:10.0.0.0/255.0.0.0');
        expect(generalName({ kind: 'otherName', typeId: '1.3.6.1.4.1.311.20.2.3', value: node } as never)).toBe('othername:1.3.6.1.4.1.311.20.2.3');
        expect(generalName({ kind: 'x400Address', value: node } as never)).toBe('x400Address');
    });
});

describe('extensionLine', () => {
    it('renders the extension kinds the fixtures lack', () => {
        expect(extensionLine({ ...base, oid: '2.5.29.19', kind: 'basicConstraints', cA: true, pathLenConstraint: 2 } as never)).toBe('basicConstraints: CA=true, pathLen=2');
        expect(extensionLine({ ...base, oid: '2.5.29.35', kind: 'authorityKeyIdentifier', keyIdentifier: undefined, authorityCertIssuer: [], authorityCertSerialNumber: undefined } as never))
            .toBe('authorityKeyIdentifier: issuer and serial');
        expect(extensionLine({ ...base, oid: '2.5.29.46', kind: 'freshestCRL', points: [{ fullName: undefined }] } as never)).toBe('freshestCRL: ');
        expect(extensionLine({ ...base, oid: '1.3.6.1.5.5.7.1.11', kind: 'subjectInfoAccess', descriptions: [{ accessMethod: '1.2.3.4', accessLocation: { kind: 'dNSName', value: 'a' } }] } as never))
            .toBe('subjectInfoAccess: 1.2.3.4 DNS:a');
        expect(extensionLine({ ...base, oid: '2.5.29.32', kind: 'certificatePolicies', policies: [{ policyIdentifier: '2.5.29.32.0', qualifiers: [] }, { policyIdentifier: '1.2.3.4', qualifiers: [] }] } as never))
            .toBe('certificatePolicies: anyPolicy, 1.2.3.4');
        expect(extensionLine({ ...base, oid: '1.2.3.4.5', kind: 'unknown' } as never)).toBe('1.2.3.4.5: 3 bytes');
    });
});

describe('publicKeyLine', () => {
    it('renders every key kind', () => {
        expect(publicKeyLine({ kind: 'rsa-pss', modulus: new Uint8Array([0x80, ...new Uint8Array(255)]) } as never)).toBe('rsa-pss 2048 bits');
        expect(publicKeyLine({ kind: 'rsa', modulus: new Uint8Array() } as never)).toBe('rsa -8 bits'.replace('-8', String(0 * 8 - 32 + 24)));
        expect(publicKeyLine({ kind: 'ec', curve: undefined, namedCurve: '1.3.132.0.10', pointFormat: 'compressed' } as never)).toBe('ec 1.3.132.0.10 (compressed)');
        expect(publicKeyLine({ kind: 'ec', curve: undefined, namedCurve: undefined, pointFormat: 'uncompressed' } as never)).toBe('ec explicit curve (uncompressed)');
        expect(publicKeyLine({ kind: 'unknown', algorithm: { oid: '1.2.3.4' } } as never)).toBe('unknown 1.2.3.4');
        expect(publicKeyLine({ kind: 'x25519' } as never)).toBe('x25519');
    });
});

describe('verdicts', () => {
    it('renders reasons with path and cause', () => {
        const reason = { code: 'PKI_REASON_INPUT_MALFORMED', message: 'm', standard: 'RFC 5280', path: 'path[0]', errorCode: 'PKI_ASN1_TRUNCATED' };
        expect(reasonLine(reason as never)).toBe('  PKI_REASON_INPUT_MALFORMED at path[0] [PKI_ASN1_TRUNCATED]: m (RFC 5280)');
        expect(reasonLine({ ...reason, path: '', errorCode: undefined } as never)).toBe('  PKI_REASON_INPUT_MALFORMED: m (RFC 5280)');
        expect(renderVerdict(palette(false), false, 'chain', [reason as never])).toMatch(/^chain: INVALID\n {2}PKI_REASON/);
    });
});

describe('names and requests', () => {
    it('renders an empty name, and a request without extensions or attributes', async () => {
        const { dn, renderRequest } = await import('../../src/utils/render.js');
        expect(dn({ rdns: [], der: new Uint8Array([0x30, 0x00]) } as never)).toBe('(empty)');
        const text = renderRequest({
            subject: { rdns: [], der: new Uint8Array([0x30, 0x00]) },
            subjectPublicKeyInfo: { kind: 'ed25519' },
            signatureAlgorithm: { oid: '1.3.101.112' },
            attributes: [{ oid: '1.2.3.4', values: [] }],
            extensions: undefined,
        } as never);
        expect(text).toContain('Subject:    (empty)');
        expect(text).toContain('Attributes: 1.2.3.4');
        expect(text).toContain('Requested extensions (0):');
        expect(renderRequest({ subject: { rdns: [], der: new Uint8Array([0x30, 0x00]) }, subjectPublicKeyInfo: { kind: 'ed25519' }, signatureAlgorithm: { oid: '1.3.101.112' }, attributes: [], extensions: [] } as never))
            .toContain('Attributes: (none)');
    });
});
